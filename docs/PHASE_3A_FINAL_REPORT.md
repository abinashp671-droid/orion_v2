# ORION v2 — Phase 3A Final Report
## Real URL / Phishing Intelligence

**Date:** September 27, 2026  
**Status:** COMPLETE & VERIFIED  
**Final Status:** **READY FOR PHASE 3B**

---

## 1. Current Architecture

ORION v2 employs an evidence-based security architecture where artificial intelligence models act as **Evidence Providers** feeding a deterministic, non-linear **Risk Engine**:

```
TARGET URL
   │
   ├─► URL Normalization (RFC 3986, port/case/query/fragment preservation)
   ├─► Handcrafted 24-Feature Lexical Extractor (Levenshtein, entropy, TLD, punycode)
   ├─► ACTUAL URLBERT TRANSFORMER (CrabInHoney/urlbert-tiny-v4-malicious-url-classifier)
   ├─► Threat Intelligence (Local SQLite IOC Cache + Cloud Feeds)
   └─► Context Semantic Extraction (Semantic Gateway / Browser DOM Signals)
               │
               ▼
       Evidence Fusion
               │
               ▼
    Deterministic Risk Engine
    (Linear contributions + Non-linear interaction rules + Circuit breakers)
               │
               ▼
    Explainability (XAI) & Playbooks
               │
               ▼
    Incident Entity & Audit Trail (Dashboard / Browser Shield)
```

**Core Invariant:** The machine learning model is an **Evidence Provider**. It never directly outputs `SAFE`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Final risk decisions remain strictly within the deterministic Risk Engine.

---

## 2. Previous URL Classifier

In Phase 0, 1, and 2, the URL classifier was a simulated placeholder:
- **Prior Implementation:** `URLClassifierEngine._compute_calibrated_probability(features)` computed a handcrafted logistic score over heuristic feature flags without loading neural weights.
- **Limitation:** While it generated normalized `EvidenceItem` objects, it lacked real deep-learning sequence representation or tokenization of arbitrary URL strings.

---

## 3. New Transformer Implementation

The placeholder has been replaced with genuine transformer-based neural inference:
- **Exact Model Identifier:** [`CrabInHoney/urlbert-tiny-v4-malicious-url-classifier`](https://huggingface.co/CrabInHoney/urlbert-tiny-v4-malicious-url-classifier)
- **Base Architecture Model:** `CrabInHoney/urlbert-tiny-base-v4`
- **Parameter Count:** 3.69 Million parameters (Tensor type: F32)
- **Model Checkpoint Size:** 14.8 MB
- **Training Benchmark:** Fine-tuned on the multi-class Malicious URLs Dataset (ISCX-URL-2016, PhishTank, URLhaus, and Malware Domain Blacklist).

---

## 4. Model Architecture

- **Class:** `BertForSequenceClassification` via Hugging Face `transformers`
- **Hidden Layers:** 4 layers, 128 hidden dimensions, 2 attention heads (BERT-tiny architecture)
- **Sequence Length:** Truncated up to 512 tokens with `BertTokenizerFast` / `AutoTokenizer`
- **Output:** 4-dimensional classification logits passed through `torch.softmax` for calibrated class probabilities.

---

## 5. Tokenizer / Label Mapping

The model outputs 4 classification logits mapped to the verified four-class taxonomy:

| Label ID | Config Key | Target Class | Semantics in ORION |
| :---: | :---: | :---: | :--- |
| `0` | `LABEL_0` | **benign** | Clean, non-malicious URL |
| `1` | `LABEL_1` | **defacement** | Unauthorized website defacement / compromise |
| `2` | `LABEL_2` | **malware** | Malware distribution / payload delivery |
| `3` | `LABEL_3` | **phishing** | Credential theft / brand impersonation |

- **Benign Probability:** $p(\text{benign}) = p_0$
- **Malicious Probability:** $p(\text{malicious}) = p_1 + p_2 + p_3 = 1.0 - p_0$
- **Dominant Prediction:** Label corresponding to $\operatorname{argmax}(p_0, p_1, p_2, p_3)$.

---

## 6. Inference Device

- **Hardware Detection:** Dynamic, non-breaking safe detection:
  - If `torch.cuda.is_available()`: uses `cuda`
  - Otherwise: uses `cpu`
- **Verified Environment:** Windows 11 AMD64, Python 3.12.10, PyTorch 2.14.0+cpu, Transformers 5.17.0.
- **Active Runtime Device:** `cpu` (no CUDA hardware required, fully portable).
- **Metadata Transparency:** Device identifier is recorded internally in `indicators["device"]` and audit logs; it is not displayed in normal user-facing views.

---

## 7. Model Loading and Caching

- **Singleton Pattern:** Implemented in `TransformerURLClassifier` using thread-safe locking (`threading.Lock()`).
- **Lazy Initialization:** The model and tokenizer are downloaded/cached upon initial access and retained in memory.
- **Cache Persistence:** Checkpoints are stored in the local Hugging Face cache directory (`~/.cache/huggingface/hub/`).
- **No Per-Request Reloading:** Subsequent requests reuse the shared in-memory model instance immediately with zero disk reloading overhead.

---

## 8. Evidence Contract

The classifier produces normalized, schema-compliant `EvidenceItem` objects:

```json
{
  "id": "evi_8b14a2f019c4",
  "type": "urlbert_malicious",
  "source": "web_intelligence",
  "value": 0.9982,
  "confidence": 0.99,
  "severity_contribution": "CRITICAL",
  "weight": 0.30,
  "indicators": {
    "provider": "urlbert",
    "model": "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier",
    "model_loaded": true,
    "prediction": "phishing",
    "malicious_probability": 0.9982,
    "benign_probability": 0.0002,
    "category_probabilities": {
      "benign": 0.0002,
      "defacement": 0.0001,
      "malware": 0.0015,
      "phishing": 0.9982
    },
    "device": "cpu",
    "latency_ms": 16.12,
    "fallback_reason": null
  },
  "explanation": "URLBERT neural model (CrabInHoney/urlbert-tiny-v4-malicious-url-classifier) classified URL structure as PHISHING with probability 99.8% on cpu."
}
```

No raw PyTorch tensors, gradient graphs, or internal logits are exposed to API consumers or the frontend.

---

## 9. Risk Engine Integration

- **Model Confidence $\neq$ Final Risk:**
  - An isolated high probability from URLBERT (e.g. `0.92`) produces a moderate linear base contribution ($0.30 \times 0.92 \times 1.6 \approx 0.441$), resulting in `MEDIUM / SUSPICIOUS`, **never** `CRITICAL`.
- **Compound Non-Linear Synergies:**
  - When URLBERT malicious indicators coincide with **Lookalike Domain** (`brand_similarity >= 0.70`) and **Credential Path** / **Intent**, the Risk Engine activates Multiplicative Interaction Rule B:
    - $+0.20$ synergy bonus
    - Circuit breaker floor: $\ge 0.85$ (`CRITICAL`)
- **False-Positive Protection:**
  - Benign documentation pages (e.g. `example.com/docs`) and clean URLs with zero suspicious lexical flags are protected from Kaggle dataset scheme artifacts via calibrated scheme-free evaluation, resulting in `risk_score < 0.40` (`SAFE / LOW`).

---

## 10. Threat Intelligence Integration

- **Provider:** `ThreatIntelProvider` with offline SQLite IOC repository (`threat_intel_ioc.db`).
- **Positive Match Semantics:** Emits `EvidenceType.THREAT_INTEL_MATCH` with `severity_contribution = CRITICAL` and triggers the Risk Engine circuit-breaker floor ($0.90$).
- **Negative Match Semantics:** When an indicator is not found in threat intelligence feeds, `ThreatIntelProvider` returns `is_malicious = False`.
- **Safety Principle:** **`UNKNOWN != SAFE`**. Absence from threat intelligence does not override malicious model predictions or suspicious lexical traits.

---

## 11. Browser Shield Integration

- The browser security endpoint `/api/v1/analyze/browser` automatically benefits from the real URLBERT pipeline through `WebIntelligenceOrchestrator.analyze_browser_page`.
- When an active password field is detected on a domain flagged by URLBERT and lexical heuristics, the compound interaction triggers immediate `CRITICAL` risk and issues an in-browser advisory banner with deep-linking to ORION.

---

## 12. Fallback Behaviour

- If PyTorch, Hugging Face Hub, or the transformer model cannot be initialized, the system automatically activates `HeuristicURLClassifier`.
- **Honest Provider Tagging:** The fallback explicitly outputs:
  - `provider: "heuristic_fallback"`
  - `model_loaded: false`
  - `model: "heuristic_calibrated"`
- **Strict Prohibition:** The system **NEVER** claims `URLBERT` or reports `model_loaded: true` when executing the fallback.
- **Fail-Safe Inconclusive:** A provider failure never converts into a fake `SAFE` verdict.

---

## 13. Tests

### Full Regression Suite:
- **Baseline (Phase 2):** 60 passed, 0 failed
- **New Total (Phase 3A):** **76 passed, 0 failed, 1 warning**
- **Duration:** 147.98 seconds

### Test Breakdown by Subsystem:
1. `tests/test_phase0.py`: 4 passed (baseline & contracts)
2. `tests/test_phase1.py`: 7 passed (multimodal architecture & threat intel)
3. `tests/test_phase1_uploads.py`: 14 passed (file upload & validation)
4. `tests/test_phase2.py`: 9 passed (Browser Shield & deep-linking)
5. `tests/test_phase3.py`: 9 passed (media intelligence baseline)
6. `tests/test_phase3a_urlbert.py`: **16 passed** (URLBERT unit, integration & benchmarks)
7. `tests/test_phase4.py`: 9 passed (behavioural analytics & ATO)
8. `tests/test_phase5.py`: 8 passed (benchmark evaluation suite)

---

## 14. Real Model Integration Test

- **Actual Checkpoint Inference Executed:** **YES**.
- Tests `test_real_transformer_loading_and_architecture`, `test_real_transformer_inference_malicious_fixture`, `test_real_transformer_inference_malware_fixture`, and `test_urlbert_performance_benchmark` download and execute actual neural inference against `CrabInHoney/urlbert-tiny-v4-malicious-url-classifier`.
- **Unit Test Separation:** Isolated adapter logic, fallback routing, and exception containment are covered in deterministic tests with mocked failure injection.

---

## 15. Performance Measurements

Measured on CPU (Intel Core i5-1135G7 @ 2.40GHz, Windows 11):

| Stage | Measured Latency |
| :--- | :--- |
| **Initial Checkpoint Load & Init:** | ~16.58 seconds (one-time cold start) |
| **Warm In-Memory Inference (First Query):** | 28.90 ms |
| **Warm In-Memory Inference (Average, 4 fixtures):** | **17.41 ms** |
| **Heuristic Fallback Latency:** | 0.42 ms |

The model adds less than 20 ms to URL inspection workflows, comfortably below the 150 ms interactive budget.

---

## 16. Unsupported Claims Removed/Corrected

1. **Simulated Model Claims:** Previous references implying URLBERT was active in Phase 0–2 have been updated; `provider_status` now reports `"ok"` only when the transformer is genuinely running, and `"heuristic_fallback"` otherwise.
2. **False Safety Statements:** Documented that an IOC miss in threat intelligence is not proof of safety.
3. **No Exaggerated Accuracies:** Preserved model card accuracy values (0.9922 F1 on benchmark) while maintaining that the model is solely an evidence provider subject to Risk Engine fusion.

---

## 17. Remaining Issues

### For Phase 3B:
- Audio synthetic voice detection (`W2V2-AASIST`) and speaker verification (`ECAPA-TDNN`) are currently simulated in `app/engines/media/` and will be upgraded to real inference in Phase 3B.

### For Phase 3C:
- Facial embedding verification (`ArcFace`) and image tampering forensics will be upgraded in Phase 3C.

### For Phase 3D:
- Temporal video deepfake frame/jitter analysis will be upgraded in Phase 3D.

---

## 18. Acceptance Checklist

| Requirement | Status | Verification Evidence |
| :--- | :---: | :--- |
| Actual URL transformer model integration exists | **PASS** | `TransformerURLClassifier` using `AutoModelForSequenceClassification` |
| Correct model architecture is used | **PASS** | `BertForSequenceClassification` (3.69M params) |
| Correct tokenizer is used | **PASS** | `AutoTokenizer` (512 max length) |
| Correct label mapping is verified | **PASS** | `0: benign, 1: defacement, 2: malware, 3: phishing` |
| Actual transformer inference is demonstrated | **PASS** | Verified on live test URLs (`phishing: 0.9982`, `malware: 1.000`) |
| Model is cached | **PASS** | In-memory singleton + HF Hub local cache |
| CPU fallback works | **PASS** | Verified on Windows host without CUDA |
| CUDA support exists when available | **PASS** | Dynamic `cuda` / `cpu` device selection |
| Existing 24-feature lexical analysis remains | **PASS** | `URLLexicalExtractor` retains all 24+ features |
| Threat intelligence remains integrated | **PASS** | `ThreatIntelProvider` SQLite IOC lookup functional |
| Model evidence is separate from final risk | **PASS** | `RiskEngine` decoupled evaluation verified |
| Model failure does not become fake SAFE | **PASS** | Failures fall back to `heuristic_fallback` |
| Heuristic fallback is explicitly identified | **PASS** | `provider: "heuristic_fallback"` explicitly returned |
| Browser Shield uses the improved URL pipeline | **PASS** | `/api/v1/analyze/browser` verified |
| Existing frontend remains compatible | **PASS** | Production build passes (`dist/assets/index-D6O2Zccs.js`) |
| XAI remains evidence-grounded | **PASS** | `ExplainabilityGenerator` trace verified |
| Tests cover the new adapter | **PASS** | 16 dedicated Phase 3A tests passing |
| Real-model integration test is clearly distinguished | **PASS** | Explicitly separated in `test_phase3a_urlbert.py` |
| Full regression suite passes | **PASS** | 76 passed, 0 failed |
| Frontend build passes | **PASS** | `vite build` completed in 1.60s with 0 errors |
| Frontend lint has no errors | **PASS** | 0 errors |
| No unsupported capability claims remain | **PASS** | Codebase audited |

---

## 19. Final Status

# **READY FOR PHASE 3B**

*(Per strict stop conditions, stopping execution now. Do NOT begin Phase 3B until explicitly instructed.)*
