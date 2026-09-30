# ORION v2 — Model & Algorithm Stack Specification
## AI-Powered Cyber Threat Intelligence & Digital Trust Platform
### Technical Architecture, Models, Feature Engineering & Detection Pipelines

---

## 1. Executive Summary & Core Philosophy

ORION v2 implements a multi-tiered, multimodal detection architecture that protects both the **human layer** (phishing, social engineering, impersonation, deepfakes, voice cloning) and the **technology layer** (account takeover, malicious URLs, behavioural anomalies).

The system enforces a strict architectural boundary across three distinct roles:
1. **AI that Observes:** Extracts structured intent, entities, and transcripts without issuing risk verdicts (e.g., Whisper, Gemini Flash, Qwen Instruct).
2. **AI that Detects:** Computes domain-specific synthetic or anomalous probabilities using specialized ML (e.g., URLBERT, DistilBERT, W2V2-AASIST, ECAPA-TDNN, ArcFace, Isolation Forest).
3. **ORION that Decides:** A purely deterministic, rule-and-interaction-driven risk and fusion engine that evaluates normalized evidence against security policies to guarantee **fully traceable and auditable decisioning**.

### Key Architectural Tenets:
* **Decoupled Detection & Decisioning:** Individual models produce normalized probabilistic evidence; they do **not** dictate final risk scores.
* **Traceable & Auditable Decisioning:** Final threat classifications and severity scores are computed through an auditable, deterministic fusion engine, eliminating black-box decision uncertainty.
* **Semantic Observers, Never Deciders:** Gemini Flash and Qwen Instruct serve strictly as structured semantic extractors behind a unified Provider Gateway; they never issue final risk verdicts.
* **Separation of Semantic Dimensions:**
  - $\text{AI-Generated Media} \neq \text{Cyberattack}$ (creation is distinct from malicious deployment)
  - $\text{Voice / Face Similarity} \neq \text{Identity Authenticity}$ (acoustic similarity is not identity proof)
  - $\text{Voice-Clone Likelihood} \neq \text{Automatic Fraud}$ (synthetic voice is not fraud without coercive context)

---

## 2. Global Pipeline & Semantic Provider Hierarchy

### 2.1. Global Detection & Decision Flow
```text
                             RAW DIGITAL INPUT
              (URL, Email/SMS, Image, Video, Audio, Auth Log)
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
  HEURISTIC RULES               SPECIALIZED ML               LLM / SLM
(Lexical, Forensics,          (URLBERT, DistilBERT,     (Semantic Extraction,
 Statistical Baselines)       AASIST, ArcFace, iForest)   Intent & Entities)
        │                            │                            │
        └────────────────────────────┼────────────────────────────┘
                                     ▼
                          UNIVERSAL EVIDENCE LAYER
                      (Normalized Evidence Objects)
                                     │
                                     ▼
                              EVIDENCE FUSION
                      (Cross-Modal Entity Correlation)
                                     │
                                     ▼
                           THREAT CLASSIFICATION
                      (Phishing, Impersonation, ATO)
                                     │
                                     ▼
                    INTERACTION & DETERMINISTIC RISK ENGINE
          (Weighted Sum + Multiplicative Synergies + Circuit Breakers)
                                     │
                                     ▼
                       MITRE ATT&CK ENRICHMENT ENGINE
                    (Technique & Tactic Lineage Mapping)
                                     │
                                     ▼
                            EXPLAINABLE AI (XAI)
                   (Grounded Evidence & Risk Drivers)
                                     │
                                     ▼
                        CANONICAL INCIDENT & ACTIONS
                (Advisory Playbooks & Command Center Alerts)
```

### 2.2. Formalized Semantic Provider Hierarchy
The semantic analysis engine isolates language understanding from downstream decisioning. It supports a prioritized fallback hierarchy:

```text
                     ORION Semantic Engine
                              │
                      Provider Gateway
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
     Gemini Flash          Qwen API           Local Qwen
    (Primary Cloud)    (Cloud Alternative)  (Instruct / Ollama)
          │                   │                   │
          └───────────────────┼───────────────────┘
                              ▼
                     Structured Evidence
                              │
                              ▼
                      ORION Risk Engine
```

* **Primary Cloud:** **Gemini Flash** (Fast, highly structured JSON output, comprehensive multilingual reasoning).
* **Cloud Alternative:** **Qwen API** (High-throughput, competitive security reasoning and entity recognition).
* **Local Fallback:** **Qwen 2.5 / 3 Instruct** (Quantized local deployment via Ollama / vLLM for air-gapped or zero-internet resilience).
* **Development Only (Out-of-Band):** **Qwen-Coder** is utilized exclusively for software engineering, tool building, and codebase generation; it is **never** used as a runtime semantic security analysis model.

---

## 3. Concrete Model Checkpoint & Component Registry

Rather than specifying only abstract model families, ORION pins exact, publicly reproducible model checkpoints and benchmark datasets:

| System Component | Category | Concrete Model Checkpoint / Tech | Primary Training / Benchmark Dataset | Operational Provider | Runtime Role |
|---|---|---|---|---|---|
| **Semantic LLM** | AI that Observes | `gemini-1.5-flash` / `gemini-2.0-flash`<br>Alt: `qwen-turbo`<br>Local: `qwen2.5:3b-instruct-q4_K_M` | Security Intent Benchmarks | Provider Gateway (Gemini API / Qwen API / Ollama) | Extracts structured intent, urgency, credential/payment requests, claimed targets. Never scores risk. |
| **Coding LLM** | Development Tooling | `qwen2.5-coder:7b-instruct` | HumanEval, MBPP | Local / Offline Dev Env | **Development only.** Used for codebase generation and automation; excluded from runtime detection. |
| **Speech Transcription** | AI that Observes | `openai/whisper-tiny` / `openai/whisper-base` | LibriSpeech / CommonVoice | Local ONNX / Faster-Whisper | Converts incoming audio/video speech into text for semantic analysis. |
| **URL Phishing** | AI that Detects | `CrabInHoney/urlbert-tiny-v4-malicious-url-classifier` (4.2M params) | PhishStorm + ISCXURL-2016 | Local Hugging Face / ONNX | Evaluates structural URL anomalies, punycode, entropy, and brand distance. |
| **Text Phishing** | AI that Detects | `cybersectony/phishing-email-detection-distilbert_v2.4.1` | Nazario Phishing Corpus + Enron | Local Hugging Face / ONNX | Computes linguistic probability of phishing and coercive social engineering. |
| **Synthetic Speech** | AI that Detects | `takashi-ishida/wav2vec2-aasist` / `MelodyMachine/Deepfake-audio-detection-V2` | ASVspoof 2019/2021 LA + In-The-Wild Audio | Local PyTorch / TorchScript | Evaluates acoustic and vocoder artifacts to determine if speech is synthetic. |
| **Speaker Similarity** | AI that Detects | `speechbrain/spkrec-ecapa-voxceleb` (ECAPA-TDNN) | VoxCeleb 1 & VoxCeleb 2 | Local SpeechBrain / PyAnnote | Generates vocal embeddings and computes cosine similarity against authorized reference identities. |
| **Face Verification** | AI that Detects | `InsightFace/buffalo_l` (ArcFace ResNet-50) | Glint360k / LFW Benchmark | Local ONNX Runtime | Computes facial embeddings and matches against protected identity records. |
| **AI Image Detection** | AI that Detects | `umm-maybe/AI-image-detector` (ViT) / `dima806/ai_generated_images_detection` | Midjourney, SDXL, DALL-E 3 vs Real (100k) | Local PyTorch / ONNX | Evaluates pixel-level generative artifacts to estimate AI synthesis probability. |
| **Image Forensics** | Classical Detection | Native OpenCV (ELA, Laplacian Variance, FFT Spectrum) | CASIA 2.0 / CoMoFoD Forensics | Native Python / NumPy / SciPy | Analyzes JPEG quantization grids, ELA, Laplacian edge variance, and FFT anomalies. |
| **Video Deepfakes** | Multimodal Detection | Frame Sampling (MTCNN) + `FaceForensics++` EfficientNet-B0 | FaceForensics++ / DFDC | OpenCV + ViT + Audio Pipeline | Cross-references frame-level manipulation with temporal stability and demuxed audio. |
| **Behaviour / ATO** | Anomaly Detection | `scikit-learn` Isolation Forest (`n_estimators=100`) | BPUT Auth Telemetry / CERT Insider Threat | Native scikit-learn | Detects multivariate anomalies in login patterns, device fingerprints, and geographic velocity. |
| **Threat Intelligence** | External Grounding | `ThreatIntelProvider` (URLhaus, PhishTank, Local IOC DB) | abuse.ch Feeds, AlienVault OTX | In-Memory / SQLite IOC Cache | Validates IP/domain/hash reputation against known malicious infrastructure. |
| **Risk Engine** | ORION Decides | **Interaction & Deterministic Risk Engine** | Versioned Rule Matrix Configuration | Native Core Engine | Auditable, weighted and interaction-based evidence fusion formula. NOT a machine learning model. |
| **Explainability (XAI)** | ORION Decides | **Evidence-Grounded Templates** + Optional LLM Wording | Grounded Evidence Lineage | Native Core + Provider Gateway | Explains exact contributing evidence drivers in human-readable SOC summaries. |

---

## 4. Module-by-Module Technical Specifications

### 4.1. Web & Phishing Intelligence

#### A. URL Security Engine
* **Architecture:**
  ```text
  Raw URL ──► URL Parser ──► Handcrafted Feature Vector (24 features) ──► URLBERT ──► Threat Intel ──► Evidence Object
  ```
* **Handcrafted Features:**
  - `domain_length`, `subdomain_count`, `path_depth`, `url_entropy`
  - `ip_as_host_flag`, `punycode_flag`, `encoded_char_ratio`
  - `suspicious_tld_flag` (`.xyz`, `.top`, `.tk`, `.live`, `.click`)
  - `brand_similarity_score` (Levenshtein / Jaro-Winkler distance to protected targets: SBI, HDFC, Google, Microsoft, PayPal)
  - `credential_path_flag` (`/login`, `/verify`, `/account`, `/update`, `/kyc`, `/banking`)
  - `redirect_parameter_count` (`?url=`, `?next=`, `?redirect=`)
* **Model Checkpoint:** `CrabInHoney/urlbert-tiny-v4-malicious-url-classifier` (Inference <15ms on CPU).

#### B. Text & Message Phishing Engine
* **Model Checkpoint:** `cybersectony/phishing-email-detection-distilbert_v2.4.1`
* **Input:** Raw text from emails, SMS, WhatsApp, social media messages, or OCR text.
* **Output:** `phishing_probability` (0.0 to 1.0).

#### C. Semantic Security Analysis (Structured Intent Extraction)
* **Runtime Providers:** Gemini Flash (Primary Cloud), Qwen API (Cloud Alt), Qwen 2.5/3 Instruct (Local Fallback).
* **Role:** Structured JSON extraction only. Never dictates final risk.
* **Output Contract:**
  ```json
  {
    "urgency": true,
    "credential_request": true,
    "payment_request": false,
    "impersonation_attempt": true,
    "claimed_entity": "State Bank of India",
    "social_engineering_tactics": ["fear_appeal", "immediate_action_demand"],
    "suspicious_intent": true
  }
  ```

---

### 4.2. Threat Intelligence Abstraction

ORION features an explicit, decoupled Threat Intelligence subsystem providing ground-truth correlation against active threat feeds:

```text
                     ThreatIntelProvider (Interface)
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
   URLhaus / PhishTank        Local IOC Database       VirusTotal / AbuseIPDB
     (Active Abuse.ch)          (Offline SQLite)          (API Gateway Adapter)
```

#### Contract Schema:
```python
class ThreatIntelResult(BaseModel):
    indicator: str                   # Domain, URL, IPv4, SHA256
    indicator_type: str              # "url", "domain", "ip", "hash"
    is_malicious: bool
    reputation_score: float          # 0.0 (clean) to 1.0 (confirmed malicious)
    threat_category: Optional[str]   # "phishing", "c2", "malware_distribution"
    matched_feed: Optional[str]      # "URLhaus_recent", "PhishTank_verified"
    first_seen: Optional[datetime]
    confidence: float
```
* **Offline Resiliency:** A local SQLite fixture (`data/fixtures/threat_intel_ioc.db`) ensures threat intel lookups function reliably even with zero external internet connectivity.

---

### 4.3. Image Forensics & AI Generation Detection

```text
                               SUSPICIOUS IMAGE
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
METADATA FORENSICS           CLASSICAL FORENSICS            AI-GENERATION ML
• EXIF presence/editor tags  • JPEG quantization grids      • umm-maybe/AI-image-detector
• Software signatures        • Noise inconsistencies        • Synthetic score (0-1)
• Dimension anomalies        • Laplacian edge variance      • Manipulation score
                             • FFT frequency anomalies
         │                            │                            │
         └────────────────────────────┼────────────────────────────┘
                                      ▼
                        IMAGE EVIDENCE NORMALIZATION
```

#### Core Four-Dimensional Signal Differentiation:
To avoid conflating creative AI generation with a cyberattack:
1. `ai_generated_probability` (0.0 – 1.0): Likelihood the media was synthesized by GenAI.
2. `manipulation_probability` (0.0 – 1.0): Likelihood of localized tampering/splicing.
3. `identity_similarity` (0.0 – 1.0): Likelihood the face matches a protected reference profile.
4. `malicious_intent` (0.0 – 1.0): Coercive or fraudulent intent derived from context.

* **Case 1 (Benign AI Content):** High AI-generation (0.92), Low identity match (0.10), Low intent (0.05) $\longrightarrow$ **Informational: AI-generated media detected (Safe/Low Risk)**.
* **Case 2 (Targeted Impersonation Attack):** High AI-generation (0.91), High identity match (0.89), High malicious intent (0.95) $\longrightarrow$ **Critical Alert: AI-powered Digital Impersonation**.

---

### 4.4. Video Deepfake Detection Pipeline

```text
VIDEO STREAM / FILE
  │
  ├── 1. Container & Codec Validation (FFprobe / OpenCV)
  │
  ├── 2. Frame Sampling (Uniform stride: e.g., 2–4 FPS across timeline)
  │
  ├── 3. Face Detection & Bounding Box Tracking (InsightFace / MTCNN)
  │
  ├── 4. Frame-Level Deepfake Inference (FaceForensics++ EfficientNet-B0 checkpoint)
  │
  ├── 5. Temporal Consistency Analysis (Optical flow / inter-frame embedding delta / blink rate)
  │
  ├── 6. Demuxed Audio Stream Extraction ──► Feeds Audio Deepfake Pipeline (Section 4.5)
  │
  └── 7. Multimodal Fusion Engine ──► Unified Video Authenticity Score
```

---

### 4.5. Audio Deepfake & Voice Cloning Detection (Flagship Feature)

ORION decouples Voice Cloning Detection into four coordinated, independent models:
1. **W2V2-AASIST (`takashi-ishida/wav2vec2-aasist`):** *Is this synthetic?* (Detects vocoder artifacts and synthetic speech acoustic signatures).
2. **ECAPA-TDNN (`speechbrain/spkrec-ecapa-voxceleb`):** *Does it resemble the claimed person?* (Computes acoustic speaker similarity against an authorized voice profile).
3. **Whisper (`openai/whisper-tiny`):** *What is being said?* (Transcribes audio into text for semantic evaluation).
4. **Gemini / Qwen Instruct:** *What is the intent & context?* (Extracts urgency, impersonation targets, and financial demands).

#### Technical Architecture:
```text
                                INCOMING AUDIO CLIP
                                         │
                   ┌─────────────────────┴─────────────────────┐
                   ▼                                           ▼
              W2V2-AASIST                                   WHISPER
        "Is this synthetic speech?"                  "What is being said?"
                   │                                           │
                   ▼                                           ▼
       synthetic_speech_prob: 0.88                         Transcript
                   │                                           │
                   │                                           ▼
                   │                                   GEMINI / QWEN INSTRUCT
                   │                                  "What is the intent?"
                   │                                           │
                   │                               ┌───────────┴───────────┐
                   │                               ▼                       ▼
                   │                     claimed_identity: "CFO"    urgency: true
                   │                               │                financial_demand: true
                   ▼                               ▼
        ECAPA-TDNN SPEAKER EMBEDDING ◄─────────────┘
      "Does it resemble claimed person?"
                   │
                   ▼
       speaker_similarity: 0.93
                   │
                   └─────────────────────┬─────────────────────┘
                                         ▼
                              EVIDENCE FUSION LAYER
                                         │
                                         ▼
                            DIGITAL IMPERSONATION THREAT
                       (Synthetic Voice + Real Identity Match +
                            Unauthorized Financial Demand)
                                         │
                                         ▼
                         INTERACTION RISK: 0.95 (CRITICAL)
```

---

### 4.6. Behavioural Security & Account Takeover (ATO)

#### Layer 1: Statistical Rolling Baseline
* Computes running window statistics per user identity:
  - Typical login hours (diurnal distribution)
  - Usual IP subnets and geographic coordinates
  - Known device fingerprints (User-Agent, Canvas, WebGL, OS)
  - Typical session duration and API request frequency

#### Layer 2: Multivariate Anomaly Detection
* **Model Checkpoint:** `scikit-learn` Isolation Forest (`n_estimators=100`, `contamination=0.03`).
* **Feature Vector:**
  $$\mathbf{x} = \begin{bmatrix} \text{failed\_logins\_last\_15m} \\ \text{new\_device\_flag} \\ \text{new\_country\_flag} \\ \text{hour\_deviation\_score} \\ \text{impossible\_travel\_velocity} \\ \text{ip\_reputation\_score} \end{bmatrix}$$
* **Explainability:** Tree traversal extracts exact split paths, directly identifying contributing features (e.g., *7 failed attempts within 3 minutes followed by successful login from an unobserved ASN*).

---

## 5. Interaction-Based Deterministic Risk Engine

A pure linear addition ($\sum w_i e_i$) is inadequate for sophisticated cyber threats. Real-world threat interactions require **non-linear synergy rules, circuit breakers, and dampening logic**.

### 5.1. Risk Formulation
$$\text{Raw Risk} = \left( \sum_{i=1}^n w_i \cdot e_i \right) + \sum \text{Synergy Bonuses} - \sum \text{Dampening Reductions}$$
$$\text{Final Risk Score} = \max\Big(\text{CircuitBreakerFloor}, \min(1.0, \text{Raw Risk})\Big)$$

### 5.2. Non-Linear Interaction Rules
1. **Multiplicative Voice Impersonation Synergy:**
   ```python
   # If synthetic audio matches a real executive AND demands urgent financial action:
   if (synthetic_speech_prob > 0.75 and 
       speaker_similarity > 0.80 and 
       financial_demand is True):
       synergy_bonus += 0.25
       circuit_breaker_floor = 0.95  # Force CRITICAL tier
   ```
2. **Threat Intelligence Hard Override (Circuit Breaker):**
   ```python
   # If the URL or domain is an active, confirmed malicious IOC in URLhaus/PhishTank:
   if threat_intel_reputation >= 0.90:
       circuit_breaker_floor = 0.90  # Force CRITICAL immediately
   ```
3. **Legitimate Sender Dampening Rule:**
   ```python
   # If sender domain is strictly verified with SPF, DKIM, and long-standing domain age:
   if (sender_authenticated is True and 
       domain_age_days > 730 and 
       domain_reputation == "clean"):
       dampening_reduction += 0.35  # Suppress false positives on lookalike substrings
   ```
4. **Credential Request on Lookalike Synergy:**
   ```python
   # If a look-alike domain hosts an explicit password or KYC input field:
   if brand_lookalike is True and credential_field_detected is True:
       synergy_bonus += 0.20
       circuit_breaker_floor = 0.85  # Force HIGH/CRITICAL
   ```

### 5.3. Risk Level Thresholds
* `0.00 – 0.19`: **SAFE**
* `0.20 – 0.39`: **LOW**
* `0.40 – 0.69`: **MEDIUM**
* `0.70 – 0.84`: **HIGH**
* `0.85 – 1.00`: **CRITICAL**

---

## 6. MITRE ATT&CK Enterprise Enrichment

Every detected incident is enriched with standard MITRE ATT&CK techniques, providing SOC analysts with immediate operational context:

| ORION Detection Event | MITRE ID | Technique Name | MITRE Tactic |
|---|---|---|---|
| Phishing URL in Message / Browser | **T1566.002** | Spearphishing Link | Initial Access |
| QR Code Phishing | **T1566.002** | Spearphishing Link (QR Vector) | Initial Access |
| Malicious Attachment / Payloads | **T1566.001** | Spearphishing Attachment | Initial Access |
| Synthetic Voice Coercion (Vishing) | **T1566.004** | Spearphishing Voice | Initial Access |
| Digital Impersonation / CEO Fraud | **T1656** | Impersonation | Defense Evasion |
| Lookalike / Typosquatting Domain | **T1583.001** | Acquire Infrastructure: Domains | Resource Development |
| Password Spraying / Failed Bursts | **T1110.003** | Password Spraying | Credential Access |
| Compromised Credentials / ATO | **T1078** | Valid Accounts | Initial Access / Persistence |
| Session Anomaly / Cookie Hijack | **T1539** | Steal Web Session Cookie | Credential Access |

Incident objects export populated `mitre_techniques` arrays with direct links to the official MITRE knowledgebase.

---

## 7. Embedded In-App Evaluation Subsystem

Evaluation in ORION is not an isolated offline script; it is **built into the running platform** and exposed via API and the Command Center UI:

### 7.1. Built-in Benchmark Datasets
Packaged under `data/evaluation/`:
* `phishing_bench_50.json`: 50 verified malicious vs legitimate URLs/messages.
* `voice_deepfake_bench_30.json`: 30 authenticated vs synthetic voice clips with target ground truths.
* `auth_event_bench_40.json`: 40 normal baseline vs brute-force/ATO authentication event streams.

### 7.2. Evaluation Endpoints & Live Metrics
* `POST /api/v1/evaluation/run`: Triggers benchmark evaluation across all registered providers.
* `GET /api/v1/evaluation/metrics`: Returns live metrics per detector:
  - **Confusion Matrix:** True Positive (TP), False Positive (FP), True Negative (TN), False Negative (FN)
  - **Performance Metrics:** Accuracy, Precision, Recall, F1-Score, ROC-AUC
  - **Latency Benchmarks:** P50, P95, and P99 inference latencies in milliseconds.
* The Command Center "Evaluation" page renders these metrics directly from disk/API.

---

## 8. Phased Implementation Roadmap & Golden Path

To guarantee an exceptional, stable working system for hackathon demonstration, development is strictly staged:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      PHASE 0: THE GOLDEN PATH (MUST)                   │
│                                                                        │
│ 1. URL & Message Phishing Engine (URLBERT + DistilBERT + Heuristics)   │
│ 2. Semantic Observer (Gemini Flash / Qwen Instruct Provider Gateway)   │
│ 3. Interaction & Deterministic Risk Engine (Synergies + Overrides)     │
│ 4. Browser Shield Extension (Manifest V3 + DOM Signal Capture)         │
│ 5. Flagship Voice Impersonation Pipeline                               │
│    (W2V2-AASIST + ECAPA-TDNN + Whisper + Semantic Coercion Extraction) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   PHASE 1: SOC DASHBOARD & ATO (SHOULD)                │
│                                                                        │
│ 1. Command Center Dashboard (KPIs, Attack Timeline, Live SQLite Data)   │
│ 2. Behavioural ATO Engine (Isolation Forest + Rolling Baselines)       │
│ 3. In-App Evaluation Subsystem & Benchmarks                            │
│ 4. MITRE ATT&CK Enrichment & Threat Intel IOC Cache                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    PHASE 2: EXTENDED INTELLIGENCE (COULD)              │
│                                                                        │
│ 1. Video Deepfake Multi-Frame Sampling & Facial Tracking Pipeline      │
│ 2. Cross-Incident Attack Graph Correlation                             │
│ 3. Automated Response Playbooks & External Webhook Dispatchers         │
└────────────────────────────────────────────────────────────────────────┘
```