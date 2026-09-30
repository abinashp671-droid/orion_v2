# ORION v2 — Final Hackathon Demo Script

**System:** ORION v2 — AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System  
**Format:** Technical Judge Demonstration & Walkthrough  
**Duration:** ~5–7 Minutes  
**Target Audience:** Technical Judges, Security Engineers, Hackathon Evaluation Panel  

---

## 🎭 Demonstration Flow Overview

| Step | Topic | Target Component / UI | Key Message / Technical Evidence |
|---|---|---|---|
| **1** | **The Problem & Architecture** | Slide / Intro Overview | Next-gen attacks use multimodal vectors (AI voice clones, deepfakes, ATO). Heuristics alone fail; black-box LLMs hallucinate risk. |
| **2** | **Citizen Safety Hub** | `CitizenSafetyHub.jsx` | Dual-persona interface. Zero-jargon citizen defense with 1-click scanners & National 1930 Helpline dispatch simulation. |
| **3** | **Browser Shield Protection** | `browser-shield` MV3 | Passive, bounded DOM signal extraction (form destinations, password fields, claimed brand) without collecting credentials. |
| **4** | **Phishing & URL Intelligence** | URL Scanner & Incident Drawer | 24-feature lexical extractor, URLBERT, and LLM semantic observer decoupled from risk engine. |
| **5** | **Voice Cloning & Deepfake Audio** | Audio Scanner & Media Studio | W2V2-AASIST anti-spoofing, Whisper STT, and ECAPA-TDNN speaker identity embeddings. |
| **6** | **Image Forensics & Video Deepfakes** | Image & Video Scanners | 2D FFT spectral analysis, Laplacian variance, frame manipulation, and temporal jitter decomposition. |
| **7** | **Account Takeover & Behavioural Anomaly** | Auth Event Scanner & SOC Stream | Haversine geo-velocity impossible travel ($>850$ km/h) & Isolation Forest anomaly scoring. |
| **8** | **SOC Command Center & XAI Lineage** | Command Center Dashboard | Executive KPIs, real-time threat stream, evidence graphs, MITRE ATT&CK mapping, and transparent rationale. |
| **9** | **Response Playbooks & Audit Trail** | Incident Drawer (Response Tab) | Advisory & simulated response actions (MFA step-up, credential reset, domain block) with immutable audit logs. |
| **10** | **Evaluation & Honest AI Metrics** | Evaluation Dashboard | Reproducible benchmark system, dataset provenance (SYNTHETIC_DATA), sample sizes ($n$), and explicit `NOT_MEASURED` sentinels. |

---

## 📜 Step-by-Step Script & Talking Points

### Step 1: Problem Statement & Evidence-Driven Architecture (30 sec)

> *"Judges, modern cyber attacks are no longer simple phishing emails. Attackers combine lookalike domains, AI-cloned voices, synthetic executive video deepfakes, and credential harvesting in coordinated campaigns.*
>
> *ORION v2 was built to solve two major flaws in current security tools:*
> 1. *Black-box LLMs hallucinate risk scores and cannot be audited.*
> 2. *Traditional heuristic tools fail against AI-generated media.*
>
> *ORION enforces a strict Evidence-Driven Architecture: AI models act solely as semantic feature observers, feeding a deterministic Risk Engine with calibrated interaction formulas and circuit breakers."*

---

### Step 2: Citizen Safety Hub & Public Defense (45 sec)

> *"We begin with the Citizen Safety Hub — a zero-jargon public interface built for non-technical users.*
>
> *Users can test suspicious URLs, SMS text, or voice calls in one click. Watch as we run a suspicious banking SMS preset: ORION immediately displays a clear Traffic-Light Verdict ('Dangerous Scam'), plain-English explanation, and an actionable 1-click button to file a simulated report to India's National Cyber Crime Helpline (1930) with an instant tracking reference."*

---

### Step 3: Browser Shield Extension (45 sec)

> *"Next, we demonstrate the ORION Browser Shield — a Manifest V3 browser extension.*
>
> *When a user navigates to a login page, the Shield extracts bounded DOM signals: password field presence, form submission destinations, page title, and claimed brand cues. Crucially, it collects ZERO sensitive data — no passwords, no keystrokes, no cookies, no tokens. When a lookalike domain matches a credential harvester pattern, a high-visibility warning banner injects directly into the page."*

---

### Step 4: URL & Phishing Intelligence (45 sec)

> *"Switching to the SOC Command Center, we inspect the backend URL analysis pipeline.*
>
> *Our pipeline extracts 24 lexical features — Shannon entropy, punycode flags, Levenshtein distance against top brands, sub-domain depth — combined with URLBERT inference. The evidence is passed into our Interaction Risk Engine, mapping directly to MITRE ATT&CK Technique T1566.002 (Spearphishing Link)."*

---

### Step 5: Voice Impersonation & Deepfake Audio (60 sec)

> *"Now let's examine Voice Impersonation analysis.*
>
> *When an audio sample is uploaded, ORION executes three parallel neural models:*
> 1. **W2V2-AASIST:** Raw acoustic waveform anti-spoofing to detect synthetic vocoder artifacts.
> 2. **Whisper STT:** Lightweight transcription extracting semantic intent (e.g. financial coercion keywords).
> 3. **ECAPA-TDNN:** 192-dimensional acoustic speaker embeddings computing similarity against enrolled executive reference profiles.
>
> *The Risk Engine applies a multiplicative synergy rule: when acoustic synthetic probability is high and financial coercion is present, the risk score elevates to CRITICAL ($0.95$). Notice how ORION reports resemblance rather than claiming absolute identity verification — keeping decisions scientifically honest."*

---

### Step 6: Account Takeover & Behavioural Security (45 sec)

> *"For enterprise protection, ORION handles Behavioural Account Takeover (ATO).*
>
> *Our engine evaluates authentication events using Haversine great-circle distance for geo-velocity calculations ($> 850$ km/h flags impossible travel) combined with an Isolation Forest model over 7-dimensional login feature vectors. An impossible travel signal triggers an instant circuit breaker elevating the risk floor to CRITICAL ($0.88+$)."*

---

### Step 7: Response Playbooks & Immutable Audit Trail (45 sec)

> *"In the SOC Incident Drawer, analysts receive automated Response Playbook recommendations.*
>
> *Every action operates under safe boundaries: ADVISORY actions log analyst intent without external side effects; SIMULATED actions modify internal database state (`real_systems_modified = false`). No action can accidentally disrupt real production firewalls or credentials during evaluation."*

---

### Step 8: Evaluation Framework & Honest AI Metrics (60 sec)

> *"Finally, we show the ORION Phase 7 Evaluation Dashboard.*
>
> *Most AI security tools make unsubstantiated claims like '99.9% accuracy'. ORION enforces complete evaluation integrity:*
> - *Every sample has explicit provenance (`SYNTHETIC_DATA`).*
> - *Every metric displays sample count ($n=22$).*
> - *Zero-denominator states output `NOT_MEASURED` rather than fabricated $100\%$ precision.*
> - *Scenarios lacking ground truth (e.g. video deepfakes) are explicitly labeled `NOT MEASURED — INSUFFICIENT GROUND TRUTH`.*
> - *Model failure handling is verified: `UNAVAILABLE` providers never fail silently into `SAFE`."*

---

### Step 9: Technical Closing (30 sec)

> *"To summarize: ORION v2 delivers a hardened, defense-in-depth security system combining real neural inference, deterministic risk calculation, dual-persona UX, advisory response playbooks, and a fully reproducible evaluation framework.*
>
> *Thank you. We are ready for your technical questions!"*

---

## ❓ Anticipated Technical Judge Q&A

| Question | Defensible Technical Answer |
|---|---|
| *"Does the LLM decide the risk score?"* | **No.** LLMs act as feature observers. The Risk Engine uses a deterministic, mathematical interaction formula with hardcoded weights, multiplicative synergies, and circuit breakers. |
| *"What happens if an AI model API fails?"* | **Provider failure $\neq$ SAFE.** The system sets provider status to `INCONCLUSIVE`, preserving evidence and reporting uncertainty in XAI. |
| *"Can your response playbooks break production?"* | **No.** All actions are strictly ADVISORY or SIMULATED inside ORION's database. `real_systems_modified` is always `false`. |
| *"Are your evaluation metrics from real-world data?"* | **No.** All 22 evaluation samples are labeled `SYNTHETIC_DATA`. We display sample counts ($n$) and explicitly mark unmeasured modalities as `NOT_MEASURED`. |
