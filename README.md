# ORION v2 — AI-Powered Cyber Threat Intelligence & Digital Trust Platform

> **BPUT Hackathon PS09: CYBERGUARD**  
> *Production-Grade Multimodal Threat Detection, Explainable AI Lineage, and Dual-Persona Public Defense.*

---

## 🛡️ Executive Summary

**ORION v2** is a defense-in-depth cyber threat intelligence and digital trust platform engineered to protect both everyday citizens and enterprise SOC teams against next-generation cyber warfare: **banking phishing campaigns**, **AI-cloned voice extortion**, **deepfake media manipulation**, **impossible travel account takeovers (ATO)**, and **social engineering coercion**.

Unlike traditional heuristic tools or opaque black-box LLM classifiers, ORION v2 implements a **Strict Evidence-Driven Architecture**:
1. **Semantic Observation Decoupled from Risk Scoring:** Online models (**Google Gemini 3.8 Flash**, **Qwen 2.5 72B**, and **Hugging Face**) act as semantic feature observers and evidence extractors. **The LLM never directly outputs risk numbers.**
2. **Deterministic Risk Engine:** A mathematical interaction formula with **multiplicative synergies** (e.g. synthetic audio + reference voice similarity + financial coercion $\ge 0.95$ Critical Risk) and **circuit breakers** (e.g. travel velocity $> 850\text{ km/h} \to$ instant ATO floor $\ge 0.88$).
3. **Dual-Persona Interface:**
   - **Citizen Safety Portal:** Zero-jargon, 1-click verification for links, WhatsApp/SMS messages, and suspicious phone calls with National Cyber Helpline **1930** integration.
   - **SOC Command Center:** Real-time threat streams, MITRE ATT&CK technique tags, 24 lexical feature matrices, Isolation Forest vectors, and in-app accuracy benchmark runners.

---

## 🏛️ System Architecture

```text
  [ Raw Multimodal Input: Web / SMS / Audio / Image / Video / Auth ]
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────┐
   │             Provider Gateway & Detection Adapters            │
   │  • URLBERT & 24 Lexical Extractors  • DistilBERT Classifier  │
   │  • W2V2-AASIST Audio Anti-Spoofing  • ECAPA-TDNN Similarity  │
   │  • OpenCV 2D FFT Image Forensics    • Isolation Forest ATO   │
   │  • Gemini 3.8 Flash Cloud           • Qwen 2.5 Cloud         │
   └─────────────────────────────┬───────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────┐
   │               Universal Evidence Contract Layer              │
   │      Normalized Evidence Items with Calibrated Confidence    │
   └─────────────────────────────┬───────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────┐
   │         Interaction & Deterministic Risk Engine (IRE)        │
   │  • Multiplicative Impersonation Synergy                      │
   │  • Lookalike + Credential Form Harvester Synergy             │
   │  • Geo-Velocity Impossible Travel Circuit Breaker            │
   │  • Trust Verification & Baseline Dampening Logic             │
   └─────────────────────────────┬───────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────┐
   │            Explainability & Threat Enrichment Layer          │
   │  • MITRE ATT&CK Mapping (T1566.002, T1656, T1078, T1110.003) │
   │  • Plain-English Rationale Generation                        │
   │  • Actionable Incident Response Playbooks                    │
   └─────────────────────────────┬───────────────────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
   ┌───────────────────────────┐   ┌───────────────────────────┐
   │    Citizen Safety Hub     │   │    SOC Command Center     │
   │  • 1-Click Scam Scanner   │   │  • Threat Stream & KPIs   │
   │  • Traffic-Light Verdict  │   │  • Forensic Drawer (XAI)  │
   │  • National 1930 Report   │   │  • Multi-Modal Studio     │
   │  • WhatsApp Alert Share   │   │  • Live Benchmark Matrix  │
   └───────────────────────────┘   └───────────────────────────┘
```

---

## ⚡ Key Modules & Capabilities

### 1. Web & Phishing Intelligence
- **24-Feature Lexical Extractor:** Computes Shannon entropy, punycode flags, Levenshtein brand distance, credential path patterns, and sub-domain depth.
- **URLBERT Classifier:** Calibrated statistical model assessing lookalike domains and credential harvesting infrastructure.
- **Browser Shield Extension (Manifest V3):** Passive DOM signal observer capturing form action destinations, brand assertions, and password fields without transmitting user keystrokes.

### 2. Identity, Voice Cloning & Media Intelligence
- **W2V2-AASIST Neural Anti-Spoofing:** Deep Wav2Vec2 transformer (`MelodyMachine/Deepfake-audio-detection-V2`) evaluating raw acoustic speech waveforms for synthetic vocoder and generative voice artifacts.
- **Whisper Speech-to-Text:** Lightweight neural transcription (`openai/whisper-tiny`) extracting conversational transcripts and feeding the Semantic Gateway for coercive intent analysis.
- **ECAPA-TDNN Speaker Verification:** 192-dimensional acoustic speaker embeddings (`speechbrain/spkrec-ecapa-voxceleb`) computing cosine similarity against enrolled VIP reference profiles without manufacturing false matches.
- **OpenCV Image Forensics:** 2D FFT high-frequency spectrum analysis and Laplacian edge variance detecting GAN/diffusion generation and boundary tampering.
- **Video Deepfake Decomposition:** Demuxes audio for voice analysis while computing frame-by-frame manipulation and temporal jitter scores.

### 3. Behavioural Security & Account Takeover (ATO)
- **Geo-Velocity Calculator:** Haversine great-circle distance computation flagging impossible travel ($> 850\text{ km/h}$).
- **Isolation Forest Anomaly Scorer:** Unsupervised multivariate anomaly detection over 7-dimensional authentication vectors (ASN novelty, login hour distribution, user-agent deviation, failed attempt bursts).

### 4. Citizen Cyber Safety Hub
- **Universal Scanner:** One-click checks for links, messages, calls, and logins.
- **Pre-Loaded Scam Presets:** Realistic everyday scenarios (Electricity bill cutoff SMS, fake SBI NetBanking KYC, WhatsApp task scams, digital arrest threats).
- **Traffic-Light Safety Verdict:** High-contrast visual indicators (Safe / Suspicious / Dangerous Scam).
- **Helpline 1930 Integration:** Simulated incident dispatch generating complaint reference IDs (e.g. `NCRB-2026-94812`).

---

## 🚀 Quickstart Guide

### Prerequisites
- **Python:** 3.10+ (tested on Python 3.12)
- **Node.js:** v18+ (tested on Node v24)
- **Git**

### Single-Click Launch (Windows)
To start both backend and frontend servers simultaneously and open the portal:
```cmd
scripts\start_all.bat
```

To re-seed the SQLite database with 14 demo threat scenarios at any time:
```cmd
scripts\seed_demo.bat
```

---

### Manual Launch

#### 1. Backend Setup
```bash
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
python scripts/seed_demo_incidents.py
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend API Docs will be available at: [http://localhost:8000/docs](http://localhost:8000/docs)*

#### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
*Frontend Portal will be available at: [http://localhost:5173](http://localhost:5173)*

#### 3. Browser Shield Extension Setup
1. Open Google Chrome or Microsoft Edge and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in top right).
3. Click **Load unpacked** and select the `browser-shield/` directory.
4. Pin the **ORION Browser Shield** to your toolbar.

---

## 📡 API Reference Overview

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/system/health` | Operational health and active provider status |
| `GET` | `/api/v1/system/threat-intel/lookup` | Search domain, IP, or hash in threat intelligence feeds |
| `GET` | `/api/v1/system/identities` | List enrolled protected VIP profiles |
| `POST` | `/api/v1/system/identities` | Enroll a new executive profile with acoustic vector |
| `GET` | `/api/v1/incidents` | List, filter, and paginate security incidents |
| `GET` | `/api/v1/incidents/{id}` | Full incident details with complete evidence lineage |
| `PATCH`| `/api/v1/incidents/{id}/status` | Triage and update incident status (`ACKNOWLEDGED`, `RESOLVED`, etc.) |
| `GET` | `/api/v1/incidents/summary/dashboard` | Aggregated SOC KPI metrics |
| `POST` | `/api/v1/analyze/url` | Lexical & URLBERT phishing analysis |
| `POST` | `/api/v1/analyze/message` | DistilBERT NLP & coercion intent analysis |
| `POST` | `/api/v1/analyze/browser` | Browser Shield DOM security signals |
| `POST` | `/api/v1/analyze/audio` | W2V2-AASIST & ECAPA-TDNN voice clone analysis |
| `POST` | `/api/v1/analyze/image` | OpenCV 2D FFT & 4-signal image forensics |
| `POST` | `/api/v1/analyze/video` | Video deepfake temporal decomposition |
| `POST` | `/api/v1/analyze/auth-event` | Geo-velocity & Isolation Forest ATO analysis |
| `POST` | `/api/v1/evaluation/run` | Execute live in-app benchmark test suite |
| `GET` | `/api/v1/evaluation/latest` | Retrieve latest benchmark metrics & confusion matrix |

---

## 🧪 Testing & Verification

The test suite covers all subsystems with **100% pass rate** across all phases:

```bash
cd backend
python -m pytest tests/ -v
```

```text
tests/test_phase0.py::test_database_persistence_and_retrieval PASSED
tests/test_phase0.py::test_incident_repository_crud PASSED
tests/test_phase0.py::test_system_health_endpoint PASSED
tests/test_phase0.py::test_incidents_api_endpoints PASSED
tests/test_phase1.py::test_threat_intel_provider_lookup PASSED
tests/test_phase1.py::test_semantic_gateway_provider_routing PASSED
tests/test_phase1.py::test_risk_engine_base_scoring PASSED
tests/test_phase1.py::test_risk_engine_voice_impersonation_synergy PASSED
tests/test_phase1.py::test_risk_engine_circuit_breakers PASSED
tests/test_phase1.py::test_mitre_mapper_enrichment PASSED
tests/test_phase1.py::test_explainability_and_playbook_generation PASSED
tests/test_phase2.py::test_url_lexical_feature_extraction PASSED
tests/test_phase2.py::test_url_classifier_engine PASSED
tests/test_phase2.py::test_text_classifier_engine PASSED
tests/test_phase2.py::test_web_orchestrator_url_analysis PASSED
tests/test_phase2.py::test_web_orchestrator_message_analysis PASSED
tests/test_phase2.py::test_web_orchestrator_browser_analysis PASSED
tests/test_phase3.py::test_audio_synthetic_detector PASSED
tests/test_phase3.py::test_speaker_embedding_verifier PASSED
tests/test_phase3.py::test_whisper_transcription_engine PASSED
tests/test_phase3.py::test_identity_registry_operations PASSED
tests/test_phase3.py::test_image_forensics_engine PASSED
tests/test_phase3.py::test_image_synthetic_classifier PASSED
tests/test_phase3.py::test_media_orchestrator_audio_synergy PASSED
tests/test_phase3.py::test_media_orchestrator_image_pipeline PASSED
tests/test_phase3.py::test_media_orchestrator_video_pipeline PASSED
tests/test_phase4.py::test_profile_store_retrieval_and_seeding PASSED
tests/test_phase4.py::test_haversine_great_circle_distance PASSED
tests/test_phase4.py::test_impossible_travel_velocity_trigger PASSED
tests/test_phase4.py::test_isolation_forest_anomaly_detection PASSED
tests/test_phase4.py::test_behavioural_orchestrator_benign_event PASSED
tests/test_phase4.py::test_behavioural_orchestrator_impossible_travel PASSED
tests/test_phase4.py::test_behavioural_orchestrator_failed_login_burst PASSED
tests/test_phase4.py::test_behavioural_orchestrator_novel_asn PASSED
tests/test_phase4.py::test_auth_event_api_endpoint PASSED
tests/test_phase5.py::test_ground_truth_dataset_loading PASSED
tests/test_phase5.py::test_evaluation_metrics_calculator PASSED
tests/test_phase5.py::test_benchmark_runner_execution PASSED
tests/test_phase5.py::test_benchmark_runner_caching PASSED
tests/test_phase5.py::test_evaluation_api_endpoints PASSED
tests/test_phase5.py::test_benchmark_accuracy_threshold PASSED
tests/test_phase5.py::test_benchmark_latency_metrics PASSED
tests/test_phase5.py::test_confusion_matrix_consistency PASSED

======================== 43 passed in 88.9s (100%) ========================
```

---

## 📁 Repository Directory Structure

```text
Orion_v2/
├── backend/
│   ├── app/
│   │   ├── api/v1/           # Endpoints: analyze, incidents, evaluation, system
│   │   ├── core/             # Configuration, database WAL engine
│   │   ├── engines/
│   │   │   ├── behavioural/  # Profile store, geo-velocity, Isolation Forest
│   │   │   ├── identity/     # VIP profile registry, 192-dim acoustic vectors
│   │   │   ├── media/        # W2V2-AASIST, ECAPA-TDNN, OpenCV FFT forensics
│   │   │   └── phishing/     # 24 URL lexical features, URLBERT, DistilBERT
│   │   ├── evaluation/       # Benchmark runner, metrics, confusion matrix
│   │   ├── explainability/   # Grounded plain-language XAI rationale generator
│   │   ├── providers/        # Gemini Flash, Qwen Cloud, Threat Intel IOC
│   │   ├── repositories/     # SQLite persistence & audit logging layer
│   │   ├── response/         # Advisory mitigation response playbooks
│   │   ├── risk/             # Deterministic interaction engine & MITRE mapper
│   │   └── schemas/          # Universal Evidence, Incident, Threat schemas
│   ├── data/
│   │   ├── evaluation/       # ground_truth.json (20 multimodal benchmarks)
│   │   ├── fixtures/         # threat_intel_ioc.db (offline blacklist cache)
│   │   └── orion.db          # SQLite operational database
│   ├── scripts/
│   │   └── seed_demo_incidents.py  # 14 realistic threat scenarios seeder
│   └── tests/                # 43 automated unit & integration tests
│
├── browser-shield/           # Chrome / Edge Browser Shield Extension (Manifest V3)
│   ├── manifest.json
│   └── src/
│       ├── background/       # Threat gateway integration worker
│       ├── content/          # Bounded DOM security observer
│       └── popup/            # Extension UI popup
│
├── frontend/                 # Command Center SOC Dashboard & Citizen Portal
│   ├── src/
│   │   ├── components/
│   │   │   ├── CitizenSafetyHub.jsx      # Zero-jargon public safety portal
│   │   │   ├── EvaluationDashboard.jsx   # Live accuracy & latency matrix
│   │   │   ├── Header.jsx                # Persona switcher & telemetry
│   │   │   ├── IdentityRegistryView.jsx  # VIP identity & biometric manager
│   │   │   ├── IncidentDrawer.jsx        # XAI evidence lineage & triage
│   │   │   ├── IncidentFeed.jsx          # Live SOC incident stream & KPIs
│   │   │   └── ThreatStudio.jsx          # 8-modality forensic sandbox
│   │   ├── services/         # Centralized API service
│   │   └── index.css         # Dark-mode SOC design system tokens
│   └── package.json
│
├── scripts/                  # Unified Windows Launchers
│   ├── seed_demo.bat         # Reset & seed SQLite database
│   ├── start_all.bat         # Single-click master launcher
│   ├── start_backend.bat     # Launch FastAPI backend
│   └── start_frontend.bat    # Launch Vite frontend
│
├── docs/                     # Specifications & Trackers
│   ├── TASK_TRACKER.md       # Live implementation audit tracker
│   └── model_stack.md        # AI model architecture & weights documentation
└── README.md
```

---

## 🏆 Hackathon PS09 Compliance Highlights

| PS09 Hackathon Requirement | ORION v2 Implementation |
|---|---|
| **Multimodal Threat Detection** | URLs, email/SMS text, audio voice clones, image/video deepfakes, and auth events. |
| **Evidence Lineage & Explainability** | Every incident retains complete evidence items with severity contributions and plain-English rationales. |
| **Online Model Integration** | Gemini 3.8 Flash, Qwen 2.5 72B, and Hugging Face actively connected with graceful offline fallbacks. |
| **Public & Citizen Usability** | Dedicated Citizen Safety Portal with 1-click verification, traffic-light verdicts, and National Cyber Helpline 1930 integration. |
| **Deterministic Risk Scoring** | Interaction formula with multiplicative synergies and circuit breakers—models never guess risk numbers directly. |
| **Live In-App Benchmarks** | One-click benchmark runner measuring Accuracy, Precision, Recall, F1, FPR, FNR, and latency percentiles. |

---

*Developed for BPUT Hackathon PS09: CYBERGUARD. All rights reserved.*
