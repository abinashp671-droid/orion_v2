# ORION v2 Phase 0 Baseline & Safety Freeze Report

**Date of Audit:** September 26, 2026  
**Auditor:** Antigravity AI Pair Programmer  
**Repository:** ORION v2 (`c:\Users\Sweta\Desktop\Orion_v2`)  
**Hackathon Problem Statement:** BPUT Hackathon PS09: CYBERGUARD  
**Status:** Baseline Established — Safety Freeze Active  

---

## 1. Repository Structure

The ORION v2 repository is organized into five top-level functional areas:

```text
Orion_v2/
├── backend/
│   ├── app/
│   │   ├── api/v1/               # FastAPI route controllers
│   │   │   ├── analyze.py        # Threat analysis endpoints (url, message, browser, audio, image, video, auth)
│   │   │   ├── evaluation.py     # Live benchmark runner & ground truth APIs
│   │   │   ├── incidents.py      # Incident management, triage, and KPI summaries
│   │   │   └── system.py         # System health, threat intel lookup, and identity registry
│   │   ├── core/
│   │   │   ├── config.py         # Pydantic v2 application settings and environment loader
│   │   │   └── database.py       # aiosqlite asynchronous SQLite database connection and WAL pragma
│   │   ├── engines/
│   │   │   ├── behavioural/      # Profile store, Haversine geo-velocity, Isolation Forest anomaly detection
│   │   │   ├── identity/         # Protected VIP identity registry and 192-dim acoustic embeddings
│   │   │   ├── media/            # Audio synthetic detector, ECAPA speaker verifier, OpenCV image forensics, Whisper adapter
│   │   │   └── phishing/         # 24 URL lexical features, URLBERT adapter, DistilBERT text classifier
│   │   ├── evaluation/           # Benchmark suite runner, ground truth loader, metrics calculator
│   │   ├── explainability/       # Grounded XAI plain-English rationale generator
│   │   ├── providers/            # Semantic Provider Gateway (Gemini, Qwen, Ollama, Heuristic) & Threat Intel IOC
│   │   ├── repositories/         # SQLite incident repository and telemetry audit logging
│   │   ├── response/             # Context-aware advisory response playbook generator
│   │   ├── risk/                 # Deterministic Interaction Risk Engine & MITRE ATT&CK mapper
│   │   └── schemas/              # Pydantic models: EvidenceItem, Incident, ThreatAssessment, Playbooks
│   ├── data/
│   │   ├── evaluation/           # ground_truth.json (22 benchmark test samples)
│   │   ├── fixtures/             # threat_intel_ioc.db (offline SQLite IOC cache)
│   │   └── orion.db              # Primary SQLite database (incidents, entities, audit logs)
│   ├── scripts/
│   │   └── seed_demo_incidents.py # Database seeder with 14 realistic cyber incidents
│   ├── tests/                    # 43 automated unit & integration tests (Phases 0–5)
│   ├── .env                      # API keys and provider configurations
│   └── requirements.txt          # Python dependencies
│
├── browser-shield/               # Chrome & Edge Extension (Manifest V3)
│   ├── manifest.json             # Manifest V3 specification
│   ├── README.md                 # Extension installation instructions
│   └── src/
│       ├── background/           # background.js (service worker dispatching to FastAPI)
│       ├── content/              # content.js (bounded DOM extraction & warning banner)
│       └── popup/                # popup.html, popup.js, popup.css (extension toolbar UI)
│
├── frontend/                     # React 19 + Vite 8 Command Center & Citizen Portal
│   ├── src/
│   │   ├── assets/               # Branding assets & hero graphics
│   │   ├── components/
│   │   │   ├── CitizenSafetyHub.jsx     # Zero-jargon public safety scanner & 1930 integration
│   │   │   ├── EvaluationDashboard.jsx  # Live in-app benchmark viewer & confusion matrix
│   │   │   ├── Header.jsx               # Navigation bar & Citizen/SOC persona toggle
│   │   │   ├── IdentityRegistryView.jsx # VIP identity biometric management interface
│   │   │   ├── IncidentDrawer.jsx       # Forensic XAI evidence lineage & triage actions
│   │   │   ├── IncidentFeed.jsx         # Live SOC threat stream with filters & KPI metrics
│   │   │   └── ThreatStudio.jsx         # 8-modality forensic sandbox with presets & sliders
│   │   ├── services/
│   │   │   └── api.js                   # Centralized API service layer
│   │   ├── App.css                      # Layout styling
│   │   ├── App.jsx                      # Main application container & state router
│   │   ├── index.css                    # Dark-mode SOC design system tokens
│   │   └── main.jsx                     # Vite React entry point
│   ├── package.json                     # Frontend dependencies & scripts
│   └── vite.config.js                   # Vite configuration
│
├── scripts/                      # Unified Windows launchers
│   ├── create_archive.py         # Packaging utility
│   ├── seed_demo.bat             # Database re-seeding batch script
│   ├── start_all.bat             # Simultaneous backend + frontend master launcher
│   ├── start_backend.bat         # FastAPI Uvicorn launcher
│   └── start_frontend.bat        # Vite dev server launcher
│
├── docs/                         # Specifications & engineering logs
│   ├── model_stack.md            # AI model architecture & weights documentation
│   ├── ORION_V2_MASTER_SPEC_FINAL.md # Core technical architecture specification
│   ├── Problem_Statement_9.pdf   # Hackathon PS09 problem definition
│   └── TASK_TRACKER.md           # Live implementation phase tracker
└── README.md                     # Project master documentation
```

---

## 2. Current Architecture

ORION v2 implements a strict **Evidence-Driven Decoupled Architecture**:

```text
  [ Raw Multimodal Input: URL / Message / Audio / Image / Video / Auth Event ]
                                    │
                                    ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                        Provider & Feature Tier                         │
  │  • 24-feature Lexical URL Extractor                                    │
  │  • Handcrafted Logistic URL Classifier (attributed to URLBERT)         │
  │  • Text Phishing Classifier (Hugging Face online / Regex heuristic)    │
  │  • W2V2-AASIST Acoustic Synthetic Detector (heuristic proxy)          │
  │  • ECAPA-TDNN Speaker Embedding Verifier (synthetic 192-dim vectors)   │
  │  • OpenCV 2D FFT Frequency Spectrum & Laplacian Edge Forensics         │
  │  • Geo-Velocity Impossible Travel Calculator (Haversine formula)       │
  │  • Isolation Forest Unsupervised Anomaly Detector (scikit-learn)       │
  │  • Semantic Provider Gateway: Gemini Flash -> Qwen Cloud -> Heuristic  │
  │  • Offline Threat Intel IOC SQLite Fixture (`threat_intel_ioc.db`)    │
  └────────────────────────────────────┬───────────────────────────────────┘
                                       │
                                       ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                    Universal Evidence Contract Layer                   │
  │  Normalized EvidenceItem schemas with source, confidence, severity,    │
  │  and explainability metadata.                                          │
  └────────────────────────────────────┬───────────────────────────────────┘
                                       │
                                       ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                 Interaction & Deterministic Risk Engine                │
  │  • Mathematical interaction formula (Base Linear + Synergies)          │
  │  • Multiplicative Synergies:                                           │
  │    - Voice clone + executive similarity + financial demand >= 0.95     │
  │    - Lookalike domain + credential harvesting >= 0.85                  │
  │    - Failed login burst + anomalous geography >= 0.85                  │
  │  • Hard Circuit-Breaker Floors:                                        │
  │    - Threat intel active IOC match >= 0.90                             │
  │    - Impossible travel velocity (> 850 km/h) >= 0.88                   │
  │  • Models NEVER output risk scores directly                            │
  └────────────────────────────────────┬───────────────────────────────────┘
                                       │
                                       ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                  Enrichment & Explainability Layer                     │
  │  • MITRE ATT&CK technique mapping (T1566.002, T1566.004, T1656, etc.)  │
  │  • Deterministic plain-English XAI rationale synthesis                 │
  │  • Context-aware advisory response playbooks                           │
  └────────────────────────────────────┬───────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
  ┌──────────────────────────────────┐  ┌──────────────────────────────────┐
  │       Citizen Safety Hub         │  │       SOC Command Center         │
  │  • 1-Click Scam Scanner          │  │  • Threat Stream & Live KPIs     │
  │  • Traffic-Light Verdict         │  │  • Interactive Forensic Drawer   │
  │  • National Helpline 1930 Action │  │  • 8-Modality Threat Studio      │
  │  • WhatsApp Alert Formatter      │  │  • In-App Benchmark Runner       │
  └──────────────────────────────────┘  └──────────────────────────────────┘
```

---

## 3. How to Run Backend

### Prerequisites
- Python 3.10+ (Verified on Python 3.12.10)
- Dependencies installed via `backend/requirements.txt`

### Intended Command
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Alternatively via the provided batch script:
```cmd
scripts\start_backend.bat
```

### Verified Status
- **Application Process:** Starts cleanly and binds to `http://127.0.0.1:8000`.
- **Database Initialization:** Auto-creates tables in `backend/data/orion.db` via `app.core.database.init_db()` during application lifespan.
- **Operational Health Endpoint:** `GET http://127.0.0.1:8000/api/v1/system/health` returns HTTP 200 with status `"online"` and database `"connected"`.
- **Interactive Documentation:** Available at `http://127.0.0.1:8000/docs`.

---

## 4. How to Run Frontend

### Prerequisites
- Node.js v18+ (Verified on Node v24.21.0, npm 11.19.0)
- Packages installed in `frontend/node_modules`

### Intended Command
```bash
cd frontend
npm run dev
```
Alternatively via the provided batch script:
```cmd
scripts\start_frontend.bat
```

### Verified Status
- **Dev Server:** Starts cleanly on `http://127.0.0.1:5173/` in under 700 ms.
- **Production Build:** `npm run build` compiles with 0 errors (`dist/assets/index-CeQHgtXB.js` 345 kB, `dist/assets/index-Dxhhzp91.css` 4.25 kB).
- **Linter Status:** `npm run lint` (`oxlint`) reports 34 warnings (unused imports) and 2 errors (conditional React Hook in `IncidentDrawer.jsx:8-9`).

---

## 5. How to Run Browser Shield

### Architecture
- **Specification:** Manifest V3 (`browser-shield/manifest.json`).
- **Dependencies:** Pure static HTML, JavaScript, CSS (no build step needed).

### Installation Instructions
1. Open Google Chrome or Microsoft Edge and navigate to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top right corner.
3. Click **Load unpacked** and select the folder `c:\Users\Sweta\Desktop\Orion_v2\browser-shield`.
4. Pin **ORION Browser Shield** to the browser toolbar.

### Verified Status
- **Manifest:** Valid Manifest V3, specifies service worker `src/background/background.js`, content script `src/content/content.js`, popup `src/popup/popup.html`.
- **Backend Communication:** Successfully connects to `POST http://localhost:8000/api/v1/analyze/browser`.
- **Signal Extraction:** Extracts bounded passive DOM signals: `url`, `title`, `has_password_field`, `form_actions`, `claimed_brand`. Does NOT log keystrokes or password contents.
- **Warning UI:** Injects fixed top banner `#orion-shield-banner` on `HIGH` and `CRITICAL` threats.

---

## 6. API Inventory

| Method | Path | Purpose | Input Format | Output Format | Frontend Used? | Extension Used? | Live Test Status |
|---|---|---|---|---|---|---|---|
| `GET` | `/` | Root info & service metadata | None | JSON | No | No | Verified HTTP 200 |
| `GET` | `/docs` | OpenAPI Swagger documentation | None | HTML | No | No | Verified HTTP 200 |
| `GET` | `/api/v1/system/health` | Operational healthcheck | None | JSON | Yes (`api.getHealth`) | No | Verified HTTP 200 (`online`) |
| `GET` | `/api/v1/system/threat-intel/lookup` | IOC database lookup | Query: `indicator`, `indicator_type` | JSON (`ThreatIntelResult`) | Yes (`api.lookupThreatIntel`) | No | Verified HTTP 200 |
| `GET` | `/api/v1/system/identities` | List VIP profiles | None | JSON (`List[ProtectedIdentity]`) | Yes (`api.getProtectedIdentities`) | No | Verified HTTP 200 (3 profiles) |
| `POST` | `/api/v1/system/identities` | Enroll new VIP profile | JSON (`IdentityEnrollRequest`) | JSON (`ProtectedIdentity`) | Yes (`api.enrollProtectedIdentity`) | No | Verified |
| `GET` | `/api/v1/incidents` | List & filter incidents | Query: `limit`, `offset`, `status`, etc. | JSON (`List[Incident]`) | Yes (`api.getIncidents`) | No | Verified HTTP 200 |
| `GET` | `/api/v1/incidents/{incident_id}` | Incident details & evidence lineage | Path: `incident_id` | JSON (`Incident`) | Yes (`api.getIncidentById`) | Yes (link target) | Verified HTTP 200 |
| `PATCH`| `/api/v1/incidents/{incident_id}/status` | Triage update incident status | Path: `incident_id`, Query: `status` | JSON (`Incident`) | Yes (`api.updateIncidentStatus`) | No | Verified HTTP 200 |
| `GET` | `/api/v1/incidents/summary/dashboard` | Aggregated SOC KPIs | None | JSON (counts, distributions, timeline) | Yes (`api.getDashboardSummary`) | No | Verified HTTP 200 |
| `POST` | `/api/v1/analyze/url` | URL phishing & lexical analysis | JSON: `{url, context}` | JSON (`Incident`) | Yes (`api.analyzeUrl`) | No | Verified HTTP 200 |
| `POST` | `/api/v1/analyze/message` | Text / SMS / email phishing analysis | JSON: `{text}` | JSON (`Incident`) | Yes (`api.analyzeMessage`) | No | Verified HTTP 200 |
| `POST` | `/api/v1/analyze/browser` | Browser Shield DOM signal analysis | JSON: `{url, title, has_password_field, form_actions, claimed_brand}` | JSON (`Incident`) | Yes (`api.analyzeBrowser`) | Yes (`ANALYZE_PAGE`) | Verified HTTP 200 |
| `POST` | `/api/v1/analyze/audio` | Synthetic speech & voice clone analysis | JSON: `{claimed_identity_name, provided_transcript, injected_synthetic_score, injected_similarity_score, audio_b64}` | JSON (`Incident`) | Yes (`api.analyzeAudio`) | No | Verified HTTP 200 |
| `POST` | `/api/v1/analyze/image` | Image forensics & 4-signal analysis | JSON: `{ai_generated_prob, manipulation_prob, identity_similarity, malicious_intent, target_name, image_b64}` | JSON (`Incident`) | Yes (`api.analyzeImage`) | No | Verified HTTP 200 |
| `POST` | `/api/v1/analyze/video` | Video deepfake decomposition | JSON: `{video_name, frame_manipulation_score, temporal_jitter_score, target_name, audio_transcript}` | JSON (`Incident`) | Yes (`api.analyzeVideo`) | No | Verified HTTP 200 |
| `POST` | `/api/v1/analyze/auth-event` | Behavioural ATO analysis | JSON: `{user_id, ip_address, latitude, longitude, city, country, asn, success, ...}` | JSON (`Incident`) | Yes (`api.analyzeAuthEvent`) | No | Verified HTTP 200 |
| `POST` | `/api/v1/evaluation/run` | Execute benchmark evaluation | JSON: `{modality, sample_limit}` | JSON (`EvaluationRunResult`) | Yes (`api.runEvaluation`) | No | Verified HTTP 200 (auth_event) |
| `GET` | `/api/v1/evaluation/latest` | Retrieve latest benchmark run | None | JSON (`EvaluationRunResult`) | Yes (`api.getLatestEvaluation`) | No | Fails on default url sample (see Section 11) |
| `GET` | `/api/v1/evaluation/ground-truth` | Inspect ground truth dataset | None | JSON (counts, modalities, labels) | Yes (`api.getGroundTruthMetadata`) | No | Verified HTTP 200 |

### Media Upload Support Check
- **Multipart Image Upload:** NOT SUPPORTED. Endpoint expects JSON payload (`image_b64` optional string or numerical probabilities).
- **Multipart Audio Upload:** NOT SUPPORTED. Endpoint expects JSON payload (`audio_b64` optional string or numerical probabilities).
- **Multipart Video Upload:** NOT SUPPORTED. Endpoint expects JSON metadata (`video_name`, `frame_manipulation_score`, `temporal_jitter_score`).
- **URL Analysis:** SUPPORTED via JSON.
- **Message Analysis:** SUPPORTED via JSON.
- **Auth Event Analysis:** SUPPORTED via JSON.

---

## 7. Existing Test Results

The backend automated test suite was executed via `python -m pytest tests/ -v`:

- **Total Tests:** 43
- **Passed:** 43 (100%)
- **Failed:** 0
- **Skipped:** 0
- **Errors:** 0
- **Warnings:** 1 (`StarletteDeprecationWarning` regarding `httpx` with `TestClient`)
- **Execution Time:** 87.78 seconds

### Breakdown by Test Suite:
1. `tests/test_phase0.py` (4/4 passed): Universal Evidence contract, inconclusive contract, incident repository CRUD, FastAPI base endpoints.
2. `tests/test_phase1.py` (7/7 passed): Semantic Provider Gateway, threat intel provider, voice impersonation synergy, circuit breakers, MITRE ATT&CK mapper, XAI explainability.
3. `tests/test_phase2.py` (6/6 passed): 24 URL lexical feature extractor, URL classifier scoring, DistilBERT text classifier, web intelligence orchestrator, browser page analysis, analyze endpoints.
4. `tests/test_phase3.py` (9/9 passed): Identity registry, W2V2-AASIST detector, ECAPA speaker verifier, voice cloning synergy, 4-signal image separation, OpenCV forensics, multimodal video analysis.
5. `tests/test_phase4.py` (9/9 passed): User profile store, Haversine distance, impossible travel scenarios, Isolation Forest anomaly scoring, ATO attack orchestration, benign login dampening.
6. `tests/test_phase5.py` (8/8 passed): Ground truth dataset loading, metrics calculator (perfect, mixed, empty), benchmark runner execution (auth_event), evaluation APIs.

---

## 8. Frontend Verification

- **Framework:** React 19.2.8 + Vite 8.3.1.
- **Entry Points:** `frontend/index.html` -> `frontend/src/main.jsx` -> `frontend/src/App.jsx`.
- **Navigation & Views:**
  - Citizen Safety Hub (default public view with 1-click verification for links, text, voice, accounts).
  - SOC Command Center (analyst toggle):
    - Incident Stream & KPIs (`IncidentFeed.jsx`).
    - Multi-Modal Forensic Sandbox (`ThreatStudio.jsx`).
    - In-App Evaluation Matrix (`EvaluationDashboard.jsx`).
    - VIP Protected Identities Registry (`IdentityRegistryView.jsx`).
- **Inspection Drawer:** `IncidentDrawer.jsx` displays risk dial, evidence lineage cards, MITRE ATT&CK tags, and advisory playbooks.
- **State Management:** React native `useState` / `useEffect` with polling every 15s (`App.jsx`).
- **Styling System:** Pure CSS tokens in `index.css` using modern dark-mode palette (`#090d16` background, cyan/emerald glow accents, high-contrast badges).
- **Build Status:** Built cleanly in 1.01s with zero bundle errors.

---

## 9. Browser Shield Verification

- **Manifest:** Manifest V3 (`browser-shield/manifest.json`).
- **Permissions:** `["activeTab", "storage"]`, `host_permissions: ["http://localhost:8000/*", "http://127.0.0.1:8000/*"]`.
- **Content Script (`src/content/content.js`):** Passively inspects DOM on `document_idle`. Bounded security signals: `url`, `title`, `hasPasswordField`, `formActions` (first 5), `claimedBrand` (meta tags). Strictly avoids capturing keystrokes or password strings.
- **Background Worker (`src/background/background.js`):** Dispatches analysis request to `POST http://localhost:8000/api/v1/analyze/browser`. Caches result in `chrome.storage.local`. Updates browser action badge (`!`, `▲`, `✓`).
- **Warning UI:** Renders red high-contrast warning banner at top of webpage on `HIGH` or `CRITICAL` risk with threat type, top risk drivers, and direct incident link.
- **Popup UI (`src/popup/popup.html`):** Renders hostname, risk probability bar, primary threat badge, and top 3 evidence items.
- **Checklist Assessment:**
  - A. Builds successfully: Yes (vanilla, no build step required).
  - B. Loads successfully in Chrome/Edge: Yes (valid Manifest V3).
  - C. Communicates with backend: Yes (`POST /api/v1/analyze/browser` tested and confirmed).
  - D. Analyzes current page/URL: Yes.
  - E. Displays a result: Yes (in popup and on-page banner).
  - F. Opens ORION dashboard: Partially (link points to backend API endpoint `/api/v1/incidents/{id}` instead of frontend portal URL).

---

## 10. Intelligence Capability Matrix

| Capability | Status | Current Implementation | File(s) | Notes |
|---|---|---|---|---|
| **24-Feature Lexical URL Extractor** | **REAL** | Shannon entropy, Levenshtein distance (rapidfuzz), punycode flags, TLD checks, path depth, parameters | `backend/app/engines/phishing/url_features.py` | Fully functional, deterministic feature extractor |
| **URLBERT Phishing Classifier** | **SIMULATED** | Calibrated logistic regression formula scoring handcrafted lexical features; attributes score to `CrabInHoney/urlbert-tiny-v4-malicious-url-classifier` | `backend/app/engines/phishing/url_classifier.py` | No Hugging Face or PyTorch transformer model executed |
| **Threat Intelligence Provider** | **REAL** | Offline SQLite fixture query with pre-seeded IOC indicators and reputation scoring | `backend/app/providers/threat_intel.py`, `data/fixtures/threat_intel_ioc.db` | Works reliably offline with fast index lookups |
| **Message Phishing Classifier** | **PARTIAL** | Live online Hugging Face call if `HF_TOKEN` present; falls back to calibrated Regex rule weights + sigmoid | `backend/app/engines/phishing/text_classifier.py` | Online Hugging Face call can time out; regex fallback active |
| **Gemini Semantic Observer** | **PARTIAL** | Cloud REST call to `generativelanguage.googleapis.com` (attempts `gemini-3.8-flash`, `gemini-flash-latest`, `gemini-2.5-flash`) | `backend/app/providers/semantic_gateway.py` | Key present in `.env`; if model name or quota fails, cascades to Qwen |
| **Qwen Semantic Observer** | **REAL** | Cloud REST call to OpenRouter (`qwen/qwen-2.5-72b-instruct`) with JSON structured output format | `backend/app/providers/semantic_gateway.py` | Actively verified working live during audit (`qwen_cloud_openrouter`) |
| **Local Qwen (Ollama)** | **NOT IMPLEMENTED** | Connects to `http://localhost:11434`; returns None when Ollama service is not running locally | `backend/app/providers/semantic_gateway.py` | Service not active; gracefully falls to heuristic |
| **Heuristic Semantic Fallback** | **REAL** | Pattern-based keyword matchers extracting urgency, credential requests, financial demands, impersonation | `backend/app/providers/semantic_gateway.py` | Deterministic terminal fallback |
| **OpenCV Classical Image Forensics** | **REAL** | cv2.Laplacian edge variance, 2D FFT magnitude spectrum high-frequency ratio, RGB channel noise std dev | `backend/app/engines/media/image_forensics.py` | Genuine computer vision computation executed on raw image bytes |
| **AI-Generated Image Detection** | **PARTIAL** | Optional online HF call to `umm-maybe/AI-image-detector`; otherwise uses input parameter `ai_generated_prob` | `backend/app/engines/media/image_synthetic.py` | Mostly relies on front-end slider probability |
| **4-Signal Media Separation** | **REAL** | Mathematical decoupling between AI-generation, localized tampering, identity match, and malicious intent | `backend/app/engines/media/image_synthetic.py` | Prevents benign AI art from triggering critical alerts |
| **Video Deepfake Detection** | **SIMULATED** | Accepts `frame_manipulation_score` and `temporal_jitter_score` as float inputs; does not process video bytes | `backend/app/engines/media/orchestrator.py` | No video decoding, frame extraction, or temporal CV model |
| **Whisper Transcription** | **STUB** | Accepts pre-extracted transcript; runtime byte transcription has a `pass` block | `backend/app/engines/media/transcription.py` | Does not transcribe audio files locally |
| **W2V2-AASIST Audio Anti-Spoofing** | **SIMULATED** | Computes raw byte variance over first 2048 bytes or accepts `injected_synthetic_score`; attributes to `takashi-ishida/wav2vec2-aasist` | `backend/app/engines/media/audio_synthetic.py` | No PyTorch/Wav2Vec2 neural network inference |
| **ECAPA-TDNN Speaker Verification** | **SIMULATED** | Generates pseudo-random 192-dim unit vector seeded by byte hash; attributes to `speechbrain/spkrec-ecapa-voxceleb` | `backend/app/engines/media/speaker_embedding.py` | No actual acoustic neural embedding extraction |
| **ArcFace / InsightFace** | **NOT IMPLEMENTED** | Referenced in documentation; no face detection or face embedding extractor in codebase | `backend/app/engines/media/` | Facial similarity is purely a slider input parameter |
| **Voice Cloning Detection Pipeline** | **REAL (Logic)** | Fuses synthetic speech score + acoustic similarity match + financial demand intent | `backend/app/engines/media/orchestrator.py` | Multiplicative synergy formula correctly triggers critical threat |
| **Identity Profile Registry** | **REAL** | In-memory registry with 3 pre-seeded VIPs and cosine similarity matching | `backend/app/engines/identity/registry.py` | Enrolls and matches profiles with 192-dim reference vectors |
| **Geo-Velocity / Impossible Travel** | **REAL** | Haversine formula calculation computing distance in km, elapsed hours, and velocity in km/h | `backend/app/engines/behavioural/geo_velocity.py` | Flags velocities > 850 km/h with hard circuit breaker |
| **Isolation Forest Anomaly Scorer** | **REAL** | scikit-learn `IsolationForest(n_estimators=100, contamination=0.05)` fitted on 1500 7-dim baseline vectors | `backend/app/engines/behavioural/isolation_forest.py` | Computes genuine decision function anomaly scores |
| **User Profile Baseline Store** | **REAL** | Tracks rolling historical login locations, typical hours, typical ASNs, failed login counters | `backend/app/engines/behavioural/profile_store.py` | Pre-seeded with realistic enterprise executive profiles |
| **Deterministic Risk Engine** | **REAL** | Mathematical interaction formula with multiplicative synergies, dampening, and circuit breakers | `backend/app/risk/engine.py` | Central decisioning engine; models never output risk numbers |
| **MITRE ATT&CK Mapper** | **REAL** | Maps primary threats and active evidence items to 7 Enterprise ATT&CK techniques with official URLs | `backend/app/risk/mitre.py` | Enriches incidents with T1566.002, T1566.004, T1656, etc. |
| **Explainable AI (XAI)** | **REAL** | Synthesizes plain-English evidence lineage, top risk drivers, and compound synergy explanations | `backend/app/explainability/generator.py` | Traceable and auditable plain-language summaries |
| **Response Playbook Generator** | **REAL** | Generates prioritized, category-tagged mitigation actions (BLOCK, WARN, SESSION, MFA, etc.) | `backend/app/response/playbooks.py` | Advisory playbooks contextualized to incident severity |
| **In-App Evaluation Subsystem** | **REAL** | Benchmark runner loading 22 ground-truth samples, computing accuracy, precision, recall, F1, FPR, FNR, latency | `backend/app/evaluation/` | Evaluates live orchestrator pipelines (with 1 keyword bug) |
| **Browser Shield Extension** | **REAL** | Manifest V3 Chrome extension extracting passive DOM signals and rendering warning banners | `browser-shield/` | Fully operational integration with FastAPI backend |

---

## 11. Known Issues

### 1. Keyword Argument Mismatch in Benchmark Runner (`evaluation/runner.py:93`)
- **Issue:** When running URL evaluation samples, `BenchmarkRunner` calls:
  ```python
  incident = await self.web_orchestrator.analyze_url(
      url=sample.input_data.get("url", ""),
      context=sample.input_data.get("context"),
  )
  ```
  However, `WebIntelligenceOrchestrator.analyze_url` defines its first parameter as `raw_url: str`, NOT `url: str`.
- **Impact:** Calling `GET /api/v1/evaluation/latest` when no run is cached triggers an automatic 4-sample smoke benchmark on the first samples (which are URLs), resulting in:
  `TypeError: WebIntelligenceOrchestrator.analyze_url() got an unexpected keyword argument 'url'`.
- **Status:** Left unchanged per Phase 0 policy. Must be addressed in Phase 1.

### 2. React Hooks Violation in `IncidentDrawer.jsx:6-9`
- **Issue:** In `frontend/src/components/IncidentDrawer.jsx`:
  ```javascript
  export default function IncidentDrawer({ incident, onClose, onActionExecuted }) {
    if (!incident) return null; // <-- Early return before Hook calls!

    const [currentStatus, setCurrentStatus] = useState(incident.status || 'NEW');
    const [updatingStatus, setUpdatingStatus] = useState(false);
  ```
- **Impact:** Violates the React Rules of Hooks. Flagged as an error by `oxlint`. Does not crash production bundle because `App.jsx` conditionally renders `<IncidentDrawer>` only when `selectedIncident` is truthy, but causes linter failure.
- **Status:** Documented; left unchanged per Phase 0 policy.

### 3. Missing Multipart Upload Endpoints for Media
- **Issue:** The endpoints `/api/v1/analyze/audio`, `/api/v1/analyze/image`, and `/api/v1/analyze/video` accept JSON bodies (`application/json`). None accept `multipart/form-data` file streams.
- **Impact:** Users in the Threat Studio cannot upload actual `.wav`, `.mp3`, `.jpg`, `.png`, or `.mp4` binary files directly from their disk through standard file input fields without encoding them into base64 strings or manually adjusting simulation sliders.
- **Status:** Documented for future phase implementation.

### 4. Browser Shield Popup Link Target
- **Issue:** `browser-shield/src/popup/popup.js:76` sets `investigateLink.href = 'http://localhost:8000/api/v1/incidents/' + incident.id`.
- **Impact:** Clicking "Investigate in ORION" opens the raw backend JSON endpoint in a browser tab instead of the frontend React SOC dashboard (`http://localhost:5173`).
- **Status:** Documented for future phase implementation.

### 5. Git Executable Missing in Environment
- **Issue:** `git` is not in the system `PATH`, and the workspace directory does not have an initialized `.git` folder.
- **Impact:** Version control commands (`git status`, `git commit`) cannot be executed by CLI.
- **Status:** Documented. No destructive Git actions were taken.

---

## 12. Demo/Claim Leakage

The audit identified several areas where documentation or UI elements make claims that exceed the current underlying model execution:

1. **URLBERT Claim:** `docs/model_stack.md` and `README.md` claim live inference with `CrabInHoney/urlbert-tiny-v4-malicious-url-classifier`. In reality, `backend/app/engines/phishing/url_classifier.py` calculates a logistic regression over 24 handcrafted features and tags the indicator dictionary with `model: CrabInHoney/urlbert-tiny-v4-malicious-url-classifier`.
2. **W2V2-AASIST Claim:** `docs/model_stack.md` claims execution of `takashi-ishida/wav2vec2-aasist` for voice spoofing. In reality, `backend/app/engines/media/audio_synthetic.py` computes raw byte variance over the first 2048 bytes or accepts an `injected_synthetic_score`.
3. **ECAPA-TDNN Claim:** `docs/model_stack.md` claims 192-dim acoustic embeddings extracted via `speechbrain/spkrec-ecapa-voxceleb`. In reality, `backend/app/engines/media/speaker_embedding.py` generates pseudo-random Gaussian vectors seeded by byte hash.
4. **Whisper Transcription Claim:** `docs/model_stack.md` claims live speech-to-text via `openai/whisper-tiny`. In reality, `backend/app/engines/media/transcription.py` has a `pass` statement and returns whatever transcript is passed into the request.
5. **Video Deepfake Model Claim:** `docs/model_stack.md` claims video deepfake decomposition. In reality, `VideoAnalysisRequest` only accepts pre-computed float values (`frame_manipulation_score` default 0.82, `temporal_jitter_score` default 0.79).
6. **Ground Truth Hardcoded Scores:** In `backend/data/evaluation/ground_truth.json`, audio test samples (e.g. `gt_audio_01`, `gt_audio_02`) hardcode `"injected_synthetic_score": 0.94` and `"injected_similarity_score": 0.91` rather than referencing audio files.
7. **Manual Risk Sliders in UI:** `frontend/src/components/ThreatStudio.jsx` provides manual `<input type="range">` sliders for Synthetic Speech Prob, Speaker Cosine Sim, AI-Generated Prob, Manipulation Prob, Identity Similarity, and Video Temporal Jitter.

---

## 13. Environment Requirements

- **Operating System:** Windows 10/11 (or Linux/macOS)
- **Python Runtime:** Python 3.10+ (tested on Python 3.12.10)
  - Packages: `fastapi`, `uvicorn`, `pydantic`, `aiosqlite`, `numpy`, `scikit-learn`, `opencv-python-headless`, `httpx`, `pytest`, `pytest-asyncio`, `python-multipart`, `rapidfuzz`, `pillow`
- **Node Runtime:** Node.js v18+ (tested on Node v24.21.0, npm 11.19.0)
  - Packages: `react`, `react-dom`, `lucide-react`, `vite`, `@vitejs/plugin-react`, `oxlint`
- **Network Access:**
  - Ports: `8000` (FastAPI backend), `5173` (Vite frontend dev server)
  - External API endpoints: `https://openrouter.ai/api/v1/chat/completions` (Qwen cloud), `https://generativelanguage.googleapis.com/` (Gemini cloud), `https://router.huggingface.co/` (Hugging Face inference)

---

## 14. Phase 1 Recommendations

During Phase 1 (and subsequent implementation phases), the following items should be addressed in strict priority order:

1. **Fix Parameter Mismatch in Benchmark Runner:** Change `url=sample.input_data.get("url", "")` to `raw_url=sample.input_data.get("url", "")` in `backend/app/evaluation/runner.py:93`.
2. **Fix React Hook Order in IncidentDrawer:** Move the `useState` calls above the `if (!incident) return null;` guard in `frontend/src/components/IncidentDrawer.jsx`.
3. **Implement Real Multipart Upload Handlers:** Add `UploadFile = File(...)` endpoints in `analyze.py` for direct image (`.jpg`, `.png`) and audio (`.wav`, `.mp3`) drag-and-drop file ingestion.
4. **Wire Browser Shield Popup to Frontend Dashboard:** Update `browser-shield/src/popup/popup.js` so "Investigate in ORION" opens `http://localhost:5173?incident=${incident.id}` instead of the raw backend API.
5. **Calibrate or Connect Local Hugging Face / Transformers:** Migrate simulated model proxies (URLBERT, W2V2-AASIST, ECAPA-TDNN) to either live on-device ONNX runtime models or verified cloud inference pipelines with transparent confidence calibration.
6. **Initialize Git Repository:** Initialize a clean Git repository (`git init`) once git is installed or configured, committing the Phase 0 baseline.
