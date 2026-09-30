# ORION v2 — Master Project Specification
## AI-Powered Cyber Threat Intelligence & Digital Trust Platform
### BPUT Hackathon PS09 — CYBERGUARD

**Status:** Frozen implementation specification  
**Product:** ORION  
**Problem Statement:** PS09 — CYBERGUARD  
**Primary demo chain:** Detection → Classification → Risk Assessment → Explanation → Alert → Recommended Response

---

# 1. Product Definition

ORION is an AI-powered cyber defence and digital trust platform designed around two protection layers:

1. **Human layer**
   - phishing and social engineering
   - digital impersonation
   - AI-generated content
   - deepfake images/video
   - voice cloning/audio impersonation

2. **Technology layer**
   - credential theft
   - account takeover
   - abnormal authentication behaviour
   - suspicious URLs/websites
   - API/system/network anomalies

ORION converts raw digital signals into:

**Input → Evidence → Detection → Classification → Risk → Explanation → Incident → Response Recommendation**

ORION is the product identity. **CYBERGUARD** is the PS09 problem-statement concept.

---

# 2. PS09 Traceability

The official PS09 requires a working prototype covering at least three cybersecurity scenarios and specifically identifies phishing/social engineering, digital impersonation/deepfake/identity fraud, and technical threats/abnormal behaviour as preferred coverage.

ORION therefore freezes these three primary demo scenarios:

| Scenario | ORION module | Priority |
|---|---|---|
| AI-powered phishing + malicious URL | Web & Phishing Intelligence | MUST |
| Digital impersonation + deepfake + AI-generated media + voice cloning | Identity & Media Intelligence | MUST |
| Account takeover + abnormal authentication behaviour | Behavioural Security | MUST |

Additional PS09 capabilities such as QR phishing, system/API/network indicators, threat intelligence, graph analysis and MITRE mapping are implemented where practical or exposed through extension points.

The PS09 dashboard requirements are first-class requirements, not optional UI decoration.

---

# 3. Core Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                         ORION CLIENTS                            │
│                                                                 │
│  Command Center │ Analyze │ Browser Shield │ Future Android     │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                         FastAPI API Gateway
                                │
                    Intelligence Orchestrator
                                │
       ┌────────────────────────┼────────────────────────┐
       │                        │                        │
       ▼                        ▼                        ▼
 Web/Phishing            Identity/Media          Behaviour/ATO
 Intelligence            Intelligence             Intelligence
       │                        │                        │
       └────────────────────────┼────────────────────────┘
                                ▼
                       Provider Gateway
                                │
                       Evidence Normalizer
                                │
                         Evidence Fusion
                                │
                      Threat Classification
                                │
                     Deterministic Risk Engine
                                │
                         Explainability
                                │
                    Response Recommendation
                                │
                       Canonical Incident
                                │
                  ┌─────────────┴─────────────┐
                  ▼                           ▼
               SQLite                  SOC Dashboard
```

### Architectural rule

Detection providers may change. The following contracts must not:

- AnalysisRequest
- Evidence
- ProviderResult
- ThreatClassification
- RiskAssessment
- Explanation
- ResponseRecommendation
- Incident

---

# 4. First-Class Product Surfaces

```text
ORION
├── COMMAND CENTER
│   ├── Total Events
│   ├── Threats Detected
│   ├── Risk Distribution
│   ├── Phishing
│   ├── Impersonation
│   ├── Deepfake
│   ├── Voice Clone
│   ├── Account Takeover
│   ├── Attack Timeline
│   ├── Targeted Users/Services
│   └── Incident Status
│
├── ANALYZE
│   ├── URL / Website
│   ├── Email / Message
│   ├── Image
│   ├── Video
│   ├── Audio
│   └── Authentication Event
│
├── BROWSER SHIELD
│   ├── Extension Status
│   ├── Current Page Analysis
│   ├── Recent Warnings
│   ├── Block/Warning Events
│   └── Investigate in ORION
│
├── INCIDENTS
│   ├── All
│   ├── Active
│   ├── High/Critical
│   └── Incident Detail
│
├── INTELLIGENCE
│   ├── Entities
│   ├── Relationships
│   ├── Attack Chains
│   └── Threat Intelligence
│
├── EVALUATION
│   ├── Dataset
│   ├── Metrics
│   ├── Confusion Matrix
│   └── Model/Provider Results
│
└── SYSTEM
    ├── Provider Health
    ├── Analysis Health
    └── Configuration
```

---

# 5. Browser Shield — Mandatory First-Class Component

Browser Shield is the actual Chrome/Edge browser extension. It is not merely a UI page.

## Flow

```text
Browser
   ↓
ORION Browser Shield
   ↓
Bounded page/security signals
   ↓
ORION /analyze/browser
   ↓
Web Intelligence
   ↓
Evidence + Classification + Risk
   ↓
Browser warning
   ↓
Investigate in ORION
```

## Signals permitted

- current URL
- hostname
- page title
- visible links
- form destinations
- presence of password fields
- visible security-relevant text/metadata
- claimed organization/brand

## Explicitly prohibited

- passwords
- keystrokes
- cookies
- authentication tokens
- session tokens
- arbitrary browsing history collection
- covert surveillance

## Extension UI

A suspicious page should display:

- **Risk:** High/Critical
- threat category
- key evidence
- explanation
- confidence/analysis status
- **Investigate in ORION**
- safe navigation option

The extension does not maintain its own risk engine or incident database. ORION remains the source of analysis truth.

---

# 6. Intelligence Module A — AI Phishing & Malicious URL Detection

## Inputs

- URL
- email
- SMS
- social-media message
- pasted message
- QR-derived URL
- website security signals

## Detection signals

### URL/domain

- look-alike domains
- suspicious TLD/domain characteristics
- excessive subdomains
- encoded URL components
- suspicious redirects
- credential-related paths
- brand/domain mismatch
- IP-address URLs
- newly observed/untrusted indicators where supported by a provider

### Message/NLP

- urgency
- credential request
- payment request
- impersonation language
- unusual communication pattern
- social-engineering language
- suspicious call-to-action
- sender/reply-to mismatch
- brand mismatch

## AI layer

Use a hybrid approach:

```text
Deterministic URL features
        +
NLP semantic classifier
        +
Threat-intelligence provider(s)
        +
Brand/entity matching
        ↓
Evidence Fusion
```

LLMs may assist structured semantic observations and explanation, but do not directly determine the final risk score.

---

# 7. Intelligence Module B — Digital Impersonation

ORION must detect attempts to impersonate:

- government officials
- senior management
- teachers/university authorities
- financial institutions
- brands/organizations
- friends/relatives
- known contacts

## Signals

- claimed identity
- communication style
- sender identity
- domain mismatch
- metadata
- profile/context mismatch
- known identity profile
- unusual request
- urgency
- payment/credential request
- media authenticity result

## Protected Identity Profiles

A protected identity can contain:

```text
identity_id
display_name
organization
known_domains
known_contact_channels
communication_features
approved_media_references
risk_policy
```

No secret credentials are stored.

---

# 8. Intelligence Module C — Deepfake & AI-Generated Media

This is a **core ORION v2 capability**, not a future-only feature.

PS09 explicitly includes manipulated images, videos, voice/audio clips, video calls and AI-generated multimedia, and lists multimodal deepfake detection and voice-cloning detection as innovation opportunities.

ORION therefore separates:

1. **Media authenticity analysis**
2. **AI-generated-content detection**
3. **Identity/impersonation analysis**
4. **Voice-cloning analysis**

These signals are fused into one incident without pretending that any detector is perfect.

---

# 9. Image Deepfake / AI-Generated Image Detection

## Input

- JPG
- PNG
- WEBP and other supported image formats

## Analysis layers

### Layer 1 — File/metadata forensics

- file signature
- EXIF presence
- software/editor metadata
- dimensions
- compression characteristics
- metadata inconsistencies

### Layer 2 — Pixel/forensic features

Where supported:

- compression anomalies
- resampling artifacts
- noise inconsistency
- edge irregularities
- face-region inconsistencies
- frequency-domain features

### Layer 3 — AI-generated image detector

A model/provider adapter may produce:

```text
ai_generated_probability
manipulation_probability
model_version
provider
confidence
```

### Layer 4 — Identity analysis

If the media claims to depict a protected identity:

```text
identity_match_signal
face_consistency_signal
context_consistency_signal
```

## Output

Never say:

> "This is definitely a deepfake."

Instead:

> "High likelihood of AI-generated/manipulated media based on the following observed indicators."

The system must distinguish:

- **Authenticity assessment**
- **AI-generation likelihood**
- **Identity impersonation risk**

---

# 10. Video Deepfake Detection

Video analysis is multimodal and should not rely on a single frame.

## Pipeline

```text
Video
 ↓
Container metadata
 ↓
Frame sampling
 ↓
Face detection/tracking
 ↓
Frame-level forensic analysis
 ↓
Temporal consistency analysis
 ↓
Optional audio analysis
 ↓
Fusion
 ↓
Authenticity assessment
```

Potential signals:

- frame-level manipulation indicators
- temporal inconsistency
- face boundary anomalies
- inconsistent lighting
- unnatural facial motion
- lip/voice synchronization anomalies
- metadata inconsistencies

The UI should expose sampled evidence rather than claiming certainty.

---

# 11. Audio Deepfake & Voice-Cloning Detection

**Voice cloning is a dedicated ORION v2 feature.**

PS09 explicitly mentions cloned voices in the background and voice-cloning detection in its innovation opportunities.

## Input

- WAV
- MP3
- M4A and supported audio formats

## Pipeline

```text
Audio
 ↓
Format/metadata validation
 ↓
Audio normalization
 ↓
Speech segmentation
 ↓
Acoustic feature extraction
 ↓
Synthetic-speech / voice-clone detector
 ↓
Speaker/identity comparison where authorized
 ↓
Context analysis
 ↓
Evidence Fusion
```

## Audio signals

Potential evidence includes:

- spectral irregularities
- unnatural prosody
- abnormal pitch transitions
- vocoder/synthesis artifacts
- phase characteristics
- frequency-domain anomalies
- speaker embedding similarity where a reference voice is authorized
- transcript semantics
- unusual urgency/payment/credential requests

## Voice impersonation scenario

Example:

```text
Incoming audio:
"Hi, this is the finance head. Transfer the payment immediately."

Signals:
- claimed identity = finance head
- voice similarity = high
- synthetic speech probability = elevated
- urgent financial request = elevated
- communication channel = unusual
```

ORION should combine these into an **impersonation incident**, not treat voice similarity alone as proof.

## Important distinction

```text
Voice similarity ≠ voice authenticity
Voice-clone probability ≠ identity proof
AI-generated probability ≠ malicious intent
```

The incident engine must keep these as separate evidence dimensions.

---

# 12. Multimodal Deepfake Fusion

For a video containing both face and voice:

```text
Video
 ├── Visual authenticity
 ├── Facial consistency
 ├── Temporal consistency
 ├── Audio authenticity
 ├── Voice-clone likelihood
 ├── Lip-sync consistency
 └── Identity/context analysis
          ↓
      Evidence Fusion
          ↓
   Authenticity Assessment
          +
    Impersonation Risk
```

This is one of ORION's major differentiation points.

---

# 13. AI Detection Is Not a Single Boolean

ORION must never implement:

```text
AI_DETECTED = true
```

as a universal truth.

Instead:

```text
AI-generation likelihood
Manipulation likelihood
Authenticity confidence
Identity confidence
Threat confidence
```

are separate values.

Example:

```json
{
  "ai_generated_probability": 0.87,
  "manipulation_probability": 0.79,
  "identity_match_probability": 0.91,
  "threat_confidence": 0.84
}
```

These values become evidence for the deterministic risk engine.

---

# 14. Media Provider Gateway

All media models/providers must use adapters.

```text
MediaProvider
├── ImageAuthenticityProvider
├── VideoAuthenticityProvider
├── AudioAuthenticityProvider
├── VoiceCloneProvider
└── IdentityVerificationProvider
```

Provider result:

```json
{
  "provider": "example_provider",
  "model_version": "x.y",
  "status": "ok",
  "observations": [],
  "scores": {},
  "latency_ms": 0
}
```

Provider failure must produce:

```text
UNKNOWN / INCONCLUSIVE
```

It must never silently become:

```text
SAFE
```

---

# 15. Intelligence Module D — Authentication & Account Takeover

## Inputs

- login event
- logout/session event
- IP/device information
- timestamp
- location where authorized
- authentication result
- session behaviour

## Detection signals

- repeated failed logins
- password spraying pattern
- new device
- new location
- unusual time
- impossible/suspicious travel pattern where valid data exists
- session anomaly
- sudden behaviour change
- unusual privilege/resource access

## Behaviour model

Use deterministic features first, then optional anomaly detection:

- rolling baseline
- z-score/robust deviation
- Isolation Forest or similar model
- temporal features

No fabricated model accuracy.

---

# 16. Universal Evidence Model

Every detector outputs evidence.

```text
Evidence
├── type
├── source
├── value
├── confidence
├── severity_contribution
├── timestamp
├── entity_refs
└── explanation
```

Examples:

```text
brand_lookalike
credential_request
urgent_language
ai_generated_probability
voice_clone_probability
face_manipulation_indicator
lip_sync_anomaly
new_device
failed_login_burst
```

Evidence is the universal language across all ORION modules.

---

# 17. Threat Classification

Every analysis produces:

```text
threat_type
assessment
confidence
```

Example threat types:

- phishing
- malicious_url
- impersonation
- deepfake_image
- deepfake_video
- synthetic_audio
- voice_clone
- credential_theft
- account_takeover
- authentication_anomaly
- malware_indicator
- suspicious_network_activity
- api_abuse
- abnormal_user_activity

Assessment:

```text
SAFE
SUSPICIOUS
MALICIOUS
INCONCLUSIVE
```

---

# 18. Deterministic Risk Engine

Risk levels:

```text
SAFE → LOW → MEDIUM → HIGH → CRITICAL
```

The risk engine consumes evidence rather than trusting a provider's final verdict.

Example conceptual model:

```text
Risk =
    base threat evidence
  + identity/impact factors
  + behavioural factors
  + provider evidence
  + policy floors
  - trusted/mitigating evidence
```

The exact weights belong in a versioned configuration file.

Every score must expose its major evidence drivers.

---

# 19. Explainable AI

ORION must answer:

> Why did the system produce this assessment?

Example:

```text
HIGH RISK — Suspected Voice Impersonation

Evidence:
+ Voice-clone detector produced elevated synthetic-speech probability
+ Claimed identity matches a protected finance executive
+ Audio requests an urgent financial transfer
+ Communication channel differs from the identity's known channels

Recommended:
Verify through an independent trusted channel.
Do not execute the requested transfer until identity is confirmed.
```

For deepfakes:

```text
HIGH RISK — Suspected AI-Manipulated Media

Evidence:
+ Multiple forensic indicators
+ AI-generation detector produced elevated probability
+ Facial/temporal consistency anomalies
+ Media is being used to impersonate a protected identity
```

The explanation must be grounded in actual evidence.

---

# 20. Response Recommendation Engine

Recommended actions include:

- block suspicious URL
- warn user
- quarantine email
- require additional authentication
- revoke session
- block suspicious device/IP
- flag media for manual verification
- report impersonation
- notify administrator/SOC
- escalate incident

For media:

```text
Flag for manual verification
Verify identity through an independent channel
Do not rely on the suspicious media as sole proof
Preserve original evidence
Escalate to security team
```

ORION is advisory by default. Destructive autonomous remediation is outside the prototype boundary.

---

# 21. Canonical Incident

Every threat becomes an incident.

```text
Incident
├── id
├── timestamp
├── source
├── input_type
├── threat_type
├── assessment
├── risk_level
├── risk_score
├── confidence
├── evidence[]
├── explanation
├── recommended_actions[]
├── entities[]
├── status
└── analysis_run_id
```

Incident states:

```text
NEW
ACKNOWLEDGED
INVESTIGATING
RESOLVED
FALSE_POSITIVE
```

---

# 22. Command Center Dashboard — Mandatory

The dashboard must directly map to PS09.

## KPI cards

- Total events analysed
- Threats detected
- High/Critical incidents
- Phishing attempts
- Impersonation attempts
- Suspected deepfakes
- Suspected AI-generated media
- Voice-cloning incidents
- Account takeover attempts

## Visualizations

- risk distribution
- threat category distribution
- attack timeline
- incident status
- frequently targeted users/services
- threat-source distribution

## Operations

- incident table
- severity filter
- threat-type filter
- status filter
- time filter
- recommended actions
- incident detail navigation

## Live demo

The dashboard must update from real persisted incident data, not hardcoded fake counters.

---

# 23. Incident Detail

A judge should be able to open an incident and see:

```text
Threat
Risk
Confidence
Input
Evidence
Detection Results
AI/ML Results
Explanation
Risk Drivers
Entities
Timeline
Recommended Response
Provider Results
Incident Status
```

For media incidents additionally show:

```text
media preview
authenticity assessment
AI-generation likelihood
manipulation indicators
voice-clone result
identity/context result
```

---

# 24. Intelligence & Correlation

Entities may include:

- people
- organizations
- domains
- URLs
- IPs
- devices
- email addresses
- phone numbers
- media hashes

Correlation examples:

```text
Phishing URL
    ↓
Targeted employee
    ↓
Suspicious login
    ↓
New device
    ↓
ATO incident
```

or:

```text
Fake executive profile
    ↓
Voice-cloned call
    ↓
Urgent payment request
    ↓
Impersonation incident
```

Graph correlation is an enhancement after the core three verticals are stable.

---

# 25. Evaluation

Evaluation must use real, reproducible datasets or clearly labelled simulated/authorized data.

Never hardcode claimed accuracy.

## Required metrics

Depending on the detector:

- precision
- recall
- F1
- accuracy where appropriate
- ROC-AUC where meaningful
- false-positive rate
- false-negative rate
- latency
- throughput

## Media evaluation

Report results separately for:

- image authenticity
- video authenticity
- synthetic audio
- voice cloning
- identity/context analysis

Do not combine incompatible metrics into one misleading score.

## Evaluation UI

Show:

- dataset name/version
- model/provider
- sample count
- metrics
- confusion matrix
- evaluation timestamp
- configuration/model version

---

# 26. Model & Algorithm Registry

Create `docs/models.md`.

For every model:

```text
Name
Purpose
Modality
Version
Dataset
Training/evaluation method
Input
Output
Threshold
Known limitations
Provider
License
```

Potential technology families:

- NLP classifier
- URL feature model
- anomaly detection
- computer vision model
- media forensic model
- synthetic speech detector
- speaker embedding model
- LLM-assisted structured analysis

No model may be presented as more capable than the evidence supports.

---

# 27. Dataset Registry

Create `docs/datasets.md`.

Every dataset must state:

- name
- source
- license/usage conditions
- modality
- classes
- number of samples
- preprocessing
- train/test split
- limitations
- evaluation purpose

Use simulated, authorized or publicly available cybersecurity data in accordance with PS09.

---

# 28. API Contract

Core:

```text
POST /api/v1/analyze/url
POST /api/v1/analyze/message
POST /api/v1/analyze/image
POST /api/v1/analyze/video
POST /api/v1/analyze/audio
POST /api/v1/analyze/auth-event
POST /api/v1/analyze/browser
```

Incidents:

```text
GET  /api/v1/incidents
GET  /api/v1/incidents/{id}
PATCH /api/v1/incidents/{id}/status
```

Dashboard:

```text
GET /api/v1/dashboard/summary
GET /api/v1/dashboard/timeline
GET /api/v1/dashboard/categories
GET /api/v1/dashboard/targets
```

System:

```text
GET /api/v1/system/providers
GET /api/v1/system/health
```

---

# 29. Repository Structure

```text
orion/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── engines/
│   │   │   ├── phishing/
│   │   │   ├── media/
│   │   │   ├── identity/
│   │   │   └── behaviour/
│   │   ├── providers/
│   │   │   ├── base.py
│   │   │   ├── web/
│   │   │   ├── threat_intel/
│   │   │   ├── media/
│   │   │   └── audio/
│   │   ├── risk/
│   │   ├── explainability/
│   │   ├── response/
│   │   └── repositories/
│   └── tests/
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   ├── components/
│   │   ├── charts/
│   │   ├── services/
│   │   └── types/
│
├── browser-shield/
│   ├── manifest.json
│   ├── src/
│   │   ├── content/
│   │   ├── background/
│   │   ├── popup/
│   │   └── api/
│   └── README.md
│
├── data/
│   ├── fixtures/
│   └── samples/
│
├── docs/
│   ├── architecture.md
│   ├── models.md
│   ├── datasets.md
│   ├── evaluation.md
│   ├── deployment.md
│   └── ps09-compliance.md
│
├── scripts/
│   ├── seed_demo.py
│   ├── evaluate.py
│   └── benchmark.py
│
└── README.md
```

---

# 30. Development Phases

## Phase 0 — Foundation

Build:

- repository
- FastAPI
- React
- SQLite
- schemas
- repositories
- canonical analysis contract
- evidence model
- incident model
- provider interface
- tests

Exit:

```text
Input → Evidence → Risk → Incident → Persistence
```

---

## Phase 1 — Intelligence Core

Build:

- evidence normalization
- evidence fusion
- classification
- deterministic risk engine
- explanations
- response recommendations
- incident creation

Exit: one deterministic analysis produces a complete persisted incident.

---

## Phase 2 — Web & Phishing

Build:

- URL analyzer
- message analyzer
- phishing NLP
- URL feature engine
- brand similarity
- threat intelligence adapter
- QR flow where practical
- Browser Shield extension

Exit:

**same phishing engine works from both ORION UI and Browser Shield.**

---

## Phase 3 — Identity, Deepfake & AI Media

Build:

- image ingestion
- image forensic analysis
- AI-generated image detection adapter
- video frame sampling
- video authenticity adapter
- audio ingestion
- synthetic speech/voice-clone adapter
- identity profiles
- impersonation analysis
- multimodal evidence fusion

Exit:

A single demo can show:

```text
AI-generated/deepfake media
        +
voice clone
        +
claimed identity
        +
social-engineering request
        ↓
IMPERSIONATION INCIDENT
```

---

## Phase 4 — Behaviour / ATO

Build:

- authentication schema
- baseline features
- failed-login detection
- new device/location detection
- anomaly model
- ATO classification
- response recommendation

Exit: realistic abnormal authentication event becomes a persisted incident.

---

## Phase 5 — Command Center

Build the complete PS09 dashboard:

- KPI cards
- risk distribution
- category distribution
- phishing count
- impersonation count
- deepfake count
- voice clone count
- ATO count
- timeline
- targeted users/services
- incident table
- recommended actions
- incident status
- provider health

Exit: judge can understand ORION from the dashboard without a separate explanation.

---

## Phase 6 — Correlation & Intelligence

Build:

- entity registry
- relationships
- cross-incident correlation
- attack chains
- threat intelligence view
- optional MITRE ATT&CK mapping

Only start this after the three core verticals are stable.

---

## Phase 7 — Evaluation & PS09 Documentation

Build:

- evaluation datasets
- evaluation scripts
- metrics
- model registry
- dataset registry
- architecture documentation
- deployment documentation
- PS09 compliance matrix

Exit: every claimed metric can be reproduced.

---

## Phase 8 — Demo Hardening

Verify:

- clean installation
- seeded demo
- provider failures
- empty states
- loading states
- invalid files
- oversized files
- API failures
- extension failure mode
- database persistence
- security boundaries
- frontend build
- backend tests

Freeze features before the final presentation.

---

# 31. Three Golden Demo Scenarios

## Demo 1 — Phishing

```text
Open suspicious URL in Browser Shield
        ↓
ORION detects look-alike domain
        ↓
Credential request detected
        ↓
Urgency detected
        ↓
Threat classified as phishing
        ↓
HIGH/CRITICAL risk
        ↓
Browser warning
        ↓
Incident appears in Command Center
```

---

## Demo 2 — Deepfake + Voice Clone + Impersonation

```text
Upload suspicious video/audio
        ↓
Visual authenticity analysis
        +
AI-generated media analysis
        +
Voice-clone analysis
        +
Protected identity analysis
        +
Message/request semantics
        ↓
Evidence fusion
        ↓
Digital impersonation
        ↓
Risk assessment
        ↓
Explainable evidence
        ↓
Manual verification recommendation
        ↓
Incident on dashboard
```

This is the flagship human-layer demo.

---

## Demo 3 — Account Takeover

```text
Authentication events
        ↓
Failed-login burst
        +
New device
        +
Unusual location/time
        ↓
Behavioural anomaly
        ↓
ATO classification
        ↓
HIGH risk
        ↓
Require MFA / revoke session recommendation
        ↓
SOC incident
```

---

# 32. Security & Privacy Boundaries

ORION must not:

- collect passwords
- collect keystrokes
- collect cookies
- collect session tokens
- perform unauthorized exploitation
- perform unauthorized scanning
- conduct arbitrary crawling
- silently monitor users
- claim certainty where the model is probabilistic
- fabricate metrics
- fabricate provider results

Media and identity analysis must use authorized or public/synthetic inputs.

---

# 33. Failure Handling

Provider failure:

```text
Provider unavailable
      ↓
status = inconclusive
      ↓
retain available evidence
      ↓
risk engine applies uncertainty policy
      ↓
explanation states limitation
```

Never:

```text
provider failed → SAFE
```

For extension/API failure:

```text
ORION unavailable
      ↓
extension does not claim the site is safe
      ↓
show analysis unavailable
      ↓
user can proceed only according to configured safe-failure policy
```

---

# 34. Innovation Priorities

## MUST / Core

- AI-assisted phishing detection
- Browser Shield
- digital impersonation
- deepfake analysis
- AI-generated media detection
- voice-cloning detection
- explainable risk
- behavioural ATO detection
- command dashboard

## SHOULD

- multimodal fusion
- email sender authenticity
- QR phishing
- threat intelligence
- entity correlation
- MITRE ATT&CK mapping

## COULD

- graph-based attack analysis
- richer real-time feeds
- additional media models
- advanced anomaly models

## ROADMAP

- federated learning
- privacy-preserving distributed training
- autonomous cyber-defence agents
- full automated response playbooks
- production-scale multi-tenant deployment

The roadmap exists so the architecture demonstrates scalability without pretending all advanced research features are already production-ready.

---

# 35. Scalability

Prototype:

```text
React
FastAPI
SQLite
Local/remote model adapters
```

Production evolution:

```text
React
 ↓
API Gateway
 ↓
FastAPI service layer
 ↓
Task queue
 ↓
Analysis workers
 ├── phishing workers
 ├── media workers
 ├── audio workers
 ├── behaviour workers
 └── enrichment workers
 ↓
PostgreSQL
 ↓
Object storage
 ↓
Redis/cache
 ↓
SOC dashboard
```

Media files should move to object storage in production rather than remain in the relational database.

---

# 36. Definition of Done

ORION v2 is complete for the PS09 prototype when all of the following are true:

### Detection

- [ ] phishing detection works
- [ ] malicious URL analysis works
- [ ] impersonation detection works
- [ ] image AI/deepfake analysis works
- [ ] video analysis path works
- [ ] audio/voice-clone analysis path works
- [ ] authentication anomaly/ATO detection works

### Intelligence

- [ ] evidence is normalized
- [ ] multiple evidence sources can be fused
- [ ] threat classification is explicit
- [ ] risk score is deterministic/configured
- [ ] explanations reference actual evidence
- [ ] response recommendations are generated

### Browser Shield

- [ ] Chrome/Edge extension loads
- [ ] current URL can be analyzed
- [ ] warning UI works
- [ ] evidence is visible
- [ ] investigate-in-ORION works
- [ ] prohibited data is not collected

### Dashboard

- [ ] all PS09 dashboard fields exist
- [ ] dashboard uses persisted data
- [ ] deepfake and voice-clone incidents are visible
- [ ] attack timeline exists
- [ ] targeted users/services exist
- [ ] incident status exists

### Evaluation

- [ ] datasets are documented
- [ ] models/providers are documented
- [ ] metrics are reproducible
- [ ] no fabricated performance numbers exist

### Documentation

- [ ] architecture
- [ ] model registry
- [ ] dataset registry
- [ ] evaluation
- [ ] deployment/scalability
- [ ] PS09 compliance matrix

---

# 37. Final Engineering Contract

1. **Do not build UI around fake backend capabilities.**
2. **Do not call a provider's verdict the system's final truth.**
3. **Evidence drives risk.**
4. **Risk is separate from detection.**
5. **AI-generated does not automatically mean malicious.**
6. **Voice similarity does not prove identity.**
7. **Voice-clone probability does not prove fraud.**
8. **Deepfake probability does not prove malicious intent.**
9. **Media authenticity and impersonation are separate signals that may be fused.**
10. **Provider failure means uncertainty, not safety.**
11. **No fabricated metrics.**
12. **Browser Shield is a first-class ORION client.**
13. **The Command Center is a first-class PS09 deliverable.**
14. **Every incident must be explainable from stored evidence.**
15. **The three required scenarios must remain stable before optional innovation is added.**
16. **All advanced capabilities must be implemented through replaceable adapters.**
17. **Use only synthetic, authorized or publicly available data.**
18. **No destructive autonomous remediation in the prototype.**

---

# 38. ORION v2 Final Product Picture

```text
                         ORION v2
        AI Cyber Defence & Digital Trust Platform

 ┌─────────────────────────────────────────────────────────┐
 │                    COMMAND CENTER                       │
 │ Threats │ Risk │ Phishing │ Deepfake │ Voice Clone │ ATO│
 └──────────────────────────┬──────────────────────────────┘
                            │
        ┌───────────────────┼────────────────────┐
        │                   │                    │
        ▼                   ▼                    ▼
  BROWSER SHIELD      MEDIA & IDENTITY       BEHAVIOUR
  Phishing/URLs       Deepfake/AI Media      ATO/Anomaly
        │             Voice Cloning               │
        └───────────────────┼────────────────────┘
                            ▼
                    EVIDENCE FUSION
                            ▼
                     CLASSIFICATION
                            ▼
                       RISK ENGINE
                            ▼
                      EXPLAINABILITY
                            ▼
                  RESPONSE RECOMMENDATION
                            ▼
                       INCIDENT
                            ▼
                     SOC DASHBOARD
```

**The central differentiator is not a single model. It is the complete evidence-to-action pipeline across human and technology-layer threats, with phishing, deepfake/AI-generated media, voice cloning, impersonation and account takeover represented inside one coherent incident system.**
