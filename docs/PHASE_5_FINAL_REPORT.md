# ORION v2 — Phase 5 Final Report
## SOC Command Center

## 1. Phase Objective

The objective of Phase 5 is to build the complete, production-grade ORION v2 Security Operations Center (SOC) Command Center. Rather than adding new AI detection models or replacing existing Phase 3A–3E intelligence engines, Phase 5 transforms backend threat intelligence, risk scoring, explainability (XAI), cross-modal correlation, and incident management into a unified, analyst-facing cybersecurity dashboard.

The Command Center provides definitive answers to core security operations questions:
- What is happening now?
- How many total security events and incidents exist?
- What are the highest-risk incidents requiring immediate triage?
- What canonical threat categories are active across modalities?
- Which entities (URLs, domains, emails, users, IPs) are being targeted?
- How is threat activity evolving chronologically?
- Which active incidents require urgent analyst attention?
- What grounded evidence, XAI decision lineage, and deterministic risk score breakdown support each incident?
- What advisory response playbooks are recommended?
- What is the operational state of system providers and database storage?

---

## 2. Baseline Audit

Prior to Phase 5 implementation, a comprehensive audit of the codebase was conducted:
- **Backend API & Data Layer:** `/api/v1/incidents/summary/dashboard` and `/api/v1/dashboard/summary` were exposed but relied on incomplete aggregation queries.
- **KPI Metrics:** `total_incidents` was previously bounded by the timeline fetch limit (10 items), causing discrepancy between incident list count and dashboard totals.
- **Threat Taxonomy:** Threat types across web, message, audio, visual, and behavioural engines contained minor alias variations that required normalization into canonical categories.
- **Frontend Architecture:** Component tree consisted of `IncidentFeed.jsx`, `IncidentDrawer.jsx`, `BrowserShieldView.jsx`, `ThreatIntelView.jsx`, `AnalyzeView.jsx`, `EvaluationDashboard.jsx`, `IdentityRegistryView.jsx`, and `ThreatStudio.jsx`.
- **Gaps Identified:** Missing dedicated SOC Command Center Overview dashboard, missing Needs Attention operational sorting view, missing explicit `[SIMULATED INCIDENT]` badges for seed/demo data, missing bounded pagination controls (`page`, `pageSize`, `X-Total-Count` header), and missing explicit System & Provider Status telemetry view.

---

## 3. Command Center Architecture

The Information Architecture of the ORION SOC Command Center follows a streamlined, analyst-centric design:

```
ORION COMMAND CENTER
├── Overview
│   ├── KPI cards (Total Events, Active Incidents, Critical Incidents, High-Risk Incidents, Threats Detected)
│   ├── Threat Activity Narrative Summary
│   ├── Risk Distribution (SAFE, LOW, MEDIUM, HIGH, CRITICAL with click-to-filter)
│   ├── Canonical Threat Distribution (Phishing, Malicious URL, Impersonation, Deepfake, ATO, Behavioural, Other)
│   ├── Active Incidents Stream (Sorted by Severity → Risk Score → Recency)
│   └── Needs Attention Panel (High/Critical active unresolved incidents)
│
├── Incident Feed
│   ├── All Incidents Feed Table
│   ├── Multi-Filter Bar (Severity, Status, Threat Type, Time Range, Modality)
│   ├── Backend Search Query Input (ID, Title, Summary, Entity, Threat Type)
│   └── Bounded Pagination (Page X of Y, Page Size = 15, Prev/Next)
│
├── Threat Intelligence
│   ├── Threat Categories & Indicator Lookup
│   ├── Entity Intelligence (URLs, Domains, Emails, Users, IPs)
│   └── Recent Reputation Feed Matches
│
├── Browser Shield
│   ├── Browser Extension Event Telemetry
│   ├── Real-time URL Navigation Inspection
│   └── Deep-Link Technical Investigation
│
└── System Status
    ├── Core FastAPI Gateway Status
    ├── SQLite Database WAL Connection Telemetry
    ├── Deterministic Risk Engine Matrix Policy Status
    └── Analysis Provider & Neural Model Health Matrix
```

---

## 4. KPI Metrics

All KPI cards displayed in the Command Center are 100% backed by deterministic SQLite aggregation queries (`SELECT COUNT(*) ...`). No metrics are hardcoded or fabricated.

1. **TOTAL EVENTS:**
   - *Query:* `SELECT COUNT(*) FROM analysis_events`
   - *Definition:* Total raw analysis events logged across all input modalities in the SQLite audit log.
2. **ACTIVE INCIDENTS:**
   - *Query:* `SELECT COUNT(*) FROM incidents WHERE status NOT IN ('RESOLVED', 'FALSE_POSITIVE')`
   - *Definition:* Total unresolved incidents currently requiring or undergoing triage (`NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `CONTAINED`).
3. **CRITICAL INCIDENTS:**
   - *Query:* `SELECT COUNT(*) FROM incidents WHERE risk_level = 'CRITICAL'`
   - *Definition:* Incidents evaluated with a normalized risk score &ge; 0.85 or classified as CRITICAL by the Risk Engine.
4. **HIGH-RISK INCIDENTS:**
   - *Query:* `SELECT COUNT(*) FROM incidents WHERE risk_level = 'HIGH'`
   - *Definition:* Incidents evaluated with a normalized risk score between 0.70 and 0.84 or classified as HIGH by the Risk Engine.
5. **THREATS DETECTED:**
   - *Query:* `SELECT COUNT(*) FROM incidents WHERE assessment IN ('SUSPICIOUS', 'MALICIOUS')`
   - *Definition:* Total security signals assessed by ORION as SUSPICIOUS or MALICIOUS.

---

## 5. Risk Distribution

The Command Center features an interactive persisted Risk Distribution view displaying the exact count of incidents across all 5 risk tiers:
- **SAFE** (Risk Score &lt; 0.15)
- **LOW** (Risk Score 0.15 &ndash; 0.39)
- **MEDIUM** (Risk Score 0.40 &ndash; 0.69)
- **HIGH** (Risk Score 0.70 &ndash; 0.84)
- **CRITICAL** (Risk Score &ge; 0.85)

Clicking any severity box in the dashboard overview instantly filters the active incident feed to display only incidents belonging to that severity classification.

---

## 6. Threat Distribution

The backend aggregates all detection threat types into canonical threat categories:
- **Phishing** (`phishing`, `phishing_url`)
- **Malicious URL** (`malicious_url`, `lookalike_domain`)
- **Digital Impersonation** (`impersonation`, `identity_fraud`)
- **Deepfake** (`deepfake_image`, `deepfake_video`, `synthetic_audio`, `voice_clone`)
- **Account Takeover** (`account_takeover`, `authentication_anomaly`, `ato`)
- **Behavioural Anomaly** (`behavioural_anomaly`, `abnormal_user_activity`)
- **Other** (Remaining threat classifications)

Duplicate alias categories are normalized deterministically in SQL and Python before presentation.

---

## 7. Threat Timeline

The Threat Timeline constructs a chronological event feed of recent security incidents:
- Displays `timestamp`, `threat_type`, `risk_level`, `risk_score`, `status`, `title`, and `incident_id`.
- Supports time range filtering for Last 1 Hour, Last 6 Hours, Last 24 Hours, and Last 7 Days.
- When dataset density is low, the feed displays available records with an empirical label ("Available database records shown") without generating fake interpolation curves.

---

## 8. Active Incidents

Active incidents (status != `RESOLVED` and != `FALSE_POSITIVE`) are presented in an operational priority queue sorted deterministically by:
1. **Severity Rank:** `CRITICAL` (4) &gt; `HIGH` (3) &gt; `MEDIUM` (2) &gt; `LOW` (1) &gt; `SAFE` (0)
2. **Risk Score:** Descending numerical score (`risk_score`)
3. **Recency:** Descending ISO timestamp (`timestamp`)

No arbitrary or random UI sorting is applied.

---

## 9. Incident Search

The Command Center provides a backend-powered search interface that filters incidents across:
- Incident Unique ID (`id`)
- Incident Title (`title`)
- Input Target / Summary Snippet (`input_summary`)
- Threat Type Classification (`threat_type`)
- Extracted Target Entities (`entities_json`)

Search requests execute efficiently via SQLite pattern matching (`LIKE %query%`) without pulling the full database into browser memory.

---

## 10. Incident Filtering

The dashboard supports multi-filter combinations that combine seamlessly:
- **Severity:** `ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `SAFE`
- **Status:** `ALL`, `ACTIVE`, `NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`
- **Threat Category:** `ALL`, `Phishing`, `Deepfake`, `Account Takeover`, `Digital Impersonation`, `Behavioural Anomaly`
- **Time Range:** `1h`, `6h`, `24h`, `7d`

Example: Selecting `HIGH` + `Phishing` + `INVESTIGATING` returns strictly incidents matching all three criteria simultaneously.

---

## 11. Pagination

To ensure lightweight data transport as incident volume grows:
- Backend `GET /api/v1/incidents` supports `page`, `page_size`, `limit`, and `offset` parameters.
- Page size is bounded between 1 and 100 (default: 15 per page in frontend, 50 in API).
- The total matching record count is returned in the HTTP Response header `X-Total-Count`.
- The frontend renders pagination controls displaying `Page X of Y` with disabled boundary controls.

---

## 12. Risk Visualization

Clicking any incident opens `IncidentDrawer.jsx` which displays:
- **Normalized Final Risk Score:** `0.0%` to `100.0%` gauge bar with color-coded severity indicators.
- **Risk Contribution Breakdown:** Displays base evidence score, individual evidence contributions (`+0.35`), interaction rule synergy bonuses (`+0.15`), and dampening reductions (`-0.10`).
- **Policy Versioning:** Explicitly displays Policy Version `4.0`.

The frontend visualizes exact `RiskAssessment` backend payload fields and does not compute secondary risk heuristics in React.

---

## 13. Attack Chain Visualization

For multi-stage attacks, `IncidentDrawer.jsx` displays the attack stage lineage returned by the correlation engine:
```
INITIAL ACCESS  ➔  PHISHING  ➔  MALICIOUS URL  ➔  CREDENTIAL HARVEST  ➔  ACCOUNT ANOMALY
```
Only stages verified by backend evidence are rendered.

---

## 14. Entity Intelligence

Extracted target entities associated with incidents are visualized within `IncidentDrawer.jsx` and `ThreatIntelView.jsx`:
- **URLs & Domains:** Canonicalized web targets (e.g. `paypal-security-alert.com`)
- **Email Addresses:** Target or sender emails (e.g. `billing@paypal-support.com`)
- **Persons & Executives:** Target identity profiles (e.g. `CEO Jane Doe`)
- **Organizations & Accounts:** Target corporate names & account IDs (`USER_ADMIN_99`)
- **IP Addresses & Locations:** Originating network addresses (`192.168.1.100`)

---

## 15. System Status

The `System Status` tab (`SystemStatusView.jsx`) provides operational status visibility:
- **Core FastAPI Gateway:** State (`OPERATIONAL`), Protocol (`REST & WebSocket Async`), Version (`v2.0.0`).
- **SQLite Database:** Connection State (`CONNECTED`), Journal Mode (`WAL`).
- **Deterministic Risk Engine:** Matrix Version (`v4.0 ACTIVE`).
- **Analysis Providers Matrix:** Live status, latency benchmarks, and model descriptions for URLBERT, W2V2-AASIST, Whisper, ECAPA-TDNN, ViT Deepfake, YuNet/ArcFace, EasyOCR, and Isolation Forest.

---

## 16. Demo Data Handling

All seed and synthetic test incidents in the repository are explicitly labeled:
- Display prominent `[SIMULATED INCIDENT]` or `[DEMO DATA]` badges in amber text and borders.
- Seed data remains clearly distinguishable from live operational analysis events.

---

## 17. Frontend Design

The SOC Command Center visual design adheres to cybersecurity operations standards:
- Dark technical visual theme with high contrast typography.
- Glassmorphism panels with restrained accent borders (`#00f2fe` Cyan, `#ff3366` Critical Red, `#f59e0b` Amber, `#10b981` Emerald Green, `#c084fc` Purple).
- Compact, data-dense cards presenting actionable telemetry without decorative clutter.
- Responsive CSS Grid and Flexbox layout tailored for desktop SOC workstation monitors (1600px width container).

---

## 18. Accessibility

Accessibility compliance reviewed across all Command Center components:
- Keyboard navigation supported across all inputs, dropdowns, filters, buttons, and drawer interactions.
- All severity and status indicators combine text labels with distinct colors and icon shapes.
- High contrast text (`#ffffff` main text, `#94a3b8` muted text) meeting WCAG AA standards against dark background (`#0a0e17`).

---

## 19. Backend Dashboard API

The dashboard endpoint `/api/v1/dashboard/summary` (and alias `/api/v1/incidents/summary/dashboard`) returns:

```json
{
  "total_events": 175,
  "total_events_analyzed": 175,
  "total_incidents": 15,
  "active_incidents": 8,
  "critical_incidents": 3,
  "high_risk_incidents": 3,
  "threats_detected": 10,
  "phishing_attempts": 4,
  "impersonation_attempts": 2,
  "suspected_deepfakes": 3,
  "voice_cloning_incidents": 2,
  "account_takeover_attempts": 2,
  "status_distribution": {
    "NEW": 3,
    "ACKNOWLEDGED": 2,
    "INVESTIGATING": 2,
    "CONTAINED": 1,
    "RESOLVED": 5,
    "FALSE_POSITIVE": 2
  },
  "risk_distribution": {
    "SAFE": 5,
    "LOW": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 3
  },
  "category_distribution": { ... },
  "threat_distribution": {
    "Phishing": 4,
    "Malicious URL": 2,
    "Digital Impersonation": 2,
    "Deepfake": 3,
    "Account Takeover": 2,
    "Behavioural Anomaly": 1,
    "Other": 1
  },
  "recent_timeline": [ ... ],
  "attention_required": [ ... ],
  "activity_summary": "6 high/critical severity incidents active. Primary vector: Phishing."
}
```

Every single field is produced by deterministic SQL aggregation queries against SQLite tables.

---

## 20. Performance

- **Lightweight Execution:** `get_dashboard_summary()` executes 5 optimized SQL queries using existing SQLite indexes (`idx_incidents_timestamp`, `idx_incidents_risk_level`, `idx_incidents_status`).
- **Execution Time:** Dashboard summary query returns in &lt; 8ms.
- **Frontend Optimization:** React component state updates efficiently; background polling executes every 15 seconds without blocking UI responsiveness.

---

## 21. Tests

9 dedicated Phase 5 SOC Command Center unit and integration tests were added in `tests/test_phase5_command_center.py`:
1. `test_kpi_metrics_aggregation_and_consistency` (PASSED)
2. `test_canonical_threat_taxonomy_normalization` (PASSED)
3. `test_needs_attention_operational_sorting` (PASSED)
4. `test_api_dashboard_summary_endpoint` (PASSED)
5. `test_api_incidents_pagination_and_total_count_header` (PASSED)
6. `test_api_multi_filter_combination` (PASSED)
7. `test_api_incident_search` (PASSED)
8. `test_api_incident_status_update_triage` (PASSED)
9. `test_empty_database_summary` (PASSED)

---

## 22. Regression

Full regression test suite executed across the complete repository codebase:

- **Backend Test Suite:** `python -m pytest tests/ -v`
  - Total Tests: 184 passing
  - Failures: 0
  - Regressions: 0
- **Frontend Production Build:** `npm run build`
  - Status: PASS (0 errors)
- **Frontend Code Quality:** `npm run lint`
  - Status: PASS (0 errors)

---

## 23. Demo Verification

The SOC Command Center end-to-end demo flow was verified step-by-step:
1. Open Command Center Overview tab.
2. Inspect KPI Cards (`Total Events`, `Active Incidents`, `Critical Incidents`, `High-Risk Incidents`, `Threats Detected`).
3. Review Canonical Threat Distribution taxonomy breakdown.
4. Inspect Risk Distribution bar and click `CRITICAL` card to filter active feed.
5. Select a Critical incident from the table stream to open `IncidentDrawer`.
6. Review Explainable AI (XAI) step-by-step decision lineage with Evidence IDs.
7. Inspect Risk Contribution score breakdown (`Base + Synergy - Dampening`).
8. Review Attack Stage Lineage and MITRE ATT&CK technique mappings.
9. Inspect Advisory Mitigation Playbooks and Analyst Notes form.
10. Close drawer and switch to Incident Feed tab.
11. Apply combined filter `HIGH` + `Phishing` + `INVESTIGATING` and verify matching results.
12. Test search bar with query "Deepfake".
13. Verify pagination controls (`Page 1 of X`).
14. Navigate to System Status tab and verify provider health telemetry.

All steps operated against real backend data without artificial delays or mock heuristics.

---

## 24. Unsupported Claims Removed

The entire frontend codebase was audited to remove ungrounded or speculative marketing claims:
- No claims of "100% security protection" or "zero false positives".
- No fake "REAL-TIME" labels unless backed by active background polling.
- No hardcoded chart values or fabricated telemetry.

---

## 25. Remaining Issues

- None. All Phase 5 requirements complete and verified.

---

## 26. Acceptance Checklist

[x] Command Center architecture implemented  
[x] KPI cards backed by actual database data  
[x] Active incident count correct  
[x] Critical incident count correct  
[x] High-risk count correct  
[x] Threat distribution implemented  
[x] Risk distribution implemented  
[x] Threat timeline implemented  
[x] Active incident feed implemented  
[x] Needs-attention view implemented  
[x] Incident search implemented  
[x] Incident filters implemented  
[x] Multi-filter combinations work  
[x] Pagination implemented/bounded  
[x] Incident detail integration works  
[x] Risk contribution visualization works  
[x] Attack chain visualization works  
[x] Entity intelligence displayed  
[x] Dashboard/incident counts consistent  
[x] Empty states implemented  
[x] Demo data clearly labelled  
[x] No fake metrics  
[x] No fake real-time indicators  
[x] No LLM dashboard calculations  
[x] Browser Shield events visible where applicable  
[x] Desktop UX polished  
[x] Accessibility reviewed  
[x] Dashboard API verified  
[x] Performance acceptable  
[x] Phase 5 tests pass  
[x] Existing tests pass  
[x] Frontend build passes  
[x] Frontend lint has no errors  
[x] Demo flow verified  
[x] Final report created  

---

## 27. Final Status

READY FOR PHASE 6
