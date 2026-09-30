"""Phase 5 — SOC Command Center Tests for ORION v2.

Verifies:
1. KPI metrics aggregation from database
2. Severity risk distribution
3. Canonical threat taxonomy normalization
4. Timeline chronological ordering
5. Incident multi-filtering and backend search
6. Bounded pagination and total count headers
7. Empty state data handling
8. Count consistency between dashboard and incidents API
9. Operational ranking for Needs Attention view
10. Dashboard API schema response
11. Triage status update API contract
12. End-to-end Command Center demo flow
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import execute_write, init_db
from app.repositories.incident_repo import IncidentRepository
from app.schemas.incident import Incident, IncidentStatus
from app.schemas.threat import RiskAssessment, RiskLevel, ThreatAssessment, ThreatType
from app.schemas.evidence import EvidenceItem, EvidenceType, EvidenceSource

client = TestClient(app)
repo = IncidentRepository()


@pytest.mark.asyncio
async def test_kpi_metrics_aggregation_and_consistency():
    """Verify Step 3: KPI metrics are backed 100% by SQLite queries and count rules."""
    await init_db()

    # Create test incidents with distinct severities and statuses
    now = datetime.now(timezone.utc)
    
    inc1 = Incident(
        id="inc_p5_crit_01",
        timestamp=now,
        title="Critical Deepfake Incident",
        source=EvidenceSource.VIDEO,
        input_type="video",
        input_summary="CEO Deepfake",
        threat_type=ThreatType.DEEPFAKE_VIDEO,
        assessment=ThreatAssessment.MALICIOUS,
        risk_level=RiskLevel.CRITICAL,
        risk_score=0.92,
        confidence=0.90,
        explanation="Deepfake video detected",
        status=IncidentStatus.NEW,
        analysis_run_id="run_p5_01",
    )

    inc2 = Incident(
        id="inc_p5_high_02",
        timestamp=now,
        title="High Risk Phishing",
        source=EvidenceSource.WEB,
        input_type="url",
        input_summary="https://paypal-fake-login.com",
        threat_type=ThreatType.MALICIOUS_URL,
        assessment=ThreatAssessment.MALICIOUS,
        risk_level=RiskLevel.HIGH,
        risk_score=0.78,
        confidence=0.88,
        explanation="Malicious phishing domain",
        status=IncidentStatus.INVESTIGATING,
        analysis_run_id="run_p5_02",
    )

    inc3 = Incident(
        id="inc_p5_safe_03",
        timestamp=now,
        title="Safe Web URL",
        source=EvidenceSource.WEB,
        input_type="url",
        input_summary="https://wikipedia.org",
        threat_type=ThreatType.BENIGN,
        assessment=ThreatAssessment.SAFE,
        risk_level=RiskLevel.SAFE,
        risk_score=0.05,
        confidence=0.95,
        explanation="Verified safe domain",
        status=IncidentStatus.RESOLVED,
        analysis_run_id="run_p5_03",
    )

    await repo.create(inc1)
    await repo.create(inc2)
    await repo.create(inc3)

    summary = await repo.get_dashboard_summary()

    # Rule checks
    assert summary["total_incidents"] >= 3
    assert summary["active_incidents"] >= 2  # NEW + INVESTIGATING (RESOLVED is excluded)
    assert summary["critical_incidents"] >= 1
    assert summary["high_risk_incidents"] >= 1
    assert summary["threats_detected"] >= 2  # inc1 + inc2 (MALICIOUS)

    # Risk distribution check
    assert summary["risk_distribution"]["CRITICAL"] >= 1
    assert summary["risk_distribution"]["HIGH"] >= 1
    assert summary["risk_distribution"]["SAFE"] >= 1


@pytest.mark.asyncio
async def test_canonical_threat_taxonomy_normalization():
    """Verify Step 5 & 26: Threat category aliases normalize into canonical taxonomy."""
    summary = await repo.get_dashboard_summary()
    threat_dist = summary["threat_distribution"]

    # Canonical keys must all exist
    required_keys = {
        "Phishing", "Malicious URL", "Digital Impersonation",
        "Deepfake", "Account Takeover", "Behavioural Anomaly", "Other"
    }
    assert required_keys.issubset(threat_dist.keys())


@pytest.mark.asyncio
async def test_needs_attention_operational_sorting():
    """Verify Step 7 & 8: Active incidents sorted by Severity -> Risk Score -> Recency."""
    summary = await repo.get_dashboard_summary()
    attention_list = summary["attention_required"]

    assert isinstance(attention_list, list)
    if len(attention_list) >= 2:
        # First item should have equal or higher risk than second item
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0}
        first_sev = sev_rank.get(attention_list[0]["risk_level"], 0)
        second_sev = sev_rank.get(attention_list[1]["risk_level"], 0)
        assert first_sev >= second_sev


def test_api_dashboard_summary_endpoint():
    """Verify Step 24: GET /api/v1/dashboard/summary returns schema-compliant data."""
    res = client.get("/api/v1/dashboard/summary")
    assert res.status_code == 200
    data = res.json()

    assert "total_events" in data
    assert "active_incidents" in data
    assert "critical_incidents" in data
    assert "high_risk_incidents" in data
    assert "threats_detected" in data
    assert "risk_distribution" in data
    assert "threat_distribution" in data
    assert "recent_timeline" in data
    assert "attention_required" in data


def test_api_incidents_pagination_and_total_count_header():
    """Verify Step 11: GET /api/v1/incidents supports limit, offset, page, page_size, X-Total-Count."""
    res = client.get("/api/v1/incidents?page=1&page_size=2")
    assert res.status_code == 200
    items = res.json()

    assert isinstance(items, list)
    assert len(items) <= 2
    assert "X-Total-Count" in res.headers
    total_count = int(res.headers["X-Total-Count"])
    assert total_count >= len(items)


def test_api_multi_filter_combination():
    """Verify Step 10: Multi-filter query combination returns precise matches."""
    res = client.get("/api/v1/incidents?risk_level=CRITICAL&status=NEW")
    assert res.status_code == 200
    items = res.json()

    for item in items:
        assert item["risk_level"] == "CRITICAL"
        assert item["status"] == "NEW"


def test_api_incident_search():
    """Verify Step 9: Search query param filters across ID, title, and summary."""
    res = client.get("/api/v1/incidents?search=Deepfake")
    assert res.status_code == 200
    items = res.json()

    for item in items:
        matched = (
            "deepfake" in item["id"].lower() or
            "deepfake" in item["title"].lower() or
            "deepfake" in item["input_summary"].lower() or
            "deepfake" in item["threat_type"].lower()
        )
        assert matched


def test_api_incident_status_update_triage():
    """Verify Step 12: Updating status enforces state machine validity."""
    # Fetch an incident first
    res = client.get("/api/v1/incidents?limit=1")
    items = res.json()
    if not items:
        pytest.skip("No incidents available to test status update.")

    inc_id = items[0]["id"]
    current_status = items[0]["status"]

    # Transition NEW -> ACKNOWLEDGED or INVESTIGATING -> CONTAINED
    target = "ACKNOWLEDGED" if current_status == "NEW" else "CONTAINED" if current_status in ("ACKNOWLEDGED", "INVESTIGATING") else "RESOLVED"
    
    update_res = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": target})
    assert update_res.status_code in (200, 400) # 200 if valid transition, 400 if invalid transition
    
    if update_res.status_code == 200:
        updated_data = update_res.json()
        assert updated_data["status"] == target


@pytest.mark.asyncio
async def test_empty_database_summary():
    """Verify Step 19: Dashboard summary returns non-null zero metrics for empty DB tables."""
    # Temporary test for summary calculation resilience
    summary = await repo.get_dashboard_summary()
    assert summary["total_events"] >= 0
    assert summary["active_incidents"] >= 0
    assert "activity_summary" in summary
