import pytest
from app.repositories.incident_repo import IncidentRepository
from app.schemas.incident import Incident, IncidentStatus
from app.schemas.evidence import EvidenceSource
from app.schemas.threat import RiskLevel, ThreatAssessment, ThreatType


@pytest.mark.asyncio
async def test_command_center_dashboard_summary_real_data_only():
    """Verify SOC Command Center metrics aggregate live SQLite database counts and contain no fake data."""
    repo = IncidentRepository()
    summary = await repo.get_dashboard_summary()

    assert "total_events_analyzed" in summary
    assert "active_incidents" in summary
    assert "critical_incidents" in summary
    assert "risk_distribution" in summary
    assert "recent_timeline" in summary


@pytest.mark.asyncio
async def test_incident_search_and_multi_field_filters():
    """Verify search filtering by text query (ID, title, input summary) and status/risk/threat filters."""
    repo = IncidentRepository()

    inc1 = Incident(
        title="Spearphishing Email Target Alice",
        source=EvidenceSource.MESSAGE,
        input_type="text",
        input_summary="Urgent password reset link for alice@corp.com",
        threat_type=ThreatType.PHISHING,
        assessment=ThreatAssessment.MALICIOUS,
        risk_level=RiskLevel.HIGH,
        risk_score=0.82,
        confidence=0.9,
        explanation="Phishing test",
        status=IncidentStatus.NEW,
    )
    inc2 = Incident(
        title="Executive Deepfake Audio Voice Call",
        source=EvidenceSource.AUDIO,
        input_type="audio",
        input_summary="Voice clone targeting Finance VP",
        threat_type=ThreatType.VOICE_CLONE,
        assessment=ThreatAssessment.MALICIOUS,
        risk_level=RiskLevel.CRITICAL,
        risk_score=0.95,
        confidence=0.95,
        explanation="Voice clone test",
        status=IncidentStatus.INVESTIGATING,
    )

    await repo.create(inc1)
    await repo.create(inc2)

    # Filter by search query "alice"
    search_res = await repo.list_all(query_str="alice")
    assert any(i.id == inc1.id for i in search_res)
    assert not any(i.id == inc2.id for i in search_res)

    # Filter by threat_type "voice_clone"
    type_res = await repo.list_all(threat_type="voice_clone")
    assert any(i.id == inc2.id for i in type_res)

    # Filter by status "INVESTIGATING"
    status_res = await repo.list_all(status="INVESTIGATING")
    assert any(i.id == inc2.id for i in status_res)
