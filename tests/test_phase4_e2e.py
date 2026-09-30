import pytest
from app.engines.phishing.orchestrator import WebIntelligenceOrchestrator
from app.repositories.incident_repo import IncidentRepository
from app.schemas.incident import IncidentStatus


@pytest.mark.asyncio
async def test_end_to_end_phishing_incident_lifecycle():
    """Verify complete end-to-end workflow:
    EVENT -> DETECTION -> EVIDENCE -> CORRELATION -> RISK ASSESSMENT -> XAI -> INCIDENT -> RECOMMENDATIONS -> ANALYST ACTIONS -> LIFECYCLE RESOLUTION.
    """
    orchestrator = WebIntelligenceOrchestrator()
    repo = IncidentRepository()

    raw_message = "ALERT: Immediate action required! Your account is suspended. Verify credentials at http://login-update-security-verify.com"
    raw_url = "http://login-update-security-verify.com"

    # 1. Detection, Evidence Extraction, Fusion, Deterministic Risk & XAI Generation
    incident = await orchestrator.analyze_url(raw_url, context=raw_message)

    assert incident.id is not None
    assert incident.risk_score >= 0.70
    assert incident.status == IncidentStatus.NEW
    assert incident.explanation is not None
    assert len(incident.evidence) > 0
    assert len(incident.recommended_actions) > 0
    assert incident.policy_version == "4.0"

    # 2. Analyst Workflow: Acknowledge & Begin Investigation
    inv_incident = await repo.update_status(incident.id, IncidentStatus.INVESTIGATING)
    assert inv_incident.status == IncidentStatus.INVESTIGATING
    assert any("INVESTIGATING" in t.title for t in inv_incident.timeline)

    # 3. Analyst Workflow: Add Investigation Note
    note_incident = await repo.add_analyst_note(
        incident_id=incident.id,
        text="Verified with perimeter gateway. URL blocked at DNS level. User alerted.",
        author="SOC Analyst 42",
    )
    assert len(note_incident.notes) == 1
    assert note_incident.notes[0].author == "SOC Analyst 42"

    # 4. Analyst Workflow: Transition to Containment
    cont_incident = await repo.update_status(incident.id, IncidentStatus.CONTAINED)
    assert cont_incident.status == IncidentStatus.CONTAINED

    # 5. Analyst Workflow: Transition to Resolution
    res_incident = await repo.update_status(incident.id, IncidentStatus.RESOLVED)
    assert res_incident.status == IncidentStatus.RESOLVED

    # 6. Verify Complete Persistence
    final_fetch = await repo.get_by_id(incident.id)
    assert final_fetch.status == IncidentStatus.RESOLVED
    assert len(final_fetch.notes) == 1
    assert len(final_fetch.evidence) == len(incident.evidence)
    assert final_fetch.policy_version == "4.0"
