import pytest
from app.repositories.incident_repo import IncidentRepository
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceType
from app.schemas.incident import Incident, IncidentStatus
from app.schemas.threat import RiskLevel, ThreatAssessment, ThreatType


@pytest.mark.asyncio
async def test_valid_incident_status_transitions():
    """Verify valid state machine transitions: NEW -> INVESTIGATING -> CONTAINED -> RESOLVED."""
    repo = IncidentRepository()

    incident = Incident(
        title="Test Incident Lifecycle",
        source=EvidenceSource.WEB,
        input_type="url",
        input_summary="http://suspicious-login.org",
        threat_type=ThreatType.PHISHING,
        assessment=ThreatAssessment.MALICIOUS,
        risk_level=RiskLevel.HIGH,
        risk_score=0.82,
        confidence=0.9,
        explanation="Phishing url test",
        status=IncidentStatus.NEW,
    )
    created = await repo.create(incident)
    assert created.status == IncidentStatus.NEW

    # NEW -> INVESTIGATING
    st1 = await repo.update_status(created.id, IncidentStatus.INVESTIGATING)
    assert st1.status == IncidentStatus.INVESTIGATING

    # INVESTIGATING -> CONTAINED
    st2 = await repo.update_status(created.id, IncidentStatus.CONTAINED)
    assert st2.status == IncidentStatus.CONTAINED

    # CONTAINED -> RESOLVED
    st3 = await repo.update_status(created.id, IncidentStatus.RESOLVED)
    assert st3.status == IncidentStatus.RESOLVED


@pytest.mark.asyncio
async def test_invalid_incident_status_transition_raises_error():
    """Verify invalid state machine transition raises clear ValueError exception."""
    repo = IncidentRepository()

    incident = Incident(
        title="Test Invalid Transition",
        source=EvidenceSource.MESSAGE,
        input_type="text",
        input_summary="Suspicious message",
        threat_type=ThreatType.PHISHING,
        assessment=ThreatAssessment.MALICIOUS,
        risk_level=RiskLevel.HIGH,
        risk_score=0.85,
        confidence=0.9,
        explanation="Phishing text test",
        status=IncidentStatus.RESOLVED,
    )
    created = await repo.create(incident)

    # RESOLVED -> CONTAINED is invalid
    with pytest.raises(ValueError, match="Invalid status transition"):
        await repo.update_status(created.id, IncidentStatus.CONTAINED)


@pytest.mark.asyncio
async def test_analyst_notes_append_and_timeline_logging():
    """Verify analyst investigation notes are append-only, timestamped, attributable, and recorded in timeline."""
    repo = IncidentRepository()

    incident = Incident(
        title="Test Analyst Notes",
        source=EvidenceSource.MESSAGE,
        input_type="text",
        input_summary="Phishing message test",
        threat_type=ThreatType.PHISHING,
        assessment=ThreatAssessment.SUSPICIOUS,
        risk_level=RiskLevel.MEDIUM,
        risk_score=0.65,
        confidence=0.85,
        explanation="Phishing text test",
        status=IncidentStatus.NEW,
    )
    created = await repo.create(incident)

    updated = await repo.add_analyst_note(
        incident_id=created.id,
        text="Contacted recipient user. User confirmed opening link but did not submit credentials.",
        author="Analyst Bob",
    )

    assert len(updated.notes) == 1
    assert updated.notes[0].author == "Analyst Bob"
    assert "Contacted recipient" in updated.notes[0].text
    assert any("Analyst Note Added" in t.title for t in updated.timeline)


@pytest.mark.asyncio
async def test_historical_evidence_immutability():
    """Verify original evidence items remain immutable when incident status or notes are updated."""
    repo = IncidentRepository()
    e_orig = EvidenceItem(
        id="EV-IMMUTABLE-01",
        source=EvidenceSource.WEB,
        type=EvidenceType.URLBERT_MALICIOUS,
        value=0.92,
        weight=0.4,
        confidence=0.92,
        explanation="Original URLBERT evidence",
    )

    incident = Incident(
        title="Test Immutability",
        source=EvidenceSource.WEB,
        input_type="url",
        input_summary="http://immutable-test.com",
        threat_type=ThreatType.MALICIOUS_URL,
        assessment=ThreatAssessment.MALICIOUS,
        risk_level=RiskLevel.HIGH,
        risk_score=0.88,
        confidence=0.92,
        evidence=[e_orig],
        explanation="Immutability test",
        status=IncidentStatus.NEW,
    )
    created = await repo.create(incident)

    await repo.update_status(created.id, IncidentStatus.INVESTIGATING)
    await repo.add_analyst_note(created.id, "Investigating origin IP", author="Analyst Alice")

    fetched = await repo.get_by_id(created.id)
    assert len(fetched.evidence) == 1
    assert fetched.evidence[0].id == "EV-IMMUTABLE-01"
    assert fetched.evidence[0].explanation == "Original URLBERT evidence"
