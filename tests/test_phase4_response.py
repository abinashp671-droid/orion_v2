"""Phase 4: Response Recommendation Engine & Playbooks Unit Tests."""

import pytest
from app.response.playbooks import ResponsePlaybookGenerator
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceType, SeverityContribution
from app.schemas.response import ActionCategory, ActionPriority
from app.schemas.threat import RiskLevel, ThreatType


def test_phishing_playbook_recommendations():
    """Verify phishing threat generates advisory URL blocking and warning playbooks with evidence references."""
    e1 = EvidenceItem(
        id="EV-P1",
        source=EvidenceSource.WEB,
        type=EvidenceType.URLBERT_MALICIOUS,
        value=0.9,
        weight=0.4,
        confidence=0.9,
        explanation="Malicious URL probability 0.9",
    )
    e2 = EvidenceItem(
        id="EV-P2",
        source=EvidenceSource.MESSAGE,
        type=EvidenceType.CREDENTIAL_HARVEST_INTENT,
        value=True,
        weight=0.4,
        confidence=0.85,
        explanation="Credential harvest intent",
    )

    actions = ResponsePlaybookGenerator.generate(
        threat_type=ThreatType.PHISHING,
        risk_level=RiskLevel.CRITICAL,
        evidence=[e1, e2],
        target_entity="http://phish-login.net",
    )

    assert len(actions) >= 2
    assert any(a.category == ActionCategory.BLOCK for a in actions)
    assert any(a.category == ActionCategory.WARN for a in actions)

    for action in actions:
        assert action.mode == "ADVISORY"
        assert action.reason is not None
        assert "EV-P1" in action.supporting_evidence_ids
        assert "EV-P2" in action.supporting_evidence_ids


def test_account_takeover_playbook_recommendations():
    """Verify ATO threat generates session revocation and MFA step-up playbooks."""
    e1 = EvidenceItem(
        id="EV-ATO1",
        source=EvidenceSource.AUTH,
        type=EvidenceType.ISOLATION_FOREST_ANOMALY,
        value=-0.4,
        weight=0.4,
        confidence=0.95,
        explanation="Isolation forest anomaly",
    )
    e2 = EvidenceItem(
        id="EV-ATO2",
        source=EvidenceSource.AUTH,
        type=EvidenceType.IMPOSSIBLE_TRAVEL,
        value=1200.0,
        weight=0.4,
        confidence=0.9,
        explanation="Impossible travel velocity",
    )

    actions = ResponsePlaybookGenerator.generate(
        threat_type=ThreatType.ACCOUNT_TAKEOVER,
        risk_level=RiskLevel.HIGH,
        evidence=[e1, e2],
        target_entity="user_alice",
    )

    assert len(actions) >= 2
    assert any(a.category == ActionCategory.SESSION for a in actions)
    assert any(a.category == ActionCategory.AUTHENTICATION for a in actions)
    assert all(a.mode == "ADVISORY" for a in actions)


def test_impersonation_and_deepfake_playbooks():
    """Verify digital impersonation and synthetic media trigger out-of-band identity verification."""
    e1 = EvidenceItem(
        id="EV-DF1",
        source=EvidenceSource.AUDIO,
        type=EvidenceType.SYNTHETIC_SPEECH_DETECTED,
        value=0.92,
        weight=0.45,
        confidence=0.92,
        explanation="Synthetic speech detected",
    )

    actions = ResponsePlaybookGenerator.generate(
        threat_type=ThreatType.VOICE_CLONE,
        risk_level=RiskLevel.HIGH,
        evidence=[e1],
        target_entity="CEO Persona",
    )

    assert len(actions) >= 2
    assert any(a.category == ActionCategory.VERIFICATION for a in actions)
    assert any("Out-of-Band" in a.title for a in actions)
    assert all(a.mode == "ADVISORY" for a in actions)
