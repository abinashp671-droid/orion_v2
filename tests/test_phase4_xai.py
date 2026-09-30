"""Phase 4: XAI Engine Upgrade, Evidence Linking, and Contradictory Evidence Tests."""

import pytest
from app.explainability.generator import ExplainabilityGenerator
from app.risk.engine import RiskEngine
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceStatus, EvidenceType, SeverityContribution


def test_xai_structured_sections_and_evidence_links():
    """Verify XAI output contains required structured sections and traceable evidence IDs."""
    engine = RiskEngine()
    e1 = EvidenceItem(
        id="EV-0012",
        source=EvidenceSource.MESSAGE,
        type=EvidenceType.PHISHING_LANGUAGE,
        value=0.85,
        weight=0.4,
        confidence=0.85,
        severity_contribution=SeverityContribution.HIGH,
        explanation="Detected urgent account suspension notice",
    )
    e2 = EvidenceItem(
        id="EV-0017",
        source=EvidenceSource.WEB,
        type=EvidenceType.URLBERT_MALICIOUS,
        value=0.92,
        weight=0.4,
        confidence=0.92,
        severity_contribution=SeverityContribution.HIGH,
        explanation="Embedded link assigned high malicious probability by URLBERT",
    )

    assessment = engine.evaluate([e1, e2])
    explanation = ExplainabilityGenerator.generate(
        assessment=assessment,
        evidence=[e1, e2],
        input_summary="http://security-update-login.com",
        attack_chain=["INITIAL_ACCESS", "PHISHING", "MALICIOUS_URL"],
    )

    assert "ASSESSMENT" in explanation
    assert "WHY ORION FLAGGED THIS" in explanation
    assert "RISK BREAKDOWN" in explanation
    assert "WHAT WOULD CHANGE THE ASSESSMENT" in explanation
    assert "Determinism Guarantee" in explanation

    assert "EV-0012" in explanation
    assert "EV-0017" in explanation
    assert "4.0" in explanation


def test_xai_exposes_contradictory_or_inconclusive_evidence():
    """Verify XAI explicitly discloses inconclusive evidence and missing threat intel matches."""
    engine = RiskEngine()
    e1 = EvidenceItem(
        id="EV-0020",
        source=EvidenceSource.WEB,
        type=EvidenceType.LOOKALIKE_DOMAIN,
        value=True,
        weight=0.4,
        confidence=0.9,
        severity_contribution=SeverityContribution.HIGH,
        explanation="Domain resembles target brand",
    )
    e2 = EvidenceItem(
        id="EV-0021",
        source=EvidenceSource.AUDIO,
        type=EvidenceType.SPEAKER_SIMILARITY_MATCH,
        value=0.4,
        weight=0.3,
        confidence=0.4,
        status=EvidenceStatus.INCONCLUSIVE,
        explanation="Acoustic background noise prevented conclusive speaker identification",
    )

    assessment = engine.evaluate([e1, e2])
    explanation = ExplainabilityGenerator.generate(
        assessment=assessment,
        evidence=[e1, e2],
        input_summary="Call from claimed executive",
    )

    assert "CONTRADICTORY OR INCONCLUSIVE EVIDENCE" in explanation
    assert "EV-0021" in explanation
    assert "Threat-intelligence lookup returned no matching IOC" in explanation
