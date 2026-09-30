"""Phase 4: Deterministic Risk Engine Hardening & Calibration Tests."""

import pytest
from app.risk.engine import RiskEngine
from app.schemas.evidence import (
    EvidenceItem,
    EvidenceSource,
    EvidenceStatus,
    EvidenceType,
    SeverityContribution,
)
from app.schemas.threat import RiskLevel, ThreatType


def test_risk_score_bounds_and_severity_boundaries():
    """Verify continuous risk score discretization at exact policy boundary values."""
    engine = RiskEngine()

    assert engine._map_risk_level(0.00) == RiskLevel.SAFE
    assert engine._map_risk_level(0.01) == RiskLevel.SAFE
    assert engine._map_risk_level(0.19) == RiskLevel.SAFE

    assert engine._map_risk_level(0.20) == RiskLevel.LOW
    assert engine._map_risk_level(0.39) == RiskLevel.LOW

    assert engine._map_risk_level(0.40) == RiskLevel.MEDIUM
    assert engine._map_risk_level(0.69) == RiskLevel.MEDIUM

    assert engine._map_risk_level(0.70) == RiskLevel.HIGH
    assert engine._map_risk_level(0.84) == RiskLevel.HIGH

    assert engine._map_risk_level(0.85) == RiskLevel.CRITICAL
    assert engine._map_risk_level(0.99) == RiskLevel.CRITICAL
    assert engine._map_risk_level(1.00) == RiskLevel.CRITICAL


def test_empty_evidence_produces_safe():
    """Verify zero evidence yields SAFE verdict, 0.0 score, and policy version 4.0."""
    engine = RiskEngine()
    assessment = engine.evaluate([])

    assert assessment.score == 0.0
    assert assessment.level == RiskLevel.SAFE
    assert assessment.policy_version == "4.0"
    assert len(assessment.contributions) == 0


def test_risk_contributions_breakdown_and_traceability():
    """Verify every evidence item exposes transparent risk contribution breakdown."""
    engine = RiskEngine()
    e1 = EvidenceItem(
        id="ev_001",
        source=EvidenceSource.WEB,
        type=EvidenceType.URLBERT_MALICIOUS,
        value=0.9,
        weight=0.4,
        confidence=0.9,
        severity_contribution=SeverityContribution.HIGH,
        explanation="High malicious URL probability detected by URLBERT",
    )
    e2 = EvidenceItem(
        id="ev_002",
        source=EvidenceSource.WEB,
        type=EvidenceType.LOOKALIKE_DOMAIN,
        value=True,
        weight=0.3,
        confidence=0.8,
        severity_contribution=SeverityContribution.MEDIUM,
        explanation="Domain resembles target organization",
    )

    assessment = engine.evaluate([e1, e2])

    assert assessment.policy_version == "4.0"
    assert assessment.base_score > 0.0
    assert len(assessment.contributions) == 2
    assert assessment.contributions[0].evidence_id == "ev_001"
    assert assessment.contributions[0].contribution > 0.0
    assert assessment.contributions[1].evidence_id == "ev_002"
    assert 0.0 <= assessment.score <= 1.0


def test_interaction_synergy_and_circuit_breaker():
    """Verify non-linear interaction rules trigger synergy bonus and circuit breaker floor."""
    engine = RiskEngine()
    e_lookalike = EvidenceItem(
        id="ev_la",
        source=EvidenceSource.WEB,
        type=EvidenceType.LOOKALIKE_DOMAIN,
        value=True,
        weight=0.4,
        confidence=0.9,
        severity_contribution=SeverityContribution.HIGH,
        explanation="Lookalike domain detected",
    )
    e_cred = EvidenceItem(
        id="ev_cr",
        source=EvidenceSource.MESSAGE,
        type=EvidenceType.CREDENTIAL_HARVEST_INTENT,
        value=True,
        weight=0.4,
        confidence=0.9,
        severity_contribution=SeverityContribution.HIGH,
        explanation="Credential harvesting intent detected",
    )

    assessment = engine.evaluate([e_lookalike, e_cred])

    assert assessment.synergy_bonuses >= 0.20
    assert assessment.score >= 0.85
    assert assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert any(ic.rule == "PHISHING_CHAIN" for ic in assessment.interaction_contributions)


def test_evidence_status_handling_unavailable_and_inconclusive():
    """Verify UNAVAILABLE evidence yields 0 contribution; INCONCLUSIVE capped at 0.05."""
    engine = RiskEngine()
    e_unavail = EvidenceItem(
        id="ev_unavail",
        source=EvidenceSource.THREAT_INTEL,
        type=EvidenceType.THREAT_INTEL_MATCH,
        value=None,
        weight=0.5,
        confidence=0.9,
        status=EvidenceStatus.UNAVAILABLE,
        explanation="Threat intel provider unavailable due to timeout",
    )
    e_inconclusive = EvidenceItem(
        id="ev_inconc",
        source=EvidenceSource.AUDIO,
        type=EvidenceType.SPEAKER_SIMILARITY_MATCH,
        value=0.5,
        weight=0.4,
        confidence=0.5,
        status=EvidenceStatus.INCONCLUSIVE,
        explanation="Speaker verification inconclusive due to ambient noise",
    )

    assessment = engine.evaluate([e_unavail, e_inconclusive])

    assert assessment.contributions[0].contribution == 0.0
    assert assessment.contributions[1].contribution <= 0.05


def test_duplicate_evidence_diminishing_returns():
    """Verify duplicate evidence of the same type applies diminishing returns dampening."""
    engine = RiskEngine()
    e1 = EvidenceItem(
        id="ev_d1",
        source=EvidenceSource.MESSAGE,
        type=EvidenceType.PHISHING_LANGUAGE,
        value=0.8,
        weight=0.4,
        confidence=0.8,
        severity_contribution=SeverityContribution.MEDIUM,
        explanation="Phishing language pattern 1",
    )
    e2 = EvidenceItem(
        id="ev_d2",
        source=EvidenceSource.MESSAGE,
        type=EvidenceType.PHISHING_LANGUAGE,
        value=0.8,
        weight=0.4,
        confidence=0.8,
        severity_contribution=SeverityContribution.MEDIUM,
        explanation="Phishing language pattern 2",
    )

    assessment = engine.evaluate([e1, e2])

    contrib1 = assessment.contributions[0].contribution
    contrib2 = assessment.contributions[1].contribution

    assert contrib1 > contrib2  # Second duplicate item contribution is dampened
