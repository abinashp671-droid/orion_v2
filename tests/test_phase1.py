"""Comprehensive Verification Tests for ORION v2 Phase 1 (Decisioning Engines & Providers)."""

import pytest
import pytest_asyncio
from app.providers.semantic_gateway import SemanticProviderGateway, SemanticObservation
from app.providers.threat_intel import ThreatIntelProvider
from app.risk.engine import RiskEngine
from app.risk.mitre import MitreMapper
from app.explainability.generator import ExplainabilityGenerator
from app.response.playbooks import ResponsePlaybookGenerator
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceType, SeverityContribution
from app.schemas.threat import RiskLevel, ThreatAssessment, ThreatType
from app.schemas.response import ActionCategory, ActionPriority


@pytest.mark.asyncio
async def test_semantic_provider_gateway_phishing():
    """Verify semantic gateway extracts structured intent from phishing text without scoring risk."""
    gateway = SemanticProviderGateway()
    text = "URGENT: Your SBI account is suspended. Verify your KYC immediately to prevent permanent blockage."
    
    obs, evidence = await gateway.analyze(text)
    assert isinstance(obs, SemanticObservation)
    assert obs.urgency is True
    assert obs.credential_request is True
    assert obs.claimed_entity is not None and ("SBI" in obs.claimed_entity or "State Bank" in obs.claimed_entity)
    assert obs.suspicious_intent is True

    # Verify generated evidence items
    types = [e.type for e in evidence]
    assert EvidenceType.URGENT_CALL_TO_ACTION in types
    assert EvidenceType.CREDENTIAL_HARVEST_INTENT in types

@pytest.mark.asyncio
async def test_semantic_provider_gateway_voice_coercion():
    """Verify semantic gateway extracts financial coercion and executive impersonation."""
    gateway = SemanticProviderGateway()
    text = "Hi team, this is the Director. Wire transfer rs 500000 immediately for the vendor invoice."
    
    obs, evidence = await gateway.analyze(text)
    assert obs.urgency is True
    assert obs.payment_request is True
    assert obs.claimed_entity is not None and "Director" in obs.claimed_entity


    types = [e.type for e in evidence]
    assert EvidenceType.FINANCIAL_DEMAND_INTENT in types
    assert EvidenceType.PROTECTED_IDENTITY_TARGETED in types


@pytest.mark.asyncio
async def test_threat_intel_provider():
    """Verify local SQLite IOC lookup and evidence generation."""
    provider = ThreatIntelProvider()

    # 1. Known malicious domain
    res = await provider.lookup("secure-sbi-kyc-update.xyz")
    assert res.is_malicious is True
    assert res.reputation_score >= 0.90
    assert "URLhaus" in (res.matched_feed or "")

    evi = await provider.generate_evidence("secure-sbi-kyc-update.xyz", "domain")
    assert evi is not None
    assert evi.type == EvidenceType.THREAT_INTEL_MATCH
    assert evi.severity_contribution == SeverityContribution.CRITICAL

    # 2. Clean/unlisted domain
    clean_res = await provider.lookup("wikipedia.org")
    assert clean_res.is_malicious is False
    assert clean_res.reputation_score == 0.0


@pytest.mark.asyncio
async def test_risk_engine_voice_impersonation_synergy():
    """Verify non-linear multiplicative synergy: synthetic audio + speaker similarity + financial demand."""
    engine = RiskEngine()

    evidence = [
        EvidenceItem(
            type=EvidenceType.SYNTHETIC_SPEECH_DETECTED,
            source=EvidenceSource.AUDIO,
            value=True,
            confidence=0.90,
            severity_contribution=SeverityContribution.HIGH,
            weight=0.30,
            explanation="Acoustic analysis detected synthetic vocoder artifacts."
        ),
        EvidenceItem(
            type=EvidenceType.SPEAKER_SIMILARITY_MATCH,
            source=EvidenceSource.AUDIO,
            value="CFO",
            confidence=0.88,
            severity_contribution=SeverityContribution.HIGH,
            weight=0.20,
            explanation="Voice embedding cosine similarity matches CFO profile at 0.88."
        ),
        EvidenceItem(
            type=EvidenceType.FINANCIAL_DEMAND_INTENT,
            source=EvidenceSource.SEMANTIC,
            value=True,
            confidence=0.92,
            severity_contribution=SeverityContribution.HIGH,
            weight=0.25,
            explanation="Transcript requests urgent wire transfer."
        )
    ]

    assessment = engine.evaluate(evidence)
    assert assessment.score >= 0.95
    assert assessment.level == RiskLevel.CRITICAL
    assert assessment.assessment == ThreatAssessment.MALICIOUS
    assert assessment.primary_threat in (ThreatType.VOICE_CLONE, ThreatType.IMPERSONATION)
    all_threats = [assessment.primary_threat] + assessment.secondary_threats
    assert any(t in (ThreatType.VOICE_CLONE, ThreatType.IMPERSONATION) for t in all_threats)
    assert assessment.synergy_bonuses > 0
    assert any("synergy" in d.lower() for d in assessment.risk_drivers)


@pytest.mark.asyncio
async def test_risk_engine_threat_intel_circuit_breaker():
    """Verify Threat Intel match triggers hard circuit-breaker floor."""
    engine = RiskEngine()

    evidence = [
        EvidenceItem(
            type=EvidenceType.THREAT_INTEL_MATCH,
            source=EvidenceSource.THREAT_INTEL,
            value="secure-sbi-kyc-update.xyz",
            confidence=0.98,
            severity_contribution=SeverityContribution.CRITICAL,
            weight=0.35,
            explanation="Domain is a verified URLhaus phishing feed indicator."
        )
    ]

    assessment = engine.evaluate(evidence)
    assert assessment.score >= 0.90
    assert assessment.level == RiskLevel.CRITICAL
    assert assessment.assessment == ThreatAssessment.MALICIOUS


@pytest.mark.asyncio
async def test_mitre_attack_enrichment():
    """Verify automated MITRE ATT&CK technique mapping."""
    # 1. Phishing URL evidence
    phish_evidence = [
        EvidenceItem(
            type=EvidenceType.LOOKALIKE_DOMAIN,
            source=EvidenceSource.WEB,
            value="sbi-update.xyz",
            confidence=0.9,
            severity_contribution=SeverityContribution.HIGH,
            weight=0.2,
            explanation="Domain mimics SBI."
        )
    ]
    techniques = MitreMapper.enrich(ThreatType.PHISHING, phish_evidence)
    tech_ids = [t.id for t in techniques]
    assert "T1566.002" in tech_ids  # Spearphishing Link
    assert "T1583.001" in tech_ids  # Domains

    # 2. Voice cloning evidence
    voice_evidence = [
        EvidenceItem(
            type=EvidenceType.SYNTHETIC_SPEECH_DETECTED,
            source=EvidenceSource.AUDIO,
            value=True,
            confidence=0.88,
            severity_contribution=SeverityContribution.HIGH,
            weight=0.3,
            explanation="Synthetic audio"
        )
    ]
    v_techniques = MitreMapper.enrich(ThreatType.VOICE_CLONE, voice_evidence)
    v_ids = [t.id for t in v_techniques]
    assert "T1566.004" in v_ids  # Spearphishing Voice
    assert "T1656" in v_ids      # Impersonation


@pytest.mark.asyncio
async def test_explainability_and_playbooks():
    """Verify evidence-grounded XAI generation and advisory playbooks."""
    evidence = [
        EvidenceItem(
            type=EvidenceType.LOOKALIKE_DOMAIN,
            source=EvidenceSource.WEB,
            value="sbi-kyc.xyz",
            confidence=0.95,
            severity_contribution=SeverityContribution.CRITICAL,
            weight=0.3,
            explanation="Domain 'sbi-kyc.xyz' targets State Bank of India."
        ),
        EvidenceItem(
            type=EvidenceType.CREDENTIAL_HARVEST_INTENT,
            source=EvidenceSource.SEMANTIC,
            value=True,
            confidence=0.90,
            severity_contribution=SeverityContribution.HIGH,
            weight=0.25,
            explanation="Page solicits banking login credentials."
        )
    ]

    engine = RiskEngine()
    assessment = engine.evaluate(evidence)

    # 1. Explainability
    explanation = ExplainabilityGenerator.generate(assessment, evidence, "http://sbi-kyc.xyz/login")
    assert "Assessment: CRITICAL RISK" in explanation
    assert "sbi-kyc.xyz" in explanation
    assert "solicits banking login credentials" in explanation

    # 2. Advisory Playbooks
    actions = ResponsePlaybookGenerator.generate(
        ThreatType.PHISHING,
        assessment.level,
        evidence,
        target_entity="sbi-kyc.xyz"
    )
    assert len(actions) >= 2
    action_categories = [a.category for a in actions]
    assert ActionCategory.BLOCK in action_categories
    assert ActionCategory.WARN in action_categories
    assert any(a.priority == ActionPriority.P0_IMMEDIATE for a in actions)
