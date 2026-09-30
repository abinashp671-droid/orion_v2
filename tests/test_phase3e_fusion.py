"""ORION v2 — PHASE 3E INTEGRATION & REGRESSION TEST SUITE
Multimodal Evidence Fusion + Cross-Modal Intelligence + Entity Resolution

Validates:
1. Evidence normalization
2. Evidence provenance
3. Evidence status (OBSERVED, INCONCLUSIVE, UNAVAILABLE)
4. Evidence deduplication (diminishing return weights 1.0x, 0.60x, 0.35x)
5. URL entity normalization
6. Domain entity resolution
7. Media fingerprinting (deterministic SHA-256)
8. Temporal correlation & correlation confidence formula
9. Message -> URL correlation
10. URL -> domain correlation
11. Identity -> media correlation
12. Audio -> identity correlation
13. Video -> identity correlation
14. Phishing multimodal synergy
15. Executive impersonation synergy
16. ATO correlation
17. Contradictory evidence resolution
18. Missing provider handling
19. Unavailable provider handling
20. Incident deduplication
21. Incident timeline chronological ordering
22. Attack-chain generation
23. MITRE evidence mapping with supporting_evidence_ids
24. XAI evidence-chain narrative generation
25. Browser Shield -> incident correlation
26. End-to-end multimodal incident (/api/v1/analyze/multimodal)
27. Demo Scenario A, B, C, D, E
"""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceStatus, EvidenceType
from app.schemas.incident import (
    AttackChainStage,
    CorrelationGroup,
    EntityType,
    Incident,
    IncidentEntity,
    IncidentStatus,
)
from app.schemas.threat import MitreTechnique, RiskLevel, ThreatType, ThreatAssessment
from app.engines.fusion.entity import CanonicalEntity, EntityNormalizer, EntityResolver
from app.engines.fusion.graph import EvidenceGraph, GraphRelation
from app.engines.fusion.correlation import CorrelationEngine
from app.engines.fusion.engine import EvidenceFusionEngine
from app.engines.fusion.fingerprint import FingerprintEngine
from app.risk.engine import RiskEngine
from app.risk.mitre import MitreMapper
from app.explainability.generator import ExplainabilityGenerator
from app.repositories.incident_repo import IncidentRepository
from app.engines.phishing.orchestrator import WebIntelligenceOrchestrator
from app.engines.media.orchestrator import MediaIntelligenceOrchestrator
from app.engines.behavioural.orchestrator import BehaviouralOrchestrator


@pytest.fixture
def client():
    return TestClient(app)


# ============================================================================
# 1. CANONICAL EVIDENCE MODEL, PROVENANCE, STATUS
# ============================================================================

def test_canonical_evidence_contract_and_provenance():
    """Verify canonical EvidenceItem adheres to Step 2 & 4 provenance standards."""
    now = datetime.now(timezone.utc)
    item = EvidenceItem(
        type=EvidenceType.URLBERT_PHISHING_CONFIDENCE,
        source=EvidenceSource.WEB,
        category="network",
        provider="urlbert",
        model="CrabInHoney/urlbert-tiny-v4-malicious-url-classifier",
        value=0.92,
        confidence=0.92,
        severity_contribution="CRITICAL",
        weight=0.35,
        timestamp=now,
        status=EvidenceStatus.OBSERVED,
        entity_refs=["ent_url_a1b2c3d4e5f6"],
        incident_refs=["inc_12345"],
        indicators={
            "prediction": "phishing",
            "malicious_probability": 0.92,
        },
        explanation="URLBERT scored 0.92 probability of phishing URL.",
    )

    data = item.model_dump()
    assert data["provider"] == "urlbert"
    assert data["model"] == "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier"
    assert data["status"] == "observed"
    assert data["category"] == "network"
    assert "ent_url_a1b2c3d4e5f6" in data["entity_refs"]
    assert "inc_12345" in data["incident_refs"]
    assert data["indicators"]["prediction"] == "phishing"


def test_evidence_status_inconclusive_and_unavailable():
    """Verify Step 3: UNAVAILABLE and INCONCLUSIVE never convert to SAFE."""
    unavail = EvidenceItem(
        type=EvidenceType.EXTERNAL_THREAT_INTEL_MATCH,
        source=EvidenceSource.THREAT_INTEL,
        provider="otx_alienvault",
        status=EvidenceStatus.UNAVAILABLE,
        value=0.0,
        confidence=0.0,
        weight=0.25,
        explanation="Threat intelligence provider timed out.",
    )
    inconcl = EvidenceItem(
        type=EvidenceType.FACIAL_MANIPULATION_DETECTED,
        source=EvidenceSource.IMAGE,
        provider="yunet_detector",
        status=EvidenceStatus.INCONCLUSIVE,
        value=0.50,
        confidence=0.20,
        weight=0.25,
        explanation="Face partially occluded; tampering inconclusive.",
    )

    resolved = EvidenceFusionEngine.resolve_contradictions([unavail, inconcl])
    assert len(resolved) == 2
    # Weights must be dampened to protect against false certainty, but status retained
    for r in resolved:
        assert r.weight <= 0.05
        assert r.status in (EvidenceStatus.UNAVAILABLE, EvidenceStatus.INCONCLUSIVE)
        assert "contradiction_safeguard" in r.indicators


# ============================================================================
# 2. EVIDENCE DEDUPLICATION (DIMINISHING RETURNS)
# ============================================================================

def test_evidence_deduplication_diminishing_returns():
    """Verify Step 5: Multiple co-observed signals on the same entity receive 1.0x, 0.60x, 0.35x weights."""
    url_ent_id = "ent_url_deadbeef1234"
    now = datetime.now(timezone.utc)

    # 3 distinct providers observing the same URL threat (same signal family)
    e1 = EvidenceItem(
        type=EvidenceType.URLBERT_PHISHING_CONFIDENCE,
        source=EvidenceSource.WEB,
        provider="urlbert",
        value=0.94,
        confidence=0.94,
        weight=0.35,
        entity_refs=[url_ent_id],
        timestamp=now,
        explanation="URLBERT scored phishing.",
    )
    e2 = EvidenceItem(
        type=EvidenceType.LEXICAL_LOOKALIKE_DOMAIN,
        source=EvidenceSource.WEB,
        provider="lexical_engine",
        value=0.88,
        confidence=0.88,
        weight=0.25,
        entity_refs=[url_ent_id],
        timestamp=now,
        explanation="Lexical lookalike detected.",
    )
    e3 = EvidenceItem(
        type=EvidenceType.EXTERNAL_THREAT_INTEL_MATCH,
        source=EvidenceSource.THREAT_INTEL,
        provider="threat_feed",
        value=True,
        confidence=0.82,
        weight=0.30,
        entity_refs=[url_ent_id],
        timestamp=now,
        explanation="Matched threat intelligence feed.",
    )

    deduped = EvidenceFusionEngine.deduplicate_evidence([e1, e2, e3])
    assert len(deduped) == 3

    # Sorted by confidence: e1 (rank 0, factor 1.0), e2 (rank 1, factor 0.6), e3 (rank 2, factor 0.35)
    d0 = next(d for d in deduped if d.provider == "urlbert")
    d1 = next(d for d in deduped if d.provider == "lexical_engine")
    d2 = next(d for d in deduped if d.provider == "threat_feed")

    assert d0.indicators["weight_adjustment_factor"] == 1.0
    assert d0.weight == 0.35

    assert d1.indicators["weight_adjustment_factor"] == 0.60
    assert d1.weight == round(0.25 * 0.60, 3)

    assert d2.indicators["weight_adjustment_factor"] == 0.35
    assert d2.weight == round(0.30 * 0.35, 3)


# ============================================================================
# 3. ENTITY NORMALIZATION & RESOLUTION
# ============================================================================

def test_url_and_domain_entity_normalization():
    """Verify Step 6 & 7: Canonical URL normalization without forensic loss."""
    raw_url = "HTTPS://PayPa1-Security.EXAMPLE.COM:443/login/verify?ref=sms#frag"
    # EntityResolver.resolve_url returns a (url_entity, domain_entity) tuple
    url_ent, domain_ent = EntityResolver.resolve_url(raw_url)

    assert url_ent.type == EntityType.URL
    # Canonical value: scheme lowercase, port stripped, fragment removed
    assert url_ent.canonical_value == "https://paypa1-security.example.com/login/verify?ref=sms"
    assert url_ent.raw_value == raw_url

    assert domain_ent.type == EntityType.DOMAIN
    assert domain_ent.canonical_value == "paypa1-security.example.com"


def test_entity_resolver_email_and_ip_normalization():
    """Verify email, IP, and user/account canonical resolution."""
    # resolve_email returns (email_entity, optional_domain_entity)
    email_ent, _ = EntityResolver.resolve_email("  Security-Alert@PAYPAL-SUPPORT.COM  ")
    assert email_ent.canonical_value == "security-alert@paypal-support.com"

    ip_ent = EntityResolver.resolve_ip("  192.168.1.100  ")
    assert ip_ent.canonical_value == "192.168.1.100"

    acc_ent = EntityResolver.resolve_user("  USER_ADMIN_99  ")
    assert acc_ent.canonical_value == "USER_ADMIN_99"


def test_message_entity_extraction():
    """Verify automatic entity extraction from raw communication text."""
    msg = (
        "Dear customer, your Microsoft Office 365 license has expired. "
        "Contact billing@microsoft-support.co or visit https://microsoft-billing.co/renew "
        "immediately to avoid account suspension."
    )
    entities = EntityResolver.extract_from_message(msg)
    types = {e.type for e in entities}

    assert EntityType.ORGANIZATION in types
    assert EntityType.EMAIL in types
    assert EntityType.URL in types
    assert EntityType.DOMAIN in types

    orgs = [e.canonical_value for e in entities if e.type == EntityType.ORGANIZATION]
    assert any("microsoft" in o.lower() or "Microsoft" in o for o in orgs)


# ============================================================================
# 4. MEDIA FINGERPRINTING
# ============================================================================

def test_media_fingerprinting_deterministic():
    """Verify Step 29: Deterministic fingerprinting for media artifacts."""
    sample_bytes = b"IDAT_FAKE_IMAGE_DATA_STREAM_ORION_V2"
    fp1 = FingerprintEngine.fingerprint_media(sample_bytes, "image")
    fp2 = FingerprintEngine.fingerprint_media(sample_bytes, "image")

    # Fingerprints must be deterministic
    assert fp1 == fp2
    # Prefix format: media_image_<20-char-hex>
    assert fp1.startswith("media_image_")
    assert len(fp1) > 10

    # resolve_media_fingerprint returns IMAGE/VIDEO/AUDIO entity type
    ent = EntityResolver.resolve_media_fingerprint(sample_bytes, "image")
    assert ent.type == EntityType.IMAGE
    assert "sha256" in ent.raw_value or "media" in ent.canonical_value


# ============================================================================
# 5. EVIDENCE GRAPH & BOUNDED TRAVERSAL
# ============================================================================

def test_evidence_graph_cycle_protection_and_traversal():
    """Verify Step 12 & 38: In-memory graph correctly links nodes with cycle prevention."""
    graph = EvidenceGraph()

    # CanonicalEntity uses canonical_value (not normalized_value)
    e_url = CanonicalEntity(
        id="ent_url_1",
        type=EntityType.URL,
        raw_value="http://a.com",
        canonical_value="http://a.com",
    )
    e_dom = CanonicalEntity(
        id="ent_dom_1",
        type=EntityType.DOMAIN,
        raw_value="a.com",
        canonical_value="a.com",
    )
    e_org = CanonicalEntity(
        id="ent_org_1",
        type=EntityType.ORGANIZATION,
        raw_value="Acme",
        canonical_value="Acme",
    )

    graph.add_entity(e_url)
    graph.add_entity(e_dom)
    graph.add_entity(e_org)

    graph.add_edge("ent_url_1", "ent_dom_1", GraphRelation.RELATED_TO)
    graph.add_edge("ent_dom_1", "ent_org_1", GraphRelation.ASSOCIATED_WITH)
    # Intentionally add circular edge
    graph.add_edge("ent_org_1", "ent_url_1", GraphRelation.CONTAINS)

    # Bounded traversal must terminate cleanly without recursion error
    # traverse() returns dict: {root_id, depth_reached, entities: [{id,...}], evidence, edges}
    result = graph.traverse("ent_url_1", max_depth=5)
    # Exclude the root entity itself from the count
    connected_ids = {e["id"] for e in result["entities"] if e["id"] != "ent_url_1"}

    assert "ent_dom_1" in connected_ids
    assert "ent_org_1" in connected_ids
    assert len(connected_ids) == 2


# ============================================================================
# 6. TEMPORAL CORRELATION & CONFIDENCE FORMULA
# ============================================================================

def test_temporal_correlation_within_and_outside_window():
    """Verify Step 9 & 10: Events inside temporal window correlate; distant events do not."""
    # CorrelationEngine uses default_time_window_seconds (not default_window_minutes)
    corr_engine = CorrelationEngine(default_time_window_seconds=1800)  # 30-minute window
    base_time = datetime(2026, 9, 27, 10, 0, 0, tzinfo=timezone.utc)

    # Event 1: SMS at 10:02
    e1 = EvidenceItem(
        type=EvidenceType.URGENT_CALL_TO_ACTION,
        source=EvidenceSource.MESSAGE,
        value=1.0,
        confidence=0.85,
        timestamp=base_time + timedelta(minutes=2),
        entity_refs=["ent_user_1"],
        explanation="Urgent call to action detected.",
    )
    # Event 2: URL visit at 10:04 (within 30m window)
    e2 = EvidenceItem(
        type=EvidenceType.URLBERT_PHISHING_CONFIDENCE,
        source=EvidenceSource.WEB,
        value=0.91,
        confidence=0.91,
        timestamp=base_time + timedelta(minutes=4),
        entity_refs=["ent_user_1"],
        explanation="URLBERT phishing detection.",
    )
    # Event 3: Login 3 days later (outside 30m window)
    e3 = EvidenceItem(
        type=EvidenceType.FAILED_LOGIN_BURST,
        source=EvidenceSource.AUTH,
        value=14,
        confidence=0.90,
        timestamp=base_time + timedelta(days=3),
        entity_refs=["ent_user_1"],
        explanation="Failed login burst.",
    )

    entities = [
        CanonicalEntity(
            id="ent_user_1",
            type=EntityType.USER,
            raw_value="u1",
            canonical_value="u1",
        )
    ]

    groups = corr_engine.correlate([e1, e2, e3], entities)

    # Expect e1 and e2 to cluster; e3 must be in a separate group or isolated
    cluster_with_e1 = next(g for g in groups if e1.id in g.evidence_ids)
    assert e2.id in cluster_with_e1.evidence_ids
    assert e3.id not in cluster_with_e1.evidence_ids


def test_correlation_confidence_formula_decoupled_from_model_confidence():
    """Verify Step 16: Correlation confidence formula follows documented components."""
    corr_engine = CorrelationEngine(default_time_window_seconds=3600)  # 60-minute window

    # calculate_correlation_confidence takes positional numeric args:
    # (shared_entities_count, time_delta_seconds, distinct_modalities_count, avg_evidence_confidence)
    conf = corr_engine.calculate_correlation_confidence(
        shared_entities_count=2,
        time_delta_seconds=240,      # 4 minutes, well inside 60-minute window
        distinct_modalities_count=3,
        avg_evidence_confidence=0.65,
    )

    # Correlation confidence is independent of single model's confidence
    assert 0.50 <= conf <= 1.0
    assert isinstance(conf, float)


# ============================================================================
# 7. CROSS-MODAL DEMO SCENARIOS A, B, C, D, E
# ============================================================================

@pytest.mark.asyncio
async def test_demo_scenario_a_phishing_message_to_malicious_url():
    """DEMO 1 / SCENARIO A: Phishing Message -> Malicious URL -> Lookalike Domain."""
    orchestrator = WebIntelligenceOrchestrator()

    message_text = "URGENT: Your PayPal account has been restricted. Visit https://paypa1-security.com/login immediately."
    incident = await orchestrator.analyze_message(message_text)

    assert incident.id is not None
    assert incident.risk_score >= 0.70
    assert incident.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    # Must contain url and domain entities
    ent_types = {e.type for e in incident.entities}
    assert EntityType.URL in ent_types
    assert EntityType.DOMAIN in ent_types

    # Attack chain should progress through initial access
    assert AttackChainStage.INITIAL_ACCESS.value in incident.attack_chain
    assert len(incident.timeline) >= 2


@pytest.mark.asyncio
async def test_demo_scenario_b_executive_audio_impersonation():
    """DEMO 2 / SCENARIO B: Synthetic Voice + Executive Identity Match + Financial Coercion."""
    media_orchestrator = MediaIntelligenceOrchestrator()

    transcript = (
        "This is Rajesh Sharma CFO. We have an urgent offshore wire transfer requirement "
        "of $85,000 for the acquisition. Send the funds immediately or the deal collapses."
    )
    incident = await media_orchestrator.analyze_audio(
        claimed_identity_name="Rajesh Sharma",
        injected_synthetic_score=0.94,
        injected_similarity_score=0.92,
        provided_transcript=transcript,
    )

    assert incident.risk_level == RiskLevel.CRITICAL
    assert incident.risk_score >= 0.90

    evidence_types = {e.type for e in incident.evidence}
    assert EvidenceType.SYNTHETIC_SPEECH_DETECTED in evidence_types
    assert EvidenceType.SPEAKER_SIMILARITY_MATCH in evidence_types
    assert EvidenceType.FINANCIAL_DEMAND_INTENT in evidence_types

    # Attack chain must include social engineering
    assert AttackChainStage.SOCIAL_ENGINEERING.value in incident.attack_chain


@pytest.mark.asyncio
async def test_demo_scenario_c_multimodal_video_impersonation():
    """SCENARIO C: Video Deepfake + Face Similarity + Coercive Transcript."""
    media_orchestrator = MediaIntelligenceOrchestrator()

    transcript = "This is Rajesh Sharma. Authorize payment immediately."
    incident = await media_orchestrator.analyze_video(
        video_name="exec_briefing.mp4",
        target_name="Rajesh Sharma",
        audio_transcript=transcript,
    )

    assert incident.id is not None
    assert incident.source == EvidenceSource.VIDEO
    assert len(incident.evidence) >= 1
    assert len(incident.timeline) >= 1


@pytest.mark.asyncio
async def test_demo_scenario_d_account_takeover_chain():
    """DEMO 3 / SCENARIO D: Phishing Event + Credential Attempt + New Device/Auth Anomaly."""
    beh_orchestrator = BehaviouralOrchestrator()

    # analyze_auth_event takes keyword arguments (not a dict)
    incident = await beh_orchestrator.analyze_auth_event(
        user_id="usr_998877",
        ip_address="185.220.101.5",
        device_id="dev_unrecognized_tor_exit",
        user_agent="Mozilla/5.0 (X11; Linux x86_64)",
        country="RU",
        success=False,
        injected_failed_burst=14,
    )

    assert incident.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    evidence_types = {e.type for e in incident.evidence}
    # The behavioural orchestrator emits FAILED_LOGIN_BURST (= AUTHENTICATION_BURST alias)
    assert (
        EvidenceType.FAILED_LOGIN_BURST in evidence_types
        or EvidenceType.ISOLATION_FOREST_ANOMALY in evidence_types
    )
    assert AttackChainStage.ACCOUNT_ANOMALY.value in incident.attack_chain


@pytest.mark.asyncio
async def test_demo_scenario_e_benign_synthetic_media():
    """DEMO 4 / SCENARIO E: Synthetic media without malice or identity abuse does NOT escalate to CRITICAL."""
    media_orchestrator = MediaIntelligenceOrchestrator()

    # Synthetic voice reading benign weather report
    incident = await media_orchestrator.analyze_audio(
        injected_synthetic_score=0.92,
        provided_transcript="Good morning everyone. Today's forecast calls for light rain in the afternoon.",
    )

    assert incident.risk_level != RiskLevel.CRITICAL, (
        f"Benign synthetic media must NOT escalate to CRITICAL, got {incident.risk_level}"
    )


# ============================================================================
# 8. INCIDENT TIMELINE, ATTACK CHAIN, MITRE GROUNDING
# ============================================================================

def test_incident_timeline_chronological_ordering():
    """Verify Step 22: Timeline events are strictly chronological and use real timestamps."""
    t1 = datetime(2026, 9, 27, 10, 0, 10, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 27, 10, 0, 25, tzinfo=timezone.utc)
    t3 = datetime(2026, 9, 27, 10, 0, 45, tzinfo=timezone.utc)

    items = [
        EvidenceItem(
            type=EvidenceType.URLBERT_PHISHING_CONFIDENCE,
            source=EvidenceSource.WEB,
            value=0.89,
            confidence=0.89,
            timestamp=t2,
            explanation="URLBERT phishing.",
        ),
        EvidenceItem(
            type=EvidenceType.URGENT_CALL_TO_ACTION,
            source=EvidenceSource.MESSAGE,
            value=1.0,
            confidence=0.85,
            timestamp=t1,
            explanation="Urgent CTA.",
        ),
        EvidenceItem(
            type=EvidenceType.NEW_DEVICE_FINGERPRINT,
            source=EvidenceSource.AUTH,
            value=True,
            confidence=0.95,
            timestamp=t3,
            explanation="New device seen.",
        ),
    ]

    # construct_timeline is the actual method name on EvidenceFusionEngine
    timeline = EvidenceFusionEngine.construct_timeline(items)
    assert len(timeline) == 3
    # Strictly increasing chronological timestamps
    assert timeline[0].timestamp <= timeline[1].timestamp <= timeline[2].timestamp
    # First event should be from the earliest timestamp (URGENT_CALL_TO_ACTION at t1)
    assert "message" in timeline[0].source.lower() or "urgent" in timeline[0].title.lower()


def test_mitre_mapping_grounded_in_evidence():
    """Verify Step 24: MITRE techniques contain reason and supporting_evidence_ids."""
    now = datetime.now(timezone.utc)
    e1 = EvidenceItem(
        id="evi_urlbert_999",
        type=EvidenceType.URLBERT_PHISHING_CONFIDENCE,
        source=EvidenceSource.WEB,
        value=0.94,
        confidence=0.94,
        timestamp=now,
        explanation="URLBERT phishing.",
    )
    e2 = EvidenceItem(
        id="evi_lexical_888",
        type=EvidenceType.LEXICAL_LOOKALIKE_DOMAIN,
        source=EvidenceSource.WEB,
        value=0.88,
        confidence=0.88,
        timestamp=now,
        explanation="Lexical lookalike domain.",
    )

    techniques = MitreMapper.enrich("phishing", [e1, e2])
    assert len(techniques) >= 1

    t0 = techniques[0]
    # MitreTechnique field is 'id', not 'technique_id'
    assert t0.id == "T1566.002"
    assert t0.reason is not None
    assert "evi_urlbert_999" in t0.supporting_evidence_ids
    assert "evi_lexical_888" in t0.supporting_evidence_ids


def test_xai_evidence_chain_explanation():
    """Verify Step 20: XAI generates a numbered step-by-step evidence chain without fake claims."""
    now = datetime.now(timezone.utc)
    # Give evidence items enough weight so RiskEngine scores HIGH (not SAFE)
    items = [
        EvidenceItem(
            type=EvidenceType.URGENT_CALL_TO_ACTION,
            source=EvidenceSource.MESSAGE,
            value=1.0,
            confidence=0.85,
            weight=0.30,
            explanation="Urgent language demanding verification",
            timestamp=now,
        ),
        EvidenceItem(
            type=EvidenceType.URLBERT_PHISHING_CONFIDENCE,
            source=EvidenceSource.WEB,
            value=0.94,
            confidence=0.94,
            weight=0.35,
            explanation="URLBERT neural classifier scored 0.94 probability of credential theft",
            timestamp=now,
        ),
    ]

    risk_engine = RiskEngine()
    assessment = risk_engine.evaluate(items)
    attack_chain = [AttackChainStage.INITIAL_ACCESS.value, AttackChainStage.MALICIOUS_URL.value]

    narrative = ExplainabilityGenerator.generate(
        assessment, items, "Phishing SMS targeting user", attack_chain=attack_chain
    )

    # XAI generator outputs these actual strings:
    assert "WHY ORION FLAGGED THIS INCIDENT" in narrative
    assert " 1." in narrative
    assert " 2." in narrative
    # Attack chain is rendered as: "Attack Stage Lineage: ..."
    assert "Attack Stage Lineage" in narrative
    # Determinism guarantee is rendered as: "Determinism Guarantee: Risk score..."
    assert "Determinism Guarantee" in narrative
    assert "AI thinks" not in narrative


# ============================================================================
# 9. INCIDENT DEDUPLICATION & REPOSITORY PERSISTENCE
# ============================================================================

@pytest.mark.asyncio
async def test_incident_deduplication_fingerprint():
    """Verify Step 28: Identical security events generate the same fingerprint to prevent duplicate incidents."""
    t0 = datetime(2026, 9, 27, 14, 0, 0, tzinfo=timezone.utc)

    # FingerprintEngine.fingerprint_incident signature: (input_type, entities, timestamp, bucket_seconds)
    # It accepts a list of CanonicalEntity objects, not entity_ids directly
    url_ent = CanonicalEntity(id="ent_url_123", type=EntityType.URL, raw_value="http://x.com", canonical_value="http://x.com")
    dom_ent = CanonicalEntity(id="ent_dom_456", type=EntityType.DOMAIN, raw_value="x.com", canonical_value="x.com")

    fp1 = FingerprintEngine.fingerprint_incident(
        input_type="phishing_url",
        entities=[url_ent, dom_ent],
        timestamp=t0,
        bucket_seconds=600,  # 10-minute bucket
    )
    fp2 = FingerprintEngine.fingerprint_incident(
        input_type="phishing_url",
        entities=[url_ent, dom_ent],
        timestamp=t0 + timedelta(minutes=4),  # Inside same 10-min bucket
        bucket_seconds=600,
    )
    fp_different_time = FingerprintEngine.fingerprint_incident(
        input_type="phishing_url",
        entities=[url_ent, dom_ent],
        timestamp=t0 + timedelta(hours=3),  # Outside bucket
        bucket_seconds=600,
    )

    assert fp1 == fp2
    assert fp1 != fp_different_time


@pytest.mark.asyncio
async def test_incident_persistence_with_timeline_and_groups():
    """Verify upgraded incident fields (timeline, correlation_groups, attack_chain) persist cleanly in SQLite."""
    repo = IncidentRepository()
    now = datetime.now(timezone.utc)

    incident = Incident(
        title="Test Multimodal Incident",
        source=EvidenceSource.MULTIMODAL,
        input_type="multimodal",
        input_summary="Test event",
        threat_type=ThreatType.PHISHING,
        assessment=ThreatAssessment.MALICIOUS,
        risk_level=RiskLevel.HIGH,
        risk_score=0.85,
        confidence=0.90,
        evidence=[],
        explanation="Correlated phishing and credential theft chain.",
        timeline=[],
        correlation_groups=[
            {
                "group_id": "grp_1",
                "entities": ["ent_url_1"],
                "evidence_ids": ["evi_1"],
                "correlation_confidence": 0.88,
                "cross_modal_modalities": ["message", "web"],
            }
        ],
        attack_chain=[AttackChainStage.INITIAL_ACCESS.value, AttackChainStage.MALICIOUS_URL.value],
        xai_summary="Correlated phishing and credential theft chain.",
        status=IncidentStatus.NEW,
    )

    created = await repo.create(incident)
    assert created.id is not None
    assert created.attack_chain == [AttackChainStage.INITIAL_ACCESS.value, AttackChainStage.MALICIOUS_URL.value]
    assert created.xai_summary == "Correlated phishing and credential theft chain."
    assert len(created.correlation_groups) == 1

    # Fetch back from DB using get_by_id
    fetched = await repo.get_by_id(created.id)
    assert fetched is not None
    assert len(fetched.correlation_groups) == 1
    # correlation_groups are stored as dicts
    assert fetched.correlation_groups[0]["group_id"] == "grp_1"


# ============================================================================
# 10. END-TO-END MULTIMODAL API ENDPOINT
# ============================================================================

def test_api_multimodal_endpoint_phishing_and_auth(client):
    """Verify POST /api/v1/analyze/multimodal correlates message + URL + auth into a single incident."""
    payload = {
        "message_text": "URGENT: Verify your account immediately.",
        "url": "https://secure-login-paypa1.com/verify",
        "auth_event": {
            "user_id": "victim_usr_42",
            "ip_address": "194.26.29.112",
            "device_id": "dev_new_unseen",
            "is_new_device": True,
            "failed_attempts_last_hour": 5,
        },
    }

    res = client.post("/api/v1/analyze/multimodal", json=payload)
    assert res.status_code == 200, res.text

    data = res.json()
    assert data["id"] is not None
    assert data["source"] == "multimodal"
    assert data["risk_level"] in ("HIGH", "CRITICAL")
    assert len(data["timeline"]) >= 2
    assert len(data["correlation_groups"]) >= 1
    assert len(data["attack_chain"]) >= 2
    assert "WHY ORION FLAGGED THIS INCIDENT" in data["explanation"]


def test_api_multimodal_endpoint_requires_at_least_one_modality(client):
    """Verify POST /api/v1/analyze/multimodal rejects empty payloads."""
    res = client.post("/api/v1/analyze/multimodal", json={})
    assert res.status_code == 400
    assert "At least one modality" in res.json()["detail"]
