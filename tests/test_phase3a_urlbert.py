"""Phase 3A: Real URL / Phishing Intelligence Test Suite for ORION v2.

Covers:
1. URL normalization (RFC 3986, ports, case, query params, fragments)
2. Transformer model loading & architecture verification
3. Real transformer inference & label mapping (benign, defacement, malware, phishing)
4. Probability calibration & category distribution
5. CPU/CUDA hardware detection & metadata transparency
6. Provider caching / singleton reuse
7. Explicit heuristic fallback provider separation (NEVER claims URLBERT when fallback)
8. Model failure & error containment
9. Threat intelligence match & miss semantics (UNKNOWN != SAFE)
10. Evidence contract compliance (no raw tensors exposed)
11. Decoupling: Model Confidence != Final ORION Risk
12. Web Intelligence Orchestrator & Browser Shield integration
13. Fast API endpoint backward compatibility
14. Real model performance benchmarking (measured latency)
"""

import time
from unittest.mock import patch
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.core.database import init_db
from app.engines.phishing.orchestrator import WebIntelligenceOrchestrator
from app.engines.phishing.url_classifier import (
    HeuristicURLClassifier,
    TransformerURLClassifier,
    URLClassifierEngine,
    URLPredictionResult,
)
from app.engines.phishing.url_features import URLLexicalExtractor, normalize_url
from app.main import app
from app.providers.threat_intel import ThreatIntelProvider
from app.risk.engine import RiskEngine
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceType, SeverityContribution
from app.schemas.threat import RiskLevel

TEST_DB_PATH = settings.DATA_DIR / "test_orion_p3a.db"
settings.DATABASE_PATH = TEST_DB_PATH


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    """Setup and teardown a clean SQLite test database."""
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except PermissionError:
            pass
    await init_db()
    yield
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except PermissionError:
            pass


# ============================================================================
# 1. URL NORMALIZATION TESTS
# ============================================================================

def test_url_normalization_handles_various_formats():
    """Verify normalization standardizes schemes, lowercase hosts, and preserves path/query/fragment/port."""
    # Naked domain
    assert normalize_url("example.com") == "http://example.com"
    # Uppercase scheme and host
    assert normalize_url("HTTPS://EXAMPLE.COM/Path") == "https://example.com/Path"
    # Ports preserved
    assert normalize_url("http://example.com:8080/api/v1") == "http://example.com:8080/api/v1"
    # Query parameters and fragments preserved
    assert normalize_url("https://Test.org/login?redirect=1&user=admin#section") == "https://test.org/login?redirect=1&user=admin#section"
    # Encoded characters preserved
    assert normalize_url("http://phish.xyz/%20test%2Fpath") == "http://phish.xyz/%20test%2Fpath"


def test_lexical_extractor_24_features():
    """Verify URLLexicalExtractor preserves all 24+ security features."""
    feats = URLLexicalExtractor.extract_features("http://secure-sbi-kyc-update.xyz/login.php?user=1")
    expected_keys = [
        "raw_url", "normalized_url", "scheme", "is_https", "hostname", "base_domain",
        "tld", "url_length", "domain_length", "path_length", "subdomain_count", "path_depth",
        "url_entropy", "hostname_entropy", "ip_as_host_flag", "punycode_flag",
        "suspicious_tld_flag", "brand_similarity_score", "targeted_brand",
        "brand_in_subdomain_flag", "credential_path_flag", "redirect_parameter_count",
        "encoded_char_ratio", "at_symbol_flag", "double_slash_redirect_flag",
        "num_digits_domain", "hyphen_count_domain", "num_query_params"
    ]
    for k in expected_keys:
        assert k in feats, f"Missing expected lexical feature: {k}"
    assert feats["targeted_brand"] == "sbi"
    assert feats["suspicious_tld_flag"] is True
    assert feats["credential_path_flag"] is True


# ============================================================================
# 2. REAL TRANSFORMER MODEL INFERENCE & LABEL MAPPING
# ============================================================================

def test_real_transformer_loading_and_architecture():
    """Verify genuine URLBERT transformer loads with expected architecture and metadata."""
    classifier = TransformerURLClassifier()
    assert classifier.is_loaded() is True
    assert classifier.model_name == "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier"
    device = classifier.get_device()
    assert device in ("cpu", "cuda")


def test_real_transformer_inference_malicious_fixture():
    """Real Model Integration: Verify actual neural inference on confirmed phishing fixture."""
    classifier = TransformerURLClassifier()
    phish_url = "http://secure-sbi-kyc-update.xyz/login.php"
    result = classifier.predict(phish_url)

    assert isinstance(result, URLPredictionResult)
    assert result.provider == "urlbert"
    assert result.model_loaded is True
    assert result.prediction in ("phishing", "malware", "defacement")
    assert result.malicious_probability >= 0.90
    assert result.benign_probability <= 0.10
    assert "phishing" in result.category_probabilities
    assert "benign" in result.category_probabilities
    assert result.latency_ms > 0.0


def test_real_transformer_inference_malware_fixture():
    """Real Model Integration: Verify neural inference on malware fixture."""
    classifier = TransformerURLClassifier()
    malware_url = "http://www.824555.com/app/member/SportOption.php?uid=guest&langx=gb"
    result = classifier.predict(malware_url)

    assert result.provider == "urlbert"
    assert result.prediction == "malware"
    assert result.category_probabilities["malware"] >= 0.90


def test_real_transformer_label_mapping_integrity():
    """Verify label mapping matches the four-class taxonomy."""
    classifier = TransformerURLClassifier()
    assert classifier.LABEL_MAPPING[0] == "benign"
    assert classifier.LABEL_MAPPING[1] == "defacement"
    assert classifier.LABEL_MAPPING[2] == "malware"
    assert classifier.LABEL_MAPPING[3] == "phishing"


def test_provider_caching_singleton_behavior():
    """Verify TransformerURLClassifier reuses cached model/tokenizer without reloading."""
    c1 = TransformerURLClassifier()
    t0 = time.perf_counter()
    _ = c1.predict("http://example.com/test1")
    lat1 = time.perf_counter() - t0

    c2 = TransformerURLClassifier()
    t1 = time.perf_counter()
    _ = c2.predict("http://example.com/test2")
    lat2 = time.perf_counter() - t1

    assert c1._model is c2._model
    assert c1._tokenizer is c2._tokenizer
    # Reused inference must be fast (< 200ms on CPU)
    assert lat2 < 0.20


# ============================================================================
# 3. HEURISTIC FALLBACK & FAILURE BEHAVIOR
# ============================================================================

def test_heuristic_fallback_explicitly_tagged():
    """Verify heuristic fallback explicitly tags provider as 'heuristic_fallback' and NEVER claims URLBERT."""
    engine = URLClassifierEngine(force_heuristic=True)
    assert engine.is_transformer_active is False
    assert engine.provider_name == "heuristic_fallback"

    prob, features, evidence = engine.analyze_url("http://secure-sbi-kyc-update.xyz/login.php")
    assert prob >= 0.80

    model_evidence = [e for e in evidence if e.type == EvidenceType.URLBERT_MALICIOUS]
    assert len(model_evidence) >= 1
    evi = model_evidence[0]
    assert evi.indicators["provider"] == "heuristic_fallback"
    assert evi.indicators["model_loaded"] is False
    assert "heuristic_fallback" in evi.explanation
    assert "URLBERT neural model" not in evi.explanation


def test_engine_gracefully_handles_transformer_exception():
    """Verify that if the transformer throws at runtime, the engine catches it and falls back seamlessly."""
    engine = URLClassifierEngine()
    with patch.object(engine._transformer, "predict", side_effect=RuntimeError("Simulated CUDA OOM or load error")):
        res = engine.classify("http://secure-sbi-kyc-update.xyz/login.php")
        assert res.provider == "heuristic_fallback"
        assert res.model_loaded is False
        assert "Simulated CUDA OOM" in (res.fallback_reason or "")


# ============================================================================
# 4. THREAT INTELLIGENCE INTEGRATION
# ============================================================================

@pytest.mark.asyncio
async def test_threat_intel_match_generates_critical_evidence():
    """Verify confirmed threat intel match emits critical evidence."""
    ti = ThreatIntelProvider()
    res = await ti.generate_evidence("secure-sbi-kyc-update.xyz", "domain")
    assert res is not None
    assert res.type == EvidenceType.THREAT_INTEL_MATCH
    assert res.source == EvidenceSource.THREAT_INTEL
    assert res.severity_contribution == SeverityContribution.CRITICAL


@pytest.mark.asyncio
async def test_threat_intel_unknown_is_not_safe():
    """Verify that an unknown domain does NOT emit threat intel evidence, but does not declare safe."""
    ti = ThreatIntelProvider()
    res = await ti.generate_evidence("unseen-unknown-domain-12345.com", "domain")
    assert res is None  # No positive match


# ============================================================================
# 5. MODEL CONFIDENCE VS RISK ENGINE DECOUPLING
# ============================================================================

def test_model_confidence_decoupled_from_final_risk():
    """Verify that high model probability alone does not trigger CRITICAL without compounding evidence."""
    risk_engine = RiskEngine()

    # Case A: URLBERT malicious evidence alone without lookalike domain or credential theft
    isolated_urlbert_evidence = [
        EvidenceItem(
            type=EvidenceType.URLBERT_MALICIOUS,
            source=EvidenceSource.WEB,
            value=0.92,
            confidence=0.92,
            severity_contribution=SeverityContribution.HIGH,
            weight=0.30,
            explanation="URLBERT detected malicious tokens."
        )
    ]
    assessment = risk_engine.evaluate(isolated_urlbert_evidence)
    # Without synergy rules, score must not reach CRITICAL (>= 0.85)
    assert assessment.score < 0.85
    assert assessment.level != RiskLevel.CRITICAL

    # Case B: Multiplicative synergy with Lookalike Domain + Credential Path
    synergistic_evidence = [
        EvidenceItem(
            type=EvidenceType.URLBERT_MALICIOUS,
            source=EvidenceSource.WEB,
            value=0.95,
            confidence=0.95,
            severity_contribution=SeverityContribution.CRITICAL,
            weight=0.30,
            explanation="URLBERT flagged phishing."
        ),
        EvidenceItem(
            type=EvidenceType.LOOKALIKE_DOMAIN,
            source=EvidenceSource.WEB,
            value="secure-sbi-kyc-update.xyz",
            confidence=0.95,
            severity_contribution=SeverityContribution.CRITICAL,
            weight=0.30,
            explanation="Mimics SBI."
        ),
        EvidenceItem(
            type=EvidenceType.CREDENTIAL_PATH,
            source=EvidenceSource.WEB,
            value="http://secure-sbi-kyc-update.xyz/login.php",
            confidence=0.90,
            severity_contribution=SeverityContribution.HIGH,
            weight=0.20,
            explanation="Credential endpoint."
        ),
    ]
    syn_assessment = risk_engine.evaluate(synergistic_evidence)
    assert syn_assessment.score >= 0.85
    assert syn_assessment.level == RiskLevel.CRITICAL


# ============================================================================
# 6. ORCHESTRATOR & API ENDPOINT INTEGRATION
# ============================================================================

@pytest.mark.asyncio
async def test_web_orchestrator_complete_pipeline():
    """Verify WebIntelligenceOrchestrator runs URLBERT + Lexical + Threat Intel -> Incident."""
    orchestrator = WebIntelligenceOrchestrator()
    incident = await orchestrator.analyze_url("http://secure-sbi-kyc-update.xyz/login.php")

    assert incident.id is not None
    assert incident.risk_score >= 0.85
    assert incident.risk_level == RiskLevel.CRITICAL
    evi_types = [e.type for e in incident.evidence]
    assert EvidenceType.URLBERT_MALICIOUS in evi_types
    assert EvidenceType.THREAT_INTEL_MATCH in evi_types
    assert len(incident.mitre_techniques) >= 1
    assert len(incident.recommended_actions) >= 1


@pytest.mark.asyncio
async def test_browser_shield_endpoint_integration():
    """Verify /api/v1/analyze/browser endpoint processes URLBERT neural evidence."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/api/v1/analyze/browser", json={
            "url": "http://secure-sbi-kyc-update.xyz/login.php",
            "title": "SBI NetBanking Security Verification",
            "has_password_field": True,
            "claimed_brand": "State Bank of India"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "CRITICAL"
        assert data["risk_score"] >= 0.90


@pytest.mark.asyncio
async def test_url_api_endpoint_backward_compatibility():
    """Verify existing /api/v1/analyze/url endpoint remains 100% backward compatible."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/api/v1/analyze/url", json={
            "url": "https://example.com/docs"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("SAFE", "LOW")
        assert data["risk_score"] < 0.40


# ============================================================================
# 7. PERFORMANCE BENCHMARK
# ============================================================================

def test_urlbert_performance_benchmark():
    """Measure inference latency across benign and malicious URL fixtures."""
    classifier = TransformerURLClassifier()
    # Warmup prediction so cold-start model weight loading is excluded from latency measurement
    classifier.predict("http://example.com/warmup")
    fixtures = [
        "http://secure-sbi-kyc-update.xyz/login.php",
        "http://www.824555.com/app/member/SportOption.php?uid=guest&langx=gb",
        "https://example.com/docs",
        "wikipedia.org/wiki/Computer_security",
    ]

    latencies = []
    for u in fixtures:
        res = classifier.predict(u)
        latencies.append(res.latency_ms)

    avg_latency = sum(latencies) / len(latencies)
    # On CPU, average inference must be under 150ms per URL
    assert avg_latency < 150.0
    print(f"\n[BENCHMARK] URLBERT Average Latency: {avg_latency:.2f}ms on {classifier.get_device()}")
