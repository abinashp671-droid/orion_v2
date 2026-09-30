"""Comprehensive Verification Tests for ORION v2 Phase 2 (Web & Phishing Intelligence + Browser Shield)."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.core.config import settings
from app.core.database import init_db
from app.engines.phishing.url_features import URLLexicalExtractor
from app.engines.phishing.url_classifier import URLClassifierEngine
from app.engines.phishing.text_classifier import DistilBertPhishingClassifier
from app.engines.phishing.orchestrator import WebIntelligenceOrchestrator
from app.schemas.evidence import EvidenceType
from app.schemas.threat import RiskLevel, ThreatType
from app.main import app

TEST_DB_PATH = settings.DATA_DIR / "test_orion_p2.db"
settings.DATABASE_PATH = TEST_DB_PATH


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    """Setup and teardown a clean SQLite test database."""
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    await init_db()
    yield
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except PermissionError:
            pass


@pytest.mark.asyncio
async def test_url_feature_extraction_phishing():
    """Verify 24-feature extractor detects lookalike, suspicious TLD, and credential endpoints."""
    phish_url = "http://secure-sbi-kyc-update.xyz/login.php?redirect=account"
    feats = URLLexicalExtractor.extract_features(phish_url)

    assert feats["hostname"] == "secure-sbi-kyc-update.xyz"
    assert feats["tld"] == "xyz"
    assert feats["suspicious_tld_flag"] is True
    assert feats["credential_path_flag"] is True
    assert feats["redirect_parameter_count"] >= 1
    assert feats["brand_similarity_score"] >= 0.70
    assert feats["targeted_brand"] == "sbi"
    assert feats["url_entropy"] > 3.0


@pytest.mark.asyncio
async def test_url_classifier_scoring():
    """Verify URL classifier assigns elevated threat probability and emits normalized evidence."""
    engine = URLClassifierEngine()
    phish_url = "http://secure-sbi-kyc-update.xyz/login.php"
    
    prob, feats, evidence = engine.analyze_url(phish_url)
    assert prob >= 0.85
    evi_types = [e.type for e in evidence]
    assert EvidenceType.LOOKALIKE_DOMAIN in evi_types
    assert EvidenceType.SUSPICIOUS_TLD in evi_types
    assert EvidenceType.CREDENTIAL_PATH in evi_types
    assert EvidenceType.URLBERT_MALICIOUS in evi_types


@pytest.mark.asyncio
async def test_distilbert_text_classifier():
    """Verify text phishing classifier flags coercive urgent language."""
    classifier = DistilBertPhishingClassifier()
    suspicious_text = "URGENT: Your bank account is suspended due to unverified KYC. Click here to confirm identity immediately."
    
    prob, evidence = classifier.analyze(suspicious_text)
    assert prob >= 0.75
    assert len(evidence) >= 1
    assert evidence[0].type == EvidenceType.PHISHING_LANGUAGE


@pytest.mark.asyncio
async def test_web_orchestrator_url_analysis():
    """Verify end-to-end URL analysis pipeline: features -> threat intel -> risk -> incident persistence."""
    orchestrator = WebIntelligenceOrchestrator()
    incident = await orchestrator.analyze_url("http://secure-sbi-kyc-update.xyz/login.php")

    assert incident.risk_level == RiskLevel.CRITICAL
    assert incident.risk_score >= 0.85
    assert incident.threat_type in (ThreatType.PHISHING, ThreatType.MALICIOUS_URL)
    
    # Check MITRE mapping
    mitre_ids = [m.id for m in incident.mitre_techniques]
    assert "T1566.002" in mitre_ids
    assert "T1583.001" in mitre_ids

    # Check evidence lineage
    evi_types = [e.type for e in incident.evidence]
    assert EvidenceType.LOOKALIKE_DOMAIN in evi_types
    assert EvidenceType.THREAT_INTEL_MATCH in evi_types  # Verified by pre-seeded threat intel fixture

    # Check advisory playbooks
    assert len(incident.recommended_actions) >= 2


@pytest.mark.asyncio
async def test_web_orchestrator_browser_page():
    """Verify Browser Shield analysis handler with active password field on lookalike domain."""
    orchestrator = WebIntelligenceOrchestrator()
    incident = await orchestrator.analyze_browser_page(
        url="http://hdfc-security-netbanking.top/auth",
        title="HDFC NetBanking Secure Login",
        has_password_field=True,
        form_actions=["/submit_credentials.php"],
        claimed_brand="HDFC Bank"
    )

    assert incident.risk_level == RiskLevel.CRITICAL
    assert incident.risk_score >= 0.85
    evi_types = [e.type for e in incident.evidence]
    assert EvidenceType.CREDENTIAL_HARVEST_INTENT in evi_types
    assert EvidenceType.LOOKALIKE_DOMAIN in evi_types


@pytest.mark.asyncio
async def test_fastapi_analyze_endpoints():
    """Verify FastAPI routes for /analyze/url, /analyze/message, and /analyze/browser."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. URL Analysis
        res_url = await ac.post("/api/v1/analyze/url", json={
            "url": "http://secure-sbi-kyc-update.xyz/login.php",
            "context": "Verify KYC immediately"
        })
        assert res_url.status_code == 200
        data_url = res_url.json()
        assert data_url["risk_level"] == "CRITICAL"
        assert len(data_url["evidence"]) >= 3

        # 2. Message Analysis
        res_msg = await ac.post("/api/v1/analyze/message", json={
            "text": "Your SBI account is suspended. Verify KYC at http://secure-sbi-kyc-update.xyz/login.php immediately."
        })
        assert res_msg.status_code == 200
        data_msg = res_msg.json()
        assert data_msg["risk_level"] in ("HIGH", "CRITICAL")

        # 3. Browser Shield Analysis
        res_browser = await ac.post("/api/v1/analyze/browser", json={
            "url": "http://secure-sbi-kyc-update.xyz/login.php",
            "title": "SBI KYC Verification",
            "has_password_field": True,
            "claimed_brand": "State Bank of India"
        })
        assert res_browser.status_code == 200
        data_browser = res_browser.json()
        assert data_browser["risk_level"] == "CRITICAL"


@pytest.mark.asyncio
async def test_browser_shield_safe_site_analysis():
    """Verify Browser Shield assigns SAFE risk level to benign, non-phishing domains."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post("/api/v1/analyze/browser", json={
            "url": "https://example.com/docs",
            "title": "Example Domain Documentation",
            "has_password_field": False,
            "claimed_brand": None
        })
        assert res.status_code == 200
        data = res.json()
        assert data["risk_level"] in ("SAFE", "LOW")
        assert data["risk_score"] < 0.40


@pytest.mark.asyncio
async def test_browser_shield_api_validation():
    """Verify Browser Shield rejects empty URL payload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post("/api/v1/analyze/browser", json={
            "url": "",
            "title": "Empty Page"
        })
        assert res.status_code == 400
        assert "URL cannot be empty" in res.json()["detail"]


@pytest.mark.asyncio
async def test_browser_shield_deep_link_contract():
    """Verify Browser Shield incident ID is retrievable via GET /api/v1/incidents/{id} for frontend deep-link."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post("/api/v1/analyze/browser", json={
            "url": "http://phish-axis-login.xyz/auth",
            "title": "Axis Bank Secure NetBanking",
            "has_password_field": True,
            "form_actions": ["http://exfiltrate.xyz/steal.php"],
            "claimed_brand": "Axis Bank"
        })
        assert res.status_code == 200
        incident = res.json()
        inc_id = incident["id"]
        assert inc_id.startswith("inc_")
        
        # Test frontend deep-link endpoint retrieval
        res_get = await ac.get(f"/api/v1/incidents/{inc_id}")
        assert res_get.status_code == 200
        fetched = res_get.json()
        assert fetched["id"] == inc_id
        assert fetched["risk_level"] in ("HIGH", "CRITICAL")

