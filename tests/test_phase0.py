"""Comprehensive Verification Tests for ORION v2 Phase 0 (Foundation & Contracts)."""

import pytest
import pytest_asyncio
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from httpx import AsyncClient, ASGITransport

from app.core.config import settings
from app.core.database import execute_write, init_db
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceType, SeverityContribution
from app.schemas.threat import MitreTechnique, RiskAssessment, RiskLevel, ThreatAssessment, ThreatType
from app.schemas.response import ActionCategory, ActionPriority, ActionRecommendation
from app.schemas.incident import Incident, IncidentEntity, IncidentStatus, EntityType
from app.providers.base import BaseProvider, ProviderResult, ProviderStatus
from app.repositories.incident_repo import IncidentRepository
from app.main import app

# Ensure a dedicated test database path
TEST_DB_PATH = settings.DATA_DIR / "test_orion.db"
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
async def test_evidence_contract():
    """Verify Universal Evidence contract attributes, constraints, and serialization."""
    evidence = EvidenceItem(
        type=EvidenceType.LOOKALIKE_DOMAIN,
        source=EvidenceSource.WEB,
        value=True,
        confidence=0.92,
        severity_contribution=SeverityContribution.HIGH,
        weight=0.25,
        indicators={"levenshtein_distance": 1, "target": "sbi.co.in"},
        explanation="Domain closely mimics state bank portal."
    )
    assert evidence.confidence == 0.92
    assert evidence.severity_contribution == "HIGH"
    data = evidence.model_dump(mode="json")
    assert data["type"] == "lookalike_domain"
    assert data["source"] == "web_intelligence"


@pytest.mark.asyncio
async def test_provider_inconclusive_contract():
    """Verify that provider failures MUST produce INCONCLUSIVE, never SAFE."""
    class DummyProvider(BaseProvider):
        async def is_healthy(self) -> bool:
            return False

    provider = DummyProvider("dummy_test", "1.0.0")
    res = provider.create_inconclusive_result("API timed out")
    assert res.status == ProviderStatus.INCONCLUSIVE
    assert res.status != "SAFE"
    assert res.error_message == "API timed out"


@pytest.mark.asyncio
async def test_incident_repository_crud():
    """Verify SQLite persistence, retrieval, status updates, and summary metrics."""
    await execute_write("DELETE FROM incidents")
    repo = IncidentRepository()

    # 1. Create Incident
    incident = Incident(
        title="Suspicious Banking Phishing Site",
        source=EvidenceSource.WEB,
        input_type="url",
        input_summary="http://sbi-kyc-verify-portal.xyz/login",
        threat_type=ThreatType.PHISHING,
        assessment=ThreatAssessment.MALICIOUS,
        risk_level=RiskLevel.CRITICAL,
        risk_score=0.94,
        confidence=0.91,
        explanation="Look-alike domain hosting credential harvesting form.",
        risk_drivers=["Look-alike domain", "Urgent KYC verification request"],
        mitre_techniques=[
            MitreTechnique(
                id="T1566.002",
                name="Spearphishing Link",
                tactic="Initial Access",
                url="https://attack.mitre.org/techniques/T1566/002/"
            )
        ],
        evidence=[
            EvidenceItem(
                type=EvidenceType.LOOKALIKE_DOMAIN,
                source=EvidenceSource.WEB,
                value=True,
                confidence=0.95,
                severity_contribution=SeverityContribution.CRITICAL,
                explanation="Domain 'sbi-kyc-verify-portal.xyz' targets SBI."
            )
        ],
        recommended_actions=[
            ActionRecommendation(
                title="Block URL",
                description="Add domain to perimeter blocklist.",
                category=ActionCategory.BLOCK,
                priority=ActionPriority.P0_IMMEDIATE,
                target_entity="sbi-kyc-verify-portal.xyz"
            )
        ],
        entities=[
            IncidentEntity(name="sbi-kyc-verify-portal.xyz", type=EntityType.DOMAIN),
            IncidentEntity(name="State Bank of India", type=EntityType.ORGANIZATION)
        ]
    )

    created = await repo.create(incident)
    assert created.id == incident.id

    # 2. Get by ID
    fetched = await repo.get_by_id(incident.id)
    assert fetched is not None
    assert fetched.title == incident.title
    assert fetched.risk_score == 0.94
    assert fetched.risk_level == RiskLevel.CRITICAL
    assert len(fetched.evidence) == 1
    assert fetched.evidence[0].type == EvidenceType.LOOKALIKE_DOMAIN
    assert len(fetched.mitre_techniques) == 1
    assert fetched.mitre_techniques[0].id == "T1566.002"

    # 3. Update Status
    updated = await repo.update_status(incident.id, IncidentStatus.INVESTIGATING)
    assert updated is not None
    assert updated.status == IncidentStatus.INVESTIGATING

    # 4. List Incidents
    all_incidents = await repo.list_all(limit=10)
    assert len(all_incidents) == 1
    assert all_incidents[0].id == incident.id

    # 5. Log Analysis Event
    event_id = await repo.log_event(
        input_type="url",
        source="web",
        risk_score=0.94,
        risk_level="CRITICAL",
        duration_ms=12.4,
        incident_id=incident.id
    )
    assert event_id.startswith("evt_")

    # 6. Dashboard Summary
    summary = await repo.get_dashboard_summary()
    assert summary["threats_detected"] == 1
    assert summary["phishing_attempts"] == 1
    assert summary["risk_distribution"]["CRITICAL"] == 1


@pytest.mark.asyncio
async def test_fastapi_endpoints():
    """Verify FastAPI routes for system health, incident listing, and dashboard summary."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Root
        res = await ac.get("/")
        assert res.status_code == 200
        assert res.json()["service"] == "ORION v2"

        # Health
        health_res = await ac.get("/api/v1/system/health")
        assert health_res.status_code == 200
        health_data = health_res.json()
        assert health_data["status"] == "online"
        assert health_data["database"]["status"] == "connected"

        # Incidents List (initially empty or populated)
        inc_res = await ac.get("/api/v1/incidents")
        assert inc_res.status_code == 200
        assert isinstance(inc_res.json(), list)

        # Dashboard Summary
        dash_res = await ac.get("/api/v1/incidents/summary/dashboard")
        assert dash_res.status_code == 200
        dash_data = dash_res.json()
        assert "threats_detected" in dash_data
        assert "risk_distribution" in dash_data
