"""Phase 4 Test Suite — Behavioural Security & Account Takeover (ATO) Prevention Engine.

Verifies:
1. User Baseline Profile Store (seeded identities, dynamic profiles, failed login counters).
2. Geo-Velocity & Haversine Great-Circle Calculation.
3. Impossible Travel detection circuit breakers and feasible travel bounds.
4. Unsupervised Isolation Forest multi-vector anomaly detection.
5. Behavioural Security Orchestrator integrating risk engine, MITRE enrichment, and advisory playbooks.
6. FastAPI POST /api/v1/analyze/auth-event endpoint.
"""

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from app.engines.behavioural.geo_velocity import GeoVelocityCalculator
from app.engines.behavioural.isolation_forest import IsolationForestAnomalyDetector
from app.engines.behavioural.orchestrator import BehaviouralOrchestrator
from app.engines.behavioural.profile_store import LoginRecord, UserProfileStore
from app.main import app
from app.schemas.evidence import EvidenceType, SeverityContribution
from app.schemas.threat import RiskLevel, ThreatAssessment, ThreatType


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# 1. User Baseline Profile Store Tests
# ==============================================================================

def test_user_profile_store_seeded_and_dynamic():
    """Verify seeded executive profiles and dynamic profile auto-creation."""
    store = UserProfileStore()

    # Seeded CFO profile
    cfo = store.get_profile("exec_alice")
    assert cfo is not None
    assert cfo.user_id == "exec_alice"
    assert "US" in cfo.typical_countries
    assert "dev_mac_alice_99" in cfo.known_devices
    assert cfo.last_login is not None
    assert cfo.last_login.city == "San Francisco"

    # Dynamic creation for novel user
    new_user = store.get_or_create_profile("contractor_dave")
    assert new_user.user_id == "contractor_dave"
    assert new_user.failed_login_counter == 0
    assert new_user.total_logins == 0


def test_user_profile_store_login_lifecycle():
    """Verify login tracking: failure increment, success update, and counter reset."""
    store = UserProfileStore()
    user_id = "test_user_lifecycle"

    # 1. Record 2 failures
    t1 = datetime(2026, 9, 26, 10, 0, 0, tzinfo=timezone.utc)
    count = store.record_failure(user_id, t1)
    assert count == 1
    count = store.record_failure(user_id, t1 + timedelta(minutes=1))
    assert count == 2

    profile = store.get_profile(user_id)
    assert profile.failed_login_counter == 2

    # 2. Successful login resets failure counter and records new device/location
    success_record = LoginRecord(
        timestamp=t1 + timedelta(minutes=5),
        latitude=51.5074,
        longitude=-0.1278,
        city="London",
        country="GB",
        ip_address="82.165.197.1",
        asn="AS3356",
        device_id="dev_macbook_pro_m3",
        success=True,
    )
    store.record_login(user_id, success_record)

    updated = store.get_profile(user_id)
    assert updated.failed_login_counter == 0
    assert updated.total_logins == 1
    assert "dev_macbook_pro_m3" in updated.known_devices
    assert "AS3356" in updated.typical_asns
    assert "GB" in updated.typical_countries


# ==============================================================================
# 2. Geo-Velocity & Haversine Great-Circle Tests
# ==============================================================================

def test_haversine_distance_accuracy():
    """Verify Haversine formula against known geographical distances."""
    # San Francisco (37.7749, -122.4194) to New York (40.7128, -74.0060) is ~4130 km
    sf_lat, sf_lon = 37.7749, -122.4194
    ny_lat, ny_lon = 40.7128, -74.0060

    dist = GeoVelocityCalculator.haversine_distance(sf_lat, sf_lon, ny_lat, ny_lon)
    assert 4100.0 < dist < 4200.0

    # Same location yields 0.0 km
    assert GeoVelocityCalculator.haversine_distance(sf_lat, sf_lon, sf_lat, sf_lon) == 0.0


def test_impossible_travel_scenarios():
    """Verify detection of supersonic / impossible travel velocities vs feasible commutes."""
    t0 = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)

    # Scenario A: SF to London (8600 km) in 30 minutes (~17,200 km/h) -> Impossible
    last_login = LoginRecord(
        timestamp=t0,
        latitude=37.7749,
        longitude=-122.4194,
        city="San Francisco",
        country="US",
    )

    london_lat, london_lon = 51.5074, -0.1278
    t_london = t0 + timedelta(minutes=30)

    evidence_a, metrics_a = GeoVelocityCalculator.evaluate_movement(
        last_login=last_login,
        current_lat=london_lat,
        current_lon=london_lon,
        current_time=t_london,
        current_country="GB",
        known_countries={"US"},
    )

    assert metrics_a is not None
    assert metrics_a["is_impossible"] is True
    assert metrics_a["velocity_kmh"] > 10000.0
    assert any(e.type == EvidenceType.IMPOSSIBLE_TRAVEL for e in evidence_a)

    # Scenario B: SF to Oakland (15 km) in 40 minutes (~22.5 km/h) -> Feasible local commute
    oakland_lat, oakland_lon = 37.8044, -122.2712
    t_oakland = t0 + timedelta(minutes=40)

    evidence_b, metrics_b = GeoVelocityCalculator.evaluate_movement(
        last_login=last_login,
        current_lat=oakland_lat,
        current_lon=oakland_lon,
        current_time=t_oakland,
        current_country="US",
        known_countries={"US"},
    )

    assert metrics_b is not None
    assert metrics_b["is_impossible"] is False
    assert not any(e.type == EvidenceType.IMPOSSIBLE_TRAVEL for e in evidence_b)

    # Scenario C: SF to New York (4130 km) in 6 hours (~688 km/h) -> Feasible commercial flight
    ny_lat, ny_lon = 40.7128, -74.0060
    t_ny = t0 + timedelta(hours=6)

    evidence_c, metrics_c = GeoVelocityCalculator.evaluate_movement(
        last_login=last_login,
        current_lat=ny_lat,
        current_lon=ny_lon,
        current_time=t_ny,
        current_country="US",
        known_countries={"US"},
    )

    assert metrics_c is not None
    assert metrics_c["is_impossible"] is False
    # Relocation indicator produced without impossible travel flag
    assert any(e.type == EvidenceType.ANOMALOUS_GEOLOCATION for e in evidence_c)


# ==============================================================================
# 3. Isolation Forest Anomaly Detection Tests
# ==============================================================================

def test_isolation_forest_anomaly_scoring():
    """Verify Isolation Forest differentiates normal business activity from abnormal multi-vector outliers."""
    detector = IsolationForestAnomalyDetector(random_state=42)
    profile = UserProfileStore().get_profile("exec_alice")

    # Inlier Event: Wednesday at 13:00, known device, known ASN, home country, 0 failures, 15 km/h
    ev_inlier, score_inlier = detector.evaluate_auth_event(
        user_id="exec_alice",
        profile=profile,
        hour=13,
        day_of_week=2,  # Wednesday
        is_new_device=False,
        is_new_asn=False,
        is_new_country=False,
        failed_attempts=0,
        velocity_kmh=15.0,
    )
    assert score_inlier < 0.55
    assert not any(e.type == EvidenceType.ISOLATION_FOREST_ANOMALY for e in ev_inlier)

    # Outlier Event: Sunday at 03:00 AM, unknown device, unknown ASN, novel country, 4 failed attempts, 5000 km/h
    ev_outlier, score_outlier = detector.evaluate_auth_event(
        user_id="exec_alice",
        profile=profile,
        hour=3,
        day_of_week=6,  # Sunday
        is_new_device=True,
        is_new_asn=True,
        is_new_country=True,
        failed_attempts=4,
        velocity_kmh=5000.0,
    )
    assert score_outlier > score_inlier
    assert score_outlier >= 0.60
    assert any(e.type == EvidenceType.ISOLATION_FOREST_ANOMALY for e in ev_outlier)
    assert any(e.type == EvidenceType.OFF_HOURS_ACTIVITY for e in ev_outlier)
    assert any(e.type == EvidenceType.NEW_DEVICE_FINGERPRINT for e in ev_outlier)
    assert any(e.type == EvidenceType.FAILED_LOGIN_BURST for e in ev_outlier)


# ==============================================================================
# 4. Behavioural Security Orchestrator & ATO Threat Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_orchestrator_account_takeover_attack():
    """Verify Flagship ATO Synergy: Failed Login Burst + Impossible Travel + Unknown Device."""
    orchestrator = BehaviouralOrchestrator()

    # User exec_alice last logged in SF at 14:00 on 2026-09-25.
    # An attack arrives 20 minutes later from Frankfurt, Germany with 4 failed attempts on a new device.
    event_time = datetime(2026, 9, 25, 14, 20, 0, tzinfo=timezone.utc)

    incident = await orchestrator.analyze_auth_event(
        user_id="exec_alice",
        timestamp=event_time,
        ip_address="194.26.29.112",
        latitude=50.1109,
        longitude=8.6821,  # Frankfurt, Germany (~9150 km away in 20 min!)
        city="Frankfurt",
        country="DE",
        asn="AS51167",  # Contabo / Hosting ASN
        device_id="dev_attacker_kali_v4",
        success=False,
        injected_failed_burst=4,
    )

    assert incident.id.startswith("inc_auth_")
    # Risk should hit Critical/High due to impossible travel & ATO synergy circuit breaker
    assert incident.risk_score >= 0.85
    assert incident.threat_type in (ThreatType.ACCOUNT_TAKEOVER, ThreatType.AUTHENTICATION_ANOMALY)
    assert incident.assessment == ThreatAssessment.MALICIOUS

    # MITRE ATT&CK Mapping
    mitre_ids = {t.id for t in incident.mitre_techniques}
    assert "T1078" in mitre_ids  # Valid Accounts
    assert "T1110.003" in mitre_ids  # Password Spraying / Brute Force

    # Advisory Playbooks
    action_titles = [a.title for a in incident.recommended_actions]
    assert any("Revoke Active User Sessions" in t for t in action_titles)
    assert any("Step-Up Multi-Factor Authentication" in t for t in action_titles)


@pytest.mark.asyncio
async def test_orchestrator_threat_intel_c2_ip_breaker():
    """Verify Threat Intel Circuit Breaker: Login from verified C2/Malicious IP."""
    orchestrator = BehaviouralOrchestrator()

    # 185.220.101.5 is in data/fixtures/threat_intel_ioc.db as abuse_ch_c2
    incident = await orchestrator.analyze_auth_event(
        user_id="admin_charlie",
        ip_address="185.220.101.5",
        city="Moscow",
        country="RU",
        success=False,
    )

    assert incident.risk_score >= 0.90  # Threat intel circuit breaker floor
    assert incident.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert any(e.type == EvidenceType.THREAT_INTEL_MATCH for e in incident.evidence)


@pytest.mark.asyncio
async def test_orchestrator_benign_executive_login():
    """Verify routine executive authentication remains low risk / SAFE."""
    orchestrator = BehaviouralOrchestrator()

    # Alice logging in 2 hours later from San Francisco on known Mac device
    event_time = datetime(2026, 9, 25, 16, 0, 0, tzinfo=timezone.utc)

    incident = await orchestrator.analyze_auth_event(
        user_id="exec_alice",
        timestamp=event_time,
        ip_address="192.168.1.50",
        latitude=37.7749,
        longitude=-122.4194,
        city="San Francisco",
        country="US",
        asn="AS15169",
        device_id="dev_mac_alice_99",
        success=True,
    )

    assert incident.risk_score <= 0.35
    assert incident.assessment == ThreatAssessment.SAFE
    assert incident.threat_type == ThreatType.BENIGN


# ==============================================================================
# 5. FastAPI HTTP API Endpoint Tests
# ==============================================================================

def test_api_analyze_auth_event_endpoint(client):
    """Verify HTTP POST /api/v1/analyze/auth-event API endpoint."""
    payload = {
        "user_id": "dev_bob",
        "ip_address": "10.100.2.14",
        "latitude": 12.9716,
        "longitude": 77.5946,
        "city": "Bengaluru",
        "country": "IN",
        "asn": "AS9498",
        "device_id": "dev_thinkpad_bob_01",
        "success": True,
        "auth_method": "password",
    }

    response = client.post("/api/v1/analyze/auth-event", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "id" in data
    assert data["source"] == "auth_intelligence"
    assert data["input_type"] == "auth_event"
    assert "risk_score" in data
    assert "recommended_actions" in data
    assert len(data["entities"]) >= 2
