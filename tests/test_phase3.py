import io
import pytest
import pytest_asyncio
from PIL import Image
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import init_db
from app.main import app
from app.engines.identity.registry import IdentityRegistry
from app.engines.media.audio_synthetic import W2V2AasistSyntheticDetector
from app.engines.media.speaker_embedding import EcapaTdnnSpeakerVerifier
from app.engines.media.image_forensics import ImageForensicsEngine
from app.engines.media.image_synthetic import ImageSyntheticClassifier
from app.engines.media.orchestrator import MediaIntelligenceOrchestrator
from app.schemas.threat import RiskLevel, ThreatType

TEST_DB_PATH = settings.DATA_DIR / "test_orion_p3.db"
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


@pytest.fixture
def client():
    return TestClient(app)



@pytest.fixture
def sample_image_bytes():
    img = Image.new("RGB", (128, 128), color=(73, 109, 137))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def sample_noisy_image_bytes():
    import numpy as np
    arr = np.random.randint(0, 255, (128, 128, 3), dtype=np.uint8)
    img = Image.fromarray(arr)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_identity_registry():
    """Verify protected VIP identity profiles are correctly loaded."""
    registry = IdentityRegistry()
    assert len(registry.profiles) >= 3

    cfo = registry.find_by_name_or_title("Rajesh Sharma")
    assert cfo is not None
    assert cfo.role_title == "Chief Financial Officer"

    by_title = registry.find_by_name_or_title("Vice Chancellor")
    assert by_title is not None
    assert "Mishra" in by_title.display_name


def test_w2v2_aasist_synthetic_detector():
    """Verify synthetic speech detection generates calibrated evidence."""
    detector = W2V2AasistSyntheticDetector()

    # Direct injected high synthetic score
    prob, indicators, evidence = detector.analyze_audio_features(injected_synthetic_score=0.94)
    assert prob == 0.94
    assert len(evidence) >= 1
    assert "W2V2-AASIST" in evidence[0].explanation


def test_ecapa_speaker_verifier():
    """Verify speaker verification decouples acoustic similarity from malice."""
    registry = IdentityRegistry()
    verifier = EcapaTdnnSpeakerVerifier(registry=registry)

    cfo = registry.find_by_name_or_title("Rajesh Sharma")
    assert cfo is not None

    matched, similarity, evidence = verifier.verify_speaker(
        candidate_embedding=cfo.voice_embedding_reference,
        claimed_identity_name="Rajesh Sharma",
    )
    assert matched is not None
    assert similarity >= 0.90
    assert len(evidence) >= 1


@pytest.mark.asyncio
async def test_flagship_voice_cloning_synergy():
    """Flagship Verification:

    Synthetic Voice (W2V2-AASIST=0.92) +
    Targeted Executive Match (Rajesh Sharma ECAPA=0.88) +
    Coercive Financial Wire Transfer Transcript
    -> Triggers Voice Impersonation Multiplicative Synergy -> Risk Score >= 0.95 (CRITICAL).
    """
    orchestrator = MediaIntelligenceOrchestrator()

    urgent_cfo_transcript = (
        "Rajesh Sharma here, CFO. I am in an urgent closed board session. "
        "Transfer forty thousand dollars to the vendor account immediately. "
        "Do not delay or standard approvals will lapse."
    )

    incident = await orchestrator.analyze_audio(
        provided_transcript=urgent_cfo_transcript,
        claimed_identity_name="Rajesh Sharma",
        injected_synthetic_score=0.92,
        injected_similarity_score=0.88,
    )

    assert incident.id is not None
    assert incident.risk_score >= 0.95
    assert incident.risk_level in (RiskLevel.CRITICAL, "CRITICAL")
    assert incident.threat_type in (
        ThreatType.VOICE_CLONE,
        ThreatType.IMPERSONATION,
        "voice_clone",
        "impersonation",
    )

    # Verify MITRE ATT&CK includes Impersonation / Spearphishing Voice
    techniques = incident.mitre_techniques
    tech_ids = [t.id if hasattr(t, "id") else (t.get("id") if isinstance(t, dict) else str(t)) for t in techniques]
    assert any("T1656" in tid or "T1566.004" in tid for tid in tech_ids)


    # Verify Response Playbook has out-of-band verification
    assert len(incident.recommended_actions) >= 1
    assert any("Out-of-Band" in a.title or "CALLBACK" in a.title.upper() or "VOICE" in a.title.upper() or "VERIF" in a.title.upper() for a in incident.recommended_actions)




@pytest.mark.asyncio
async def test_synthetic_voice_without_coercion_not_critical():
    """Verify Core Principle: Synthetic Voice != Malicious Attack.

    High synthetic score on a benign public announcement must NOT trigger the 0.95 critical synergy floor.
    """
    orchestrator = MediaIntelligenceOrchestrator()

    benign_transcript = "Good morning everyone. The university library will close at 8 PM this evening for maintenance."

    incident = await orchestrator.analyze_audio(
        provided_transcript=benign_transcript,
        injected_synthetic_score=0.91,
        injected_similarity_score=0.10,
    )

    # Without financial coercion and identity impersonation, score should remain below Critical
    assert incident.risk_score < 0.90
    assert incident.risk_level not in (RiskLevel.CRITICAL, "CRITICAL")


def test_image_4_signal_separation():
    """Verify 4-Signal Separation in Image Intelligence:

    Signal 1: AI Generated
    Signal 2: Tampering / Manipulation
    Signal 3: Identity Target Match
    Signal 4: Malicious / Coercive Intent
    """
    classifier = ImageSyntheticClassifier()

    # Scenario A: Benign Generative AI Art -> Low Risk
    signals_benign, evidence_benign = classifier.evaluate_media_signals(
        ai_generated_prob=0.95,
        manipulation_prob=0.0,
        identity_similarity=0.0,
        malicious_intent=0.0,
    )
    assert signals_benign["risk_multiplier"] <= 0.40

    # Scenario B: Malicious Deepfake Targeting VIP with Coercive Context -> High Multiplier
    signals_hostile, evidence_hostile = classifier.evaluate_media_signals(
        ai_generated_prob=0.92,
        manipulation_prob=0.88,
        identity_similarity=0.85,
        malicious_intent=0.80,
        target_name="Dr. Aris Thorne",
    )
    assert signals_hostile["risk_multiplier"] >= 0.70
    assert len(evidence_hostile) >= 3


def test_opencv_image_forensics(sample_image_bytes, sample_noisy_image_bytes):
    """Verify classical OpenCV forensics extracts Laplacian variance, noise, and frequency metrics."""
    forensics = ImageForensicsEngine()

    info_clean, ev_clean = forensics.analyze_image_bytes(sample_image_bytes)
    assert "laplacian_variance" in info_clean
    assert "noise_std" in info_clean

    info_noisy, ev_noisy = forensics.analyze_image_bytes(sample_noisy_image_bytes)
    assert info_noisy["laplacian_variance"] > info_clean["laplacian_variance"]


@pytest.mark.asyncio
async def test_multimodal_video_analysis():
    """Verify Video Deepfake Pipeline decomposing frame and temporal manipulation."""
    orchestrator = MediaIntelligenceOrchestrator()

    incident = await orchestrator.analyze_video(
        video_name="urgent_statement_ceo.mp4",
        frame_manipulation_score=0.88,
        temporal_jitter_score=0.84,
        target_name="Vikram Malhotra",
        audio_transcript="I am ordering an emergency settlement payment immediately.",
    )

    assert incident.id is not None
    assert incident.risk_score >= 0.70
    assert incident.threat_type in (ThreatType.DEEPFAKE_VIDEO, "DEEPFAKE_VIDEO")
    assert incident.metadata["video_name"] == "urgent_statement_ceo.mp4"


def test_phase3_api_endpoints(client, sample_image_bytes):
    """Verify HTTP API endpoints for audio, image, and video analysis."""
    import base64

    # 1. Audio endpoint
    resp_audio = client.post(
        "/api/v1/analyze/audio",
        json={
            "claimed_identity_name": "Rajesh Sharma",
            "provided_transcript": "Authorize wire transfer right away.",
            "injected_synthetic_score": 0.89,
            "injected_similarity_score": 0.85,
        },
    )
    assert resp_audio.status_code == 200
    data_audio = resp_audio.json()
    assert "risk_score" in data_audio
    assert data_audio["risk_score"] >= 0.80

    # 2. Image endpoint
    img_b64 = base64.b64encode(sample_image_bytes).decode("utf-8")
    resp_img = client.post(
        "/api/v1/analyze/image",
        json={
            "ai_generated_prob": 0.88,
            "manipulation_prob": 0.75,
            "identity_similarity": 0.80,
            "malicious_intent": 0.70,
            "target_name": "Dr. Aris Thorne",
            "image_b64": img_b64,
        },
    )
    assert resp_img.status_code == 200
    data_img = resp_img.json()
    assert "risk_score" in data_img

    # 3. Video endpoint
    resp_vid = client.post(
        "/api/v1/analyze/video",
        json={
            "video_name": "board_briefing.mp4",
            "frame_manipulation_score": 0.85,
            "temporal_jitter_score": 0.82,
            "target_name": "Rajesh Sharma",
            "audio_transcript": "Transfer funds to overseas partner without review.",
        },
    )
    assert resp_vid.status_code == 200
    data_vid = resp_vid.json()
    assert "risk_score" in data_vid
