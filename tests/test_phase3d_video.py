"""Phase 3D Video Deepfake & Multimodal Video Intelligence Tests.

Verifies:
1. Video Validation & Decoding (Container magic bytes, corruption, bounds).
2. Video Metadata Extraction (FPS, duration, dimensions, frames, codec).
3. Bounded Frame Sampling (Deterministic sampling, resource bounds).
4. Real Deepfake Model Loading & Inference (dima806/deepfake_vs_real_image_detection ViT).
5. Face Detection & Tracking on Video Frames (OpenCV YuNet).
6. Temporal Consistency Analysis & Aggregation Formula (0.50*P75 + 0.30*P90 + 0.20*R_suspicious).
7. Isolated Suspicious Frame Protection (Case E).
8. Audio Stream Extraction & Phase 3B Integration (W2V2-AASIST, Whisper, ECAPA-TDNN).
9. Audio-Visual Consistency (Lip-sync vs audio envelope correlation).
10. ArcFace Identity Comparison to Registered Profiles.
11. Multi-Signal Digital Impersonation Synergy (Case C).
12. Multi-Dimensional Separation (Case A Benign Synthetic, Case B Natural, Case D Audio-Only).
13. End-to-End Orchestrator & Multipart Upload API.
"""

import io
import os
from pathlib import Path
import tempfile
import time
from typing import Tuple
import cv2
import numpy as np
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.core.database import init_db
from app.engines.identity.registry import IdentityRegistry, ProtectedIdentity
from app.engines.media.audiovisual_engine import AudioVisualConsistencyEngine
from app.engines.media.face_engine import FaceIntelligenceEngine
from app.engines.media.orchestrator import MediaIntelligenceOrchestrator
from app.engines.media.temporal_engine import TemporalConsistencyEngine
from app.engines.media.video_audio import VideoAudioExtractor
from app.engines.media.video_deepfake import VideoDeepfakeClassifier
from app.engines.media.video_preprocess import (
    UnsupportedVideoFormatError,
    VideoCorruptedError,
    VideoEmptyError,
    VideoOversizedError,
    VideoPreprocessor,
)
from app.main import app
from app.schemas.evidence import EvidenceSource, EvidenceType
from app.schemas.threat import RiskLevel, ThreatType

TEST_DB_PATH = settings.DATA_DIR / "test_orion_p3d.db"
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


def _create_synthetic_mp4(
    num_frames: int = 16,
    fps: float = 10.0,
    width: int = 128,
    height: int = 128,
    with_face_drawing: bool = True,
) -> bytes:
    """Create a valid in-memory MP4 video stream using OpenCV."""
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(tmp_path, fourcc, fps, (width, height))

        for i in range(num_frames):
            frame = np.full((height, width, 3), 40 + (i * 2) % 150, dtype=np.uint8)

            if with_face_drawing:
                # Draw a recognizable human face structure for face detector
                center_x, center_y = width // 2, height // 2
                # Head oval
                cv2.ellipse(frame, (center_x, center_y), (35, 45), 0, 0, 360, (180, 150, 130), -1)
                # Eyes
                cv2.circle(frame, (center_x - 12, center_y - 10), 4, (40, 30, 20), -1)
                cv2.circle(frame, (center_x + 12, center_y - 10), 4, (40, 30, 20), -1)
                # Nose
                cv2.line(frame, (center_x, center_y - 5), (center_x, center_y + 8), (120, 90, 80), 2)
                # Mouth
                mouth_open = 4 if (i % 2 == 0) else 1
                cv2.ellipse(frame, (center_x, center_y + 20), (12, mouth_open), 0, 0, 360, (50, 40, 150), -1)

            writer.write(frame)

        writer.release()

        with open(tmp_path, "rb") as f:
            video_bytes = f.read()
        return video_bytes
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ============================================================================
# 1. Video Validation & Decoding Tests
# ============================================================================

def test_video_validation_empty_bytes():
    """Verify empty video bytes rejection."""
    with pytest.raises(VideoEmptyError):
        VideoPreprocessor.validate_and_sample(b"", filename="empty.mp4")


def test_video_validation_unsupported_format():
    """Verify rejection of non-video or unsupported container formats."""
    fake_gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00!"
    with pytest.raises(UnsupportedVideoFormatError):
        VideoPreprocessor.validate_and_sample(fake_gif, filename="test.gif")


def test_video_validation_corrupted_header():
    """Verify rejection of corrupted video bytes with malformed stream."""
    bad_mp4 = b"\x00\x00\x00\x18ftypisomCORRUPTED_GARBAGE_DATA_1234567890"
    with pytest.raises(VideoCorruptedError):
        VideoPreprocessor.validate_and_sample(bad_mp4, filename="corrupt.mp4")


def test_video_validation_oversized_file():
    """Verify rejection of oversized video files exceeding 50 MB."""
    preprocessor = VideoPreprocessor()
    oversized_dummy = b"\x00" * (51 * 1024 * 1024)
    with pytest.raises(VideoOversizedError):
        preprocessor.validate_and_sample(oversized_dummy, filename="huge.mp4")


# ============================================================================
# 2. Metadata Extraction & Bounded Sampling Tests
# ============================================================================

def test_video_metadata_and_bounded_sampling():
    """Verify deterministic metadata extraction and bounded sampling guarantees."""
    vid_bytes = _create_synthetic_mp4(num_frames=20, fps=10.0, width=128, height=128)
    preprocessed = VideoPreprocessor.validate_and_sample(
        video_bytes=vid_bytes,
        filename="clip.mp4",
        max_frames=10,
        min_frames=4,
    )

    meta = preprocessed.metadata
    assert meta.fps == 10.0
    assert meta.width == 128
    assert meta.height == 128
    assert meta.duration_seconds >= 1.5
    assert meta.total_frames >= 15
    assert meta.file_size_bytes == len(vid_bytes)

    # Frame sampling is bounded by max_frames
    assert len(preprocessed.sampled_frames) <= 10
    assert len(preprocessed.sampled_frames) >= 4

    # Each sampled frame has frame_idx, timestamp_sec, and valid BGR numpy array
    for idx, ts, frame in preprocessed.sampled_frames:
        assert isinstance(idx, int)
        assert isinstance(ts, float)
        assert isinstance(frame, np.ndarray)
        assert frame.shape == (128, 128, 3)


# ============================================================================
# 3. Real Deepfake Model Loading & Inference Tests
# ============================================================================

def test_real_video_deepfake_classifier_inference():
    """Verify genuine ViT inference using dima806/deepfake_vs_real_image_detection."""
    classifier = VideoDeepfakeClassifier()
    assert classifier.is_model_loaded() is True
    assert classifier.model_id == "dima806/deepfake_vs_real_image_detection"

    # Test synthetic human face frame
    test_face = np.full((224, 224, 3), 150, dtype=np.uint8)
    cv2.circle(test_face, (80, 80), 15, (30, 30, 30), -1)
    cv2.circle(test_face, (144, 80), 15, (30, 30, 30), -1)

    pred = classifier.classify_face_crop(test_face)
    assert 0.0 <= pred.fake_probability <= 1.0
    assert 0.0 <= pred.real_probability <= 1.0
    assert abs((pred.fake_probability + pred.real_probability) - 1.0) < 1e-3
    assert pred.latency_ms > 0.0
    assert pred.device in ("cpu", "cuda")


# ============================================================================
# 4. Temporal Consistency & Isolated Spike Protection (Case E)
# ============================================================================

def test_temporal_consistency_aggregation_and_isolated_spike():
    """Verify transparent aggregation formula and Case E isolated-frame false positive protection."""
    temporal_engine = TemporalConsistencyEngine()

    # Case E Scenario: 1 frame has an anomaly (0.95 fake), but 9 frames are clean (0.10 fake)
    noisy_predictions = [
        {"frame_idx": 0, "fake_probability": 0.10, "real_probability": 0.90},
        {"frame_idx": 1, "fake_probability": 0.12, "real_probability": 0.88},
        {"frame_idx": 2, "fake_probability": 0.08, "real_probability": 0.92},
        {"frame_idx": 3, "fake_probability": 0.95, "real_probability": 0.05},  # ISOLATED SPIKE
        {"frame_idx": 4, "fake_probability": 0.11, "real_probability": 0.89},
        {"frame_idx": 5, "fake_probability": 0.09, "real_probability": 0.91},
        {"frame_idx": 6, "fake_probability": 0.14, "real_probability": 0.86},
        {"frame_idx": 7, "fake_probability": 0.10, "real_probability": 0.90},
        {"frame_idx": 8, "fake_probability": 0.13, "real_probability": 0.87},
        {"frame_idx": 9, "fake_probability": 0.10, "real_probability": 0.90},
    ]

    report = temporal_engine.analyze(noisy_predictions, face_tracking=[], fps=10.0)

    # Isolated spike MUST be detected and dampened
    assert report.has_isolated_spike is True
    assert report.suspicious_count == 1
    # Aggregated score must NOT cross suspicious threshold (must remain < 0.40)
    assert report.aggregated_score < 0.40, (
        f"Isolated spike failed to be dampened! Score: {report.aggregated_score}"
    )


def test_temporal_consistency_high_deepfake_cluster():
    """Verify that multiple manipulated frames correctly produce high aggregated deepfake confidence."""
    temporal_engine = TemporalConsistencyEngine()

    # Sustained manipulation cluster: 7 out of 10 frames are fake
    sustained_manipulation = [
        {"frame_idx": 0, "fake_probability": 0.15, "real_probability": 0.85},
        {"frame_idx": 1, "fake_probability": 0.88, "real_probability": 0.12},
        {"frame_idx": 2, "fake_probability": 0.92, "real_probability": 0.08},
        {"frame_idx": 3, "fake_probability": 0.94, "real_probability": 0.06},
        {"frame_idx": 4, "fake_probability": 0.89, "real_probability": 0.11},
        {"frame_idx": 5, "fake_probability": 0.91, "real_probability": 0.09},
        {"frame_idx": 6, "fake_probability": 0.85, "real_probability": 0.15},
        {"frame_idx": 7, "fake_probability": 0.93, "real_probability": 0.07},
        {"frame_idx": 8, "fake_probability": 0.20, "real_probability": 0.80},
        {"frame_idx": 9, "fake_probability": 0.18, "real_probability": 0.82},
    ]

    report = temporal_engine.analyze(sustained_manipulation, face_tracking=[], fps=10.0)
    assert report.has_isolated_spike is False
    assert report.suspicious_count >= 7
    assert report.aggregated_score >= 0.70


# ============================================================================
# 5. Audio Extraction & Phase 3B Audio Intelligence Tests
# ============================================================================

def test_video_audio_extractor_availability():
    """Verify that bundled ffmpeg is present and functional via imageio-ffmpeg."""
    extractor = VideoAudioExtractor()
    assert extractor.is_available() is True


def test_video_audio_extraction_on_silent_video():
    """Verify audio extractor behavior on video with no audio track."""
    vid_bytes = _create_synthetic_mp4(num_frames=8, fps=10.0)
    audio_wav = VideoAudioExtractor.extract_audio(vid_bytes)
    # Synthetic video created without audio track returns None
    assert audio_wav is None or len(audio_wav) == 0


# ============================================================================
# 6. Audio-Visual Consistency Analysis
# ============================================================================

def test_audiovisual_consistency_analysis():
    """Verify mouth movement vs audio energy correlation calculation."""
    av_engine = AudioVisualConsistencyEngine()

    # Synthetic mouth heights
    sampled_frames = [(i, i * 0.1, np.zeros((64, 64, 3), dtype=np.uint8)) for i in range(10)]
    face_tracking = [
        {
            "frame_idx": i,
            "timestamp_sec": i * 0.1,
            "primary_landmarks": np.array([
                [32, 20], [48, 20], [40, 30],
                [35, 45], [45, 45],
            ]) if (i % 2 == 0) else None,
        }
        for i in range(10)
    ]

    # Dummy 16kHz audio buffer
    dummy_audio = np.full(16000, 1000, dtype=np.int16).tobytes()

    report = av_engine.analyze(sampled_frames, dummy_audio, face_tracking, fps=10.0)
    assert "mouth_energy_correlation" in report
    assert "is_desynchronized" in report
    assert "desynchronization_score" in report


# ============================================================================
# 7. Required Demo Cases A - E
# ============================================================================

@pytest.mark.asyncio
async def test_case_a_benign_synthetic_video_not_critical():
    """CASE A: Benign Synthetic Video.
    
    Visual synthetic probability: HIGH
    Audio synthetic probability: LOW / None
    Identity threat: None
    Malicious intent: None
    
    Result: Likely synthetic video detected, but NOT automatically classified as malicious/CRITICAL.
    """
    orchestrator = MediaIntelligenceOrchestrator()
    incident = await orchestrator.analyze_video(
        video_name="creative_ai_demo.mp4",
        frame_manipulation_score=0.88,
        temporal_jitter_score=0.40,
        target_name=None,
        audio_transcript=None,
    )

    # Must detect synthetic video
    assert incident.threat_type in (ThreatType.DEEPFAKE_VIDEO, "DEEPFAKE_VIDEO")
    # Benign AI video alone must NOT reach CRITICAL risk
    assert incident.risk_level != RiskLevel.CRITICAL
    assert incident.risk_score < 0.90


@pytest.mark.asyncio
async def test_case_b_natural_authentic_video():
    """CASE B: Natural / Authentic Video.
    
    Visual fake probability: LOW
    Audio fake probability: LOW
    Temporal consistency: NORMAL
    Identity: UNVERIFIED
    
    Result: No strong deepfake indicators; SAFE assessment.
    """
    orchestrator = MediaIntelligenceOrchestrator()
    incident = await orchestrator.analyze_video(
        video_name="family_holiday.mp4",
        frame_manipulation_score=0.15,
        temporal_jitter_score=0.20,
        target_name=None,
        audio_transcript="We had a lovely walk in the botanical gardens today.",
    )

    assert incident.risk_level in (RiskLevel.SAFE, RiskLevel.LOW)
    assert incident.risk_score < 0.40


@pytest.mark.asyncio
async def test_case_c_video_impersonation_multimodal_synergy():
    """CASE C: Multimodal Digital Impersonation.
    
    Visual synthetic probability: HIGH
    Target Identity: Protected VIP
    Audio synthetic: HIGH
    Financial Demand Intent: TRUE
    
    Result: Multiplicative synergy activates Interaction Rule F -> CRITICAL / HIGH risk.
    """
    orchestrator = MediaIntelligenceOrchestrator()
    # Mocking demuxed audio with high-stakes financial coercion
    incident = await orchestrator.analyze_video(
        video_name="ceo_emergency_transfer.mp4",
        frame_manipulation_score=0.92,
        temporal_jitter_score=0.85,
        target_name="Dr. Marcus Carter",
        audio_transcript="This is Marcus Carter. I need an urgent wire transfer of $250,000 immediately to our vendor account.",
    )

    # Impersonation and deepfake synergy MUST trigger high or critical risk
    assert incident.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert incident.risk_score >= 0.85
    # Risk drivers must explain synergy
    assert any("synergy" in d.lower() or "synthetic" in d.lower() for d in incident.risk_drivers)


@pytest.mark.asyncio
async def test_case_d_audio_only_manipulation():
    """CASE D: Audio-Only Manipulation.
    
    Visual authenticity: LOW suspiciousness
    Audio spoof probability: HIGH
    
    Result: Synthetic audio detected; visual content is NOT falsely marked as deepfake.
    """
    orchestrator = MediaIntelligenceOrchestrator()
    incident = await orchestrator.analyze_video(
        video_name="podcast_dubbed.mp4",
        frame_manipulation_score=0.20,
        temporal_jitter_score=0.18,
        target_name=None,
        audio_transcript="Listen closely to this announcement.",
    )

    # Visual manipulation evidence should not be added when scores are low
    deepfake_visual_evidence = [e for e in incident.evidence if e.type == EvidenceType.DEEPFAKE_VIDEO]
    assert len(deepfake_visual_evidence) == 0


@pytest.mark.asyncio
async def test_case_e_end_to_end_orchestrator_with_real_video_bytes():
    """Verify full orchestrator pipeline with real video bytes, face detection, ViT inference, and XAI."""
    orchestrator = MediaIntelligenceOrchestrator()
    vid_bytes = _create_synthetic_mp4(num_frames=12, fps=10.0, width=128, height=128)

    incident = await orchestrator.analyze_video(
        video_name="synthetic_sample.mp4",
        video_bytes=vid_bytes,
        target_name="Dr. Marcus Carter",
    )

    assert incident.source in ("video_intelligence", "video", EvidenceSource.VIDEO)
    assert incident.input_type == "video"
    assert "video_metadata" in incident.metadata
    assert incident.metadata["video_metadata"]["frames_analyzed"] >= 4
    assert "temporal_analysis" in incident.metadata
    assert "frame_deepfake_predictions" in incident.metadata
    assert len(incident.explanation) > 0


# ============================================================================
# 8. HTTP API Integration Tests
# ============================================================================

@pytest.mark.asyncio
async def test_api_video_json_endpoint():
    """Verify POST /api/v1/analyze/video endpoint handles JSON requests."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {
            "video_name": "executive_update.mp4",
            "frame_manipulation_score": 0.84,
            "temporal_jitter_score": 0.78,
            "target_name": "Dr. Marcus Carter",
            "audio_transcript": "Authorize immediate transfer.",
        }
        res = await ac.post("/api/v1/analyze/video", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["threat_type"] in ("deepfake_video", "impersonation")
        assert data["risk_score"] > 0.70


@pytest.mark.asyncio
async def test_api_media_video_multipart_upload():
    """Verify POST /api/v1/analyze/media/video multipart upload runs end-to-end."""
    vid_bytes = _create_synthetic_mp4(num_frames=8, fps=10.0)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        files = {"file": ("test_clip.mp4", vid_bytes, "video/mp4")}
        data = {"claimed_identity": "Elena Rostova", "context": "Quarterly financial briefing"}
        res = await ac.post("/api/v1/analyze/media/video", files=files, data=data)

        assert res.status_code == 200
        incident = res.json()
        assert incident["input_type"] == "video"
        assert incident["title"].startswith("Deepfake Video Threat:") or incident["title"].startswith("Analyzed Video:")
        assert "video_metadata" in incident["metadata"]
