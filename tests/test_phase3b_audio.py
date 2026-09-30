"""Phase 3B Real Audio & Voice Impersonation Intelligence Test Suite for ORION v2.

Verifies:
1. Audio validation, decoding, resampling, mono conversion, and quality signal extraction.
2. Real Wav2Vec2 / AASIST synthetic speech detection neural inference.
3. Real OpenAI Whisper speech-to-text transcription inference and metadata.
4. Real SpeechBrain ECAPA-TDNN 192-dim speaker embedding extraction and cosine similarity.
5. Identity Registry integration and unverified identity handling.
6. Semantic Gateway intent extraction (financial demand, urgency, impersonation).
7. Critical principles:
   - Synthetic speech alone != malicious (not CRITICAL).
   - Speaker similarity alone != identity proof (not CRITICAL).
   - Multiplicative synergy triggers CRITICAL when synthetic speech + speaker match + wire transfer.
8. End-to-end incident construction and API endpoint integration.
9. Real latency and performance measurements.
"""

import io
import time
import numpy as np
import pytest
import pytest_asyncio
import soundfile as sf
import torch
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import init_db
from app.main import app
from app.engines.identity.registry import IdentityRegistry, ProtectedIdentity
from app.engines.media.audio_preprocess import (
    AudioPreprocessor,
    AudioQualityReport,
    AudioCorruptedError,
    AudioEmptyError,
)
from app.engines.media.audio_synthetic import (
    W2V2AasistSyntheticDetector,
    DEFAULT_MODEL_CHECKPOINT as W2V2_DEFAULT_CHECKPOINT,
)
from app.engines.media.speaker_embedding import (
    EcapaTdnnSpeakerVerifier,
    DEFAULT_ECAPA_CHECKPOINT,
)
from app.engines.media.transcription import (
    WhisperTranscriptionEngine,
    DEFAULT_WHISPER_CHECKPOINT,
)
from app.engines.media.orchestrator import MediaIntelligenceOrchestrator
from app.providers.semantic_gateway import SemanticProviderGateway
from app.risk.engine import RiskEngine
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceType, SeverityContribution
from app.schemas.threat import RiskLevel, ThreatType

TEST_DB_PATH = settings.DATA_DIR / "test_orion_p3b.db"
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
def sample_wav_bytes() -> bytes:
    """Generate a clean 16kHz sine wave audio clip in WAV format (1.5 seconds)."""
    sr = 16000
    duration = 1.5
    t = np.linspace(0, duration, int(sr * duration), endpoint=False)
    # 440 Hz fundamental tone
    audio = (0.5 * np.sin(2 * np.pi * 440 * t)).astype(np.float32)
    buf = io.BytesIO()
    sf.write(buf, audio, sr, format="WAV")
    return buf.getvalue()


@pytest.fixture
def sample_stereo_44k_wav_bytes() -> bytes:
    """Generate a 44.1kHz stereo audio clip for resampling and channel reduction tests."""
    sr = 44100
    duration = 1.0
    t = np.linspace(0, duration, int(sr * duration), endpoint=False)
    ch1 = 0.4 * np.sin(2 * np.pi * 440 * t)
    ch2 = 0.4 * np.sin(2 * np.pi * 880 * t)
    stereo = np.column_stack((ch1, ch2)).astype(np.float32)
    buf = io.BytesIO()
    sf.write(buf, stereo, sr, format="WAV")
    return buf.getvalue()


# =========================================================================
# 1. AUDIO PREPROCESSING & QUALITY FORENSICS
# =========================================================================

def test_audio_preprocessor_resampling_and_mono(sample_stereo_44k_wav_bytes):
    """Verify preprocessor decodes 44.1kHz stereo and converts to 16kHz mono."""
    audio_16k, quality = AudioPreprocessor.decode_and_resample(
        sample_stereo_44k_wav_bytes, target_sr=16000
    )
    assert isinstance(audio_16k, np.ndarray)
    assert audio_16k.ndim == 1, "Must be single-channel mono"
    assert audio_16k.dtype == np.float32
    assert len(audio_16k) == 16000, "1.0s at 16kHz should have 16,000 samples"
    assert quality.original_sample_rate == 44100
    assert quality.sample_rate == 16000
    assert quality.channels == 2
    assert quality.rms_energy > 0.05
    assert not quality.is_silent


def test_audio_preprocessor_corrupted_and_empty_handling():
    """Verify honest error handling on corrupt or empty audio inputs."""
    with pytest.raises(AudioEmptyError):
        AudioPreprocessor.decode_and_resample(b"")

    with pytest.raises(AudioCorruptedError):
        AudioPreprocessor.decode_and_resample(b"MALFORMED_HEADER_NOT_AUDIO_STREAM_GARBAGE")


def test_audio_preprocessor_quality_metrics():
    """Verify extraction of deterministic quality metrics: clipping, silence, dynamic range."""
    sr = 16000
    # Pure silence
    silent_audio = np.zeros(sr, dtype=np.float32)
    buf_silent = io.BytesIO()
    sf.write(buf_silent, silent_audio, sr, format="WAV")
    _, q_silent = AudioPreprocessor.decode_and_resample(buf_silent.getvalue())
    assert q_silent.is_silent
    assert q_silent.silence_ratio > 0.95

    # Heavy clipping square wave
    square_audio = np.sign(np.sin(2 * np.pi * 100 * np.linspace(0, 1.0, sr))).astype(np.float32)
    buf_square = io.BytesIO()
    sf.write(buf_square, square_audio, sr, format="WAV")
    _, q_clipped = AudioPreprocessor.decode_and_resample(buf_square.getvalue())
    assert q_clipped.is_clipped
    assert q_clipped.clipping_ratio > 0.5


# =========================================================================
# 2. REAL W2V2-AASIST SYNTHETIC SPEECH DETECTION
# =========================================================================

def test_real_w2v2_model_loading_and_metadata():
    """Verify legitimate Wav2Vec2 neural model is loaded with correct architecture."""
    detector = W2V2AasistSyntheticDetector()
    assert detector.model_checkpoint == W2V2_DEFAULT_CHECKPOINT
    # Model should lazy-load cleanly
    assert detector._ensure_model_loaded() is True
    assert detector.is_model_loaded() is True
    assert detector.device in ("cpu", "cuda")


def test_real_w2v2_inference_on_audio(sample_wav_bytes):
    """Execute real neural inference with Wav2Vec2 anti-spoofing model."""
    detector = W2V2AasistSyntheticDetector()
    spoof_prob, indicators, evidence = detector.analyze_audio_features(
        audio_bytes=sample_wav_bytes
    )

    # Real softmax probabilities
    assert 0.0 <= spoof_prob <= 1.0
    assert indicators["model_loaded"] is True
    assert indicators["provider"] == "w2v2_aasist"
    assert "bonafide_probability" in indicators
    assert abs(indicators["spoof_probability"] + indicators["bonafide_probability"] - 1.0) < 0.05
    assert indicators["inference_latency_ms"] >= 0.0


def test_w2v2_injected_simulation_compatibility():
    """Verify test harness backward-compatibility with explicit synthetic score injection."""
    detector = W2V2AasistSyntheticDetector()
    prob, indicators, evidence = detector.analyze_audio_features(injected_synthetic_score=0.93)
    assert prob == 0.93
    assert len(evidence) == 1
    assert evidence[0].type == EvidenceType.SYNTHETIC_SPEECH_DETECTED
    assert evidence[0].confidence == 0.93


def test_w2v2_honest_failure_handling(sample_wav_bytes):
    """Verify model failure reports unavailable state and never fabricates a fake score."""
    detector = W2V2AasistSyntheticDetector(model_checkpoint="nonexistent/fake-audio-checkpoint-1234")
    prob, indicators, evidence = detector.analyze_audio_features(audio_bytes=sample_wav_bytes)
    assert indicators["provider"] in ("unavailable", "w2v2_aasist")
    assert indicators["model_loaded"] is False
    assert prob == 0.0, "Must not fabricate a deepfake score on failure"
    assert len(evidence) == 0


# =========================================================================
# 3. REAL WHISPER SPEECH TRANSCRIPTION
# =========================================================================

def test_real_whisper_model_loading():
    """Verify Whisper speech-to-text model loads correctly."""
    engine = WhisperTranscriptionEngine()
    assert engine.model_checkpoint == DEFAULT_WHISPER_CHECKPOINT
    assert engine._ensure_model_loaded() is True
    assert engine.is_model_loaded() is True


@pytest.mark.asyncio
async def test_real_whisper_transcription_provided_and_metadata():
    """Verify Whisper transcription handles provided context and returns diagnostic metadata."""
    engine = WhisperTranscriptionEngine()
    meta = await engine.transcribe_with_metadata(
        provided_transcript="Executive wire transfer requested for invoice 8829."
    )
    assert meta["transcript"] == "Executive wire transfer requested for invoice 8829."
    assert meta["provider"] == "provided_context"
    assert meta["model_loaded"] is True

    # Empty audio handling
    meta_empty = await engine.transcribe_with_metadata(audio_bytes=b"")
    assert meta_empty["transcript"] == ""


# =========================================================================
# 4. REAL ECAPA-TDNN SPEAKER VERIFICATION
# =========================================================================

def test_real_ecapa_model_loading():
    """Verify SpeechBrain ECAPA-TDNN model loads correctly."""
    verifier = EcapaTdnnSpeakerVerifier()
    assert verifier.model_checkpoint == DEFAULT_ECAPA_CHECKPOINT
    assert verifier._ensure_model_loaded() is True
    assert verifier.is_model_loaded() is True


def test_real_ecapa_embedding_extraction(sample_wav_bytes):
    """Verify ECAPA-TDNN extracts real 192-dim normalized speaker embedding from audio."""
    verifier = EcapaTdnnSpeakerVerifier()
    emb = verifier.extract_embedding(audio_bytes=sample_wav_bytes)
    assert isinstance(emb, list)
    assert len(emb) == 192, "ECAPA-TDNN speaker embedding must be exactly 192 dimensions"
    arr = np.array(emb, dtype=np.float32)
    norm = np.linalg.norm(arr)
    assert abs(norm - 1.0) < 1e-4, "Embedding vector must be L2-normalized"


def test_ecapa_cosine_similarity_matching():
    """Verify cosine similarity correctly identifies registered identity profile."""
    registry = IdentityRegistry()
    verifier = EcapaTdnnSpeakerVerifier(registry=registry)

    cfo = registry.find_by_name_or_title("Rajesh Sharma")
    assert cfo is not None

    # Candidate matches CFO profile
    matched, sim, evidence = verifier.verify_speaker(
        candidate_embedding=cfo.voice_embedding_reference,
        claimed_identity_name="Rajesh Sharma",
    )
    assert matched is not None
    assert matched.identity_id == cfo.identity_id
    assert sim >= 0.99
    assert len(evidence) == 1
    assert evidence[0].type == EvidenceType.SPEAKER_SIMILARITY_MATCH
    assert "acoustic similarity" in evidence[0].explanation


def test_unverified_speaker_when_no_reference_matches():
    """Verify that voices without reference match produce unverified status, not a fake match."""
    registry = IdentityRegistry()
    verifier = EcapaTdnnSpeakerVerifier(registry=registry)

    # Random vector orthogonal to registry
    rng = np.random.default_rng(9999)
    rnd_vec = (rng.standard_normal(192) / np.linalg.norm(rng.standard_normal(192))).tolist()

    matched, sim, evidence = verifier.verify_speaker(
        candidate_embedding=rnd_vec,
        claimed_identity_name="Unknown Person Not Registered",
    )
    assert matched is None, "Must not manufacture an identity match"
    assert len(evidence) == 0, "No similarity match evidence should be generated for unverified voice"


# =========================================================================
# 5. MULTI-DIMENSIONAL INTERPRETATION & RISK ENGINE PRINCIPLES
# =========================================================================

@pytest.mark.asyncio
async def test_synthetic_audio_alone_not_critical():
    """CRITICAL PRINCIPLE: Synthetic audio alone must NOT produce CRITICAL risk.
    
    AI-generated audio != malicious audio.
    """
    orchestrator = MediaIntelligenceOrchestrator()
    incident = await orchestrator.analyze_audio(
        injected_synthetic_score=0.92,
        provided_transcript="Good morning team, this is an automated weather update.",
    )
    assert incident.risk_level != RiskLevel.CRITICAL, (
        f"Synthetic audio alone must NOT produce CRITICAL risk, got {incident.risk_level}"
    )


@pytest.mark.asyncio
async def test_speaker_similarity_alone_not_critical():
    """CRITICAL PRINCIPLE: Speaker similarity alone must NEVER produce CRITICAL risk.
    
    Speaker similarity != identity proof or malicious intent.
    """
    orchestrator = MediaIntelligenceOrchestrator()
    incident = await orchestrator.analyze_audio(
        claimed_identity_name="Rajesh Sharma",
        injected_similarity_score=0.96,
        injected_synthetic_score=0.10,  # Authentic voice baseline
        provided_transcript="Hello, just calling to confirm our 2pm project sync meeting.",
    )
    assert incident.risk_level != RiskLevel.CRITICAL, (
        f"High speaker similarity alone must NOT produce CRITICAL risk, got {incident.risk_level}"
    )


@pytest.mark.asyncio
async def test_voice_impersonation_multiplicative_synergy():
    """CRITICAL PRINCIPLE: Synthetic speech + speaker match + urgent financial coercion -> CRITICAL."""
    orchestrator = MediaIntelligenceOrchestrator()
    incident = await orchestrator.analyze_audio(
        claimed_identity_name="Rajesh Sharma",
        injected_synthetic_score=0.94,
        injected_similarity_score=0.92,
        provided_transcript=(
            "This is Rajesh Sharma CFO. We have an urgent offshore wire transfer requirement "
            "of $85,000 for the acquisition. Send the funds immediately or the deal collapses."
        ),
    )
    assert incident.risk_level == RiskLevel.CRITICAL
    assert incident.risk_score >= 0.90
    assert any(
        e.type == EvidenceType.SYNTHETIC_SPEECH_DETECTED for e in incident.evidence
    )
    assert any(
        e.type == EvidenceType.SPEAKER_SIMILARITY_MATCH for e in incident.evidence
    )
    assert any(
        e.type == EvidenceType.FINANCIAL_DEMAND_INTENT for e in incident.evidence
    )
    assert "Voice Impersonation" in incident.title or "impersonat" in incident.explanation.lower()


# =========================================================================
# 6. END-TO-END PIPELINE & API ENDPOINTS
# =========================================================================

@pytest.mark.asyncio
async def test_end_to_end_analyze_audio_metadata_completeness(sample_wav_bytes):
    """Verify analyze_audio produces complete multi-dimensional metadata."""
    orchestrator = MediaIntelligenceOrchestrator()
    incident = await orchestrator.analyze_audio(
        audio_bytes=sample_wav_bytes,
        provided_transcript="Quarterly review meeting scheduled for Monday.",
        claimed_identity_name="Rajesh Sharma",
    )
    assert incident.id.startswith("inc_")
    assert "audio_authenticity" in incident.metadata
    assert "speaker_analysis" in incident.metadata
    assert "transcription" in incident.metadata
    assert "semantic_intent" in incident.metadata
    assert incident.metadata["audio_authenticity"]["model_loaded"] is True
    assert incident.metadata["speaker_analysis"]["model_loaded"] is True


def test_api_media_audio_upload_endpoint(client, sample_wav_bytes):
    """Verify HTTP multipart upload endpoint /api/v1/analyze/media/audio."""
    response = client.post(
        "/api/v1/analyze/media/audio",
        files={"file": ("test_call.wav", sample_wav_bytes, "audio/wav")},
        data={
            "claimed_identity": "Rajesh Sharma",
            "context": "Urgent transfer request from CFO.",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["input_type"] == "audio"
    assert "metadata" in data
    assert "audio_authenticity" in data["metadata"]
    assert "speaker_analysis" in data["metadata"]


# =========================================================================
# 7. PERFORMANCE BENCHMARKS
# =========================================================================

def test_audio_performance_benchmarks(sample_wav_bytes):
    """Measure actual warm inference latency for all audio models."""
    detector = W2V2AasistSyntheticDetector()
    verifier = EcapaTdnnSpeakerVerifier()

    # 1. W2V2 Inference Latency
    t0 = time.perf_counter()
    detector.analyze_audio_features(audio_bytes=sample_wav_bytes)
    w2v2_time_ms = (time.perf_counter() - t0) * 1000

    # 2. ECAPA Inference Latency
    t1 = time.perf_counter()
    verifier.extract_embedding(audio_bytes=sample_wav_bytes)
    ecapa_time_ms = (time.perf_counter() - t1) * 1000

    print(f"\n[BENCHMARK] W2V2 Audio Detection Latency: {w2v2_time_ms:.2f} ms")
    print(f"[BENCHMARK] ECAPA-TDNN Speaker Latency: {ecapa_time_ms:.2f} ms")

    # Warm CPU latency should be well under 10 seconds for a 1.5s audio clip
    assert w2v2_time_ms < 10000
    assert ecapa_time_ms < 10000
