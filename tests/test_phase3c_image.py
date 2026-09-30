"""Phase 3C Image & Identity Intelligence Tests.

Verifies:
1. Image Preprocessing, Validation & Decompression Safety
2. Classical OpenCV & PIL Forensics (Laplacian variance, FFT spectrum, noise)
3. Real Vision Transformer (ViT) Synthetic Image Detection (umm-maybe/AI-image-detector)
4. Real Deep Neural Face Detection (OpenCV YuNet: opencv/face_detection_yunet)
5. Real ArcFace Facial Feature Extraction (gaunernst/vit_tiny_patch8_112.arcface_ms1mv3)
6. Normalization & Cosine Similarity in IdentityRegistry
7. Multiple Faces Explicit Handling
8. Real EasyOCR Visual Text Extraction & Intent Tagging
9. Multi-dimensional Decoupling (AI-gen alone != Critical, Face Sim alone != Critical)
10. Multi-Signal Digital Impersonation Synergy
11. Honest Failure Handling & Fallback Transparency
12. End-to-End Orchestrator & API Integration
"""

import io
import os
import cv2
from huggingface_hub import hf_hub_download
import numpy as np
from PIL import Image
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.engines.identity.registry import IdentityRegistry, ProtectedIdentity
from app.engines.media.face_engine import FaceIntelligenceEngine
from app.engines.media.image_forensics import ImageForensicsEngine
from app.engines.media.image_preprocess import (
    ImageCorruptedError,
    ImageEmptyError,
    ImageOversizedError,
    ImagePreprocessor,
    UnsupportedImageFormatError,
)
from app.engines.media.image_synthetic import ImageSyntheticClassifier
from app.engines.media.ocr_engine import OCREngine
from app.engines.media.orchestrator import MediaIntelligenceOrchestrator
from app.core.config import settings
from app.core.database import init_db
from app.main import app
from app.schemas.threat import RiskLevel

TEST_DB_PATH = settings.DATA_DIR / "test_orion_p3c.db"
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
def sample_png_bytes() -> bytes:
    """Generate a clean synthetic 200x200 PNG image."""
    img = Image.new("RGB", (200, 200), color=(70, 130, 180))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def sample_jpeg_bytes() -> bytes:
    """Generate a clean synthetic 200x200 JPEG image."""
    img = Image.new("RGB", (200, 200), color=(180, 70, 70))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


@pytest.fixture
def sample_ocr_image_bytes() -> bytes:
    """Generate an image with visible coercive payment demand text."""
    arr = np.ones((120, 400, 3), dtype=np.uint8) * 255
    cv2.putText(arr, "URGENT WIRE TRANSFER", (15, 65), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 0), 2)
    pil_img = Image.fromarray(arr)
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def public_face_fixture_path() -> str:
    """Download public OpenCV benchmark face fixture (largest_selfie.jpg)."""
    return hf_hub_download(repo_id="opencv/face_detection_yunet", filename="example_outputs/largest_selfie.jpg")


# ============================================================================
# 1. PREPROCESSING & VALIDATION TESTS
# ============================================================================

def test_image_preprocessor_validation_and_decoding(sample_png_bytes, sample_jpeg_bytes):
    """Test safe decoding and dimension extraction across PNG and JPEG formats."""
    png_res = ImagePreprocessor.validate_and_decode(sample_png_bytes)
    assert png_res.format == "PNG"
    assert png_res.width == 200
    assert png_res.height == 200
    assert png_res.channels == 3
    assert png_res.rgb_array.shape == (200, 200, 3)

    jpg_res = ImagePreprocessor.validate_and_decode(sample_jpeg_bytes)
    assert jpg_res.format == "JPEG"
    assert jpg_res.width == 200
    assert jpg_res.height == 200


def test_image_preprocessor_corrupted_and_empty():
    """Verify robust rejection of empty, truncated, or invalid file streams."""
    with pytest.raises(ImageEmptyError):
        ImagePreprocessor.validate_and_decode(b"")

    with pytest.raises(UnsupportedImageFormatError):
        ImagePreprocessor.validate_and_decode(b"NOT_AN_IMAGE_FILE_DATA")

    with pytest.raises(ImageCorruptedError):
        # Starts with PNG magic but truncated payload
        ImagePreprocessor.validate_and_decode(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRbadbytes")


def test_image_preprocessor_oversized():
    """Test guard against decompression bombs exceeding maximum dimension limit."""
    with pytest.raises(ImageOversizedError):
        # Create an oversized image in memory
        oversized = Image.new("RGB", (4500, 4500), color=(0, 0, 0))
        buf = io.BytesIO()
        oversized.save(buf, format="JPEG")
        ImagePreprocessor.validate_and_decode(buf.getvalue())


# ============================================================================
# 2. CLASSICAL FORENSICS TESTS
# ============================================================================

def test_image_forensics_classical_signals(sample_png_bytes):
    """Verify Laplacian edge variance, FFT frequency spectrum, and noise variance."""
    indicators, evidence = ImageForensicsEngine.analyze_image_bytes(sample_png_bytes)
    assert "laplacian_edge_variance" in indicators
    assert "fft_high_freq_ratio" in indicators
    assert "noise_channel_diff" in indicators
    assert "dimensions" in indicators
    assert indicators["dimensions"] == "200x200"


# ============================================================================
# 3. REAL SYNTHETIC IMAGE DETECTOR (ViT) TESTS
# ============================================================================

def test_real_vit_synthetic_image_detector_loading():
    """Verify thread-safe singleton loading of umm-maybe/AI-image-detector."""
    classifier = ImageSyntheticClassifier()
    assert classifier.model_checkpoint == "umm-maybe/AI-image-detector"
    assert classifier._ensure_model_loaded() is True
    assert classifier.is_model_loaded() is True


def test_real_vit_synthetic_image_detector_inference(sample_png_bytes):
    """Execute real neural inference with ViT and inspect output probabilities."""
    classifier = ImageSyntheticClassifier()
    res = classifier.classify_image(sample_png_bytes)

    assert res["model_loaded"] is True
    assert res["provider"] == "synthetic_image_detector"
    assert "ai_generated_probability" in res
    assert "natural_probability" in res
    assert 0.0 <= res["ai_generated_probability"] <= 1.0
    assert 0.0 <= res["natural_probability"] <= 1.0
    assert abs(res["ai_generated_probability"] + res["natural_probability"] - 1.0) < 0.01
    assert res["inference_latency_ms"] > 0.0


def test_vit_synthetic_injected_score_compatibility(sample_png_bytes):
    """Verify backward compatibility of injected simulation scores for testing."""
    classifier = ImageSyntheticClassifier()
    res = classifier.classify_image(sample_png_bytes, injected_ai_prob=0.912)

    assert res["ai_generated_probability"] == 0.912
    assert res["natural_probability"] == round(1.0 - 0.912, 4)


# ============================================================================
# 4. REAL FACE DETECTION & ARCFACE EMBEDDING TESTS
# ============================================================================

def test_real_yunet_face_detector_and_landmarks(public_face_fixture_path):
    """Verify OpenCV YuNet detects real faces, bounding boxes, and landmarks."""
    engine = FaceIntelligenceEngine()
    bgr_img = cv2.imread(public_face_fixture_path)
    assert bgr_img is not None

    faces = engine.detect_faces(bgr_img)
    assert len(faces) >= 1

    # Check bounding box and confidence of dominant face
    box, conf, landmarks = faces[0]
    assert len(box) == 4
    assert conf >= 0.60
    assert len(landmarks) == 5  # 5 facial landmarks


def test_real_arcface_embedding_extraction_and_normalization():
    """Verify ArcFace ViT extracts 512-dim embedding with L2 unit norm."""
    engine = FaceIntelligenceEngine()
    dummy_face_112 = np.ones((112, 112, 3), dtype=np.uint8) * 128

    embedding = engine.extract_arcface_embedding(dummy_face_112)
    assert len(embedding) == 512

    # Verify unit norm: sum of squares ≈ 1.0
    norm = np.linalg.norm(np.array(embedding, dtype=np.float32))
    assert abs(norm - 1.0) < 0.01


def test_arcface_cosine_similarity_identity_matching():
    """Test identity matching when candidate embedding resembles reference profile."""
    registry = IdentityRegistry()
    cfo = registry.get_by_id("id_cfo_01")
    assert cfo is not None
    assert cfo.face_embedding_reference is not None

    # Candidate embedding identical to reference profile
    cand_embedding = list(cfo.face_embedding_reference)
    matched, sim = registry.match_face_embedding(cand_embedding, claimed_identity_query="Rajesh Sharma")

    assert matched is not None
    assert matched.identity_id == "id_cfo_01"
    assert sim >= 0.99


def test_unverified_face_when_no_reference_matches():
    """Verify candidate with orthogonal/unrelated embedding is tagged unverified."""
    registry = IdentityRegistry()
    rng = np.random.default_rng(99999)
    unrelated_vec = rng.standard_normal(512)
    unrelated_vec /= np.linalg.norm(unrelated_vec)

    matched, sim = registry.match_face_embedding(unrelated_vec.tolist(), match_threshold=0.60)
    assert matched is None
    assert sim < 0.60


def test_multiple_faces_handling_explicitly(public_face_fixture_path):
    """Verify that multiple faces in a group image are each detected and evaluated separately."""
    engine = FaceIntelligenceEngine()
    bgr_img = cv2.imread(public_face_fixture_path)

    results, _ = engine.process_image(bgr_img)
    # The benchmark selfie contains multiple faces
    assert len(results) >= 2

    for r in results:
        assert len(r.bbox) == 4
        assert len(r.embedding) == 512
        assert 0.0 <= r.confidence <= 1.0


# ============================================================================
# 5. REAL OCR & VISUAL TEXT EXTRACTION TESTS
# ============================================================================

def test_real_easyocr_text_extraction(sample_ocr_image_bytes):
    """Verify EasyOCR extracts visible text and tags intent keywords."""
    ocr_engine = OCREngine()
    preprocessed = ImagePreprocessor.validate_and_decode(sample_ocr_image_bytes)

    res, evidence = ocr_engine.extract_text(preprocessed.rgb_array)
    assert res.model_loaded is True
    assert "WIRE TRANSFER" in res.text.upper() or "URGENT" in res.text.upper()
    assert res.signals.get("payment_request") is True or res.signals.get("urgency") is True
    assert len(evidence) >= 1


# ============================================================================
# 6. MULTI-DIMENSIONAL DECOUPLING & RISK ENGINE INTEGRATION TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_synthetic_image_alone_not_critical(sample_png_bytes):
    """CRITICAL PRINCIPLE: AI-generated image alone must NEVER trigger CRITICAL risk."""
    orchestrator = MediaIntelligenceOrchestrator()

    # Pass high AI generation score but neutral context (no face similarity, no malicious demand)
    incident = await orchestrator.analyze_image(
        image_bytes=sample_png_bytes,
        ai_generated_prob=0.95,
        manipulation_prob=0.0,
        identity_similarity=0.0,
        malicious_intent=0.0,
        target_name=None,
    )

    assert incident.risk_level in (RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM)
    assert incident.risk_score < 0.60


@pytest.mark.asyncio
async def test_face_similarity_alone_not_critical(sample_png_bytes):
    """CRITICAL PRINCIPLE: High face similarity alone must NEVER trigger CRITICAL risk."""
    orchestrator = MediaIntelligenceOrchestrator()

    # Benign photo matching registered executive without AI generation or coercive demands
    incident = await orchestrator.analyze_image(
        image_bytes=sample_png_bytes,
        ai_generated_prob=0.10,
        manipulation_prob=0.0,
        identity_similarity=0.88,
        malicious_intent=0.0,
        target_name="Rajesh Sharma",
    )

    assert incident.risk_level in (RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM)
    assert incident.risk_score < 0.70


@pytest.mark.asyncio
async def test_digital_impersonation_multi_signal_synergy(sample_png_bytes):
    """Verify non-linear synergy when AI-gen + High VIP Face Similarity + Coercive Financial Demand co-occur."""
    orchestrator = MediaIntelligenceOrchestrator()

    # Tri-factor digital impersonation: Synthetic + High VIP Resemblance + Urgent Financial Transfer
    incident = await orchestrator.analyze_image(
        image_bytes=sample_png_bytes,
        ai_generated_prob=0.92,
        manipulation_prob=0.80,
        identity_similarity=0.85,
        malicious_intent=0.85,
        target_name="Rajesh Sharma",
        context_text="Urgent wire transfer required immediately per CFO directive.",
    )

    assert incident.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert incident.risk_score >= 0.75


# ============================================================================
# 7. HONEST FAILURE & FALLBACK TRANSPARENCY TESTS
# ============================================================================

def test_image_honest_failure_handling():
    """Verify that failure returns honest unavailable status without fake scores."""
    classifier = ImageSyntheticClassifier()
    # Invalid data format
    res = classifier.classify_image("invalid_string_not_an_image")  # type: ignore

    assert res["model_loaded"] is False
    assert res["provider"] == "unavailable"


# ============================================================================
# 8. END-TO-END PIPELINE & API TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_end_to_end_analyze_image_metadata_completeness(sample_png_bytes):
    """Verify complete metadata logging across all engines in analyze_image."""
    orchestrator = MediaIntelligenceOrchestrator()

    incident = await orchestrator.analyze_image(
        image_bytes=sample_png_bytes,
        target_name="Anita Roy",
    )

    assert "synthetic_detection" in incident.metadata
    assert "face_analysis" in incident.metadata
    assert "ocr_analysis" in incident.metadata
    assert "forensics" in incident.metadata
    assert "signals" in incident.metadata
    assert incident.metadata["synthetic_detection"]["model_loaded"] is True


@pytest.mark.asyncio
async def test_api_media_image_upload_endpoint(sample_png_bytes):
    """Test HTTP multipart upload to /api/v1/analyze/media/image."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("test_avatar.png", sample_png_bytes, "image/png")}
        data = {"claimed_identity": "Rajesh Sharma", "context": "Executive profile check"}
        response = await client.post("/api/v1/analyze/media/image", files=files, data=data)

        assert response.status_code == 200
        incident = response.json()
        assert incident["source"] in ("image", "image_intelligence")
        assert "metadata" in incident
        assert incident["metadata"]["synthetic_detection"]["model_loaded"] is True
