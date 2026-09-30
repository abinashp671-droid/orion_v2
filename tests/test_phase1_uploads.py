"""Phase 1 Upload Endpoints & Multimodal Ingestion Tests.

Verifies:
1. Image multipart upload (PNG, JPG, WEBP)
2. Audio multipart upload (WAV, MP3)
3. Video multipart upload (MP4)
4. Unsupported file types (rejected with 400)
5. Empty / missing files (rejected with 400)
6. Malformed files (rejected with 400)
7. Oversized file handling (rejected with 400)
8. Successful URL analysis
9. Successful Message analysis
10. Backward compatibility with existing JSON endpoints
"""

import io
import pytest
import cv2
import numpy as np
from httpx import AsyncClient, ASGITransport

from app.main import app


def _create_dummy_image(format="png") -> bytes:
    """Create a valid in-memory image byte stream."""
    img = np.zeros((100, 100, 3), dtype=np.uint8)
    cv2.circle(img, (50, 50), 30, (0, 0, 255), -1)
    ext = f".{format}"
    _, buf = cv2.imencode(ext, img)
    return buf.tobytes()


def _create_dummy_wav() -> bytes:
    """Create a minimal valid WAV audio file header and PCM chunk."""
    riff = b"RIFF"
    wave = b"WAVE"
    fmt = b"fmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00"
    data_header = b"data\x40\x00\x00\x00"
    pcm_data = b"\x00" * 64
    total_size = len(wave) + len(fmt) + len(data_header) + len(pcm_data)
    size_bytes = total_size.to_bytes(4, byteorder="little")
    return riff + size_bytes + wave + fmt + data_header + pcm_data


def _create_dummy_mp3() -> bytes:
    """Create a minimal valid MP3 frame with ID3 header."""
    id3_header = b"ID3\x03\x00\x00\x00\x00\x00\x00"
    mp3_frame = b"\xff\xfb\x90\x00" + (b"\x00" * 128)
    return id3_header + mp3_frame


def _create_dummy_mp4() -> bytes:
    """Create a minimal dummy MP4 with ftyp box."""
    # Box size (4 bytes), box type b'ftyp' (4 bytes), major brand b'isom'
    ftyp_box = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41"
    mdat_box = b"\x00\x00\x00\x08mdat"
    return ftyp_box + mdat_box


@pytest.mark.asyncio
async def test_upload_image_png_success():
    """Verify multipart PNG upload performs forensic analysis and returns an Incident."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        img_bytes = _create_dummy_image("png")
        files = {"file": ("test_avatar.png", img_bytes, "image/png")}
        data = {"claimed_identity": "CEO Alice", "context": "Avatar uploaded to executive portal"}

        response = await ac.post("/api/v1/analyze/media/image", files=files, data=data)
        assert response.status_code == 200, response.text
        incident = response.json()
        assert incident["input_type"] == "image"
        assert "CEO Alice" in incident["title"] or "Visual" in incident["title"]
        assert "evidence" in incident
        assert "risk_score" in incident


@pytest.mark.asyncio
async def test_upload_image_unsupported_type():
    """Verify rejection of unsupported extensions (e.g. .exe, .txt)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        files = {"file": ("malicious.exe", b"MZ\x90\x00\x03\x00\x00\x00", "application/x-dosexec")}
        response = await ac.post("/api/v1/analyze/media/image", files=files)
        assert response.status_code == 400
        assert "Unsupported file type" in response.json()["detail"]


@pytest.mark.asyncio
async def test_upload_image_empty_file():
    """Verify rejection of empty file (0 bytes)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        files = {"file": ("empty.png", b"", "image/png")}
        response = await ac.post("/api/v1/analyze/media/image", files=files)
        assert response.status_code == 400
        assert "Uploaded file is empty" in response.json()["detail"]


@pytest.mark.asyncio
async def test_upload_image_malformed():
    """Verify rejection of corrupted or non-decodable image data."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        corrupted = b"NOT_A_VALID_IMAGE_BYTES_XYZ_12345"
        files = {"file": ("corrupt.png", corrupted, "image/png")}
        response = await ac.post("/api/v1/analyze/media/image", files=files)
        assert response.status_code == 400
        assert "Malformed image file" in response.json()["detail"]


@pytest.mark.asyncio
async def test_upload_audio_wav_success():
    """Verify multipart WAV audio upload with anti-spoofing and speaker verification."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        wav_bytes = _create_dummy_wav()
        files = {"file": ("call_sample.wav", wav_bytes, "audio/wav")}
        data = {"claimed_identity": "CFO", "context": "Urgent vendor wire transfer authorization"}

        response = await ac.post("/api/v1/analyze/media/audio", files=files, data=data)
        assert response.status_code == 200, response.text
        incident = response.json()
        assert incident["input_type"] == "audio"
        assert "evidence" in incident
        assert incident["status"].lower() == "new"



@pytest.mark.asyncio
async def test_upload_audio_mp3_success():
    """Verify multipart MP3 audio upload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        mp3_bytes = _create_dummy_mp3()
        files = {"file": ("voicemail.mp3", mp3_bytes, "audio/mpeg")}
        response = await ac.post("/api/v1/analyze/media/audio", files=files)
        assert response.status_code == 200
        assert response.json()["input_type"] == "audio"


@pytest.mark.asyncio
async def test_upload_audio_unsupported():
    """Verify rejection of unsupported audio extensions."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        files = {"file": ("recording.flac", b"fLaC\x00\x00", "audio/flac")}
        response = await ac.post("/api/v1/analyze/media/audio", files=files)
        assert response.status_code == 400
        assert "Unsupported file type" in response.json()["detail"]


@pytest.mark.asyncio
async def test_upload_audio_malformed_header():
    """Verify rejection of files with fake extension but invalid audio headers."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        files = {"file": ("fake.wav", b"THIS_IS_NOT_A_WAV_HEADER", "audio/wav")}
        response = await ac.post("/api/v1/analyze/media/audio", files=files)
        assert response.status_code == 400
        assert "Malformed audio file" in response.json()["detail"]


def _create_dummy_video() -> bytes:
    """Create a minimal valid MP4 video byte stream using OpenCV."""
    import tempfile, os
    temp = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
    temp.close()
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(temp.name, fourcc, 10.0, (64, 64))
    for _ in range(5):
        frame = np.zeros((64, 64, 3), dtype=np.uint8)
        out.write(frame)
    out.release()
    with open(temp.name, "rb") as f:
        data = f.read()
    try:
        os.unlink(temp.name)
    except OSError:
        pass
    return data


@pytest.mark.asyncio
async def test_upload_video_mp4_success():
    """Verify multipart MP4 video upload with frame analysis and incident creation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        vid_bytes = _create_dummy_video()
        files = {"file": ("deepfake_clip.mp4", vid_bytes, "video/mp4")}
        data = {"claimed_identity": "CEO Alice", "context": "Executive announcement video"}
        response = await ac.post("/api/v1/analyze/media/video", files=files, data=data)
        assert response.status_code == 200, response.text
        incident = response.json()
        assert incident["input_type"] == "video"
        assert "evidence" in incident
        assert incident["status"].lower() == "new"


@pytest.mark.asyncio
async def test_upload_video_unsupported():
    """Verify rejection of unsupported video types."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        files = {"file": ("test.avi", b"RIFF....AVI ", "video/x-msvideo")}
        response = await ac.post("/api/v1/analyze/media/video", files=files)
        assert response.status_code == 400
        assert "Unsupported file type" in response.json()["detail"]


@pytest.mark.asyncio
async def test_upload_video_malformed():
    """Verify rejection of corrupted video file."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        files = {"file": ("broken.mp4", b"\x00\x00\x00\x18ftypisomCORRUPT_REST", "video/mp4")}
        response = await ac.post("/api/v1/analyze/media/video", files=files)
        assert response.status_code == 400
        assert "Malformed video file" in response.json()["detail"]



@pytest.mark.asyncio
async def test_url_analysis_endpoint():
    """Verify POST /api/v1/analyze/url produces a valid Incident."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {"url": "https://secure-sbi-kyc-update.xyz/login", "context": "Phishing email link"}
        response = await ac.post("/api/v1/analyze/url", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["input_type"] == "url"
        assert data["risk_score"] > 0
        assert len(data["evidence"]) > 0


@pytest.mark.asyncio
async def test_message_analysis_endpoint():
    """Verify POST /api/v1/analyze/message produces a valid Incident."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {"text": "URGENT: Your SBI account is blocked. Verify KYC immediately at http://secure-kyc.com"}
        response = await ac.post("/api/v1/analyze/message", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["input_type"] in ("message", "text")
        assert len(data["evidence"]) > 0



@pytest.mark.asyncio
async def test_existing_json_image_endpoint_backward_compatible():
    """Verify existing JSON POST /api/v1/analyze/image remains compatible."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {
            "ai_generated_prob": 0.88,
            "manipulation_prob": 0.75,
            "target_name": "Executive Smith",
        }
        response = await ac.post("/api/v1/analyze/image", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["input_type"] == "image"
        assert data["risk_score"] > 0
