"""Phase 5 Test Suite — In-App Evaluation Subsystem & Benchmarks.

Verifies:
1. Ground truth dataset loading and schema integrity.
2. Statistical metrics calculator (Accuracy, Precision, Recall, F1, FPR, FNR, Latency percentiles).
3. Benchmark suite runner executing across multimodal samples.
4. FastAPI evaluation endpoints (/api/v1/evaluation/ground-truth, /run, /latest).
"""

import pytest
from fastapi.testclient import TestClient

from app.evaluation.metrics import EvaluationMetricsCalculator
from app.evaluation.runner import BenchmarkRunner
from app.main import app
from app.schemas.evaluation import SampleEvaluationResult
from app.schemas.threat import ThreatAssessment, ThreatType


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# 1. Ground Truth Dataset Integrity Tests
# ==============================================================================

def test_ground_truth_dataset_loading():
    """Verify ground_truth.json loads cleanly and contains balanced samples across all modalities."""
    runner = BenchmarkRunner()
    samples = runner.load_dataset()

    assert len(samples) >= 15, "Ground truth dataset should have at least 15 representative samples"

    modalities = {s.modality for s in samples}
    assert "url" in modalities
    assert "message" in modalities
    assert "audio" in modalities
    assert "auth_event" in modalities

    labels = {s.ground_truth_label for s in samples}
    assert "MALICIOUS" in labels
    assert "SAFE" in labels

    # Modality filter works
    url_samples = runner.load_dataset(modality_filter="url")
    assert all(s.modality == "url" for s in url_samples)
    assert len(url_samples) >= 4


def test_ground_truth_summary():
    """Verify dataset summary metadata aggregation."""
    runner = BenchmarkRunner()
    summary = runner.get_ground_truth_summary()

    assert summary["total_samples"] >= 15
    assert "url" in summary["modality_breakdown"]
    assert "MALICIOUS" in summary["label_breakdown"]


# ==============================================================================
# 2. Statistical Metrics Calculator Tests
# ==============================================================================

def test_metrics_calculator_perfect_classification():
    """Verify metrics calculator under 100% accuracy."""
    dummy_results = [
        SampleEvaluationResult(
            sample_id=f"s_{i}",
            modality="url",
            description="test",
            predicted_assessment=ThreatAssessment.MALICIOUS if i < 5 else ThreatAssessment.SAFE,
            ground_truth_assessment="MALICIOUS" if i < 5 else "SAFE",
            predicted_risk_score=0.90 if i < 5 else 0.10,
            predicted_threat_type=ThreatType.PHISHING if i < 5 else ThreatType.BENIGN,
            is_correct=True,
            is_false_positive=False,
            is_false_negative=False,
            latency_ms=15.0 + i,
        )
        for i in range(10)
    ]

    metrics = EvaluationMetricsCalculator.compute(dummy_results, modality_name="url")
    assert metrics.accuracy == 1.0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.false_negative_rate == 0.0
    assert metrics.confusion_matrix.true_positives == 5
    assert metrics.confusion_matrix.true_negatives == 5
    assert metrics.confusion_matrix.false_positives == 0
    assert metrics.confusion_matrix.false_negatives == 0
    assert metrics.avg_latency_ms > 0.0


def test_metrics_calculator_mixed_classification():
    """Verify metrics calculation with known False Positives and False Negatives."""
    # 4 True Positives, 3 True Negatives, 2 False Positives, 1 False Negative
    results = [
        # TP: GT Malicious, Pred Malicious (4)
        SampleEvaluationResult(
            sample_id=f"tp_{i}", modality="url", description="tp",
            predicted_assessment=ThreatAssessment.MALICIOUS, ground_truth_assessment="MALICIOUS",
            predicted_risk_score=0.85, predicted_threat_type=ThreatType.PHISHING,
            is_correct=True, is_false_positive=False, is_false_negative=False, latency_ms=20.0
        ) for i in range(4)
    ] + [
        # TN: GT Safe, Pred Safe (3)
        SampleEvaluationResult(
            sample_id=f"tn_{i}", modality="url", description="tn",
            predicted_assessment=ThreatAssessment.SAFE, ground_truth_assessment="SAFE",
            predicted_risk_score=0.10, predicted_threat_type=ThreatType.BENIGN,
            is_correct=True, is_false_positive=False, is_false_negative=False, latency_ms=10.0
        ) for i in range(3)
    ] + [
        # FP: GT Safe, Pred Malicious (2)
        SampleEvaluationResult(
            sample_id=f"fp_{i}", modality="url", description="fp",
            predicted_assessment=ThreatAssessment.MALICIOUS, ground_truth_assessment="SAFE",
            predicted_risk_score=0.80, predicted_threat_type=ThreatType.PHISHING,
            is_correct=False, is_false_positive=True, is_false_negative=False, latency_ms=25.0
        ) for i in range(2)
    ] + [
        # FN: GT Malicious, Pred Safe (1)
        SampleEvaluationResult(
            sample_id="fn_0", modality="url", description="fn",
            predicted_assessment=ThreatAssessment.SAFE, ground_truth_assessment="MALICIOUS",
            predicted_risk_score=0.15, predicted_threat_type=ThreatType.BENIGN,
            is_correct=False, is_false_positive=False, is_false_negative=True, latency_ms=12.0
        )
    ]

    metrics = EvaluationMetricsCalculator.compute(results, modality_name="test_mixed")
    # Total = 10, Correct = 7 -> Acc = 0.70
    assert metrics.total_samples == 10
    assert metrics.correct_predictions == 7
    assert metrics.accuracy == 0.70
    # Precision = TP / (TP + FP) = 4 / (4 + 2) = 4/6 = 0.6667
    assert round(metrics.precision, 2) == 0.67
    # Recall = TP / (TP + FN) = 4 / (4 + 1) = 4/5 = 0.80
    assert metrics.recall == 0.80
    # FPR = FP / (FP + TN) = 2 / (2 + 3) = 2/5 = 0.40
    assert metrics.false_positive_rate == 0.40
    # FNR = FN / (FN + TP) = 1 / (1 + 4) = 1/5 = 0.20
    assert metrics.false_negative_rate == 0.20


def test_metrics_calculator_empty():
    """Verify metrics calculator handles empty list gracefully."""
    metrics = EvaluationMetricsCalculator.compute([])
    assert metrics.total_samples == 0
    assert metrics.accuracy == 0.0


# ==============================================================================
# 3. Live Benchmark Runner Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_benchmark_runner_execution():
    """Verify live benchmark runner runs across selected auth & url samples."""
    runner = BenchmarkRunner()

    # Run on 2 auth_event samples (1 malicious, 1 safe)
    run_result = await runner.run(modality="auth_event", sample_limit=2)

    assert run_result.run_id.startswith("eval_")
    assert run_result.total_samples == 2
    assert run_result.duration_seconds > 0.0
    assert "auth_event" in run_result.per_modality_metrics
    assert run_result.overall_metrics.accuracy >= 0.50
    assert len(run_result.sample_results) == 2

    # Cached latest result works
    assert runner.get_latest_result() is not None
    assert runner.get_latest_result().run_id == run_result.run_id


# ==============================================================================
# 4. FastAPI Evaluation Endpoints Tests
# ==============================================================================

def test_api_evaluation_ground_truth(client):
    """Verify GET /api/v1/evaluation/ground-truth returns metadata."""
    resp = client.get("/api/v1/evaluation/ground-truth")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_samples" in data
    assert data["total_samples"] >= 15
    assert "modality_breakdown" in data


def test_api_evaluation_run_and_latest(client):
    """Verify POST /api/v1/evaluation/run and GET /api/v1/evaluation/latest."""
    # 1. Trigger benchmark with sample_limit=2 for fast execution
    resp_run = client.post(
        "/api/v1/evaluation/run",
        json={"modality": "auth_event", "sample_limit": 2}
    )
    assert resp_run.status_code == 200
    run_data = resp_run.json()
    assert "run_id" in run_data
    assert "overall_metrics" in run_data
    assert run_data["total_samples"] == 2

    # 2. Query latest benchmark
    resp_latest = client.get("/api/v1/evaluation/latest")
    assert resp_latest.status_code == 200
    latest_data = resp_latest.json()
    assert latest_data["run_id"] == run_data["run_id"]
    assert latest_data["overall_metrics"]["total_samples"] == 2
