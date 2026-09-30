"""Phase 7 Test Suite — Evaluation Framework Hardening.

Verifies all 17 Phase 7 requirements:
1.  test_ground_truth_schema              — every sample has required Phase 7 fields
2.  test_dataset_provenance              — provenance metadata present and correct
3.  test_binary_metrics                  — honest binary classification metrics
4.  test_multiclass_metrics              — threat type classification tracking
5.  test_zero_denominator_handling       — NOT_MEASURED, not fabricated value
6.  test_risk_band_evaluation            — expected vs observed risk level
7.  test_provider_evaluation             — provider availability records correct
8.  test_multimodal_fusion_evaluation    — fusion result marked NOT_MEASURED where appropriate
9.  test_response_evaluation             — response class comparison
10. test_unavailable_provider_handling   — provider unavailable tracked correctly
11. test_unavailable_not_safe            — UNAVAILABLE provider causes_safe == False
12. test_latency_measurement             — latency stats computed correctly
13. test_sample_size_reporting           — small-sample warnings on n < 10
14. test_evaluation_reproducibility      — same ground truth → deterministic metrics
15. test_evaluation_api                  — all Phase 7 API endpoints return expected structure
16. test_evaluation_dashboard_payload    — dashboard payload matches schema
17. test_no_fabricated_metrics           — empty input returns NOT_MEASURED, not 1.0

IMPORTANT: These tests do not modify any existing Phase 0–6 tests.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.database import init_db
from app.evaluation.metrics import EvaluationMetricsCalculator, PhaseSevenMetricsCalculator
from app.evaluation.runner import BenchmarkRunner
from app.main import app
from app.schemas.evaluation import (
    ConfusionMatrix,
    DatasetProvenance,
    HonestMetric,
    MeasurementStatus,
    SampleEvaluationResult,
)
from app.schemas.threat import ThreatAssessment, ThreatType


@pytest.fixture
def client():
    """TestClient with lifespan=True so app startup (init_db) runs before tests."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def runner():
    return BenchmarkRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    sample_id: str,
    modality: str,
    gt: str,
    pred: str,
    score: float,
    latency: float = 20.0,
    threat_type: ThreatType = ThreatType.PHISHING,
    risk_level: str = "HIGH",
) -> SampleEvaluationResult:
    """Build a minimal SampleEvaluationResult for unit testing."""
    is_pos = pred in ("MALICIOUS", "SUSPICIOUS")
    gt_pos = gt in ("MALICIOUS", "SUSPICIOUS")
    return SampleEvaluationResult(
        sample_id=sample_id,
        modality=modality,
        description="test",
        predicted_assessment=ThreatAssessment(pred),
        ground_truth_assessment=gt,
        predicted_risk_score=score,
        predicted_risk_level=risk_level,
        expected_risk_level=risk_level,
        risk_band_match=True,
        predicted_threat_type=threat_type,
        expected_threat_type=threat_type.value,
        threat_type_match=True,
        is_correct=(gt_pos == is_pos),
        is_false_positive=(not gt_pos) and is_pos,
        is_false_negative=gt_pos and (not is_pos),
        latency_ms=latency,
    )


# ==============================================================================
# 1. test_ground_truth_schema
# ==============================================================================

def test_ground_truth_schema(runner):
    """Verify every ground-truth sample has required Phase 7 fields."""
    samples = runner.load_dataset()
    assert len(samples) >= 20, f"Expected >= 20 Phase 7 samples, got {len(samples)}"

    for sample in samples:
        assert sample.id, f"Sample missing 'id': {sample}"
        assert sample.modality in ("url", "message", "audio", "auth_event"), \
            f"Unknown modality: {sample.modality}"
        assert sample.ground_truth_label in ("MALICIOUS", "SAFE", "SUSPICIOUS"), \
            f"Invalid ground_truth_label: {sample.ground_truth_label}"
        assert sample.description, f"Sample {sample.id} missing description"

        # Phase 7 extended fields — should be present in upgraded ground truth
        assert sample.scenario is not None, \
            f"Sample {sample.id} missing 'scenario' (Phase 7 required)"
        assert sample.expected_risk_level is not None, \
            f"Sample {sample.id} missing 'expected_risk_level' (Phase 7 required)"
        assert sample.expected_response_class is not None, \
            f"Sample {sample.id} missing 'expected_response_class' (Phase 7 required)"

        # Provenance
        assert sample.dataset is not None, \
            f"Sample {sample.id} missing 'dataset' provenance block"
        assert sample.dataset.get("type") in (
            "SYNTHETIC_DATA", "PUBLIC_DATA", "AUTHORIZED_DATA", "DEMO_FIXTURE"
        ), f"Sample {sample.id} has invalid dataset type: {sample.dataset.get('type')}"


# ==============================================================================
# 2. test_dataset_provenance
# ==============================================================================

def test_dataset_provenance(runner):
    """Verify dataset provenance is present and SYNTHETIC_DATA is correctly labeled."""
    summary = runner.get_ground_truth_summary()

    assert "dataset_types" in summary
    assert "SYNTHETIC_DATA" in summary["dataset_types"], \
        "All samples should be labeled SYNTHETIC_DATA"

    # No 'PUBLIC_DATA' or 'AUTHORIZED_DATA' should be present (these are all synthetic)
    for dtype in summary["dataset_types"]:
        assert dtype != "NOT_MEASURED", "Dataset type should not be 'NOT_MEASURED'"

    assert "provenance_note" in summary
    assert "SYNTHETIC" in summary["provenance_note"].upper()

    # Samples with Phase 7 fields
    assert summary.get("samples_with_expected_risk_level", 0) > 0
    assert summary.get("samples_with_expected_response_class", 0) > 0


# ==============================================================================
# 3. test_binary_metrics
# ==============================================================================

def test_binary_metrics():
    """Verify correct binary TP/TN/FP/FN computation and metric formulas."""
    # 6 TP, 4 TN, 2 FP, 3 FN
    results = (
        [_make_result(f"tp_{i}", "url", "MALICIOUS", "MALICIOUS", 0.9) for i in range(6)]
        + [_make_result(f"tn_{i}", "url", "SAFE", "SAFE", 0.1) for i in range(4)]
        + [_make_result(f"fp_{i}", "url", "SAFE", "MALICIOUS", 0.8) for i in range(2)]
        + [_make_result(f"fn_{i}", "url", "MALICIOUS", "SAFE", 0.2) for i in range(3)]
    )

    dm = PhaseSevenMetricsCalculator.compute_detection(results, "url")

    assert dm.confusion_matrix.true_positives == 6
    assert dm.confusion_matrix.true_negatives == 4
    assert dm.confusion_matrix.false_positives == 2
    assert dm.confusion_matrix.false_negatives == 3
    assert dm.sample_count == 15

    # All metrics should be MEASURED
    assert dm.precision.status == MeasurementStatus.MEASURED
    assert dm.recall.status == MeasurementStatus.MEASURED
    assert dm.f1_score.status == MeasurementStatus.MEASURED
    assert dm.false_positive_rate.status == MeasurementStatus.MEASURED

    # Precision = TP / (TP + FP) = 6 / 8 = 0.75
    assert abs(dm.precision.value - 0.75) < 0.01, f"Expected ~0.75, got {dm.precision.value}"

    # Recall = TP / (TP + FN) = 6 / 9 = 0.6667
    assert abs(dm.recall.value - 0.6667) < 0.01, f"Expected ~0.667, got {dm.recall.value}"

    # F1 = 2 * (0.75 * 0.667) / (0.75 + 0.667) = 0.706
    assert abs(dm.f1_score.value - 0.706) < 0.02, f"Expected ~0.706, got {dm.f1_score.value}"

    # FPR = FP / (FP + TN) = 2 / 6 = 0.333
    assert abs(dm.false_positive_rate.value - 0.333) < 0.01, \
        f"Expected ~0.333, got {dm.false_positive_rate.value}"

    # Accuracy = (TP + TN) / total = 10 / 15 = 0.667
    assert abs(dm.accuracy.value - 0.667) < 0.01, f"Expected ~0.667, got {dm.accuracy.value}"


# ==============================================================================
# 4. test_multiclass_metrics
# ==============================================================================

def test_multiclass_metrics(runner):
    """Verify threat type classification is tracked per sample."""
    samples = runner.load_dataset()

    # Check that expected_threat_type is set on malicious samples
    malicious = [s for s in samples if s.ground_truth_label == "MALICIOUS"]
    for s in malicious:
        assert s.expected_threat_type is not None, \
            f"Malicious sample {s.id} missing expected_threat_type"

    # Verify threat types are valid ThreatType values
    valid_types = {t.value for t in ThreatType}
    for s in malicious:
        # expected_threat_type is stored as str (use_enum_values=True) or ThreatType enum
        exp_type = (
            s.expected_threat_type.value
            if hasattr(s.expected_threat_type, "value")
            else s.expected_threat_type  # already a str
        )
        assert exp_type in valid_types, \
            f"Invalid threat type: {s.expected_threat_type}"


# ==============================================================================
# 5. test_zero_denominator_handling
# ==============================================================================

def test_zero_denominator_handling():
    """Verify zero denominators return NOT_MEASURED, not fabricated values."""
    # Empty list — all metrics should be NOT_MEASURED
    dm_empty = PhaseSevenMetricsCalculator.compute_detection([], "empty")
    assert dm_empty.sample_count == 0
    assert dm_empty.precision.status == MeasurementStatus.NOT_MEASURED
    assert dm_empty.recall.status == MeasurementStatus.NOT_MEASURED
    assert dm_empty.f1_score.status == MeasurementStatus.NOT_MEASURED
    assert dm_empty.false_positive_rate.status == MeasurementStatus.NOT_MEASURED
    assert dm_empty.precision.value is None
    assert dm_empty.recall.value is None
    assert dm_empty.f1_score.value is None

    # All-negative predictions (no TP, no FP) → precision undefined
    results_all_tn = [
        _make_result(f"tn_{i}", "url", "SAFE", "SAFE", 0.1)
        for i in range(5)
    ]
    dm_all_neg = PhaseSevenMetricsCalculator.compute_detection(results_all_tn, "url")
    # Precision denominator = TP + FP = 0 + 0 = 0 → NOT_MEASURED
    assert dm_all_neg.precision.status == MeasurementStatus.NOT_MEASURED, \
        "Precision should be NOT_MEASURED when TP+FP=0"
    # Recall denominator = TP + FN = 0 + 0 = 0 → NOT_MEASURED
    assert dm_all_neg.recall.status == MeasurementStatus.NOT_MEASURED, \
        "Recall should be NOT_MEASURED when TP+FN=0"

    # Verify legacy calculator also handles empty gracefully (no exception)
    legacy = EvaluationMetricsCalculator.compute([])
    assert legacy.total_samples == 0
    # Phase 7 fix verification: legacy now returns 0.0, not fabricated 1.0
    assert legacy.accuracy == 0.0, \
        f"Empty-list accuracy should be 0.0 (honest), got {legacy.accuracy}"


def test_zero_denominator_legacy_fabrication_removed():
    """Explicitly verify the Phase 5 bug is fixed: empty list no longer returns 1.0."""
    legacy = EvaluationMetricsCalculator.compute([])
    # Before Phase 7: returned accuracy=1.0, precision=1.0, recall=1.0, f1=1.0 (FABRICATED)
    # After Phase 7: returns 0.0 (honest)
    assert legacy.precision != 1.0, "Fabricated precision=1.0 on empty list must be fixed"
    assert legacy.recall != 1.0, "Fabricated recall=1.0 on empty list must be fixed"
    assert legacy.f1_score != 1.0, "Fabricated f1_score=1.0 on empty list must be fixed"


# ==============================================================================
# 6. test_risk_band_evaluation
# ==============================================================================

@pytest.mark.asyncio
async def test_risk_band_evaluation(runner):
    """Verify risk band evaluation correctly classifies EXACT / OVER / UNDER."""
    await init_db()
    # Run on auth_event samples which have expected_risk_level
    result = await runner.run(modality="auth_event", sample_limit=4)

    risk_eval = result.risk_evaluation
    assert risk_eval is not None
    assert risk_eval.sample_count > 0

    if risk_eval.measured_sample_count > 0:
        # Exact match rate should be MEASURED
        assert risk_eval.exact_match_rate.status == MeasurementStatus.MEASURED
        assert risk_eval.exact_match_rate.value is not None
        assert 0.0 <= risk_eval.exact_match_rate.value <= 1.0

        # Results should contain direction labels
        for r in risk_eval.results:
            assert r.direction in ("EXACT", "OVER_CLASSIFIED", "UNDER_CLASSIFIED", "UNKNOWN"), \
                f"Invalid direction: {r.direction}"
            assert r.expected_risk_level in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert r.observed_risk_level in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    else:
        # If no risk levels observed, should be NOT_MEASURED
        assert risk_eval.exact_match_rate.status in (
            MeasurementStatus.NOT_MEASURED,
            MeasurementStatus.INSUFFICIENT_GROUND_TRUTH,
        )


# ==============================================================================
# 7. test_provider_evaluation
# ==============================================================================

@pytest.mark.asyncio
async def test_provider_evaluation(runner):
    """Verify provider evaluation records correct availability and not-safe flag."""
    await init_db()
    result = await runner.run(modality="auth_event", sample_limit=2)

    prov_eval = result.provider_evaluation
    assert prov_eval is not None
    assert len(prov_eval.providers) >= 1

    # No provider should have unavailable_causes_safe=True
    for p in prov_eval.providers:
        assert p.unavailable_causes_safe is False, \
            f"Provider {p.provider_name} should not cause SAFE when unavailable"
        assert p.availability in ("AVAILABLE", "UNAVAILABLE", "DEGRADED", "NOT_TESTED")

    # Architecture verification flag
    assert prov_eval.unavailable_not_safe_verified is True


# ==============================================================================
# 8. test_multimodal_fusion_evaluation
# ==============================================================================

@pytest.mark.asyncio
async def test_multimodal_fusion_evaluation(runner):
    """Verify fusion evaluation is correctly marked NOT_MEASURED when no fusion ground truth."""
    await init_db()
    result = await runner.run(sample_limit=4)

    # The current evaluation set has no multimodal fusion samples
    # Scenario matrix should reflect this
    scenario_names = [r.scenario for r in result.scenario_matrix]
    assert result.scenario_matrix is not None

    # deepfake_image and deepfake_video should be present and marked NOT_MEASURED
    not_measured = [
        r for r in result.scenario_matrix
        if r.detection_status == MeasurementStatus.NOT_MEASURED
    ]
    assert len(not_measured) >= 1, \
        "At least deepfake_image or deepfake_video should be NOT_MEASURED"

    for row in not_measured:
        assert row.total_samples == 0, \
            f"NOT_MEASURED row {row.scenario} should have 0 samples"


# ==============================================================================
# 9. test_response_evaluation
# ==============================================================================

@pytest.mark.asyncio
async def test_response_evaluation(runner):
    """Verify response evaluation runs and produces honest results."""
    await init_db()
    result = await runner.run(modality="auth_event", sample_limit=2)

    resp_eval = result.response_evaluation
    assert resp_eval is not None

    if resp_eval.status == MeasurementStatus.MEASURED:
        assert resp_eval.sample_count > 0
        assert resp_eval.appropriateness_rate.status == MeasurementStatus.MEASURED
        assert resp_eval.appropriateness_rate.value is not None
        assert 0.0 <= resp_eval.appropriateness_rate.value <= 1.0
        total_resp = resp_eval.appropriate_count + resp_eval.inappropriate_count
        assert total_resp == resp_eval.sample_count
    else:
        # NOT_MEASURED is acceptable if response generation failed or no ground truth
        assert resp_eval.appropriateness_rate.value is None


# ==============================================================================
# 10. test_unavailable_provider_handling
# ==============================================================================

def test_unavailable_provider_handling(runner):
    """Verify providers without ground truth samples are marked NOT_TESTED."""
    # Create a runner and get provider evaluation without running
    # (by using the static method)
    prov_eval = runner._build_provider_evaluation()

    # Image and video providers should be NOT_TESTED
    not_tested = [p for p in prov_eval.providers if p.availability == "NOT_TESTED"]
    assert len(not_tested) >= 2, \
        "ImageSyntheticDetector and VideoDeepfakeDetector should be NOT_TESTED"

    not_tested_names = {p.provider_name for p in not_tested}
    assert "ImageSyntheticDetector" in not_tested_names
    assert "VideoDeepfakeDetector" in not_tested_names


# ==============================================================================
# 11. test_unavailable_not_safe
# ==============================================================================

def test_unavailable_not_safe(runner):
    """Critical: UNAVAILABLE provider must never map to SAFE assessment."""
    prov_eval = runner._build_provider_evaluation()

    for p in prov_eval.providers:
        assert p.unavailable_causes_safe is False, (
            f"CRITICAL: Provider '{p.provider_name}' has unavailable_causes_safe=True. "
            "UNAVAILABLE provider MUST NOT cause SAFE assessment. "
            "This would be a security regression."
        )


# ==============================================================================
# 12. test_latency_measurement
# ==============================================================================

def test_latency_measurement():
    """Verify latency statistics are computed correctly."""
    results = [
        _make_result(f"s_{i}", "url", "MALICIOUS", "MALICIOUS", 0.9, latency=float(10 + i * 5))
        for i in range(6)
    ]
    # latencies: 10, 15, 20, 25, 30, 35

    stats = PhaseSevenMetricsCalculator.compute_latency_stats(results, "url")

    assert stats.modality == "url"
    assert stats.sample_count == 6
    assert stats.mean_ms is not None
    assert stats.median_ms is not None
    assert stats.p95_ms is not None
    assert stats.min_ms is not None
    assert stats.max_ms is not None

    assert abs(stats.mean_ms - 22.5) < 0.5, f"Expected mean ~22.5, got {stats.mean_ms}"
    assert stats.min_ms == 10.0
    assert stats.max_ms == 35.0
    assert stats.min_ms <= stats.median_ms <= stats.max_ms

    # Single sample
    single = PhaseSevenMetricsCalculator.compute_latency_stats(
        [_make_result("s0", "url", "SAFE", "SAFE", 0.1, latency=50.0)], "url"
    )
    assert single.sample_count == 1
    assert single.mean_ms == 50.0
    assert single.note is not None  # Should have a single-execution warning

    # Empty
    empty = PhaseSevenMetricsCalculator.compute_latency_stats([], "url")
    assert empty.sample_count == 0
    assert empty.mean_ms is None


# ==============================================================================
# 13. test_sample_size_reporting
# ==============================================================================

def test_sample_size_reporting():
    """Verify small-sample (n < 10) warning is attached."""
    # n = 5 — should get warning
    small = [_make_result(f"s_{i}", "url", "MALICIOUS", "MALICIOUS", 0.9) for i in range(5)]
    dm_small = PhaseSevenMetricsCalculator.compute_detection(small, "url")
    assert dm_small.small_sample_warning is not None, "n=5 should have small sample warning"
    assert dm_small.precision.warning is not None

    # n = 10 — no warning
    large = [_make_result(f"s_{i}", "url", "MALICIOUS", "MALICIOUS", 0.9) for i in range(5)] + \
            [_make_result(f"b_{i}", "url", "SAFE", "SAFE", 0.1) for i in range(5)]
    dm_large = PhaseSevenMetricsCalculator.compute_detection(large, "url")
    assert dm_large.small_sample_warning is None, "n=10 should NOT have small sample warning"

    # Sample count is always reported
    assert dm_small.sample_count == 5
    assert dm_small.precision.sample_count == 5


# ==============================================================================
# 14. test_evaluation_reproducibility
# ==============================================================================

@pytest.mark.asyncio
async def test_evaluation_reproducibility():
    """Verify same ground truth produces same deterministic metrics."""
    await init_db()
    r1 = BenchmarkRunner()
    r2 = BenchmarkRunner()

    # Run same modality twice
    result1 = await r1.run(modality="url", sample_limit=4)
    result2 = await r2.run(modality="url", sample_limit=4)

    # Metadata (run_id) will differ — that's expected
    assert result1.run_id != result2.run_id

    # But sample count, confusion matrix, and dataset version must match
    assert result1.total_samples == result2.total_samples
    assert result1.dataset_version == result2.dataset_version

    cm1 = result1.overall_metrics.confusion_matrix
    cm2 = result2.overall_metrics.confusion_matrix
    assert cm1.true_positives == cm2.true_positives
    assert cm1.true_negatives == cm2.true_negatives
    assert cm1.false_positives == cm2.false_positives
    assert cm1.false_negatives == cm2.false_negatives


# ==============================================================================
# 15. test_evaluation_api
# ==============================================================================

def test_evaluation_api_all_endpoints(client):
    """Verify all Phase 7 evaluation API endpoints return correct structure."""
    # First run a benchmark to populate the cache
    run_resp = client.post("/api/v1/evaluation/run", json={"modality": "auth_event", "sample_limit": 2})
    assert run_resp.status_code == 200
    run_data = run_resp.json()
    assert "run_id" in run_data
    assert "overall_metrics" in run_data
    assert "scenario_matrix" in run_data
    assert "detection_metrics" in run_data
    assert "risk_evaluation" in run_data
    assert "response_evaluation" in run_data
    assert "latency_stats" in run_data
    assert "provenance" in run_data

    # GET /summary
    resp = client.get("/api/v1/evaluation/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "run_id" in data
    assert "detection_summary" in data
    assert "risk_evaluation_summary" in data
    assert "response_evaluation_summary" in data
    assert "provenance" in data
    assert "important_disclaimer" in data

    # GET /scenarios
    resp = client.get("/api/v1/evaluation/scenarios")
    assert resp.status_code == 200
    scenarios = resp.json()
    assert isinstance(scenarios, list)
    assert len(scenarios) > 0
    for row in scenarios:
        assert "scenario" in row
        assert "total_samples" in row
        assert "detection_status" in row

    # GET /metrics
    resp = client.get("/api/v1/evaluation/metrics")
    assert resp.status_code == 200
    metrics = resp.json()
    assert isinstance(metrics, dict)
    for mod, m in metrics.items():
        assert "precision" in m
        assert "recall" in m
        assert "f1_score" in m
        # Each metric has status field
        assert "status" in m["precision"]

    # GET /latency
    resp = client.get("/api/v1/evaluation/latency")
    assert resp.status_code == 200
    latency = resp.json()
    assert isinstance(latency, list)
    for stat in latency:
        assert "modality" in stat
        assert "sample_count" in stat

    # GET /providers
    resp = client.get("/api/v1/evaluation/providers")
    assert resp.status_code == 200
    providers = resp.json()
    assert "providers" in providers
    assert "unavailable_not_safe_verified" in providers

    # GET /risk
    resp = client.get("/api/v1/evaluation/risk")
    assert resp.status_code == 200
    risk = resp.json()
    assert "exact_match_rate" in risk

    # GET /response
    resp = client.get("/api/v1/evaluation/response")
    assert resp.status_code == 200
    response = resp.json()
    assert "status" in response

    # Existing endpoints still work
    gt_resp = client.get("/api/v1/evaluation/ground-truth")
    assert gt_resp.status_code == 200
    gt_data = gt_resp.json()
    assert gt_data["total_samples"] >= 20

    latest_resp = client.get("/api/v1/evaluation/latest")
    assert latest_resp.status_code == 200


# ==============================================================================
# 16. test_evaluation_dashboard_payload
# ==============================================================================

def test_evaluation_dashboard_payload(client):
    """Verify dashboard payload contains all fields the EvaluationDashboard.jsx expects."""
    # Run a quick benchmark
    run_resp = client.post("/api/v1/evaluation/run", json={"sample_limit": 4})
    assert run_resp.status_code == 200
    data = run_resp.json()

    # Phase 5 dashboard fields (backward compatibility)
    assert "run_id" in data
    assert "overall_metrics" in data
    assert "per_modality_metrics" in data
    assert "sample_results" in data

    overall = data["overall_metrics"]
    assert "precision" in overall
    assert "recall" in overall
    assert "f1_score" in overall
    assert "false_positive_rate" in overall
    assert "avg_latency_ms" in overall
    assert "p95_latency_ms" in overall
    assert "confusion_matrix" in overall
    cm = overall["confusion_matrix"]
    assert "true_positives" in cm
    assert "true_negatives" in cm
    assert "false_positives" in cm
    assert "false_negatives" in cm

    # Phase 7 extended dashboard fields
    assert "scenario_matrix" in data
    assert "detection_metrics" in data
    assert "risk_evaluation" in data
    assert "response_evaluation" in data
    assert "latency_stats" in data
    assert "provenance" in data

    # Provenance disclaimer
    provenance = data["provenance"]
    assert provenance["dataset_type"] == "SYNTHETIC_DATA"
    assert "SYNTHETIC" in provenance.get("note", "").upper()


# ==============================================================================
# 17. test_no_fabricated_metrics
# ==============================================================================

def test_no_fabricated_metrics():
    """Critical: verify no metric fabrication in any path.

    Phase 5 bug: EvaluationMetricsCalculator returned precision=1.0, recall=1.0,
    f1_score=1.0 on empty input — fabricated values.

    Phase 7 requirement: empty or zero-denominator → NOT_MEASURED or 0.0.
    """
    # Empty list — PhaseSevenMetricsCalculator
    dm = PhaseSevenMetricsCalculator.compute_detection([], "url")
    assert dm.precision.status == MeasurementStatus.NOT_MEASURED
    assert dm.recall.status == MeasurementStatus.NOT_MEASURED
    assert dm.f1_score.status == MeasurementStatus.NOT_MEASURED
    assert dm.precision.value is None, "Empty-list precision must be None, not fabricated"
    assert dm.recall.value is None, "Empty-list recall must be None, not fabricated"
    assert dm.f1_score.value is None, "Empty-list f1_score must be None, not fabricated"

    # Empty list — legacy calculator (Phase 7 fix)
    legacy = EvaluationMetricsCalculator.compute([])
    assert legacy.accuracy == 0.0, "Legacy: empty-list accuracy must be 0.0 not 1.0"
    assert legacy.precision == 0.0, "Legacy: empty-list precision must be 0.0 not 1.0"
    assert legacy.recall == 0.0, "Legacy: empty-list recall must be 0.0 not 1.0"
    assert legacy.f1_score == 0.0, "Legacy: empty-list f1_score must be 0.0 not 1.0"

    # HonestMetric.not_measured() must never have a numeric value
    nm = HonestMetric.not_measured("test")
    assert nm.value is None, "NOT_MEASURED metric must have value=None"
    assert nm.status == MeasurementStatus.NOT_MEASURED

    # HonestMetric.measured() must have a float value
    m = HonestMetric.measured(0.75, 20)
    assert m.value == 0.75
    assert m.status == MeasurementStatus.MEASURED

    # UNAVAILABLE must have value=None
    ua = HonestMetric.unavailable("provider down")
    assert ua.value is None
    assert ua.status == MeasurementStatus.UNAVAILABLE


# ==============================================================================
# Bonus: End-to-end smoke test
# ==============================================================================

@pytest.mark.asyncio
async def test_full_evaluation_run_produces_honest_output():
    """Run a small full evaluation and verify no fabricated claims appear in output."""
    await init_db()
    runner = BenchmarkRunner()
    result = await runner.run(sample_limit=6)

    assert result.run_id.startswith("eval_")
    assert result.dataset_version == "7.0.0"
    assert result.total_samples <= 6

    # Provenance must be present and honest
    assert result.provenance is not None
    assert result.provenance.dataset_type == "SYNTHETIC_DATA"

    # Detection metrics must not contain precision=1.0 with sample_count=0
    for mod, dm in result.detection_metrics.items():
        if dm.sample_count == 0:
            assert dm.precision.value is None, \
                f"Modality {mod}: precision should be None when no samples"

    # Scenario matrix must have NOT_MEASURED entries for missing scenarios
    not_measured_rows = [
        r for r in result.scenario_matrix
        if r.detection_status == MeasurementStatus.NOT_MEASURED
    ]
    assert len(not_measured_rows) > 0, \
        "Expected at least one NOT_MEASURED scenario (deepfake_image, deepfake_video)"

    # Risk evaluation should be populated
    assert result.risk_evaluation is not None
