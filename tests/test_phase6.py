"""Phase 6: Response Playbook Execution Engine — Full Test Suite."""

import json
import pytest
import pytest_asyncio
from uuid import uuid4

from app.response.response_service import ResponseExecutionService
from app.schemas.response import (
    VALID_ACTION_TRANSITIONS,
    ActionCategory,
    ActionExecutionMode,
    ActionPriority,
    ActionTransitionRequest,
    ActionRecommendation,
    ExecuteActionRequest,
    ResponseActionStatus,
    ResponseAuditEvent,
    ResponseExecutionRecord,
)
from app.schemas.threat import RiskLevel, ThreatType
from app.schemas.evidence import EvidenceItem, EvidenceSource, EvidenceType
from app.response.playbooks import ResponsePlaybookGenerator


# ─── Schema Tests ──────────────────────────────────────────────────────────────

class TestResponseSchemas:
    def test_response_action_status_enum_values(self):
        """All canonical lifecycle states are present."""
        statuses = {s.value for s in ResponseActionStatus}
        assert "RECOMMENDED" in statuses
        assert "ACKNOWLEDGED" in statuses
        assert "EXECUTING" in statuses
        assert "COMPLETED" in statuses
        assert "DISMISSED" in statuses
        assert "FAILED" in statuses

    def test_action_execution_mode_values(self):
        """ADVISORY and SIMULATED are the only execution modes."""
        modes = {m.value for m in ActionExecutionMode}
        assert modes == {"ADVISORY", "SIMULATED"}

    def test_execution_record_defaults(self):
        """ResponseExecutionRecord initializes to RECOMMENDED status."""
        rec = ResponseExecutionRecord(
            incident_id="inc_test",
            action_id="act_001",
            title="Test Action",
            description="Test description",
            category=ActionCategory.BLOCK,
            priority=ActionPriority.P0_IMMEDIATE,
        )
        assert rec.status == ResponseActionStatus.RECOMMENDED
        assert rec.mode == ActionExecutionMode.ADVISORY
        assert rec.audit_trail == []
        assert rec.simulation_output is None

    def test_audit_event_immutable_fields(self):
        """ResponseAuditEvent captures all required fields."""
        evt = ResponseAuditEvent(
            action_id="resp_001",
            incident_id="inc_001",
            from_status="RECOMMENDED",
            to_status="ACKNOWLEDGED",
            actor="analyst_alice",
            mode=ActionExecutionMode.SIMULATED,
            note="Reviewed and acknowledged",
        )
        assert evt.action_id == "resp_001"
        assert evt.actor == "analyst_alice"
        assert evt.to_status == "ACKNOWLEDGED"
        assert evt.note == "Reviewed and acknowledged"

    def test_execute_action_request_defaults(self):
        """ExecuteActionRequest defaults to SIMULATED mode."""
        req = ExecuteActionRequest()
        assert req.mode == ActionExecutionMode.SIMULATED
        assert req.actor == "Security Analyst"

    def test_action_recommendation_has_id(self):
        """ActionRecommendation generates a unique ID."""
        rec1 = ActionRecommendation(
            title="Block URL", description="Block the URL", 
            category=ActionCategory.BLOCK, priority=ActionPriority.P0_IMMEDIATE,
        )
        rec2 = ActionRecommendation(
            title="Warn User", description="Issue a user warning",
            category=ActionCategory.WARN, priority=ActionPriority.P1_HIGH,
        )
        assert rec1.id != rec2.id
        assert rec1.id.startswith("act_")


# ─── State Machine Tests ───────────────────────────────────────────────────────

class TestStateMachine:
    def test_recommended_can_transition_to_acknowledged(self):
        allowed = VALID_ACTION_TRANSITIONS[ResponseActionStatus.RECOMMENDED]
        assert ResponseActionStatus.ACKNOWLEDGED in allowed

    def test_recommended_can_be_dismissed(self):
        allowed = VALID_ACTION_TRANSITIONS[ResponseActionStatus.RECOMMENDED]
        assert ResponseActionStatus.DISMISSED in allowed

    def test_recommended_cannot_jump_to_completed(self):
        allowed = VALID_ACTION_TRANSITIONS[ResponseActionStatus.RECOMMENDED]
        assert ResponseActionStatus.COMPLETED not in allowed

    def test_acknowledged_can_transition_to_executing(self):
        allowed = VALID_ACTION_TRANSITIONS[ResponseActionStatus.ACKNOWLEDGED]
        assert ResponseActionStatus.EXECUTING in allowed

    def test_executing_can_only_complete_or_fail(self):
        allowed = VALID_ACTION_TRANSITIONS[ResponseActionStatus.EXECUTING]
        assert allowed == {ResponseActionStatus.COMPLETED, ResponseActionStatus.FAILED}

    def test_completed_is_terminal(self):
        """COMPLETED state has no outgoing transitions."""
        allowed = VALID_ACTION_TRANSITIONS[ResponseActionStatus.COMPLETED]
        assert len(allowed) == 0

    def test_dismissed_can_reopen(self):
        """DISMISSED allows re-opening back to RECOMMENDED."""
        allowed = VALID_ACTION_TRANSITIONS[ResponseActionStatus.DISMISSED]
        assert ResponseActionStatus.RECOMMENDED in allowed

    def test_failed_can_retry_via_acknowledged(self):
        """FAILED can go back to ACKNOWLEDGED for retry."""
        allowed = VALID_ACTION_TRANSITIONS[ResponseActionStatus.FAILED]
        assert ResponseActionStatus.ACKNOWLEDGED in allowed


# ─── Simulation Engine Tests ───────────────────────────────────────────────────

class TestSimulationEngine:
    def _make_record(self, category: ActionCategory, target: str = "test_target") -> ResponseExecutionRecord:
        return ResponseExecutionRecord(
            id="resp_test",
            incident_id="inc_test",
            action_id="act_test",
            title="Test",
            description="Test description",
            category=category,
            priority=ActionPriority.P1_HIGH,
            target_entity=target,
        )

    def test_block_simulation_is_safe(self):
        rec = self._make_record(ActionCategory.BLOCK, "http://phish.evil")
        result = ResponseExecutionService._simulate_execution(rec)
        assert result["real_systems_modified"] is False
        assert result["safety_guarantee"] == "ZERO_EXTERNAL_IMPACT"
        assert "SIMULATION" in result["result"]

    def test_session_simulation_is_safe(self):
        rec = self._make_record(ActionCategory.SESSION, "user_alice")
        result = ResponseExecutionService._simulate_execution(rec)
        assert result["real_systems_modified"] is False
        assert "REVOKED_IN_SIMULATION" in result["result"]

    def test_notification_simulation_is_safe(self):
        rec = self._make_record(ActionCategory.NOTIFICATION)
        result = ResponseExecutionService._simulate_execution(rec)
        assert result["real_systems_modified"] is False
        assert "SIMULATION" in result["result"]

    def test_simulation_has_required_keys(self):
        rec = self._make_record(ActionCategory.AUTHENTICATION)
        result = ResponseExecutionService._simulate_execution(rec)
        for key in ("simulation_id", "timestamp", "mode", "safety_guarantee", "result"):
            assert key in result, f"Missing key: {key}"
        assert result["mode"] == "SIMULATED"

    def test_all_categories_have_safe_simulations(self):
        """Every ActionCategory produces a safe simulation output."""
        for cat in ActionCategory:
            rec = self._make_record(cat)
            result = ResponseExecutionService._simulate_execution(rec)
            assert result["real_systems_modified"] is False, f"Category {cat} has unsafe simulation"


# ─── Playbook Generator Integration Tests ─────────────────────────────────────

class TestPlaybookIntegration:
    def _evidence(self, ev_type: EvidenceType) -> EvidenceItem:
        return EvidenceItem(
            id=f"EV-{uuid4().hex[:6]}",
            source=EvidenceSource.WEB,
            type=ev_type,
            value=0.9,
            weight=0.4,
            confidence=0.9,
            explanation="Test evidence",
        )

    def test_playbook_generates_advisory_only_actions(self):
        """Playbook generator never emits SIMULATED mode — always ADVISORY."""
        evidence = [self._evidence(EvidenceType.URLBERT_MALICIOUS)]
        actions = ResponsePlaybookGenerator.generate(
            threat_type=ThreatType.PHISHING,
            risk_level=RiskLevel.CRITICAL,
            evidence=evidence,
        )
        assert all(a.mode == "ADVISORY" for a in actions)

    def test_phishing_critical_generates_block_and_warn(self):
        evidence = [self._evidence(EvidenceType.CREDENTIAL_HARVEST_INTENT)]
        actions = ResponsePlaybookGenerator.generate(
            threat_type=ThreatType.PHISHING,
            risk_level=RiskLevel.CRITICAL,
            evidence=evidence,
        )
        categories = {a.category for a in actions}
        assert ActionCategory.BLOCK in categories or "BLOCK" in categories
        assert ActionCategory.WARN in categories or "WARN" in categories

    def test_all_actions_have_evidence_ids(self):
        e = self._evidence(EvidenceType.URLBERT_MALICIOUS)
        e.id = "EV-SPECIFIC-001"
        actions = ResponsePlaybookGenerator.generate(
            threat_type=ThreatType.MALICIOUS_URL,
            risk_level=RiskLevel.HIGH,
            evidence=[e],
        )
        for action in actions:
            assert "EV-SPECIFIC-001" in action.supporting_evidence_ids

    def test_safe_risk_returns_no_action_required(self):
        actions = ResponsePlaybookGenerator.generate(
            threat_type=ThreatType.PHISHING,
            risk_level=RiskLevel.SAFE,
            evidence=[],
        )
        assert len(actions) == 1
        assert actions[0].category == ActionCategory.VERIFICATION
        assert actions[0].priority == ActionPriority.P3_ADVISORY


# ─── API Contract Tests (schema validation) ───────────────────────────────────

class TestAPIContracts:
    def test_execute_request_rejects_invalid_mode(self):
        """ExecuteActionRequest only accepts valid modes."""
        with pytest.raises(Exception):
            ExecuteActionRequest(mode="DESTRUCTIVE")

    def test_transition_request_rejects_invalid_status(self):
        """ActionTransitionRequest only accepts valid lifecycle statuses."""
        with pytest.raises(Exception):
            ActionTransitionRequest(target_status="RANDOM_STATE")

    def test_response_execution_record_serialization(self):
        """ResponseExecutionRecord round-trips through JSON cleanly."""
        rec = ResponseExecutionRecord(
            incident_id="inc_001",
            action_id="act_001",
            title="Block Phishing Domain",
            description="Block at DNS gateway",
            category=ActionCategory.BLOCK,
            priority=ActionPriority.P0_IMMEDIATE,
            mode=ActionExecutionMode.SIMULATED,
        )
        data = rec.model_dump(mode="json")
        restored = ResponseExecutionRecord(**data)
        assert restored.title == rec.title
        assert restored.category == rec.category
        assert restored.mode == rec.mode
