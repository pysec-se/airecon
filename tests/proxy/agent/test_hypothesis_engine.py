"""Tests for the Hypothesis Engine in AgentState (models.py)."""
from __future__ import annotations

import pytest

from airecon.proxy.agent.models import MAX_HYPOTHESES, AgentState


@pytest.fixture()
def state() -> AgentState:
    return AgentState()


class TestAddHypothesis:
    def test_adds_new_hypothesis(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis(
            claim="Login form is vulnerable to SQLi",
            test_plan="Send ' OR 1=1-- in username field",
            phase="EXPLOIT",
        )
        assert hyp_id
        assert len(state.hypothesis_queue) == 1
        h = state.hypothesis_queue[0]
        assert h["claim"] == "Login form is vulnerable to SQLi"
        assert h["status"] == "pending"
        assert h["phase"] == "EXPLOIT"

    def test_empty_claim_returns_empty_id(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis(claim="   ", test_plan="test plan")
        assert hyp_id == ""
        assert len(state.hypothesis_queue) == 0

    def test_deduplicates_similar_claims(self, state: AgentState) -> None:
        id1 = state.add_hypothesis("IDOR on /api/user endpoint via user_id", "test plan")
        id2 = state.add_hypothesis("IDOR on /api/user endpoint via user_id param", "test plan")
        # Second should be deduplicated (Jaccard >= 0.80)
        assert id1 == id2
        assert len(state.hypothesis_queue) == 1

    def test_different_claims_both_added(self, state: AgentState) -> None:
        state.add_hypothesis("SQLi on login form", "test sql")
        state.add_hypothesis("XSS on search page", "test xss")
        assert len(state.hypothesis_queue) == 2

    def test_caps_at_max_hypotheses(self, state: AgentState) -> None:
        for i in range(MAX_HYPOTHESES + 5):
            state.add_hypothesis(f"Unique hypothesis number {i} about endpoint {i}", f"plan {i}")
        assert len(state.hypothesis_queue) <= MAX_HYPOTHESES


class TestUpdateHypothesis:
    def test_updates_existing_status(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis("Test SSRF on redirect param", "check Location header")
        updated = state.update_hypothesis(hyp_id, "confirmed", "Got 302 to internal IP")
        assert updated is True
        h = state.hypothesis_queue[0]
        assert h["status"] == "confirmed"
        assert "Got 302 to internal IP" in h["evidence_refs"]

    def test_returns_false_for_unknown_id(self, state: AgentState) -> None:
        result = state.update_hypothesis("h_99_99", "confirmed")
        assert result is False

    def test_evidence_truncated_to_200_chars(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis("XSS via search param", "send <script>")
        long_evidence = "A" * 500
        state.update_hypothesis(hyp_id, "confirmed", long_evidence)
        h = state.hypothesis_queue[0]
        assert len(h["evidence_refs"][0]) <= 200


class TestGetPendingHypotheses:
    def test_returns_only_pending_and_testing(self, state: AgentState) -> None:
        id1 = state.add_hypothesis("SQLi claim pending", "plan 1")
        id2 = state.add_hypothesis("XSS claim pending", "plan 2")
        id3 = state.add_hypothesis("SSRF claim confirmed", "plan 3")
        state.update_hypothesis(id3, "confirmed")

        pending = state.get_pending_hypotheses()
        pending_ids = [h["id"] for h in pending]
        assert id1 in pending_ids
        assert id2 in pending_ids
        assert id3 not in pending_ids

    def test_respects_max_items(self, state: AgentState) -> None:
        for i in range(10):
            state.add_hypothesis(f"Hypothesis about port {i} service", f"plan {i}")
        pending = state.get_pending_hypotheses(max_items=3)
        assert len(pending) == 3

    def test_oldest_first_ordering(self, state: AgentState) -> None:
        state.state = None  # not needed; state already is an AgentState
        state.iteration = 5
        id1 = state.add_hypothesis("First hypothesis at iter 5", "plan")
        state.iteration = 10
        id2 = state.add_hypothesis("Second hypothesis at iter 10", "plan")
        pending = state.get_pending_hypotheses()
        assert pending[0]["id"] == id1
        assert pending[1]["id"] == id2


class TestResolveHypothesesFromEvidence:
    def test_auto_confirms_matching_evidence(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis(
            "SQLi vulnerability in login username field", "inject quotes"
        )
        # Add HIGH severity evidence with overlapping terms
        state.add_evidence(
            phase="EXPLOIT",
            source_tool="sqlmap",
            summary="SQLi vulnerability confirmed in login username field via union injection",
            confidence=0.90,
            severity=4,
        )
        confirmed = state.resolve_hypotheses_from_evidence()
        assert confirmed == 1
        h = next(h for h in state.hypothesis_queue if h["id"] == hyp_id)
        assert h["status"] == "confirmed"

    def test_ignores_low_severity_evidence(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis(
            "SQLi vulnerability in login username field", "inject quotes"
        )
        state.add_evidence(
            phase="EXPLOIT",
            source_tool="manual",
            summary="SQLi vulnerability login username field possibly affected",
            confidence=0.90,
            severity=2,  # LOW — below threshold
        )
        confirmed = state.resolve_hypotheses_from_evidence()
        assert confirmed == 0

    def test_ignores_low_confidence_evidence(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis(
            "SSRF via redirect parameter endpoint", "check Location"
        )
        state.add_evidence(
            phase="RECON",
            source_tool="manual",
            summary="SSRF via redirect parameter endpoint maybe",
            confidence=0.50,  # below 0.75 threshold
            severity=4,
        )
        confirmed = state.resolve_hypotheses_from_evidence()
        assert confirmed == 0

    def test_does_not_reconfirm_already_confirmed(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis("Already confirmed SQLi", "plan")
        state.update_hypothesis(hyp_id, "confirmed")
        state.add_evidence(
            phase="EXPLOIT",
            source_tool="tool",
            summary="Already confirmed SQLi vulnerability in database",
            confidence=0.95,
            severity=5,
        )
        confirmed = state.resolve_hypotheses_from_evidence()
        assert confirmed == 0


class TestBuildHypothesisContext:
    def test_returns_empty_when_no_hypotheses(self, state: AgentState) -> None:
        ctx = state.build_hypothesis_context()
        assert ctx == ""

    def test_contains_pending_hypothesis(self, state: AgentState) -> None:
        state.add_hypothesis(
            "IDOR via user_id parameter", "change id to 2 in request"
        )
        ctx = state.build_hypothesis_context()
        assert "<hypothesis_queue>" in ctx
        assert "IDOR via user_id parameter" in ctx
        assert "change id to 2 in request" in ctx

    def test_contains_confirmed_section(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis("XSS confirmed in search", "plan")
        state.update_hypothesis(hyp_id, "confirmed")
        # Add a new pending hypothesis so context is non-empty
        state.add_hypothesis("IDOR pending in profile", "plan 2")
        ctx = state.build_hypothesis_context()
        assert "<confirmed>" in ctx
        assert "XSS confirmed in search" in ctx

    def test_contains_refuted_section(self, state: AgentState) -> None:
        hyp_id = state.add_hypothesis("SQLi in search bar", "inject quotes")
        state.update_hypothesis(hyp_id, "refuted")
        # Need pending too for context to be non-empty
        state.add_hypothesis("SSRF in redirect param", "send internal IP")
        ctx = state.build_hypothesis_context()
        assert "<refuted_do_not_retry>" in ctx

    def test_contains_instruction(self, state: AgentState) -> None:
        state.add_hypothesis("XSS via comment field", "send <img onerror>")
        ctx = state.build_hypothesis_context()
        assert "record_hypothesis" in ctx
        assert "test_plan" in ctx
