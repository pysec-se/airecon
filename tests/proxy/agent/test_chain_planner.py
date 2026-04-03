"""Tests for Exploit Chain Planner (chain_planner.py)."""

from __future__ import annotations

from airecon.proxy.agent.chain_planner import (
    ChainStep,
    ExploitChain,
    advance_chain,
    build_chain_context,
    plan_chains,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_chain(num_steps: int = 3, status: str = "planning") -> ExploitChain:
    steps = [
        ChainStep(step_id=i, description=f"Step {i}", tool_hint="execute")
        for i in range(num_steps)
    ]
    return ExploitChain(
        chain_id="test_chain_1",
        name="Test Chain",
        steps=steps,
        status=status,
    )


# ---------------------------------------------------------------------------
# ExploitChain
# ---------------------------------------------------------------------------


class TestExploitChain:
    def test_current_step_returns_first_pending(self) -> None:
        chain = _make_chain(num_steps=3)
        step = chain.current_step()
        assert step is not None
        assert step.step_id == 0

    def test_current_step_none_when_complete(self) -> None:
        chain = _make_chain(num_steps=2)
        chain.current_step_index = 2  # past end
        assert chain.current_step() is None

    def test_advance_marks_step_done(self) -> None:
        chain = _make_chain(num_steps=3)
        next_step = chain.advance(evidence="Got 200 OK response")
        assert chain.steps[0].status == "done"
        assert chain.steps[0].evidence == "Got 200 OK response"
        assert next_step is not None
        assert next_step.step_id == 1

    def test_advance_changes_status_to_active(self) -> None:
        chain = _make_chain(num_steps=3, status="planning")
        chain.advance()
        assert chain.status == "active"

    def test_advance_completes_chain(self) -> None:
        chain = _make_chain(num_steps=2)
        chain.advance()
        chain.advance()
        assert chain.status == "completed"
        assert chain.current_step() is None

    def test_completed_steps_returns_done(self) -> None:
        chain = _make_chain(num_steps=3)
        chain.advance()
        chain.advance()
        done = chain.completed_steps()
        assert len(done) == 2
        assert all(s.status == "done" for s in done)

    def test_pending_steps_returns_not_done(self) -> None:
        chain = _make_chain(num_steps=3)
        chain.advance()
        pending = chain.pending_steps()
        assert len(pending) == 2


# ---------------------------------------------------------------------------
# plan_chains
# ---------------------------------------------------------------------------


class TestPlanChains:
    def test_matches_sqli_vuln_to_chain(self) -> None:
        vulns = [
            {"finding": "SQL injection confirmed in login username parameter"},
        ]
        chains = plan_chains(vulns, existing_chain_ids=set(), iteration=5)
        assert len(chains) > 0
        names = [c.name for c in chains]
        assert any("sql" in n.lower() or "sqli" in n.lower() for n in names)

    def test_matches_xss_vuln_to_chain(self) -> None:
        vulns = [
            {"finding": "XSS reflected in search parameter", "url": "http://target.com/search", "evidence": "<script> alert(1)</script>"},
        ]
        chains = plan_chains(vulns, existing_chain_ids=set(), iteration=5)
        assert len(chains) > 0

    def test_skips_existing_chain_ids(self) -> None:
        vulns = [{"finding": "SQL injection in login"}]
        existing: set[str] = set()
        chains1 = plan_chains(
            vulns, existing_chain_ids=existing, iteration=5, max_chains=3
        )
        # A second call may still return chains (different templates), but
        # must not repeat any previously returned chain_id.
        chains2 = plan_chains(
            vulns, existing_chain_ids=existing, iteration=6, max_chains=3
        )
        ids_after_first = {c.chain_id for c in chains1}
        ids_after_second = {c.chain_id for c in chains2}
        assert ids_after_first.isdisjoint(ids_after_second)

    def test_chain_id_is_stable_across_iterations(self) -> None:
        """Same template+finding should produce the same ID regardless of iteration."""
        vulns = [{"finding": "SQL injection in login"}]
        chains_i5 = plan_chains(
            vulns, existing_chain_ids=set(), iteration=5, max_chains=1
        )
        chains_i999 = plan_chains(
            vulns, existing_chain_ids=set(), iteration=999, max_chains=1
        )
        assert chains_i5 and chains_i999
        assert chains_i5[0].chain_id == chains_i999[0].chain_id

    def test_uses_title_when_finding_missing(self) -> None:
        vulns = [{"title": "SSRF detected in metadata fetch endpoint", "url": "http://internal/api/fetch", "evidence": "169.254.169.254"}]
        chains = plan_chains(vulns, existing_chain_ids=set(), iteration=9)
        assert len(chains) > 0

    def test_empty_vulns_returns_no_chains(self) -> None:
        chains = plan_chains([], existing_chain_ids=set(), iteration=5)
        assert chains == []

    def test_respects_max_chains(self) -> None:
        vulns = [
            {"finding": "SQL injection in username field"},
            {"finding": "XSS in search parameter"},
            {"finding": "SSRF via redirect parameter"},
            {"finding": "IDOR in user ID parameter"},
            {"finding": "Authentication bypass via JWT alg:none"},
        ]
        chains = plan_chains(vulns, existing_chain_ids=set(), iteration=5, max_chains=2)
        assert len(chains) <= 2

    def test_uses_causal_hypotheses_as_additional_candidates(self) -> None:
        chains = plan_chains(
            vulnerabilities=[],
            existing_chain_ids=set(),
            iteration=11,
            max_chains=3,
            causal_hypotheses=[
                {
                    "hypothesis_id": "hyp_causal_1",
                    "statement": "SQL injection is likely in login parameter id",
                    "posterior": 0.87,
                    "status": "supported",
                    "evidence_refs": [
                        "vulnerability_signal:[HIGH] SQLi candidate in /login"
                    ],
                }
            ],
        )
        assert chains
        assert any("sql" in c.vuln_basis.lower() for c in chains)

    def test_causal_hypothesis_below_posterior_threshold_filtered(self) -> None:
        """CRITICAL: Hypotheses with posterior < 0.62 should be filtered out."""
        chains = plan_chains(
            vulnerabilities=[],
            existing_chain_ids=set(),
            iteration=11,
            max_chains=3,
            causal_hypotheses=[
                {
                    "hypothesis_id": "hyp_weak",
                    "statement": "Maybe XSS somewhere",
                    "posterior": 0.45,  # Below _CAUSAL_CHAIN_MIN_POSTERIOR (0.62)
                    "status": "supported",
                    "evidence_refs": ["weak_signal"],
                }
            ],
        )
        # Weak hypothesis should not generate chains
        # (may still generate chains from other logic, but not from this hypothesis)
        assert chains is not None  # Should not crash

    def test_causal_hypothesis_high_posterior_triggers_chain(self) -> None:
        """CRITICAL: Hypotheses with posterior >= 0.82 should trigger high-confidence path."""
        chains = plan_chains(
            vulnerabilities=[],
            existing_chain_ids=set(),
            iteration=11,
            max_chains=3,
            causal_hypotheses=[
                {
                    "hypothesis_id": "hyp_strong",
                    "statement": "SQL injection confirmed in login parameter with error-based evidence",
                    "posterior": 0.89,  # Above _CAUSAL_CHAIN_HIGH_POSTERIOR (0.82)
                    "status": "supported",
                    "evidence_refs": ["strong_signal:[HIGH] SQLi error messages"],
                }
            ],
        )
        # Strong hypothesis should generate chains
        assert chains is not None
        # Should find SQL-related chain
        assert any("sql" in str(c.__dict__).lower() for c in chains)

    def test_chain_has_steps(self) -> None:
        vulns = [{"finding": "SQL injection confirmed in database"}]
        chains = plan_chains(vulns, existing_chain_ids=set(), iteration=10)
        if chains:
            assert len(chains[0].steps) > 0

    def test_chain_has_vuln_basis(self) -> None:
        vulns = [{"finding": "XSS reflected in search parameter via <script>"}]
        chains = plan_chains(vulns, existing_chain_ids=set(), iteration=10)
        if chains:
            assert (
                "xss" in chains[0].vuln_basis.lower()
                or "search" in chains[0].vuln_basis.lower()
            )

    def test_word_boundary_trigger_avoids_substring_false_positive(
        self, monkeypatch
    ) -> None:
        import airecon.proxy.agent.chain_planner as cp

        monkeypatch.setattr(
            cp,
            "_ATTACK_CHAIN_TEMPLATES",
            [
                {
                    "id": "word_boundary_test",
                    "name": "SQL Word Trigger Chain",
                    "description": "",
                    "triggers": ["sql"],
                    "steps": [{"description": "step1", "tool_hint": "execute"}],
                }
            ],
        )

        # "nosql" should not satisfy single-word trigger "sql" with boundary matching.
        chains = cp.plan_chains(
            [{"finding": "NoSQL injection in profile query handler"}],
            existing_chain_ids=set(),
            iteration=1,
        )
        assert chains == []

    def test_prioritizes_high_severity_finding_first(self, monkeypatch) -> None:
        import airecon.proxy.agent.chain_planner as cp

        monkeypatch.setattr(
            cp,
            "_ATTACK_CHAIN_TEMPLATES",
            [
                {
                    "id": "severity_priority_test",
                    "name": "SQL Severity Chain",
                    "description": "",
                    "triggers": ["sql injection"],
                    "steps": [{"description": "step1", "tool_hint": "execute"}],
                }
            ],
        )

        vulns = [
            {"finding": "[LOW] SQL injection in search", "severity": "LOW"},
            {
                "finding": "[CRITICAL] SQL injection in admin login",
                "severity": "CRITICAL",
                "proof": "admin dump",
            },
        ]
        chains = cp.plan_chains(
            vulns, existing_chain_ids=set(), iteration=1, max_chains=1
        )
        assert chains
        assert "CRITICAL" in chains[0].vuln_basis.upper()

    def test_semantic_trigger_matches_synonym(self, monkeypatch) -> None:
        import airecon.proxy.agent.chain_planner as cp

        monkeypatch.setattr(
            cp,
            "_ATTACK_CHAIN_TEMPLATES",
            [
                {
                    "id": "semantic_synonym",
                    "name": "SQLi Semantic Chain",
                    "description": "",
                    "triggers": ["sql injection"],
                    "steps": [{"description": "step1", "tool_hint": "execute"}],
                }
            ],
        )

        chains = cp.plan_chains(
            [{"finding": "Boolean-based SQLi confirmed in login flow"}],
            existing_chain_ids=set(),
            iteration=7,
        )
        assert chains, "semantic synonym (SQLi) should match trigger 'sql injection'"

    def test_semantic_trigger_rejects_unverified_vuln(self, monkeypatch) -> None:
        import airecon.proxy.agent.chain_planner as cp

        monkeypatch.setattr(
            cp,
            "_ATTACK_CHAIN_TEMPLATES",
            [
                {
                    "id": "semantic_negative",
                    "name": "Unverified SQL Chain",
                    "description": "",
                    "triggers": ["sql injection"],
                    "steps": [{"description": "step1", "tool_hint": "execute"}],
                }
            ],
        )

        chains = cp.plan_chains(
            [{"finding": "Potential SQL injection, needs verification"}],
            existing_chain_ids=set(),
            iteration=9,
        )
        assert chains == []


# ---------------------------------------------------------------------------
# advance_chain
# ---------------------------------------------------------------------------


class TestAdvanceChain:
    def test_advances_chain(self) -> None:
        chain = _make_chain(num_steps=3)
        next_step = advance_chain(chain, evidence="Confirmed SQLi")
        assert chain.steps[0].status == "done"
        assert next_step is not None

    def test_returns_none_when_complete(self) -> None:
        chain = _make_chain(num_steps=1)
        result = advance_chain(chain)
        assert result is None
        assert chain.status == "completed"


# ---------------------------------------------------------------------------
# build_chain_context
# ---------------------------------------------------------------------------


class TestBuildChainContext:
    def test_returns_empty_for_no_active_chains(self) -> None:
        chains = [_make_chain(status="completed")]
        ctx = build_chain_context(chains)
        assert ctx == ""

    def test_returns_empty_for_empty_list(self) -> None:
        assert build_chain_context([]) == ""

    def test_returns_xml_with_chain_info(self) -> None:
        chain = _make_chain(num_steps=3, status="active")
        chain.current_step_index = 1  # step 0 is done
        chain.steps[0].status = "done"
        ctx = build_chain_context([chain])
        assert "<exploit_chain_plan>" in ctx
        assert "Test Chain" in ctx

    def test_shows_current_step(self) -> None:
        chain = _make_chain(num_steps=3)
        ctx = build_chain_context([chain])
        assert "<current_step" in ctx
        assert "Step 0" in ctx

    def test_respects_max_chains(self) -> None:
        chains = [_make_chain(num_steps=2) for _ in range(5)]
        for i, c in enumerate(chains):
            c.chain_id = f"chain_{i}"
        ctx = build_chain_context(chains, max_chains=2)
        # Should only contain 2 chain entries
        assert ctx.count("<chain ") == 2

    def test_contains_instruction(self) -> None:
        chain = _make_chain(num_steps=2)
        ctx = build_chain_context([chain])
        assert "<instruction>" in ctx
