"""Unit tests for the five context-injection / evidence helpers added to
loop_cycle_post.py and loop_objectives.py.

These tests cover:
  - _auto_http_context          (HTTP baseline + behavioral diff)
  - _hypothesis_feedback_context (tool result -> pending hypothesis match)
  - _evidence_action_directive   (escalation hint on meaningful evidence bursts)
  - _prune_stale_system_context  (drop old ephemeral system messages)
  - _check_evidence_corroboration (cross-tool tag corroboration)

All tests are deterministic — no network, no subprocess, no Docker.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from airecon.proxy.agent.executors_observe import _ObserveExecutorMixin
from airecon.proxy.agent.loop_cycle_post import _CyclePostMixin
from airecon.proxy.agent.loop_objectives import _ObjectivesMixin
from airecon.proxy.agent.models import AgentState


class _PostAgent(_CyclePostMixin, _ObserveExecutorMixin):
    """Minimal agent that composes the post-cycle mixin with the real HTTP
    parser from the observe mixin — exactly the MRO used at runtime."""

    def __init__(self) -> None:
        self.state = AgentState()


class _ObjAgent(_ObjectivesMixin):
    def __init__(self) -> None:
        self.state = AgentState()
        self._session = SimpleNamespace(vulnerabilities=[])


# ── _auto_http_context ──────────────────────────────────────────────────────


class TestAutoHttpContext:
    def _http_body(
        self, status: int = 200, headers: dict | None = None, body: str = "ok"
    ) -> str:
        headers = headers or {"Content-Type": "text/html"}
        hdr_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        return f"HTTP/1.1 {status}\r\n{hdr_lines}\r\n\r\n{body}"

    def test_returns_empty_on_non_http_tool(self):
        agent = _PostAgent()
        out = agent._auto_http_context(
            "filesystem_read", {}, {"stdout": "data"}, True
        )
        assert out == ""

    def test_returns_empty_on_failed_call(self):
        agent = _PostAgent()
        out = agent._auto_http_context(
            "execute",
            {"command": "curl https://x.com"},
            {"stdout": self._http_body()},
            False,
        )
        assert out == ""

    def test_first_visit_writes_baseline_and_returns_minimal_card(self):
        agent = _PostAgent()
        out = agent._auto_http_context(
            "execute",
            {"command": "curl -i https://api.example.com/users"},
            {"stdout": self._http_body(200, body="hello")},
            True,
        )
        assert "[HTTP BASELINE]" in out
        assert "api.example.com/users" in out
        assert any("api.example.com/users" in k for k in agent.state.http_baselines)

    def test_error_status_returns_full_snapshot(self):
        agent = _PostAgent()
        out = agent._auto_http_context(
            "execute",
            {"command": "curl -i https://api.example.com/secret"},
            {"stdout": self._http_body(500, body="server error")},
            True,
        )
        assert "[HTTP RESPONSE SNAPSHOT]" in out
        assert "Status   : 500" in out

    def test_second_visit_with_change_emits_diff(self):
        agent = _PostAgent()
        args = {"command": "curl -i https://api.example.com/login"}
        # First call — baseline
        agent._auto_http_context(
            "execute", args, {"stdout": self._http_body(200, body="login form")}, True
        )
        # Second call — size changes significantly
        out = agent._auto_http_context(
            "execute",
            args,
            {"stdout": self._http_body(302, body="x" * 2000)},
            True,
        )
        assert "[BEHAVIORAL DIFF vs BASELINE]" in out
        assert "Status: 200 → 302" in out

    def test_second_visit_identical_returns_empty(self):
        agent = _PostAgent()
        args = {"command": "curl -i https://api.example.com/ping"}
        body = self._http_body(200, body="pong-pong-pong-pong-pong")
        agent._auto_http_context("execute", args, {"stdout": body}, True)
        out = agent._auto_http_context("execute", args, {"stdout": body}, True)
        # No diff, not an error — injection must stay silent
        assert out == ""


# ── _hypothesis_feedback_context ────────────────────────────────────────────


class TestHypothesisFeedbackContext:
    def test_empty_when_no_pending_hypothesis(self):
        agent = _PostAgent()
        out = agent._hypothesis_feedback_context(
            "execute", {"command": "curl x"}, "some data"
        )
        assert out == ""

    def test_matches_hypothesis_by_endpoint(self):
        agent = _PostAgent()
        agent.state.iteration = 20
        hyp_id = agent.state.add_hypothesis(
            claim="authentication bypass on api.example.com/login",
            test_plan="probe /login",
            phase="ANALYSIS",
        )
        assert hyp_id

        out = agent._hypothesis_feedback_context(
            "execute",
            {"command": "curl https://api.example.com/login?x=1"},
            "200 OK body...",
        )
        assert "[HYPOTHESIS CHECK —" in out
        assert hyp_id in out
        # Status transitioned pending -> testing
        hyp = next(h for h in agent.state.hypothesis_queue if h["id"] == hyp_id)
        assert hyp["status"] == "testing"

    def test_rate_limit_prevents_back_to_back_injections(self):
        agent = _PostAgent()
        agent.state.iteration = 20
        agent.state.add_hypothesis(
            claim="xss reflection on /search",
            test_plan="try payload",
            phase="ANALYSIS",
        )
        args = {"command": "curl https://x.com/search?q=1"}
        first = agent._hypothesis_feedback_context("execute", args, "search body")
        # Second call within 4 iterations => suppressed
        agent.state.iteration += 1
        second = agent._hypothesis_feedback_context("execute", args, "search body")
        assert first != ""
        assert second == ""


# ── _evidence_action_directive ──────────────────────────────────────────────


class TestEvidenceActionDirective:
    def test_no_directive_when_no_new_evidence(self):
        agent = _PostAgent()
        out = agent._evidence_action_directive("RECON", 0, [])
        assert out == ""

    def test_directive_fires_when_delta_reaches_threshold(self):
        agent = _PostAgent()
        # Seed confidence >= 0.65 so evidence is counted meaningful
        agent.state.evidence_log = [
            {"confidence": 0.8, "summary": "finding a"},
            {"confidence": 0.9, "summary": "finding b"},
        ]
        new_ev = [
            {"summary": "reflected input on /profile", "confidence": 0.8},
            {"summary": "verbose error leaks sql driver", "confidence": 0.9},
        ]
        out = agent._evidence_action_directive("ANALYSIS", 2, new_ev)
        assert "[NEW EVIDENCE — 2 meaningful finding(s)" in out
        assert "reflected input" in out
        # Must ask questions, not prescribe a specific vuln class
        assert "vulnerability signal" in out

    def test_directive_suppressed_for_single_find_off_cycle(self):
        agent = _PostAgent()
        # Total meaningful = 3 (not a multiple of 5), delta < 2 => suppressed
        agent.state.evidence_log = [
            {"confidence": 0.7, "summary": "a"},
            {"confidence": 0.7, "summary": "b"},
            {"confidence": 0.7, "summary": "c"},
        ]
        new_ev = [{"summary": "only one new", "confidence": 0.7}]
        out = agent._evidence_action_directive("ANALYSIS", 1, new_ev)
        assert out == ""


# ── _prune_stale_system_context ─────────────────────────────────────────────


class TestPruneStaleSystemContext:
    def test_no_op_when_iteration_not_multiple_of_10(self):
        agent = _PostAgent()
        agent.state.iteration = 7
        agent.state.conversation = [
            {"role": "system", "content": "[HTTP BASELINE] a"},
            {"role": "system", "content": "[HTTP BASELINE] b"},
            {"role": "system", "content": "[HTTP BASELINE] c"},
        ]
        before = list(agent.state.conversation)
        agent._prune_stale_system_context()
        assert agent.state.conversation == before

    def test_keeps_two_most_recent_of_each_prefix(self):
        agent = _PostAgent()
        agent.state.iteration = 10
        # Five HTTP BASELINE messages — only the 2 newest must survive
        agent.state.conversation = [
            {"role": "system", "content": "[HTTP BASELINE] old-1"},
            {"role": "system", "content": "[HTTP BASELINE] old-2"},
            {"role": "system", "content": "[HTTP BASELINE] old-3"},
            {"role": "system", "content": "[HTTP BASELINE] keep-1"},
            {"role": "system", "content": "[HTTP BASELINE] keep-2"},
            {"role": "user", "content": "keep me"},
        ]
        agent._prune_stale_system_context()

        baselines = [
            m for m in agent.state.conversation if "[HTTP BASELINE]" in m["content"]
        ]
        assert len(baselines) == 2
        assert baselines[0]["content"] == "[HTTP BASELINE] keep-1"
        assert baselines[1]["content"] == "[HTTP BASELINE] keep-2"
        # User message untouched
        assert any(m.get("role") == "user" for m in agent.state.conversation)

    def test_preserves_non_prunable_system_messages(self):
        agent = _PostAgent()
        agent.state.iteration = 10
        agent.state.conversation = [
            {"role": "system", "content": "<waf_context>keep me</waf_context>"},
            {"role": "system", "content": "[HTTP BASELINE] drop-1"},
            {"role": "system", "content": "[HTTP BASELINE] drop-2"},
            {"role": "system", "content": "[HTTP BASELINE] drop-3"},
            {"role": "system", "content": "[HTTP BASELINE] keep-1"},
            {"role": "system", "content": "[HTTP BASELINE] keep-2"},
        ]
        agent._prune_stale_system_context()
        waf_present = any(
            "<waf_context>" in m["content"] for m in agent.state.conversation
        )
        assert waf_present


# ── _check_evidence_corroboration ───────────────────────────────────────────


class TestEvidenceCorroboration:
    def test_no_corroboration_with_single_tool(self):
        agent = _ObjAgent()
        agent.state.evidence_log = [
            {
                "source_tool": "nmap",
                "summary": "port 8080 open",
                "tags": ["admin-panel"],
                "confidence": 0.7,
                "phase": "RECON",
            },
            {
                "source_tool": "nmap",
                "summary": "port 8443 open",
                "tags": ["admin-panel"],
                "confidence": 0.7,
                "phase": "RECON",
            },
        ]
        before = len(agent.state.evidence_log)
        agent._check_evidence_corroboration("RECON", "nmap")
        assert len(agent.state.evidence_log) == before

    def test_corroborates_when_two_tools_share_tag(self):
        agent = _ObjAgent()
        agent.state.evidence_log = [
            {
                "source_tool": "nmap",
                "summary": "port 8080 open",
                "tags": ["admin-panel"],
                "confidence": 0.7,
                "phase": "RECON",
            },
            {
                "source_tool": "httpx",
                "summary": "admin title detected",
                "tags": ["admin-panel"],
                "confidence": 0.7,
                "phase": "RECON",
            },
        ]
        agent._check_evidence_corroboration("RECON", "httpx")
        corroborated = [
            e
            for e in agent.state.evidence_log
            if "CORROBORATED" in str(e.get("summary", ""))
        ]
        assert len(corroborated) == 1
        assert "admin-panel" in corroborated[0]["summary"]
        assert "corroborated" in corroborated[0].get("tags", [])

    def test_generic_tags_are_ignored(self):
        agent = _ObjAgent()
        agent.state.evidence_log = [
            {
                "source_tool": "nmap",
                "summary": "any",
                "tags": ["artifact", "file"],
                "confidence": 0.7,
                "phase": "RECON",
            },
            {
                "source_tool": "httpx",
                "summary": "any",
                "tags": ["artifact", "file"],
                "confidence": 0.7,
                "phase": "RECON",
            },
        ]
        agent._check_evidence_corroboration("RECON", "httpx")
        corroborated = [
            e
            for e in agent.state.evidence_log
            if "CORROBORATED" in str(e.get("summary", ""))
        ]
        assert corroborated == []

    def test_each_tag_corroborated_only_once(self):
        agent = _ObjAgent()
        agent.state.evidence_log = [
            {
                "source_tool": "nmap",
                "summary": "a",
                "tags": ["jwt-signing"],
                "confidence": 0.7,
                "phase": "ANALYSIS",
            },
            {
                "source_tool": "sqlmap",
                "summary": "b",
                "tags": ["jwt-signing"],
                "confidence": 0.7,
                "phase": "ANALYSIS",
            },
        ]
        agent._check_evidence_corroboration("ANALYSIS", "sqlmap")
        # Second call must not double-record the same tag
        agent._check_evidence_corroboration("ANALYSIS", "sqlmap")
        corroborated = [
            e
            for e in agent.state.evidence_log
            if "CORROBORATED" in str(e.get("summary", ""))
        ]
        assert len(corroborated) == 1


# ── MCP hint in system prompt ───────────────────────────────────────────────


class TestMcpServerHint:
    def test_empty_hint_when_no_servers(self, monkeypatch):
        from airecon.proxy import system as sys_mod

        monkeypatch.setattr(sys_mod, "list_mcp_servers", lambda: {}, raising=False)
        # Direct call — attribute may not exist, so patch at the import site
        monkeypatch.setattr(
            "airecon.proxy.mcp.list_mcp_servers", lambda: {}, raising=False
        )
        out = sys_mod._build_mcp_server_hint()
        assert out == ""

    def test_lists_enabled_servers_by_name(self, monkeypatch):
        from airecon.proxy import system as sys_mod

        fake = {
            "hexstrike": {"url": "http://x:9", "enabled": True, "description": "pentest"},
            "gmail": {"command": "node", "enabled": True},
            "disabled_one": {"url": "http://y", "enabled": False},
        }
        monkeypatch.setattr(
            "airecon.proxy.mcp.list_mcp_servers", lambda: fake, raising=False
        )
        out = sys_mod._build_mcp_server_hint()
        assert "<available_mcp_servers>" in out
        assert "mcp_hexstrike" in out
        assert "mcp_gmail" in out
        assert "mcp_disabled_one" not in out
        # Each entry should show transport hint
        assert "stdio" in out and "http/sse" in out


# ── _verify_confirmed_hypotheses ───────────────────────────────────────────


class TestVerifyConfirmedHypotheses:
    def _agent(self) -> _ObjAgent:
        a = _ObjAgent()
        a.state.iteration = 5
        return a

    def _add_confirmed_hyp(self, agent: _ObjAgent, claim: str, tags: list[str]) -> str:
        hid = agent.state.add_hypothesis(
            claim=claim, test_plan="x", phase="ANALYSIS", tags=tags
        )
        agent.state.update_hypothesis(hid, "confirmed", "claim supported by probe")
        return hid

    def test_no_verification_without_supporting_evidence(self):
        agent = self._agent()
        self._add_confirmed_hyp(
            agent, "sql injection on /search param q", ["sqli"]
        )
        new_ids = agent._verify_confirmed_hypotheses()
        assert new_ids == []

    def test_no_verification_with_single_tool_evidence(self):
        agent = self._agent()
        hid = self._add_confirmed_hyp(
            agent, "blind sql injection on /search param q", ["sqli"]
        )
        # Two evidence entries but from the SAME tool
        agent.state.evidence_log = [
            {
                "source_tool": "sqlmap",
                "summary": "search param vulnerable to boolean sqli",
                "tags": ["sqli"],
                "confidence": 0.9,
                "phase": "ANALYSIS",
            },
            {
                "source_tool": "sqlmap",
                "summary": "search param time-based payload succeeded",
                "tags": ["sqli"],
                "confidence": 0.9,
                "phase": "ANALYSIS",
            },
        ]
        new_ids = agent._verify_confirmed_hypotheses()
        assert new_ids == []
        hyp = next(h for h in agent.state.hypothesis_queue if h["id"] == hid)
        assert not hyp.get("verified")

    def test_verification_fires_with_two_independent_tools(self):
        agent = self._agent()
        hid = self._add_confirmed_hyp(
            agent, "stored xss on /comments param body", ["stored-xss"]
        )
        agent.state.evidence_log = [
            {
                "source_tool": "burpsuite",
                "summary": "comments body reflects payload in response",
                "tags": ["stored-xss", "reflection"],
                "confidence": 0.85,
                "phase": "ANALYSIS",
            },
            {
                "source_tool": "xsstrike",
                "summary": "payload executed on comments page",
                "tags": ["stored-xss"],
                "confidence": 0.88,
                "phase": "ANALYSIS",
            },
        ]
        new_ids = agent._verify_confirmed_hypotheses()
        assert hid in new_ids
        hyp = next(h for h in agent.state.hypothesis_queue if h["id"] == hid)
        assert hyp["verified"] is True
        assert set(hyp["verified_by"]) == {"burpsuite", "xsstrike"}

    def test_verification_ignores_low_confidence_evidence(self):
        agent = self._agent()
        hid = self._add_confirmed_hyp(
            agent, "ssrf on import url parameter", ["ssrf"]
        )
        agent.state.evidence_log = [
            {
                "source_tool": "t1",
                "summary": "import url triggered outbound connection",
                "tags": ["ssrf"],
                "confidence": 0.5,  # below 0.65 floor
                "phase": "ANALYSIS",
            },
            {
                "source_tool": "t2",
                "summary": "import url forwarded request header",
                "tags": ["ssrf"],
                "confidence": 0.9,
                "phase": "ANALYSIS",
            },
        ]
        new_ids = agent._verify_confirmed_hypotheses()
        assert new_ids == []

    def test_verification_is_idempotent(self):
        agent = self._agent()
        hid = self._add_confirmed_hyp(
            agent, "idor on /accounts path account_id", ["idor"]
        )
        agent.state.evidence_log = [
            {
                "source_tool": "ffuf",
                "summary": "accounts path enumerates other users",
                "tags": ["idor"],
                "confidence": 0.9,
                "phase": "ANALYSIS",
            },
            {
                "source_tool": "burpsuite",
                "summary": "accounts path returns foreign user data",
                "tags": ["idor"],
                "confidence": 0.9,
                "phase": "ANALYSIS",
            },
        ]
        first = agent._verify_confirmed_hypotheses()
        second = agent._verify_confirmed_hypotheses()
        assert first == [hid]
        assert second == []

    def test_build_verification_note_mentions_claim_and_tools(self):
        agent = self._agent()
        hid = self._add_confirmed_hyp(
            agent, "auth bypass via jwt none alg on /admin", ["jwt", "auth-bypass"]
        )
        # Seed verified_by on the hypothesis directly for the note builder
        hyp = next(h for h in agent.state.hypothesis_queue if h["id"] == hid)
        hyp["verified"] = True
        hyp["verified_by"] = ["jwt-analyzer", "burpsuite"]
        note = agent._build_verification_note([hid])
        assert "[VERIFICATION" in note
        assert hid in note
        assert "jwt-analyzer" in note
        assert "burpsuite" in note
