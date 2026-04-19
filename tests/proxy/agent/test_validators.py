import pytest
from types import SimpleNamespace
import json
from pathlib import Path

from airecon.proxy.agent.validators import (
    _ValidatorMixin,
    _extract_scope_candidates_from_text,
)


class DummyTestAgent(_ValidatorMixin):
    pass


@pytest.fixture
def validator():
    return DummyTestAgent()


def test_validator_execute(validator):
    # Empty commands block
    valid, msg = validator._validate_tool_args("execute", {"command": ""})
    assert not valid

    # Overly long commands block
    long_cmd = "a" * 25000
    valid, msg = validator._validate_tool_args("execute", {"command": long_cmd})
    assert not valid

    # Good command
    valid, msg = validator._validate_tool_args("execute", {"command": "ls -la"})
    assert valid


def test_validator_browser_actions(validator):
    # Invalid Action
    valid, msg = validator._validate_tool_args("browser_action", {"action": "fly"})
    assert not valid

    # Missing kwargs on navigation
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "goto", "url": ""}
    )
    assert not valid

    # Valid navigation
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "goto", "url": "http://1.com"}
    )
    assert valid


def test_browser_actions_match_tool_schema():
    from airecon.proxy.agent import constants as constants_mod

    tools_path = Path(constants_mod.__file__).resolve().parents[1] / "data" / "tools.json"
    raw = json.loads(tools_path.read_text(encoding="utf-8"))
    browser_entry = next(
        item
        for item in raw
        if item.get("function", {}).get("name") == "browser_action"
    )
    expected = set(
        browser_entry["function"]["parameters"]["properties"]["action"]["enum"]
    )

    assert set(constants_mod.VALID_BROWSER_ACTIONS) == expected


def test_validator_browser_action_nonstring_args(validator):
    """Non-string LLM args must not crash with AttributeError/TypeError."""
    # action=dict would cause TypeError: unhashable type before fix
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": {"evil": "dict"}}
    )
    assert not valid
    assert msg is not None

    # action=int same issue
    valid, msg = validator._validate_tool_args("browser_action", {"action": 42})
    assert not valid

    # url=dict would cause AttributeError on .strip() before fix
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "goto", "url": {"evil": "dict"}}
    )
    assert not valid

    # text=dict for "type" action — was only checking is None, not isinstance
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "type", "text": {"evil": "dict"}}
    )
    assert not valid

    # text=None still rejected
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "type", "text": None}
    )
    assert not valid

    # text="" (empty string) — valid (clearing a field)
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "type", "text": ""}
    )
    assert valid


def test_validator_browser_action_execute_js_parallel_contract(validator):
    valid, msg = validator._validate_tool_args(
        "browser_action",
        {"action": "execute_js", "js_code": "return 1", "parallel": True},
    )
    assert valid, msg

    valid, msg = validator._validate_tool_args(
        "browser_action",
        {"action": "execute_js", "js_code": "return 1", "parallel": "yes"},
    )
    assert not valid
    assert msg is not None and "must be boolean" in msg

    valid, msg = validator._validate_tool_args(
        "browser_action",
        {
            "action": "execute_js",
            "js_code": "return 1",
            "parallel": True,
            "tab_id": "tab_1",
        },
    )
    assert not valid
    assert msg is not None and "must not set 'tab_id'" in msg


def test_validator_read_file(validator):
    # Negative Offset
    valid, msg = validator._validate_tool_args(
        "read_file", {"path": "test.txt", "offset": -5}
    )
    assert not valid

    # Good constraints
    valid, msg = validator._validate_tool_args(
        "read_file", {"path": "test.txt", "offset": 10, "limit": 100}
    )
    assert valid


def test_validator_report_nonstring_args(validator):
    """Non-string args to create_vulnerability_report must not crash."""
    # poc_script_code=dict would AttributeError on .strip() before fix
    valid, msg = validator._validate_tool_args(
        "create_vulnerability_report",
        {
            "poc_script_code": {"evil": "dict"},
            "poc_description": "desc",
            "title": "title",
            "technical_analysis": "tech",
        },
    )
    assert not valid
    assert msg is not None

    # title=int
    valid, msg = validator._validate_tool_args(
        "create_vulnerability_report",
        {
            "poc_script_code": "curl http://x",
            "poc_description": "desc",
            "title": 42,
            "technical_analysis": "tech",
        },
    )
    assert not valid


def test_validator_report_rejections(validator):
    # Missing POC indicators
    args = {
        "title": "A Very Detailed Bug Triggered",
        "poc_script_code": "I found it by clicking.",
        "poc_description": "We clicked hard and it crashed" + (" " * 80),
        "technical_analysis": "The system died completely" + (" " * 80),
    }

    valid, msg = validator._validate_tool_args(
        "create_vulnerability_report", args.copy()
    )
    assert not valid
    # Rejected either for being too short OR for not looking like real exploit code.
    assert "too short" in msg or "does not look like code" in msg

    # Needs HTTP Evidence on non-CTF
    args_http = args.copy()
    args_http["poc_script_code"] = "curl -X GET http://example.com/api/test" + (
        "." * 50
    )
    args_http["poc_description"] = "We clicked hard and it crashed" + ("." * 80)
    args_http["technical_analysis"] = "The system died completely" + ("." * 80)
    valid, msg = validator._validate_tool_args("create_vulnerability_report", args_http)
    assert not valid
    assert "HTTP response evidence" in msg

    # Needs to be a real URL (If HTTP Evidence is provided)
    args_url = args.copy()
    args_url["poc_description"] = "We sent the payload and observed HTTP 200" + (
        "." * 80
    )
    args_url["poc_script_code"] = "python3 exploit.py" + (
        "." * 50
    )  # No HTTP or curl present
    args_url["technical_analysis"] = "The system died completely" + ("." * 80)
    valid, msg = validator._validate_tool_args("create_vulnerability_report", args_url)
    assert not valid
    assert "actual target URL" in msg

    # Valid
    args_valid = args.copy()
    args_valid["poc_script_code"] = "curl -X GET http://example.com/api/test" + (
        "." * 50
    )
    args_valid["poc_description"] = (
        "We sent the payload and observed HTTP 200 containing user data." + ("." * 80)
    )
    args_valid["technical_analysis"] = "The system died completely" + ("." * 80)
    # The regex explicitly wants the word `python`, `curl` or `http` in the POC code,
    # and a formatted status code in the description.
    valid, msg = validator._validate_tool_args(
        "create_vulnerability_report", args_valid
    )
    if not valid:
        print(f"FAILED REASON: {msg}")
    assert valid


def test_validator_create_file(validator):
    # Markdown paths are no longer blocked by heuristic report-name filters.
    args = {"path": "vuln_report.md", "content": "# Finding"}
    valid, msg = validator._validate_tool_args("create_file", args)
    assert valid

    # Writing normal tools is fine
    args = {"path": "script.py", "content": "print('hello')"}
    valid, msg = validator._validate_tool_args("create_file", args)
    assert valid


def test_scope_candidate_extraction_ignores_embedded_query_host_values():
    candidates = _extract_scope_candidates_from_text(
        "https://example.com/test/?url=evil.com"
    )
    assert "http://example.com" in candidates
    assert "http://evil.com" not in candidates

    candidates = _extract_scope_candidates_from_text("example.com/test/?url=evil.com")
    assert "http://example.com" in candidates
    assert "http://evil.com" not in candidates


def test_scope_candidate_extraction_prefers_host_header_over_query_host_values():
    candidates = _extract_scope_candidates_from_text(
        "GET /test/?url=evil.com HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    assert "http://example.com" in candidates
    assert "http://evil.com" not in candidates


def test_scope_guard_allows_embedded_outbound_host_value_on_in_scope_url(validator):
    validator._scope_lock_active = True
    validator._scope_anchor_target = "example.com"

    valid, msg = validator._validate_tool_args(
        "browser_action",
        {"action": "goto", "url": "https://example.com/test/?url=evil.com"},
    )

    assert valid, msg

    valid, msg = validator._validate_tool_args(
        "execute",
        {"command": "curl 'https://example.com/test/?url=evil.com'"},
    )

    assert valid, msg


def test_scope_guard_still_blocks_true_out_of_scope_destination(validator):
    validator._scope_lock_active = True
    validator._scope_anchor_target = "example.com"

    valid, msg = validator._validate_tool_args(
        "browser_action",
        {"action": "goto", "url": "https://evil.com/test/?next=example.com"},
    )

    assert not valid
    assert msg is not None and "OUT-OF-SCOPE" in msg


def test_replay_score_uses_session_waf_profile_to_avoid_false_penalty(validator):
    """Direct session.waf_profiles evidence should prevent WAF false-positive penalty."""
    validator.state = SimpleNamespace(
        active_target="example.com",
        tool_history=[
            SimpleNamespace(
                tool_name="execute",
                arguments={"command": "curl -i http://example.com/login"},
                result={"stdout": "HTTP/1.1 403 Forbidden blocked by security edge"},
            )
        ],
        evidence_log=[],
    )
    validator._session = SimpleNamespace(
        waf_profiles={"example.com": {"name": "Cloudflare", "confidence": 0.92}}
    )

    score, gaps, has_runtime, _runtime_bound = validator._replay_verification_score(
        poc_code="curl -i http://example.com/login",
        poc_desc="Sent payload and observed HTTP 403 forbidden from edge block.",
        report_finding="Potential auth bypass on login endpoint",
        matching_finding=True,
    )

    assert has_runtime is True
    assert score > 0.0
    assert not any("WAF block detected without bypass evidence" in g for g in gaps)


def test_replay_score_applies_waf_penalty_without_session_profile(validator):
    """Without session WAF profile, pure block signal should trigger penalty gap."""
    validator.state = SimpleNamespace(
        active_target="example.com",
        tool_history=[
            SimpleNamespace(
                tool_name="execute",
                arguments={"command": "curl -i http://example.com/login"},
                result={
                    "stdout": "HTTP/1.1 403 Forbidden access denied blocked by firewall"
                },
            )
        ],
        evidence_log=[],
    )
    validator._session = SimpleNamespace(waf_profiles={})

    _score, gaps, has_runtime, _runtime_bound = validator._replay_verification_score(
        poc_code="curl -i http://example.com/login",
        poc_desc="Sent payload and observed HTTP 403 forbidden from firewall block.",
        report_finding="Potential auth bypass on login endpoint",
        matching_finding=True,
    )

    assert has_runtime is True
    assert any("WAF block detected without bypass evidence" in g for g in gaps)


def test_report_validator_requires_runtime_replay_in_strict_non_ctf_phase(validator):
    validator._get_current_phase = lambda: type("P", (), {"value": "EXPLOIT"})()  # type: ignore[attr-defined]

    valid, msg = validator._validate_tool_args(
        "create_vulnerability_report",
        {
            "title": "SQL Injection in Search Endpoint Parameter",
            "description": "Confirmed SQL injection in search parameter with observable database error output.",
            "target": "http://target.local",
            "poc_script_code": (
                "#!/bin/bash\n"
                'curl "http://target.local/search?q=1\' OR 1=1 --" -i 2>&1 | head -50'
            ),
            "poc_description": (
                "Sent crafted payload to /search and observed HTTP 200 response containing SQL syntax error "
                "and leaked user rows in response body."
            ),
            "technical_analysis": (
                "The backend concatenates unsanitized query input into SQL statements, allowing attacker-controlled "
                "predicates and unauthorized data extraction."
            ),
        },
    )

    assert not valid
    assert msg is not None and "Runtime replay evidence is mandatory" in msg


def test_replay_threshold_is_severity_aware(validator):
    critical = validator._resolve_replay_threshold(
        is_strict_phase=True,
        has_runtime_context=True,
        severity="CRITICAL",
    )
    high = validator._resolve_replay_threshold(
        is_strict_phase=True,
        has_runtime_context=True,
        severity="HIGH",
    )
    medium = validator._resolve_replay_threshold(
        is_strict_phase=True,
        has_runtime_context=True,
        severity="MEDIUM",
    )
    low = validator._resolve_replay_threshold(
        is_strict_phase=True,
        has_runtime_context=True,
        severity="LOW",
    )

    assert critical > high > medium > low


# ---------------------------------------------------------------------------
# _is_target_in_scope (scope guard for quick_fuzz / deep_fuzz)
# ---------------------------------------------------------------------------


class DummyScopeAgent:
    """Minimal executor shim that satisfies _is_target_in_scope's attribute reads."""

    from airecon.proxy.agent.executors import _ExecutorMixin

    _is_target_in_scope = _ExecutorMixin._is_target_in_scope

    def __init__(self, session_target: str = "example.com"):
        from types import SimpleNamespace

        self._session = SimpleNamespace(target=session_target)


class TestIsTargetInScope:
    def test_exact_match_is_in_scope(self):
        agent = DummyScopeAgent("example.com")
        assert agent._is_target_in_scope("https://example.com/path") is True

    def test_subdomain_is_in_scope(self):
        agent = DummyScopeAgent("example.com")
        assert agent._is_target_in_scope("https://api.example.com/endpoint") is True

    def test_third_party_domain_out_of_scope(self):
        agent = DummyScopeAgent("example.com")
        assert agent._is_target_in_scope("https://fonts.googleapis.com/css") is False

    def test_similar_but_different_domain_out_of_scope(self):
        agent = DummyScopeAgent("example.com")
        assert agent._is_target_in_scope("https://notexample.com/page") is False

    def test_no_session_target_is_permissive(self):
        agent = DummyScopeAgent("")
        assert agent._is_target_in_scope("https://anywhere.com/") is True

    def test_empty_target_url_is_permissive(self):
        agent = DummyScopeAgent("example.com")
        assert agent._is_target_in_scope("") is True

    def test_session_target_with_scheme_parsed_correctly(self):
        agent = DummyScopeAgent("https://example.com/")
        assert agent._is_target_in_scope("https://sub.example.com/api") is True
        assert agent._is_target_in_scope("https://other.com/api") is False


class TestSoftScopeAdvisory:
    """Soft scope guard — when scope_lock is NOT active, out-of-declared-scope
    URLs must pass validation (True) and enqueue an advisory for the LLM to
    reason about, instead of hard-blocking.
    """

    def _agent(self, active_target: str = "example.com"):
        v = DummyTestAgent()
        v._scope_lock_active = False
        v._scope_anchor_target = active_target
        return v

    def test_soft_scope_allows_s3_bucket_with_target_label(self):
        v = self._agent()
        valid, msg = v._validate_tool_args(
            "execute",
            {"command": "curl -s https://example-assets.s3.amazonaws.com/config.json"},
        )
        assert valid is True
        assert msg is None
        advisories = getattr(v, "_pending_scope_advisories", [])
        assert len(advisories) == 1
        assert "s3.amazonaws.com" in advisories[0]["url"]
        assert advisories[0]["declared_scope"] == "example.com"

    def test_soft_scope_allows_cdn_subdomain(self):
        v = self._agent()
        valid, msg = v._validate_tool_args(
            "browser_action",
            {"action": "goto", "url": "https://example.cloudfront.net/app.js"},
        )
        assert valid is True
        assert msg is None
        advisories = getattr(v, "_pending_scope_advisories", [])
        assert len(advisories) == 1
        assert "cloudfront.net" in advisories[0]["url"]

    def test_soft_scope_allows_third_party_api_validation(self):
        """When LLM finds a leaked API key it may want to validate it against
        the issuer (e.g. Stripe, GitHub). That pivot is legitimate under a
        soft scope — the advisory surfaces for the LLM to justify.
        """
        v = self._agent()
        valid, msg = v._validate_tool_args(
            "execute",
            {"command": "curl -s https://api.stripe.com/v1/charges -u sk_test_xxx:"},
        )
        assert valid is True
        assert msg is None
        advisories = getattr(v, "_pending_scope_advisories", [])
        assert any("stripe.com" in a["url"] for a in advisories)

    def test_hard_lock_still_blocks_oos(self):
        v = self._agent()
        v._scope_lock_active = True
        valid, msg = v._validate_tool_args(
            "browser_action",
            {"action": "goto", "url": "https://unrelated.example.io/x"},
        )
        assert valid is False
        assert msg is not None and "OUT-OF-SCOPE" in msg

    def test_in_scope_urls_never_queue_advisory(self):
        v = self._agent()
        valid, _ = v._validate_tool_args(
            "browser_action",
            {"action": "goto", "url": "https://api.example.com/v1/users"},
        )
        assert valid is True
        advisories = getattr(v, "_pending_scope_advisories", [])
        assert advisories == []


class TestDrainScopeAdvisories:
    def _agent(self):
        from airecon.proxy.agent.loop_cycle_post import _CyclePostMixin
        from airecon.proxy.agent.models import AgentState

        class _A(_CyclePostMixin):
            def __init__(self):
                self.state = AgentState()

        return _A()

    def test_drain_empty_returns_empty_string(self):
        a = self._agent()
        assert a._drain_scope_advisories() == ""

    def test_drain_produces_scope_advisory_block(self):
        a = self._agent()
        a._pending_scope_advisories = [
            {
                "url": "http://example-bucket.s3.amazonaws.com",
                "declared_scope": "example.com",
                "tool": "execute",
            },
            {
                "url": "http://api.stripe.com/v1/charges",
                "declared_scope": "example.com",
                "tool": "execute",
            },
        ]
        out = a._drain_scope_advisories()
        assert "[SCOPE ADVISORY]" in out
        assert "example-bucket.s3.amazonaws.com" in out
        assert "api.stripe.com" in out
        assert "example.com" in out
        # Drained — second call returns empty
        assert a._drain_scope_advisories() == ""

    def test_drain_deduplicates_urls(self):
        a = self._agent()
        a._pending_scope_advisories = [
            {"url": "http://x.com/a", "declared_scope": "example.com", "tool": "x"},
            {"url": "http://x.com/a", "declared_scope": "example.com", "tool": "x"},
        ]
        out = a._drain_scope_advisories()
        assert out.count("http://x.com/a") == 1
