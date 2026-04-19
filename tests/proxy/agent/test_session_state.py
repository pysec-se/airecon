"""Tests for per-host session state (cookie jar) and rate-limit detection.

Covers the helpers added to ``executors_observe`` and the advisory helper in
``loop_cycle_post`` so we can trust that:
  - Cookies are parsed and attribute-stripped correctly
  - Rate-limit signals are flagged for 429/503/x-ratelimit-remaining
  - ``_execute_http_observe_tool`` injects cookies from the jar and harvests
    Set-Cookie responses back into state
  - ``_build_session_rate_advisory`` surfaces both signals to the LLM

All tests are deterministic — no network, no Docker. The tool engine is
replaced with an ``AsyncMock`` so we drive canned raw HTTP responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from airecon.proxy.agent.executors_observe import (
    _ObserveExecutorMixin,
    _detect_rate_limit,
    _extract_csrf_token,
    _parse_set_cookie_headers,
    _registrable_host,
)
from airecon.proxy.agent.loop_cycle_post import _CyclePostMixin
from airecon.proxy.agent.models import AgentState


# ── Module-level helpers ────────────────────────────────────────────────────


class TestRegistrableHost:
    def test_extracts_hostname(self):
        assert _registrable_host("https://api.example.com/v1/users") == "api.example.com"

    def test_lowercases_and_strips_trailing_dot(self):
        assert _registrable_host("https://API.Example.COM./path") == "api.example.com"

    def test_empty_on_malformed_url(self):
        assert _registrable_host("not-a-url") == ""

    def test_preserves_subdomain(self):
        # Distinct subdomains must not share a cookie jar.
        assert _registrable_host("https://auth.example.com/") != _registrable_host(
            "https://api.example.com/"
        )


class TestParseSetCookieHeaders:
    def test_extracts_single_cookie(self):
        raw = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc123; Path=/; HttpOnly\r\n\r\n"
        cookies = _parse_set_cookie_headers(raw)
        assert cookies == {"sid": "abc123"}

    def test_extracts_multiple_cookies(self):
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: sid=abc; Path=/\r\n"
            "Set-Cookie: csrf=xyz; Secure; SameSite=Strict\r\n"
            "\r\n"
        )
        cookies = _parse_set_cookie_headers(raw)
        assert cookies == {"sid": "abc", "csrf": "xyz"}

    def test_strips_cookie_attributes(self):
        # Attributes like Expires/Max-Age must never be treated as cookie names.
        raw = (
            "Set-Cookie: sessionid=deadbeef; Expires=Wed, 09 Jun 2031 10:18:14 GMT; "
            "Max-Age=3600; Path=/; Domain=.example.com; HttpOnly; Secure; SameSite=Lax"
        )
        cookies = _parse_set_cookie_headers(raw)
        assert cookies == {"sessionid": "deadbeef"}

    def test_empty_input_returns_empty_dict(self):
        assert _parse_set_cookie_headers("") == {}

    def test_ignores_malformed_pairs(self):
        raw = "Set-Cookie: nobody-here\r\nSet-Cookie: sid=ok"
        cookies = _parse_set_cookie_headers(raw)
        assert cookies == {"sid": "ok"}


class TestDetectRateLimit:
    def test_429_flagged(self):
        signal = _detect_rate_limit(429, {})
        assert signal is not None
        assert signal["kind"] == "rate_limited"

    def test_503_with_retry_after_flagged(self):
        signal = _detect_rate_limit(503, {"Retry-After": "30"})
        assert signal is not None
        assert signal["kind"] == "service_unavailable_throttle"
        assert signal["retry_after_seconds"] == 30

    def test_503_without_retry_after_not_flagged(self):
        # Plain 503 could just be a backend outage — don't cry wolf.
        assert _detect_rate_limit(503, {"Content-Type": "text/html"}) is None

    def test_quota_exhausted_via_x_ratelimit_remaining(self):
        signal = _detect_rate_limit(200, {"X-RateLimit-Remaining": "0"})
        assert signal is not None
        assert signal["kind"] == "quota_exhausted"

    def test_200_with_remaining_positive_not_flagged(self):
        assert _detect_rate_limit(200, {"X-RateLimit-Remaining": "42"}) is None

    def test_retry_after_non_numeric_preserved_raw(self):
        signal = _detect_rate_limit(429, {"Retry-After": "Wed, 09 Jun 2031 10:18:14 GMT"})
        assert signal is not None
        assert signal["retry_after_raw"].startswith("Wed,")
        assert "retry_after_seconds" not in signal

    def test_reset_header_captured(self):
        signal = _detect_rate_limit(429, {"X-RateLimit-Reset": "1717000000"})
        assert signal is not None
        assert signal["reset_at"] == "1717000000"

    def test_none_headers_tolerated(self):
        # Make sure the helper is safe to call with None (some code paths do).
        assert _detect_rate_limit(200, None) is None


# ── End-to-end: cookie inject + harvest via _execute_http_observe_tool ──────


class _ObserveAgent(_ObserveExecutorMixin):
    """Minimal agent wiring just enough for the HTTP observe executor."""

    def __init__(self):
        self.state = AgentState()
        self.state.active_target = "example.com"
        self._session = None
        self._last_output_file = None
        self.engine = MagicMock()

    # The real mixin calls this helper on the class for string args.
    def _str_arg(self, arguments, key):
        v = arguments.get(key)
        return str(v).strip() if v is not None else ""


@pytest.fixture
def observe_agent():
    return _ObserveAgent()


@pytest.mark.asyncio
async def test_http_observe_harvests_cookies_into_session_jar(observe_agent):
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: sid=abc123; Path=/; HttpOnly\r\n"
        "Set-Cookie: csrf=token-1; Secure\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html>ok</html>"
    )
    observe_agent.engine.execute_tool = AsyncMock(
        return_value={"success": True, "stdout": raw, "stderr": "", "error": ""}
    )

    success, _, result, _ = await observe_agent._execute_http_observe_tool(
        "http_observe", {"url": "https://api.example.com/login"}
    )
    assert success is True
    assert sorted(result.get("session_cookies_harvested", [])) == ["csrf", "sid"]
    jar = observe_agent.state.http_sessions["api.example.com"]
    assert jar["cookies"] == {"sid": "abc123", "csrf": "token-1"}


@pytest.mark.asyncio
async def test_http_observe_injects_jar_cookies_on_next_call(observe_agent):
    # Seed the jar as if a prior login already ran.
    observe_agent.state.http_sessions["api.example.com"] = {
        "cookies": {"sid": "abc123"},
        "updated_at_iter": 1,
    }
    raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"
    mock_exec = AsyncMock(
        return_value={"success": True, "stdout": raw, "stderr": "", "error": ""}
    )
    observe_agent.engine.execute_tool = mock_exec

    _, _, result, _ = await observe_agent._execute_http_observe_tool(
        "http_observe", {"url": "https://api.example.com/profile"}
    )
    # Cookie injection is reported back to the LLM.
    assert result.get("session_cookies_used") == ["sid"]
    # curl invocation carried the cookie as a -H arg.
    issued_cmd = mock_exec.await_args.args[1]["command"]
    assert "Cookie: sid=abc123" in issued_cmd


@pytest.mark.asyncio
async def test_http_observe_does_not_override_user_cookie_header(observe_agent):
    observe_agent.state.http_sessions["api.example.com"] = {
        "cookies": {"sid": "from-jar"},
    }
    raw = "HTTP/1.1 200 OK\r\n\r\nok"
    mock_exec = AsyncMock(
        return_value={"success": True, "stdout": raw, "stderr": "", "error": ""}
    )
    observe_agent.engine.execute_tool = mock_exec

    _, _, result, _ = await observe_agent._execute_http_observe_tool(
        "http_observe",
        {
            "url": "https://api.example.com/x",
            "headers": {"Cookie": "sid=explicit"},
        },
    )
    # LLM-supplied header wins — no auto-injection.
    assert "session_cookies_used" not in result
    issued_cmd = mock_exec.await_args.args[1]["command"]
    assert "Cookie: sid=explicit" in issued_cmd
    assert "Cookie: sid=from-jar" not in issued_cmd


@pytest.mark.asyncio
async def test_http_observe_scopes_jar_per_host(observe_agent):
    observe_agent.state.http_sessions["api.example.com"] = {"cookies": {"sid": "one"}}
    observe_agent.state.http_sessions["auth.example.com"] = {"cookies": {"sid": "two"}}
    raw = "HTTP/1.1 200 OK\r\n\r\nok"
    mock_exec = AsyncMock(
        return_value={"success": True, "stdout": raw, "stderr": "", "error": ""}
    )
    observe_agent.engine.execute_tool = mock_exec

    await observe_agent._execute_http_observe_tool(
        "http_observe", {"url": "https://auth.example.com/whoami"}
    )
    cmd = mock_exec.await_args.args[1]["command"]
    assert "Cookie: sid=two" in cmd
    assert "Cookie: sid=one" not in cmd


@pytest.mark.asyncio
async def test_http_observe_flags_rate_limit_response(observe_agent):
    raw = (
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Retry-After: 45\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "slow down"
    )
    observe_agent.engine.execute_tool = AsyncMock(
        return_value={"success": True, "stdout": raw, "stderr": "", "error": ""}
    )

    _, _, result, _ = await observe_agent._execute_http_observe_tool(
        "http_observe", {"url": "https://api.example.com/search"}
    )
    rl = result.get("rate_limit")
    assert rl is not None
    assert rl["kind"] == "rate_limited"
    assert rl["retry_after_seconds"] == 45
    jar = observe_agent.state.http_sessions["api.example.com"]
    assert jar.get("rate_limit_signal", {}).get("kind") == "rate_limited"


# ── Advisory builder (LLM-facing text) ──────────────────────────────────────


class _PostAgent(_CyclePostMixin):
    def __init__(self):
        self.state = AgentState()


class TestBuildSessionRateAdvisory:
    def test_empty_when_no_session_or_rate_fields(self):
        agent = _PostAgent()
        out = agent._build_session_rate_advisory(
            "http_observe", {"url": "https://example.com/"}, {"success": True}
        )
        assert out == ""

    def test_session_block_when_cookies_used(self):
        agent = _PostAgent()
        out = agent._build_session_rate_advisory(
            "http_observe",
            {"url": "https://api.example.com/profile"},
            {"session_cookies_used": ["sid"]},
        )
        assert "[SESSION — api.example.com]" in out
        assert "Cookies reused from jar" in out

    def test_session_block_when_cookies_harvested(self):
        agent = _PostAgent()
        out = agent._build_session_rate_advisory(
            "http_observe",
            {"url": "https://api.example.com/login"},
            {"session_cookies_harvested": ["sid", "csrf"]},
        )
        assert "[SESSION" in out
        assert "New cookies captured" in out
        assert "sid" in out and "csrf" in out

    def test_rate_limit_block_includes_retry_after(self):
        agent = _PostAgent()
        out = agent._build_session_rate_advisory(
            "http_observe",
            {"url": "https://api.example.com/search"},
            {"rate_limit": {"kind": "rate_limited", "retry_after_seconds": 60}},
        )
        assert "[RATE LIMIT — api.example.com]" in out
        assert "rate_limited" in out
        assert "60s" in out
        assert "Throttling detected" in out

    def test_both_blocks_when_both_signals_present(self):
        agent = _PostAgent()
        out = agent._build_session_rate_advisory(
            "http_observe",
            {"url": "https://api.example.com/profile"},
            {
                "session_cookies_used": ["sid"],
                "rate_limit": {"kind": "quota_exhausted"},
            },
        )
        assert "[SESSION" in out
        assert "[RATE LIMIT" in out

    def test_non_dict_result_tolerated(self):
        agent = _PostAgent()
        # Should not crash when a tool returns a non-dict payload.
        assert agent._build_session_rate_advisory("exec", {}, "oops") == ""


class TestExtractCsrfToken:
    def test_meta_tag_form(self):
        body = (
            '<html><head>'
            '<meta name="csrf-token" content="abcDEF1234-meta-token">'
            '</head><body>ok</body></html>'
        )
        info = _extract_csrf_token(body, {})
        assert info["token"] == "abcDEF1234-meta-token"
        assert info["source"] == "meta"
        assert info["field"].lower() == "csrf-token"

    def test_hidden_input_form(self):
        body = (
            '<form action="/login" method="post">'
            '<input type="hidden" name="csrfmiddlewaretoken" value="ZZZ123-django-token">'
            '<input type="text" name="user">'
            '</form>'
        )
        info = _extract_csrf_token(body, {})
        assert info["source"] == "form"
        assert info["token"] == "ZZZ123-django-token"
        assert info["field"] == "csrfmiddlewaretoken"

    def test_cookie_wins_over_body_when_both_present(self):
        # Cookies are the most reliable signal so they should take priority.
        body = '<meta name="csrf-token" content="from-meta-tag-value">'
        cookies = {"XSRF-TOKEN": "from-cookie-value-xyz"}
        info = _extract_csrf_token(body, cookies)
        assert info["source"] == "cookie"
        assert info["token"] == "from-cookie-value-xyz"

    def test_returns_empty_when_nothing_matches(self):
        assert _extract_csrf_token("<html><body>hi</body></html>", {}) == {}
        assert _extract_csrf_token("", {"sid": "abc"}) == {}

    def test_ignores_short_tokens(self):
        # A literal 3-char "value" should not be mistaken for a real token.
        body = '<meta name="csrf-token" content="x">'
        assert _extract_csrf_token(body, {}) == {}


@pytest.mark.asyncio
async def test_http_observe_harvests_csrf_from_meta_tag(observe_agent):
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        '<html><head><meta name="csrf-token" content="harvested-token-12345">'
        "</head><body>hello</body></html>"
    )
    observe_agent.engine.execute_tool = AsyncMock(
        return_value={"success": True, "stdout": raw, "stderr": "", "error": ""}
    )
    _, _, result, _ = await observe_agent._execute_http_observe_tool(
        "http_observe", {"url": "https://api.example.com/login"}
    )
    assert result.get("csrf_token", {}).get("source") == "meta"
    jar = observe_agent.state.http_sessions["api.example.com"]
    assert jar["csrf"]["token"] == "harvested-token-12345"
    assert jar["csrf"]["source"] == "meta"


@pytest.mark.asyncio
async def test_http_observe_harvests_csrf_from_cookie(observe_agent):
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: XSRF-TOKEN=cookie-csrf-value-7; Path=/\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html>no body token</html>"
    )
    observe_agent.engine.execute_tool = AsyncMock(
        return_value={"success": True, "stdout": raw, "stderr": "", "error": ""}
    )
    _, _, result, _ = await observe_agent._execute_http_observe_tool(
        "http_observe", {"url": "https://api.example.com/"}
    )
    assert result.get("csrf_token", {}).get("source") == "cookie"
    jar = observe_agent.state.http_sessions["api.example.com"]
    assert jar["csrf"]["source"] == "cookie"
    assert jar["csrf"]["token"] == "cookie-csrf-value-7"


class TestCsrfAdvisory:
    def test_session_advisory_mentions_csrf(self):
        agent = _PostAgent()
        out = agent._build_session_rate_advisory(
            "http_observe",
            {"url": "https://api.example.com/login"},
            {
                "csrf_token": {"field": "csrf-token", "source": "meta"},
                "session_cookies_harvested": ["sid"],
            },
        )
        assert "[SESSION" in out
        assert "CSRF token captured" in out
        assert "meta" in out
        assert "re-inject" in out.lower() or "re-inject" in out


class TestPrunablePrefixesRegistered:
    def test_session_and_rate_limit_prefixes_prunable(self):
        # Explicit check so pruning doesn't silently stop working if a future
        # refactor drops these from the tuple.
        assert any(p.startswith("[SESSION") for p in _CyclePostMixin._PRUNABLE_PREFIXES)
        assert any(
            p.startswith("[RATE LIMIT") for p in _CyclePostMixin._PRUNABLE_PREFIXES
        )
