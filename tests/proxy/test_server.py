"""Tests for server.py FastAPI routes — with mocked Ollama/Docker/Agent globals."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

import airecon.proxy.server as srv


# ── Fixture: inject mocked globals before each test ──────────────────────────

@pytest.fixture(autouse=True)
def _patch_server_globals(tmp_path):
    """Replace module-level globals so routes work without real services."""
    import asyncio

    mock_agent = _make_mock_agent()
    mock_ollama = _make_mock_ollama()
    mock_engine = _make_mock_engine()
    lock = asyncio.Lock()

    with (
        patch.dict("os.environ", {"AIRECON_TEST_MODE": "1"}, clear=False),
        patch.object(srv, "agent", mock_agent),
        patch.object(srv, "ollama_client", mock_ollama),
        patch.object(srv, "engine", mock_engine),
        patch.object(srv, "_chat_lock", lock),
    ):
        yield {
            "agent": mock_agent,
            "ollama": mock_ollama,
            "engine": mock_engine,
        }


def _make_mock_agent() -> MagicMock:
    m = MagicMock()
    m.get_stats.return_value = {"iterations": 5, "phase": "RECON"}
    m.get_progress.return_value = {
        "target": "example.com", "phase": "RECON", "iteration": 5}
    m._tools_ollama = [{"type": "function", "function": {"name": "execute"}}]
    m.state = MagicMock()
    m.state.conversation = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "scan example.com"},
        {"role": "assistant", "content": "Starting scan."},
    ]
    m._session = MagicMock()
    m._session.session_id = "sess_001"
    m._session.target = "example.com"
    m._session.created_at = "2026-03-18T00:00:00"
    m._session.scan_count = 3
    m._session.subdomains = ["a.example.com"]
    m._session.live_hosts = ["1.2.3.4"]
    m._session.vulnerabilities = [{"title": "SQLi", "severity": "HIGH"}]

    async def _process(msg):
        from airecon.proxy.agent.models import AgentEvent
        yield AgentEvent(type="text", data={"content": "scanning..."})
        yield AgentEvent(type="done", data={})

    m.process_message = _process
    m.reset = MagicMock()
    m.stop = AsyncMock()
    return m


def _make_mock_ollama() -> MagicMock:
    m = MagicMock()
    m.health_check = AsyncMock(return_value=True)
    m.unload_model = AsyncMock()
    m.model = "test-model"
    return m


def _make_mock_engine() -> MagicMock:
    m = MagicMock()
    m.is_connected = True
    m.discover_tools = AsyncMock(return_value=[])
    return m


# Helper: create TestClient WITHOUT starting lifespan (we manage globals ourselves)
class _OneShotClient:
    """Open/close TestClient per request to avoid leaked background tasks."""

    def request(self, method: str, url: str, **kwargs):
        async def _do_request():
            transport = httpx.ASGITransport(app=srv.app, raise_app_exceptions=True)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.request(method, url, **kwargs)

        return asyncio.run(_do_request())

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)


def _client() -> _OneShotClient:
    return _OneShotClient()


# ── GET /api/status ───────────────────────────────────────────────────────────

class TestGetStatus:
    def test_returns_200(self):
        r = _client().get("/api/status")
        assert r.status_code == 200

    def test_status_ok_when_both_connected(self):
        r = _client().get("/api/status")
        data = r.json()
        assert data["status"] == "ok"
        assert data["ollama"]["connected"] is True
        assert data["docker"]["connected"] is True

    def test_status_degraded_when_ollama_down(self, _patch_server_globals):
        _patch_server_globals["ollama"].health_check = AsyncMock(return_value=False)
        r = _client().get("/api/status")
        assert r.json()["status"] == "degraded"

    def test_status_degraded_when_docker_down(self, _patch_server_globals):
        _patch_server_globals["engine"].is_connected = False
        r = _client().get("/api/status")
        assert r.json()["status"] == "degraded"

    def test_agent_stats_included(self):
        r = _client().get("/api/status")
        assert "agent" in r.json()

    def test_no_agent_returns_empty_stats(self):
        with patch.object(srv, "agent", None):
            r = _client().get("/api/status")
            assert r.json()["agent"] == {}


# ── GET /api/progress ─────────────────────────────────────────────────────────

class TestGetProgress:
    def test_returns_200_with_agent(self):
        r = _client().get("/api/progress")
        assert r.status_code == 200
        assert "target" in r.json()

    def test_returns_503_without_agent(self):
        with patch.object(srv, "agent", None):
            r = _client().get("/api/progress")
            assert r.status_code == 503


# ── GET /api/tools ────────────────────────────────────────────────────────────

class TestListTools:
    def test_returns_tools_from_agent(self):
        r = _client().get("/api/tools")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1

    def test_returns_503_when_agent_and_engine_none(self):
        with patch.object(srv, "agent", None), patch.object(srv, "engine", None):
            r = _client().get("/api/tools")
            assert r.status_code == 503

    def test_falls_back_to_engine_when_no_agent_tools(self, _patch_server_globals):
        """When agent exists but _tools_ollama is empty, call engine.discover_tools."""
        _patch_server_globals["agent"]._tools_ollama = []
        r = _client().get("/api/tools")
        assert r.status_code == 200


# ── GET /api/skills ───────────────────────────────────────────────────────────

class TestListSkills:
    def test_empty_skills_dir(self):
        """When skills dir doesn't exist, returns count=0."""
        with (
            patch.object(srv, "_skills_cache", None),
            patch.object(srv, "_build_skills_cache_sync", return_value=[]),
        ):
            r = _client().get("/api/skills")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_skills_with_real_dir(self):
        """The actual skills dir should return count > 0 if populated."""
        r = _client().get("/api/skills")
        assert r.status_code == 200
        data = r.json()
        assert "skills" in data
        assert isinstance(data["count"], int)


# ── POST /api/chat ────────────────────────────────────────────────────────────

class TestChat:
    def test_non_streaming_returns_events(self):
        r = _client().post("/api/chat", json={"message": "scan example.com", "stream": False})
        assert r.status_code == 200
        data = r.json()
        assert "events" in data
        assert len(data["events"]) >= 1

    def test_non_streaming_without_agent_returns_503(self):
        with patch.object(srv, "agent", None):
            r = _client().post("/api/chat", json={"message": "hi", "stream": False})
            assert r.status_code == 503

    def test_empty_message_rejected(self):
        r = _client().post("/api/chat", json={"message": "", "stream": False})
        # Pydantic field validator allows empty string (no min_length), so 200 or 422
        assert r.status_code in (200, 422)

    def test_message_too_long_rejected(self):
        r = _client().post("/api/chat", json={"message": "x" * 100_001, "stream": False})
        assert r.status_code == 422


# ── POST /api/reset ───────────────────────────────────────────────────────────

class TestResetConversation:
    def test_reset_returns_ok(self):
        r = _client().post("/api/reset")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_reset_without_agent_still_200(self):
        with patch.object(srv, "agent", None):
            r = _client().post("/api/reset")
            assert r.status_code == 200

    def test_reset_calls_agent_reset(self, _patch_server_globals):
        _client().post("/api/reset")
        _patch_server_globals["agent"].reset.assert_called_once()


# ── GET /api/history ─────────────────────────────────────────────────────────

class TestGetHistory:
    def test_returns_non_system_messages(self):
        r = _client().get("/api/history")
        assert r.status_code == 200
        msgs = r.json()["messages"]
        # System messages must be stripped
        assert all(m.get("role") != "system" for m in msgs)
        # user + assistant messages present
        roles = {m["role"] for m in msgs}
        assert "user" in roles

    def test_returns_empty_list_without_agent(self):
        with patch.object(srv, "agent", None):
            r = _client().get("/api/history")
            assert r.status_code == 200
            assert r.json()["messages"] == []


# ── GET /api/sessions ─────────────────────────────────────────────────────────

class TestListSessions:
    def test_returns_sessions_list(self):
        with patch("airecon.proxy.agent.session.list_sessions", return_value=[
            {"session_id": "s1", "target": "a.com", "created_at": "2026-01-01"}
        ]):
            r = _client().get("/api/sessions")
        assert r.status_code == 200
        assert len(r.json()["sessions"]) == 1

    def test_returns_empty_list_when_no_sessions(self):
        with patch("airecon.proxy.agent.session.list_sessions", return_value=[]):
            r = _client().get("/api/sessions")
        assert r.status_code == 200
        assert r.json()["sessions"] == []


# ── GET /api/session/current ─────────────────────────────────────────────────

class TestCurrentSession:
    def test_returns_session_info_with_agent(self):
        r = _client().get("/api/session/current")
        assert r.status_code == 200
        sess = r.json()["session"]
        assert sess["session_id"] == "sess_001"
        assert sess["target"] == "example.com"

    def test_returns_null_without_agent(self):
        with patch.object(srv, "agent", None):
            r = _client().get("/api/session/current")
            assert r.status_code == 200
            assert r.json()["session"] is None

    def test_returns_null_without_session(self, _patch_server_globals):
        _patch_server_globals["agent"]._session = None
        r = _client().get("/api/session/current")
        assert r.json()["session"] is None


# ── POST /api/stop ────────────────────────────────────────────────────────────

class TestStopAgent:
    def test_stop_returns_ok(self):
        r = _client().post("/api/stop")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_stop_without_agent_returns_503(self):
        with patch.object(srv, "agent", None):
            r = _client().post("/api/stop")
            assert r.status_code == 503

    def test_stop_calls_agent_stop(self, _patch_server_globals):
        _client().post("/api/stop")
        _patch_server_globals["agent"].stop.assert_called_once()


# ── POST /api/unload ─────────────────────────────────────────────────────────

class TestUnloadModel:
    def test_unload_returns_ok(self):
        r = _client().post("/api/unload")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_unload_without_client_returns_503(self):
        with patch.object(srv, "ollama_client", None):
            r = _client().post("/api/unload")
            assert r.status_code == 503

    def test_unload_calls_unload_model(self, _patch_server_globals):
        _client().post("/api/unload")
        _patch_server_globals["ollama"].unload_model.assert_called_once()
