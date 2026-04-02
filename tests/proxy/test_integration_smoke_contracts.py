"""Lightweight integration smoke/contract tests for server, browser, and Ollama."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import airecon.proxy.server as srv
from airecon.proxy.browser import browser_action
from airecon.proxy.ollama import OllamaClient


@pytest.mark.asyncio
async def test_server_status_smoke_contract() -> None:
    mock_agent = MagicMock()
    mock_agent.get_stats.return_value = {"phase": "RECON"}
    mock_ollama = MagicMock()
    mock_ollama.health_check = AsyncMock(return_value=True)
    mock_engine = MagicMock()
    mock_engine.is_connected = True

    with (
        patch.object(srv, "agent", mock_agent),
        patch.object(srv, "ollama_client", mock_ollama),
        patch.object(srv, "engine", mock_engine),
    ):
        transport = httpx.ASGITransport(app=srv.app, raise_app_exceptions=True)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.get("/api/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["ollama"]["connected"] is True
    assert payload["docker"]["connected"] is True
    assert payload["agent"]["phase"] == "RECON"


@pytest.mark.asyncio
async def test_server_skills_contract_uses_cache_fallback() -> None:
    fake_skills = [{"name": "[tools] Demo", "description": "demo", "category": "tools"}]
    with (
        patch.dict("os.environ", {"AIRECON_TEST_MODE": "1"}, clear=False),
        patch.object(srv, "_skills_cache", None),
        patch.object(srv, "_build_skills_cache_sync", return_value=fake_skills),
    ):
        transport = httpx.ASGITransport(app=srv.app, raise_app_exceptions=True)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.get("/api/skills")

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["skills"][0]["category"] == "tools"


def test_browser_execute_js_parallel_smoke_contract(mocker) -> None:
    execute_js = mocker.patch(
        "airecon.proxy.browser._manager.execute_js",
        return_value={"ok": True},
    )
    result = browser_action(action="execute_js", js_code="return 1", parallel=True)
    execute_js.assert_called_once_with("return 1", None, parallel=True)
    assert result["ok"] is True


@pytest.mark.asyncio
async def test_ollama_complete_contract_accepts_dict_message_content() -> None:
    client = OllamaClient.__new__(OllamaClient)
    client.model = "test-model"
    client._client = SimpleNamespace(
        chat=AsyncMock(return_value={"message": {"content": "ok"}})
    )
    client._get_request_gate = AsyncMock(return_value=asyncio.Semaphore(1))

    with patch(
        "airecon.proxy.ollama.get_config",
        return_value=SimpleNamespace(ollama_keep_alive="5m"),
    ):
        result = await client.complete(
            messages=[{"role": "user", "content": "ping"}], max_retries=0
        )

    assert result == "ok"


@pytest.mark.asyncio
async def test_ollama_complete_contract_rejects_invalid_response_format() -> None:
    client = OllamaClient.__new__(OllamaClient)
    client.model = "test-model"
    client._client = SimpleNamespace(
        chat=AsyncMock(return_value={"unexpected": "shape"})
    )
    client._get_request_gate = AsyncMock(return_value=asyncio.Semaphore(1))

    with patch(
        "airecon.proxy.ollama.get_config",
        return_value=SimpleNamespace(ollama_keep_alive="5m"),
    ):
        with pytest.raises(RuntimeError, match="Invalid Ollama response format"):
            await client.complete(
                messages=[{"role": "user", "content": "ping"}], max_retries=0
            )
