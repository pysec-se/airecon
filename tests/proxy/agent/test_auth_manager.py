"""Tests for AuthManager auto-recovery behavior."""

from __future__ import annotations

import httpx
import pytest

from airecon.proxy.agent.auth_manager import AuthManager


class _DummyAuthClient:
    def __init__(self) -> None:
        self.post_data: dict[str, str] | None = None
        self.cookies = httpx.Cookies()

    async def get(self, url: str, **kwargs) -> httpx.Response:
        del kwargs
        return httpx.Response(
            200,
            text='<form><input name="_token" value="freshcsrf"></form>',
            request=httpx.Request("GET", url),
        )

    async def post(self, url: str, **kwargs) -> httpx.Response:
        self.post_data = kwargs.get("data", {})
        return httpx.Response(
            200,
            text="welcome dashboard",
            headers={"set-cookie": "sessionid=abc123; Path=/; HttpOnly"},
            request=httpx.Request("POST", url),
        )

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_auto_reauth_includes_extra_fields_and_rebinds_csrf() -> None:
    manager = AuthManager()
    dummy = _DummyAuthClient()
    manager.client = dummy
    manager.set_credentials("alice", "secret", {"tenant": "acme", "otp": "123456", "_token": "stale"})

    ok = await manager.auto_reauth("https://example.com/login")

    assert ok is True
    assert dummy.post_data is not None
    assert dummy.post_data.get("username") == "alice"
    assert dummy.post_data.get("password") == "secret"
    assert dummy.post_data.get("tenant") == "acme"
    assert dummy.post_data.get("otp") == "123456"
    assert dummy.post_data.get("_token") == "freshcsrf"
    await manager.close()


@pytest.mark.asyncio
async def test_login_page_content_not_treated_as_success() -> None:
    manager = AuthManager()
    response = httpx.Response(
        200,
        text="<html><body>Please sign in</body></html>",
        request=httpx.Request("POST", "https://example.com/login"),
    )
    assert manager._is_login_successful(response) is False
    await manager.close()


@pytest.mark.asyncio
async def test_redirect_to_login_not_treated_as_success() -> None:
    manager = AuthManager()
    response = httpx.Response(
        302,
        text="",
        headers={"location": "/login"},
        request=httpx.Request("POST", "https://example.com/login"),
    )
    assert manager._is_login_successful(response) is False
    await manager.close()
