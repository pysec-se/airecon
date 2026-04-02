import pytest
from unittest.mock import AsyncMock

from airecon.proxy.caido_client import CaidoClient


@pytest.fixture(autouse=True)
def reset_token_and_failure_state():
    """Reset module-level singleton state before each test."""
    CaidoClient._token=None
    CaidoClient._auth_fail_count=0
    CaidoClient._last_auth_fail_warn_ts=0.0
    CaidoClient._last_bootstrap_attempt_ts=0.0


@pytest.mark.asyncio
async def test_get_token_success(mocker):
    mock_client = mocker.MagicMock()
    mock_post = AsyncMock()
    mock_response = mocker.MagicMock()
    mock_response.json.return_value = {
        "data": {"loginAsGuest": {"token": {"accessToken": "test_token_123"}}}
    }
    mock_post.return_value = mock_response
    mock_client.__aenter__.return_value.post = mock_post
    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    token = await CaidoClient._get_token()

    assert token == "test_token_123"
    assert CaidoClient._token == "test_token_123"
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == CaidoClient.BASE_URL
    assert "loginAsGuest" in kwargs["json"]["query"]


@pytest.mark.asyncio
async def test_gql_query_with_variables(mocker):
    CaidoClient._token = "cached_token"

    mock_post = AsyncMock()
    mock_response = mocker.MagicMock()
    mock_response.json.return_value = {"data": {"someQuery": "success"}}
    mock_post.return_value = mock_response

    mock_client = mocker.MagicMock()
    mock_client.__aenter__.return_value.post = mock_post
    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    result = await CaidoClient.gql("query { test }", variables={"var": "val"})

    assert result == {"data": {"someQuery": "success"}}
    args, kwargs = mock_post.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer cached_token"
    assert kwargs["json"]["query"] == "query { test }"
    assert kwargs["json"]["variables"] == {"var": "val"}


@pytest.mark.asyncio
async def test_get_token_failure_logs_warning_with_cooldown(mocker):
    mock_client = mocker.MagicMock()
    mock_post = AsyncMock(side_effect=RuntimeError("connection failed"))
    mock_client.__aenter__.return_value.post = mock_post
    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    mock_warn = mocker.patch("airecon.proxy.caido_client.logger.warning")
    mock_debug = mocker.patch("airecon.proxy.caido_client.logger.debug")

    first = await CaidoClient._get_token()
    second = await CaidoClient._get_token()

    assert first is None
    assert second is None
    assert mock_warn.call_count == 1
    assert mock_debug.call_count >= 1


def test_encode_raw_http():
    raw = "GET / HTTP/1.1\nHost: example.com\n\n"
    encoded = CaidoClient.encode_raw_http(raw)

    import base64

    decoded = base64.b64decode(encoded).decode()
    assert decoded == "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


def test_find_fuzz_offsets():
    raw_clean = "POST /api HTTP/1.1\nHost: example.com\n\nfield="
    raw_with_fuzz = raw_clean + "§FUZZ§"

    offsets = CaidoClient.find_fuzz_offsets(raw_with_fuzz)

    crlf_clean = raw_clean.replace("\n", "\r\n").encode()
    expected_start = len(crlf_clean)

    assert len(offsets) == 1
    assert offsets[0]["start"] == expected_start
    assert offsets[0]["end"] == expected_start

    multi_fuzz = "GET /?a=§FUZZ§&b=§FUZZ§ HTTP/1.1"
    offsets2 = CaidoClient.find_fuzz_offsets(multi_fuzz)
    assert len(offsets2) == 2
    assert offsets2[1]["start"] - offsets2[0]["start"] == 3


@pytest.mark.asyncio
async def test_get_token_bootstrap_path_uses_extracted_token(mocker):
    mocker.patch.object(CaidoClient, "_try_guest_login", side_effect=[None, None])
    mocker.patch.object(CaidoClient, "_find_bootstrap_command", return_value=["caido-setup"])
    mocker.patch(
        "asyncio.to_thread",
        new=AsyncMock(return_value=(0, "✅ Caido\n🔑 Access Token: token_from_bootstrap\n")),
    )

    token = await CaidoClient._get_token(allow_bootstrap=True)

    assert token == "token_from_bootstrap"
    assert CaidoClient._token == "token_from_bootstrap"


@pytest.mark.asyncio
async def test_get_token_without_bootstrap_does_not_run_bootstrap(mocker):
    mocker.patch.object(CaidoClient, "_try_guest_login", return_value=None)
    bootstrap_mock = mocker.patch.object(CaidoClient, "_try_bootstrap", new=AsyncMock())

    token = await CaidoClient._get_token(allow_bootstrap=False)

    assert token is None
    bootstrap_mock.assert_not_awaited()
