import pytest
import httpx
from unittest.mock import AsyncMock
from airecon.proxy.caido_client import CaidoClient


@pytest.fixture(autouse=True)
def reset_token():
    """Reset the module-level singleton token before each test."""
    CaidoClient._token = None


@pytest.mark.asyncio
async def test_get_token_success(mocker):
    # We must patch the context manager returned by AsyncClient()
    mock_client = mocker.MagicMock()
    # The __aenter__ method returns the client itself, so we mock post on the enter result
    mock_post = AsyncMock()
    mock_response = mocker.MagicMock()
    mock_response.json.return_value = {
        "data": {
            "loginAsGuest": {
                "token": {
                    "accessToken": "test_token_123"
                }
            }
        }
    }
    mock_post.return_value = mock_response
    mock_client.__aenter__.return_value.post = mock_post
    mocker.patch("httpx.AsyncClient", return_value=mock_client)
    
    token = await CaidoClient._get_token()
    
    assert token == "test_token_123"
    assert CaidoClient._token == "test_token_123"
    
    # Verify post was called with correct login query
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == CaidoClient.BASE_URL
    assert "loginAsGuest" in kwargs["json"]["query"]


@pytest.mark.asyncio
async def test_gql_query_with_variables(mocker):
    # Setup token to avoid login call
    CaidoClient._token = "cached_token"
    
    mock_post = AsyncMock()
    mock_response = mocker.MagicMock()
    mock_response.json.return_value = {"data": {"someQuery": "success"}}
    mock_post.return_value = mock_response
    
    mock_client = mocker.MagicMock()
    mock_client.__aenter__.return_value.post = mock_post
    mocker.patch("httpx.AsyncClient", return_value=mock_client)
    
    # Execute query
    result = await CaidoClient.gql("query { test }", variables={"var": "val"})
    
    assert result == {"data": {"someQuery": "success"}}
    
    args, kwargs = mock_post.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer cached_token"
    assert kwargs["json"]["query"] == "query { test }"
    assert kwargs["json"]["variables"] == {"var": "val"}


def test_encode_raw_http():
    raw = "GET / HTTP/1.1\nHost: example.com\n\n"
    encoded = CaidoClient.encode_raw_http(raw)
    
    # The LF should be replaced by CRLF before base64
    import base64
    decoded = base64.b64decode(encoded).decode()
    assert decoded == "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


def test_find_fuzz_offsets():
    raw_clean = "POST /api HTTP/1.1\nHost: example.com\n\nfield="
    raw_with_fuzz = raw_clean + "§FUZZ§"
    
    offsets = CaidoClient.find_fuzz_offsets(raw_with_fuzz)
    
    # Convert clean string to crlf to match internal logic bytes count
    crlf_clean = raw_clean.replace("\n", "\r\n").encode()
    expected_start = len(crlf_clean)
    
    assert len(offsets) == 1
    assert offsets[0]["start"] == expected_start
    assert offsets[0]["end"] == expected_start
    
    # Test multiple fuzz injection points
    multi_fuzz = "GET /?a=§FUZZ§&b=§FUZZ§ HTTP/1.1"
    offsets2 = CaidoClient.find_fuzz_offsets(multi_fuzz)
    assert len(offsets2) == 2
    # The distance between the two should be 3 bytes ("&b=")
    assert offsets2[1]["start"] - offsets2[0]["start"] == 3
