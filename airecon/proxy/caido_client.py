"""Caido HTTP proxy GraphQL client for native tool integration.

Provides authenticated access to Caido's GraphQL API at 127.0.0.1:48080/graphql.
Token is fetched once via loginAsGuest and cached for the process lifetime.
"""
from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

logger = logging.getLogger("airecon.caido")


class CaidoClient:
    """Async GraphQL client for Caido proxy API."""

    BASE_URL = "http://127.0.0.1:48080/graphql"
    _token: str | None = None  # process-level token cache

    @classmethod
    async def _get_token(cls) -> str | None:
        if cls._token:
            return cls._token
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                resp = await c.post(
                    cls.BASE_URL,
                    json={
                        "query": "mutation { loginAsGuest { token { accessToken } } }"},
                    headers={"Content-Type": "application/json"},
                )
                data = resp.json()
                cls._token = data["data"]["loginAsGuest"]["token"]["accessToken"]
                logger.debug("Caido token acquired")
                return cls._token
        except Exception as e:
            logger.warning(f"Caido auth failed (is Caido running?): {e}")
            return None

    @classmethod
    async def gql(
        cls,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a GraphQL query/mutation against Caido."""
        token = await cls._get_token()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        try:
            async with httpx.AsyncClient(timeout=30.0) as c:
                resp = await c.post(cls.BASE_URL, json=payload, headers=headers)
                # Re-authenticate on token expiry and retry once
                if resp.status_code in (401, 403):
                    logger.debug("Caido token rejected (%d) — re-authenticating", resp.status_code)
                    cls._token = None
                    fresh_token = await cls._get_token()
                    if fresh_token:
                        headers["Authorization"] = f"Bearer {fresh_token}"
                    resp = await c.post(cls.BASE_URL, json=payload, headers=headers)
                return resp.json()
        except httpx.TimeoutException as e:
            logger.error(f"Caido GQL request timed out: {e}")
            return {"errors": [{"message": "Caido request timed out after 30s. Is Caido running?"}]}
        except Exception as e:
            logger.error(f"Caido GQL error: {e}")
            return {"errors": [{"message": str(e)}]}

    @classmethod
    def encode_raw_http(cls, raw_http: str) -> str:
        """Encode plain-text raw HTTP request to base64 for Caido API."""
        # Normalize line endings to CRLF as HTTP spec requires
        normalized = raw_http.replace("\r\n", "\n").replace("\n", "\r\n")
        return base64.b64encode(normalized.encode()).decode()

    @classmethod
    def find_fuzz_offsets(cls, raw_http: str) -> list[dict[str, int]]:
        """Find §FUZZ§ marker byte offsets in a raw HTTP request string.

        Returns list of {start, end} dicts for use as Caido Automate placeholders.
        Byte offsets are calculated on the CRLF-normalized CLEAN bytes (markers removed).
        start == end means "insert payload here" (zero-length injection point).
        """
        MARKER = "§FUZZ§"
        normalized = raw_http.replace("\r\n", "\n").replace("\n", "\r\n")
        encoded_bytes = normalized.encode()
        marker_bytes = MARKER.encode()
        marker_len = len(marker_bytes)

        placeholders = []
        removed = 0  # cumulative bytes removed by previous markers
        pos = 0

        while True:
            idx = encoded_bytes.find(marker_bytes, pos)
            if idx == -1:
                break
            # Position in clean bytes = original position minus bytes already
            # removed
            clean_pos = idx - removed
            placeholders.append({"start": clean_pos, "end": clean_pos})
            removed += marker_len
            pos = idx + marker_len

        return placeholders
