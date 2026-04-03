from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("airecon.caido")


class CaidoClient:
    BASE_URL = "http://127.0.0.1:48080/graphql"
    _token: str | None = None

    # Avoid warning spam when /api/status polls frequently while Caido is down.
    _auth_fail_warn_interval_sec=60.0
    _last_auth_fail_warn_ts=0.0
    _auth_fail_count=0

    _bootstrap_cooldown_sec=120.0
    _last_bootstrap_attempt_ts=0.0

    @classmethod
    def _warn_auth_failure(cls, err: Exception) -> None:
        cls._auth_fail_count += 1
        now = time.monotonic()
        should_warn = (
            cls._last_auth_fail_warn_ts == 0.0
            or (now - cls._last_auth_fail_warn_ts) >= cls._auth_fail_warn_interval_sec
        )
        if should_warn:
            logger.warning(
                "Caido auth failed (is Caido running?): %s [failures=%d, cooldown=%.0fs]",
                err,
                cls._auth_fail_count,
                cls._auth_fail_warn_interval_sec,
            )
            cls._last_auth_fail_warn_ts = now
        else:
            logger.debug("Caido auth still unavailable: %s", err)

    @classmethod
    def _mark_auth_success(cls) -> None:
        if cls._auth_fail_count:
            logger.info("Caido auth recovered after %d failures", cls._auth_fail_count)
        cls._auth_fail_count=0
        cls._last_auth_fail_warn_ts=0.0

    @classmethod
    async def _try_guest_login(cls) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                resp = await c.post(
                    cls.BASE_URL,
                    json={
                        "query": "mutation { loginAsGuest { token { accessToken } } }"
                    },
                    headers={"Content-Type": "application/json"},
                )
                data = resp.json()
                token = (
                    data.get("data", {})
                    .get("loginAsGuest", {})
                    .get("token", {})
                    .get("accessToken")
                )
                if isinstance(token, str) and token:
                    return token
                raise RuntimeError("loginAsGuest returned empty accessToken")
        except Exception as e:
            cls._warn_auth_failure(e)
            return None

    @classmethod
    def _find_bootstrap_command(cls) -> list[str] | None:
        path_cmd = shutil.which("caido-setup")
        if path_cmd:
            return [path_cmd]

        repo_cmd = Path(__file__).resolve().parent.parent / "containers" / "caido-setup"
        if repo_cmd.exists() and os.access(repo_cmd, os.X_OK):
            return [str(repo_cmd)]
        if repo_cmd.exists():
            return ["bash", str(repo_cmd)]

        return None

    @classmethod
    def _extract_token_from_bootstrap_output(cls, text: str) -> str | None:
        m = re.search(r"Access Token:\s*([^\s\n]+)", text)
        if not m:
            return None
        token = m.group(1).strip()
        return token if token and token.lower() != "null" else None

    @classmethod
    def extract_and_set_token_from_execute_output(cls, output: str) -> bool:
        token = cls._extract_token_from_bootstrap_output(output)
        if token:
            cls._token = token
            logger.info("Extracted token from execute/caido-setup output")
            return True
        return False

    @classmethod
    async def _try_bootstrap(cls) -> None:
        now = time.monotonic()
        # Enforce cooldown only after at least one real bootstrap attempt timestamp exists.
        # This avoids false skips when monotonic clocks are patched or start near zero in tests.
        if (
            cls._last_bootstrap_attempt_ts > 0.0
            and (now - cls._last_bootstrap_attempt_ts) < cls._bootstrap_cooldown_sec
        ):
            return
        cls._last_bootstrap_attempt_ts = now

        cmd = cls._find_bootstrap_command()
        if not cmd:
            logger.debug("Caido bootstrap command not found on host (caido-setup)")
            return

        logger.info("Attempting Caido bootstrap via host command: %s", " ".join(cmd))

        def _run() -> tuple[int, str]:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            out = (proc.stdout or "") + "\n" + (proc.stderr or "")
            return proc.returncode, out

        try:
            code, output = await asyncio.to_thread(_run)
        except Exception as e:
            logger.warning("Caido bootstrap command failed to execute: %s", e)
            return

        token = cls._extract_token_from_bootstrap_output(output)
        if token:
            cls._token = token
            logger.info("Caido bootstrap produced access token")
            return

        if code != 0:
            logger.warning(
                "Caido bootstrap exited with code=%d (no token extracted). Tail: %s",
                code,
                output[-300:],
            )
        else:
            logger.warning("Caido bootstrap completed but no Access Token found in output")

    @classmethod
    async def _get_token(cls, allow_bootstrap: bool = False) -> str | None:
        if cls._token:
            return cls._token

        token = await cls._try_guest_login()
        if token:
            cls._token = token
            cls._mark_auth_success()
            logger.debug("Caido token acquired")
            return cls._token

        if not allow_bootstrap:
            return None

        # Last-resort: try running host bootstrap once, then re-auth.
        await cls._try_bootstrap()

        if cls._token:
            cls._mark_auth_success()
            return cls._token

        token = await cls._try_guest_login()
        if token:
            cls._token = token
            cls._mark_auth_success()
            logger.debug("Caido token acquired after bootstrap")
            return cls._token
        return None

    @classmethod
    async def gql(
        cls,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        token = await cls._get_token(allow_bootstrap=True)
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            async with httpx.AsyncClient(timeout=30.0) as c:
                resp = await c.post(cls.BASE_URL, json=payload, headers=headers)

                if resp.status_code in (401, 403):
                    logger.debug(
                        "Caido token rejected (%d) — re-authenticating",
                        resp.status_code,
                    )
                    cls._token = None
                    fresh_token = await cls._get_token()
                    if fresh_token:
                        headers["Authorization"] = f"Bearer {fresh_token}"
                    else:
                        headers.pop("Authorization", None)
                    resp = await c.post(cls.BASE_URL, json=payload, headers=headers)

                return resp.json()

        except httpx.TimeoutException as e:
            logger.error("Caido GQL request timed out: %s", e)
            return {
                "errors": [
                    {"message": "Caido request timed out after 30s. Is Caido running?"}
                ]
            }
        except Exception as e:
            logger.error("Caido GQL error: %s", e)
            return {"errors": [{"message": str(e)}]}

    @classmethod
    def encode_raw_http(cls, raw_http: str) -> str:
        normalized = raw_http.replace("\r\n", "\n").replace("\n", "\r\n")
        return base64.b64encode(normalized.encode()).decode()

    @classmethod
    def find_fuzz_offsets(cls, raw_http: str) -> list[dict[str, int]]:
        marker = "§FUZZ§"
        normalized = raw_http.replace("\r\n", "\n").replace("\n", "\r\n")
        encoded_bytes = normalized.encode()
        marker_bytes = marker.encode()
        marker_len = len(marker_bytes)

        placeholders: list[dict[str, int]] = []
        removed = 0
        pos = 0

        while True:
            idx = encoded_bytes.find(marker_bytes, pos)
            if idx == -1:
                break

            clean_pos = idx - removed
            placeholders.append({"start": clean_pos, "end": clean_pos})
            removed += marker_len
            pos = idx + marker_len

        return placeholders
