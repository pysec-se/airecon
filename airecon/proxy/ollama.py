from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any, AsyncIterator, Callable, Dict

import httpx

from .config import get_config

logger = logging.getLogger("airecon.ollama")

_CONTEXT_RESET_THRESHOLD = 65536

_PERMANENT_OLLAMA_ERRORS: frozenset[str] = frozenset(
    [
        "model not found",
        "model is not loaded",
        "unsupported model",
        "context length exceeded",
        "out of memory",
        "no gpu",
    ]
)


def _detect_model_capabilities_from_show(
    model_name: str,
    show_response: dict[str, Any] | Any,
) -> tuple[bool, bool]:
    data = show_response if isinstance(show_response, dict) else dict(show_response)

    capabilities = {
        str(item).strip().lower()
        for item in (data.get("capabilities") or [])
        if item is not None
    }
    template = (data.get("template") or "").lower()
    modelfile = (data.get("modelfile") or "").lower()

    supports_thinking = (
        "thinking" in capabilities
        or "<think>" in template
        or "<think>" in modelfile
        or "<thinking>" in template
        or "<thinking>" in modelfile
    )

    has_native_tools = any(
        cap in capabilities for cap in ("tools", "tool-calling", "function-calling")
    )

    supports_native_tools = has_native_tools and supports_thinking

    logger.info(
        "Model %s (show): capabilities=%s thinking=%s native_tools=%s",
        model_name,
        sorted(capabilities),
        supports_thinking,
        supports_native_tools,
    )
    return supports_thinking, supports_native_tools


class OllamaClient:
    _global_semaphore: asyncio.Semaphore | None = None
    _httpx_client: httpx.AsyncClient | None = None
    _initialized: bool = False
    _init_lock: asyncio.Lock | None = None
    _semaphore_init_lock = threading.Lock()

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:

        cfg = get_config()
        host = (base_url or cfg.ollama_url).rstrip("/")
        self._host = host
        self.model = model or cfg.ollama_model

        self._supports_thinking = cfg.ollama_supports_thinking
        self._supports_native_tools = cfg.ollama_supports_native_tools

        if not self._supports_thinking and self._supports_native_tools:
            logger.warning(
                "native_tools=True requires thinking=True (AIRecon uses reasoning "
                "traces to validate tool calls). Forcing native_tools=False."
            )
            self._supports_native_tools = False

        logger.info(
            "Initializing Ollama httpx client (sync init) for host: %s, model: %s",
            host,
            self.model,
        )

        if OllamaClient._global_semaphore is None:
            with OllamaClient._semaphore_init_lock:
                if OllamaClient._global_semaphore is None:
                    OllamaClient._global_semaphore = asyncio.Semaphore(1)
        self._request_semaphore = OllamaClient._global_semaphore

    async def _async_init(self) -> None:
        if OllamaClient._initialized:
            return

        if OllamaClient._init_lock is None:
            OllamaClient._init_lock = asyncio.Lock()

        async with OllamaClient._init_lock:
            if OllamaClient._initialized:
                return

            logger.info(
                "Initializing Ollama httpx client (async init) for model: %s",
                self.model,
            )
            logger.info(
                "Model capabilities: thinking=%s, native_tools=%s",
                self._supports_thinking,
                self._supports_native_tools,
            )

            if OllamaClient._httpx_client is None:
                _cfg = get_config()
                _http_timeout = _cfg.ollama_timeout
                OllamaClient._httpx_client = httpx.AsyncClient(
                    timeout=httpx.Timeout(
                        _http_timeout, connect=10.0, read=_http_timeout, write=10.0
                    ),
                    headers={"Content-Type": "application/json"},
                )
                OllamaClient._initialized = True
            logger.info("Ollama httpx client initialized")

    async def _run_http_request(
        self,
        method: str,
        endpoint: str,
        json_data: dict[str, Any] | None = None,
        stream: bool = False,
        timeout: float | None = None,
    ) -> httpx.Response | None:
        async with self._request_semaphore:
            client = OllamaClient._httpx_client
            if client is None:
                raise RuntimeError("HTTP client not initialized")

            url = f"{self._host}{endpoint}"

            if timeout is not None:
                timeout_obj = httpx.Timeout(
                    timeout, connect=10.0, read=timeout, write=10.0
                )
            else:
                _cfg = get_config()
                _http_timeout = _cfg.ollama_timeout
                timeout_obj = httpx.Timeout(
                    _http_timeout, connect=10.0, read=_http_timeout, write=10.0
                )

            if stream:
                raise RuntimeError(
                    "stream=True not supported in _run_http_request. "
                    "Use _run_http_stream() for streaming requests."
                )

            resp = await client.request(
                method=method,
                url=url,
                json=json_data,
                timeout=timeout_obj,
            )
            resp.raise_for_status()
            return resp

    async def reset_context(self, system_prompt: str | None = None) -> bool:
        cfg = get_config()
        timeout = cfg.ollama_timeout

        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            await self._run_http_request(
                "POST",
                "/api/chat",
                json_data={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {"num_predict": 100},
                },
                timeout=timeout,
            )
            logger.info("Ollama context reset successful")
            return True
        except asyncio.TimeoutError:
            logger.error(
                "Ollama context reset timeout after %.0fs",
                timeout,
            )
            return False
        except httpx.HTTPError as e:
            logger.error("Ollama context reset failed: %s", e)
            return False

    async def _detect_capabilities(self) -> tuple[bool, bool] | None:
        try:
            resp = await self._run_http_request(
                "POST",
                "/api/show",
                json_data={"name": self.model},
            )
            if resp is None:
                logger.warning("Ollama capability detection returned None response")
                return None
            data = resp.json()
            return _detect_model_capabilities_from_show(self.model, data)
        except Exception as e:
            logger.warning(
                "Could not inspect model metadata for %s: %s. Keeping config defaults.",
                self.model,
                e,
            )
            return None

    @property
    def supports_thinking(self) -> bool:
        return self._supports_thinking

    @property
    def supports_native_tools(self) -> bool:
        return self._supports_native_tools

    async def close(self) -> None:
        await self.unload_model()
        client = OllamaClient._httpx_client
        if client is not None:
            await client.aclose()

    async def unload_model(self) -> None:
        try:
            logger.info("Unloading model %s...", self.model)
            await self._run_http_request(
                "POST",
                "/api/generate",
                json_data={
                    "model": self.model,
                    "prompt": "",
                    "keep_alive": 0,
                },
                timeout=30.0,
                stream=False,
            )
            logger.info("Model unloaded successfully.")
        except Exception as e:
            logger.error("Failed to unload model: %s", e)

    async def health_check(self) -> bool:
        try:
            client = OllamaClient._httpx_client
            if client is None:
                return False
            resp = await client.get(
                f"{self._host}/api/tags",
                timeout=httpx.Timeout(10.0),
            )
            return resp.status_code == 200
        except Exception:
            return False

    async def complete(
        self,
        messages: list[dict[str, Any]],
        max_retries: int = 3,
        options: dict[str, Any] | None = None,
        operation: str = "compression",
    ) -> str:
        return await self._complete_impl(messages, max_retries, options, operation)

    async def _complete_impl(
        self,
        messages: list[dict[str, Any]],
        max_retries: int = 3,
        options: dict[str, Any] | None = None,
        operation: str = "compression",
    ) -> str:
        max_retries = max(0, max_retries)

        for attempt in range(max_retries + 1):
            try:
                payload: dict[str, Any] = {
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                }

                if options:
                    payload["options"] = options

                timeout = self._get_dynamic_timeout(operation)

                resp = await self._run_http_request(
                    "POST",
                    "/api/chat",
                    json_data=payload,
                    timeout=timeout,
                )
                if resp is None:
                    logger.warning(
                        "Ollama returned None response. Attempt %d/%d",
                        attempt + 1,
                        max_retries + 1,
                    )
                    if attempt < max_retries:
                        await asyncio.sleep(2 ** (attempt + 1))
                        continue
                    raise RuntimeError(
                        "Ollama returned None response after all retries"
                    )
                data = resp.json()

                content = None
                if isinstance(data, dict):
                    message = data.get("message", {})
                    if isinstance(message, dict):
                        content = message.get("content")

                if content is None:
                    logger.warning(
                        "Ollama returned unexpected response format: %r. Attempt %d/%d",
                        data,
                        attempt + 1,
                        max_retries + 1,
                    )
                    if attempt < max_retries:
                        await asyncio.sleep(2 ** (attempt + 1))
                        continue
                    raise RuntimeError(
                        f"Invalid Ollama response format: {type(data)}. "
                        f"Expected dict with 'message.content' or 'content' key."
                    )

                return content or ""

            except asyncio.TimeoutError:
                timeout = self._get_dynamic_timeout(operation)
                logger.warning(
                    "Ollama complete() timeout (%.0fs) for model %s (attempt %d/%d)",
                    timeout,
                    self.model,
                    attempt + 1,
                    max_retries + 1,
                )
                if attempt < max_retries:
                    await asyncio.sleep(2 ** (attempt + 1))
                    continue
                raise RuntimeError(
                    f"Ollama timeout after {timeout:.0f}s for model {self.model}"
                )
            except RuntimeError:
                raise
            except httpx.HTTPStatusError as e:
                if 500 <= e.response.status_code < 600 and attempt < max_retries:
                    await asyncio.sleep(2 ** (attempt + 1))
                    continue
                raise
            except httpx.NetworkError:
                if attempt < max_retries:
                    await asyncio.sleep(2 ** (attempt + 1))
                    continue
                raise

        raise RuntimeError("Unexpected code path in complete()")

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        options: dict[str, Any] | None = None,
        think: bool = False,
        max_retries: int = 3,
        stop_requested_fn: Callable[[], bool] | None = None,
    ) -> AsyncIterator[Any]:
        async for chunk in self._chat_stream_impl(
            messages, tools, options, think, max_retries, stop_requested_fn
        ):
            yield chunk

    async def _chat_stream_impl(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        options: dict[str, Any] | None = None,
        think: bool = False,
        max_retries: int = 3,
        stop_requested_fn: Callable[[], bool] | None = None,
    ) -> AsyncIterator[Any]:
        cfg = get_config()

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
        }
        if think:
            payload["think"] = think
        if tools:
            payload["tools"] = tools
        if options:
            payload["options"] = options

        _STOP_POLL = 2.0
        _overall_timeout = cfg.ollama_timeout
        _chunk_timeout = cfg.ollama_chunk_timeout

        for attempt in range(max_retries + 1):
            _next_fut: asyncio.Future | None = None
            _last_activity_time: float | None = None
            _stream = None
            _aiter = None

            try:
                async with self._request_semaphore:
                    client = OllamaClient._httpx_client
                    if client is None:
                        raise RuntimeError("HTTP client not initialized")

                    start_time = asyncio.get_running_loop().time()
                    _last_activity_time = start_time

                    url = f"{self._host}/api/chat"
                    timeout_obj = httpx.Timeout(_overall_timeout, read=_chunk_timeout)

                    async with client.stream(
                        "POST",
                        url,
                        json=payload,
                        timeout=timeout_obj,
                    ) as resp:
                        resp.raise_for_status()
                        _aiter = resp.aiter_lines()

                        chunk_count = 0
                        elapsed = 0.0

                        while True:
                            current_time = asyncio.get_running_loop().time()

                            if (current_time - start_time) > _overall_timeout:
                                raise TimeoutError(
                                    f"Ollama overall timeout: request took longer than {_overall_timeout:.0f}s"
                                )

                            if _last_activity_time is not None:
                                inactivity_time = current_time - _last_activity_time
                                if inactivity_time > get_config().ollama_timeout:
                                    logger.warning(
                                        "Ollama inactivity: %.0fs, cancelling request",
                                        inactivity_time,
                                    )
                                    raise TimeoutError("Ollama inactivity timeout")

                            if stop_requested_fn and stop_requested_fn():
                                return

                            if _next_fut is None:
                                _next_fut = asyncio.ensure_future(_aiter.__anext__())

                            remaining = _chunk_timeout - elapsed
                            wait = (
                                min(_STOP_POLL, remaining)
                                if remaining > 0
                                else _STOP_POLL
                            )

                            try:
                                assert _next_fut is not None
                                line = await asyncio.wait_for(
                                    asyncio.shield(_next_fut),
                                    timeout=wait,
                                )
                            except StopAsyncIteration:
                                _next_fut = None
                                if _last_activity_time is not None:
                                    _last_activity_time = (
                                        asyncio.get_running_loop().time()
                                    )
                                break
                            except asyncio.TimeoutError:
                                elapsed += wait
                                if elapsed >= _chunk_timeout:
                                    if _next_fut is not None and not _next_fut.done():
                                        _next_fut.cancel()
                                        try:
                                            await _next_fut
                                        except (
                                            StopAsyncIteration,
                                            asyncio.CancelledError,
                                        ):
                                            pass
                                    _next_fut = None
                                    raise TimeoutError(
                                        f"Ollama stream timeout: no chunk received for {_chunk_timeout:.0f}s "
                                        f"after {chunk_count} chunks."
                                    )
                                continue

                            elapsed = 0.0
                            if _last_activity_time is not None:
                                _last_activity_time = asyncio.get_running_loop().time()
                            _next_fut = None

                            if not line:
                                continue

                            try:
                                chunk = json.loads(line)
                                yield chunk
                                chunk_count += 1

                                if chunk.get("done"):
                                    break

                            except json.JSONDecodeError:
                                continue

                return

            except TimeoutError:
                if _next_fut is not None and not _next_fut.done():
                    _next_fut.cancel()
                raise

            except httpx.HTTPStatusError as e:
                err_msg = str(e).lower()

                if any(p in err_msg for p in _PERMANENT_OLLAMA_ERRORS):
                    logger.error("Permanent Ollama error (not retrying): %s", e)
                    raise

                if 400 <= e.response.status_code < 500:
                    logger.error("Permanent Ollama error (client error): %s", e)
                    raise

                if attempt < max_retries:
                    wait = 2 ** (attempt + 1)
                    logger.warning(
                        "Ollama HTTP error (attempt %d/%d), retrying in %ss: %s",
                        attempt + 1,
                        max_retries + 1,
                        wait,
                        e,
                    )
                    await asyncio.sleep(wait)
                    continue
                logger.error(
                    "Ollama HTTP error after %d attempts: %s",
                    max_retries + 1,
                    e,
                )
                raise

            except Exception as e:
                if _next_fut is not None and not _next_fut.done():
                    _next_fut.cancel()
                _next_fut = None

                err_str = str(e).lower()
                is_transient = any(
                    k in err_str
                    for k in (
                        "connection reset",
                        "connection refused",
                        "eof",
                        "broken pipe",
                        "timeout",
                        "timed out",
                        "network",
                        "connection error",
                        "stream ended",
                    )
                )

                if is_transient and attempt < max_retries:
                    wait = 2 ** (attempt + 1)
                    logger.warning(
                        "Transient Ollama error (attempt %d/%d), retrying in %ss: %s",
                        attempt + 1,
                        max_retries + 1,
                        wait,
                        e,
                    )
                    await asyncio.sleep(wait)
                    continue

                logger.exception("Unexpected error: %s", e)
                raise

    def _get_dynamic_timeout(self, operation: str = "inference") -> float:
        cfg = get_config()

        if operation == "compression":
            return max(180.0, cfg.ollama_chunk_timeout)
        return cfg.ollama_chunk_timeout

    def _record_response_time(self, response_time: float) -> None:
        """Record a response time for adaptive timeout calculations."""
        if not hasattr(self, "_response_times"):
            self._response_times = []
        if not hasattr(self, "_max_response_times"):
            self._max_response_times = 20
        self._response_times.append(response_time)
        max_len = self._max_response_times
        if len(self._response_times) > max_len:
            self._response_times = self._response_times[-max_len:]

    def get_response_time_stats(self) -> Dict[str, float]:
        """Get statistics for recorded response times.

        Returns avg/min/max of last 10 response times.
        """
        if not hasattr(self, "_response_times"):
            self._response_times = []
        times = self._response_times[-10:] if self._response_times else []
        if not times:
            return {"avg": 0.0, "min": 0.0, "max": 0.0, "count": 0}
        return {
            "avg": sum(times) / len(times),
            "min": min(times),
            "max": max(times),
            "count": len(self._response_times),
        }
