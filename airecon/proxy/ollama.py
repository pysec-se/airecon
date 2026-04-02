from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator, Callable

import ollama

from .config import get_config

logger = logging.getLogger("airecon.ollama")

_CONTEXT_RESET_THRESHOLD = 100000

_PERMANENT_OLLAMA_ERRORS: frozenset[str] = frozenset([
    "model not found",
    "model is not loaded",
    "unsupported model",
    "context length exceeded",
    "out of memory",
    "no gpu",
])

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
        cap in capabilities
        for cap in ("tools", "tool-calling", "function-calling")
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

    _request_gates: dict[tuple[int, str, str], tuple[int, asyncio.Semaphore]] = {}

    def __init__(self, base_url: str | None = None,
                 model: str | None = None) -> None:
        cfg = get_config()
        host = (base_url or cfg.ollama_url).rstrip("/")
        self._host = host
        self.model = model or cfg.ollama_model

        self._supports_thinking = cfg.ollama_supports_thinking
        self._supports_native_tools = cfg.ollama_supports_native_tools

        if cfg.ollama_supports_thinking is True or cfg.ollama_supports_native_tools is True:
            detected = self._detect_capabilities()
            if detected is not None:
                detected_think, detected_tools = detected
                if cfg.ollama_supports_thinking is True:
                    self._supports_thinking = detected_think
                if cfg.ollama_supports_native_tools is True:
                    self._supports_native_tools = detected_tools

        if not self._supports_thinking and self._supports_native_tools:
            logger.warning(
                "native_tools=True requires thinking=True (AIRecon uses reasoning "
                "traces to validate tool calls). Forcing native_tools=False."
            )
            self._supports_native_tools = False

        logger.info(
            "Initializing Ollama SDK client for host: %s, model: %s, timeout: %ss",
            host, self.model, cfg.ollama_timeout,
        )
        logger.info(
            "Model capabilities: thinking=%s, native_tools=%s",
            self._supports_thinking, self._supports_native_tools,
        )
        self._client = ollama.AsyncClient(
            host=host, timeout=cfg.ollama_timeout)

        self._response_times_storage: list[float] = []
        self._max_response_times = 20
        self._slow_response_threshold = 30.0
        self._critical_response_threshold = 60.0

    async def reset_context(self, system_prompt: str | None = None) -> bool:
        try:
            if system_prompt:
                # Re-inject system prompt to maintain context continuity
                await self._client.chat(
                    model=self.model,
                    messages=[{"role": "system", "content": system_prompt}],
                    keep_alive="10m",  # Keep model loaded for 10 minutes
                )
                logger.info("✓ Ollama context reset with system prompt re-injection")
            else:
                # Pure reset - empty messages
                await self._client.chat(
                    model=self.model,
                    messages=[],
                    keep_alive="10m",  # Keep model loaded for 10 minutes
                )
                logger.info("✓ Ollama context reset (empty)")
            return True
        except Exception as e:
            logger.warning("Ollama context reset failed: %s", e)
            return False

    @property
    def _response_times(self) -> list[float]:
        if not hasattr(self, "_response_times_storage"):
            self._response_times_storage = []
        return self._response_times_storage

    @_response_times.setter
    def _response_times(self, value: list[float]) -> None:
        self._response_times_storage = value

    @property
    def _max_response_times(self) -> int:
        if not hasattr(self, "_max_response_times_value"):
            self._max_response_times_value = 20
        return self._max_response_times_value

    @_max_response_times.setter
    def _max_response_times(self, value: int) -> None:
        self._max_response_times_value = value

    @property
    def _slow_response_threshold(self) -> float:
        if not hasattr(self, "_slow_response_threshold_value"):
            self._slow_response_threshold_value = 30.0
        return self._slow_response_threshold_value

    @_slow_response_threshold.setter
    def _slow_response_threshold(self, value: float) -> None:
        self._slow_response_threshold_value = value

    @property
    def _critical_response_threshold(self) -> float:
        if not hasattr(self, "_critical_response_threshold_value"):
            self._critical_response_threshold_value = 60.0
        return self._critical_response_threshold_value

    @_critical_response_threshold.setter
    def _critical_response_threshold(self, value: float) -> None:
        self._critical_response_threshold_value = value

    def _get_adaptive_timeout(self) -> float:
        model_lower = self.model.lower()

        if any(x in model_lower for x in ["122b", "100b", "150b", "200b"]):
            return 300.0

        elif any(x in model_lower for x in ["70b", "80b", "90b"]):
            return 180.0

        elif any(x in model_lower for x in ["30b", "32b", "35b", "40b", "50b"]):
            return 120.0

        elif any(x in model_lower for x in ["7b", "8b", "9b", "10b", "11b", "12b", "13b", "14b"]):
            return 180.0

        elif any(x in model_lower for x in ["1b", "2b", "3b", "4b", "5b", "6b"]):
            return 120.0

        else:
            return 90.0

    def _record_response_time(self, response_time: float) -> None:
        self._response_times.append(response_time)
        if len(self._response_times) > self._max_response_times:
            self._response_times.pop(0)

    def _get_dynamic_timeout(self, operation: str = "inference") -> float:
        base_timeout = self._get_adaptive_timeout()

        if operation == "compression":
            base_timeout = max(base_timeout, 120.0)

        response_times = self._response_times
        if len(response_times) >= 3:
            avg_time = sum(response_times[-10:]) / min(len(response_times), 10)
            max_time = max(response_times[-10:])

            dynamic_timeout = max(avg_time * 3.0, max_time, base_timeout)

            dynamic_timeout = min(dynamic_timeout, 600.0)

            if dynamic_timeout > base_timeout * 1.5:
                logger.warning(
                    "Ollama response degradation detected: avg=%.1fs, max=%.1fs, "
                    "base_timeout=%.0fs → dynamic_timeout=%.0fs",
                    avg_time, max_time, base_timeout, dynamic_timeout
                )

            return dynamic_timeout

        return base_timeout

    def get_response_time_stats(self) -> dict[str, float]:
        response_times = self._response_times
        if not response_times:
            return {"avg": 0.0, "min": 0.0, "max": 0.0, "count": 0}

        recent = response_times[-10:]
        return {
            "avg": sum(recent) / len(recent),
            "min": min(recent),
            "max": max(recent),
            "count": len(response_times),
        }

    async def _get_request_gate(self) -> asyncio.Semaphore:
        cfg = get_config()
        limit = max(
            1,
            int(getattr(cfg, "ollama_max_concurrent_requests", 1)),
        )
        loop_id = id(asyncio.get_running_loop())
        key = (loop_id, self._host, self.model)

        cached = self._request_gates.get(key)
        if cached is None or cached[0] != limit:
            gate = asyncio.Semaphore(limit)
            self._request_gates[key] = (limit, gate)
            logger.info(
                "Ollama concurrency gate initialized for %s (%s): %d",
                self.model,
                self._host,
                limit,
            )
        else:
            gate = cached[1]
        return gate

    def _detect_capabilities(self) -> tuple[bool, bool] | None:
        try:
            sync_client = ollama.Client(host=self._host)
            show_response = sync_client.show(model=self.model)
            return _detect_model_capabilities_from_show(self.model, show_response)
        except Exception as e:
            logger.warning(
                "Could not inspect model metadata via `ollama show` for %s: %s. "
                "Keeping config defaults (thinking/native-tools remain as configured). "
                "If your model does NOT support thinking or tool-calling, set "
                "ollama_supports_thinking=false and/or ollama_supports_native_tools=false "
                "in config.json to avoid runtime errors.",
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

    async def unload_model(self) -> None:
        try:
            logger.info("Unloading model %s...", self.model)
            await self._client.generate(model=self.model, prompt="", keep_alive=0)
            logger.info("Model unloaded successfully.")
        except Exception as e:
            logger.error("Failed to unload model: %s", e)

    async def health_check(self) -> bool:
        try:
            await self._client.list()
            return True
        except Exception:
            return False

    async def complete(
        self,
        messages: list[dict[str, Any]],
        max_retries: int = 3,
        options: dict[str, Any] | None = None,
        operation: str = "compression",
    ) -> str:
        max_retries = max(0, max_retries)
        gate = await self._get_request_gate()
        async with gate:
            for attempt in range(max_retries + 1):
                try:
                    kwargs: dict[str, Any] = {
                        "model": self.model,
                        "messages": messages,
                        "stream": False,
                        "keep_alive": get_config().ollama_keep_alive,
                    }
                    if options:
                        kwargs["options"] = options

                    timeout = self._get_dynamic_timeout(operation)
                    start_time = asyncio.get_running_loop().time()

                    response = await asyncio.wait_for(
                        self._client.chat(**kwargs),
                        timeout=timeout
                    )

                    response_time = asyncio.get_running_loop().time() - start_time
                    self._record_response_time(response_time)

                    if response_time > self._critical_response_threshold:
                        logger.critical(
                            "Ollama CRITICAL slow response: %.1fs (threshold: %.0fs) — "
                            "Consider reducing load or switching to smaller model",
                            response_time, self._critical_response_threshold
                        )
                    elif response_time > self._slow_response_threshold:
                        logger.warning(
                            "Ollama slow response: %.1fs (threshold: %.0fs)",
                            response_time, self._slow_response_threshold
                        )

                    content = None
                    if hasattr(response, "message") and response.message is not None:
                        content = response.message.content
                    elif isinstance(response, dict):
                        content = response.get("message", {}).get("content")

                    if content is None:
                        logger.warning(
                            "Ollama returned unexpected response format: %r. "
                            "Response: %r. Attempt %d/%d",
                            type(response), response, attempt + 1, max_retries + 1
                        )
                        if attempt < max_retries:
                            wait = 2 ** (attempt + 1)
                            await asyncio.sleep(wait)
                            continue
                        raise RuntimeError(
                            f"Invalid Ollama response format: {type(response)}. "
                            f"Expected response with 'message.content' attribute or dict with 'message.content' key."
                        )

                    return content or ""

                except asyncio.TimeoutError:

                    logger.warning(
                        "Ollama complete() timeout (%.0fs) for model %s (attempt %d/%d)",
                        timeout, self.model, attempt + 1, max_retries + 1
                    )
                    if attempt < max_retries:
                        wait = 2 ** (attempt + 1)
                        await asyncio.sleep(wait)
                        continue
                    raise RuntimeError(
                        f"Ollama timeout after {timeout:.0f}s for model {self.model}"
                    )
                except RuntimeError:
                    raise
                except Exception as e:
                    err_str = str(e).lower()
                    is_transient = any(
                        k in err_str
                        for k in (
                            "connection reset", "connection refused", "eof",
                            "broken pipe", "timeout", "timed out",
                            "network", "connection error",
                        )
                    )
                    if is_transient and attempt < max_retries:
                        wait = 2 ** (attempt + 1)
                        logger.warning(
                            "Transient Ollama error in complete() (attempt %d/%d), retrying in %ss: %s",
                            attempt + 1, max_retries + 1, wait, e,
                        )
                        await asyncio.sleep(wait)
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
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "keep_alive": get_config().ollama_keep_alive,
        }
        if think:
            kwargs["think"] = think
        if tools:
            kwargs["tools"] = tools
        if options:
            kwargs["options"] = options

        _STOP_POLL = 2.0

        gate = await self._get_request_gate()
        async with gate:
            for attempt in range(max_retries + 1):
                try:
                    _chunk_timeout = get_config().ollama_chunk_timeout

                    _overall_timeout = get_config().ollama_timeout
                    _loop = asyncio.get_running_loop()
                    _start_time = _loop.time()

                    _stream = await self._client.chat(**kwargs)
                    _aiter = _stream.__aiter__()
                    _chunk_count = 0
                    _elapsed = 0.0

                    _next_fut: asyncio.Future | None = None
                    _last_activity_time = _start_time

                    while True:

                        _current_time = _loop.time()
                        if (_current_time - _start_time) > _overall_timeout:
                            raise TimeoutError(
                                f"Ollama overall timeout: request took longer than "
                                f"{_overall_timeout:.0f}s"
                            )

                        if (_current_time - _last_activity_time) > 300:
                            _inactive = _current_time - _last_activity_time
                            logger.warning(
                                "Ollama watchdog: No activity for %.0fs, cancelling request",
                                _inactive,
                            )
                            if _next_fut is not None and not _next_fut.done():
                                _next_fut.cancel()
                            raise TimeoutError(
                                "Ollama watchdog: No activity for 300s, request cancelled"
                            )

                        if stop_requested_fn and stop_requested_fn():
                            if _next_fut is not None and not _next_fut.done():
                                _next_fut.cancel()
                            return

                        if _next_fut is None:
                            _next_fut = asyncio.ensure_future(_aiter.__anext__())

                        _remaining = _chunk_timeout - _elapsed
                        _wait = min(_STOP_POLL, _remaining) if _remaining > 0 else _STOP_POLL
                        try:
                            assert _next_fut is not None
                            chunk = await asyncio.wait_for(
                                asyncio.shield(_next_fut),
                                timeout=_wait,
                            )
                        except StopAsyncIteration:
                            _next_fut = None
                            _last_activity_time = _loop.time()
                            break
                        except asyncio.TimeoutError:
                            _elapsed += _wait
                            if _elapsed >= _chunk_timeout:
                                if _next_fut is not None and not _next_fut.done():
                                    _next_fut.cancel()
                                _next_fut = None
                                raise TimeoutError(
                                    f"Ollama stream timeout: no chunk received for "
                                    f"{_chunk_timeout:.0f}s after {_chunk_count} chunks. "
                                    "The model may be frozen or overloaded."
                                ) from None

                            continue
                        _elapsed = 0.0
                        _chunk_count += 1
                        _last_activity_time = _loop.time()
                        _next_fut = None
                        yield chunk
                    return

                except TimeoutError:

                    if _next_fut is not None and not _next_fut.done():
                        _next_fut.cancel()
                    raise

                except ollama.ResponseError as e:
                    err_str = str(e.error)
                    if (
                        "invalid character '<'" in err_str
                        or "failed to parse JSON" in err_str
                    ):

                        raise ollama.ResponseError(
                            "Ollama returned an HTML error page instead of JSON. "
                            "This usually means Ollama crashed or ran out of memory. "
                            "Try: `systemctl restart ollama` or reduce `ollama_num_ctx` in config.",
                            status_code=e.status_code,
                        )

                    err_lower = err_str.lower()
                    if any(p in err_lower for p in _PERMANENT_OLLAMA_ERRORS):
                        logger.error("Permanent Ollama error (not retrying): %s", err_str)
                        raise

                    if attempt < max_retries:
                        wait = 2 ** (attempt + 1)
                        logger.warning(
                            "Ollama ResponseError (attempt %d/%d), retrying in %ss: %s",
                            attempt + 1, max_retries + 1, wait, e.error,
                        )
                        await asyncio.sleep(wait)
                        continue
                    logger.error(
                        "Ollama ResponseError after %d attempts: %s",
                        max_retries + 1, e.error,
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
                        )
                    )
                    if is_transient and attempt < max_retries:
                        wait = 2 ** (attempt + 1)
                        logger.warning(
                            "Transient Ollama error (attempt %d/%d), retrying in %ss: %s",
                            attempt + 1, max_retries + 1, wait, e,
                        )
                        await asyncio.sleep(wait)
                        continue
                    logger.exception("Unexpected SDK error: %s", e)
                    raise
