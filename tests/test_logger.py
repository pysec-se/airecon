"""Tests for logger.py — multi-file logging configuration."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from airecon.logger import (
    AI_REASONING_LOG,
    DEBUG_LOG,
    ERROR_LOG,
    HTTP_PROXY_LOG,
    setup_logging,
)


def _flush_all() -> None:
    """Flush handlers on all loggers touched by setup_logging."""
    for name in (
        "",
        "airecon",
        "airecon.agent",
        "airecon.proxy.agent",
        "airecon.server",
        "uvicorn.access",
    ):
        for h in logging.getLogger(name).handlers:
            h.flush()


@pytest.fixture(autouse=True)
def _reset_logging():
    """Close and remove all handlers added by setup_logging between tests."""
    yield
    for name in (
        "",
        "airecon",
        "airecon.agent",
        "airecon.proxy.agent",
        "airecon.server",
        "airecon.proxy.server",
        "uvicorn.access",
    ):
        lg = logging.getLogger(name)
        for h in list(lg.handlers):
            try:
                h.close()
            except Exception:
                pass
        lg.handlers.clear()
    logging.root.setLevel(logging.WARNING)


class TestSetupLogging:
    """Core setup behaviour."""

    def test_creates_log_directory(self, tmp_path: Path) -> None:
        nested = tmp_path / "nested" / "logs"
        setup_logging(log_dir=nested, level=logging.INFO, is_tui=True)
        assert nested.exists()

    def test_creates_all_four_log_files(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.INFO, is_tui=True)
        assert (tmp_path / DEBUG_LOG).exists()
        assert (tmp_path / ERROR_LOG).exists()
        assert (tmp_path / AI_REASONING_LOG).exists()
        assert (tmp_path / HTTP_PROXY_LOG).exists()

    def test_airecon_logger_at_requested_level(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        assert logging.getLogger("airecon").level == logging.DEBUG

    def test_suppresses_noisy_third_party_loggers(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.INFO, is_tui=True)
        assert logging.getLogger("httpx").level >= logging.WARNING
        assert logging.getLogger("httpcore").level >= logging.WARNING
        assert logging.getLogger("asyncio").level >= logging.WARNING
        assert logging.getLogger("watchfiles").level >= logging.WARNING

    def test_idempotent_no_duplicate_file_handlers(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        # debug.log handler on airecon should be exactly 1
        debug_handlers = sum(
            1
            for h in logging.getLogger("airecon").handlers
            if isinstance(h, logging.FileHandler)
        )
        assert debug_handlers == 1
        # ai_log_reasoning handler on airecon.agent should be exactly 1
        ai_handlers = sum(
            1
            for h in logging.getLogger("airecon.agent").handlers
            if isinstance(h, logging.FileHandler)
        )
        assert ai_handlers == 1


class TestLogRouting:
    """Verify each logger routes to the correct file(s)."""

    def test_debug_log_captures_airecon_messages(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.some_module").info("debug_routing_test")
        _flush_all()
        assert "debug_routing_test" in (tmp_path / DEBUG_LOG).read_text()

    def test_error_log_captures_error_level(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.some_module").error("error_routing_test")
        _flush_all()
        assert "error_routing_test" in (tmp_path / ERROR_LOG).read_text()

    def test_error_log_does_not_capture_debug(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.some_module").debug("debug_should_not_be_in_error")
        _flush_all()
        assert "debug_should_not_be_in_error" not in (tmp_path / ERROR_LOG).read_text()

    def test_debug_log_does_not_capture_third_party_debug(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        # httpx is suppressed to WARNING — debug should not appear
        logging.getLogger("httpx").debug("httpx_debug_should_not_appear")
        _flush_all()
        assert "httpx_debug_should_not_appear" not in (tmp_path / DEBUG_LOG).read_text()

    def test_ai_reasoning_log_captures_agent_messages(self, tmp_path: Path) -> None:
        # Actual logger name in loop.py/executors.py: "airecon.agent"
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.agent").info("llm_reasoning_trace")
        _flush_all()
        assert "llm_reasoning_trace" in (tmp_path / AI_REASONING_LOG).read_text()

    def test_ai_reasoning_log_captures_agent_child(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.agent.pipeline").info("pipeline_reasoning_trace")
        _flush_all()
        assert "pipeline_reasoning_trace" in (tmp_path / AI_REASONING_LOG).read_text()

    def test_ai_reasoning_log_captures_proxy_agent_path(self, tmp_path: Path) -> None:
        # Some modules use "airecon.proxy.agent.*" (auth_manager, rate_limiter)
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.proxy.agent.auth_manager").info("auth_trace")
        _flush_all()
        assert "auth_trace" in (tmp_path / AI_REASONING_LOG).read_text()

    def test_ai_reasoning_log_also_propagates_to_debug_log(
        self, tmp_path: Path
    ) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.agent.pipeline").info("agent_in_debug_too")
        _flush_all()
        # propagation: airecon.agent → airecon → debug.log
        assert "agent_in_debug_too" in (tmp_path / DEBUG_LOG).read_text()

    def test_http_proxy_log_captures_server_messages(self, tmp_path: Path) -> None:
        # Actual logger name in server.py: "airecon.server"
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.server").info("http_request_log")
        _flush_all()
        assert "http_request_log" in (tmp_path / HTTP_PROXY_LOG).read_text()

    def test_http_proxy_log_also_propagates_to_debug_log(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.server").info("server_in_debug_too")
        _flush_all()
        assert "server_in_debug_too" in (tmp_path / DEBUG_LOG).read_text()

    def test_uvicorn_access_goes_to_http_proxy_log(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        # uvicorn.access is set to INFO and routed to http_proxy.log
        logging.getLogger("uvicorn.access").info("GET /api/status 200")
        _flush_all()
        assert "GET /api/status 200" in (tmp_path / HTTP_PROXY_LOG).read_text()

    def test_uvicorn_access_does_not_propagate_to_error_log(
        self, tmp_path: Path
    ) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("uvicorn.access").error("uvicorn_access_error")
        _flush_all()
        # propagate=False → should NOT appear in error.log via root
        assert "uvicorn_access_error" not in (tmp_path / ERROR_LOG).read_text()


class TestStreamHandler:
    """StreamHandler only appears in proxy/CLI mode (not TUI)."""

    def test_stream_handler_added_when_not_tui(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=False)
        handler_types = [
            type(h).__name__ for h in logging.getLogger("airecon").handlers
        ]
        assert "StreamHandler" in handler_types

    def test_stream_handler_absent_in_tui_mode(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        handler_types = [
            type(h).__name__ for h in logging.getLogger("airecon").handlers
        ]
        assert "StreamHandler" not in handler_types


class TestLogFormat:
    """Verify log message format is correct."""

    def test_debug_log_includes_timestamp(self, tmp_path: Path) -> None:
        import re

        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.test").info("timestamp_check")
        _flush_all()
        content = (tmp_path / DEBUG_LOG).read_text()
        assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", content)

    def test_debug_log_includes_level_name(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.test").info("level_name_check")
        _flush_all()
        assert "INFO" in (tmp_path / DEBUG_LOG).read_text()

    def test_debug_log_includes_logger_name(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.fmt_name_check").info("msg")
        _flush_all()
        assert "airecon.fmt_name_check" in (tmp_path / DEBUG_LOG).read_text()

    def test_error_log_includes_filename_and_lineno(self, tmp_path: Path) -> None:
        setup_logging(log_dir=tmp_path, level=logging.DEBUG, is_tui=True)
        logging.getLogger("airecon.test").error("error_fmt_detail")
        _flush_all()
        content = (tmp_path / ERROR_LOG).read_text()
        # error format: "... filename:lineno: message"
        assert "error_fmt_detail" in content
        import re

        assert re.search(r"\w+\.py:\d+", content)
