from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

LOG_DIR = Path(os.environ.get("AIRECON_LOG_DIR", tempfile.gettempdir())) / "airecon"

DEBUG_LOG = "debug.log"
ERROR_LOG = "error.log"
AI_REASONING_LOG = "ai_log_reasoning.log"
HTTP_PROXY_LOG = "http_proxy.log"


def setup_logging(
    log_dir: str | Path = LOG_DIR,
    level: int = logging.DEBUG,
    is_tui: bool = False,
) -> None:
    _dir = Path(log_dir)
    _dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    fmt_debug = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fmt_error = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s %(filename)s:%(lineno)d: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    def _fh(name: str, lvl: int, fmt: logging.Formatter) -> logging.FileHandler:
        h = logging.FileHandler(_dir / name, mode="a", encoding="utf-8")
        h.setLevel(lvl)
        h.setFormatter(fmt)
        return h

    _managed = (
        "",
        "airecon",
        "airecon.agent",
        "airecon.proxy.agent",
        "airecon.server",
        "uvicorn.access",
    )
    for _name in _managed:
        _lg = logging.getLogger(_name)
        for _h in list(_lg.handlers):
            try:
                _h.close()
            except Exception as e:
                logging.getLogger(__name__).debug(
                    "Expected failure closing old handler for %s: %s", _name, e
                )
        _lg.handlers.clear()

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(_fh(ERROR_LOG, logging.ERROR, fmt_error))
    airecon = logging.getLogger("airecon")
    airecon.setLevel(level)
    airecon.propagate = True
    airecon.addHandler(_fh(DEBUG_LOG, level, fmt_debug))

    if not is_tui:
        _sh = logging.StreamHandler()
        _sh.setLevel(level)
        _sh.setFormatter(fmt_debug)
        airecon.addHandler(_sh)

    _ai_fh = _fh(AI_REASONING_LOG, level, fmt_debug)
    agent = logging.getLogger("airecon.agent")
    agent.setLevel(level)
    agent.propagate = True
    agent.addHandler(_ai_fh)
    proxy_agent = logging.getLogger("airecon.proxy.agent")
    proxy_agent.setLevel(level)
    proxy_agent.propagate = True
    proxy_agent.addHandler(_ai_fh)
    _http_fh = _fh(HTTP_PROXY_LOG, logging.DEBUG, fmt_debug)
    srv = logging.getLogger("airecon.server")
    srv.setLevel(level)
    srv.propagate = True
    srv.addHandler(_http_fh)

    uv_access = logging.getLogger("uvicorn.access")
    uv_access.setLevel(logging.INFO)
    uv_access.addHandler(_http_fh)
    uv_access.propagate = False

    for _noisy in (
        "httpx",
        "httpcore",
        "watchfiles",
        "asyncio",
        "markdown_it",
        "uvicorn",
        "uvicorn.error",
        "multipart",
    ):
        logging.getLogger(_noisy).setLevel(logging.WARNING)

    logging.getLogger("airecon.logger").info(
        "Debug logging active → %s  [debug | error | ai_log_reasoning | http_proxy]",
        _dir.absolute(),
    )
