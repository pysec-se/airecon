"""Web search tool — SearXNG (preferred) with DuckDuckGo fallback."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.web_search")

# Cache search results to avoid repeated queries
_CACHE_DIR = Path.home() / ".airecon" / "cache" / "search"
_CACHE_TTL = 3600  # 1 hour cache lifetime

# Minimum seconds between consecutive DDG requests to avoid rate limiting
_DDG_MIN_INTERVAL = 2.0
_last_ddg_search_time: float = 0.0
# Lock to serialize concurrent DDG calls and enforce the rate limit correctly.
# Initialized at first use via _get_ddg_lock() which is always called from
# within a running asyncio event loop — asyncio.Lock() binds to the running
# loop at creation time, so creation here (module load, no loop) would bind
# to the wrong loop. _get_ddg_lock() must be called from an async context.
_ddg_lock: asyncio.Lock | None = None
_ddg_lock_init_lock = __import__("threading").Lock()


def _get_ddg_lock() -> asyncio.Lock:
    """Return a shared asyncio.Lock, created once within the running loop.

    Thread-safe: uses a threading.Lock to prevent double-initialization
    if two coroutines race before the asyncio.Lock is created.
    """
    global _ddg_lock
    if _ddg_lock is None:
        with _ddg_lock_init_lock:
            if _ddg_lock is None:  # double-checked locking
                _ddg_lock = asyncio.Lock()
    return _ddg_lock


async def _searxng_search(
    query: str,
    max_results: int,
    base_url: str,
    engines: str,
) -> dict[str, Any]:
    """Query a self-hosted SearXNG instance and return formatted results."""
    import aiohttp

    url = f"{base_url.rstrip('/')}/search"
    params = {
        "q": query,
        "format": "json",
        "engines": engines,
        "language": "en",
        "safesearch": "0",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return {
                        "success": False,
                        "error": f"SearXNG returned HTTP {resp.status}",
                    }
                data = await resp.json(content_type=None)
    except aiohttp.ClientConnectorError as e:
        return {
            "success": False,
            "error": f"Cannot connect to SearXNG at {base_url}: {e}. "
            "Check that the SearXNG container is running.",
        }
    except asyncio.TimeoutError:
        return {
            "success": False,
            "error": f"SearXNG request timed out at {base_url}.",
        }

    results = data.get("results", [])[:max_results]

    if not results:
        return {
            "success": True,
            "result": f"No results found for: {query}\n"
            f"(SearXNG queried engines: {engines})",
        }

    lines: list[str] = []
    for i, r in enumerate(results, 1):
        title = r.get("title", "No title")
        href = r.get("url", "")
        body = r.get("content", "")
        engine = r.get("engine", "")
        lines.append(f"{i}. [{engine}] **{title}**\n   URL: {href}\n   {body}")

    return {"success": True, "result": "\n\n".join(lines)}


async def _ddg_search(query: str, max_results: int) -> dict[str, Any]:
    """Search via DuckDuckGo with rate-limit handling."""
    global _last_ddg_search_time

    try:
        from duckduckgo_search import DDGS
        from duckduckgo_search.exceptions import (
            DuckDuckGoSearchException,
            RatelimitException,
        )
    except ImportError:
        return {
            "success": False,
            "error": "duckduckgo-search not installed. Run: pip install duckduckgo-search",
        }

    def _search() -> list[dict[str, Any]]:
        with DDGS() as ddgs:
            return list(ddgs.text(query, max_results=max_results))

    # Serialize all DDG calls through a lock so concurrent agents don't bypass
    # the rate-limit interval. The lock is held for the duration of the wait
    # AND the actual search to prevent concurrent requests from slipping
    # through after the gate.
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            async with _get_ddg_lock():
                now = time.monotonic()
                wait = _DDG_MIN_INTERVAL - (now - _last_ddg_search_time)
                if wait > 0:
                    await asyncio.sleep(wait)
                _last_ddg_search_time = time.monotonic()
                results = await asyncio.to_thread(_search)
            break
        except RatelimitException as e:
            last_err = e
            wait_time = 5.0 * (attempt + 1)
            logger.warning(
                f"DDG rate limit attempt {attempt + 1}, waiting {wait_time:.0f}s"
            )
            await asyncio.sleep(wait_time)
        except DuckDuckGoSearchException as e:
            last_err = e
            logger.warning(f"DDG error attempt {attempt + 1}: {e}")
            await asyncio.sleep(3.0 * (attempt + 1))
    else:
        return {
            "success": False,
            "error": f"DuckDuckGo rate limited after 3 attempts: {last_err}. "
            "Configure searxng_url in ~/.airecon/config.json for better results.",
        }

    if not results:
        hint = ""
        if "site:*." in query or "ext:" in query:
            hint = (
                " NOTE: DuckDuckGo does not support wildcard site: or ext: operators. "
                "Configure SearXNG (searxng_url in config) to enable full Google dork support, "
                "or use execute: curl 'https://crt.sh/?q=%25.target.com&output=json'"
            )
        return {"success": True, "result": f"No results found for: {query}{hint}"}

    lines: list[str] = []
    for i, r in enumerate(results, 1):
        title = r.get("title", "No title")
        href = r.get("href", "")
        body = r.get("body", "")
        lines.append(f"{i}. [ddg] **{title}**\n   URL: {href}\n   {body}")

    return {"success": True, "result": "\n\n".join(lines)}


def _is_target_specific_query(query: str) -> bool:
    """Return True if the query contains target-specific identifiers.

    Target-specific queries (domain, IP, site: dork) should never be cached
    because the target's attack surface changes over time and fresh intel is
    required for accurate results.
    Generic queries (CVE lookups, tool docs, payloads) are safe to cache.
    """
    q = query.lower()
    # Google dork operators that pin the query to a specific target
    if re.search(r"\bsite:\S+\b", q):
        return True
    # Bare domain patterns: something.tld or sub.something.tld
    if re.search(r"\b[a-z0-9\-]+\.[a-z]{2,}\b", q):
        return True
    # IPv4 address
    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", q):
        return True
    return False


async def web_search(query: str, max_results: int = 10, use_cache: bool = True) -> dict[str, Any]:
    """Search the web. Uses SearXNG if configured, otherwise DuckDuckGo.

    Args:
        query: Search query string. With SearXNG, full Google dork operators work:
               site:target.com ext:sql, inurl:admin, intitle:"index of",
               filetype:pdf, intext:password, site:*.target.com -www
               Also searches github, stackoverflow, google_news if SearXNG enabled.
               Without SearXNG (DDG fallback), advanced dork operators are ignored.
        max_results: Maximum number of results (default 10, max 50).
                     Use 30-50 for comprehensive dorking sessions.
        use_cache: Whether to use cached results if available (default True).
                  Set to False to force fresh results.
                  Note: target-specific queries (domain, IP, site: dork) are
                  never cached regardless of this flag — fresh intel is always
                  required for accurate results.

    Returns:
        dict with 'success' bool and 'result' string (formatted results).
    """
    # Never cache target-specific queries — fresh intel only.
    effective_cache = use_cache and not _is_target_specific_query(query)

    try:
        from .config import get_config
        cfg = get_config()
        searxng_url = cfg.searxng_url.strip()
        engines = cfg.searxng_engines.strip() or "google,bing,duckduckgo,brave"
    except Exception:
        searxng_url = ""
        engines = "google,bing,duckduckgo,brave"

    max_results = min(int(max_results), 50)

    # Check cache first — include engines in key to avoid cross-engine cache hits
    if effective_cache:
        cached = _get_cached_results(query, max_results, engines)
        if cached:
            cached["from_cache"] = True
            return cached

    if searxng_url:
        result = await _searxng_search(query, max_results, searxng_url, engines)
        # Cache generic SearXNG results too (previously uncached)
        if result.get("success") and effective_cache:
            _cache_results(query, max_results, result, engines)
        # If SearXNG is unreachable, fall back to DDG with a warning
        if not result.get(
                "success") and "Cannot connect" in result.get("error", ""):
            logger.warning(
                f"SearXNG unreachable, falling back to DDG: {result['error']}"
            )
            ddg_result = await _ddg_search(query, max_results)
            ddg_result["result"] = (
                "[SearXNG unavailable — using DuckDuckGo fallback]\n\n"
                + ddg_result.get("result", "")
            )
            if ddg_result.get("success") and effective_cache:
                _cache_results(query, max_results, ddg_result, "")
            return ddg_result
        return result

    result = await _ddg_search(query, max_results)

    # Cache successful results
    if result.get("success") and effective_cache:
        _cache_results(query, max_results, result, "")

    return result


def _get_cache_key(query: str, max_results: int, engines: str = "") -> str:
    """Generate a unique cache key for the search parameters."""
    return hashlib.md5(  # nosec B324 - non-security cache key
        f"{query}:{max_results}:{engines}".encode(), usedforsecurity=False).hexdigest()


def _get_cached_results(query: str, max_results: int, engines: str = "") -> dict[str, Any] | None:
    """Get cached results if they exist and are fresh."""
    try:
        cache_key = _get_cache_key(query, max_results, engines)
        import gzip
        cache_file = _CACHE_DIR / f"{cache_key}.json.gz"

        if not cache_file.exists():
            return None

        # Check if cache is still fresh
        if time.time() - cache_file.stat().st_mtime > _CACHE_TTL:
            return None

        with gzip.open(cache_file, "rt") as f:
            return json.load(f)
    except Exception as e:
        logger.debug(f"Cache read failed: {e}")
        return None


def _cache_results(query: str, max_results: int, results: dict[str, Any], engines: str = "") -> None:
    """Cache search results to disk."""
    try:
        import gzip
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_key = _get_cache_key(query, max_results, engines)
        cache_file = _CACHE_DIR / f"{cache_key}.json.gz"

        with gzip.open(cache_file, "wt") as f:
            json.dump(results, f)
    except Exception as e:
        logger.debug(f"Cache write failed: {e}")
