"""WAF Bypass Engine - Automated WAF detection and bypass strategies.

This module provides automated WAF bypass capabilities for AIRecon,
enabling testing of WAF-protected targets that were previously blocked.

Usage:
    bypass_engine = WAFBypassEngine()
    result = await bypass_engine.test_bypass(url, waf_type, payload)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("airecon.proxy.agent.waf_bypass")


def _load_waf_bypass_config() -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, dict[str, Any]],
    int,
    int,
]:
    """Load WAF bypass strategies and detection patterns from JSON data."""
    config_path = Path(__file__).resolve().parent.parent / "data" / "waff_bypass.json"
    default_strategies: dict[str, list[dict[str, Any]]] = {
        "generic": [
            {
                "name": "sql_comment",
                "description": "Use SQL comments to bypass filters",
                "comments": ["--", "#", "/*", "-- -", "#-", "/*-"],
            }
        ]
    }
    default_patterns: dict[str, dict[str, Any]] = {}

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not load waff_bypass.json (%s): %s", config_path, exc)
        return default_strategies, default_patterns, 2, 8

    if not isinstance(data, dict):
        logger.warning("Invalid waff_bypass.json format: expected JSON object")
        return default_strategies, default_patterns, 2, 8

    raw_strategies = data.get("BYPASS_STRATEGIES", {})
    raw_patterns = data.get("WAF_PATTERNS", {})

    if not isinstance(raw_strategies, dict):
        logger.warning("Invalid BYPASS_STRATEGIES format in waff_bypass.json")
        raw_strategies = {}
    if not isinstance(raw_patterns, dict):
        logger.warning("Invalid WAF_PATTERNS format in waff_bypass.json")
        raw_patterns = {}

    strategies: dict[str, list[dict[str, Any]]] = {}
    for waf_name, entries in raw_strategies.items():
        if not isinstance(entries, list):
            continue
        normalized = [entry for entry in entries if isinstance(entry, dict)]
        if normalized:
            strategies[str(waf_name)] = normalized

    patterns: dict[str, dict[str, Any]] = {}
    for waf_name, cfg in raw_patterns.items():
        if isinstance(cfg, dict):
            patterns[str(waf_name)] = cfg

    if "generic" not in strategies:
        strategies["generic"] = default_strategies["generic"]

    raw_detection_cfg = data.get("DETECTION_SCORING", {})
    raw_policy_cfg = data.get("SAFE_TEST_POLICY", {})
    if not isinstance(raw_detection_cfg, dict):
        raw_detection_cfg = {}
    if not isinstance(raw_policy_cfg, dict):
        raw_policy_cfg = {}

    try:
        min_detection_score = int(raw_detection_cfg.get("minimum_detection_score", 2))
    except (TypeError, ValueError):
        min_detection_score = 2
    try:
        max_strategies_per_profile = int(raw_policy_cfg.get("max_strategies_per_profile", 8))
    except (TypeError, ValueError):
        max_strategies_per_profile = 8

    min_detection_score = max(1, min_detection_score)
    max_strategies_per_profile = max(1, max_strategies_per_profile)

    return strategies, patterns, min_detection_score, max_strategies_per_profile


(
    _BYPASS_STRATEGIES,
    _WAF_PATTERNS,
    _DETECTION_MIN_SCORE,
    _MAX_STRATEGIES_PER_PROFILE,
) = _load_waf_bypass_config()


class WAFBypassEngine:
    """Automated WAF bypass with adaptive strategies."""
    BYPASS_STRATEGIES = _BYPASS_STRATEGIES
    WAF_PATTERNS = _WAF_PATTERNS
    DETECTION_MIN_SCORE = _DETECTION_MIN_SCORE
    MAX_STRATEGIES_PER_PROFILE = _MAX_STRATEGIES_PER_PROFILE
    
    def __init__(self, timeout: int = 30):
        """Initialize WAF bypass engine.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )
    
    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()

    async def __aenter__(self) -> "WAFBypassEngine":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    def detect_waf(self, headers: dict, body: str, status_code: int) -> list[str]:
        """Detect WAF from response.

        Delegates to :func:`waf_detector.detect_waf_from_response` — the
        single authoritative WAF detection implementation in AIRecon.  The
        local ``WAF_PATTERNS`` dict is kept for strategy look-up only.

        Args:
            headers: Response headers (case-insensitive dict).
            body: Response body text (excerpt is sufficient).
            status_code: HTTP status code.

        Returns:
            List of detected WAF names (may be empty).
        """
        from .waf_detector import (
            detect_waf_from_response,  # lazy import avoids circular
        )

        headers_lower = {k.lower(): v for k, v in headers.items()}
        host = headers_lower.get("host", "unknown")
        body_excerpt = body[:4000]  # waf_detector only needs a short excerpt

        profile = detect_waf_from_response(
            host=host,
            status_code=status_code,
            headers=headers_lower,
            body_excerpt=body_excerpt,
        )
        if profile is None:
            return []
        waf_name = profile.waf_name if profile.waf_name != "Unknown" else ""
        if waf_name:
            logger.info("WAF detected via waf_detector: %s (confidence=%.2f)", waf_name, profile.confidence)
            # Normalize to lowercase for backward compatibility with existing callers
            # that compare against lowercase WAF name strings.
            return [waf_name.lower()]
        return []
    
    async def test_bypass(
        self,
        target_url: str,
        waf_type: str,
        payload: str,
        param_name: str = "id",
        method: str = "GET",
        base_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Test WAF bypass strategies.
        
        Args:
            target_url: Target URL
            waf_type: WAF type (cloudflare, modsecurity, etc.)
            payload: Payload to test
            param_name: Parameter name
            method: HTTP method
        
        Returns:
            Dict with bypass results
        """
        strategies = self.BYPASS_STRATEGIES.get(
            waf_type, self.BYPASS_STRATEGIES["generic"]
        )
        if self.MAX_STRATEGIES_PER_PROFILE > 0:
            strategies = strategies[: self.MAX_STRATEGIES_PER_PROFILE]
        
        results = {
            "target_url": target_url,
            "waf_type": waf_type,
            "payload": payload,
            "strategies_tested": 0,
            "successful_bypasses": [],
            "failed_bypasses": [],
            "response": None,
        }
        
        for strategy in strategies:
            results["strategies_tested"] += 1
            strategy_name = strategy.get("name", "unknown")
            
            try:
                bypass_result = await self._apply_strategy(
                    target_url, strategy, payload, param_name, method, base_headers
                )
                
                if bypass_result.get("success"):
                    results["successful_bypasses"].append({
                        "strategy": strategy_name,
                        "description": strategy.get("description", ""),
                        "response_status": bypass_result.get("status_code"),
                        "response_length": bypass_result.get("content_length"),
                    })
                    if results["response"] is None and bypass_result.get("response") is not None:
                        results["response"] = bypass_result.get("response")
                    logger.info(
                        f"Bypass successful: {strategy_name} on {waf_type}"
                    )
                    # First confirmed bypass is enough for main fuzz flow.
                    break
                else:
                    results["failed_bypasses"].append({
                        "strategy": strategy_name,
                        "reason": bypass_result.get("reason", "Unknown"),
                    })
                    
            except Exception as e:
                logger.error(f"Strategy {strategy_name} failed: {e}")
                results["failed_bypasses"].append({
                    "strategy": strategy_name,
                    "reason": str(e),
                })
        
        return results
    
    async def _apply_strategy(
        self,
        url: str,
        strategy: dict,
        payload: str,
        param_name: str,
        method: str,
        base_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Apply a single bypass strategy.
        
        Args:
            url: Target URL
            strategy: Strategy configuration
            payload: Payload to test
            param_name: Parameter name
            method: HTTP method
        
        Returns:
            Dict with success status and response details
        """
        strategy_name = strategy.get("name", "")
        
        # Header rotation
        if strategy_name == "header_rotation":
            for header_name, values in strategy.get("headers", {}).items():
                for value in values:
                    headers = {header_name: value}
                    response = await self._send_request(
                        url,
                        payload,
                        param_name,
                        method,
                        self._merge_headers(base_headers, headers),
                    )
                    if self._is_bypass_successful(response):
                        return {
                            "success": True,
                            "status_code": response.status_code,
                            "content_length": len(response.content),
                            "response": response,
                        }
        
        # Encoding bypass
        elif strategy_name == "encoding_bypass":
            encodings = strategy.get("encodings", [])
            for encoding in encodings:
                encoded_payload = self._encode_payload(payload, encoding)
                response = await self._send_request(
                    url,
                    encoded_payload,
                    param_name,
                    method,
                    base_headers,
                )
                if self._is_bypass_successful(response):
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "encoding_used": encoding,
                        "response": response,
                    }
        
        # HTTP method rotation
        elif strategy_name == "http_method":
            for test_method in strategy.get("methods", []):
                response = await self._send_request(
                    url,
                    payload,
                    param_name,
                    test_method,
                    base_headers,
                )
                if self._is_bypass_successful(response):
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "method_used": test_method,
                        "response": response,
                    }
        
        # Content-Type rotation
        elif strategy_name == "content_type":
            for content_type in strategy.get("content_types", []):
                headers = {"Content-Type": content_type}
                response = await self._send_request(
                    url,
                    payload,
                    param_name,
                    method,
                    self._merge_headers(base_headers, headers),
                )
                if self._is_bypass_successful(response):
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "content_type_used": content_type,
                        "response": response,
                    }
        
        # Null byte injection
        elif strategy_name == "null_byte":
            for null_byte in strategy.get("payloads", []):
                test_payload = payload + null_byte
                response = await self._send_request(
                    url,
                    test_payload,
                    param_name,
                    method,
                    base_headers,
                )
                if self._is_bypass_successful(response):
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "null_byte_used": null_byte,
                        "response": response,
                    }
        
        # Case variation
        elif strategy_name == "case_variation":
            varied_payload = self._mix_case(payload)
            response = await self._send_request(
                url,
                varied_payload,
                param_name,
                method,
                base_headers,
            )
            if self._is_bypass_successful(response):
                return {
                    "success": True,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "response": response,
                }
        
        # SQL comments
        elif strategy_name == "sql_comment":
            for comment in strategy.get("comments", []):
                test_payload = payload + comment
                response = await self._send_request(
                    url,
                    test_payload,
                    param_name,
                    method,
                    base_headers,
                )
                if self._is_bypass_successful(response):
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "comment_used": comment,
                        "response": response,
                    }

        # Whitespace obfuscation
        elif strategy_name == "whitespace":
            for whitespace_token in strategy.get("whitespace", []):
                token = str(whitespace_token)
                test_payload = payload.replace(" ", token)
                response = await self._send_request(
                    url,
                    test_payload,
                    param_name,
                    method,
                    base_headers,
                )
                if self._is_bypass_successful(response):
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "whitespace_used": token,
                        "response": response,
                    }

        # Cookie challenge bypass
        elif strategy_name == "cookie_bypass":
            raw_cookies = strategy.get("cookies", {})
            if isinstance(raw_cookies, dict) and raw_cookies:
                cookie_header = "; ".join(
                    f"{str(k).strip()}={str(v).strip()}"
                    for k, v in raw_cookies.items()
                    if str(k).strip()
                )
                if cookie_header:
                    headers = self._merge_headers(base_headers, {"Cookie": cookie_header})
                    response = await self._send_request(
                        url,
                        payload,
                        param_name,
                        method,
                        headers,
                    )
                    if self._is_bypass_successful(response):
                        return {
                            "success": True,
                            "status_code": response.status_code,
                            "content_length": len(response.content),
                            "cookie_header": cookie_header,
                            "response": response,
                        }

        # Duplicate parameter / parameter pollution checks
        elif strategy_name == "parameter_pollution":
            response = await self._send_parameter_pollution_request(
                url=url,
                payload=payload,
                param_name=param_name,
                method=method,
                headers=base_headers,
            )
            if self._is_bypass_successful(response):
                return {
                    "success": True,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "technique": strategy.get("technique", "duplicate_params"),
                    "response": response,
                }

        # Concatenation operator variants
        elif strategy_name == "concatenation":
            for operator in strategy.get("operators", []):
                op = str(operator)
                if not op:
                    continue
                if op.upper().startswith("CONCAT"):
                    prefix = op if op.endswith("(") else f"{op}("
                    test_payload = f"{prefix}'{payload}','x')"
                else:
                    test_payload = f"{payload}{op}1"
                response = await self._send_request(
                    url,
                    test_payload,
                    param_name,
                    method,
                    base_headers,
                )
                if self._is_bypass_successful(response):
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "operator_used": op,
                        "response": response,
                    }
        
        # Default: try payload as-is
        response = await self._send_request(
            url, payload, param_name, method, base_headers
        )
        if self._is_bypass_successful(response):
            return {
                "success": True,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "response": response,
            }
        
        return {"success": False, "reason": "WAF blocked all attempts"}

    async def _send_parameter_pollution_request(
        self,
        *,
        url: str,
        payload: str,
        param_name: str,
        method: str,
        headers: dict[str, str] | None,
    ) -> httpx.Response:
        """Send duplicated parameter values for pollution testing."""
        from urllib.parse import parse_qsl, quote_plus, urlencode, urlparse, urlunparse

        try:
            if method.upper() == "GET":
                parsed = urlparse(url)
                query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
                query_pairs.append((param_name, payload))
                query_pairs.append((param_name, f"{payload}_dup"))
                polluted_url = urlunparse(parsed._replace(query=urlencode(query_pairs, doseq=True)))
                return await self.client.get(polluted_url, headers=headers)

            body = (
                f"{quote_plus(param_name)}={quote_plus(payload)}&"
                f"{quote_plus(param_name)}={quote_plus(f'{payload}_dup')}"
            )
            req_headers = dict(headers or {})
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            if method.upper() == "POST":
                return await self.client.post(url, content=body, headers=req_headers)
            return await self.client.request(method, url, content=body, headers=req_headers)
        except Exception as exc:
            logger.error("Parameter pollution request failed: %s", exc)
            return httpx.Response(status_code=0, content=b"")

    @staticmethod
    def _merge_headers(
        base_headers: dict[str, str] | None,
        override_headers: dict[str, str] | None,
    ) -> dict[str, str] | None:
        if not base_headers and not override_headers:
            return None
        merged: dict[str, str] = {}
        if base_headers:
            merged.update(base_headers)
        if override_headers:
            merged.update(override_headers)
        return merged
    
    async def _send_request(
        self,
        url: str,
        payload: str,
        param_name: str,
        method: str = "GET",
        headers: dict | None = None,
    ) -> httpx.Response:
        """Send HTTP request with payload.
        
        Args:
            url: Target URL
            payload: Payload to inject
            param_name: Parameter name
            method: HTTP method
            headers: Optional headers
        
        Returns:
            HTTP response
        """
        try:
            if method.upper() == "GET":
                response = await self.client.get(
                    url,
                    params={param_name: payload},
                    headers=headers,
                )
            
            elif method.upper() == "POST":
                # Send payload in body
                if headers and "application/json" in headers.get("Content-Type", ""):
                    data = {param_name: payload}
                    response = await self.client.post(url, json=data, headers=headers)
                else:
                    data = {param_name: payload}
                    response = await self.client.post(url, data=data, headers=headers)
            
            else:
                # Other methods
                response = await self.client.request(
                    method, url, data={param_name: payload}, headers=headers
                )
            
            return response
            
        except Exception as e:
            logger.error(f"Request failed: {e}")
            # Return mock response for error handling
            return httpx.Response(status_code=0, content=b"")
    
    def _is_bypass_successful(self, response: httpx.Response) -> bool:
        """Check if WAF bypass was successful.
        
        Success indicators:
        - Status code is not auth/rate-limit/WAF block
        - Response length significantly different from WAF block page
        - No WAF error pages in response
        
        Args:
            response: HTTP response
        
        Returns:
            True if bypass successful
        """
        if response.status_code == 0:
            return False
        
        # Authentication/rate-limit or explicit block statuses are not bypass.
        if response.status_code in (401, 403, 407, 429, 503):
            return False
        
        # Check for WAF error page indicators
        body_lower = response.text.lower()
        waf_indicators = [
            "access denied",
            "blocked",
            "forbidden",
            "security",
            "firewall",
            "cloudflare",
            "sucuri",
            "akamai",
        ]
        
        waf_count = sum(1 for indicator in waf_indicators if indicator in body_lower)
        
        # If less than 2 WAF indicators, likely bypassed
        return waf_count < 2
    
    def _encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload using specified encoding.
        
        Args:
            payload: Original payload
            encoding: Encoding type (url, double_url, unicode, html_entity)
        
        Returns:
            Encoded payload
        """
        import urllib.parse
        
        if encoding == "url":
            return urllib.parse.quote(payload, safe="")
        elif encoding == "double_url":
            encoded = urllib.parse.quote(payload, safe="")
            return urllib.parse.quote(encoded, safe="")
        elif encoding == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encoding == "html_entity":
            return "".join(f"&#{ord(c)};" for c in payload)
        else:
            return payload
    
    def _mix_case(self, payload: str) -> str:
        """Mix uppercase/lowercase in payload.
        
        Args:
            payload: Original payload
        
        Returns:
            Case-varied payload
        """
        import random
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
