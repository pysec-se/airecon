"""Tests for WAF detection and bypass strategy module (waf_detector.py)."""
from __future__ import annotations

import pytest

from airecon.proxy.agent.waf_detector import (
    WAFProfile,
    _GENERIC_BYPASS_FALLBACK,
    build_waf_bypass_context,
    detect_waf_from_response,
    merge_waf_profiles,
    rank_bypass_strategies,
)


class TestDetectWafFromResponse:
    def test_no_waf_returns_none(self) -> None:
        result = detect_waf_from_response(
            host="example.com",
            status_code=200,
            headers={"content-type": "text/html"},
            body_excerpt="<html><body>Hello</body></html>",
        )
        assert result is None

    def test_cloudflare_detected_via_cf_ray_header(self) -> None:
        result = detect_waf_from_response(
            host="example.com",
            status_code=200,
            headers={"cf-ray": "7a1234abcd-LHR"},
            body_excerpt="",
        )
        assert result is not None
        assert "Cloudflare" in result.waf_name
        assert result.confidence >= 0.30

    def test_modsecurity_detected_via_body(self) -> None:
        result = detect_waf_from_response(
            host="example.com",
            status_code=403,
            headers={},
            body_excerpt="ModSecurity: Access denied by rule set",
        )
        assert result is not None
        assert "ModSecurity" in result.waf_name

    def test_imperva_detected_via_set_cookie(self) -> None:
        result = detect_waf_from_response(
            host="example.com",
            status_code=200,
            headers={"x-imperva-id": "12345"},
            body_excerpt="",
        )
        assert result is not None
        assert "Imperva" in result.waf_name

    def test_generic_waf_detected_via_body(self) -> None:
        result = detect_waf_from_response(
            host="example.com",
            status_code=403,
            headers={},
            body_excerpt="This request has been blocked for security reasons by our WAF.",
        )
        assert result is not None
        assert result.confidence >= 0.30

    def test_block_status_code_boosts_confidence(self) -> None:
        """403 + WAF body pattern = higher confidence than body alone."""
        result_403 = detect_waf_from_response(
            host="example.com",
            status_code=403,
            headers={},
            body_excerpt="ModSecurity: Access denied",
        )
        result_200 = detect_waf_from_response(
            host="example.com",
            status_code=200,
            headers={},
            body_excerpt="ModSecurity: Access denied",
        )
        assert result_403 is not None
        assert result_200 is not None
        assert result_403.confidence > result_200.confidence

    def test_confidence_capped_at_1(self) -> None:
        """Multiple strong signals must not exceed confidence 1.0."""
        result = detect_waf_from_response(
            host="example.com",
            status_code=403,
            headers={
                "cf-ray": "7a1234abcd",
                "server": "cloudflare",
                "x-cdn": "cloudflare",
            },
            body_excerpt="cloudflare is protecting this site",
        )
        assert result is not None
        assert result.confidence <= 1.0

    def test_waf_profile_has_evidence_list(self) -> None:
        result = detect_waf_from_response(
            host="example.com",
            status_code=403,
            headers={"cf-ray": "abc123"},
            body_excerpt="",
        )
        assert result is not None
        assert isinstance(result.evidence, list)
        assert len(result.evidence) > 0

    def test_prefers_highest_confidence_vendor_when_signals_conflict(self) -> None:
        """When multiple vendor signatures appear, pick the highest-scoring WAF."""
        result = detect_waf_from_response(
            host="example.com",
            status_code=200,
            headers={
                "server": "cloudflare",          # Cloudflare (0.80)
                "x-amzn-waf-action": "BLOCK",    # AWS WAF (0.95) -> should win
            },
            body_excerpt="",
        )
        assert result is not None
        assert result.waf_name == "AWS WAF"


class TestBuildWafBypassContext:
    def test_returns_empty_for_low_confidence(self) -> None:
        profile = WAFProfile(host="example.com", waf_name="Cloudflare", confidence=0.10)
        ctx = build_waf_bypass_context(profile)
        assert ctx == ""

    def test_returns_xml_block_for_detected_waf(self) -> None:
        profile = WAFProfile(
            host="example.com",
            waf_name="Cloudflare",
            confidence=0.80,
            evidence=["Header cf-ray: Cloudflare"],
        )
        ctx = build_waf_bypass_context(profile)
        assert ctx.startswith("<waf_bypass")
        assert "Cloudflare" in ctx
        assert "example.com" in ctx

    def test_contains_bypass_strategies(self) -> None:
        profile = WAFProfile(
            host="example.com",
            waf_name="Generic WAF",
            confidence=0.70,
            evidence=["Status 403"],
        )
        ctx = build_waf_bypass_context(profile)
        assert "<bypass_strategies>" in ctx
        # Should contain at least one strategy
        assert "- " in ctx

    def test_contains_instruction(self) -> None:
        profile = WAFProfile(
            host="example.com",
            waf_name="ModSecurity",
            confidence=0.75,
            evidence=["Body: ModSecurity"],
        )
        ctx = build_waf_bypass_context(profile)
        assert "record_hypothesis" in ctx or "instruction" in ctx.lower()

    def test_loads_patterns_from_json(self) -> None:
        """Verify that patterns.json waf_bypass_strategies is loaded correctly."""
        from airecon.proxy.agent.waf_detector import _load_bypass_strategies
        strategies = _load_bypass_strategies("generic")
        assert isinstance(strategies, list)
        assert len(strategies) > 0

    def test_fallback_strategies_when_waf_unknown(self) -> None:
        """Unknown WAF name falls back to generic strategies."""
        from airecon.proxy.agent.waf_detector import _load_bypass_strategies
        strategies = _load_bypass_strategies("totally_unknown_waf_xyz")
        # Should return generic strategies (from patterns.json) or fallback
        assert isinstance(strategies, list)
        assert len(strategies) > 0


class TestWafProfileMergingAndRanking:
    def test_merge_preserves_history_and_increases_confidence_on_repeat_blocks(self) -> None:
        existing = {
            "host": "example.com",
            "waf_name": "Cloudflare",
            "confidence": 0.70,
            "evidence": ["Header cf-ray: Cloudflare (conf=90%)"],
            "detected_at": 3,
        }
        merged = merge_waf_profiles(
            existing=existing,
            observed=None,
            host="example.com",
            status_code=403,
            iteration=10,
        )
        assert merged is not None
        assert merged.confidence >= 0.70
        assert any("Repeated block status code" in e for e in merged.evidence)

    def test_merge_prefers_fresher_higher_confidence_vendor(self) -> None:
        old = WAFProfile(
            host="example.com",
            waf_name="Generic WAF",
            confidence=0.40,
            evidence=["Block status code: 403"],
            detected_at_iteration=1,
        )
        observed = WAFProfile(
            host="example.com",
            waf_name="AWS WAF",
            confidence=0.90,
            evidence=["Header x-amzn-waf-action: AWS WAF (conf=95%)"],
            detected_at_iteration=2,
        )
        merged = merge_waf_profiles(
            existing=old,
            observed=observed,
            host="example.com",
            status_code=403,
            iteration=11,
        )
        assert merged is not None
        assert merged.waf_name == "AWS WAF"
        assert merged.confidence >= 0.75

    def test_rank_bypass_strategies_uses_success_stats(self) -> None:
        profile = WAFProfile(
            host="example.com",
            waf_name="Cloudflare",
            confidence=0.85,
            evidence=["Header cf-ray: Cloudflare"],
        )
        stats = {
            "Header injection: move payload to X-Forwarded-For or User-Agent header": {
                "attempts": 5,
                "successes": 4,
            }
        }
        ranked = rank_bypass_strategies(profile, stats)
        assert isinstance(ranked, list)
        assert len(ranked) > 0
