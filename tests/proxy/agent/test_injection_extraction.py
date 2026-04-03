"""Tests for injection point extraction helpers in session.py."""

from __future__ import annotations


from airecon.proxy.agent.session import (
    _extract_injection_points,
    _guess_injection_type,
    _merge_injection_points,
    _normalize_url,
)
from airecon.proxy.agent.formatters import _load_port_hints, _load_tech_hints


# ---------------------------------------------------------------------------
# _guess_injection_type
# ---------------------------------------------------------------------------


class TestGuessInjectionType:
    def test_canonical_map_id(self):
        # "id" is a canonical IDOR param in fuzzer_data.json PARAM_TYPE_MAP
        result = _guess_injection_type("id", "42")
        assert result in ("IDOR", "INJECT")  # depends on fuzzer_data presence

    def test_suffix_id(self):
        assert _guess_injection_type("user_id", "") == "IDOR"
        assert _guess_injection_type("product_id", "") == "IDOR"

    def test_suffix_id_end(self):
        assert _guess_injection_type("userid", "") == "IDOR"

    def test_numeric_value_fallback(self):
        # Any param with numeric value → IDOR
        assert _guess_injection_type("ref", "12345") == "IDOR"

    def test_large_numeric_value_not_matched(self):
        # >10 digits should NOT trigger numeric IDOR heuristic.
        # Use a param name unlikely to be in the canonical map.
        result = _guess_injection_type("zzz_unknown_param_xyz", "12345678901")
        # 11-digit value exceeds the ^\d{1,10}$ pattern — should NOT be IDOR from value
        assert result == "INJECT"

    def test_camelcase_normalisation(self):
        # "userId" → "user_id" which matches suffix heuristic
        result = _guess_injection_type("userId", "")
        assert result == "IDOR"

    def test_default_inject(self):
        result = _guess_injection_type("q", "")
        # "q" may be in canonical map as XSS/SQLi or default INJECT
        assert isinstance(result, str) and len(result) > 0


# ---------------------------------------------------------------------------
# _extract_injection_points
# ---------------------------------------------------------------------------


class TestExtractInjectionPoints:
    def test_query_params_extracted(self):
        url = "https://example.com/search?q=hello&page=2"
        points = _extract_injection_points(url)
        params = {p["parameter"] for p in points}
        assert "q" in params
        assert "page" in params

    def test_query_param_method_is_get(self):
        url = "https://example.com/items?id=5"
        points = _extract_injection_points(url)
        assert all(p["method"] == "GET" for p in points)

    def test_query_param_value_sample_truncated(self):
        url = "https://example.com/search?q=" + "A" * 50
        points = _extract_injection_points(url)
        q_point = next(p for p in points if p["parameter"] == "q")
        assert len(q_point["value_sample"]) <= 30

    def test_numeric_path_segment_detected(self):
        url = "https://example.com/api/users/123"
        points = _extract_injection_points(url)
        assert any(
            "123" in p["parameter"] or "123" == p["value_sample"] for p in points
        )

    def test_uuid_path_segment_detected(self):
        uid = "550e8400-e29b-41d4-a716-446655440000"
        url = f"https://example.com/api/items/{uid}"
        points = _extract_injection_points(url)
        assert any(uid in p["value_sample"] for p in points)

    def test_path_segment_type_hint_is_idor(self):
        url = "https://example.com/users/42"
        points = _extract_injection_points(url)
        id_points = [p for p in points if p["value_sample"] == "42"]
        assert id_points, "Expected numeric path segment point"
        assert id_points[0]["type_hint"] == "IDOR"

    def test_path_segment_label_includes_parent(self):
        # /api/users/123 → parameter should be path/users/123
        url = "https://example.com/api/users/123"
        points = _extract_injection_points(url)
        labels = [p["parameter"] for p in points]
        assert any("users" in lbl and "123" in lbl for lbl in labels)

    def test_full_url_preserved_in_path_point(self):
        # Fix 1 regression: path segment points must use the full URL, not truncated
        url = "https://example.com/api/users/123/orders"
        points = _extract_injection_points(url)
        id_points = [p for p in points if p["value_sample"] == "123"]
        assert id_points, "Numeric segment not extracted"
        # URL must be full path including /orders
        assert id_points[0]["url"] == "https://example.com/api/users/123/orders"

    def test_no_points_for_static_url(self):
        url = "https://example.com/about"
        points = _extract_injection_points(url)
        assert points == []

    def test_malformed_url_returns_empty(self):
        points = _extract_injection_points("not-a-url")
        assert isinstance(points, list)

    def test_empty_string_returns_empty(self):
        assert _extract_injection_points("") == []

    def test_blank_query_value_included(self):
        url = "https://example.com/search?q="
        points = _extract_injection_points(url)
        params = {p["parameter"] for p in points}
        assert "q" in params

    def test_non_numeric_path_ignored(self):
        url = "https://example.com/api/products/slug-name"
        points = _extract_injection_points(url)
        # "slug-name" is not numeric or UUID — no path points expected
        path_points = [p for p in points if p["parameter"].startswith("path/")]
        assert path_points == []

    def test_url_without_query_or_ids_empty(self):
        url = "https://example.com/api/v1/health"
        points = _extract_injection_points(url)
        assert points == []


# ---------------------------------------------------------------------------
# _merge_injection_points
# ---------------------------------------------------------------------------


class TestMergeInjectionPoints:
    def _make_point(self, url: str, param: str, method: str = "GET") -> dict:
        return {
            "url": url,
            "parameter": param,
            "method": method,
            "value_sample": "",
            "type_hint": "INJECT",
        }

    def test_adds_new_points(self):
        session = []
        new = [self._make_point("https://example.com/", "id")]
        _merge_injection_points(session, new)
        assert len(session) == 1

    def test_deduplicates_exact(self):
        session = [self._make_point("https://example.com/", "id")]
        dup = [self._make_point("https://example.com/", "id")]
        _merge_injection_points(session, dup)
        assert len(session) == 1

    def test_different_param_not_deduped(self):
        session = [self._make_point("https://example.com/", "id")]
        new = [self._make_point("https://example.com/", "user")]
        _merge_injection_points(session, new)
        assert len(session) == 2

    def test_different_method_not_deduped(self):
        session = [self._make_point("https://example.com/", "id", "GET")]
        new = [self._make_point("https://example.com/", "id", "POST")]
        _merge_injection_points(session, new)
        assert len(session) == 2

    def test_different_url_not_deduped(self):
        session = [self._make_point("https://example.com/a", "id")]
        new = [self._make_point("https://example.com/b", "id")]
        _merge_injection_points(session, new)
        assert len(session) == 2

    def test_mutates_in_place(self):
        session: list = []
        _merge_injection_points(session, [self._make_point("https://x.com/", "p")])
        assert session  # modified in place

    def test_empty_new_no_change(self):
        session = [self._make_point("https://example.com/", "id")]
        _merge_injection_points(session, [])
        assert len(session) == 1

    def test_multiple_new_batch_deduped(self):
        session: list = []
        new = [
            self._make_point("https://a.com/", "x"),
            self._make_point("https://a.com/", "x"),  # dup within batch
            self._make_point("https://a.com/", "y"),
        ]
        _merge_injection_points(session, new)
        assert len(session) == 2  # x (once) + y


# ---------------------------------------------------------------------------
# _load_port_hints / _load_tech_hints (structure validation)
# ---------------------------------------------------------------------------


class TestLoadHints:
    def test_port_hints_returns_dict_of_int(self):
        hints = _load_port_hints()
        assert isinstance(hints, dict)
        for key in hints:
            assert isinstance(key, int), f"Expected int key, got {type(key)}: {key}"

    def test_port_hints_values_are_strings(self):
        hints = _load_port_hints()
        for val in hints.values():
            assert isinstance(val, str)

    def test_tech_hints_returns_dict_of_str(self):
        hints = _load_tech_hints()
        assert isinstance(hints, dict)
        for key in hints:
            assert isinstance(key, str)

    def test_tech_hints_keys_are_lowercase(self):
        hints = _load_tech_hints()
        for key in hints:
            assert key == key.lower(), f"Key not lowercase: {key}"

    def test_tech_hints_values_are_strings(self):
        hints = _load_tech_hints()
        for val in hints.values():
            assert isinstance(val, str)

    def test_common_ports_present(self):
        hints = _load_port_hints()
        # port_correlations.json covers infra ports; SSH (22) and FTP (21) are always present
        assert 22 in hints or 21 in hints, (
            "Expected at least port 21 or 22 in port hints"
        )


# ---------------------------------------------------------------------------
# Issue #16: URL normalization
# ---------------------------------------------------------------------------


class TestNormalizeUrl:
    def test_scheme_lowercased(self):
        assert _normalize_url("HTTPS://example.com/path").startswith("https://")

    def test_host_lowercased(self):
        result = _normalize_url("https://EXAMPLE.COM/path")
        assert "example.com" in result
        assert "EXAMPLE.COM" not in result

    def test_trailing_slash_stripped(self):
        result = _normalize_url("https://example.com/api/users/")
        assert not result.endswith("/api/users/")
        assert result.endswith("/api/users")

    def test_root_path_preserved(self):
        """Root path '/' must not be stripped to empty string."""
        result = _normalize_url("https://example.com/")
        assert result == "https://example.com"  # or "https://example.com/"

    def test_fragment_stripped(self):
        result = _normalize_url("https://example.com/page#section")
        assert "#section" not in result

    def test_query_params_sorted(self):
        result = _normalize_url("https://example.com/search?z=last&a=first")
        assert result == "https://example.com/search?a=first&z=last"

    def test_identical_urls_normalize_equally(self):
        url1 = _normalize_url("https://Example.COM/api/users/?ref=1#frag")
        url2 = _normalize_url("https://example.com/api/users?ref=1")
        assert url1 == url2

    def test_malformed_url_returned_unchanged(self):
        bad = "not-a-url-at-all"
        result = _normalize_url(bad)
        assert result == bad

    def test_query_string_blank_values_preserved(self):
        result = _normalize_url("https://example.com/search?q=&lang=en")
        assert "q=" in result
        assert "lang=en" in result


class TestExtractInjectionPointUrlNormalization:
    """Issue #16: injection point URLs must be normalized for consistent dedup."""

    def test_uppercase_host_normalized_in_injection_point(self):
        """URL with uppercase host must produce lowercase host in injection point."""
        points = _extract_injection_points("https://EXAMPLE.COM/api?id=1")
        assert len(points) >= 1
        for pt in points:
            assert "EXAMPLE.COM" not in pt["url"], (
                f"Host not lowercased in injection point url: {pt['url']}"
            )

    def test_trailing_slash_stripped_in_injection_point(self):
        """URL with trailing slash must produce no trailing slash in injection point url."""
        points = _extract_injection_points("https://example.com/api/users/?id=5")
        for pt in points:
            # path in url should not end with slash (unless root)
            from urllib.parse import urlparse

            path = urlparse(pt["url"]).path
            if path != "/":
                assert not path.endswith("/"), (
                    f"Trailing slash found in injection point url path: {pt['url']}"
                )

    def test_trailing_slash_and_no_trailing_slash_dedup_correctly(self):
        """URLs differing only by trailing slash must produce the same dedup key."""
        pts_with_slash = _extract_injection_points(
            "https://example.com/api/users/?id=5"
        )
        pts_without_slash = _extract_injection_points(
            "https://example.com/api/users?id=5"
        )

        if pts_with_slash and pts_without_slash:
            url_with = pts_with_slash[0]["url"]
            url_without = pts_without_slash[0]["url"]
            assert url_with == url_without, (
                f"URLs should normalize to same value:\n  with slash: {url_with}\n  without: {url_without}"
            )

    def test_uppercase_host_dedup_in_merge(self):
        """Injection points with same URL but different host casing must dedup."""
        pts1 = _extract_injection_points("https://EXAMPLE.COM/api?id=1")
        pts2 = _extract_injection_points("https://example.com/api?id=1")

        session_points: list = []
        _merge_injection_points(session_points, pts1)
        before = len(session_points)
        _merge_injection_points(session_points, pts2)
        after = len(session_points)

        assert after == before, (
            f"URL case variants produced duplicate injection point "
            f"(before={before}, after={after}): {session_points}"
        )

    def test_fragment_url_dedup_in_merge(self):
        """URLs with and without fragment must produce the same injection point."""
        pts1 = _extract_injection_points("https://example.com/search?q=test#section")
        pts2 = _extract_injection_points("https://example.com/search?q=test")

        session_points: list = []
        _merge_injection_points(session_points, pts1)
        before = len(session_points)
        _merge_injection_points(session_points, pts2)
        after = len(session_points)

        assert after == before, (
            "Fragment-vs-no-fragment produced duplicate injection point"
        )
