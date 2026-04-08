"""Tests for reporting.py helper functions: _sanitize_target_name, _extract_target_token, _is_filesystem_like_target."""

from __future__ import annotations

from airecon.proxy.reporting import (
    _sanitize_target_name,
    _extract_target_token,
    _is_filesystem_like_target,
)


class TestSanitizeTargetName:
    def test_plain_domain(self):
        assert _sanitize_target_name("example.com") == "example.com"

    def test_strips_leading_dots(self):
        assert not _sanitize_target_name("...example").startswith(".")

    def test_strips_trailing_dashes(self):
        assert not _sanitize_target_name("example---").endswith("-")

    def test_replaces_special_chars(self):
        result = _sanitize_target_name("example com/path")
        assert " " not in result
        assert "/" not in result

    def test_allows_alphanumeric_dot_dash(self):
        result = _sanitize_target_name("my-target.example.com")
        assert result == "my-target.example.com"

    def test_empty_string(self):
        assert _sanitize_target_name("") == ""

    def test_path_traversal_chars_replaced(self):
        result = _sanitize_target_name("../../etc/passwd")
        assert ".." not in result or "/" not in result

    def test_ip_address(self):
        assert _sanitize_target_name("192.168.1.1") == "192.168.1.1"


class TestExtractTargetToken:
    def test_empty_string(self):
        assert _extract_target_token("") == ""

    def test_plain_domain(self):
        assert _extract_target_token("example.com") == "example.com"

    def test_url_with_scheme(self):
        assert _extract_target_token("https://example.com/path") == "example.com"

    def test_url_with_port(self):
        assert (
            _extract_target_token("https://example.com:8443/api") == "example.com:8443"
        )

    def test_url_without_scheme(self):
        assert _extract_target_token("example.com/login") == "example.com"

    def test_at_prefix_path(self):
        result = _extract_target_token("@/tmp/challenge.exe")
        assert result == "challenge"

    def test_file_placeholder(self):
        result = _extract_target_token("[file:binary]")
        assert result == "binary"

    def test_workspace_path(self):
        assert (
            _extract_target_token("/workspace/example.com/output/scan.txt")
            == "example.com"
        )

    def test_absolute_path_file(self):
        result = _extract_target_token("/tmp/challenge.exe")
        assert result == "challenge"

    def test_absolute_path_dir(self):
        result = _extract_target_token("/tmp/myproject")
        assert result == "myproject"

    def test_ip_address(self):
        assert _extract_target_token("192.168.1.1") == "192.168.1.1"

    def test_ip_with_url(self):
        assert _extract_target_token("http://10.10.10.10/admin") == "10.10.10.10"


class TestIsFilesystemLikeTarget:
    def test_at_prefix(self):
        assert _is_filesystem_like_target("@/tmp/file.bin") is True

    def test_workspace_prefix(self):
        assert _is_filesystem_like_target("/workspace/target/output") is True

    def test_absolute_path(self):
        assert _is_filesystem_like_target("/tmp/file.txt") is True

    def test_file_placeholder(self):
        assert _is_filesystem_like_target("[file:challenge]") is True

    def test_relative_path(self):
        assert _is_filesystem_like_target("./output/scan.txt") is True

    def test_parent_relative_path(self):
        assert _is_filesystem_like_target("../etc/passwd") is True

    def test_workspace_relative_upload_path(self):
        assert _is_filesystem_like_target("uploads/core/main.py") is True

    def test_relative_project_path(self):
        assert _is_filesystem_like_target("core/main.py") is True

    def test_plain_domain(self):
        assert _is_filesystem_like_target("example.com") is False

    def test_url(self):
        assert _is_filesystem_like_target("https://example.com") is False

    def test_ip(self):
        assert _is_filesystem_like_target("10.10.10.10") is False

    def test_empty(self):
        assert _is_filesystem_like_target("") is False
