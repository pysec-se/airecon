"""Tests for _load_recon_bins and _is_recon_phase_repeat_blocked in executors.py."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from airecon.proxy.agent.executors import (
    _load_recon_bins,
    _RECON_SUBDOMAIN_BINS,
    _RECON_PORT_SCAN_BINS,
    _ExecutorMixin,
)


# ─────────────────────────────────────────────────────────────
# _load_recon_bins
# ─────────────────────────────────────────────────────────────

class TestLoadReconBins:
    def test_loads_subdomain_bins_from_real_file(self):
        """tools_meta.json must have subdomain_enum entries."""
        result = _load_recon_bins("subdomain_enum", frozenset())
        assert isinstance(result, frozenset)
        assert len(result) > 0

    def test_loads_port_scan_bins_from_real_file(self):
        result = _load_recon_bins("port_scan", frozenset())
        assert isinstance(result, frozenset)
        assert len(result) > 0

    def test_all_entries_are_lowercase(self):
        result = _load_recon_bins("subdomain_enum", frozenset())
        for entry in result:
            assert entry == entry.lower(), f"Entry not lowercase: {entry!r}"

    def test_returns_empty_for_missing_category(self):
        """Missing category returns empty frozenset (not fallback) — fallback only on exception."""
        result = _load_recon_bins("nonexistent_category_xyz", frozenset({"toolA"}))
        assert isinstance(result, frozenset)
        assert len(result) == 0

    def test_falls_back_on_missing_file(self, tmp_path):
        fallback = frozenset({"nmap"})
        with patch(
            "airecon.proxy.agent.executors.Path",
            return_value=MagicMock(
                resolve=lambda self=None: MagicMock(
                    __truediv__=lambda s, x: MagicMock(
                        read_text=MagicMock(side_effect=FileNotFoundError("no file"))
                    )
                )
            )
        ):
            # Simpler: patch json.loads to raise
            with patch("airecon.proxy.agent.executors.json.loads", side_effect=FileNotFoundError):
                result = _load_recon_bins("port_scan", fallback)
        assert result == fallback

    def test_falls_back_on_corrupt_json(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ not valid json }")
        fallback = frozenset({"nmap"})
        with patch("airecon.proxy.agent.executors.json.loads", side_effect=json.JSONDecodeError("", "", 0)):
            result = _load_recon_bins("port_scan", fallback)
        assert result == fallback

    def test_module_level_constants_populated(self):
        """_RECON_SUBDOMAIN_BINS and _RECON_PORT_SCAN_BINS must be non-empty at import."""
        assert len(_RECON_SUBDOMAIN_BINS) > 0
        assert len(_RECON_PORT_SCAN_BINS) > 0
        # Core tools must be present
        assert "subfinder" in _RECON_SUBDOMAIN_BINS or "amass" in _RECON_SUBDOMAIN_BINS
        assert "nmap" in _RECON_PORT_SCAN_BINS


# ─────────────────────────────────────────────────────────────
# _is_recon_phase_repeat_blocked
# ─────────────────────────────────────────────────────────────

def _make_executor(phase: str = "RECON") -> _ExecutorMixin:
    """Create a minimal _ExecutorMixin instance with mocked phase."""
    mixin = _ExecutorMixin.__new__(_ExecutorMixin)
    mock_phase = MagicMock()
    mock_phase.value = phase
    mixin._get_current_phase = MagicMock(return_value=mock_phase)  # type: ignore[attr-defined]
    return mixin


class TestIsReconPhaseRepeatBlocked:
    def test_not_execute_tool_never_blocked(self):
        mixin = _make_executor("RECON")
        result = mixin._is_recon_phase_repeat_blocked(
            "web_search", {"command": "subfinder -d example.com"}, count=5
        )
        assert result is False

    def test_count_zero_never_blocked(self):
        mixin = _make_executor("RECON")
        result = mixin._is_recon_phase_repeat_blocked(
            "execute", {"command": "subfinder -d example.com"}, count=0
        )
        assert result is False

    def test_non_recon_phase_not_blocked(self):
        for phase in ("ANALYSIS", "EXPLOIT", "REPORT"):
            mixin = _make_executor(phase)
            result = mixin._is_recon_phase_repeat_blocked(
                "execute", {"command": "subfinder -d example.com"}, count=2
            )
            assert result is False, f"Should not block in phase {phase}"

    def test_subdomain_binary_blocked_in_recon(self):
        mixin = _make_executor("RECON")
        for binary in ("subfinder", "amass", "assetfinder"):
            if binary in _RECON_SUBDOMAIN_BINS:
                result = mixin._is_recon_phase_repeat_blocked(
                    "execute", {"command": f"{binary} -d example.com"}, count=1
                )
                assert result is True, f"{binary} should be blocked"

    def test_port_scan_binary_blocked_in_recon(self):
        mixin = _make_executor("RECON")
        result = mixin._is_recon_phase_repeat_blocked(
            "execute", {"command": "nmap -sV 192.168.1.1"}, count=1
        )
        assert result is True

    def test_non_recon_binary_not_blocked(self):
        mixin = _make_executor("RECON")
        result = mixin._is_recon_phase_repeat_blocked(
            "execute", {"command": "curl http://example.com"}, count=3
        )
        assert result is False

    def test_empty_command_not_blocked(self):
        mixin = _make_executor("RECON")
        result = mixin._is_recon_phase_repeat_blocked(
            "execute", {"command": ""}, count=2
        )
        assert result is False

    def test_missing_command_key_not_blocked(self):
        mixin = _make_executor("RECON")
        result = mixin._is_recon_phase_repeat_blocked(
            "execute", {}, count=2
        )
        assert result is False

    def test_phase_exception_not_blocked(self):
        """If phase detection raises, should not block (fail-open)."""
        mixin = _ExecutorMixin.__new__(_ExecutorMixin)
        mixin._get_current_phase = MagicMock(side_effect=RuntimeError("oops"))  # type: ignore[attr-defined]
        result = mixin._is_recon_phase_repeat_blocked(
            "execute", {"command": "subfinder -d example.com"}, count=2
        )
        assert result is False

    def test_no_phase_method_not_blocked(self):
        """Mixin without _get_current_phase should not block."""
        mixin = _ExecutorMixin.__new__(_ExecutorMixin)
        # No _get_current_phase attribute set
        result = mixin._is_recon_phase_repeat_blocked(
            "execute", {"command": "subfinder -d example.com"}, count=2
        )
        assert result is False

    def test_sudo_wrapped_binary_blocked(self):
        """sudo subfinder should still be detected and blocked."""
        mixin = _make_executor("RECON")
        if "subfinder" in _RECON_SUBDOMAIN_BINS:
            result = mixin._is_recon_phase_repeat_blocked(
                "execute", {"command": "sudo subfinder -d example.com"}, count=1
            )
            assert result is True
