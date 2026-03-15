"""Tests for cross-session memory: find_prior_session and merge_prior_findings."""

from __future__ import annotations

import json
import pytest
from unittest.mock import patch

from airecon.proxy.agent.session import (
    SessionData,
    save_session,
    find_prior_session,
    merge_prior_findings,
)


@pytest.fixture
def tmp_sessions_dir(tmp_path):
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()
    with patch("airecon.proxy.agent.session.SESSIONS_DIR", sessions_dir):
        yield sessions_dir


# ─────────────────────────────────────────────────────────────
# find_prior_session
# ─────────────────────────────────────────────────────────────

class TestFindPriorSession:
    def test_returns_none_when_no_sessions_dir(self, tmp_path):
        missing = tmp_path / "nonexistent"
        with patch("airecon.proxy.agent.session.SESSIONS_DIR", missing):
            result = find_prior_session("example.com")
        assert result is None

    def test_returns_none_when_no_sessions(self, tmp_sessions_dir):
        result = find_prior_session("example.com")
        assert result is None

    def test_returns_none_when_no_progress(self, tmp_sessions_dir):
        """scan_count < 3 and no completed_phases → should be ignored."""
        s = SessionData(target="example.com", scan_count=1)
        save_session(s)
        result = find_prior_session("example.com")
        assert result is None

    def test_finds_session_with_scan_count_gte_3(self, tmp_sessions_dir):
        s = SessionData(target="example.com", scan_count=5)
        save_session(s)
        result = find_prior_session("example.com")
        assert result is not None
        assert result.session_id == s.session_id

    def test_finds_session_with_completed_phases(self, tmp_sessions_dir):
        s = SessionData(target="example.com", scan_count=0, completed_phases=["RECON"])
        save_session(s)
        result = find_prior_session("example.com")
        assert result is not None
        assert result.session_id == s.session_id

    def test_returns_none_for_different_target(self, tmp_sessions_dir):
        s = SessionData(target="other.com", scan_count=5)
        save_session(s)
        result = find_prior_session("example.com")
        assert result is None

    def test_target_comparison_is_case_insensitive(self, tmp_sessions_dir):
        s = SessionData(target="EXAMPLE.COM", scan_count=5)
        save_session(s)
        result = find_prior_session("example.com")
        assert result is not None

    def test_returns_most_recent_session(self, tmp_sessions_dir):
        """When multiple sessions qualify, the most recently updated is returned."""
        older = SessionData(target="example.com", scan_count=5)
        older.updated_at = "2025-01-01T00:00:00"
        save_session(older)

        newer = SessionData(target="example.com", scan_count=5)
        newer.updated_at = "2025-06-01T00:00:00"
        save_session(newer)

        result = find_prior_session("example.com")
        assert result is not None
        assert result.session_id == newer.session_id

    def test_skips_malformed_session_files(self, tmp_sessions_dir):
        """Corrupted JSON files must not crash the function."""
        bad_file = tmp_sessions_dir / "corrupt_abc12345.json"
        bad_file.write_text("{ not valid json }")

        s = SessionData(target="example.com", scan_count=5)
        save_session(s)

        result = find_prior_session("example.com")
        assert result is not None
        assert result.session_id == s.session_id


# ─────────────────────────────────────────────────────────────
# merge_prior_findings
# ─────────────────────────────────────────────────────────────

class TestMergePriorFindings:
    def _prior(self, **kwargs) -> SessionData:
        return SessionData(target="example.com", **kwargs)

    def _new(self, **kwargs) -> SessionData:
        return SessionData(target="example.com", **kwargs)

    def test_target_mismatch_is_skipped(self):
        prior = SessionData(target="other.com", subdomains=["api.other.com"])
        new_s = SessionData(target="example.com")
        merge_prior_findings(new_s, prior)
        assert new_s.subdomains == []

    def test_merges_subdomains(self):
        prior = self._prior(subdomains=["api.example.com", "dev.example.com"])
        new_s = self._new()
        merge_prior_findings(new_s, prior)
        assert "api.example.com" in new_s.subdomains
        assert "dev.example.com" in new_s.subdomains

    def test_deduplicates_subdomains(self):
        prior = self._prior(subdomains=["api.example.com", "api.example.com"])
        new_s = self._new(subdomains=["api.example.com"])
        merge_prior_findings(new_s, prior)
        assert new_s.subdomains.count("api.example.com") == 1

    def test_merges_live_hosts(self):
        prior = self._prior(live_hosts=["http://api.example.com"])
        new_s = self._new()
        merge_prior_findings(new_s, prior)
        assert "http://api.example.com" in new_s.live_hosts

    def test_merges_open_ports_new_host(self):
        prior = self._prior(open_ports={"api.example.com": [80, 443]})
        new_s = self._new()
        merge_prior_findings(new_s, prior)
        assert new_s.open_ports["api.example.com"] == [80, 443]

    def test_merges_open_ports_existing_host_union(self):
        prior = self._prior(open_ports={"api.example.com": [443, 8080]})
        new_s = self._new(open_ports={"api.example.com": [80, 443]})
        merge_prior_findings(new_s, prior)
        assert new_s.open_ports["api.example.com"] == [80, 443, 8080]

    def test_merges_urls_capped_at_500(self):
        prior = self._prior(urls=[f"https://example.com/{i}" for i in range(600)])
        new_s = self._new()
        merge_prior_findings(new_s, prior)
        assert len(new_s.urls) <= 500

    def test_merges_technologies(self):
        prior = self._prior(technologies={"nginx": "1.18.0", "php": "8.1"})
        new_s = self._new()
        merge_prior_findings(new_s, prior)
        assert new_s.technologies["nginx"] == "1.18.0"
        assert new_s.technologies["php"] == "8.1"

    def test_does_not_overwrite_existing_technologies(self):
        prior = self._prior(technologies={"nginx": "1.14.0"})
        new_s = self._new(technologies={"nginx": "1.18.0"})
        merge_prior_findings(new_s, prior)
        assert new_s.technologies["nginx"] == "1.18.0"

    def test_merges_injection_points_deduped(self):
        ip = {"url": "https://example.com/search", "parameter": "q", "method": "GET"}
        prior = self._prior(injection_points=[ip])
        new_s = self._new(injection_points=[ip])
        merge_prior_findings(new_s, prior)
        assert len(new_s.injection_points) == 1

    def test_merges_attack_chains_by_name(self):
        chain = {"name": "sqli-chain", "steps": ["step1"]}
        prior = self._prior(attack_chains=[chain])
        new_s = self._new()
        merge_prior_findings(new_s, prior)
        assert any(c["name"] == "sqli-chain" for c in new_s.attack_chains)

    def test_does_not_merge_vulnerabilities(self):
        """Vulns are stale — must never be copied to new session."""
        prior = self._prior(vulnerabilities=[{"title": "SQLi in /search"}])
        new_s = self._new()
        merge_prior_findings(new_s, prior)
        assert new_s.vulnerabilities == []

    def test_empty_prior_session_is_harmless(self):
        prior = self._prior()
        new_s = self._new()
        merge_prior_findings(new_s, prior)
        assert new_s.subdomains == []
        assert new_s.urls == []
