"""Tests for memory.py — SQLite memory system."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def memory_manager():
    from airecon.proxy.memory import MemoryManager

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_db = tmp_path / "test_memory.db"
        test_dir = tmp_path / "memory"
        test_dir.mkdir()

        with (
            patch("airecon.proxy.memory.MEMORY_DIR", test_dir),
            patch("airecon.proxy.memory.MEMORY_DB", test_db),
        ):
            mm = MemoryManager()
            mm.connect()
            yield mm
            mm.close()


class TestMemoryManagerConnect:
    def test_connect_initializes_db(self, memory_manager):
        assert memory_manager.conn is not None

    def test_close_sets_conn_none(self, memory_manager):
        memory_manager.close()
        assert memory_manager.conn is None


class TestSaveSession:
    def test_save_and_retrieve_session(self, memory_manager):
        session_data = {
            "session_id": "test_001",
            "target": "example.com",
            "current_phase": "RECON",
            "subdomains": ["sub1.example.com"],
            "live_hosts": ["http://example.com"],
            "vulnerabilities": [{"type": "xss", "severity": "High"}],
            "attack_chains": [],
            "token_total": 5000,
            "model_used": "llama3",
        }
        memory_manager.save_session(session_data)

        sessions = memory_manager.get_past_sessions(target="example.com")
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "test_001"

    def test_save_with_no_connection_returns_silently(self):
        from airecon.proxy.memory import MemoryManager

        mm = MemoryManager()
        mm.save_session({"session_id": "x"})


class TestSaveFinding:
    def test_save_and_retrieve_finding(self, memory_manager):
        finding = {
            "session_id": "test_001",
            "target": "example.com",
            "type": "xss",
            "severity": "High",
            "url": "http://example.com/search",
            "parameter": "q",
            "description": "Reflected XSS in search parameter",
            "evidence": [{"payload": "<script>alert(1)</script>"}],
            "cwe_id": "CWE-79",
            "cvss_score": 7.5,
            "remediation": "Sanitize input",
        }
        memory_manager.save_finding(finding)

        findings = memory_manager.get_similar_findings("example.com")
        assert len(findings) == 1
        assert findings[0]["finding_type"] == "xss"

    def test_get_findings_returns_empty_for_no_match(self, memory_manager):
        findings = memory_manager.get_similar_findings("nonexistent.com")
        assert findings == []


class TestSavePattern:
    def test_save_valid_pattern(self, memory_manager):
        pattern = {
            "type": "recon",
            "tech": "nginx",
            "technique_name": "subdomain_enumeration",
            "description": "Enumerate subdomains using passive sources",
            "success_rate": 0.85,
            "times_used": 5,
            "commands_used": ["subfinder -d example.com"],
            "effectiveness_score": 85.0,
            "source_session": "test_001",
        }
        memory_manager.save_pattern(pattern)

        patterns = memory_manager.get_patterns()
        assert len(patterns) == 1
        assert patterns[0]["technique_name"] == "subdomain_enumeration"

    def test_reject_low_success_rate(self, memory_manager):
        pattern = {
            "type": "exploit",
            "tech": "apache",
            "technique_name": "failed_exploit",
            "description": "This always fails",
            "success_rate": 0.10,
            "times_used": 10,
            "commands_used": ["curl http://target/exploit"],
            "source_session": "test_001",
        }
        memory_manager.save_pattern(pattern)
        patterns = memory_manager.get_patterns()
        assert len(patterns) == 0

    def test_reject_insufficient_usage(self, memory_manager):
        pattern = {
            "type": "recon",
            "tech": None,
            "technique_name": "new_technique",
            "description": "Only tried once",
            "success_rate": 0.90,
            "times_used": 1,
            "commands_used": ["test"],
            "source_session": "test_001",
        }
        memory_manager.save_pattern(pattern)
        patterns = memory_manager.get_patterns()
        assert len(patterns) == 0


class TestTargetIntel:
    def test_save_and_retrieve_intel(self, memory_manager):
        intel = {
            "target": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
            "ports": {"80": "http", "443": "https"},
            "technologies": {"nginx": "1.18", "php": "8.1"},
            "waf": "Cloudflare",
            "auth_methods": ["jwt"],
            "interesting_endpoints": ["/api/v1", "/admin"],
        }
        memory_manager.save_target_intel(intel)

        result = memory_manager.get_target_intel("example.com")
        assert result is not None
        assert result["target_domain"] == "example.com"
        assert result["waf_detected"] == "Cloudflare"

    def test_get_intel_returns_none_for_unknown(self, memory_manager):
        result = memory_manager.get_target_intel("unknown.com")
        assert result is None

    def test_save_intel_increments_scan_count(self, memory_manager):
        intel = {
            "target": "example.com",
            "subdomains": [],
            "ports": {},
            "technologies": {},
            "waf": None,
            "auth_methods": [],
            "interesting_endpoints": [],
        }
        memory_manager.save_target_intel(intel)
        memory_manager.save_target_intel(intel)

        result = memory_manager.get_target_intel("example.com")
        assert result["scan_count"] == 2


class TestKnowledge:
    def test_save_and_retrieve_knowledge(self, memory_manager):
        knowledge = {
            "category": "exploitation",
            "title": "SQLi bypass",
            "content": "Use ' OR 1=1 -- to bypass auth",
            "confidence": 0.9,
            "source_session": "test_001",
            "tags": ["sqli", "auth_bypass"],
        }
        memory_manager.save_knowledge(knowledge)

        entries = memory_manager.get_knowledge()
        assert len(entries) == 1
        assert entries[0]["title"] == "SQLi bypass"
        assert isinstance(entries[0]["tags"], list)


class TestSmallModelContext:
    def test_context_includes_learned_chains_and_tool_pitfalls(self, memory_manager):
        memory_manager.save_target_intel(
            {
                "target": "example.com",
                "subdomains": ["api.example.com"],
                "ports": {"443": "https"},
                "technologies": {"fastapi": "0.111"},
                "waf": None,
                "auth_methods": [],
                "interesting_endpoints": ["/checkout"],
            }
        )
        memory_manager.save_chain_discovery(
            {
                "chain_id": "chain-1",
                "name": "Tenant Checkout Chain",
                "combined_severity": 4,
                "attack_path": "member -> checkout -> refund -> tenant crossover",
                "reasoning": "Historical tenant-state abuse path",
                "findings": [],
                "relation_types": [],
                "target": "example.com",
                "discovered_at": "2026-04-07T00:00:00",
            }
        )
        for _ in range(3):
            memory_manager.record_tool_usage(
                tool_name="ffuf",
                target="example.com",
                success=False,
                duration_sec=1.2,
                output_size=100,
            )

        ctx = memory_manager.get_context_for_small_model(
            target="example.com",
            current_phase="ANALYSIS",
            max_tokens=4096,
        )

        assert "LEARNED ATTACK CHAINS" in ctx
        assert "Tenant Checkout Chain" in ctx
        assert "TOOL PITFALLS" in ctx
        assert "ffuf" in ctx


class TestSkillRecommendations:
    def test_skill_recommendations_are_target_and_phase_aware(self, memory_manager):
        memory_manager.save_skill_usage(
            skill_name="skills/tools/sqlmap.md",
            target="https://api.example.com/login",
            phase="ANALYSIS",
            success=True,
            effectiveness_score=0.92,
            tokens_saved=320,
        )
        memory_manager.save_skill_usage(
            skill_name="reconnaissance/full_recon.md",
            target="other-example.com",
            phase="RECON",
            success=True,
            effectiveness_score=0.80,
            tokens_saved=120,
        )

        recs = memory_manager.get_skill_recommendations(
            target="example.com",
            current_phase="ANALYSIS",
        )

        assert recs
        assert recs[0]["skill_path"] == "tools/sqlmap.md"
        assert recs[0]["skill_name"] == "sqlmap"
        assert recs[0]["target_match"] is True


class TestContextForSmallModel:
    def test_builds_context_with_intel(self, memory_manager):
        intel = {
            "target": "example.com",
            "subdomains": [f"sub{i}.example.com" for i in range(5)],
            "ports": {"80": "http", "443": "https", "8080": "http-alt"},
            "technologies": {"nginx": "1.18", "php": "8.1"},
            "waf": None,
            "auth_methods": [],
            "interesting_endpoints": [],
        }
        memory_manager.save_target_intel(intel)

        context = memory_manager.get_context_for_small_model(
            target="example.com",
            current_phase="RECON",
            max_tokens=4096,
        )

        assert "TARGET INTELLIGENCE" in context
        assert "Subdomains" in context
        assert "Open Ports" in context

    def test_returns_empty_for_unknown_target(self, memory_manager):
        context = memory_manager.get_context_for_small_model(
            target="unknown.com",
            current_phase="RECON",
            max_tokens=4096,
        )
        assert context == ""


class TestToolStatistics:
    def test_record_and_retrieve_tool_stats(self, memory_manager):
        memory_manager.record_tool_usage(
            tool_name="nmap",
            target="example.com",
            success=True,
            duration_sec=30.0,
            output_size=5000,
        )
        memory_manager.record_tool_usage(
            tool_name="nmap",
            target="example.com",
            success=True,
            duration_sec=25.0,
            output_size=4000,
        )

        stats = memory_manager.get_tool_statistics()
        assert isinstance(stats, list)
        assert len(stats) == 1
        assert stats[0]["tool_name"] == "nmap"
        assert stats[0]["success_count"] == 2

    def test_get_tool_statistics_returns_empty_for_no_connection(self):
        from airecon.proxy.memory import MemoryManager

        mm = MemoryManager()
        assert mm.get_tool_statistics() == {}

    def test_tool_statistics_prefer_global_rollup_snapshot(self, memory_manager):
        cursor = memory_manager.conn.cursor()
        cursor.executemany(
            """
            INSERT INTO tool_usage
            (tool_name, target, success_count, failure_count, avg_duration_sec, typical_output_size)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                ("ffuf", "a.example.com", 1, 0, 1.0, 100),
                ("ffuf", "b.example.com", 2, 1, 2.0, 200),
                ("ffuf", "", 5, 1, 1.5, 300),
            ],
        )
        memory_manager.conn.commit()

        stats = memory_manager.get_tool_statistics(tool_name="ffuf")

        assert isinstance(stats, dict)
        assert stats["success_count"] == 5
        assert stats["failure_count"] == 1
        assert stats["total_calls"] == 6


class TestToolInsights:
    def test_get_tool_insights_uses_rolled_up_statistics(self, memory_manager):
        cursor = memory_manager.conn.cursor()
        cursor.executemany(
            """
            INSERT INTO tool_usage
            (tool_name, target, success_count, failure_count, avg_duration_sec, typical_output_size)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                ("ffuf", "a.example.com", 1, 0, 1.0, 100),
                ("ffuf", "", 4, 1, 1.4, 250),
                ("nmap", "example.com", 2, 1, 10.0, 500),
            ],
        )
        memory_manager.conn.commit()

        insights = memory_manager.get_tool_insights()

        assert insights["total_tools_tracked"] == 2
        assert insights["top_performing_tools"][0]["tool_name"] == "ffuf"
        assert insights["top_performing_tools"][0]["success_rate"] == 0.8


class TestHealthSnapshot:
    def test_health_snapshot_with_data(self, memory_manager):
        session_data = {
            "session_id": "test_001",
            "target": "example.com",
            "current_phase": "RECON",
            "subdomains": [],
            "live_hosts": [],
            "vulnerabilities": [],
            "attack_chains": [],
            "token_total": 0,
            "model_used": "llama3",
        }
        memory_manager.save_session(session_data)

        snapshot = memory_manager.health_snapshot(target="example.com")
        assert snapshot["ok"] is True
        assert snapshot["sessions_total"] >= 1

    def test_health_snapshot_returns_error_for_no_connection(self):
        from airecon.proxy.memory import MemoryManager

        mm = MemoryManager()
        snapshot = mm.health_snapshot()
        assert snapshot["ok"] is False
        assert "not_connected" in snapshot["error"]


class TestSaveSkillUsage:
    def test_save_skill_usage(self, memory_manager):
        memory_manager.save_skill_usage(
            skill_name="nmap_scan",
            target="example.com",
            phase="RECON",
            success=True,
            effectiveness_score=0.85,
            tokens_saved=500,
        )

        cursor = memory_manager.conn.cursor()
        cursor.execute("SELECT COUNT(*) AS c FROM skill_usage")
        count = cursor.fetchone()["c"]
        assert count == 1
