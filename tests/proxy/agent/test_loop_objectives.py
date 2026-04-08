"""Tests for loop_objectives.py — objective management, evidence recording, hypothesis."""

from __future__ import annotations

from airecon.proxy.agent.loop_objectives import _ObjectivesMixin
from airecon.proxy.agent.models import AgentState
from airecon.proxy.agent.pipeline import PipelinePhase
from airecon.proxy.agent.session import ApplicationModel


def _make_agent():
    class DummyAgent(_ObjectivesMixin):
        def __init__(self):
            self.state = AgentState()
            self._session = type(
                "Session",
                (),
                {
                    "target": "example.com",
                    "subdomains": ["sub.example.com"],
                    "live_hosts": ["http://example.com"],
                    "open_ports": {"80": "http"},
                    "urls": ["http://example.com/login"],
                    "vulnerabilities": [],
                    "injection_points": [],
                    "technologies": {"nginx": "1.18"},
                    "waf_profiles": {},
                    "tested_endpoints": set(),
                    "scan_count": 1,
                    "hypothesis_queue": [],
                    "completed_phases": [],
                    "app_model": ApplicationModel(),
                    "auth_type": "cookie",
                },
            )()
            self.pipeline = None

        def _get_current_phase(self):
            return PipelinePhase.RECON

    return DummyAgent()


class TestDynamicPhaseObjectives:
    def test_recon_dynamic_objectives_when_subdomains_no_live(self):
        agent = _make_agent()
        agent._session.live_hosts = []
        dynamic = agent._dynamic_phase_objectives(PipelinePhase.RECON)
        assert any("liveness" in d.lower() for d in dynamic)

    def test_recon_dynamic_objectives_when_high_value_ports(self):
        agent = _make_agent()
        # open_ports format: {host: [port1, port2, ...]}
        agent._session.open_ports = {"example.com": [80, 443, 8080, 3000]}
        dynamic = agent._dynamic_phase_objectives(PipelinePhase.RECON)
        assert any("non-standard" in d.lower() for d in dynamic)

    def test_analysis_dynamic_objectives_when_idor_hint(self):
        agent = _make_agent()
        agent._session.injection_points = [{"type_hint": "IDOR"}]
        dynamic = agent._dynamic_phase_objectives(PipelinePhase.ANALYSIS)
        assert any("privilege" in d.lower() for d in dynamic)

    def test_analysis_dynamic_objectives_when_tech_detected(self):
        agent = _make_agent()
        dynamic = agent._dynamic_phase_objectives(PipelinePhase.ANALYSIS)
        assert any("nginx" in d.lower() for d in dynamic)

    def test_returns_empty_without_session(self):
        agent = _make_agent()
        agent._session = None
        dynamic = agent._dynamic_phase_objectives(PipelinePhase.RECON)
        assert dynamic == []


class TestExtractResultText:
    def test_extracts_from_dict(self):
        agent = _make_agent()
        result = {"stdout": "line1\nline2", "stderr": "error"}
        text = agent._extract_result_text(result)
        assert "line1" in text
        assert "error" in text

    def test_extracts_from_string(self):
        agent = _make_agent()
        text = agent._extract_result_text("plain text")
        assert text == "plain text"

    def test_returns_empty_for_none(self):
        agent = _make_agent()
        assert agent._extract_result_text(None) == ""

    def test_truncates_long_results(self):
        agent = _make_agent()
        result = {"stdout": "a" * 10000}
        text = agent._extract_result_text(result)
        assert len(text) <= 7000


class TestAutoFormHypotheses:
    def test_forms_cve_hypothesis(self):
        agent = _make_agent()
        agent._auto_form_hypotheses(
            phase="ANALYSIS",
            tool_name="execute",
            arguments={"command": "nuclei"},
            result_text="CVE-2024-12345 detected in Apache",
        )
        hyps = [
            h
            for h in agent.state.hypothesis_queue
            if "CVE-2024-12345" in h.get("claim", "")
        ]
        assert len(hyps) > 0

    def test_forms_sqli_hypothesis(self):
        agent = _make_agent()
        agent._auto_form_hypotheses(
            phase="EXPLOIT",
            tool_name="execute",
            arguments={"command": "sqlmap -u http://target"},
            result_text="SQL injection detected in parameter id",
        )


class TestReportObjectiveSeparation:
    def test_create_note_does_not_count_as_report_completion(self):
        agent = _make_agent()
        agent.state.ensure_phase_objectives("REPORT", defaults=["Write report", "Finalize report", "Save outputs"])

        agent._update_objectives_from_tool(
            PipelinePhase.REPORT,
            "create_note",
            {},
            True,
            {
                "success": True,
                "artifact_type": "working_note",
                "report_generated": False,
                "note": {
                    "title": "Draft severity summary",
                    "content": "Severity: HIGH\nRemediation: sanitize input",
                },
            },
            None,
        )

        report_objectives = [
            obj for obj in agent.state.objective_queue if str(obj.get("phase")) == "REPORT"
        ]
        assert report_objectives
        assert all(obj.get("status") != "done" for obj in report_objectives[:2])

    def test_does_not_form_hypothesis_on_false_signal(self):
        agent = _make_agent()
        agent._auto_form_hypotheses(
            phase="EXPLOIT",
            tool_name="execute",
            arguments={"command": "curl http://target"},
            result_text="Testing for SQL injection... no injection found",
        )
        assert len(agent.state.hypothesis_queue) == 0

    def test_limits_hypotheses_per_call(self):
        agent = _make_agent()
        agent._auto_form_hypotheses(
            phase="EXPLOIT",
            tool_name="execute",
            arguments={"command": "nuclei"},
            result_text="CVE-2024-11111 and CVE-2024-22222 and CVE-2024-33333 found",
        )
        assert len(agent.state.hypothesis_queue) <= 2

    def test_tool_name_mentions_do_not_create_false_hypothesis(self):
        agent = _make_agent()
        agent._auto_form_hypotheses(
            phase="ANALYSIS",
            tool_name="execute",
            arguments={"command": "echo ready"},
            result_text="sqlmap and dalfox are installed and ready to use",
        )
        assert agent.state.hypothesis_queue == []

    def test_record_evidence_updates_application_workflow_model(self):
        agent = _make_agent()
        agent._record_evidence_from_result(
            phase="ANALYSIS",
            tool_name="http_observe",
            arguments={
                "url": "https://example.com/admin/approve",
                "method": "POST",
                "tenant_id": "acme",
                "invite_id": "123",
            },
            result={
                "stdout": (
                    "Owner approval workflow accepted tenant invite after OTP verification.\n"
                    "Cross-tenant workspace transition looked possible."
                )
            },
            success=True,
            output_file=None,
        )

        model = agent._session.app_model
        assert "admin_approval" in model.workflow_paths
        assert "tenant_boundary" in model.trust_boundaries
        assert "owner" in model.principal_profiles
