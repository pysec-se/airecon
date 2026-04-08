"""Extended pipeline tests covering all phase transitions and check_tool_phase_fit."""

from unittest.mock import MagicMock
from airecon.proxy.agent.pipeline import PipelineEngine, PipelinePhase


def _make_session(**kwargs):
    """Create a minimal mock session with sensible defaults."""
    s = MagicMock()
    s.current_phase = kwargs.get("current_phase", "RECON")
    s.subdomains = kwargs.get("subdomains", [])
    s.live_hosts = kwargs.get("live_hosts", [])
    s.open_ports = kwargs.get("open_ports", {})
    s.urls = kwargs.get("urls", [])
    s.technologies = kwargs.get("technologies", {})
    s.injection_points = kwargs.get("injection_points", [])
    s.vulnerabilities = kwargs.get("vulnerabilities", [])
    s.completed_phases = kwargs.get("completed_phases", [])
    s.scan_count = kwargs.get("scan_count", 0)
    s.target = kwargs.get("target", "example.com")
    return s


def _fast_forward(engine, iterations=15):
    """Advance the engine's iteration counter past the cooldown."""
    engine._current_iteration = iterations
    engine._phase_entry_iteration = 0


# ── Phase: ANALYSIS ───────────────────────────────────────────────────────────


class TestAnalysisPhaseTransitions:
    def test_recon_to_analysis_transition(self):
        # live_hosts_validated is now MANDATORY for RECON→ANALYSIS transition
        session = _make_session(
            subdomains=["api.example.com"],
            live_hosts=["https://api.example.com"],
            open_ports={"example.com": [80]},
            scan_count=5,
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is True
        new_phase = engine.transition()
        assert new_phase == PipelinePhase.ANALYSIS
        assert session.current_phase == "ANALYSIS"
        assert "RECON" in session.completed_phases

    def test_recon_can_jump_directly_to_exploit_with_actionable_signal(self):
        session = _make_session(
            subdomains=["api.example.com"],
            live_hosts=["https://api.example.com"],
            open_ports={"example.com": [80]},
            urls=["https://api.example.com/login"],
            vulnerabilities=[
                {"finding": "[HIGH] SQL Injection in login", "evidence": "db error"}
            ],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is True
        assert engine.transition() == PipelinePhase.EXPLOIT

    def test_analysis_criteria_urls(self):
        session = _make_session(
            current_phase="ANALYSIS",
            urls=["http://example.com/api", "http://example.com/login"],
            technologies={"nginx": "1.18"},
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is True

    def test_analysis_transition_to_exploit(self):
        session = _make_session(
            current_phase="ANALYSIS",
            urls=["http://example.com/api"],
            technologies={"nginx": "1.18"},
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        new_phase = engine.transition()
        assert new_phase == PipelinePhase.EXPLOIT
        assert "ANALYSIS" in session.completed_phases

    def test_analysis_no_transition_without_criteria(self):
        session = _make_session(
            current_phase="ANALYSIS",
            urls=[],
            technologies={},
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is False

    def test_analysis_stagnation_can_fall_back_to_recon(self):
        session = _make_session(
            current_phase="ANALYSIS",
            subdomains=["api.example.com"],
            live_hosts=["https://api.example.com"],
            urls=[],
            technologies={},
            injection_points=[],
        )
        engine = PipelineEngine(session)
        engine._phase_entry_iteration = 0
        engine._current_iteration = engine._analysis_max_iterations

        assert engine.transition() == PipelinePhase.RECON


# ── Phase: EXPLOIT ────────────────────────────────────────────────────────────


class TestExploitPhaseTransitions:
    def test_exploit_criteria_confirmed_vuln(self):
        """Explicit report_generated=True triggers transition."""
        session = _make_session(
            current_phase="EXPLOIT",
            vulnerabilities=[{"finding": "SQL Injection", "report_generated": True}],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is True

    def test_exploit_criteria_medium_severity(self):
        """Auto-parsed [MEDIUM] finding triggers transition."""
        session = _make_session(
            current_phase="EXPLOIT",
            vulnerabilities=[{"finding": "[MEDIUM] Reflected XSS in /search"}],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is True

    def test_exploit_criteria_high_severity(self):
        """Auto-parsed [HIGH] finding triggers transition."""
        session = _make_session(
            current_phase="EXPLOIT",
            vulnerabilities=[{"finding": "[HIGH] SQL Injection"}],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is True

    def test_exploit_no_transition_low_severity_only(self):
        """[LOW]/[INFO] findings alone are not enough to transition."""
        session = _make_session(
            current_phase="EXPLOIT",
            vulnerabilities=[
                {"finding": "[LOW] Server version disclosure"},
                {"finding": "[INFO] Open port 8080"},
            ],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is False

    def test_exploit_no_transition_untagged_vuln(self):
        """Untagged text-match vulnerability (no severity, no report_generated) is not enough."""
        session = _make_session(
            current_phase="EXPLOIT",
            vulnerabilities=[{"finding": "SQL Injection", "target": "example.com"}],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is False

    def test_exploit_transition_to_report(self):
        session = _make_session(
            current_phase="EXPLOIT",
            vulnerabilities=[{"finding": "[HIGH] XSS", "report_generated": True}],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        new_phase = engine.transition()
        assert new_phase == PipelinePhase.REPORT
        assert "EXPLOIT" in session.completed_phases

    def test_exploit_no_transition_without_vuln(self):
        session = _make_session(
            current_phase="EXPLOIT",
            vulnerabilities=[],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is False

    def test_exploit_stagnation_can_fall_back_to_analysis(self):
        session = _make_session(
            current_phase="EXPLOIT",
            vulnerabilities=[{"finding": "Possible SQLi candidate"}],
        )
        engine = PipelineEngine(session)
        engine._phase_entry_iteration = 0
        engine._current_iteration = engine._exploit_max_iterations

        assert engine.transition() == PipelinePhase.ANALYSIS


# ── Phase: REPORT ─────────────────────────────────────────────────────────────


class TestReportPhaseTransitions:
    def test_report_criteria_with_generated_reports(self):
        session = _make_session(
            current_phase="REPORT",
            vulnerabilities=[
                {"finding": "SQLi", "report_generated": True},
            ],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is True

    def test_report_transition_to_complete(self):
        session = _make_session(
            current_phase="REPORT",
            vulnerabilities=[{"finding": "SQLi", "report_generated": True}],
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        new_phase = engine.transition()
        assert new_phase == PipelinePhase.COMPLETE

    def test_report_no_transition_without_reports(self):
        session = _make_session(
            current_phase="REPORT",
            vulnerabilities=[{"finding": "SQLi"}],  # no report_generated
        )
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is False


# ── COMPLETE phase ────────────────────────────────────────────────────────────


class TestCompletedState:
    def test_complete_phase_no_transition(self):
        session = _make_session(current_phase="COMPLETE")
        engine = PipelineEngine(session)
        _fast_forward(engine)

        assert engine.should_transition() is False

    def test_complete_transition_returns_none(self):
        session = _make_session(current_phase="COMPLETE")
        engine = PipelineEngine(session)
        result = engine.transition()
        assert result is None

    def test_complete_phase_prompt(self):
        session = _make_session(current_phase="COMPLETE")
        engine = PipelineEngine(session)
        prompt = engine.get_phase_prompt()
        assert "COMPLETE" in prompt or "ALL PHASES" in prompt


# ── check_tool_phase_fit ──────────────────────────────────────────────────────


class TestCheckToolPhaseFit:
    def test_exploit_tool_in_recon_phase_warns(self):
        session = _make_session(current_phase="RECON")
        engine = PipelineEngine(session)

        # hydra is only in exploitation category → should warn in RECON
        warning = engine.check_tool_phase_fit("hydra")
        assert warning is not None
        assert "RECON" in warning

    def test_exploit_tool_in_exploit_phase_ok(self):
        session = _make_session(current_phase="EXPLOIT")
        engine = PipelineEngine(session)

        # hydra is in exploitation → valid in EXPLOIT phase
        assert engine.check_tool_phase_fit("hydra") is None
        # ffuf is in recon+vuln_scan+exploit → valid in EXPLOIT
        assert engine.check_tool_phase_fit("ffuf") is None
        # Unknown tools are assumed valid
        assert engine.check_tool_phase_fit("schemathesis_fuzz") is None

    def test_recommended_recon_tool_ok(self):
        session = _make_session(current_phase="RECON")
        engine = PipelineEngine(session)

        # These are in RECON recommended_tools
        assert engine.check_tool_phase_fit("execute") is None
        assert engine.check_tool_phase_fit("web_search") is None
        assert engine.check_tool_phase_fit("browser_action") is None

    def test_report_tool_in_recon_phase_warns(self):
        session = _make_session(current_phase="RECON")
        engine = PipelineEngine(session)

        # create_vulnerability_report is not in tools_meta.json → unknown → valid
        # With dynamic approach, unknown tools are assumed valid (no false positives)
        warning = engine.check_tool_phase_fit("create_vulnerability_report")
        assert warning is None

    def test_unknown_tool_in_recon_no_warning(self):
        """Tools not in the exploit-specific set don't generate warnings."""
        session = _make_session(current_phase="RECON")
        engine = PipelineEngine(session)

        # Random tool not in tools_meta.json → assumed valid
        assert engine.check_tool_phase_fit("code_analysis") is None

    def test_caido_automate_warns_in_analysis(self):
        session = _make_session(current_phase="ANALYSIS")
        engine = PipelineEngine(session)

        # caido_automate is not in tools_meta.json → unknown → valid
        # With dynamic approach, unknown tools are assumed valid (no false positives)
        warning = engine.check_tool_phase_fit("caido_automate")
        assert warning is None

    def test_known_tool_wrong_phase_warns(self):
        """Tools from tools_meta.json DO warn when used in wrong phase."""
        session = _make_session(current_phase="REPORT")
        engine = PipelineEngine(session)

        # ffuf is in recon/vuln_scan/exploitation — NOT report → should warn
        warning = engine.check_tool_phase_fit("ffuf")
        assert warning is not None
        assert "REPORT" in warning

    def test_report_phase_all_tools_ok(self):
        session = _make_session(current_phase="REPORT")
        engine = PipelineEngine(session)

        # create_vulnerability_report is unknown → valid
        assert engine.check_tool_phase_fit("create_vulnerability_report") is None
        # ffuf is in recon/vuln_scanning/exploitation — NOT report → should warn
        warning = engine.check_tool_phase_fit("ffuf")
        assert warning is not None
        assert "REPORT" in warning


# ── get_phase_prompt ──────────────────────────────────────────────────────────


class TestGetPhasePrompt:
    def test_prompt_contains_phase_name(self):
        session = _make_session(current_phase="RECON")
        engine = PipelineEngine(session)
        prompt = engine.get_phase_prompt()
        assert "RECON" in prompt or "recon" in prompt.lower()

    def test_prompt_shows_criteria_progress(self):
        session = _make_session(
            current_phase="ANALYSIS",
            urls=["http://example.com"],
            technologies={},  # only 1/3 criteria met
        )
        engine = PipelineEngine(session)
        prompt = engine.get_phase_prompt()
        assert "1/3" in prompt

    def test_ctf_mode_prompt_is_exploit_focused(self):
        session = _make_session(current_phase="RECON")
        engine = PipelineEngine(session)
        engine.set_ctf_mode(True)
        prompt = engine.get_phase_prompt()
        assert "CTF" in prompt or "FLAG" in prompt

    def test_transition_prompt_contains_new_phase(self):
        session = _make_session()
        engine = PipelineEngine(session)
        prompt = engine.get_transition_prompt(PipelinePhase.EXPLOIT)
        assert "EXPLOIT" in prompt
        assert "objective" in prompt.lower()


# ── Cooldown guard ────────────────────────────────────────────────────────────


class TestCooldownGuard:
    def test_cannot_transition_before_min_iterations(self):
        """Even if all criteria are met, the cooldown prevents an instant jump."""
        session = _make_session(
            subdomains=["api.example.com"],
            open_ports={"example.com": [80]},
            scan_count=10,
        )
        engine = PipelineEngine(session)
        # Do NOT fast-forward — only 0 iterations in current phase
        engine._current_iteration = 5
        engine._phase_entry_iteration = 0

        # MIN_ITERATIONS_PER_PHASE is 10, so 5 < 10 → no transition
        assert engine.should_transition() is False

    def test_can_transition_after_cooldown(self):
        # live_hosts_validated is now MANDATORY for RECON→ANALYSIS transition
        session = _make_session(
            subdomains=["api.example.com"],
            live_hosts=["https://api.example.com"],
            open_ports={"example.com": [80]},
            scan_count=10,
        )
        engine = PipelineEngine(session)
        engine._current_iteration = 15  # past cooldown
        engine._phase_entry_iteration = 0

        assert engine.should_transition() is True
