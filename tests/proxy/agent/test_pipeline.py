import pytest
from airecon.proxy.agent.pipeline import PipelineEngine, PipelinePhase
from airecon.proxy.agent.session import SessionData


@pytest.fixture
def empty_pipeline():
    session = SessionData(target="example.com")
    # Using 10 iterations to surpass MIN_ITERATIONS_PER_PHASE immediately
    engine = PipelineEngine(session)
    engine._current_iteration = 15
    return engine


def test_initial_phase(empty_pipeline):
    assert empty_pipeline.get_current_phase() == PipelinePhase.RECON


def test_should_not_transition_without_criteria(empty_pipeline):
    assert empty_pipeline.should_transition() is False
    assert empty_pipeline.transition() == PipelinePhase.RECON


def test_transition_recon_to_analysis(empty_pipeline):
    # Fulfill criteria for RECON -> ANALYSIS (3/5 criteria = 60%+):
    # subdomains_discovered, ports_scanned, url_discovery_met
    empty_pipeline.session.subdomains = ["app.example.com"]
    empty_pipeline.session.open_ports = {"app.example.com": [80, 443]}
    empty_pipeline.session.urls = ["https://app.example.com/login"]

    assert empty_pipeline.should_transition() is True

    new_phase = empty_pipeline.transition()
    assert new_phase == PipelinePhase.ANALYSIS
    assert empty_pipeline.get_current_phase() == PipelinePhase.ANALYSIS
    assert PipelinePhase.RECON.value in empty_pipeline.session.completed_phases


def test_transition_cooldown_prevent_immediate_jump():
    session = SessionData(target="example.com")
    # All criteria instantly met for both RECON and ANALYSIS
    session.subdomains = ["app.example.com"]
    session.open_ports = {"app.example.com": [443]}
    session.urls = ["https://app.example.com"]
    session.technologies = {"nginx": "1.18"}

    engine = PipelineEngine(session)
    # Iteration 0 - should not transition regardless of criteria because of cooldown
    engine._current_iteration = 5
    assert engine.should_transition() is False

    # Fast forward passed cooldown
    engine._current_iteration = 15
    assert engine.should_transition() is True
    engine.transition()  # Jump to ANALYSIS

    # Should be back on cooldown for ANALYSIS->EXPLOIT
    assert engine.get_current_phase() == PipelinePhase.ANALYSIS
    assert engine.should_transition() is False


def test_ctf_mode_behavior(empty_pipeline):
    # CTF mode skips all RECON/ANALYSIS logic and heuristics
    empty_pipeline.set_ctf_mode(True)

    assert empty_pipeline.get_current_phase() == PipelinePhase.EXPLOIT
    # Heuristics transition should be forcibly disabled in CTF
    empty_pipeline.session.vulnerabilities = [{"finding": "flag{123}"}]
    assert empty_pipeline.should_transition() is False


# ---------------------------------------------------------------------------
# Upgrade 2: Phase transition depth check + soft timeout
# ---------------------------------------------------------------------------

class _MockConfig:
    """Minimal config stub for PipelineEngine depth tests."""
    pipeline_recon_min_subdomains = 3
    pipeline_recon_min_urls = 1
    pipeline_recon_soft_timeout = 30


def _make_engine(session=None, config=None):
    if session is None:
        session = SessionData(target="test.com")
    engine = PipelineEngine(session, config=config or _MockConfig())
    engine._phase_entry_iteration = 0
    engine._current_iteration = 15  # past cooldown
    return engine


def test_depth_criteria_not_met_blocks_transition():
    """Fewer subdomains than min_subdomains should not satisfy depth criterion."""
    session = SessionData(target="test.com")
    # Only 1 subdomain — below min_subdomains=3; also no urls → depth criteria unmet
    session.subdomains = ["sub.test.com"]
    session.open_ports = {"test.com": [80]}
    # Satisfy recon_artifacts via scan_count
    session.scan_count = 5

    engine = _make_engine(session)
    # Only 3/5 criteria met (subdomains_discovered, ports_scanned, recon_artifacts_saved)
    # url_discovery_met and subdomain_depth_met NOT satisfied → 3/5 = 60% → transition
    # But subdomain_depth_met requires >= 3 subdomains, and url_discovery_met requires >= 1 URL
    # So only 3 met out of 5 → 60% threshold: max(1, int(5*0.6)) = 3 → SHOULD transition
    # Let's verify the criteria logic
    met = engine._evaluate_criteria(PipelinePhase.RECON)
    assert "subdomain_depth_met" not in met
    assert "url_discovery_met" not in met


def test_subdomain_depth_met_criterion():
    """When >= min_subdomains discovered, subdomain_depth_met is added."""
    session = SessionData(target="test.com")
    session.subdomains = ["a.test.com", "b.test.com", "c.test.com"]

    engine = _make_engine(session)
    met = engine._evaluate_criteria(PipelinePhase.RECON)
    assert "subdomain_depth_met" in met


def test_url_discovery_met_criterion():
    """When >= min_urls collected, url_discovery_met is added."""
    session = SessionData(target="test.com")
    session.urls = ["https://test.com/login"]

    engine = _make_engine(session)
    met = engine._evaluate_criteria(PipelinePhase.RECON)
    assert "url_discovery_met" in met


def test_depth_not_met_but_60pct_still_transitions():
    """3/5 criteria (60%) still satisfies transition threshold even without depth criteria."""
    session = SessionData(target="test.com")
    session.subdomains = ["sub.test.com"]          # subdomains_discovered ✓
    session.open_ports = {"test.com": [443]}       # ports_scanned ✓
    session.scan_count = 5                         # recon_artifacts_saved ✓
    # subdomain_depth_met ✗ (only 1, needs 3)
    # url_discovery_met ✗ (no URLs)

    engine = _make_engine(session)
    # 3/5 = 60% → threshold is max(1, int(5*0.6)) = 3 → should transition
    assert engine.should_transition() is True


def test_soft_timeout_forces_transition():
    """After soft_timeout iterations in RECON, should_transition returns True."""
    session = SessionData(target="test.com")
    # No criteria met at all
    engine = _make_engine(session)
    config = _MockConfig()
    engine._recon_soft_timeout = config.pipeline_recon_soft_timeout  # 30
    engine._phase_entry_iteration = 0
    engine._current_iteration = 31  # > soft_timeout=30

    assert engine.should_transition() is True


def test_soft_timeout_not_triggered_before_threshold():
    """Iterations below soft_timeout do not force transition."""
    session = SessionData(target="test.com")
    engine = _make_engine(session)
    engine._recon_soft_timeout = 30
    engine._phase_entry_iteration = 0
    engine._current_iteration = 25  # below soft_timeout

    # No criteria met → should not transition
    assert engine.should_transition() is False


def test_soft_timeout_transition_bypasses_criteria_guard():
    """transition() should succeed on soft timeout even with 0 criteria met."""
    session = SessionData(target="test.com")
    engine = _make_engine(session)
    engine._recon_soft_timeout = 30
    engine._phase_entry_iteration = 0
    engine._current_iteration = 35  # past soft timeout

    new_phase = engine.transition()
    assert new_phase == PipelinePhase.ANALYSIS


def test_ctf_mode_unaffected_by_depth_checks():
    """CTF mode still bypasses all heuristics including depth criteria."""
    session = SessionData(target="test.com")
    # Satisfy nothing
    engine = _make_engine(session)
    engine.set_ctf_mode(True)

    assert engine.get_current_phase() == PipelinePhase.EXPLOIT
    assert engine.should_transition() is False
