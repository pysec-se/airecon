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
    # Fulfill criteria for RECON -> ANALYSIS (2/3 criteria = 60%+)
    empty_pipeline.session.subdomains = ["app.example.com"]
    empty_pipeline.session.open_ports = {"app.example.com": [80, 443]}

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
