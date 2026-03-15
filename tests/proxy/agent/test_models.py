from airecon.proxy.agent.models import AgentState


def test_agent_state_initializes_with_defaults():
    state = AgentState()
    assert state.conversation == []
    assert state.tool_history == []
    assert state.iteration == 0
    assert state.active_target is None


def test_agent_state_add_message():
    state = AgentState()
    state.add_message("user", "Hello World")

    assert len(state.conversation) == 1
    assert state.conversation[0] == {"role": "user", "content": "Hello World"}

    state.add_message("assistant", "Hi", tool_calls=[{"name": "test_tool"}])
    assert len(state.conversation) == 2
    assert state.conversation[1]["tool_calls"] == [{"name": "test_tool"}]


def test_agent_state_approaching_limit():
    state = AgentState(max_iterations=100)
    state.iteration = 96
    assert state.is_approaching_limit() is False

    state.iteration = 97
    assert state.is_approaching_limit() is True


def test_agent_state_truncate_conversation():
    state = AgentState()
    # Add many messages to force truncation
    for i in range(100):
        state.add_message("user", f"Message {i}")

    original_len = len(state.conversation)
    # The default budget for non-system messages limits keeping everything.
    state.truncate_conversation(max_messages=50)

    # After truncation, the actual number of messages should be bounded roughly to `max_messages` + separator
    assert len(state.conversation) < original_len
    # Since all messages are short strings, they are dropped instead of compressed text,
    # but dropped message triggers the separator adding logic.
    separator_exists = any(
        "older messages compressed/removed" in str(msg.get("content")) for msg in state.conversation)
    assert separator_exists


def test_agent_state_phase_objectives_and_status_updates():
    state = AgentState()
    defaults = [
        "Enumerate attack surface",
        "Confirm open ports",
    ]
    state.ensure_phase_objectives("RECON", defaults)
    # Re-adding defaults should not duplicate entries
    state.ensure_phase_objectives("RECON", defaults)

    recon_objs = [
        o for o in state.objective_queue
        if o.get("phase") == "RECON"
    ]
    assert len(recon_objs) == 2
    assert all(o.get("status") == "pending" for o in recon_objs)

    state.mark_objective("RECON", "Enumerate attack surface", "done")
    done_obj = next(
        o for o in state.objective_queue
        if o.get("phase") == "RECON"
        and o.get("title") == "Enumerate attack surface"
    )
    assert done_obj.get("status") == "done"


def test_agent_state_evidence_dedup_and_focus_context():
    state = AgentState()
    state.ensure_phase_objectives("ANALYSIS", ["Map technologies"])
    state.add_evidence(
        phase="ANALYSIS",
        source_tool="execute",
        summary="Detected CVE-2024-1234 in plugin banner",
        artifact="output/banner.txt",
        tags=["cve", "banner"],
    )
    # Duplicate evidence should be ignored
    state.add_evidence(
        phase="ANALYSIS",
        source_tool="execute",
        summary="Detected CVE-2024-1234 in plugin banner",
        artifact="output/banner.txt",
        tags=["cve", "banner"],
    )
    assert len(state.evidence_log) == 1

    context = state.build_focus_context("ANALYSIS")
    assert "OBJECTIVE FOCUS" in context
    assert "Map technologies" in context
    assert "CVE-2024-1234" in context


# ---------------------------------------------------------------------------
# Upgrade 3: Semantic evidence deduplication (Jaccard similarity)
# ---------------------------------------------------------------------------

def test_jaccard_identical_strings():
    assert AgentState._jaccard_similarity("foo bar baz", "foo bar baz") == 1.0


def test_jaccard_completely_different():
    score = AgentState._jaccard_similarity("alpha beta", "gamma delta")
    assert score == 0.0


def test_jaccard_partial_overlap():
    score = AgentState._jaccard_similarity("nginx 1.18 running", "nginx version 2.0")
    # "nginx" is the only shared token out of {"nginx","1.18","running","version","2.0"}
    assert 0.0 < score < 1.0


def test_jaccard_empty_inputs():
    assert AgentState._jaccard_similarity("", "anything") == 0.0
    assert AgentState._jaccard_similarity("anything", "") == 0.0
    assert AgentState._jaccard_similarity("", "") == 0.0


def test_add_evidence_returns_true_on_first_add():
    state = AgentState()
    result = state.add_evidence(
        phase="RECON", source_tool="execute",
        summary="Port 80 open on 192.168.1.1",
    )
    assert result is True
    assert len(state.evidence_log) == 1


def test_add_evidence_rejects_empty_summary():
    state = AgentState()
    result = state.add_evidence(phase="RECON", source_tool="execute", summary="  ")
    assert result is False
    assert len(state.evidence_log) == 0


def test_add_evidence_exact_duplicate_rejected():
    state = AgentState()
    state.add_evidence(phase="RECON", source_tool="execute", summary="Port 80 open on host")
    result = state.add_evidence(phase="RECON", source_tool="execute", summary="Port 80 open on host")
    assert result is False
    assert len(state.evidence_log) == 1


def test_add_evidence_semantic_duplicate_rejected():
    state = AgentState()
    state.add_evidence(
        phase="EXPLOIT", source_tool="quick_fuzz",
        summary="SQL injection confirmed in login parameter id",
    )
    # Nearly identical wording — should be rejected as semantic duplicate
    result = state.add_evidence(
        phase="EXPLOIT", source_tool="quick_fuzz",
        summary="SQL injection confirmed in login parameter id field",
    )
    assert result is False
    assert len(state.evidence_log) == 1


def test_add_evidence_cross_phase_not_blocked():
    """Same summary in a different phase should NOT be deduplicated."""
    state = AgentState()
    state.add_evidence(
        phase="RECON", source_tool="execute",
        summary="nginx server detected on port 80",
    )
    result = state.add_evidence(
        phase="ANALYSIS", source_tool="execute",
        summary="nginx server detected on port 80",
    )
    assert result is True
    assert len(state.evidence_log) == 2


def test_add_evidence_full_log_scan():
    """Deduplication should check ALL entries, not just the last 50."""
    state = AgentState()
    # Fill up evidence_log with 60 unrelated entries
    for i in range(60):
        state.add_evidence(
            phase="RECON", source_tool="execute",
            summary=f"Unique finding number {i} with distinct content",
        )
    original_count = len(state.evidence_log)
    # Now try to add the very first entry again
    result = state.add_evidence(
        phase="RECON", source_tool="execute",
        summary="Unique finding number 0 with distinct content",
    )
    assert result is False
    assert len(state.evidence_log) == original_count
