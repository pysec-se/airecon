from __future__ import annotations

from airecon.proxy.agent.models import AgentState, ToolExecution


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
        "older messages compressed/removed" in str(msg.get("content"))
        for msg in state.conversation
    )
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

    recon_objs = [o for o in state.objective_queue if o.get("phase") == "RECON"]
    assert len(recon_objs) == 2
    assert all(o.get("status") == "pending" for o in recon_objs)

    state.mark_objective("RECON", "Enumerate attack surface", "done")
    done_obj = next(
        o
        for o in state.objective_queue
        if o.get("phase") == "RECON" and o.get("title") == "Enumerate attack surface"
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
    assert "<objective_focus" in context  # XML format
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
        phase="RECON",
        source_tool="execute",
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
    state.add_evidence(
        phase="RECON", source_tool="execute", summary="Port 80 open on host"
    )
    result = state.add_evidence(
        phase="RECON", source_tool="execute", summary="Port 80 open on host"
    )
    assert result is False
    assert len(state.evidence_log) == 1


def test_add_evidence_semantic_duplicate_rejected():
    state = AgentState()
    state.add_evidence(
        phase="EXPLOIT",
        source_tool="quick_fuzz",
        summary="SQL injection confirmed in login parameter id",
    )
    # Nearly identical wording — should be rejected as semantic duplicate
    result = state.add_evidence(
        phase="EXPLOIT",
        source_tool="quick_fuzz",
        summary="SQL injection confirmed in login parameter id field",
    )
    assert result is False
    assert len(state.evidence_log) == 1


def test_add_evidence_cross_phase_not_blocked():
    """Same summary in a different phase should NOT be deduplicated."""
    state = AgentState()
    state.add_evidence(
        phase="RECON",
        source_tool="execute",
        summary="nginx server detected on port 80",
    )
    result = state.add_evidence(
        phase="ANALYSIS",
        source_tool="execute",
        summary="nginx server detected on port 80",
    )
    assert result is True


def test_legacy_tool_history_truncation_handles_new_entries_incrementally():
    state = AgentState()
    # Seed above fallback threshold so legacy truncation path runs.
    for i in range(55):
        state.tool_history.append(
            ToolExecution(
                tool_name="execute",
                arguments={"command": f"echo {i}"},
                result={"stdout": "ok"},
            )
        )

    state.add_message("user", "warmup")
    first_scan_pos = getattr(state, "_legacy_tool_history_scan_pos", 0)
    assert first_scan_pos == len(state.tool_history)

    # Append a large untruncated legacy entry and ensure fallback truncates it.
    state.tool_history.append(
        ToolExecution(
            tool_name="execute",
            arguments={"command": "cat huge.log"},
            result={"stdout": "A" * 80_000},
        )
    )
    state.add_message("assistant", "next")

    latest = state.tool_history[-1].result["stdout"]
    assert "... [TRUNCATED]" in latest
    assert len(latest) < 80_000


def test_add_evidence_full_log_scan():
    """Deduplication should check ALL entries, not just the last 50."""
    state = AgentState()
    # Fill up evidence_log with 60 unrelated entries
    for i in range(60):
        state.add_evidence(
            phase="RECON",
            source_tool="execute",
            summary=f"Unique finding number {i} with distinct content",
        )
    original_count = len(state.evidence_log)
    # Now try to add the very first entry again
    result = state.add_evidence(
        phase="RECON",
        source_tool="execute",
        summary="Unique finding number 0 with distinct content",
    )
    assert result is False
    assert len(state.evidence_log) == original_count


# ---------------------------------------------------------------------------
# Dead-host tracking (add_dead_host)
# ---------------------------------------------------------------------------


class TestAddDeadHost:
    def test_new_host_returns_true(self):
        state = AgentState()
        assert state.add_dead_host("api.example.com") is True
        assert "api.example.com" in state.dead_hosts

    def test_duplicate_host_returns_false(self):
        state = AgentState()
        state.add_dead_host("dead.example.com")
        assert state.add_dead_host("dead.example.com") is False
        assert state.dead_hosts.count("dead.example.com") == 1

    def test_normalises_scheme_and_port(self):
        state = AgentState()
        state.add_dead_host("https://api.example.com:8443/path")
        assert "api.example.com" in state.dead_hosts

    def test_empty_host_returns_false(self):
        state = AgentState()
        assert state.add_dead_host("") is False
        assert state.dead_hosts == []

    def test_cap_at_500(self):
        state = AgentState()
        for i in range(510):
            state.add_dead_host(f"sub{i}.example.com")
        assert len(state.dead_hosts) == 500
        # Newest entries are kept
        assert "sub509.example.com" in state.dead_hosts
        # Oldest are dropped
        assert "sub0.example.com" not in state.dead_hosts

    def test_dead_hosts_injected_in_focus_context(self):
        state = AgentState()
        state.ensure_phase_objectives("RECON", ["Find subdomains"])
        state.add_dead_host("nxdomain.example.com")
        ctx = state.build_focus_context("RECON")
        assert "nxdomain.example.com" in ctx
        assert "dead_hosts" in ctx


# ---------------------------------------------------------------------------
# Failure log (add_failure / retry_failure / get_failure_summary)
# ---------------------------------------------------------------------------


class TestFailureLog:
    def test_add_failure_returns_id(self):
        state = AgentState()
        fid = state.add_failure(
            "httpx", "could not resolve host dead.com", target="dead.com"
        )
        assert isinstance(fid, str)
        assert len(fid) == 8

    def test_auto_classify_network_error(self):
        state = AgentState()
        state.add_failure("curl", "name_not_resolved: dead.example.com")
        assert state.failure_log[0]["error_type"] == "network"

    def test_auto_classify_auth_error(self):
        state = AgentState()
        state.add_failure("browser_action", "401 Unauthorized")
        assert state.failure_log[0]["error_type"] == "auth"

    def test_auto_classify_timeout(self):
        state = AgentState()
        state.add_failure("execute", "Timed out after 30s")
        assert state.failure_log[0]["error_type"] == "timeout"

    def test_retry_failure_allows_within_limit(self):
        state = AgentState()
        fid = state.add_failure("browser_action", "403 Forbidden")  # auth → limit=2
        assert state.retry_failure(fid) is True
        assert state.retry_failure(fid) is True
        assert state.retry_failure(fid) is False  # 3rd retry blocked

    def test_retry_failure_network_never_retries(self):
        state = AgentState()
        fid = state.add_failure("execute", "nxdomain error")  # network → limit=0
        assert state.retry_failure(fid) is False

    def test_retry_failure_unknown_id_returns_false(self):
        state = AgentState()
        assert state.retry_failure("notexist") is False

    def test_failure_log_pruned_at_50(self):
        state = AgentState()
        for i in range(55):
            state.add_failure(f"tool_{i}", "some error")
        assert len(state.failure_log) == 50

    def test_get_failure_summary_empty(self):
        state = AgentState()
        summary = state.get_failure_summary()
        assert summary == {"total": 0}

    def test_get_failure_summary_aggregates(self):
        state = AgentState()
        state.add_failure("execute", "nxdomain: a.com")
        state.add_failure("execute", "nxdomain: b.com")
        state.add_failure("browser_action", "401 unauthorized")
        summary = state.get_failure_summary()
        assert summary["total"] == 3
        assert summary["by_type"]["network"] == 2
        assert summary["by_type"]["auth"] == 1
        assert summary["most_common"] == "network"

    def test_failure_summary_in_focus_context(self):
        state = AgentState()
        state.ensure_phase_objectives("RECON", ["Find subdomains"])
        state.add_failure("execute", "nxdomain: dead.example.com")
        ctx = state.build_focus_context("RECON")
        assert "failure_summary" in ctx
        assert "network" in ctx


# ---------------------------------------------------------------------------
# Objective dependency graph (add_objective_dependency / get_blocked_objectives)
# ---------------------------------------------------------------------------


class TestObjectiveDependencies:
    def test_add_dependency_stores_correctly(self):
        state = AgentState()
        state.add_objective_dependency("Exploit SQLi", "Find injection point")
        assert "Find injection point" in state.objective_dependencies["Exploit SQLi"]

    def test_duplicate_dependency_not_added_twice(self):
        state = AgentState()
        state.add_objective_dependency("A", "B")
        state.add_objective_dependency("A", "B")
        assert state.objective_dependencies["A"].count("B") == 1

    def test_get_blocked_when_dependency_pending(self):
        state = AgentState()
        state.ensure_phase_objectives("RECON", ["Find injection point"])
        state.add_objective_dependency("Exploit SQLi", "Find injection point")
        blocked = state.get_blocked_objectives()
        assert "Exploit SQLi" in blocked

    def test_get_unblocked_when_dependency_done(self):
        state = AgentState()
        state.ensure_phase_objectives("RECON", ["Find injection point"])
        state.mark_objective("RECON", "Find injection point", "done")
        state.add_objective_dependency("Exploit SQLi", "Find injection point")
        blocked = state.get_blocked_objectives()
        assert "Exploit SQLi" not in blocked

    def test_cyclic_dependency_does_not_hang(self):
        state = AgentState()
        state.add_objective_dependency("A", "B")
        state.add_objective_dependency("B", "A")
        # Should return quickly without infinite loop; both are blocked
        blocked = state.get_blocked_objectives()
        assert isinstance(blocked, list)
