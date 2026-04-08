from airecon.proxy.agent.loop_cycle_prelude import (
    _build_graph_chain_prompt,
    _build_novel_discovery_prompt,
    _chain_step_to_text,
)


def test_chain_step_to_text_handles_string():
    assert _chain_step_to_text("probe endpoint") == "probe endpoint"


def test_chain_step_to_text_handles_dict_fields_priority():
    assert _chain_step_to_text({"description": "step desc", "name": "ignored"}) == "step desc"
    assert _chain_step_to_text({"name": "step name"}) == "step name"
    assert _chain_step_to_text({"tool_hint": "execute"}) == "execute"


def test_chain_step_to_text_handles_other_types():
    assert _chain_step_to_text(123) == "123"


def test_build_graph_chain_prompt_accepts_string_severity():
    prompt, chains = _build_graph_chain_prompt(
        [
            {
                "type": "information_disclosure",
                "finding": "Verbose stack trace leaks internal path",
                "severity": "MEDIUM",
                "url": "https://example.com/debug",
            },
            {
                "type": "access_control",
                "finding": "Role manipulation exposes admin area",
                "severity": "HIGH",
                "url": "https://example.com/admin",
            },
        ]
    )

    assert chains
    assert "GRAPH-BASED ATTACK CHAINS" in prompt


def test_build_novel_discovery_prompt_uses_actual_findings():
    prompt = _build_novel_discovery_prompt(
        [
            {
                "finding": "Debug response reveals internal config",
                "category": "information_disclosure",
                "summary": "Unexpected debug output reveals internal config and paths",
                "severity": "LOW",
            },
            {
                "finding": "Extra role parameter grants admin access",
                "category": "access_control",
                "summary": "Odd behavior anomaly when extra role field is accepted",
                "severity": "HIGH",
            },
        ],
        iteration=15,
    )

    assert "NOVEL VECTOR ANALYSIS" in prompt
    assert "Consider combining" in prompt or "Novel tactic:" in prompt
