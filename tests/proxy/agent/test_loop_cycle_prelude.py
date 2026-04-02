from airecon.proxy.agent.loop_cycle_prelude import _chain_step_to_text


def test_chain_step_to_text_handles_string():
    assert _chain_step_to_text("probe endpoint") == "probe endpoint"


def test_chain_step_to_text_handles_dict_fields_priority():
    assert _chain_step_to_text({"description": "step desc", "name": "ignored"}) == "step desc"
    assert _chain_step_to_text({"name": "step name"}) == "step name"
    assert _chain_step_to_text({"tool_hint": "execute"}) == "execute"


def test_chain_step_to_text_handles_other_types():
    assert _chain_step_to_text(123) == "123"
