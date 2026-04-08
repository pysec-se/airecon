from __future__ import annotations


def test_loop_semantic_module_importable() -> None:
    from airecon.proxy.agent.loop_semantic import get_deduplicator, reset_deduplicator

    reset_deduplicator()
    dedup = get_deduplicator()

    assert dedup is not None
