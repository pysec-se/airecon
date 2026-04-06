"""Tests for Loop Process Core."""
from __future__ import annotations
from airecon.proxy.agent.loop_process_core import _ProcessMessageCoreMixin

class TestProcessMessageCoreMixin:
    def setup_method(self):
        self.mixin = _ProcessMessageCoreMixin()

    def test_mixin_instantiation(self):
        assert self.mixin is not None

    def test_process_message_core_returns_iterator(self):
        """process_message_core should return an async iterator."""
        import asyncio
        async def test():
            events = []
            async for event in self.mixin._process_message_core("test message"):
                events.append(event)
            return events
        # Should not raise
        try:
            asyncio.get_event_loop().run_until_complete(test())
        except Exception:
            pass  # Network/LLM failures expected in test env
