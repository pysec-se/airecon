from __future__ import annotations

import logging
from typing import AsyncIterator

from .loop_message_entry import _MessageEntryMixin
from .loop_tool_cycle import _ToolCycleMixin
from .models import AgentEvent

logger = logging.getLogger("airecon.agent")

try:
    from ..server import _trace_chat_event
except (ImportError, ValueError):
    try:
        from airecon.proxy.server import _trace_chat_event
    except (ImportError, ValueError):
        def _trace_chat_event(*args, **kwargs):
            pass


class _ProcessMessageCoreMixin(_MessageEntryMixin, _ToolCycleMixin):
    async def _process_message_core(self, user_message: str) -> AsyncIterator[AgentEvent]:
        trace_id = getattr(self, "_current_trace_id", None)
        if trace_id:
            _trace_chat_event(trace_id, "agent_loop_started", user_message_len=len(user_message))
        try:
            cfg = await self._prepare_message_context(user_message)
            async for event in self._run_iteration_loop(cfg):
                yield event
        except Exception as e:
            if trace_id:
                _trace_chat_event(trace_id, "agent_loop_error", error=str(e))
            logger.exception("Fatal error in agent loop")
            yield AgentEvent(
                type="error", data={"message": f"Fatal Agent Error: {str(e)}"}
            )
            yield AgentEvent(type="done", data={})
        else:
            if trace_id:
                _trace_chat_event(trace_id, "agent_loop_finished")
