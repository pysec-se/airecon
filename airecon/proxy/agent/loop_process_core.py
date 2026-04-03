from __future__ import annotations

import logging
from typing import AsyncIterator

from .loop_message_entry import _MessageEntryMixin
from .loop_tool_cycle import _ToolCycleMixin
from .models import AgentEvent

logger = logging.getLogger("airecon.agent")


class _ProcessMessageCoreMixin(_MessageEntryMixin, _ToolCycleMixin):
    async def _process_message_core(self, user_message: str) -> AsyncIterator[AgentEvent]:
        try:
            cfg = await self._prepare_message_context(user_message)
            async for event in self._run_iteration_loop(cfg):
                yield event
        except Exception as e:
            logger.exception("Fatal error in agent loop")
            yield AgentEvent(
                type="error", data={"message": f"Fatal Agent Error: {str(e)}"}
            )
            yield AgentEvent(type="done", data={})
