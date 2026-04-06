from __future__ import annotations

import logging
from typing import AsyncIterator

from .models import AgentEvent
from .loop_process_core import _ProcessMessageCoreMixin

logger = logging.getLogger("airecon.agent.loop_process")


class _ProcessMessageMixin(_ProcessMessageCoreMixin):
    def _skill_phase_for_message_start(self) -> str:
        try:
            return self._get_current_phase().value
        except Exception as e:
            logger.debug("Failed to get phase for message start: %s", e)
            return "RECON"

    async def process_message(self, user_message: str) -> AsyncIterator[AgentEvent]:
        async for event in self._process_message_core(user_message):
            yield event
