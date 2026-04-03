from __future__ import annotations

from typing import AsyncIterator

from .models import AgentEvent
from .loop_process_core import _ProcessMessageCoreMixin


class _ProcessMessageMixin(_ProcessMessageCoreMixin):
    def _skill_phase_for_message_start(self) -> str:
        try:
            return self._get_current_phase().value
        except Exception:
            return "RECON"

    async def process_message(self, user_message: str) -> AsyncIterator[AgentEvent]:
        async for event in self._process_message_core(user_message):
            yield event
