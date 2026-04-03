from __future__ import annotations
import asyncio
import inspect
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator
from ..config import get_config
from ..ollama import OllamaClient
from .models import AgentEvent
from .session import SessionData, save_session
logger = logging.getLogger('airecon.subagent')

class AgentRole(Enum):
    SCOUT = 'scout'
    EXPLOIT = 'exploit'

@dataclass
class SubagentConfig:
    max_concurrent_agents: int = 2
    auto_exploit: bool = True

class SubagentCoordinator:

    def __init__(self, engine: Any=None, session: SessionData | None=None, config: SubagentConfig | None=None):
        self.engine = engine
        self.session = session or SessionData(target='')
        self.config = config or SubagentConfig()
        self.cfg = get_config()
        self._exploit_queue: asyncio.Queue[AgentEvent] = asyncio.Queue()
        self._scout_active = False
        self._exploit_active = False
        self._stop_requested = False

    async def start_recon(self, target: str, prompt: str) -> AsyncIterator[AgentEvent]:
        from .agent_graph import create_default_graph
        self.session.target = target
        logger.info(f'Starting subagent graph on {target}')
        graph = create_default_graph(target, prompt)
        graph.ollama = OllamaClient(model=self.cfg.ollama_model)
        from ..docker import DockerEngine
        graph.engine = self.engine if self.engine else DockerEngine()
        try:
            async for event in self._stream_graph_events(graph):
                if self._stop_requested:
                    break
                if getattr(event, 'type', None) == 'done':
                    continue
                yield event
        except Exception as e:
            logger.error(f'AgentGraph execution failed on {target}: {e}')
        save_session(self.session)
        yield AgentEvent(type='task_complete', data={'session': self.session.__dict__, 'source': AgentRole.SCOUT.value})

    async def _stream_graph_events(self, graph: Any) -> AsyncIterator[Any]:
        result = graph.execute(self.session)
        if inspect.isawaitable(result):
            result = await result
        if hasattr(result, '__aiter__'):
            async for event in result:
                yield event
            return
        if isinstance(result, (list, tuple)):
            for event in result:
                yield event
            return
        raise TypeError('graph.execute must return an async iterable or awaitable')

    def stop(self) -> None:
        self._stop_requested = True
        logger.info('Subagent coordinator stopping')

class ParallelAgentRunner:

    def __init__(self, max_concurrent: int=3, engine: Any=None):
        self.max_concurrent = max_concurrent
        self.engine = engine
        self._active_tasks: list[asyncio.Task] = []
        self._results: dict[str, SessionData] = {}
        self._cancel_event: asyncio.Event = asyncio.Event()

    def cancel_all(self) -> None:
        self._cancel_event.set()
        for task in self._active_tasks:
            task.cancel()
        logger.info(f'Cancelled {len(self._active_tasks)} active agent tasks')

    async def run_parallel(self, targets: list[str], prompt_template: str) -> dict[str, SessionData]:
        self._cancel_event.clear()
        self._results = {}
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def run_single(target: str, coordinator: SubagentCoordinator) -> tuple[str, SessionData]:
            async for _ in coordinator.start_recon(target, prompt_template):
                if self._cancel_event.is_set():
                    coordinator.stop()
                    break
            return (target, coordinator.session)

        async def bounded_run(target: str) -> tuple[str, SessionData]:
            session = SessionData(target=target)
            coordinator = SubagentCoordinator(engine=self.engine, session=session)
            async with semaphore:
                try:
                    return await run_single(target, coordinator)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.error('Agent for %s failed: %s — setting cancel event for siblings', target, exc)
                    self._cancel_event.set()
                    raise
        tasks = [asyncio.create_task(bounded_run(t)) for t in targets]
        self._active_tasks = tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        self._active_tasks.clear()
        for result in results:
            if isinstance(result, BaseException):
                logger.error('Subagent task raised exception: %s', result)
                continue
            if isinstance(result, tuple):
                target, session = result
                self._results[target] = session
        return dict(self._results)