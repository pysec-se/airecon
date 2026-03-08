import pytest
from airecon.proxy.agent.session import SessionData
from airecon.proxy.agent.models import AgentState
from unittest import mock
import asyncio
import concurrent.futures
from functools import partial


class _PatchProxy:
    """Small subset of pytest-mock's patch API used in this test suite."""

    def __init__(self, owner: "_SimpleMocker") -> None:
        self._owner = owner

    def __call__(self, target: str, *args, **kwargs):
        return self._owner._start(mock.patch(target, *args, **kwargs))

    def object(self, target, attribute: str, *args, **kwargs):
        return self._owner._start(
            mock.patch.object(target, attribute, *args, **kwargs)
        )


class _SimpleMocker:
    """Fallback mocker fixture when pytest-mock is unavailable."""

    MagicMock = mock.MagicMock
    mock_open = staticmethod(mock.mock_open)

    def __init__(self) -> None:
        self._active_patchers: list[object] = []
        self.patch = _PatchProxy(self)

    def _start(self, patcher):
        started = patcher.start()
        self._active_patchers.append(patcher)
        return started

    def stopall(self) -> None:
        for patcher in reversed(self._active_patchers):
            patcher.stop()
        self._active_patchers.clear()


@pytest.fixture
def mocker():
    """Compatibility fixture for tests expecting pytest-mock's `mocker`."""
    m = _SimpleMocker()
    try:
        yield m
    finally:
        m.stopall()


@pytest.fixture(autouse=True)
def _stable_asyncio_to_thread(monkeypatch):
    """Test-only shim for Python 3.13 loop-shutdown hangs with asyncio.to_thread."""

    async def _to_thread(func, /, *args, **kwargs):
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return await loop.run_in_executor(pool, partial(func, *args, **kwargs))

    monkeypatch.setattr(asyncio, "to_thread", _to_thread)


@pytest.fixture
def mock_session():
    """Returns a basic SessionData instance."""
    return SessionData(target="example.com")


@pytest.fixture
def mock_agent_state():
    """Returns a basic AgentState instance."""
    return AgentState(active_target="example.com")


@pytest.fixture
def sample_parsed_nmap_output():
    """Returns sample parsed nmap output dictionary format."""
    return {
        "tool": "nmap",
        "summary": "Nmap: 2 open ports found (1 hosts up)",
        "items": ["80/tcp open http", "443/tcp open https"],
        "total_count": 2,
    }
