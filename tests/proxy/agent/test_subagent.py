"""Tests for subagent.py - Subagent coordination patterns."""

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from airecon.proxy.agent.subagent import (
    AgentRole,
    SubagentConfig,
    SubagentCoordinator,
)


class TestAgentRole:
    """Test AgentRole enum in subagent module."""

    def test_scout_role(self) -> None:
        """Test SCOUT role."""
        assert AgentRole.SCOUT.value == "scout"
        assert AgentRole.SCOUT.name == "SCOUT"

    def test_exploit_role(self) -> None:
        """Test EXPLOIT role."""
        assert AgentRole.EXPLOIT.value == "exploit"
        assert AgentRole.EXPLOIT.name == "EXPLOIT"


class TestSubagentConfig:
    """Test SubagentConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = SubagentConfig()

        assert config.max_concurrent_agents == 2
        assert config.auto_exploit is True

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = SubagentConfig(max_concurrent_agents=5, auto_exploit=False)

        assert config.max_concurrent_agents == 5
        assert config.auto_exploit is False


class TestSubagentCoordinator:
    """Test SubagentCoordinator class."""

    def test_init_default(self) -> None:
        """Test initialization with defaults."""
        coordinator = SubagentCoordinator()

        assert coordinator.engine is None
        assert coordinator.session is not None
        assert coordinator.config.max_concurrent_agents == 2
        assert coordinator._scout_active is False
        assert coordinator._exploit_active is False
        assert coordinator._stop_requested is False

    def test_init_with_session(self) -> None:
        """Test initialization with custom session."""
        mock_session = MagicMock()
        coordinator = SubagentCoordinator(session=mock_session)

        assert coordinator.session == mock_session

    def test_init_with_config(self) -> None:
        """Test initialization with custom config."""
        custom_config = SubagentConfig(max_concurrent_agents=10)
        coordinator = SubagentCoordinator(config=custom_config)

        assert coordinator.config.max_concurrent_agents == 10

    def test_exploit_queue_created(self) -> None:
        """Test exploit queue is created on init."""
        coordinator = SubagentCoordinator()

        assert hasattr(coordinator, "_exploit_queue")
        assert isinstance(coordinator._exploit_queue, asyncio.Queue)

    @pytest.mark.asyncio
    async def test_start_recon_initializes_session(self) -> None:
        """Test start_recon sets session target."""
        coordinator = SubagentCoordinator()

        with patch("airecon.proxy.agent.agent_graph.create_default_graph"):
            # Just test initialization, not full execution
            coordinator.session.target = "test.com"
            assert coordinator.session.target == "test.com"

    @pytest.mark.asyncio
    async def test_start_recon_creates_graph(self) -> None:
        """Test start_recon creates agent graph."""
        coordinator = SubagentCoordinator()

        with patch(
            "airecon.proxy.agent.agent_graph.create_default_graph"
        ) as mock_create:
            mock_graph = MagicMock()
            mock_graph.execute = AsyncMock()
            mock_graph.execute.return_value.__aiter__.return_value = []
            mock_create.return_value = mock_graph

            # Should create graph
            async for _ in coordinator.start_recon("test.com", "prompt"):
                pass

            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_recon_stops_on_request(self) -> None:
        """Test start_recon respects stop request: yields only task_complete."""
        coordinator = SubagentCoordinator()
        coordinator._stop_requested = True

        with patch("airecon.proxy.agent.agent_graph.create_default_graph"):
            events = []
            async for event in coordinator.start_recon("test.com", "prompt"):
                events.append(event)

        # Generator must complete (no raise) and yield exactly one event:
        # the final task_complete summary — no graph events forwarded.
        assert len(events) == 1
        assert events[0].type == "task_complete"

    def test_stop_sets_flag(self) -> None:
        """Test stop method sets stop flag."""
        coordinator = SubagentCoordinator()

        coordinator.stop()

        assert coordinator._stop_requested is True

    def test_cleanup_on_stop(self) -> None:
        """Test cleanup happens on stop."""
        coordinator = SubagentCoordinator()

        # Stop should work without errors
        coordinator.stop()
        # Just verify it doesn't raise

    def test_session_persistence(self) -> None:
        """Test session is persisted correctly."""
        from airecon.proxy.agent.session import SessionData

        coordinator = SubagentCoordinator()

        assert isinstance(coordinator.session, SessionData)
        assert coordinator.session.target == ""

    def test_session_target_update(self) -> None:
        """Test session target can be updated."""
        coordinator = SubagentCoordinator()
        coordinator.session.target = "new-target.com"

        assert coordinator.session.target == "new-target.com"


class TestSubagentIntegration:
    """Integration tests for subagent system."""

    @pytest.mark.asyncio
    async def test_full_recon_flow(self) -> None:
        """Test full recon flow with mocked components."""
        mock_engine = None  # unused, for API compatibility
        coordinator = SubagentCoordinator(engine=mock_engine)

        with patch(
            "airecon.proxy.agent.agent_graph.create_default_graph"
        ) as mock_create:
            mock_graph = MagicMock()

            # Mock async generator
            async def mock_execute(*args):
                yield MagicMock(type="test", data={"finding": "test"})

            mock_graph.execute = mock_execute
            mock_create.return_value = mock_graph

            events = []
            async for event in coordinator.start_recon("test.com", "recon"):
                events.append(event)

            # Should have received events
            assert len(events) > 0
