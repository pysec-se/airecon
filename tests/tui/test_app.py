import pytest
from textual.widgets import Input, Static
from unittest.mock import patch, MagicMock
from airecon.tui.app import AIReconApp
from airecon.tui.widgets.input import CommandInput
from airecon.tui.widgets.chat import ChatPanel


@pytest.mark.asyncio
async def test_app_initialization():
    async with AIReconApp().run_test() as pilot:
        assert pilot.app.title == "AIRecon"
        assert pilot.app.sub_title == "AI Security Reconnaissance"

        # Check initial widgets
        assert pilot.app.query_one("#command-input") is not None
        assert pilot.app.query_one("#chat-panel") is not None
        assert pilot.app.query_one("#workspace-panel") is not None


@pytest.mark.asyncio
async def test_app_send_message_triggers_worker():
    with patch.object(AIReconApp, 'run_worker') as mock_run_worker:
        async with AIReconApp().run_test() as pilot:
            command_input = pilot.app.query_one("#command-input", CommandInput)

            # Fill inputs
            command_input.value = "scan server"

            # Submit chat directly via the on_command_input_submitted handler
            class MockSubmitted:
                value = "scan server"
            await pilot.app.on_command_input_submitted(MockSubmitted())
            await pilot.pause()

            # Assert run_worker was called to spawn the SSE streaming thread
            mock_run_worker.assert_called()


@pytest.mark.asyncio
async def test_app_status_polling_connection():
    with patch('httpx.AsyncClient.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ollama": {"connected": True, "model": "test-model"},
            "docker": {"connected": True},
            "agent": {"tool_counts": {"exec": 5, "subagents": 1}}
        }
        mock_get.return_value = mock_response

        async with AIReconApp().run_test() as pilot:
            # Manually trigger a single poll check rather than waiting for the background task
            await pilot.app._check_services(verbose=False)
            await pilot.pause()

            # Ensure status logic executed successfully without crashing
            mock_get.assert_called_with("/api/status", timeout=5.0)
