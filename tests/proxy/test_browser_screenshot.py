"""Tests for browser screenshot and save_pdf functionality."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestScreenshot:
    @pytest.mark.asyncio
    async def test_screenshot_saves_file(self, tmp_path):
        """Screenshot should save PNG to workspace/screenshots/."""
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        instance.context = MagicMock()
        mock_page = AsyncMock()

        def fake_screenshot(path=None, **kwargs):
            if path:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(b"fake_png_data")

        mock_page.screenshot = AsyncMock(side_effect=fake_screenshot)
        mock_page.url = "http://example.com"
        mock_page.title = AsyncMock(return_value="Example")
        mock_page.viewport_size = {"width": 1280, "height": 720}
        mock_page.evaluate = AsyncMock(return_value="text content")
        mock_page.is_closed = MagicMock(return_value=False)
        instance.pages = {"main": mock_page}
        instance.current_page_id = "main"

        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True)

        with patch("airecon.proxy.browser.get_workspace_root", return_value=workspace):
            result = await instance._screenshot("main")

        assert "screenshot_path" in result
        saved_path = Path(result["screenshot_path"])
        assert saved_path.exists()
        assert saved_path.suffix == ".png"
        assert "screenshots" in str(saved_path)

    @pytest.mark.asyncio
    async def test_screenshot_fails_without_tab(self):
        """Screenshot should return error when no tab is available."""
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        instance.pages = {}
        instance.current_page_id = None

        result = await instance._screenshot(None)
        assert result.get("success") is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_screenshot_fails_with_unknown_tab(self):
        """Screenshot should return error for unknown tab_id when no fallback."""
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        instance.pages = {}
        instance.current_page_id = None

        result = await instance._screenshot("nonexistent")
        assert result.get("success") is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_screenshot_handles_workspace_error(self):
        """Screenshot should return error when workspace cannot be determined."""
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        mock_page = AsyncMock()
        mock_page.url = "http://example.com"
        instance.pages = {"main": mock_page}
        instance.current_page_id = "main"

        with patch(
            "airecon.proxy.browser.get_workspace_root",
            side_effect=RuntimeError("no workspace"),
        ):
            result = await instance._screenshot("main")

        assert result.get("success") is False
        assert "error" in result


class TestSavePdf:
    @pytest.mark.asyncio
    async def test_save_pdf_saves_file(self, tmp_path):
        """PDF should be saved to the specified path."""
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        mock_page = AsyncMock()
        mock_page.pdf = AsyncMock()
        mock_page.url = "http://example.com"
        mock_page.title = AsyncMock(return_value="Example")
        mock_page.viewport_size = {"width": 1280, "height": 720}
        mock_page.evaluate = AsyncMock(return_value="text")
        mock_page.is_closed.return_value = False
        instance.pages = {"main": mock_page}
        instance.current_page_id = "main"

        pdf_path = str(tmp_path / "output" / "page.pdf")

        with patch(
            "airecon.proxy.browser.get_workspace_root",
            return_value=tmp_path,
        ):
            result = await instance._save_pdf(pdf_path, "main")

        mock_page.pdf.assert_called_once_with(path=pdf_path)
        assert result.get("pdf_saved") == pdf_path

    @pytest.mark.asyncio
    async def test_save_pdf_relative_path(self, tmp_path):
        """Relative PDF path should be resolved against workspace."""
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        mock_page = AsyncMock()
        mock_page.pdf = AsyncMock()
        mock_page.url = "http://example.com"
        mock_page.title = AsyncMock(return_value="Example")
        mock_page.viewport_size = {"width": 1280, "height": 720}
        mock_page.evaluate = AsyncMock(return_value="text")
        mock_page.is_closed.return_value = False
        instance.pages = {"main": mock_page}
        instance.current_page_id = "main"

        with patch(
            "airecon.proxy.browser.get_workspace_root",
            return_value=tmp_path,
        ):
            result = await instance._save_pdf("output/report.pdf", "main")

        expected = str(tmp_path / "output" / "report.pdf")
        mock_page.pdf.assert_called_once_with(path=expected)
        assert result.get("pdf_saved") == expected

    @pytest.mark.asyncio
    async def test_save_pdf_requires_path(self):
        """save_pdf should raise ValueError for empty path."""
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        instance.pages = {"main": MagicMock()}
        instance.current_page_id = "main"

        with pytest.raises(ValueError, match="file_path is required"):
            await instance._save_pdf("", "main")


class TestGetPageState:
    @pytest.mark.asyncio
    async def test_page_state_without_screenshot(self):
        """_get_page_state should not take screenshot by default."""
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        mock_page = AsyncMock()
        mock_page.url = "http://example.com"
        mock_page.title = AsyncMock(return_value="Example")
        mock_page.viewport_size = {"width": 1280, "height": 720}
        mock_page.evaluate = AsyncMock(return_value="text content")
        mock_page.is_closed.return_value = False
        mock_page.screenshot = AsyncMock()  # Should NOT be called
        instance.pages = {"main": mock_page}
        instance.current_page_id = "main"

        state = await instance._get_page_state("main")

        assert state["url"] == "http://example.com"
        assert state["title"] == "Example"
        assert state["screenshot"] == ""
        mock_page.screenshot.assert_not_called()

    @pytest.mark.asyncio
    async def test_page_state_with_screenshot(self):
        """_get_page_state with include_screenshot=True should take screenshot."""
        import base64
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        mock_page = AsyncMock()
        mock_page.url = "http://example.com"
        mock_page.title = AsyncMock(return_value="Example")
        mock_page.viewport_size = {"width": 1280, "height": 720}
        mock_page.evaluate = AsyncMock(return_value="text content")
        mock_page.is_closed.return_value = False
        mock_page.screenshot = AsyncMock(return_value=b"png_data")
        instance.pages = {"main": mock_page}
        instance.current_page_id = "main"

        state = await instance._get_page_state("main", include_screenshot=True)

        assert state["screenshot"] == base64.b64encode(b"png_data").decode()

    @pytest.mark.asyncio
    async def test_page_state_handles_no_tab(self):
        """_get_page_state should return error dict when no tab available."""
        from airecon.proxy.browser import BrowserInstance

        instance = BrowserInstance()
        instance.pages = {}
        instance.current_page_id = None

        state = await instance._get_page_state(None)

        assert "error" in state
        assert state["screenshot"] == ""
        assert state["url"] == ""
