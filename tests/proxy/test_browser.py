import pytest
from unittest.mock import AsyncMock, patch
from airecon.proxy.browser import BrowserInstance, _generate_totp


def test_generate_totp():
    # standard generation with sample secret
    secret = "JBSWY3DPEHPK3PXP" # Base32 for "Hello!\xDE\xAD\xBE\xEF"
    code = _generate_totp(secret)
    assert len(code) == 6
    assert code.isdigit()


@pytest.fixture
def browser():
    b = BrowserInstance()
    # Mock internal async loops
    b._loop = AsyncMock()
    # Instead of threadsafe launching, pretend run_async resolves instantly
    async def mock_run_async(coro):
        return await coro
    b._run_async = mock_run_async
    return b


@pytest.mark.asyncio
async def test_view_source_truncation(browser, mocker):
    # Setup mock page
    mock_page = AsyncMock()
    
    # Create very long source code
    long_source = "<html>" + ("A" * 30000) + "</html>"
    mock_page.content = AsyncMock(return_value=long_source)
    
    browser.pages = {"tab_1": mock_page}
    
    # Mock getting the state to just return our injected components 
    async def mock_state(*args):
        return {}
    mocker.patch.object(browser, "_get_page_state", new=mock_state)
    
    state = await browser._view_source("tab_1")
    
    assert "page_source" in state
    assert len(state["page_source"]) < len(long_source)
    assert "TRUNCATED" in state["page_source"]
    assert len(state["full_page_source"]) == len(long_source)


@pytest.mark.asyncio
async def test_tab_management(browser, mocker):
    # mock context entirely
    mock_context = AsyncMock()
    browser.context = mock_context
    
    mock_page_1 = AsyncMock()
    mock_page_2 = AsyncMock()
    
    # new_tab execution mock setup
    mock_context.new_page = AsyncMock(side_effect=[mock_page_1, mock_page_2])
    
    async def mock_state(tab_id):
        return {"tab_id": tab_id}
    mocker.patch.object(browser, "_get_page_state", new=mock_state)
    mocker.patch.object(browser, "_setup_console_logging", new_callable=AsyncMock)
    
    # Open tab 1
    state1 = await browser._new_tab("http://1.com")
    assert state1["tab_id"] == "tab_1"
    assert "tab_1" in browser.pages
    
    # Open tab 2
    state2 = await browser._new_tab("http://2.com")
    assert state2["tab_id"] == "tab_2"
    assert browser.current_page_id == "tab_2"
    
    # Switch tab back
    state_switch = await browser._switch_tab("tab_1")
    assert browser.current_page_id == "tab_1"
    
    # Close tab 2
    await browser._close_tab("tab_2")
    assert "tab_2" not in browser.pages
    
    # Disallow closing last tab
    with pytest.raises(ValueError, match="Cannot close the last tab"):
        await browser._close_tab("tab_1")


@pytest.mark.asyncio
async def test_execute_js_parallel(browser, mocker):
    mock_page_1 = AsyncMock()
    mock_page_1.evaluate = AsyncMock(return_value="Result 1")
    mock_page_1.is_closed = mocker.MagicMock(return_value=False)
    
    mock_page_2 = AsyncMock()
    mock_page_2.evaluate = AsyncMock(side_effect=Exception("JS Error"))
    mock_page_2.is_closed = mocker.MagicMock(return_value=False)
    
    browser.pages = {"tab_1": mock_page_1, "tab_2": mock_page_2}
    
    async def mock_state(tab_id):
        return {}
    mocker.patch.object(browser, "_get_page_state", new=mock_state)
    
    state = await browser._execute_js("console.log()", parallel=True)
    
    res = state["js_result"]
    assert "Result 1" in str(res)
    assert "'error': 'JS Error'" in str(res)
