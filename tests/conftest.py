import pytest
from airecon.proxy.agent.session import SessionData
from airecon.proxy.agent.models import AgentState


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
