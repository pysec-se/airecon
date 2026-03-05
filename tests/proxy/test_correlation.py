import pytest
from airecon.proxy.correlation import run_correlation
from airecon.proxy.agent.session import SessionData


@pytest.fixture
def mock_session():
    return SessionData(target="example.com")


def test_correlation_by_port(mock_session):
    # Setup session with specific port formats
    mock_session.open_ports = {
        "example.com": [80, 443, 3306], # The format output parser yields
        "8080": "http-proxy" # The older format edge case handled by the engine
    }
    
    results = run_correlation(mock_session)
    
    # Check if 3306 triggered a MySQL finding
    mysql_finding = next((r for r in results if r.get("port") == 3306), None)
    assert mysql_finding is not None
    assert "MySQL" in mysql_finding.get("service", "")


def test_correlation_by_technology_and_cve(mock_session):
    mock_session.technologies = {"WordPress": "5.8", "PHP": ""}
    
    results = run_correlation(mock_session)
    
    # Verify standard tech correlation
    wp_finding = next((r for r in results if r.get("type") == "technology" and "wordpress" in r.get("technology", "").lower()), None)
    assert wp_finding is not None
    assert "wpscan" in str(wp_finding.get("tools", [])).lower()
    
    # The tech should also trigger CVE correlations
    cve_findings = [r for r in results if r.get("type") == "technology_cve"]
    assert len(cve_findings) > 0


def test_correlation_attack_chains(mock_session):
    # Setup context matching an attack chain prerequisite
    # Based on attack_chains.json we know: XSS, Session cookies trigger XSS to Cookie Steal
    mock_session.technologies = {"Session Cookies": ""}
    # Simulate an established finding
    mock_session.vulnerabilities = [{"finding": "XSS vulnerability found in search parameter"}]
    
    results = run_correlation(mock_session)
    
    chain_finding = next((r for r in results if r.get("type") == "attack_chain"), None)
    assert chain_finding is not None
    assert "Cookie" in str(chain_finding).title() or "XSS" in str(chain_finding).upper()
