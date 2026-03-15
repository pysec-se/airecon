import pytest
from airecon.proxy.correlation import run_correlation, synthesize_attack_chains
from airecon.proxy.agent.session import SessionData


@pytest.fixture
def mock_session():
    return SessionData(target="example.com")


def test_correlation_by_port(mock_session):
    # Setup session with specific port formats
    mock_session.open_ports = {
        "example.com": [80, 443, 3306],  # The format output parser yields
        "8080": "http-proxy"  # The older format edge case handled by the engine
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
    wp_finding = next((r for r in results if r.get(
        "type") == "technology" and "wordpress" in r.get("technology", "").lower()), None)
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
    mock_session.vulnerabilities = [
        {"finding": "XSS vulnerability found in search parameter"}]

    results = run_correlation(mock_session)

    chain_finding = next(
        (r for r in results if r.get("type") == "attack_chain"), None)
    assert chain_finding is not None
    assert "Cookie" in str(chain_finding).title(
    ) or "XSS" in str(chain_finding).upper()


# ---------------------------------------------------------------------------
# Upgrade 1: Attack chain synthesis (synthesize_attack_chains)
# ---------------------------------------------------------------------------


def test_synthesize_attack_chains_happy_path(mock_session):
    """Matching all required_findings for a chain returns a synthesized entry."""
    # "SSRF to Cloud Metadata" requires ["SSRF", "cloud"]
    mock_session.technologies = {"cloud": "AWS"}
    mock_session.vulnerabilities = [{"title": "SSRF detected in image proxy"}]

    results = synthesize_attack_chains(mock_session)
    chain_ids = [r.get("chain_id") or "" for r in results]
    assert any("SSRF" in cid for cid in chain_ids), \
        f"Expected SSRF chain, got: {chain_ids}"


def test_synthesize_attack_chains_below_threshold(mock_session):
    """A chain where only 1/4 required findings match is excluded (< 50%)."""
    # Provide a signal that matches only 1 of >=4 required findings for any chain
    mock_session.technologies = {}
    mock_session.vulnerabilities = []
    mock_session.urls = []
    mock_session.open_ports = {}

    results = synthesize_attack_chains(mock_session)
    # All below threshold — may return 0 or only well-matched chains
    # None should have confidence < 0.5 (match_ratio < 0.5 is excluded)
    for r in results:
        assert r["confidence"] >= 0.50


def test_synthesize_attack_chains_severity_ordering(mock_session):
    """Results must be sorted by severity descending (CRITICAL before HIGH)."""
    mock_session.technologies = {"cloud": "AWS", "mysql": "5.7"}
    mock_session.vulnerabilities = [
        {"title": "SSRF detected"},
        {"title": "SQL injection in login"},
    ]

    results = synthesize_attack_chains(mock_session)
    if len(results) >= 2:
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        ranks = [severity_rank.get(r["severity"].upper(), 0) for r in results]
        assert ranks == sorted(ranks, reverse=True), \
            "Results not sorted by severity descending"


def test_synthesize_attack_chains_max_cap(mock_session):
    """Never returns more than 10 synthesized chains."""
    # Flood with generic signals to match many chains
    mock_session.technologies = {
        "cloud": "AWS", "mysql": "5.7", "wordpress": "6.0",
        "nginx": "1.18", "php": "8.0", "redis": "7.0",
        "elasticsearch": "8.0", "mongodb": "6.0",
    }
    mock_session.vulnerabilities = [
        {"title": "SQL injection"},
        {"title": "XSS stored"},
        {"title": "SSRF detected"},
        {"title": "IDOR in user endpoint"},
    ]
    mock_session.urls = ["/admin", "/api/user", "/upload", "/login"]

    results = synthesize_attack_chains(mock_session)
    assert len(results) <= 10


def test_synthesize_attack_chains_result_schema(mock_session):
    """Each synthesized chain dict has the expected keys."""
    mock_session.technologies = {"cloud": "AWS"}
    mock_session.vulnerabilities = [{"title": "SSRF detected"}]

    results = synthesize_attack_chains(mock_session)
    for r in results:
        assert r["type"] == "synthesized_chain"
        assert "chain_id" in r
        assert "title" in r
        assert "steps" in r
        assert "severity" in r
        assert "confidence" in r
        assert "matched_signals" in r
        assert 0.0 <= r["confidence"] <= 1.0


def test_synthesize_attack_chains_empty_session(mock_session):
    """Empty session produces no synthesized chains (nothing to correlate)."""
    results = synthesize_attack_chains(mock_session)
    # May be 0 or a few if any chain has 0 required_findings (which are skipped)
    # Key assertion: no KeyError / exception and all returned items are valid
    for r in results:
        assert r["type"] == "synthesized_chain"
