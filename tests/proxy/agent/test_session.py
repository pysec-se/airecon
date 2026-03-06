import pytest
from airecon.proxy.agent.session import SessionData, generate_session_id, _calculate_similarity, _is_duplicate_vulnerability, update_from_parsed_output
from airecon.proxy.agent.output_parser import ParsedOutput


def test_generate_session_id():
    sid = generate_session_id()
    assert "_" in sid
    assert len(sid.split("_")[1]) == 8


def test_calculate_similarity():
    # Exact match
    v1 = "SQL injection in parameter id"
    v2 = "SQL injection in parameter id"
    assert _calculate_similarity(v1, v2) == 1.0

    # Very similar phrase but different params should fail deduplication
    v1_diff_param = "SQL injection in parameter username"
    assert _calculate_similarity(v1, v1_diff_param) == 0.0

    # Minor differences in punctuation/phrasing
    v3 = "Found Cross-Site Scripting (XSS) vulnerability"
    v4 = "Found cross-site scripting xss vulnerability!"
    # Length of words1/words2 intersection calculation needs adjusting expectation
    assert _calculate_similarity(v3, v4) > 0.4


def test_is_duplicate_vulnerability():
    existing = [
        {"finding": "Reflected XSS in parameter 'q'", "target": "example.com"}
    ]

    new_dup = {"finding": "Reflected XSS in parameter 'q'",
               "target": "example.com"}
    new_diff_param = {
        "finding": "Reflected XSS in parameter 'search'", "target": "example.com"}
    new_diff_target = {
        "finding": "Reflected XSS in parameter 'q'", "target": "api.example.com"}

    assert _is_duplicate_vulnerability(new_dup, existing) is True
    assert _is_duplicate_vulnerability(new_diff_param, existing) is False
    # Combined sim: finding sim is 1.0. 1.0 * 0.8 + 0 * 0.2 = 0.8 which is >= 0.7
    # which means different target but exact same finding string IS considered a duplicate under this logic.
    assert _is_duplicate_vulnerability(new_diff_target, existing) is True


def test_update_from_parsed_output_adds_technologies(mock_session):
    parsed = ParsedOutput(
        tool="httpx",
        summary="Found tech",
        items=[],
        technologies={"nginx": "1.24", "PHP": ""}
    )
    update_from_parsed_output(mock_session, parsed)

    assert mock_session.technologies["nginx"] == "1.24"
    assert mock_session.technologies["PHP"] == ""

    # Test upgrading an empty version
    parsed2 = ParsedOutput(
        tool="whatweb",
        summary="Found PHP ver",
        items=[],
        technologies={"PHP": "8.1"}
    )
    update_from_parsed_output(mock_session, parsed2)
    assert mock_session.technologies["PHP"] == "8.1"


def test_update_from_parsed_output_classifies_items(mock_session):
    parsed = ParsedOutput(
        tool="nmap",
        summary="Scan results",
        items=[
            "[CRITICAL] SQL Injection on login endpoint",
            "https://test.example.com [200]",
            "http://other.example.com",
            "10.0.0.1:8080",
            "443/tcp open https",
            "internal-subdomain.example.com",
            # This shouldn't be matched by anything special
            "Unrelated garbage data"
        ]
    )

    update_from_parsed_output(mock_session, parsed)

    assert len(mock_session.vulnerabilities) == 1
    assert "SQL" in mock_session.vulnerabilities[0]["finding"]

    # live_hosts gets the URL with status code
    assert "https://test.example.com" in mock_session.live_hosts

    # urls gets the bare URL
    assert "http://other.example.com" in mock_session.urls

    # open_ports gets the host:port format
    assert 8080 in mock_session.open_ports["10.0.0.1"]

    # open_ports under target gets the port/proto string
    assert 443 in mock_session.open_ports[mock_session.target]

    # subdomains gets the bare domain string
    assert "internal-subdomain.example.com" in mock_session.subdomains
