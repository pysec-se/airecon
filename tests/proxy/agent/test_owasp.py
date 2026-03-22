from __future__ import annotations

import pytest
from airecon.proxy.agent.owasp import (
    classify_owasp,
    evidence_risk_summary,
    owasp_label,
    severity_for_evidence,
    severity_label,
)


# ── classify_owasp ────────────────────────────────────────────────────────────

def test_classify_sqli_by_keyword():
    tags = classify_owasp("SQL injection found in login form", [], "sqlmap")
    assert "owasp:A03:2021" in tags


def test_classify_xss_by_keyword():
    tags = classify_owasp("Reflected XSS vulnerability detected", [], "dalfox")
    assert "owasp:A03:2021" in tags


def test_classify_ssrf_by_keyword():
    tags = classify_owasp("SSRF via Host header redirect to internal network", [], "execute")
    assert "owasp:A10:2021" in tags


def test_classify_ssrf_by_tag():
    tags = classify_owasp("Server returned 200", ["ssrf"], "execute")
    assert "owasp:A10:2021" in tags


def test_classify_cve_by_keyword():
    tags = classify_owasp("CVE-2023-12345 detected in component", [], "nuclei")
    assert "owasp:A06:2021" in tags


def test_classify_auth_bypass_by_keyword():
    tags = classify_owasp("Auth bypass found via JWT manipulation", [], "execute")
    assert "owasp:A07:2021" in tags


def test_classify_misconfiguration_by_keyword():
    tags = classify_owasp("Directory listing enabled on /uploads", [], "httpx")
    assert "owasp:A05:2021" in tags


def test_classify_broken_access_by_tag():
    tags = classify_owasp("Access to restricted resource", ["idor"], "execute")
    assert "owasp:A01:2021" in tags


def test_classify_crypto_failure_by_keyword():
    tags = classify_owasp("Weak cipher detected in TLS handshake", [], "testssl")
    assert "owasp:A02:2021" in tags


def test_classify_no_match_returns_empty():
    tags = classify_owasp("Port 80 is open", [], "nmap")
    assert tags == []


def test_classify_multiple_categories():
    # SQLi + CVE reference — should match A03 and A06
    tags = classify_owasp("SQL injection CVE-2022-9999 found in parameter", [], "sqlmap")
    assert "owasp:A03:2021" in tags
    assert "owasp:A06:2021" in tags


def test_classify_no_duplicate_tags():
    # Two rules could match A03 via both keyword and tag
    tags = classify_owasp("XSS detected", ["xss"], "dalfox")
    assert tags.count("owasp:A03:2021") == 1


# ── severity_for_evidence ─────────────────────────────────────────────────────

def test_severity_rce_is_critical():
    sev = severity_for_evidence("Remote code execution via RCE payload", [], 0.9)
    assert sev == 5


def test_severity_sqli_high():
    sev = severity_for_evidence("SQL injection in login endpoint", [], 0.85)
    assert sev >= 4


def test_severity_ssrf_high():
    sev = severity_for_evidence("SSRF via internal metadata endpoint", ["ssrf"], 0.8)
    assert sev == 4


def test_severity_misconfiguration_low():
    sev = severity_for_evidence("Default credentials found on admin panel", [], 0.7)
    assert sev == 2


def test_severity_low_confidence_penalty():
    # High-severity finding but low confidence → drops by 1
    sev_high_conf = severity_for_evidence("SQL injection detected", [], 0.9)
    sev_low_conf = severity_for_evidence("SQL injection detected", [], 0.4)
    assert sev_low_conf == sev_high_conf - 1


def test_severity_no_match_returns_info():
    sev = severity_for_evidence("Port 443 is open", [], 0.7)
    assert sev == 1


def test_severity_clamps_minimum_at_1():
    sev = severity_for_evidence("random text with no signals", [], 0.1)
    assert sev >= 1


# ── owasp_label ───────────────────────────────────────────────────────────────

def test_owasp_label_known():
    label = owasp_label("owasp:A03:2021")
    assert "Injection" in label
    assert "A03:2021" in label


def test_owasp_label_unknown_passthrough():
    label = owasp_label("owasp:A99:2021")
    assert label == "owasp:A99:2021"


# ── severity_label ────────────────────────────────────────────────────────────

def test_severity_label_5():
    assert severity_label(5) == "Critical"

def test_severity_label_1():
    assert severity_label(1) == "Info"

def test_severity_label_unknown():
    assert severity_label(0) == "Info"


# ── evidence_risk_summary ─────────────────────────────────────────────────────

def test_risk_summary_empty():
    result = evidence_risk_summary([])
    assert result["total_evidence"] == 0
    assert result["high_or_critical"] == 0


def test_risk_summary_counts_severity():
    evidence = [
        {"severity": 5, "tags": ["owasp:A03:2021"]},
        {"severity": 4, "tags": ["owasp:A10:2021"]},
        {"severity": 2, "tags": []},
        {"severity": 1, "tags": []},
    ]
    result = evidence_risk_summary(evidence)
    assert result["severity_distribution"]["Critical"] == 1
    assert result["severity_distribution"]["High"] == 1
    assert result["severity_distribution"]["Low"] == 1
    assert result["severity_distribution"]["Info"] == 1
    assert result["high_or_critical"] == 2


def test_risk_summary_top_owasp():
    evidence = [
        {"severity": 4, "tags": ["owasp:A03:2021", "xss"]},
        {"severity": 4, "tags": ["owasp:A03:2021"]},
        {"severity": 3, "tags": ["owasp:A10:2021"]},
    ]
    result = evidence_risk_summary(evidence)
    top = result["top_owasp_categories"]
    assert top[0]["id"] == "owasp:A03:2021"
    assert top[0]["count"] == 2


def test_risk_summary_total_evidence():
    evidence = [{"severity": 1, "tags": []}] * 7
    result = evidence_risk_summary(evidence)
    assert result["total_evidence"] == 7
