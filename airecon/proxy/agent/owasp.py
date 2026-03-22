from __future__ import annotations

"""OWASP Web Top 10 (2021) auto-classifier and severity scorer for evidence entries.

Classifies tool findings into OWASP categories based on summary keywords and
existing tags, and assigns a severity score (1–5) inspired by the Social Impact
Score concept from ai-scanner / 0DIN probes.

Severity scale:
  5 — Critical  (RCE, full auth bypass, SQLi with data exfiltration)
  4 — High       (SSRF, IDOR, stored XSS, command injection, JWT flaw)
  3 — Medium     (reflected XSS, CSRF, weak session, open redirect)
  2 — Low        (misconfiguration, information disclosure, outdated component)
  1 — Info       (recon finding, port open, technology fingerprint)
"""

import re
from typing import Any

# ---------------------------------------------------------------------------
# OWASP Web Top 10 (2021) rule table
# Each rule: (owasp_id, owasp_name, keyword_patterns, tag_matches, base_severity)
# keyword_patterns: regex applied to lowercase summary text
# tag_matches: any of these tags triggers the rule
# ---------------------------------------------------------------------------
_OWASP_RULES: list[tuple[str, str, str, list[str], int]] = [
    (
        "A01:2021",
        "Broken Access Control",
        r"idor|access.control|unauthorized|privilege.escal|broken.access|403.bypass|path.travers",
        ["idor", "access", "privilege"],
        4,
    ),
    (
        "A02:2021",
        "Cryptographic Failures",
        r"ssl|tls|weak.cipher|weak.crypto|certificate|plaintext.password|http\b(?!s)|md5|sha1|insecure.transport",
        ["tls", "ssl", "crypto", "certificate"],
        3,
    ),
    (
        "A03:2021",
        "Injection",
        r"sql.inject|sqli|xss|cross.site.script|ssti|template.inject|command.inject|ldap.inject|nosql|rce|remote.code|os.command|inject",
        ["sqli", "xss", "rce", "injection", "ssti", "xxe"],
        5,
    ),
    (
        "A04:2021",
        "Insecure Design",
        r"logic.flaw|business.logic|insecure.design|race.condition|missing.rate.limit",
        ["logic", "design"],
        3,
    ),
    (
        "A05:2021",
        "Security Misconfiguration",
        r"misconfig|exposed.config|default.cred|debug.mode|stack.trace|directory.listing|open.redirect|xml.rpc|cors.misconfig|exposed.admin|open.port|bannergrab",
        ["misconfiguration", "exposed", "debug", "default"],
        2,
    ),
    (
        "A06:2021",
        "Vulnerable and Outdated Components",
        r"cve-\d{4}|outdated|vulnerable.component|known.vulnerab|eol.version|end.of.life",
        ["cve", "vulnerability"],
        3,
    ),
    (
        "A07:2021",
        "Identification and Authentication Failures",
        r"auth.bypass|brute.force|weak.password|session.fixat|token.leak|jwt|credential.stuff|default.login|no.authentication|unauthenticated",
        ["auth", "authentication", "session", "jwt", "brute"],
        4,
    ),
    (
        "A08:2021",
        "Software and Data Integrity Failures",
        r"deserializ|supply.chain|integrity.check|unsigned.update|tampering",
        ["deserialization", "integrity"],
        4,
    ),
    (
        "A09:2021",
        "Security Logging and Monitoring Failures",
        r"no.logging|missing.log|audit.trail|monitoring.gap",
        ["logging", "monitoring"],
        2,
    ),
    (
        "A10:2021",
        "Server-Side Request Forgery",
        r"ssrf|server.side.request|internal.network|169\.254|metadata.endpoint|127\.0\.0\.1.*fetch|localhost.*fetch",
        ["ssrf"],
        4,
    ),
]

# Pre-compile keyword regexes for performance
_COMPILED_RULES: list[tuple[str, str, re.Pattern[str], list[str], int]] = [
    (owasp_id, name, re.compile(pattern, re.IGNORECASE), tags, sev)
    for owasp_id, name, pattern, tags, sev in _OWASP_RULES
]


def classify_owasp(
    summary: str,
    tags: list[str],
    source_tool: str = "",
) -> list[str]:
    """Return a list of matching OWASP category IDs for a given evidence entry.

    Example return: ["owasp:A03:2021", "owasp:A10:2021"]
    """
    text = summary.lower()
    tag_set = {t.lower() for t in tags}
    matched: list[str] = []

    for owasp_id, _name, pattern, rule_tags, _sev in _COMPILED_RULES:
        if pattern.search(text) or tag_set.intersection(rule_tags):
            matched.append(f"owasp:{owasp_id}")

    return matched


def severity_for_evidence(
    summary: str,
    tags: list[str],
    confidence: float,
    source_tool: str = "",
) -> int:
    """Return a severity score 1–5 for an evidence entry.

    Uses the highest base_severity among matching OWASP rules, then adjusts
    down by one step if confidence < 0.6 (unconfirmed finding).
    """
    text = summary.lower()
    tag_set = {t.lower() for t in tags}
    max_sev = 1

    for _owasp_id, _name, pattern, rule_tags, base_sev in _COMPILED_RULES:
        if pattern.search(text) or tag_set.intersection(rule_tags):
            if base_sev > max_sev:
                max_sev = base_sev

    # Confidence penalty: unconfirmed findings drop one severity step
    if confidence < 0.6 and max_sev > 1:
        max_sev -= 1

    return max_sev


def owasp_label(owasp_id: str) -> str:
    """Return human-readable label for an OWASP tag like 'owasp:A03:2021'."""
    clean = owasp_id.replace("owasp:", "")
    for oid, name, *_ in _OWASP_RULES:
        if oid == clean:
            return f"{oid} – {name}"
    return owasp_id


def severity_label(severity: int) -> str:
    """Return human-readable label for severity 1–5."""
    return {
        5: "Critical",
        4: "High",
        3: "Medium",
        2: "Low",
        1: "Info",
    }.get(severity, "Info")


def evidence_risk_summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate risk metrics across a list of evidence entries.

    Returns a dict with severity distribution and top OWASP categories.
    """
    sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    owasp_counts: dict[str, int] = {}

    for ev in evidence:
        sev = int(ev.get("severity", 1))
        label = severity_label(sev)
        sev_counts[label] = sev_counts.get(label, 0) + 1

        for tag in ev.get("tags", []):
            if tag.startswith("owasp:"):
                owasp_counts[tag] = owasp_counts.get(tag, 0) + 1

    top_owasp = sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "severity_distribution": sev_counts,
        "top_owasp_categories": [{"id": k, "count": v} for k, v in top_owasp],
        "total_evidence": len(evidence),
        "high_or_critical": sev_counts["Critical"] + sev_counts["High"],
    }
