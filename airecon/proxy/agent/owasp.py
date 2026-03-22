"""OWASP Web Top 10 (2021) + API Security Top 10 (2023) auto-classifier.

Rules are loaded from proxy/data/owasp_rules.json — edit that file to add or
tune classification rules without touching Python code.

Matching logic (in priority order):
  1. high_confidence_keywords match → base_severity + 1 (capped at 5)
  2. keywords match AND no negative_keyword in ±120-char context → base_severity
  3. tag match AND no negative_keyword in full text → base_severity
  4. No match → severity = 1 (Info)

Confidence penalty: if confidence < 0.6, severity drops by 1 (min 1).

Severity scale (1–5):
  5 — Critical  (RCE, full auth bypass, SQLi with data exfiltration)
  4 — High       (SSRF, IDOR, stored XSS, command injection, JWT flaw)
  3 — Medium     (reflected XSS, CSRF, weak TLS, outdated component)
  2 — Low        (misconfiguration, information disclosure)
  1 — Info       (recon finding, port open, technology fingerprint)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_DATA_FILE = Path(__file__).parent.parent / "data" / "owasp_rules.json"

# Context window (chars) around a keyword match to check for negative words
_NEG_CONTEXT_WINDOW = 120

# Negation words checked within this many chars BEFORE a keyword match
_NEG_PREFIX_WINDOW = 25
_NEG_PREFIX_RE = re.compile(
    r"\b(no|not|none|never|without|non|cannot|can't|didn't|doesn't|isn't|wasn't|failed to|unable to)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Load and compile rules at import time (module-level cache)
# ---------------------------------------------------------------------------

def _load_rules() -> list[dict[str, Any]]:
    with _DATA_FILE.open(encoding="utf-8") as f:
        data = json.load(f)
    return data["rules"]


_RAW_RULES: list[dict[str, Any]] = _load_rules()


def _build_pattern(words: list[str]) -> re.Pattern[str]:
    """Build a compiled regex OR-pattern from a list of keyword strings."""
    escaped = sorted((re.escape(w) for w in words), key=len, reverse=True)
    return re.compile("|".join(escaped), re.IGNORECASE)


# Compiled rule cache:
# (owasp_id, name, kw_pattern, hc_pattern|None, neg_pattern|None, tag_set, base_severity)
_COMPILED: list[tuple[
    str, str,
    re.Pattern[str],
    re.Pattern[str] | None,
    re.Pattern[str] | None,
    frozenset[str],
    int,
]] = []

for _rule in _RAW_RULES:
    _kw_pat = _build_pattern(_rule["keywords"])

    _hc_words = _rule.get("high_confidence_keywords", [])
    _hc_pat = _build_pattern(_hc_words) if _hc_words else None

    _neg_words = _rule.get("negative_keywords", [])
    _neg_pat = _build_pattern(_neg_words) if _neg_words else None

    _COMPILED.append((
        _rule["id"],
        _rule["name"],
        _kw_pat,
        _hc_pat,
        _neg_pat,
        frozenset(t.lower() for t in _rule["tags"]),
        int(_rule["base_severity"]),
    ))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _negated_in_context(text: str, match: re.Match[str], neg_pattern: re.Pattern[str]) -> bool:
    """Return True if a negative keyword OR a negation prefix word appears near the match.

    Two checks:
    1. Negative phrase within ±_NEG_CONTEXT_WINDOW chars (from rule's negative_keywords)
    2. Negation word (no/not/none/…) within _NEG_PREFIX_WINDOW chars BEFORE the match
    """
    start = max(0, match.start() - _NEG_CONTEXT_WINDOW)
    end = min(len(text), match.end() + _NEG_CONTEXT_WINDOW)
    context = text[start:end]
    if neg_pattern.search(context):
        return True

    # Check for negation word in the N chars immediately before the matched keyword
    prefix_start = max(0, match.start() - _NEG_PREFIX_WINDOW)
    prefix = text[prefix_start:match.start()]
    return bool(_NEG_PREFIX_RE.search(prefix))


def _negated_anywhere(text: str, neg_pattern: re.Pattern[str]) -> bool:
    """Return True if a negative keyword appears anywhere in text (used for tag matches)."""
    return bool(neg_pattern.search(text))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_owasp(
    summary: str,
    tags: list[str],
    source_tool: str = "",
) -> list[str]:
    """Return deduplicated OWASP category tags for a given evidence entry.

    Checks high_confidence_keywords first (strongest signal), then regular
    keywords with negative-context filtering, then tag-based matching.

    Returns list like: ["owasp:A03:2021", "owasp:A10:2021"]
    """
    text = summary.lower()
    tag_set = frozenset(t.lower() for t in tags)
    matched: list[str] = []

    for owasp_id, _name, kw_pat, hc_pat, neg_pat, rule_tags, _sev in _COMPILED:
        owasp_tag = f"owasp:{owasp_id}"
        if owasp_tag in matched:
            continue

        # 1. High-confidence keyword match (no negative check — very specific signals)
        if hc_pat and hc_pat.search(text):
            matched.append(owasp_tag)
            continue

        # 2. Regular keyword match with negative context filtering
        kw_match = kw_pat.search(text)
        if kw_match:
            if neg_pat and _negated_in_context(text, kw_match, neg_pat):
                continue  # e.g. "no sql injection found" — skip
            matched.append(owasp_tag)
            continue

        # 3. Tag-based match with full-text negative check
        if tag_set & rule_tags:
            if neg_pat and _negated_anywhere(text, neg_pat):
                continue
            matched.append(owasp_tag)

    return matched


def severity_for_evidence(
    summary: str,
    tags: list[str],
    confidence: float,
    source_tool: str = "",
) -> int:
    """Return severity score 1–5 for an evidence entry.

    High-confidence keyword matches boost severity by +1 (capped at 5).
    Confidence < 0.6 applies a -1 penalty (min 1).
    """
    text = summary.lower()
    tag_set = frozenset(t.lower() for t in tags)
    max_sev = 1

    for _owasp_id, _name, kw_pat, hc_pat, neg_pat, rule_tags, base_sev in _COMPILED:
        # High-confidence match → boost
        if hc_pat and hc_pat.search(text):
            candidate = min(5, base_sev + 1)
            if candidate > max_sev:
                max_sev = candidate
            continue

        # Regular keyword match with negative filtering
        kw_match = kw_pat.search(text)
        if kw_match:
            if neg_pat and _negated_in_context(text, kw_match, neg_pat):
                continue
            if base_sev > max_sev:
                max_sev = base_sev
            continue

        # Tag match with full-text negative check
        if tag_set & rule_tags:
            if neg_pat and _negated_anywhere(text, neg_pat):
                continue
            if base_sev > max_sev:
                max_sev = base_sev

    # Confidence penalty for unconfirmed findings
    if confidence < 0.6 and max_sev > 1:
        max_sev -= 1

    return max_sev


def get_rule(owasp_id: str) -> dict[str, Any] | None:
    """Return the full rule dict for a given OWASP ID (e.g. 'A03:2021')."""
    clean = owasp_id.replace("owasp:", "")
    for rule in _RAW_RULES:
        if rule["id"] == clean:
            return rule
    return None


def remediation_for_owasp(owasp_id: str) -> list[str]:
    """Return remediation steps for a given OWASP tag like 'owasp:A03:2021'."""
    rule = get_rule(owasp_id)
    return rule.get("remediation", []) if rule else []


def cwe_for_owasp(owasp_id: str) -> list[str]:
    """Return CWE IDs for a given OWASP tag like 'owasp:A03:2021'."""
    rule = get_rule(owasp_id)
    return rule.get("cwe", []) if rule else []


def owasp_label(owasp_id: str) -> str:
    """Return human-readable label for an OWASP tag like 'owasp:A03:2021'."""
    rule = get_rule(owasp_id)
    if rule:
        return f"{rule['id']} – {rule['name']}"
    return owasp_id


def severity_label(severity: int) -> str:
    """Return human-readable label for severity 1–5."""
    return {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}.get(severity, "Info")


def evidence_risk_summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate risk metrics across a list of evidence entries."""
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
