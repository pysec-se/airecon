from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_DATA_FILE = Path(__file__).parent.parent / "data" / "owasp_rules.json"

_NEG_CONTEXT_WINDOW = 120

_NEG_PREFIX_WINDOW = 25
_NEG_PREFIX_RE = re.compile(
    r"\b(no|not|none|never|without|non|cannot|can't|didn't|doesn't|isn't|wasn't|failed to|unable to)\b",
    re.IGNORECASE,
)

def _load_rules() -> list[dict[str, Any]]:
    import logging as _log
    try:
        with _DATA_FILE.open(encoding="utf-8") as f:
            data = json.load(f)
        return data["rules"]
    except FileNotFoundError:
        _log.getLogger("airecon.owasp").error(
            "owasp_rules.json not found at %s — OWASP classification disabled", _DATA_FILE
        )
        return []
    except (KeyError, json.JSONDecodeError) as e:
        _log.getLogger("airecon.owasp").error(
            "Failed to parse owasp_rules.json: %s — OWASP classification disabled", e
        )
        return []

_RAW_RULES: list[dict[str, Any]] = _load_rules()

def _build_pattern(words: list[str]) -> re.Pattern[str]:
    escaped = sorted((re.escape(w) for w in words), key=len, reverse=True)
    return re.compile("|".join(escaped), re.IGNORECASE)

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

def _negated_in_context(text: str, match: re.Match[str], neg_pattern: re.Pattern[str]) -> bool:
    start = max(0, match.start() - _NEG_CONTEXT_WINDOW)
    end = min(len(text), match.end() + _NEG_CONTEXT_WINDOW)
    context = text[start:end]
    if neg_pattern.search(context):
        return True

    prefix_start = max(0, match.start() - _NEG_PREFIX_WINDOW)
    prefix = text[prefix_start:match.start()]
    return bool(_NEG_PREFIX_RE.search(prefix))

def _negated_anywhere(text: str, neg_pattern: re.Pattern[str]) -> bool:
    return bool(neg_pattern.search(text))

def classify_owasp(
    summary: str,
    tags: list[str],
    source_tool: str = "",
) -> list[str]:
    text = summary.lower()
    tag_set = frozenset(t.lower() for t in tags)
    matched: list[str] = []

    for owasp_id, _name, kw_pat, hc_pat, neg_pat, rule_tags, _sev in _COMPILED:
        owasp_tag = f"owasp:{owasp_id}"
        if owasp_tag in matched:
            continue

        if hc_pat and hc_pat.search(text):
            matched.append(owasp_tag)
            continue

        kw_match = kw_pat.search(text)
        if kw_match:
            if neg_pat and _negated_in_context(text, kw_match, neg_pat):
                continue
            matched.append(owasp_tag)
            continue

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
    text = summary.lower()
    tag_set = frozenset(t.lower() for t in tags)
    max_sev = 1

    for _owasp_id, _name, kw_pat, hc_pat, neg_pat, rule_tags, base_sev in _COMPILED:

        if hc_pat and hc_pat.search(text):
            candidate = min(5, base_sev + 1)
            if candidate > max_sev:
                max_sev = candidate
            continue

        kw_match = kw_pat.search(text)
        if kw_match:
            if neg_pat and _negated_in_context(text, kw_match, neg_pat):
                continue
            if base_sev > max_sev:
                max_sev = base_sev
            continue

        if tag_set & rule_tags:
            if neg_pat and _negated_anywhere(text, neg_pat):
                continue
            if base_sev > max_sev:
                max_sev = base_sev

    if confidence < 0.6 and max_sev > 1:
        max_sev -= 1

    return max_sev

def get_rule(owasp_id: str) -> dict[str, Any] | None:
    clean = owasp_id.replace("owasp:", "")
    for rule in _RAW_RULES:
        if rule["id"] == clean:
            return rule
    return None

def remediation_for_owasp(owasp_id: str) -> list[str]:
    rule = get_rule(owasp_id)
    return rule.get("remediation", []) if rule else []

def cwe_for_owasp(owasp_id: str) -> list[str]:
    rule = get_rule(owasp_id)
    return rule.get("cwe", []) if rule else []

def owasp_label(owasp_id: str) -> str:
    rule = get_rule(owasp_id)
    if rule:
        return f"{rule['id']} – {rule['name']}"
    return owasp_id

def severity_label(severity: int) -> str:
    return {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}.get(severity, "Info")

def _evidence_risk_summary_hash(evidence: tuple) -> dict[str, Any]:

    sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    owasp_counts: dict[str, int] = {}

    for ev in evidence:
        sev = int(ev[0])
        label = severity_label(sev)
        sev_counts[label] = sev_counts.get(label, 0) + 1
        for tag in ev[1]:
            if tag.startswith("owasp:"):
                owasp_counts[tag] = owasp_counts.get(tag, 0) + 1

    top_owasp = sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    return {
        "severity_distribution": sev_counts,
        "top_owasp_categories": [{"id": k, "count": v} for k, v in top_owasp],
        "total_evidence": len(evidence),
        "high_or_critical": sev_counts["Critical"] + sev_counts["High"],
    }


def evidence_risk_summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:

    if not evidence:
        return _evidence_risk_summary_hash(())

    evidence_tuple = tuple(
        (item.get("severity", 1), tuple(item.get("tags", [])))
        for item in evidence
    )
    return _evidence_risk_summary_hash(evidence_tuple)
