"""Comprehensive Output Correlation Engine for airecon.

Correlation rules are stored as JSON files in data/ and loaded at import time:
  - data/port_correlations.json        (40+ port rules)
  - data/tech_correlations.json        (86+ technology rules)
  - data/cve_correlations.json         (50+ CVE rules)
  - data/attack_chains.json            (32+ attack chain patterns)
  - data/business_logic_patterns.json  (18+ business logic patterns)
  - data/patterns.json                 (17+ expert testing patterns)
  - data/zeroday_patterns.json         (17+ zero-day discovery patterns)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
import logging

from .agent.session import SessionData

logger = logging.getLogger("airecon.correlation")

_DATA_DIR = Path(__file__).parent / "data"


def _load(filename: str, default: Any = None) -> Any:
    path = _DATA_DIR / filename
    if default is None:
        default = {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load {filename}: {e}")
        return default


# PORT_CORRELATIONS keys are integers in Python but strings in JSON
PORT_CORRELATIONS: dict[int, dict] = {
    int(k): v for k, v in _load("port_correlations.json").items()
}

TECH_CORRELATIONS: dict[str, dict] = _load("tech_correlations.json")
CVE_CORRELATIONS: dict[str, dict] = _load("cve_correlations.json")
ATTACK_CHAINS: list[dict] = _load("attack_chains.json", default=[])
BUSINESS_LOGIC_PATTERNS: dict[str, dict] = _load(
    "business_logic_patterns.json")
EXPERT_TESTING_PATTERNS: dict[str, dict] = _load(
    "patterns.json")
ZERODAY_PATTERNS: dict[str, dict] = _load("zeroday_patterns.json")

# Dynamic URL path → technology map built from tech_correlations paths.
# Replaces 6-entry hardcoded dict — now covers all 86+ technologies.
_URL_TECH_MAP: dict[str, str] = {
    path.lower(): tech
    for tech, info in TECH_CORRELATIONS.items()
    for path in info.get("paths", [])
    if path
}

# Injection point type → attack chain keyword mapping.
# Connects session.injection_points type_hints to relevant ATTACK_CHAINS entries.
_INJECTION_TO_CHAIN_KEYWORD: dict[str, str] = {
    "IDOR":           "IDOR",
    "SSRF":           "SSRF",
    "PATH_TRAVERSAL": "LFI",
    "SQLi_XSS":       "SQL injection",
    "AUTH":           "JWT",
}


def run_correlation(session: SessionData) -> list[dict]:
    """Run full correlation analysis on session data."""
    results = []

    # Port-based correlations.
    # session.open_ports is always dict[str, list[int]] — {host: [80, 443, 22]}
    # as produced by update_from_parsed_output() in session.py.
    for port, info in PORT_CORRELATIONS.items():
        port_str = str(port)
        for host, host_ports in session.open_ports.items():
            if not isinstance(host_ports, list):
                continue
            if port in host_ports or port_str in [str(p) for p in host_ports]:
                matched = True
            else:
                matched = False
            if matched:
                results.append(
                    {
                        "type": "port",
                        "port": port,
                        "service": info.get("service"),
                        "vulnerabilities": info.get("vulns", []),
                        "tools": info.get("tools", []),
                        "severity": info.get("severity", "MEDIUM"),
                    }
                )

    # Handle technologies as either a dict {name: version} or a set {name}
    techs = session.technologies
    if isinstance(techs, dict):
        tech_str = " ".join(
            f"{name} {version}" for name, version in techs.items()
        ).lower()
    else:
        # set of technology names
        tech_str = " ".join(str(t) for t in techs).lower()
    for tech, info in TECH_CORRELATIONS.items():
        if re.search(r"\b" + re.escape(tech.lower()) + r"\b", tech_str):
            results.append(
                {
                    "type": "technology",
                    "technology": tech,
                    "vulnerabilities": info.get("vulns", []),
                    "tools": info.get("tools", []),
                    "paths": info.get("paths", []),
                    "severity": info.get("severity", "MEDIUM"),
                }
            )

    # CVE Correlations based on discovered technologies
    for cve_id, cve_info in CVE_CORRELATIONS.items():
        targets = cve_info.get("targets", [])
        for target in targets:
            if re.search(r"\b" + re.escape(target.lower()) + r"\b", tech_str):
                results.append(
                    {
                        "type": "technology_cve",
                        "technology": target,
                        "vulnerabilities": [f"{cve_id} - {cve_info.get('name')}: {cve_info.get('description')}"],
                        "severity": cve_info.get("severity", "HIGH"),
                    }
                )
                break  # Don't add the same CVE multiple times if multiple targets match

    # URL-based correlations — dynamically built from tech_correlations paths.
    # Detects 86+ technologies based on known paths in discovered URLs.
    url_str = " ".join(session.urls).lower()
    seen_url_techs: set[str] = set()
    for path, tech in _URL_TECH_MAP.items():
        if path in url_str and tech not in seen_url_techs:
            tech_info = TECH_CORRELATIONS.get(tech, {})
            results.append(
                {
                    "type": "url_path",
                    "path": path,
                    "technology": tech,
                    "vulnerabilities": tech_info.get("vulns", [])[:3],
                    "tools": tech_info.get("tools", []),
                    "severity": tech_info.get("severity", "MEDIUM"),
                }
            )
            seen_url_techs.add(tech)

    # Expert testing patterns — normalize indicator case, also check ip_param_names
    # so idor_hotspot fires when user_id/order_id appear as injection_point params.
    ip_param_names_early: set[str] = {
        pt.get("parameter", "").lower().rstrip("[]")
        for pt in getattr(session, "injection_points", [])
        if pt.get("parameter")
    }
    for pattern_name, pattern_info in EXPERT_TESTING_PATTERNS.items():
        indicators = pattern_info.get("indicators", [])
        if any(
            ind.lower() in url_str
            or ind.lower() in tech_str
            or ind.lower() in ip_param_names_early
            for ind in indicators
        ):
            results.append(
                {
                    "type": "expert_test",
                    "pattern": pattern_name,
                    "description": pattern_info.get("description"),
                    "suggested_actions": pattern_info.get("suggested_actions", []),
                    "severity": pattern_info.get("severity", "MEDIUM"),
                }
            )

    # Zero-day discovery patterns — normalize indicator case
    for pattern_name, pattern_info in ZERODAY_PATTERNS.items():
        indicators = pattern_info.get("indicators", [])
        if any(ind.lower() in url_str or ind.lower() in tech_str for ind in indicators):
            results.append(
                {
                    "type": "zeroday_potential",
                    "pattern": pattern_name,
                    "description": pattern_info.get("description"),
                    "test_vectors": pattern_info.get("test_vectors", []),
                    "severity": pattern_info.get("severity", "HIGH"),
                }
            )

    # Injection point-based attack chain suggestions.
    # Maps discovered param types (IDOR/SSRF/etc.) to relevant attack chains.
    # This connects URL discovery → parameter analysis → exploit path.
    injection_points = getattr(session, "injection_points", [])
    if injection_points:
        type_counts: dict[str, int] = {}
        type_params: dict[str, list[str]] = {}
        for pt in injection_points:
            t = pt.get("type_hint", "INJECT")
            type_counts[t] = type_counts.get(t, 0) + 1
            type_params.setdefault(t, [])
            param = pt.get("parameter", "")
            if param and param not in type_params[t]:
                type_params[t].append(param)

        for inj_type, count in type_counts.items():
            chain_keyword = _INJECTION_TO_CHAIN_KEYWORD.get(inj_type)
            if not chain_keyword:
                continue
            for chain in ATTACK_CHAINS:
                req = chain.get("required_findings", [])
                if any(chain_keyword.lower() in r.lower() for r in req):
                    sample_params = type_params.get(inj_type, [])[:3]
                    results.append(
                        {
                            "type": "injection_chain",
                            "injection_type": inj_type,
                            "param_count": count,
                            "sample_params": sample_params,
                            "chain_name": chain.get("name"),
                            "steps": chain.get("steps", []),
                            "severity": chain.get("severity", "HIGH"),
                        }
                    )
                    break  # one chain suggestion per injection type

    # Business Logic patterns — check URL paths and injection_points params.
    # Param names like 'price', 'amount', 'coupon' in injection_points are strong
    # business logic indicators even if not visible in the URL path.
    ip_param_names: set[str] = ip_param_names_early  # reuse set computed above
    for pattern_name, pattern_info in BUSINESS_LOGIC_PATTERNS.items():
        indicators = pattern_info.get("indicators", [])
        if (any(ind.lower() in url_str for ind in indicators) or
                any(ind.lower() in ip_param_names for ind in indicators)):
            results.append(
                {
                    "type": "business_logic",
                    "pattern": pattern_name,
                    "description": pattern_info.get("description"),
                    "suggested_actions": pattern_info.get("suggested_actions", []),
                    "severity": pattern_info.get("severity", "HIGH"),
                }
            )

    # Attack Chains based on current vulnerabilities and context
    vuln_names_str = " ".join([v.get("title", v.get("finding", ""))
                              for v in getattr(session, "vulnerabilities", [])]).lower()
    full_attack_context = url_str + " " + tech_str + " " + vuln_names_str

    for chain in ATTACK_CHAINS:
        req_findings = chain.get("required_findings", [])
        # If any of the required findings match our context, alert the LLM to
        # the chain
        if any(finding.lower() in full_attack_context for finding in req_findings):
            results.append(
                {
                    "type": "attack_chain",
                    "name": chain.get("name"),
                    "steps": chain.get("steps", []),
                    "severity": chain.get("severity", "CRITICAL"),
                }
            )

    return results
