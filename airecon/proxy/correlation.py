"""Comprehensive Output Correlation Engine for airecon.

Correlation rules are stored as JSON files in data/ and loaded at import time:
  - data/port_correlations.json        (40+ port rules)
  - data/tech_correlations.json        (86+ technology rules)
  - data/cve_correlations.json         (20+ CVE rules)
  - data/attack_chains.json            (10+ attack chain patterns)
  - data/business_logic_patterns.json  (8+ business logic patterns)
  - data/expert_testing_patterns.json  (4+ expert testing patterns)
  - data/zeroday_patterns.json         (3+ zero-day discovery patterns)
"""

from __future__ import annotations

import json
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
    "expert_testing_patterns.json")
ZERODAY_PATTERNS: dict[str, dict] = _load("zeroday_patterns.json")


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
        if tech.lower() in tech_str:
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
            if target.lower() in tech_str:
                results.append(
                    {
                        "type": "technology_cve",
                        "technology": target,
                        "vulnerabilities": [f"{cve_id} - {cve_info.get('name')}: {cve_info.get('description')}"],
                        "severity": cve_info.get("severity", "HIGH"),
                    }
                )
                break  # Don't add the same CVE multiple times if multiple targets match

    # URL-based correlations
    url_str = " ".join(session.urls).lower()
    url_patterns = {
        "/wp-admin": "WordPress",
        "/jmx-console": "JBoss",
        "/actuator": "Spring Boot",
        "/graphql": "GraphQL",
        "/api": "REST API",
        "/wp-json": "WordPress",
    }
    for path, tech in url_patterns.items():
        if path in url_str:
            results.append(
                {
                    "type": "url_path",
                    "path": path,
                    "technology": tech,
                    "severity": "MEDIUM",
                }
            )

    # Expert testing patterns
    for pattern_name, pattern_info in EXPERT_TESTING_PATTERNS.items():
        indicators = pattern_info.get("indicators", [])
        if any(ind in url_str or ind in tech_str for ind in indicators):
            results.append(
                {
                    "type": "expert_test",
                    "pattern": pattern_name,
                    "description": pattern_info.get("description"),
                    "suggested_actions": pattern_info.get("suggested_actions", []),
                    "severity": pattern_info.get("severity", "MEDIUM"),
                }
            )

    # Zero-day discovery patterns
    for pattern_name, pattern_info in ZERODAY_PATTERNS.items():
        indicators = pattern_info.get("indicators", [])
        if any(ind in url_str or ind in tech_str for ind in indicators):
            results.append(
                {
                    "type": "zeroday_potential",
                    "pattern": pattern_name,
                    "description": pattern_info.get("description"),
                    "test_vectors": pattern_info.get("test_vectors", []),
                    "severity": "HIGH",
                }
            )

    # Business Logic patterns
    for pattern_name, pattern_info in BUSINESS_LOGIC_PATTERNS.items():
        indicators = pattern_info.get("indicators", [])
        if any(ind in url_str for ind in indicators):
            results.append(
                {
                    "type": "business_logic",
                    "pattern": pattern_name,
                    "description": pattern_info.get("description"),
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
