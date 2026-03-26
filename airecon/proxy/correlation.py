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
import logging
import re
from pathlib import Path
from typing import Any

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
_attack_chains_raw = _load("attack_chains.json", default=[])
# Support both formats: new {"chains": [...]} dict and legacy flat list
ATTACK_CHAINS: list[dict] = (
    _attack_chains_raw.get("chains", [])
    if isinstance(_attack_chains_raw, dict)
    else _attack_chains_raw
)
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

# Pre-compiled boundary-aware regexes for each URL path in _URL_TECH_MAP.
# Using word-boundary / delimiter check avoids false positives like "admin"
# matching "/administrator".  Compiled once at module load for performance.
_URL_TECH_PATH_RES: dict[str, re.Pattern[str]] = {
    path: re.compile(re.escape(path) + r"(?:[/?# ]|$)")
    for path in _URL_TECH_MAP
}

# Injection point type → attack chain keyword mapping.
# Connects session.injection_points type_hints to relevant ATTACK_CHAINS entries.
_INJECTION_TO_CHAIN_KEYWORD: dict[str, str] = {
    "IDOR":           "IDOR",
    "SSRF":           "SSRF",
    "OPEN_REDIRECT":  "open redirect",
    "PATH_TRAVERSAL": "LFI",
    "SQLi_XSS":       "SQL injection",
    "AUTH":           "JWT",
}

# Minimum ratio of required_findings that must match to include a chain.
_CHAIN_MIN_MATCH_RATIO: float = 0.5
# Maximum synthesized chains returned (prevent context flooding).
_CHAIN_MAX_RESULTS: int = 10
_CHAIN_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1
}
# Word-boundary pattern to avoid short-word false positives (e.g. "log" in "catalog").
_WORD_BOUNDARY_RE = re.compile(r"\b{}\b", re.IGNORECASE)


def _normalize_port_token(port_value: Any) -> int | None:
    """Return normalized int port from common token formats.

    Supports values like:
    - 443
    - "443"
    - "443/tcp"
    Returns None for unparsable values.
    """
    try:
        return int(str(port_value).split("/", 1)[0])
    except (TypeError, ValueError):
        return None


def _signal_matches(haystack: str, needle: str) -> bool:
    """Return True if a required signal matches text with low false positives."""
    n = needle.strip().lower()
    if not n:
        return False
    # Phrase-like signals keep substring semantics.
    if " " in n or any(ch in n for ch in ("/", ":", "-", "_")):
        return n in haystack
    # Single-word signals use boundaries to avoid partial-token noise.
    return re.search(r"\b" + re.escape(n) + r"\b", haystack, re.IGNORECASE) is not None


def build_attack_graph(session: SessionData) -> dict[str, Any] | None:
    """Build a lightweight attack graph from correlated session signals."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def _add_node(node_id: str, node_type: str, label: str, severity: str = "INFO") -> None:
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append({
            "id": node_id,
            "type": node_type,
            "label": label[:120],
            "severity": severity.upper(),
        })

    # Technology nodes
    for tech, version in list(getattr(session, "technologies", {}).items())[:15]:
        label = f"{tech} {version}".strip()
        _add_node(f"tech:{tech.lower()}", "technology", label, "LOW")

    # Service nodes from correlated ports
    for host, ports in list(getattr(session, "open_ports", {}).items())[:20]:
        if not isinstance(ports, list):
            continue
        for p in ports[:20]:
            p_norm = _normalize_port_token(p)
            if p_norm is None:
                continue
            svc = PORT_CORRELATIONS.get(p_norm, {}).get("service", f"port {p_norm}")
            _add_node(f"svc:{host}:{p_norm}", "service", f"{host}:{p_norm} ({svc})", "LOW")

    # Injection type nodes
    inj_types = sorted({
        str(pt.get("type_hint", "")).upper()
        for pt in getattr(session, "injection_points", [])
        if pt.get("type_hint")
    })
    for inj in inj_types[:10]:
        _add_node(f"inj:{inj}", "injection", inj, "MEDIUM")

    # Vulnerability nodes
    vulns = getattr(session, "vulnerabilities", [])
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    vuln_nodes: list[tuple[str, str, str, dict[str, Any]]] = []  # (node_id, text, severity, raw)
    for idx, v in enumerate(vulns[:20]):
        finding = str(v.get("title") or v.get("finding") or "").strip()
        if not finding:
            continue
        sev = str(v.get("severity", "")).upper()
        if sev in {"5", "4", "3", "2", "1"}:
            sev = {"5": "CRITICAL", "4": "HIGH", "3": "MEDIUM", "2": "LOW", "1": "INFO"}[sev]
        if sev not in sev_rank:
            for lbl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if f"[{lbl}]" in finding.upper():
                    sev = lbl
                    break
        if sev not in sev_rank:
            sev = "MEDIUM"
        node_id = f"vuln:{idx}"
        _add_node(node_id, "vulnerability", finding, sev)
        vuln_nodes.append((node_id, finding.lower(), sev, v))

    # Edges: tech/injection/service -> vulnerability
    tech_keys = list(getattr(session, "technologies", {}).keys())
    for node_id, vuln_text, _, _ in vuln_nodes:
        for tech in tech_keys[:15]:
            if _signal_matches(vuln_text, tech.lower()):
                edges.append({
                    "source": f"tech:{tech.lower()}",
                    "target": node_id,
                    "relation": "affects",
                    "weight": 0.8,
                })
        for inj in inj_types[:10]:
            if _signal_matches(vuln_text, inj.lower().replace("_", " ")):
                edges.append({
                    "source": f"inj:{inj}",
                    "target": node_id,
                    "relation": "vector",
                    "weight": 0.85,
                })
        for host, ports in list(getattr(session, "open_ports", {}).items())[:20]:
            if not isinstance(ports, list):
                continue
            for p in ports[:20]:
                p_norm = _normalize_port_token(p)
                if p_norm is None:
                    continue
                svc = str(PORT_CORRELATIONS.get(p_norm, {}).get("service", "")).lower()
                if svc and _signal_matches(vuln_text, svc):
                    edges.append({
                        "source": f"svc:{host}:{p_norm}",
                        "target": node_id,
                        "relation": "exposes",
                        "weight": 0.7,
                    })

    if len(nodes) < 3 or not vuln_nodes:
        return None

    unique_edges: list[dict[str, Any]] = []
    seen_edge_keys: set[tuple[str, str, str]] = set()
    for e in edges:
        key = (e["source"], e["target"], e["relation"])
        if key in seen_edge_keys:
            continue
        seen_edge_keys.add(key)
        unique_edges.append(e)

    if not unique_edges:
        return None

    # Causal risk model:
    # - severity_component: inherent impact from vulnerability severities
    # - exploitability_component: presence of PoC/report/evidence-backed findings
    # - convergence_component: independent upstream signal types converging on each vuln
    # - killchain_component: breadth of attack-chain stages observed in graph
    # - uncertainty_penalty: many weak/unverified vulns should reduce confidence
    avg_severity = sum(sev_rank.get(sev, 0) for _, _, sev, _ in vuln_nodes) / max(1, len(vuln_nodes))
    severity_component = min(1.0, avg_severity / 4.0)

    exploitability_votes = 0
    weak_findings = 0
    for _, _, _, raw in vuln_nodes:
        if (
            raw.get("report_generated")
            or raw.get("replay_verified")
            or raw.get("verified")
            or raw.get("proof")
            or raw.get("poc_script_code")
            or raw.get("evidence")
        ):
            exploitability_votes += 1
        else:
            weak_findings += 1
    exploitability_component = exploitability_votes / max(1, len(vuln_nodes))

    incoming_types: dict[str, set[str]] = {}
    for edge in unique_edges:
        target = str(edge.get("target", ""))
        source = str(edge.get("source", ""))
        if not target.startswith("vuln:") or ":" not in source:
            continue
        src_type = source.split(":", 1)[0]
        incoming_types.setdefault(target, set()).add(src_type)

    convergence_scores = [
        min(1.0, len(types) / 3.0) for types in incoming_types.values()
    ]
    convergence_component = (
        sum(convergence_scores) / len(convergence_scores) if convergence_scores else 0.0
    )

    node_types_present = {n.get("type", "") for n in nodes}
    killchain_component = len(node_types_present & {"technology", "service", "injection", "vulnerability"}) / 4.0

    uncertainty_penalty = min(0.25, (weak_findings / max(1, len(vuln_nodes))) * 0.25)
    risk_score = round(
        min(
            1.0,
            max(
                0.0,
                (severity_component * 0.38)
                + (exploitability_component * 0.28)
                + (convergence_component * 0.22)
                + (killchain_component * 0.12)
                - uncertainty_penalty,
            ),
        ),
        3,
    )
    return {
        "type": "attack_graph",
        "nodes": nodes[:40],
        "edges": unique_edges[:80],
        "risk_score": risk_score,
        "node_count": len(nodes),
        "edge_count": len(unique_edges),
        "risk_factors": {
            "severity_component": round(severity_component, 3),
            "exploitability_component": round(exploitability_component, 3),
            "convergence_component": round(convergence_component, 3),
            "killchain_component": round(killchain_component, 3),
            "uncertainty_penalty": round(uncertainty_penalty, 3),
        },
    }


def synthesize_attack_chains(session: SessionData) -> list[dict]:
    """Cross-correlate multiple signal types to produce ranked attack chains.

    Unlike the existing per-signal attack_chain entries which fire on ANY single
    match, this function requires >= 50% of required_findings to be satisfied
    simultaneously and scores each chain by how many signals converge.

    Returns a list of ``synthesized_chain`` dicts sorted by (severity, confidence)
    descending, capped at ``_CHAIN_MAX_RESULTS``.
    """
    # --- Build signal bag from all session data sources ---
    # Ports: service names from open_ports, mapped through PORT_CORRELATIONS
    port_signals: list[str] = []
    for host_ports in session.open_ports.values():
        if not isinstance(host_ports, list):
            continue
        for p in host_ports:
            # Handle int ports and common string forms like "443" or "443/tcp".
            p_int = _normalize_port_token(p)
            if p_int is None:
                continue
            info = PORT_CORRELATIONS.get(p_int)
            if info:
                port_signals.append(info.get("service", "").lower())

    # Technologies
    techs = session.technologies
    if isinstance(techs, dict):
        tech_signals = [f"{n} {v}".lower() for n, v in techs.items()]
    else:
        tech_signals = [str(t).lower() for t in techs]

    # Injection point type hints
    inj_signals = [
        ip.get("type_hint", "").lower()
        for ip in getattr(session, "injection_points", [])
        if ip.get("type_hint")
    ]
    inj_signal_str = " ".join(inj_signals)

    # URL paths (token-level, not raw full URLs)
    url_signals = " ".join(session.urls).lower()

    # Existing vulnerability findings
    vuln_signals = " ".join(
        v.get("title", v.get("finding", "")).lower()
        for v in getattr(session, "vulnerabilities", [])
    )

    # Single searchable string combining all signals
    full_signal_str = " ".join(
        port_signals + tech_signals + inj_signals + [url_signals, vuln_signals]
    )

    # --- Score each chain ---
    scored: list[tuple[int, float, dict]] = []
    for chain in ATTACK_CHAINS:
        req = chain.get("required_findings", [])
        if not req:
            continue

        matched: list[str] = []
        high_quality_hits = 0
        for finding in req:
            f = finding.strip()
            if not f:
                continue
            f_lower = f.lower()
            if _signal_matches(full_signal_str, f_lower):
                matched.append(f)
                # Stronger signal if corroborated by explicit vulnerability/injection evidence.
                if _signal_matches(vuln_signals, f_lower) or _signal_matches(inj_signal_str, f_lower):
                    high_quality_hits += 1

        match_ratio = len(matched) / len(req)
        if match_ratio < _CHAIN_MIN_MATCH_RATIO:
            continue

        quality_boost = min(0.15, high_quality_hits * 0.05)
        confidence = round(min(1.0, match_ratio * 1.1 + quality_boost), 2)
        evidence_strength = (
            "high" if high_quality_hits >= 2
            else "medium" if high_quality_hits == 1
            else "low"
        )
        severity_rank = _CHAIN_SEVERITY_RANK.get(
            str(chain.get("severity", "MEDIUM")).upper(), 2
        )
        scored.append((severity_rank, confidence, {
            "type": "synthesized_chain",
            "chain_id": chain.get("name", "Unknown Chain"),
            "title": (
                f"{chain.get('name')} — {len(matched)}/{len(req)} signals matched"
                f" ({', '.join(matched[:3])}{'…' if len(matched) > 3 else ''})"
            ),
            "steps": chain.get("steps", []),
            "severity": chain.get("severity", "MEDIUM"),
            "confidence": confidence,
            "evidence_strength": evidence_strength,
            "required_findings": req,
            "matched_signals": matched,
        }))

    # Sort by severity descending, then confidence descending
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return [item[2] for item in scored[:_CHAIN_MAX_RESULTS]]


def _corr_fingerprint(corr: dict) -> str:
    """Build a stable dedup key for a correlation result.

    Used to prevent the same suggestion being re-injected into context
    every 10 iterations.  Format: "<type>:<key>".
    """
    ctype = corr.get("type", "unknown")
    if ctype == "port":
        return f"port:{corr.get('port', '?')}"
    if ctype in ("technology", "technology_cve"):
        return f"tech:{corr.get('technology', '?')}"
    if ctype == "url_path":
        return f"url_path:{corr.get('path', '?')}"
    if ctype == "expert_test":
        return f"expert:{corr.get('pattern', '?')}"
    if ctype == "zeroday_potential":
        return f"zeroday:{corr.get('pattern', '?')}"
    if ctype == "business_logic":
        return f"bizlogic:{corr.get('pattern', '?')}"
    if ctype == "injection_chain":
        return f"injchain:{corr.get('injection_type', '?')}:{corr.get('chain_name', '?')}"
    if ctype == "attack_chain":
        return f"chain:{corr.get('name', '?')}"
    if ctype == "synthesized_chain":
        return f"synth:{corr.get('chain_id', '?')}"
    if ctype == "attack_graph":
        return (
            f"attack_graph:{corr.get('node_count', 0)}:"
            f"{corr.get('edge_count', 0)}:{corr.get('risk_score', 0)}"
        )
    return f"{ctype}:{str(corr)[:40]}"


def run_correlation(session: SessionData) -> list[dict]:
    """Run full correlation analysis on session data.

    Already-suggested correlations (tracked in session.suggested_correlations)
    are filtered out so the LLM doesn't see the same hint every 10 iterations.
    New suggestions are added to session.suggested_correlations after the call
    (caller responsibility: loop.py updates session after injecting results).
    """
    results = []
    _already_suggested: set[str] = set(
        getattr(session, "suggested_correlations", [])
    )

    # Port-based correlations.
    # session.open_ports is always dict[str, list[int]] — {host: [80, 443, 22]}
    # as produced by update_from_parsed_output() in session.py.
    for port, info in PORT_CORRELATIONS.items():
        for host, host_ports in session.open_ports.items():
            if not isinstance(host_ports, list):
                continue
            normalized_ports = {
                p for p in (_normalize_port_token(v) for v in host_ports) if p is not None
            }
            matched = port in normalized_ports
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
        if _URL_TECH_PATH_RES[path].search(url_str) and tech not in seen_url_techs:
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

    # Synthesized cross-signal attack chains — cross-correlate port + tech +
    # injection + URL + vuln signals together for higher-fidelity suggestions.
    synthesized = synthesize_attack_chains(session)
    results.extend(synthesized)

    # Attack graph synthesis — structural map of pivots and likely chains.
    graph = build_attack_graph(session)
    if graph:
        results.append(graph)

    # --- DEDUP FILTER ---
    # Remove correlations the LLM has already seen this session to prevent
    # context flooding.  New results are registered in session so future calls
    # skip them.  High-severity correlations (CRITICAL) are re-suggested after
    # 5 injections to keep them visible throughout a long session.
    _high_severities = {"CRITICAL", "HIGH"}
    _already_injected_count = len(_already_suggested)
    filtered: list[dict] = []
    new_fingerprints: list[str] = []

    for r in results:
        fp = _corr_fingerprint(r)
        sev = str(r.get("severity", "MEDIUM")).upper()
        # Always show CRITICAL/HIGH correlations on first encounter;
        # re-surface them if the session has grown significantly (every 5 new
        # suggestions) so they're not buried after early iterations.
        already_seen = fp in _already_suggested
        resurface = (
            already_seen
            and sev in _high_severities
            and (_already_injected_count % 5 == 0)
        )
        if not already_seen or resurface:
            filtered.append(r)
            if not already_seen:
                new_fingerprints.append(fp)

    # Persist new fingerprints into session so they're skipped next time.
    _sc = getattr(session, "suggested_correlations", None)
    if _sc is not None:
        for fp in new_fingerprints:
            if fp not in _sc:
                _sc.append(fp)

    return filtered
