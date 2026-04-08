from __future__ import annotations

import hashlib
import json
import logging
import random
import re
from pathlib import Path
from typing import Any

from ..data_loader import severity_to_int

logger = logging.getLogger("airecon.agent.novel_discovery")
rng = random.SystemRandom()

_LEARNING_FILE = Path.home() / ".airecon" / "learning" / "novel_vectors.json"

_NOVELTY_MIN_CONFIDENCE = 0.4
_VECTOR_GENERATION_ENABLED = True


def _load_learned_vectors() -> dict[str, Any]:
    try:
        if _LEARNING_FILE.exists():
            return json.loads(_LEARNING_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug("Failed to load learned vectors: %s", e)
    return {}


def _save_learned_vectors(vectors: dict[str, Any]) -> None:
    try:
        _LEARNING_FILE.parent.mkdir(parents=True, exist_ok=True)
        _LEARNING_FILE.write_text(json.dumps(vectors, indent=2), encoding="utf-8")
    except Exception as e:
        logger.debug("Failed to save novel vectors: %s", e)


_LEARNED_VECTORS = _load_learned_vectors()

_ANOMALY_INDICATORS = [
    (r"timeout|timed.out|connection.refused|connection.reset", "network_timeout"),
    (r"unusual|unexpected|anomaly|odd|strange", "behavior_anomaly"),
    (r"differs|difference|changed|modified|alteration", "response_diff"),
    (r"reveal|expose|disclose|leak|display", "information_disclosure"),
    (r"guess|predictable|deterministic|pattern", "predictability"),
    (r"race.condition|toctou|concurrency", "concurrency_issue"),
    (r"cache|poison|stale", "caching_issue"),
    (r"permission|access.denied|unauthorized", "access_control"),
    (r"inconsistent|conflict|contradiction", "logic_conflict"),
    (r"mass.assignment|over.post|extra.field", "mass_assignment"),
]

_COMBINATION_PATTERNS = [
    {
        "name": "Info_Disclosure_to_Auth_Bypass",
        "components": ["information_disclosure", "access_control"],
        "description": "Use leaked info (version, paths, configs) to find auth bypass",
        "escalation": "Use disclosed info to access protected endpoints",
    },
    {
        "name": "Race_Condition_to_Financial_Impact",
        "components": ["concurrency_issue", "logic_conflict"],
        "description": "Exploit race conditions for double-spend or coupon abuse",
        "escalation": "Send multiple concurrent requests to exploit race",
    },
    {
        "name": "Cache_Poisoning_to_Stored_Impact",
        "components": ["caching_issue", "response_diff"],
        "description": "Poison cache with XSS to affect all users",
        "escalation": "Use unkeyed headers to inject malicious content",
    },
    {
        "name": "Mass_Assignment_to_Privilege_Escalation",
        "components": ["mass_assignment", "access_control"],
        "description": "Submit extra fields to escalate privileges",
        "escalation": "Add admin=true or role=admin to request",
    },
    {
        "name": "Prediction_to_Account_Takeover",
        "components": ["predictability", "access_control"],
        "description": "Predictable IDs/tokens allow account enumeration",
        "escalation": "Enumerate and takeover accounts via predictable values",
    },
]

_INNOVATIVE_TACTICS = [
    "Test for business logic flaws in workflow sequences",
    "Check for state machine violations in multi-step processes",
    "Examine for race conditions in time-sensitive operations",
    "Look for mass assignment in API parameter binding",
    "Search for predictable resource identifiers",
    "Check for cache poisoning via unkeyed headers",
    "Test for second-order vulnerabilities (stored XSS, SQLi)",
    "Examine for client-side validation bypass opportunities",
    "Look for information disclosure in error messages",
    "Check for improper handling of file extensions",
    "Test for prototype pollution in JavaScript apps",
    "Search for insecure deserialization in data parsing",
    "Check for broken cryptographic implementations",
    "Examine for improper session management",
    "Look for SAML validation bypass opportunities",
    "Test for OAuth/SSO implementation flaws",
    "Search for JWT validation weaknesses",
    "Check for GraphQL introspection exposure",
    "Examine for WebSocket security issues",
    "Search for API rate limiting bypass",
]


def _detect_anomalies(text: str) -> list[tuple[str, str]]:
    text_lower = text.lower()
    detected = []

    for pattern, category in _ANOMALY_INDICATORS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            detected.append((category, pattern))

    return detected


def _analyze_combination_potential(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if len(findings) < 2:
        return []

    finding_categories = set()
    for f in findings:
        cat = f.get("category", f.get("type", "unknown")).lower()
        finding_categories.add(cat)

    combinations = []
    for pattern in _COMBINATION_PATTERNS:
        match_count = sum(1 for c in pattern["components"] if c in finding_categories)
        if match_count >= 2:
            combinations.append(
                {
                    "name": pattern["name"],
                    "description": pattern["description"],
                    "escalation": pattern["escalation"],
                    "confidence": match_count / len(pattern["components"]),
                    "components_found": [
                        c for c in pattern["components"] if c in finding_categories
                    ],
                }
            )

    return sorted(combinations, key=lambda x: x["confidence"], reverse=True)


def _generate_innovative_tactic() -> str:
    return rng.choice(_INNOVATIVE_TACTICS)


def analyze_novel_vectors(
    findings: list[dict[str, Any]],
    iteration: int = 0,
) -> dict[str, Any]:
    if not findings or not _VECTOR_GENERATION_ENABLED:
        return {
            "novel_vectors": [],
            "combinations": [],
            "innovative_tactics": [],
            "recommendations": [],
        }

    detected_anomalies = []
    for f in findings:
        summary = f.get("summary", f.get("description", ""))
        if summary:
            anomalies = _detect_anomalies(summary)
            detected_anomalies.extend(anomalies)

    unique_anomalies = list(set(detected_anomalies))

    combinations = _analyze_combination_potential(findings)

    tactics = []
    if iteration % 3 == 0:
        tactics.append(_generate_innovative_tactic())

    if iteration % 5 == 0:
        tactics.append(_generate_innovative_tactic())

    recommendations = []
    if combinations:
        recommendations.append(
            f"Consider combining: {combinations[0]['name']} "
            f"({combinations[0]['confidence']:.0%} confidence)"
        )

    if unique_anomalies:
        recommendations.append(
            f"Detected {len(unique_anomalies)} anomaly patterns in findings"
        )

    novel_vectors = []
    vector_seed = hashlib.md5(  # non-cryptographic identifier
        f"{iteration}:{rng.random()}:{len(findings)}".encode(),
        usedforsecurity=False,
    ).hexdigest()[:12]

    if iteration > 10 and len(findings) >= 3:
        vector_id = f"novel_{vector_seed}"
        vector = {
            "id": vector_id,
            "description": "Multi-finding escalation path",
            "bases": [
                f.get("finding", f.get("title", "unknown"))[:50] for f in findings[:3]
            ],
            "escalation": recommendations[0]
            if recommendations
            else "Analyze for escalation",
            "confidence": min(0.7, 0.3 + (len(findings) * 0.1)),
        }

        if vector_id not in _LEARNED_VECTORS:
            _LEARNED_VECTORS[vector_id] = vector
            _LEARNED_VECTORS[vector_id]["discovery_count"] = 0
        _LEARNED_VECTORS[vector_id]["discovery_count"] = (
            _LEARNED_VECTORS[vector_id].get("discovery_count", 0) + 1
        )

        if len(_LEARNED_VECTORS) % 5 == 0:
            _save_learned_vectors(_LEARNED_VECTORS)

        novel_vectors.append(vector)

    result = {
        "novel_vectors": novel_vectors,
        "combinations": combinations[:3],
        "innovative_tactics": tactics,
        "recommendations": recommendations,
        "anomalies_detected": list(set([a[0] for a in unique_anomalies])),
    }

    return result


def get_recommendation_for_finding(
    finding: dict[str, Any],
    all_findings: list[dict[str, Any]],
) -> list[str]:
    recommendations = []

    finding_cat = finding.get("category", "unknown").lower()
    finding_sev = severity_to_int(finding.get("severity", 3))

    if finding_sev <= 2:
        combinations = _analyze_combination_potential(all_findings)
        if combinations:
            recommendations.append(
                f"LOW severity can be escalated via: {combinations[0]['name']}"
            )

    anomalies = _detect_anomalies(finding.get("summary", ""))
    anomaly_types = list(set([a[0] for a in anomalies]))

    if "network_timeout" in anomaly_types:
        recommendations.append(
            "Timeout anomalies may indicate SSRF or blind injection - probe internal services"
        )
    if "behavior_anomaly" in anomaly_types:
        recommendations.append(
            "Behavioral anomalies may reveal logic flaws - test edge cases"
        )
    if "information_disclosure" in anomaly_types:
        recommendations.append(
            "Disclosed info can enable further exploitation - enumerate using revealed paths"
        )
    if "predictability" in anomaly_types:
        recommendations.append(
            "Predictable values enable enumeration attacks - test systematically"
        )

    if len(all_findings) >= 5 and finding_cat != "unknown":
        recommendations.append(
            "With multiple findings, consider chaining for higher impact"
        )

    if not recommendations:
        recommendations.append(
            "Review in attack chain context for escalation opportunities"
        )

    return recommendations


def get_all_learned_vectors() -> dict[str, Any]:
    return dict(_LEARNED_VECTORS)


def clear_learned_vectors() -> None:
    global _LEARNED_VECTORS
    _LEARNED_VECTORS = {}
    try:
        if _LEARNING_FILE.exists():
            _LEARNING_FILE.unlink()
    except Exception as e:
        logger.debug("Failed to clear learned vectors: %s", e)
