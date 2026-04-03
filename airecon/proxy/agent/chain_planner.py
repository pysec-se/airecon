from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .tuning import get_tuning

logger = logging.getLogger("airecon.agent.chain_planner")

_TRIGGER_TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
_NEGATIVE_VULN_RE = re.compile(
    r"\b("
    r"not vulnerable|false positive|unverified|needs verification|"
    r"potential vulnerability|could be vulnerable|might be vulnerable"
    r")\b",
    re.IGNORECASE,
)
_TRIGGER_SYNONYMS: dict[str, tuple[str, ...]] = {
    "sql injection": ("sqli", "boolean-based", "time-based", "union select", "sql syntax"),
    "sqli": ("sql injection", "boolean-based", "time-based", "union select", "sql syntax"),
    "xss": ("cross site scripting", "cross-site scripting", "script injection"),
    "ssrf": ("server-side request forgery", "internal request", "metadata endpoint"),
    "idor": ("insecure direct object reference", "object reference", "access control bypass"),
    "lfi": ("local file inclusion", "path traversal"),
    "jwt": ("json web token", "alg:none", "token forgery"),
    "rce": ("remote code execution", "command injection", "shell execution"),
    "csrf": ("cross site request forgery", "cross-site request forgery"),
    "auth bypass": ("authentication bypass", "authorization bypass", "access control bypass"),
}
_TEMPLATE_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}
_CONFIRMED_SIGNAL_RE = re.compile(
    r"\b(confirmed|verified|replay_verified|report_generated|exploit(?:ed|ation)?\s+confirmed)\b",
    re.IGNORECASE,
)
_CHAIN_MATCH_THRESHOLD = float(
    get_tuning("chain_planner.match_threshold", 0.45)
)
_CHAIN_WEIGHTS = {
    "coverage": float(get_tuning("chain_planner.weights.coverage", 0.60)),
    "trigger": float(get_tuning("chain_planner.weights.trigger", 0.25)),
    "evidence": float(get_tuning("chain_planner.weights.evidence", 0.15)),
    "combined_match": float(get_tuning("chain_planner.weights.combined_match", 0.45)),
    "combined_priority": float(get_tuning("chain_planner.weights.combined_priority", 0.35)),
    "combined_evidence": float(get_tuning("chain_planner.weights.combined_evidence", 0.20)),
}
_CHAIN_TRIGGER_TUNING = {
    "phrase_exact_score": float(get_tuning("chain_planner.trigger.phrase_exact_score", 1.0)),
    "word_exact_score": float(get_tuning("chain_planner.trigger.word_exact_score", 0.90)),
    "overlap_min": float(get_tuning("chain_planner.trigger.overlap_min", 0.60)),
    "overlap_base": float(get_tuning("chain_planner.trigger.overlap_base", 0.65)),
    "overlap_scale": float(get_tuning("chain_planner.trigger.overlap_scale", 0.25)),
    "accept_threshold": float(get_tuning("chain_planner.trigger.accept_threshold", 0.55)),
}
_CHAIN_EVIDENCE_SUPPORT = {
    "direct_evidence": float(get_tuning("chain_planner.evidence_support.direct_evidence", 0.55)),
    "target_context": float(get_tuning("chain_planner.evidence_support.target_context", 0.25)),
    "confirmation_language": float(get_tuning("chain_planner.evidence_support.confirmation_language", 0.20)),
}
_CHAIN_MIN_TRIGGER_WITHOUT_EVIDENCE = float(
    get_tuning("chain_planner.min_trigger_without_evidence", 0.90)
)
_CAUSAL_CHAIN_MIN_POSTERIOR = float(
    get_tuning("causal_reasoning.chain_min_posterior", 0.62)
)
_CAUSAL_CHAIN_HIGH_POSTERIOR = float(
    get_tuning("causal_reasoning.chain_high_posterior", 0.82)
)

def _load_attack_chains() -> list[dict[str, Any]]:
    try:
        path = Path(__file__).parent.parent / "data" / "attack_chains.json"
        raw = json.loads(path.read_text(encoding="utf-8"))

        if isinstance(raw, dict) and "chains" in raw:
            chains = raw["chains"]
        elif isinstance(raw, list):
            chains = raw
        else:
            return []

        normalized: list[dict[str, Any]] = []
        for i, entry in enumerate(chains):
            if not isinstance(entry, dict):
                continue

            triggers = entry.get("triggers") or entry.get("required_findings") or []

            raw_steps = entry.get("steps", [])
            steps: list[dict[str, Any]] = []
            for step in raw_steps:
                if isinstance(step, dict):
                    steps.append(step)
                elif isinstance(step, str):
                    steps.append({"description": step, "tool_hint": "execute"})

            chain: dict[str, Any] = {
                "id": entry.get("id") or f"chain_{i}",
                "name": entry.get("name", f"Chain {i}"),
                "description": entry.get("description", ""),
                "triggers": [str(t).lower() for t in triggers],
                "steps": steps,
            }
            normalized.append(chain)
        return normalized
    except Exception as exc:
        logger.debug("Could not load attack_chains.json: %s", exc)
        return []

_ATTACK_CHAIN_TEMPLATES: list[dict[str, Any]] = _load_attack_chains()

@dataclass
class ChainStep:
    step_id: int
    description: str
    tool_hint: str = ""
    status: str = "pending"
    evidence: str = ""

@dataclass
class ExploitChain:
    chain_id: str
    name: str
    description: str = ""
    steps: list[ChainStep] = field(default_factory=list)
    current_step_index: int = 0
    status: str = "planning"
    phase_formed: str = "EXPLOIT"
    vuln_basis: str = ""
    iteration_formed: int = 0

    def current_step(self) -> ChainStep | None:
        if self.current_step_index >= len(self.steps):
            return None
        return self.steps[self.current_step_index]

    def advance(self, evidence: str = "") -> ChainStep | None:
        if self.current_step_index < len(self.steps):
            current = self.steps[self.current_step_index]
            current.status = "done"
            current.evidence = evidence[:300] if evidence else ""
            self.current_step_index += 1
            if self.status == "planning":
                self.status = "active"
        if self.current_step_index >= len(self.steps):
            self.status = "completed"
            return None
        return self.steps[self.current_step_index]

    def completed_steps(self) -> list[ChainStep]:
        return [s for s in self.steps if s.status == "done"]

    def pending_steps(self) -> list[ChainStep]:
        return [s for s in self.steps if s.status == "pending"]

def _match_template_to_vuln(
    template: dict[str, Any],
    vuln: dict[str, Any],
) -> tuple[float, list[str]]:
    triggers = template.get("triggers", [])
    if not triggers:
        return 0.0, []

    signal_text = " ".join(
        str(vuln.get(k, ""))
        for k in (
            "finding",
            "title",
            "description",
            "technical_analysis",
            "poc_description",
            "vuln_type",
            "url",
            "endpoint",
            "parameter",
            "cwe",
            "owasp",
            "evidence",
            "proof",
        )
    ).lower()
    signal_text = re.sub(r"\s+", " ", signal_text).strip()
    if not signal_text or _NEGATIVE_VULN_RE.search(signal_text):
        return 0.0, []

    signal_tokens = set(_TRIGGER_TOKEN_RE.findall(signal_text))
    has_target_context = bool(vuln.get("url") or vuln.get("endpoint") or vuln.get("parameter"))
    has_direct_evidence = bool(
        vuln.get("proof")
        or vuln.get("evidence")
        or vuln.get("poc_script_code")
        or vuln.get("report_generated")
        or vuln.get("replay_verified")
        or vuln.get("verified")
    )
    has_confirmation_language = bool(_CONFIRMED_SIGNAL_RE.search(signal_text))
    matched: list[str] = []
    max_trigger_score = 0.0

    for trigger in triggers:
        trigger_text = str(trigger).strip().lower()
        if not trigger_text:
            continue

        candidates = {trigger_text}
        candidates.update(_TRIGGER_SYNONYMS.get(trigger_text, ()))

        trigger_score = 0.0
        for candidate in candidates:
            c = candidate.strip().lower()
            if not c:
                continue

            if " " in c or any(ch in c for ch in ("/", ":", "-", "_")):
                if c in signal_text:
                    trigger_score = max(trigger_score, _CHAIN_TRIGGER_TUNING["phrase_exact_score"])
                    continue
            elif re.search(r"\b" + re.escape(c) + r"\b", signal_text):
                trigger_score = max(trigger_score, _CHAIN_TRIGGER_TUNING["word_exact_score"])
                continue

            trigger_tokens = set(_TRIGGER_TOKEN_RE.findall(c))
            if trigger_tokens:
                overlap = len(trigger_tokens & signal_tokens) / len(trigger_tokens)
                if overlap >= _CHAIN_TRIGGER_TUNING["overlap_min"]:
                    trigger_score = max(
                        trigger_score,
                        _CHAIN_TRIGGER_TUNING["overlap_base"]
                        + (_CHAIN_TRIGGER_TUNING["overlap_scale"] * overlap),
                    )

        if trigger_score >= _CHAIN_TRIGGER_TUNING["accept_threshold"]:
            matched.append(trigger_text)
        max_trigger_score = max(max_trigger_score, trigger_score)

    if not matched:
        return 0.0, []

    coverage = len(matched) / max(1, len(triggers))
    evidence_support = 0.0
    if has_direct_evidence:
        evidence_support += _CHAIN_EVIDENCE_SUPPORT["direct_evidence"]
    if has_target_context:
        evidence_support += _CHAIN_EVIDENCE_SUPPORT["target_context"]
    if has_confirmation_language:
        evidence_support += _CHAIN_EVIDENCE_SUPPORT["confirmation_language"]
    evidence_support = min(1.0, evidence_support)

    if (
        not has_direct_evidence
        and not has_target_context
        and max_trigger_score < _CHAIN_MIN_TRIGGER_WITHOUT_EVIDENCE
    ):
        return 0.0, []

    score = min(
        1.0,
        (coverage * _CHAIN_WEIGHTS["coverage"])
        + (max_trigger_score * _CHAIN_WEIGHTS["trigger"])
        + (evidence_support * _CHAIN_WEIGHTS["evidence"]),
    )
    return round(score, 3), matched

def _vuln_priority_score(vuln: dict[str, Any]) -> int:
    sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    sev_raw = str(vuln.get("severity", "")).strip().upper()
    if sev_raw in {"1", "2", "3", "4", "5"}:
        sev = {"1": "INFO", "2": "LOW", "3": "MEDIUM", "4": "HIGH", "5": "CRITICAL"}[sev_raw]
    else:
        sev = sev_raw

    if sev not in sev_rank:
        blob = " ".join(
            str(vuln.get(k, ""))
            for k in ("finding", "title", "description")
        ).upper()
        for candidate in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if f"[{candidate}]" in blob or f"{candidate}:" in blob:
                sev = candidate
                break

    base = sev_rank.get(sev, 1) * 10
    evidence_bonus = 0
    if vuln.get("proof") or vuln.get("evidence"):
        evidence_bonus += 3
    if vuln.get("poc_script_code") or vuln.get("flag"):
        evidence_bonus += 3
    if vuln.get("url") or vuln.get("endpoint") or vuln.get("parameter"):
        evidence_bonus += 2
    try:
        causal_posterior = float(vuln.get("causal_posterior", 0.0) or 0.0)
    except (TypeError, ValueError):
        causal_posterior = 0.0
    causal_bonus = max(0, min(10, int(causal_posterior * 10)))
    return base + evidence_bonus + causal_bonus

def _vuln_chain_evidence_score(vuln: dict[str, Any]) -> float:
    score = 0.0
    if vuln.get("report_generated") or vuln.get("replay_verified") or vuln.get("verified"):
        score += 0.45
    if vuln.get("proof") or vuln.get("evidence") or vuln.get("poc_script_code"):
        score += 0.30
    if vuln.get("url") or vuln.get("endpoint") or vuln.get("parameter"):
        score += 0.15
    finding_blob = " ".join(
        str(vuln.get(k, "")) for k in ("finding", "title", "description", "poc_description")
    )
    if _CONFIRMED_SIGNAL_RE.search(finding_blob):
        score += 0.10
    try:
        score += min(0.20, max(0.0, float(vuln.get("causal_posterior", 0.0) or 0.0) * 0.20))
    except (TypeError, ValueError):
        pass
    return min(1.0, score)

def _causal_hypotheses_to_vulns(
    causal_hypotheses: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if not causal_hypotheses:
        return []

    converted: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in causal_hypotheses:
        if not isinstance(raw, dict):
            continue
        statement = str(raw.get("statement", "")).strip()
        if not statement:
            continue
        try:
            posterior = float(raw.get("posterior", 0.0) or 0.0)
        except (TypeError, ValueError):
            posterior = 0.0
        posterior = max(0.0, min(1.0, posterior))
        if posterior < _CAUSAL_CHAIN_MIN_POSTERIOR:
            continue

        status = str(raw.get("status", "pending")).strip().lower()
        severity = "HIGH" if posterior >= _CAUSAL_CHAIN_HIGH_POSTERIOR else "MEDIUM"
        if status == "supported" and posterior >= _CAUSAL_CHAIN_HIGH_POSTERIOR:
            severity = "CRITICAL"

        refs = [str(x).strip() for x in (raw.get("evidence_refs", []) or []) if str(x).strip()]
        fingerprint = statement.lower()[:180]
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        converted.append(
            {
                "finding": statement,
                "severity": severity,
                "proof": "; ".join(refs[:3])[:240],
                "causal_posterior": posterior,
                "verified": status == "supported",
                "type": "causal_hypothesis",
            }
        )
    return converted

def plan_chains(
    vulnerabilities: list[dict[str, Any]],
    existing_chain_ids: set[str],
    iteration: int = 0,
    max_chains: int = 5,
    causal_hypotheses: list[dict[str, Any]] | None = None,
) -> list[ExploitChain]:
    new_chains: list[ExploitChain] = []

    if not _ATTACK_CHAIN_TEMPLATES:
        logger.debug("No attack chain templates loaded — chain planning skipped")
        return new_chains

    candidate_vulnerabilities = list(vulnerabilities or [])
    candidate_vulnerabilities.extend(_causal_hypotheses_to_vulns(causal_hypotheses))

    ranked_vulns = sorted(
        list(enumerate(candidate_vulnerabilities[:30])),
        key=lambda item: (-_vuln_priority_score(item[1]), item[0]),
    )

    candidate_chains: list[tuple[float, int, ExploitChain, str]] = []

    for _, vuln in ranked_vulns:
        finding = str(
            vuln.get("finding")
            or vuln.get("title")
            or vuln.get("description")
            or ""
        ).strip()
        if not finding:
            continue

        vuln_priority = _vuln_priority_score(vuln)

        for template in _ATTACK_CHAIN_TEMPLATES:
            match_score, matched_triggers = _match_template_to_vuln(template, vuln)
            if match_score < _CHAIN_MATCH_THRESHOLD:
                continue

            template_id = str(template.get("id", "x"))
            _seed = f"{template_id}:{finding.lower()[:220]}"
            _fp = hashlib.md5(
                _seed.encode("utf-8", errors="replace"),
                usedforsecurity=False,
            ).hexdigest()[:12]
            chain_id = f"chain_{template_id}_{_fp}"
            if chain_id in existing_chain_ids:
                continue

            steps = []
            for i, step_def in enumerate(template.get("steps", [])):
                steps.append(ChainStep(
                    step_id=i,
                    description=str(step_def.get("description", "")),
                    tool_hint=str(step_def.get("tool_hint", "")),
                    status="pending",
                ))

            if not steps:
                continue

            chain = ExploitChain(
                chain_id=chain_id,
                name=str(template.get("name", "Attack Chain")),
                description=(
                    str(template.get("description", "")).strip()
                    + (
                        f" | matched_triggers={', '.join(matched_triggers[:3])}"
                        if matched_triggers else ""
                    )
                ).strip(" |"),
                steps=steps,
                phase_formed="EXPLOIT",
                vuln_basis=finding[:200],
                iteration_formed=iteration,
            )
            template_rank = _TEMPLATE_SEVERITY_RANK.get(
                str(template.get("severity", "MEDIUM")).upper(),
                2,
            )
            evidence_score = _vuln_chain_evidence_score(vuln)
            combined_score = (
                (match_score * _CHAIN_WEIGHTS["combined_match"])
                + (min(1.0, vuln_priority / 60.0) * _CHAIN_WEIGHTS["combined_priority"])
                + (evidence_score * _CHAIN_WEIGHTS["combined_evidence"])
            )
            candidate_chains.append((combined_score, template_rank, chain, chain_id))

    if not candidate_chains:
        return new_chains

    candidate_chains.sort(
        key=lambda item: (item[0], item[1], -item[2].iteration_formed),
        reverse=True,
    )
    for _, _, chain, chain_id in candidate_chains:
        if chain_id in existing_chain_ids:
            continue
        new_chains.append(chain)
        existing_chain_ids.add(chain_id)
        if len(new_chains) >= max_chains:
            break

    return new_chains

def advance_chain(
    chain: ExploitChain,
    evidence: str = "",
) -> ChainStep | None:
    return chain.advance(evidence=evidence)

def build_chain_context(chains: list[ExploitChain], max_chains: int = 3) -> str:
    active = [
        c for c in chains
        if c.status in ("planning", "active")
    ][:max_chains]

    if not active:
        return ""

    lines = ["<exploit_chain_plan>"]
    for chain in active:
        lines.append(
            f'  <chain id="{chain.chain_id}" name="{chain.name}" '
            f'status="{chain.status}">'
        )
        if chain.description:
            lines.append(f"    <description>{chain.description}</description>")
        if chain.vuln_basis:
            lines.append(f'    <based_on vuln="{chain.vuln_basis[:100]}"/>')

        current = chain.current_step()
        if current:
            lines.append(
                f'    <current_step id="{current.step_id}" '
                f'tool_hint="{current.tool_hint}">'
            )
            lines.append(f"      {current.description}")
            lines.append("    </current_step>")

        done = chain.completed_steps()
        if done:
            lines.append(f"    <completed_steps count=\"{len(done)}\">")
            for s in done[-3:]:
                lines.append(f"      ✓ Step {s.step_id}: {s.description[:80]}")
            lines.append("    </completed_steps>")

        remaining = chain.pending_steps()
        if remaining:
            lines.append(f"    <remaining_steps count=\"{len(remaining)}\"/>")

        lines.append("  </chain>")

    lines.append(
        "  <instruction>Execute the CURRENT_STEP of the highest-priority chain above. "
        "Use the tool_hint as your primary tool. After getting results, advance "
        "to the next step.</instruction>"
    )
    lines.append("</exploit_chain_plan>")
    return "\n".join(lines)
