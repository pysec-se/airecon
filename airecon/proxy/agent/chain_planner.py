"""Exploit Chain Planner — multi-step attack chain orchestration.

Provides a structured way to plan and track multi-step exploit chains.
Chains are built from confirmed vulnerabilities and session findings,
guided by attack chain templates.

Design:
- ExploitChain dataclass: steps, current_step, status
- plan_chains(): generate candidate chains from session.vulnerabilities
- advance_chain(): mark current step done, move to next
- build_chain_context(): XML context block for LLM injection
- attack_chains.json: chain templates (loaded at module level)
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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

# ---------------------------------------------------------------------------
# Attack chain templates — loaded from data/attack_chains.json at import time
# ---------------------------------------------------------------------------

def _load_attack_chains() -> list[dict[str, Any]]:
    """Load attack chain templates from attack_chains.json.

    Supports two formats:
    - New format: {"chains": [{id, name, triggers, steps: [{description, tool_hint}]}]}
    - Legacy format: [{name, steps: ["str"], required_findings}]
    Both are normalised to the new format for the planner.
    """
    try:
        path = Path(__file__).parent.parent / "data" / "attack_chains.json"
        raw = json.loads(path.read_text(encoding="utf-8"))

        # New format: top-level dict with "chains" key
        if isinstance(raw, dict) and "chains" in raw:
            chains = raw["chains"]
        elif isinstance(raw, list):
            chains = raw  # Legacy: flat list
        else:
            return []

        normalized: list[dict[str, Any]] = []
        for i, entry in enumerate(chains):
            if not isinstance(entry, dict):
                continue

            # Normalise triggers: use "triggers" if present, else derive from "required_findings"
            triggers = entry.get("triggers") or entry.get("required_findings") or []

            # Normalise steps: new format is list of dicts, legacy is list of strings
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
    """One step in an exploit chain."""

    step_id: int
    description: str
    tool_hint: str = ""      # Suggested tool to use (e.g. "execute, http_observe")
    status: str = "pending"  # "pending" | "done" | "skipped"
    evidence: str = ""       # Evidence collected when this step completed


@dataclass
class ExploitChain:
    """A multi-step attack chain targeting a specific vulnerability path.

    Lifecycle:
      planning → active (first step done) → completed (all steps done) / abandoned
    """

    chain_id: str
    name: str
    description: str = ""
    steps: list[ChainStep] = field(default_factory=list)
    current_step_index: int = 0
    status: str = "planning"   # "planning" | "active" | "completed" | "abandoned"
    phase_formed: str = "EXPLOIT"
    vuln_basis: str = ""       # The confirmed vulnerability that triggered this chain
    iteration_formed: int = 0

    def current_step(self) -> ChainStep | None:
        """Return the current pending step, or None if chain is complete."""
        if self.current_step_index >= len(self.steps):
            return None
        return self.steps[self.current_step_index]

    def advance(self, evidence: str = "") -> ChainStep | None:
        """Mark current step done and advance to next step.

        Returns the new current step, or None if chain is complete.
        """
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
    """Return (match_score, matched_triggers) for template ↔ vulnerability mapping."""
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
                    trigger_score = max(trigger_score, 1.0)
                    continue
            elif re.search(r"\b" + re.escape(c) + r"\b", signal_text):
                trigger_score = max(trigger_score, 0.90)
                continue

            trigger_tokens = set(_TRIGGER_TOKEN_RE.findall(c))
            if trigger_tokens:
                overlap = len(trigger_tokens & signal_tokens) / len(trigger_tokens)
                if overlap >= 0.60:
                    trigger_score = max(trigger_score, 0.65 + (0.25 * overlap))

        if trigger_score >= 0.55:
            matched.append(trigger_text)
        max_trigger_score = max(max_trigger_score, trigger_score)

    if not matched:
        return 0.0, []

    coverage = len(matched) / max(1, len(triggers))
    score = min(1.0, (coverage * 0.75) + (max_trigger_score * 0.25))
    return round(score, 3), matched


def _vuln_priority_score(vuln: dict[str, Any]) -> int:
    """Return priority score used to order vulnerabilities for chain planning."""
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
    return base + evidence_bonus


def plan_chains(
    vulnerabilities: list[dict[str, Any]],
    existing_chain_ids: set[str],
    iteration: int = 0,
    max_chains: int = 5,
) -> list[ExploitChain]:
    """Generate candidate exploit chains from confirmed vulnerabilities.

    Matches each vulnerability against attack chain templates. Skips
    chains already in existing_chain_ids to avoid re-planning.

    Returns new chains (not yet in existing_chain_ids).
    """
    new_chains: list[ExploitChain] = []

    if not _ATTACK_CHAIN_TEMPLATES:
        logger.debug("No attack chain templates loaded — chain planning skipped")
        return new_chains

    # Prioritize high-severity, evidence-backed findings first so chain planning
    # focuses on high-impact paths before low-signal findings.
    ranked_vulns = sorted(
        list(enumerate(vulnerabilities[:20])),
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
            if match_score < 0.45:
                continue

            # Deterministic chain ID so existing_chain_ids can dedup across
            # iterations. Previously the ID included iteration/offset, which
            # made the same template+finding pair reappear as "new" every cycle.
            template_id = str(template.get("id", "x"))
            _seed = f"{template_id}:{finding.lower()[:220]}"
            _fp = hashlib.md5(  # nosec B324 - non-security dedup hash
                _seed.encode("utf-8", errors="replace"),
                usedforsecurity=False,
            ).hexdigest()[:12]
            chain_id = f"chain_{template_id}_{_fp}"
            if chain_id in existing_chain_ids:
                continue

            # Build steps from template
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
            combined_score = (match_score * 0.55) + (min(1.0, vuln_priority / 60.0) * 0.45)
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
    """Advance a chain to its next step.

    Returns the new current step, or None if the chain is complete.
    """
    return chain.advance(evidence=evidence)


def build_chain_context(chains: list[ExploitChain], max_chains: int = 3) -> str:
    """Build an XML context block for active exploit chains.

    Only includes active/planning chains. Completed and abandoned chains
    are excluded to keep context lean.
    """
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
            for s in done[-3:]:  # Show last 3 completed
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
