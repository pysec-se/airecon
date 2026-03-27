from __future__ import annotations

import asyncio
import heapq
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..config import get_config

logger = logging.getLogger("airecon.agent")

# These are now defaults - actual values are calculated from config at runtime
MAX_TOOL_ITERATIONS = 2000
MAX_TOOL_HISTORY = 100
MAX_OBJECTIVES = 64
MAX_EVIDENCE = 200
MAX_HYPOTHESES = 32  # Required for hypothesis queue
MAX_CAUSAL_OBSERVATIONS = 2000
MAX_CAUSAL_INTERVENTIONS = 300
MAX_CAUSAL_HYPOTHESES = 256
MAX_CAUSAL_EDGES = 512
FLAG_PATTERN = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)

# Compiled once at module level — used by add_message() to strip <think> leakage.
# Exact-tag match only: <think> not <thinking> (word-boundary via end-of-tag check).
_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
# Unclosed <think> that leaked at end of stream — strip from open tag to string end.
_THINK_OPEN_RE = re.compile(r"<think>(?!</think>).*$", re.DOTALL | re.IGNORECASE)

# Jaccard similarity threshold for evidence deduplication.
_EVIDENCE_SIMILARITY_THRESHOLD: float = 0.70

# Severity multipliers for evidence prioritization (CRITICAL=5:2.0x, HIGH=4:1.5x, etc.)
# Moved to module level to avoid recreation on every add_evidence() call
_SEVERITY_MULTIPLIER: dict[int, float] = {5: 2.0, 4: 1.5, 3: 1.0, 2: 0.7, 1: 0.5}

# Tool result truncation limit — applied on append to prevent memory bloat
_MAX_TOOL_RESULT_CHARS = 50_000


def _truncate_tool_result(result: dict[str, Any]) -> dict[str, Any]:
    """Truncate oversized strings in tool result dict.
    
    FIX #7 (Medium): Applied on append instead of in add_message() to prevent
    memory growth between tool execution and message add.
    
    Args:
        result: Tool result dict with potential large string values
        
    Returns:
        Same dict with oversized strings truncated
    """
    if not isinstance(result, dict):
        return result
    
    for k, v in result.items():
        if isinstance(v, str) and len(v) > _MAX_TOOL_RESULT_CHARS:
            result[k] = v[:_MAX_TOOL_RESULT_CHARS] + " ... [TRUNCATED]"
    return result


def _get_context_limits():
    """Get context management limits from config.
    
    Returns dict with:
    - max_conversation_messages: based on ollama_num_ctx // 128
    - compression_trigger: 80% of max
    - uncompressed_keep_count: last N messages to keep uncompressed
    - llm_compression_num_ctx: context window for LLM compression
    - llm_compression_num_predict: output length for compression
    """
    try:
        config = get_config()
        return {
            "max_conversation_messages": config.agent_max_conversation_messages,
            "compression_trigger": int(
                config.agent_max_conversation_messages * config.agent_compression_trigger_ratio
            ),
            "uncompressed_keep_count": config.agent_uncompressed_keep_count,
            "llm_compression_num_ctx": config.agent_llm_compression_num_ctx,
            "llm_compression_num_predict": config.agent_llm_compression_num_predict,
        }
    except Exception:
        # Fallback defaults if config not loaded yet
        return {
            "max_conversation_messages": 1024,  # 131K // 128
            "compression_trigger": 819,  # 80% of 1024
            "uncompressed_keep_count": 20,
            "llm_compression_num_ctx": 8192,
            "llm_compression_num_predict": 1024,
        }


def jaccard_similarity(a: str, b: str) -> float:
    """Token-overlap (Jaccard) similarity between two strings.

    Tokenizes on whitespace and lowercases both inputs.
    Returns 0.0 when either input is empty.

    Shared by AgentState evidence dedup and session vulnerability dedup.
    """
    tokens_a = set(a.lower().split())
    tokens_b = set(b.lower().split())
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def _calculate_objective_confidence(
    summary: str,
    artifact: str | None,
    source_tool: str,
    severity: int = 3,
) -> float:
    """Calculate objective confidence score based on evidence quality.
    
    Replaces subjective confidence with objective scoring based on:
    - Has artifact/file output (+0.2)
    - Has severity tag (+0.1)
    - Has HTTP proof (+0.15)
    - Detailed description (>100 chars, +0.05)
    
    Returns: Confidence score between 0.5 and 1.0
    """
    score = 0.5  # Base score
    
    if artifact:  # Has file output
        score += 0.2
    
    if re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", summary, re.IGNORECASE):  # Severity tag
        score += 0.1
    
    if re.search(r"\b(http|https|status|response|→)\b", summary.lower()):  # HTTP proof
        score += 0.15
    
    if len(summary) > 100:  # Detailed description
        score += 0.05
    
    # Severity-based adjustment (CRITICAL findings get slight boost if well-documented)
    if severity >= 4 and len(summary) > 80:
        score += 0.05
    
    return min(score, 1.0)


@dataclass
class ToolExecution:
    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any] | None = None
    duration: float = 0.0
    status: str = "pending"


@dataclass
class AgentEvent:
    type: str  # "text", "tool_start", "tool_end", "error", "done", "thinking"
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class CausalObservation:
    """Structured observation captured from tool/runtime output."""

    observation_type: str
    entity: str
    attribute: str = ""
    value: str = ""
    source_tool: str = ""
    evidence: str = ""
    confidence: float = 0.5
    phase: str = ""
    timestamp: str = ""

    def fingerprint(self) -> str:
        """Stable key for deduplication."""
        return "|".join(
            [
                self.observation_type.strip().lower(),
                self.entity.strip().lower(),
                self.attribute.strip().lower(),
                self.value.strip().lower(),
            ]
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalObservation":
        return cls(
            observation_type=str(raw.get("observation_type", "")).strip(),
            entity=str(raw.get("entity", "")).strip(),
            attribute=str(raw.get("attribute", "")).strip(),
            value=str(raw.get("value", "")).strip(),
            source_tool=str(raw.get("source_tool", "")).strip(),
            evidence=str(raw.get("evidence", "")).strip()[:600],
            confidence=max(0.0, min(float(raw.get("confidence", 0.5) or 0.5), 1.0)),
            phase=str(raw.get("phase", "")).strip().upper(),
            timestamp=str(raw.get("timestamp", "")).strip(),
        )


@dataclass
class CausalHypothesis:
    """Causal hypothesis with posterior confidence."""

    hypothesis_id: str
    statement: str
    prior: float = 0.5
    posterior: float = 0.5
    status: str = "pending"  # pending|supported|refuted
    evidence_refs: list[str] = field(default_factory=list)
    updated_at: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalHypothesis":
        return cls(
            hypothesis_id=str(raw.get("hypothesis_id", "")).strip(),
            statement=str(raw.get("statement", "")).strip(),
            prior=max(0.0, min(float(raw.get("prior", 0.5) or 0.5), 1.0)),
            posterior=max(0.0, min(float(raw.get("posterior", 0.5) or 0.5), 1.0)),
            status=str(raw.get("status", "pending")).strip().lower(),
            evidence_refs=[
                str(x).strip()
                for x in (raw.get("evidence_refs", []) or [])
                if str(x).strip()
            ][:30],
            updated_at=str(raw.get("updated_at", "")).strip(),
        )


@dataclass
class CausalEdge:
    """Directed relation between entities/hypotheses in the causal graph."""

    cause: str
    effect: str
    relation: str = "supports"
    confidence: float = 0.5

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalEdge":
        return cls(
            cause=str(raw.get("cause", "")).strip(),
            effect=str(raw.get("effect", "")).strip(),
            relation=str(raw.get("relation", "supports")).strip().lower(),
            confidence=max(0.0, min(float(raw.get("confidence", 0.5) or 0.5), 1.0)),
        )


@dataclass
class CausalIntervention:
    """Intervention/action and observed causal effect."""

    intervention_id: str
    action: str
    target: str = ""
    expected_effect: str = ""
    observed_effect: str = ""
    success: bool | None = None
    confidence: float = 0.5
    timestamp: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalIntervention":
        return cls(
            intervention_id=str(raw.get("intervention_id", "")).strip(),
            action=str(raw.get("action", "")).strip(),
            target=str(raw.get("target", "")).strip(),
            expected_effect=str(raw.get("expected_effect", "")).strip(),
            observed_effect=str(raw.get("observed_effect", "")).strip(),
            success=raw.get("success"),
            confidence=max(0.0, min(float(raw.get("confidence", 0.5) or 0.5), 1.0)),
            timestamp=str(raw.get("timestamp", "")).strip(),
        )


@dataclass
class CausalState:
    """Persistent causal reasoning state for a session."""

    observations: list[CausalObservation] = field(default_factory=list)
    hypotheses: list[CausalHypothesis] = field(default_factory=list)
    edges: list[CausalEdge] = field(default_factory=list)
    interventions: list[CausalIntervention] = field(default_factory=list)
    posterior: dict[str, float] = field(default_factory=dict)

    def record_observation(self, observation: CausalObservation | dict[str, Any]) -> bool:
        """Record an observation if it is not a duplicate."""
        obs = (
            observation
            if isinstance(observation, CausalObservation)
            else CausalObservation.from_dict(observation)
        )
        if not obs.observation_type or not obs.entity:
            return False
        fp = obs.fingerprint()
        for existing in self.observations:
            if existing.fingerprint() == fp:
                return False
        if not obs.timestamp:
            obs.timestamp = datetime.now(timezone.utc).isoformat()
        self.observations.append(obs)
        if len(self.observations) > MAX_CAUSAL_OBSERVATIONS:
            self.observations = self.observations[-MAX_CAUSAL_OBSERVATIONS:]
        return True

    def add_intervention(self, intervention: CausalIntervention | dict[str, Any]) -> None:
        """Append intervention history with bounded capacity."""
        iv = (
            intervention
            if isinstance(intervention, CausalIntervention)
            else CausalIntervention.from_dict(intervention)
        )
        if not iv.intervention_id:
            iv.intervention_id = f"iv_{len(self.interventions)+1}"
        if not iv.timestamp:
            iv.timestamp = datetime.now(timezone.utc).isoformat()
        self.interventions.append(iv)
        if len(self.interventions) > MAX_CAUSAL_INTERVENTIONS:
            self.interventions = self.interventions[-MAX_CAUSAL_INTERVENTIONS:]

    def add_edge(self, edge: CausalEdge | dict[str, Any]) -> bool:
        """Record a causal edge if not already present."""
        ce = edge if isinstance(edge, CausalEdge) else CausalEdge.from_dict(edge)
        if not ce.cause or not ce.effect:
            return False
        for existing in self.edges:
            if (
                existing.cause == ce.cause
                and existing.effect == ce.effect
                and existing.relation == ce.relation
            ):
                # Keep strongest confidence for repeated edges.
                if ce.confidence > existing.confidence:
                    existing.confidence = ce.confidence
                return False
        self.edges.append(ce)
        if len(self.edges) > MAX_CAUSAL_EDGES:
            self.edges = self.edges[-MAX_CAUSAL_EDGES:]
        return True

    def upsert_hypothesis(self, hypothesis: CausalHypothesis | dict[str, Any]) -> None:
        """Insert or update a causal hypothesis by id."""
        h = (
            hypothesis
            if isinstance(hypothesis, CausalHypothesis)
            else CausalHypothesis.from_dict(hypothesis)
        )
        if not h.hypothesis_id:
            h.hypothesis_id = f"hyp_{len(self.hypotheses)+1}"
        h.updated_at = datetime.now(timezone.utc).isoformat()
        for idx, existing in enumerate(self.hypotheses):
            if existing.hypothesis_id == h.hypothesis_id:
                self.hypotheses[idx] = h
                break
        else:
            self.hypotheses.append(h)
            if len(self.hypotheses) > MAX_CAUSAL_HYPOTHESES:
                self.hypotheses = self.hypotheses[-MAX_CAUSAL_HYPOTHESES:]
        self.posterior[h.hypothesis_id] = h.posterior

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": [o.__dict__ for o in self.observations],
            "hypotheses": [h.__dict__ for h in self.hypotheses],
            "edges": [e.__dict__ for e in self.edges],
            "interventions": [i.__dict__ for i in self.interventions],
            "posterior": {
                str(k): max(0.0, min(float(v), 1.0))
                for k, v in self.posterior.items()
            },
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalState":
        if not isinstance(raw, dict):
            return cls()
        state = cls(
            observations=[
                CausalObservation.from_dict(x)
                for x in (raw.get("observations", []) or [])
                if isinstance(x, dict)
            ],
            hypotheses=[
                CausalHypothesis.from_dict(x)
                for x in (raw.get("hypotheses", []) or [])
                if isinstance(x, dict)
            ],
            edges=[
                CausalEdge.from_dict(x)
                for x in (raw.get("edges", []) or [])
                if isinstance(x, dict)
            ],
            interventions=[
                CausalIntervention.from_dict(x)
                for x in (raw.get("interventions", []) or [])
                if isinstance(x, dict)
            ],
            posterior={},
        )
        raw_post = raw.get("posterior", {})
        if isinstance(raw_post, dict):
            state.posterior = {
                str(k): max(0.0, min(float(v), 1.0))
                for k, v in raw_post.items()
                if str(k).strip()
            }
        return state


@dataclass
class AgentState:
    conversation: list[dict[str, Any]] = field(default_factory=list)
    tool_history: list[ToolExecution] = field(default_factory=list)
    tool_counts: dict[str, int] = field(
        default_factory=lambda: {"exec": 0, "total": 0, "subagents": 0})
    token_usage: dict[str, int] = field(
        default_factory=lambda: {
            "used": 0,
            "limit": 65536,
            "cumulative": 0,
            "cumulative_prompt": 0,
            "cumulative_completion": 0,
            "last_prompt": 0,
            "last_completion": 0,
        }
    )
    skills_used: list[str] = field(default_factory=list)
    planned_tools: list[str] = field(
        default_factory=list
    )  # Track tools mentioned in plan
    iteration: int = 0
    max_iterations: int = MAX_TOOL_ITERATIONS
    active_target: str | None = None
    warnings_sent: bool = False
    # system_prompt: dict[str, Any] | None = None
    missing_tool_count: int = 0
    objective_queue: list[dict[str, Any]] = field(default_factory=list)
    evidence_log: list[dict[str, Any]] = field(default_factory=list)
    # Tracks cumulative tool usage per pipeline phase for soft budget enforcement.
    # Structure: {phase_name: {tool_name: call_count}}
    phase_tool_usage: dict[str, dict[str, int]] = field(default_factory=dict)
    # Tracks per-phase tool effectiveness to adapt budget pressure dynamically.
    # Structure:
    # {
    #   phase_name: {
    #     tool_name: {
    #       "calls": int,
    #       "successes": int,
    #       "meaningful_hits": int,  # calls that produced >=1 meaningful evidence
    #     }
    #   }
    # }
    tool_effectiveness: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict)
    # Stores named HTTP baselines captured via http_observe.
    # Key: save_as label (e.g. "baseline_login"), Value: parsed response dict
    # {status, headers, body_excerpt, response_time, size, url, method}
    http_baselines: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Hypothesis Engine: queue of security hypotheses the agent is tracking.
    # Each entry: {id, claim, test_plan, status, evidence_refs, iteration_formed, phase}
    # status: "pending" | "confirmed" | "refuted" | "testing"
    hypothesis_queue: list[dict[str, Any]] = field(default_factory=list)
    # Exploit Chain Planner: active multi-step attack chains.
    # Each entry: {chain_id, name, steps, current_step, status, phase_formed}
    exploit_chains: list[dict[str, Any]] = field(default_factory=list)

    def add_message(
        self,
        role: str,
        content: str,
        tool_calls: list[dict[str, Any]] | None = None,
        thinking: str | None = None,
    ) -> None:
        # Strip any <think>...</think> blocks that leaked into content_acc from
        # the streaming parser (AIRecon pattern: strip reasoning before storing).
        # Thinking content is already captured separately in thinking_acc.
        if role == "assistant" and content and "<think" in content:
            content = _THINK_BLOCK_RE.sub("", content)
            # Handle unclosed <think> at end of stream
            content = _THINK_OPEN_RE.sub("", content).strip()

        msg: dict[str, Any] = {"role": role, "content": content}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        if thinking:
            msg["thinking"] = thinking
        self.conversation.append(msg)
        
        # CRITICAL VRAM FIX: Smart truncation to prevent OOM crashes.
        # Strategy: Preserve important messages (system, tool_calls, findings)
        # while dropping pure-text analysis that can be regenerated.
        #
        # Why 800 msgs? 800 × 100 tokens = 80K tokens (safe for 131K context)
        # Leaves room for: system prompt (8K) + skills (10K) + response (30K)
        limits = _get_context_limits()
        if len(self.conversation) > limits["max_conversation_messages"]:
            self._smart_truncate_conversation()

        # Cap tool_history to prevent unbounded memory growth
        if len(self.tool_history) > MAX_TOOL_HISTORY:
            self.tool_history = self.tool_history[-MAX_TOOL_HISTORY:]

        # FIX #7 (Medium): Tool result truncation now happens on append in executors.py
        # This legacy check is kept as a safety net for old code paths
        if len(self.tool_history) > 50:
            for entry in self.tool_history:
                if entry.result and isinstance(entry.result, dict):
                    entry.result = _truncate_tool_result(entry.result)

    def _smart_truncate_conversation(self) -> None:
        """Smart conversation truncation to prevent VRAM crashes.

        PHILOSOPHY: Conversation is "working memory" - can be dropped.
        SessionData is "long-term memory" - never lost.

        SessionData already persists ALL findings:
        - subdomains: BoundedList(10000) ✅
        - live_hosts: BoundedList(5000) ✅
        - urls: BoundedList(50000) ✅
        - vulnerabilities: BoundedList(1000) ✅
        - injection_points: BoundedList(5000) ✅
        - tested_endpoints: BoundedList(500) ✅

        Strategy:
        1. Keep ALL system messages (rules, prompts, recovery)
        2. Keep last N non-system messages (LRU - recent context, config-based)
        3. Drop oldest non-system messages when over limit

        Why NOT keyword-based:
        - Keywords miss novel/creative vulns (false negatives)
        - LLM should decide what's important, not hardcoded list
        - SessionData already has structured findings

        Why NOT compress/summarize:
        - Adds complexity without benefit
        - LLM can rebuild context from SessionData
        - Simple LRU is predictable and debuggable
        """
        limits = _get_context_limits()
        if len(self.conversation) <= limits["max_conversation_messages"]:
            return

        # Separate system messages (always keep)
        system_msgs = [m for m in self.conversation if m.get("role") == "system"]
        non_system_msgs = [m for m in self.conversation if m.get("role") != "system"]

        # Keep last N non-system messages (LRU)
        keep_count = max(0, limits["max_conversation_messages"] - len(system_msgs))
        kept_non_system = non_system_msgs[-keep_count:] if keep_count > 0 else []

        # Rebuild conversation
        self.conversation = system_msgs + kept_non_system

        # Safety check - ensure we don't exceed limit
        if len(self.conversation) > limits["max_conversation_messages"]:
            # Extra safety: hard cap
            self.conversation = self.conversation[-limits["max_conversation_messages"]:]

    def ensure_phase_objectives(
        self, phase: str, defaults: list[str]
    ) -> None:
        """Ensure default objectives exist for the given phase."""
        if not defaults:
            return

        existing = {
            str(obj.get("title", "")).strip().lower()
            for obj in self.objective_queue
            if str(obj.get("phase", "")).upper() == phase.upper()
        }
        for idx, title in enumerate(defaults):
            key = title.strip().lower()
            if key in existing:
                continue
            self.objective_queue.append(
                {
                    "phase": phase.upper(),
                    "title": title,
                    "status": "pending",
                    "priority": max(1, 100 - (idx * 10)),
                    "updated_iteration": self.iteration,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )

        if len(self.objective_queue) > MAX_OBJECTIVES:
            self.objective_queue = self.objective_queue[-MAX_OBJECTIVES:]

    def mark_objective(
        self,
        phase: str,
        title: str,
        status: str = "done",
        note: str | None = None,
    ) -> None:
        """Update an objective status for a given phase/title."""
        norm_phase = phase.upper()
        norm_title = title.strip().lower()
        now = datetime.now(timezone.utc).isoformat()
        for obj in self.objective_queue:
            if (
                str(obj.get("phase", "")).upper() == norm_phase
                and str(obj.get("title", "")).strip().lower() == norm_title
            ):
                obj["status"] = status
                obj["updated_iteration"] = self.iteration
                obj["updated_at"] = now
                if note:
                    obj["note"] = note
                return

    @staticmethod
    def _jaccard_similarity(a: str, b: str) -> float:
        """Delegate to module-level jaccard_similarity()."""
        return jaccard_similarity(a, b)

    def add_evidence(
        self,
        phase: str,
        source_tool: str,
        summary: str,
        confidence: float = 0.70,
        artifact: str | None = None,
        tags: list[str] | None = None,
        severity: int = 1,
    ) -> bool:
        """Record deduplicated evidence from real tool output.

        Returns True if the evidence was added, False if it was rejected as a
        duplicate (exact match or Jaccard similarity >= threshold within the
        same phase).

        Uses objective confidence scoring if confidence < 0.70 (replaces subjective with objective).
        
        High-confidence findings (>=0.85) are checked for cross-phase duplicates
        to prevent redundant evidence cluttering the log.
        """
        clean_summary = " ".join(str(summary).strip().split())
        if not clean_summary:
            return False

        # MEDIUM FIX #4: Use objective confidence scoring instead of subjective
        if confidence < 0.70:
            confidence = _calculate_objective_confidence(clean_summary, artifact, source_tool, severity)

        phase_key = phase.upper()
        tags = tags or []
        dedup_key = (
            phase_key,
            source_tool.strip().lower(),
            clean_summary.lower(),
            (artifact or "").strip().lower(),
        )

        summary_lower = clean_summary.lower()
        for existing in self.evidence_log:
            # Fast path: exact tuple match (all fields identical)
            prev_key = (
                str(existing.get("phase", "")).upper(),
                str(existing.get("source_tool", "")).strip().lower(),
                str(existing.get("summary", "")).strip().lower(),
                str(existing.get("artifact", "")).strip().lower(),
            )
            if dedup_key == prev_key:
                return False

            # Semantic path: Jaccard similarity on summary within same phase.
            # Cross-phase entries are allowed (RECON and EXPLOIT can have
            # similar summaries for different reasons).
            if str(existing.get("phase", "")).upper() != phase_key:
                # FIX #3: High-confidence findings should be globally unique
                # to prevent cross-phase redundancy (e.g., RECON and EXPLOIT
                # both reporting the same subdomain discovery).
                if confidence >= 0.85:
                    existing_summary = str(existing.get("summary", "")).strip().lower()
                    if self._jaccard_similarity(summary_lower, existing_summary) >= 0.85:
                        logger.debug(
                            "Evidence dedup (cross-phase, high-confidence): '%s...' ~ '%s...'",
                            summary_lower[:40],
                            existing_summary[:40],
                        )
                        return False
                continue
            
            existing_summary = str(existing.get("summary", "")).strip().lower()
            if self._jaccard_similarity(summary_lower, existing_summary) >= _EVIDENCE_SIMILARITY_THRESHOLD:
                logger.debug(
                    "Evidence dedup (semantic): '%s...' ~ '%s...'",
                    summary_lower[:40],
                    existing_summary[:40],
                )
                return False

        # FIX #4: Validate and clamp severity with warning for invalid values
        clamped_severity = max(1, min(int(severity), 5))
        if clamped_severity != severity:
            logger.warning(
                "Evidence severity clamped from %d to %d: %s",
                severity, clamped_severity, clean_summary[:100]
            )
        severity = clamped_severity

        self.evidence_log.append(
            {
                "phase": phase_key,
                "source_tool": source_tool,
                "summary": clean_summary[:600],
                "confidence": max(0.0, min(float(confidence), 1.0)),
                "severity": severity,
                "artifact": artifact,
                "tags": tags,
                "iteration": self.iteration,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        if len(self.evidence_log) > MAX_EVIDENCE:
            # Severity-weighted prioritized truncation: keep high-severity +
            # high-confidence entries regardless of age.
            # Pure FIFO would discard early high-value findings when log fills up.
            # Uses module-level _SEVERITY_MULTIPLIER for performance.
            def _evidence_score(e: dict) -> float:
                conf = float(e.get("confidence", 0.0))
                sev = int(e.get("severity", 3))
                return conf * _SEVERITY_MULTIPLIER.get(sev, 1.0)
            kept = heapq.nlargest(
                MAX_EVIDENCE,
                self.evidence_log,
                key=_evidence_score,
            )
            kept.sort(key=lambda e: int(e.get("iteration", 0)))
            self.evidence_log = kept
        return True

    def record_tool_use(self, phase: str, tool_name: str) -> None:
        """Increment per-phase tool usage counter for budget tracking."""
        bucket = self.phase_tool_usage.setdefault(phase, {})
        bucket[tool_name] = bucket.get(tool_name, 0) + 1

    def record_tool_outcome(
        self,
        phase: str,
        tool_name: str,
        *,
        success: bool,
        meaningful_evidence_delta: int = 0,
    ) -> None:
        """Record tool outcome quality for adaptive budget steering.

        A "meaningful hit" means the call produced at least one new evidence item
        with confidence >= meaningful threshold (tracked by caller).
        """
        phase_bucket = self.tool_effectiveness.setdefault(phase, {})
        metrics = phase_bucket.setdefault(
            tool_name,
            {"calls": 0, "successes": 0, "meaningful_hits": 0},
        )
        metrics["calls"] += 1
        if success:
            metrics["successes"] += 1
        if meaningful_evidence_delta > 0:
            metrics["meaningful_hits"] += 1

    def get_tool_effectiveness(self, phase: str, tool_name: str) -> dict[str, float]:
        """Return normalized effectiveness metrics for a phase/tool pair."""
        raw = self.tool_effectiveness.get(phase, {}).get(tool_name, {})
        calls = int(raw.get("calls", 0))
        successes = int(raw.get("successes", 0))
        hits = int(raw.get("meaningful_hits", 0))
        if calls <= 0:
            return {
                "calls": 0.0,
                "success_rate": 0.0,
                "hit_rate": 0.0,
            }
        return {
            "calls": float(calls),
            "success_rate": round(successes / calls, 3),
            "hit_rate": round(hits / calls, 3),
        }

    def get_phase_tool_count(self, phase: str, tool_name: str) -> int:
        """Return how many times tool_name was used in the given phase."""
        return self.phase_tool_usage.get(phase, {}).get(tool_name, 0)

    # ------------------------------------------------------------------
    # Exploit Chain state helpers
    # ------------------------------------------------------------------

    def get_active_chains(self) -> list[dict[str, Any]]:
        """Return chains with status 'planning' or 'active'."""
        return [c for c in self.exploit_chains if c.get("status") in ("planning", "active")]

    def update_chain_step(
        self,
        chain_id: str,
        evidence: str = "",
    ) -> bool:
        """Advance the current step of a chain by ID. Returns True if found."""
        for chain in self.exploit_chains:
            if chain.get("chain_id") == chain_id:
                steps = chain.get("steps", [])
                idx = chain.get("current_step_index", 0)
                if idx < len(steps):
                    steps[idx]["status"] = "done"
                    if evidence:
                        steps[idx]["evidence"] = evidence[:300]
                    chain["current_step_index"] = idx + 1
                    if chain.get("status") == "planning":
                        chain["status"] = "active"
                if chain.get("current_step_index", 0) >= len(steps):
                    chain["status"] = "completed"
                return True
        return False

    # ------------------------------------------------------------------
    # Hypothesis Engine
    # ------------------------------------------------------------------

    def add_hypothesis(
        self,
        claim: str,
        test_plan: str,
        phase: str = "RECON",
        tags: list[str] | None = None,
    ) -> str:
        """Record a new security hypothesis.

        Returns the hypothesis ID (h_<iteration>_<index>).
        Does not add if a semantically identical claim already exists (Jaccard >= 0.80).
        """
        claim = claim.strip()
        if not claim:
            return ""

        # Dedup by Jaccard similarity on claim text
        for existing in self.hypothesis_queue:
            if jaccard_similarity(claim.lower(), str(existing.get("claim", "")).lower()) >= 0.80:
                return str(existing.get("id", ""))

        hyp_id = f"h_{self.iteration}_{len(self.hypothesis_queue)}"
        self.hypothesis_queue.append(
            {
                "id": hyp_id,
                "claim": claim,
                "test_plan": test_plan.strip(),
                "status": "pending",
                "evidence_refs": [],
                "iteration_formed": self.iteration,
                "phase": phase.upper(),
                "tags": tags or [],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        if len(self.hypothesis_queue) > MAX_HYPOTHESES:
            # Drop refuted first (highest key), then confirmed, keep pending/testing
            self.hypothesis_queue = sorted(
                self.hypothesis_queue,
                key=lambda h: (
                    0 if str(h.get("status", "")) in ("pending", "testing") else
                    1 if str(h.get("status", "")) == "confirmed" else 2,
                    int(h.get("iteration_formed", 0)),
                ),
            )[:MAX_HYPOTHESES]
        return hyp_id

    def update_hypothesis(
        self,
        hyp_id: str,
        status: str,
        evidence_summary: str | None = None,
    ) -> bool:
        """Update the status of a hypothesis by ID.

        status: "testing" | "confirmed" | "refuted"
        Returns True if found and updated.
        """
        for hyp in self.hypothesis_queue:
            if hyp.get("id") == hyp_id:
                hyp["status"] = status
                hyp["updated_at"] = datetime.now(timezone.utc).isoformat()
                if evidence_summary:
                    refs = hyp.setdefault("evidence_refs", [])
                    if evidence_summary not in refs:
                        refs.append(evidence_summary[:200])
                return True
        return False

    def get_pending_hypotheses(self, max_items: int = 5) -> list[dict[str, Any]]:
        """Return pending hypotheses sorted by oldest-first (most urgent)."""
        pending = [
            h for h in self.hypothesis_queue
            if str(h.get("status", "pending")) in ("pending", "testing")
        ]
        pending.sort(key=lambda h: int(h.get("iteration_formed", 0)))
        return pending[:max_items]

    def resolve_hypotheses_from_evidence(self) -> int:
        """Auto-confirm hypotheses whose claim matches recent HIGH/CRITICAL evidence.

        Returns count of hypotheses newly confirmed.
        """
        confirmed_count = 0
        high_evidence = [
            e for e in self.evidence_log
            if int(e.get("severity", 1)) >= 4
            and float(e.get("confidence", 0.0)) >= 0.75
        ]
        for hyp in self.hypothesis_queue:
            if str(hyp.get("status", "")) not in ("pending", "testing"):
                continue
            claim_lower = str(hyp.get("claim", "")).lower()
            for ev in high_evidence:
                summary_lower = str(ev.get("summary", "")).lower()
                if jaccard_similarity(claim_lower, summary_lower) >= 0.35:
                    hyp["status"] = "confirmed"
                    hyp["updated_at"] = datetime.now(timezone.utc).isoformat()
                    refs = hyp.setdefault("evidence_refs", [])
                    ref = str(ev.get("summary", ""))[:200]
                    if ref not in refs:
                        refs.append(ref)
                    confirmed_count += 1
                    break
        return confirmed_count

    def build_hypothesis_context(self, max_pending: int = 4) -> str:
        """Build XML context block for pending hypotheses to inject into conversation."""
        pending = self.get_pending_hypotheses(max_items=max_pending)
        confirmed = [
            h for h in self.hypothesis_queue
            if str(h.get("status", "")) == "confirmed"
        ][-3:]  # Last 3 confirmed
        refuted = [
            h for h in self.hypothesis_queue
            if str(h.get("status", "")) == "refuted"
        ][-2:]  # Last 2 refuted (avoid re-testing)

        if not pending and not confirmed:
            return ""

        lines = ['<hypothesis_queue>']
        if pending:
            lines.append("  <pending>")
            for h in pending:
                hid = h.get("id", "")
                claim = h.get("claim", "")
                plan = h.get("test_plan", "")
                status = h.get("status", "pending")
                lines.append(f'    <hypothesis id="{hid}" status="{status}">')
                lines.append(f'      <claim>{claim}</claim>')
                if plan:
                    lines.append(f'      <test_plan>{plan}</test_plan>')
                lines.append('    </hypothesis>')
            lines.append("  </pending>")
        if confirmed:
            lines.append("  <confirmed>")
            for h in confirmed:
                lines.append(f'    - [{h.get("id", "")}] {h.get("claim", "")}')
            lines.append("  </confirmed>")
        if refuted:
            lines.append("  <refuted_do_not_retry>")
            for h in refuted:
                lines.append(f'    - [{h.get("id", "")}] {h.get("claim", "")}')
            lines.append("  </refuted_do_not_retry>")
        lines.append(
            "  <instruction>Pick one PENDING hypothesis and execute its test_plan "
            "via tool call. Use record_hypothesis to update status after testing.</instruction>"
        )
        lines.append('</hypothesis_queue>')
        return "\n".join(lines)

    def get_phase_context(
        self,
        phase: str,
        max_objectives: int = 4,
        max_evidence: int = 6,
        filter_evidence_by_phase: bool = True,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Return (pending, completed, evidence) for a given phase."""
        phase_key = phase.upper()

        pending = [
            o for o in self.objective_queue
            if str(o.get("phase", "")).upper() == phase_key
            and str(o.get("status", "pending")).lower() != "done"
        ]
        pending = sorted(
            pending, key=lambda x: int(x.get("priority", 0)), reverse=True
        )[:max_objectives]

        completed = [
            o for o in self.objective_queue
            if str(o.get("phase", "")).upper() == phase_key
            and str(o.get("status", "")).lower() == "done"
        ][:max_objectives]

        # Only surface evidence with meaningful confidence to avoid cluttering
        # the LLM context with low-signal noise (e.g. bare execute traces).
        _CONF_FLOOR = 0.65
        if filter_evidence_by_phase:
            evidence = [
                e for e in reversed(self.evidence_log)
                if str(e.get("phase", "")).upper() == phase_key
                and float(e.get("confidence", 1.0)) >= _CONF_FLOOR
            ][:max_evidence]
        else:
            evidence = [
                e for e in reversed(self.evidence_log)
                if float(e.get("confidence", 1.0)) >= _CONF_FLOOR
            ][:max_evidence]

        return pending, completed, evidence

    def build_focus_context(
        self,
        phase: str,
        max_objectives: int = 4,
        max_evidence: int = 6,
    ) -> str:
        """Create objective+evidence context to keep the LLM execution-focused.

        Output uses semantic XML delimiters so LLMs parse structure reliably.
        Prefix is '<objective_focus' for ephemeral-message filtering.
        """
        phase_key = phase.upper()

        pending, completed, evidence = self.get_phase_context(
            phase_key, max_objectives=max_objectives, max_evidence=max_evidence
        )

        if not pending and not evidence and not completed:
            return ""

        lines = [f'<objective_focus phase="{phase_key}">']
        if pending:
            lines.append("  <pending_objectives>")
            for obj in pending:
                lines.append(f"    - {obj.get('title', '')}")
            lines.append("  </pending_objectives>")
        if completed:
            lines.append("  <completed_objectives>")
            for obj in completed:
                lines.append(f"    - {obj.get('title', '')}")
            lines.append("  </completed_objectives>")
        if evidence:
            lines.append("  <recent_evidence>")
            for ev in evidence:
                src = ev.get("source_tool", "tool")
                summary = ev.get("summary", "")
                artifact = ev.get("artifact")
                artifact_note = f" [{artifact}]" if artifact else ""
                sev = int(ev.get("severity", 1))
                sev_label = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "INFO"}.get(sev, "INFO")
                owasp_tags = [t for t in ev.get("tags", []) if t.startswith("owasp:")]
                owasp_note = f" {','.join(owasp_tags)}" if owasp_tags else ""
                lines.append(f"    - [{src}][{sev_label}]{owasp_note} {summary}{artifact_note}")
            lines.append("  </recent_evidence>")

        lines.append(
            "  <action_required>Pick one pending objective OR one high-value novel hypothesis."
            " Call the best next tool NOW — no more planning text.</action_required>"
        )
        lines.append("</objective_focus>")
        return "\n".join(lines)

    def patch_objectives(self, ops: list[dict[str, Any]]) -> int:
        """Apply delta patches to objective_queue without full regeneration.

        Supported operations (op field):
          - "add"    : add new pending objective (title + phase required)
          - "remove" : remove pending objective matching title+phase
          - "modify" : rename an objective (new_title required)
          - "done"   : mark an objective as completed (same as mark_objective)
          - "reorder": move objective to a new position (after_title)

        Returns the number of changes applied.
        """
        # FIX #5: Validate phase against PipelinePhase enum
        from .pipeline import PipelinePhase
        _valid_phases = {p.value for p in PipelinePhase}
        
        changed = 0
        now = datetime.now(timezone.utc).isoformat()

        for op in ops:
            op_type = op.get("op", "").lower()
            title = str(op.get("title", "")).strip()
            phase = str(op.get("phase", "")).strip().upper()

            if op_type == "add":
                if not title:
                    continue
                # Skip duplicate: check only within the target phase.
                # Using "phase or RECON" resolves the effective phase first so
                # the check is never accidentally cross-phase.
                _effective_phase = phase or "RECON"
                
                # Validate phase - warn and default to RECON if invalid
                if _effective_phase not in _valid_phases:
                    logger.warning(
                        "patch_objectives: Invalid phase '%s' in op '%s', defaulting to RECON",
                        phase, op_type
                    )
                    _effective_phase = "RECON"
                
                existing_titles = {
                    str(o.get("title", "")).strip().lower()
                    for o in self.objective_queue
                    if str(o.get("phase", "")).upper() == _effective_phase
                }
                if title.lower() in existing_titles:
                    continue
                new_obj: dict[str, Any] = {
                    "phase": _effective_phase,
                    "title": title,
                    "status": "pending",
                    "priority": int(op.get("priority", 50)),
                    "updated_iteration": self.iteration,
                    "updated_at": now,
                }
                after_title = str(op.get("after_title", "")).strip().lower()
                if after_title:
                    idx = next(
                        (
                            i for i, o in enumerate(self.objective_queue)
                            if str(o.get("title", "")).strip().lower() == after_title
                        ),
                        -1,
                    )
                    if idx >= 0:
                        self.objective_queue.insert(idx + 1, new_obj)
                    else:
                        self.objective_queue.append(new_obj)
                else:
                    self.objective_queue.append(new_obj)
                changed += 1

            elif op_type == "remove":
                before = len(self.objective_queue)
                self.objective_queue = [
                    o for o in self.objective_queue
                    if not (
                        str(o.get("title", "")).strip().lower() == title.lower()
                        and (not phase or str(o.get("phase", "")).upper() == phase)
                        and str(o.get("status", "pending")).lower() != "done"
                    )
                ]
                changed += before - len(self.objective_queue)

            elif op_type == "modify":
                new_title = str(op.get("new_title", "")).strip()
                for obj in self.objective_queue:
                    if (
                        str(obj.get("title", "")).strip().lower() == title.lower()
                        and (not phase or str(obj.get("phase", "")).upper() == phase)
                    ):
                        if new_title:
                            obj["title"] = new_title
                        if "priority" in op:
                            obj["priority"] = int(op["priority"])
                        obj["updated_iteration"] = self.iteration
                        obj["updated_at"] = now
                        changed += 1
                        break

            elif op_type == "done":
                _done_phase = phase or "RECON"
                if _done_phase not in _valid_phases:
                    logger.warning(
                        "patch_objectives: Invalid phase '%s' in op 'done', defaulting to RECON",
                        phase
                    )
                    _done_phase = "RECON"
                self.mark_objective(
                    _done_phase, title, status="done", note=op.get("note")
                )
                changed += 1

            elif op_type == "reorder":
                # Move matching objective to after another objective
                obj = next(
                    (
                        o for o in self.objective_queue
                        if str(o.get("title", "")).strip().lower() == title.lower()
                        and (not phase or str(o.get("phase", "")).upper() == phase)
                    ),
                    None,
                )
                if obj:
                    self.objective_queue.remove(obj)
                    after_title = str(op.get("after_title", "")).strip().lower()
                    if after_title:
                        idx = next(
                            (
                                i for i, o in enumerate(self.objective_queue)
                                if str(o.get("title", "")).strip().lower() == after_title
                            ),
                            -1,
                        )
                        self.objective_queue.insert(idx + 1 if idx >= 0 else 0, obj)
                    else:
                        self.objective_queue.insert(0, obj)
                    changed += 1

        if len(self.objective_queue) > MAX_OBJECTIVES:
            self.objective_queue = self.objective_queue[-MAX_OBJECTIVES:]

        return changed

    def is_approaching_limit(self) -> bool:
        return self.iteration >= (self.max_iterations - 3)

    def increment_iteration(self) -> None:
        self.iteration += 1

    def truncate_conversation(self, max_messages: int = 50) -> None:
        if len(self.conversation) <= max_messages:
            return

        EPHEMERAL_PREFIXES = (
            "[SYSTEM: WORKSPACE",
            "[SYSTEM: ACTIVE_TARGET",
            "[SYSTEM: ADDITIONAL_TARGETS",
            "[SYSTEM: RECENT EXECUTIONS",
            "[SYSTEM: EVALUATION CHECKPOINT",
            "[SYSTEM: MANDATORY PLANNING",
            "[SYSTEM: PREVIOUS SESSION DATA",
            "[SYSTEM: CRITICAL FINDINGS",
            "[SYSTEM: OBJECTIVE FOCUS",  # legacy prefix
            "<objective_focus",           # XML format (current)
            "[SYSTEM: PHASE GATE",
            "[SYSTEM: AGGRESSIVE EXPLORATION",
            "[SYSTEM: QUALITY SCOREBOARD",
            "[SYSTEM: CAIDO REMINDER",    # periodic reminder, keep only latest
            "[SYSTEM: UNVERIFIED CLAIM",  # claim validation warnings (ephemeral)
            "<reflector ",                # XML reflector messages
            "<mentor_analysis>",          # XML mentor messages
            "<hypothesis_queue",          # Hypothesis engine context (regenerated each iter)
            "<exploit_chain_plan>",       # Exploit chain context (regenerated each iter)
            "<waf_bypass ",               # WAF bypass context (injected on WAF detection)
        )
        # These prefixes carry recovery/orientation state that must survive
        # across truncations — never collapse them to a single message.
        PROTECTED_PREFIXES = (
            "[SYSTEM: RECOVERY STATE",
            "[SYSTEM: PINNED CONTEXT",
            "[SYSTEM: RECOVERY MODE",
            "[SYSTEM: COMPRESSION SUMMARY",  # iterative LLM compression summary
        )

        core_system: list[dict] = []
        ephemeral_system: list[dict] = []
        protected_system: list[dict] = []
        other_messages: list[dict] = []

        for msg in self.conversation:
            if msg.get("role") == "system":
                content = msg.get("content", "")
                if any(content.startswith(p) for p in PROTECTED_PREFIXES):
                    protected_system.append(msg)
                elif any(content.startswith(p) for p in EPHEMERAL_PREFIXES):
                    ephemeral_system.append(msg)
                else:
                    core_system.append(msg)
            else:
                other_messages.append(msg)

        # Collapse ephemeral messages to most recent only (they're regenerated
        # each iteration). Protected messages are kept in full.
        if ephemeral_system:
            ephemeral_system = [ephemeral_system[-1]]
        # Keep at most the 2 most recent protected messages to bound context.
        if len(protected_system) > 2:
            protected_system = protected_system[-2:]

        # STEP 1: Compress verbose tool results in older messages
        # Keep last N messages uncompressed (config-based), compress older ones
        limits = _get_context_limits()
        compress_boundary = max(0, len(other_messages) - limits["uncompressed_keep_count"])
        for i in range(compress_boundary):
            msg = other_messages[i]
            content = msg.get("content", "")
            role = msg.get("role", "")

            # Compress tool results to 1-line summaries
            if role == "tool" and len(content) > 200:
                # Extract key info
                if "COMMAND FAILED" in content:
                    first_line = content.split("\n")[0]
                    msg["content"] = f"[COMPRESSED] {first_line}"
                elif "TOTAL:" in content:
                    # Find the TOTAL line
                    for line in content.split("\n"):
                        if "TOTAL:" in line:
                            msg["content"] = f"[COMPRESSED] {line.strip()}"
                            break
                elif "Success" in content[:50]:
                    first_line = content.split("\n")[0]
                    msg["content"] = f"[COMPRESSED] {first_line[:150]}"
                else:
                    msg["content"] = f"[COMPRESSED] Tool result ({len(content)} chars)"

            # Compress verbose assistant text (not tool calls)
            elif (
                role == "assistant" and not msg.get(
                    "tool_calls") and len(content) > 500
            ):
                msg["content"] = content[:200] + "... [truncated]"

        # STEP 2: Drop text-only assistant messages from middle (least
        # critical)
        assistant_text_only = [
            m
            for m in other_messages
            if m.get("role") == "assistant" and not m.get("tool_calls")
        ]
        if len(assistant_text_only) > 3:
            dropped_text_ids = set(id(m) for m in assistant_text_only[1:-2])
            other_messages = [
                m for m in other_messages if id(m) not in dropped_text_ids
            ]

        budget = max_messages - len(core_system) - len(ephemeral_system) - len(protected_system)
        if len(other_messages) <= budget:
            self.conversation = core_system + ephemeral_system + protected_system + other_messages
            logger.info("Truncated (compressed + text-drop): %d messages", len(self.conversation))
            return

        # STEP 3: Pair-aware truncation — keep assistant+tool_calls with their
        # tool responses
        must_keep = []
        can_trim = []
        first_user_seen = False

        for msg in other_messages:
            if msg.get("role") == "user" and not first_user_seen:
                must_keep.append(msg)
                first_user_seen = True
            else:
                can_trim.append(msg)

        tail_budget = max(budget - len(must_keep), 10)
        if len(can_trim) > tail_budget:
            tail = can_trim[-tail_budget:]
            # Ensure we don't start mid-pair: scan backwards from the tail start
            # to find a safe boundary where we don't orphan any tool results.
            # A tool result is orphaned if its preceding assistant tool_call is excluded.
            start_idx = len(can_trim) - tail_budget
            while start_idx > 0:
                # Check if current position would orphan any tool message
                # by starting after an assistant with tool_calls
                found_orphan = False
                for i in range(start_idx, len(can_trim)):
                    if can_trim[i].get("role") == "tool":
                        # This tool result needs its preceding assistant call
                        # Scan backwards to find the owning assistant
                        for j in range(i - 1, start_idx - 1, -1):
                            if can_trim[j].get("role") == "assistant" and can_trim[j].get("tool_calls"):
                                # Found the owner - this is fine
                                break
                        else:
                            # No owner in range - would orphan this tool result
                            found_orphan = True
                            # Move start_idx back to include the owning assistant
                            for j in range(i - 1, -1, -1):
                                if can_trim[j].get("role") == "assistant" and can_trim[j].get("tool_calls"):
                                    start_idx = j + 1  # Include this assistant
                                    break
                            else:
                                # Owner is before start_idx - move back one more
                                start_idx -= 1
                            break
                if not found_orphan:
                    break
                tail = can_trim[start_idx:]
            trimmed = tail
            dropped_count = len(can_trim) - len(trimmed)
        else:
            trimmed = can_trim
            dropped_count = 0

        separator = {
            "role": "system",
            "content": (
                f"[SYSTEM: {dropped_count} older messages compressed/removed to manage context. "
                "Key findings are preserved in the session summary. "
                "The original user request is preserved above.]"
            ),
        }

        rebuilt = must_keep + \
            ([separator] if dropped_count > 0 else []) + trimmed
        repaired = self._repair_tool_pairs(
            core_system + ephemeral_system + protected_system + rebuilt
        )
        self.conversation = repaired
        logger.info(
            "Truncated (pair-preserving): %d messages (dropped %d older messages)",
            len(self.conversation), dropped_count,
        )

    @staticmethod
    def _repair_tool_pairs(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Fix orphaned tool_call / tool_result pairs after truncation.

        Port of AIRecon agent context_compressor._sanitize_tool_pairs() —
        uses ID-based matching (not positional) for correctness.

        Two failure modes:
        1. tool result references a call_id whose assistant tool_call was removed
           → drop the orphaned result (API rejects unknown call_ids)
        2. assistant message has tool_calls whose results were dropped
           → insert stub result per call so Ollama doesn't see an unclosed call
        """
        # Pass 1: collect all call_ids declared by assistant messages
        surviving_call_ids: set[str] = set()
        for msg in messages:
            if msg.get("role") == "assistant":
                for tc in msg.get("tool_calls") or []:
                    cid = (
                        tc.get("id", "") if isinstance(tc, dict)
                        else getattr(tc, "id", "") or ""
                    )
                    if cid:
                        surviving_call_ids.add(cid)

        # Pass 2: collect all call_ids already answered by tool messages
        result_call_ids: set[str] = set()
        for msg in messages:
            if msg.get("role") == "tool":
                cid = msg.get("tool_call_id", "")
                if cid:
                    result_call_ids.add(cid)

        # 1. Remove tool results whose call_id has no matching assistant tool_call
        orphaned_results = result_call_ids - surviving_call_ids
        if orphaned_results:
            messages = [
                m for m in messages
                if not (
                    m.get("role") == "tool"
                    and m.get("tool_call_id") in orphaned_results
                )
            ]
            logger.debug(
                "Pair repair: dropped %d orphaned tool result(s) %s",
                len(orphaned_results), orphaned_results,
            )

        # 2. Insert stub results for assistant tool_calls that have no result
        missing_results = surviving_call_ids - result_call_ids
        if missing_results:
            patched: list[dict[str, Any]] = []
            for msg in messages:
                patched.append(msg)
                if msg.get("role") == "assistant":
                    for tc in msg.get("tool_calls") or []:
                        cid = (
                            tc.get("id", "") if isinstance(tc, dict)
                            else getattr(tc, "id", "") or ""
                        )
                        if cid in missing_results:
                            patched.append({
                                "role": "tool",
                                "tool_call_id": cid,
                                "content": (
                                    "[Tool result unavailable — "
                                    "earlier context was compressed]"
                                ),
                            })
                            logger.debug("Pair repair: inserted stub for call_id=%s", cid)
            messages = patched

        return messages

    # ------------------------------------------------------------------
    # Smart context compression helper (Priority 5)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_flags(content: str) -> list[str]:
        """Return unique FLAG{...} values found in content."""
        return list({m.group(0) for m in FLAG_PATTERN.finditer(content)})

    @staticmethod
    def _extract_key_info(content: str, max_chars: int = 500) -> str:
        """Extract high-priority lines from tool output rather than dumb truncation.

        Priority order (all that match are kept, up to max_chars):
          1. FLAG{...} / flag{...} patterns                — always preserved
          2. HTTP status lines (HTTP/1.1 200, etc.)        — discovery evidence
          3. URLs (https?://...)                           — endpoint discovery
          4. Lines containing key security-relevant words  — error/success/token/cred
          5. Remaining content (first N chars)             — fill remaining budget
        """
        PRIORITY_PATTERNS = [
            FLAG_PATTERN,
            re.compile(r"HTTP/[\d.]+ \d+"),
            re.compile(r"https?://\S+"),
            re.compile(
                r"(?i)(error|found|success|failed|token|secret|password|key|"
                r"admin|root|flag|credential|auth|login|cookie|session)"
            ),
        ]

        priority_lines: list[str] = []
        seen: set[str] = set()
        for line in content.split("\n"):
            stripped = line.strip()
            if not stripped or stripped in seen:
                continue
            if any(p.search(stripped) for p in PRIORITY_PATTERNS):
                priority_lines.append(stripped)
                seen.add(stripped)

        # Build result: priority lines first, then fallback to raw start
        key_part = "\n".join(priority_lines[:30])  # max 30 priority lines
        if len(key_part) >= max_chars:
            return key_part[:max_chars]

        remaining = max_chars - len(key_part)
        filler = content[:remaining].strip()
        if key_part and filler:
            return key_part + "\n" + filler
        return (key_part or filler)[:max_chars]

    async def compress_with_llm(
        self,
        ollama: Any,
        keep_recent: int | None = None,
        num_ctx: int | None = None,
        num_predict: int | None = None,
    ) -> None:
        """Compress old messages via LLM summarization when conversation grows large.

        Trigger: conversation > 80% of max_conversation_messages (config-based).
        Strategy:
        - Keep all system messages untouched
        - Keep first user message (original task)
        - Keep last `keep_recent` messages verbatim
        - Summarize everything in between in chunks of 10
        - Preserves: URLs, vulns, credentials, tool outputs, phase info
        - Fallback: keeps original chunk if LLM call fails
        """
        limits = _get_context_limits()
        if keep_recent is None:
            keep_recent = 30
        if num_ctx is None:
            num_ctx = limits["llm_compression_num_ctx"]
        if num_predict is None:
            num_predict = limits["llm_compression_num_predict"]

        non_system = [
            m for m in self.conversation if m.get("role") != "system"]
        if len(non_system) <= keep_recent + 1:
            return  # Not enough messages to compress

        system_msgs = [
            m for m in self.conversation if m.get("role") == "system"]
        first_user = non_system[0]
        to_compress = non_system[1: len(non_system) - keep_recent]
        keep_tail = non_system[len(non_system) - keep_recent:]

        if len(to_compress) < 5:
            return  # Too few to bother compressing

        CHUNK_SIZE = 10
        summaries: list[dict[str, Any]] = []

        for i in range(0, len(to_compress), CHUNK_SIZE):
            chunk = to_compress[i: i + CHUNK_SIZE]
            chunk_text = "\n\n".join(
                f"[{m.get('role', 'unknown').upper()}]: "
                + AgentState._extract_key_info(str(m.get("content", "")), 500)
                for m in chunk
            )
            prompt = [
                {
                    "role": "system",
                    "content": (
                        "You are a memory compressor for an AI security testing agent. "
                        "Summarize the following conversation chunk in 3-5 dense sentences. "
                        "Preserve ALL of: discovered URLs, subdomains, open ports, "
                        "credentials/tokens found, confirmed vulnerability findings, "
                        "key tool outputs, and current testing phase. "
                        "Be specific and technical — no vague descriptions."
                    ),
                },
                {"role": "user", "content": chunk_text},
            ]

            # Extract flags directly to ensure they are never lost
            extracted_flags: list[str] = []
            for m in chunk:
                content = str(m.get("content", ""))
                extracted_flags.extend(AgentState._extract_flags(content))

            extracted_flags = list(set(extracted_flags))

            # FIX #6: Add timeout and retry logic for LLM compression calls
            summary_text = None
            max_retries = 2
            retry_delay = 1.0  # seconds
            
            for attempt in range(max_retries + 1):
                try:
                    # Use asyncio.wait_for to prevent hanging on slow Ollama responses
                    summary_text = await asyncio.wait_for(
                        ollama.complete(
                            prompt,
                            options={"num_ctx": num_ctx, "num_predict": num_predict, "temperature": 0.1},
                        ),
                        timeout=60.0  # 60 second timeout per chunk
                    )
                    break  # Success - exit retry loop
                except asyncio.TimeoutError:
                    logger.warning(
                        "Memory compression LLM call timed out (attempt %d/%d), retrying...",
                        attempt + 1, max_retries + 1
                    )
                    if attempt < max_retries:
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                    else:
                        logger.error("Memory compression LLM call timed out after %d attempts", max_retries + 1)
                except Exception as e:
                    logger.warning(
                        "Memory compression LLM call failed (attempt %d/%d): %s",
                        attempt + 1, max_retries + 1, e
                    )
                    if attempt < max_retries:
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2
                    else:
                        logger.error("Memory compression LLM call failed after %d attempts", max_retries + 1)
                        break

            if summary_text:
                # Append extracted flags to summary to guarantee they survive
                if extracted_flags:
                    summary_text += "\n\n[CRITICAL PRESERVED DATA]\nFlags found: " + \
                        ", ".join(extracted_flags)

                summaries.append({
                    "role": "system",
                    "content": (
                        f"[COMPRESSED MEMORY — {len(chunk)} messages]: {summary_text}"
                    ),
                })
            else:
                # Fallback: keep original chunk if all retries failed
                logger.warning("Memory compression failed for chunk, keeping original %d messages", len(chunk))
                summaries.extend(chunk)

        before = len(self.conversation)
        self.conversation = system_msgs + [first_user] + summaries + keep_tail
        logger.info(
            "Memory compressed: %d messages → %d summaries (%d → %d total)",
            len(to_compress), len(summaries), before, len(self.conversation),
        )
