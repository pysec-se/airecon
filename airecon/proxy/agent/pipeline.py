"""Structured Pipeline Engine for AIRecon.

Implements a phase-based state machine that guides the agent through
systematic security testing phases: RECON → ANALYSIS → EXPLOIT → REPORT.

Each phase has specific objectives, recommended tools, and transition
criteria. The pipeline injects phase-specific system prompts to keep
the agent focused and prevent skipping phases.
"""

from __future__ import annotations

import logging
import os
import random
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..config import get_config as _get_config

logger = logging.getLogger("airecon.agent.pipeline")

_PROMPTS_DIR = Path(__file__).parent.parent / "prompts" / "phases"

# Load tool-agnostic phase hints from tools_meta.json so tool names stay out of Python code.
try:
    import json as _json
    _tools_meta = _json.loads(
        (Path(__file__).parent.parent / "data" / "tools_meta.json").read_text(encoding="utf-8")
    )
    _recon_hints: dict[str, str] = _tools_meta.get("recon_phase_hints", {})
except Exception:
    _recon_hints = {}

_LIVE_HOST_HINT: str = _recon_hints.get(
    "live_host_validation",
    "CRITICAL: After subdomain enumeration, ALWAYS validate which hosts are alive before "
    "port scanning or directory brute-force. Never scan dead/unresolved hosts.",
)


class PipelinePhase(Enum):
    """Ordered phases of the security testing pipeline."""

    RECON = "RECON"
    ANALYSIS = "ANALYSIS"
    EXPLOIT = "EXPLOIT"
    REPORT = "REPORT"
    COMPLETE = "COMPLETE"


# Phase ordering for transitions
_PHASE_ORDER = [
    PipelinePhase.RECON,
    PipelinePhase.ANALYSIS,
    PipelinePhase.EXPLOIT,
    PipelinePhase.REPORT,
    PipelinePhase.COMPLETE,
]

_PHASE_CONFIDENCE_THRESHOLDS: dict[PipelinePhase, float] = {
    PipelinePhase.RECON: 0.60,
    PipelinePhase.ANALYSIS: 0.58,
    PipelinePhase.EXPLOIT: 0.55,
    PipelinePhase.REPORT: 0.50,
}


@dataclass
class PhaseConfig:
    """Configuration for a single pipeline phase."""

    phase: PipelinePhase
    max_iterations: int
    objective: str
    recommended_tools: list[str] = field(default_factory=list)
    transition_criteria: list[str] = field(default_factory=list)
    # Randomly sampled each checkpoint — encourages creative / non-repetitive approaches.
    # 2 hints are injected into the phase prompt so the LLM tries different angles.
    exploration_hints: list[str] = field(default_factory=list)


# Default phase configurations
DEFAULT_PHASES: dict[PipelinePhase, PhaseConfig] = {
    PipelinePhase.RECON: PhaseConfig(
        phase=PipelinePhase.RECON,
        max_iterations=500,
        objective=(
            "Understand the target deeply — choose the recon approach best suited to this "
            "specific target. Prioritise breadth initially; pivot to unusual entry points "
            "if standard paths yield nothing. " + _LIVE_HOST_HINT
        ),
        recommended_tools=[
            "execute", "web_search", "browser_action", "create_file",
            "read_file", "list_files",
            "caido_set_scope", "caido_sitemap", "caido_list_requests",
        ],
        transition_criteria=[
            "subdomains_discovered",      # session.subdomains is non-empty
            "live_hosts_validated",       # session.live_hosts is non-empty (host probing ran)
            "ports_scanned",              # session.open_ports is non-empty
            "recon_artifacts_saved",      # output/ directory has files
            "subdomain_depth_met",        # >= pipeline_recon_min_subdomains discovered
            "url_discovery_met",          # >= pipeline_recon_min_urls collected
        ],
        exploration_hints=[
            "Passive OSINT before active scanning: crt.sh, Shodan dorks, WHOIS, ASN lookup, reverse-IP",
            "favicon.ico hash lookup → identify framework and find related assets on Shodan (http.favicon.hash:X)",
            "JS file analysis finds more endpoints on SPAs than directory brute-force — run linkfinder/subjs",
            "Check /.git/, /.svn/, /backup.zip, /.env, /dump.sql — exposed VCS or backup artifacts",
            "WAF/CDN fingerprint first — masscan or nmap on a CDN IP wastes time, identify real origin",
            "Certificate transparency: crt.sh JSON API or tlsx often finds subdomains brute-force misses",
            "robots.txt + sitemap.xml explicitly list hidden/admin paths the operator wants hidden",
            "HTTP response header analysis: Server, X-Powered-By, Via, Set-Cookie — fingerprint full stack",
            "Try HTTP/2 or HTTP/3 — some endpoints respond differently or expose extra headers under h2",
            "Cloud storage: enumerate target-name S3/GCS buckets (aws s3 ls s3://target-name-*)",
            "DNS zone transfer attempt — takes <1 second, occasionally reveals full zone even on production",
            "Reverse IP lookup: shared hosting exposes sibling virtual hosts on the same IP",
            "Google/Bing dorks: site:{target} filetype:env OR filetype:sql OR inurl:admin OR intext:apikey",
            "Wayback Machine CDX API — find historical endpoints no longer in the current sitemap",
            "DMARC/SPF/DKIM records often leak internal mail servers and infrastructure hostnames",
            "Probe non-standard ports (8080, 8443, 8888, 9000, 9200, 6379, 27017) before standard port scan",
            "Check for open directory listing on /uploads/, /files/, /backup/, /static/, /assets/",
            "TLS certificate SAN fields often contain sibling subdomains not visible via DNS",
        ],
    ),
    PipelinePhase.ANALYSIS: PhaseConfig(
        phase=PipelinePhase.ANALYSIS,
        max_iterations=300,
        objective=(
            "Identify exploitable weaknesses — go beyond standard injection points. "
            "Look for logic flaws, misconfigured access controls, trust boundary violations, "
            "and technology-specific vulnerabilities based on the identified stack."
        ),
        recommended_tools=[
            "execute", "browser_action", "code_analysis", "web_search",
            "read_file", "create_file",
            "caido_list_requests", "caido_send_request", "caido_sitemap",
        ],
        transition_criteria=[
            "urls_collected",             # session.urls is non-empty
            "technologies_identified",    # session.technologies is non-empty
            "injection_points_found",     # session.injection_points is non-empty
        ],
        exploration_hints=[
            "Compare authenticated vs unauthenticated responses — missing access controls often show here",
            "GraphQL introspection if GraphQL detected — map full schema before testing mutations",
            "API versioning gaps: if /api/v2 exists, probe /api/v1 and /api/v0 for deprecated endpoints",
            "Test HTTP method override: X-HTTP-Method-Override: DELETE on read-only endpoints",
            "Mass assignment: send extra JSON fields (role, admin, is_staff) in POST body",
            "Error message mining: trigger 400/500 with malformed input to reveal framework/version/paths",
            "Session token entropy: decode base64 JWTs, check for none-alg, weak secret, or expired tokens",
            "CORS: does server echo Origin with Access-Control-Allow-Origin: * or reflect arbitrary origins?",
            "Parameter pollution: supply the same parameter twice — many frameworks use the last/first value",
            "Check OPTIONS method for allowed verbs — PUT/DELETE on read-only resources is a finding",
            "Search JS source for hardcoded API keys, tokens, internal URLs, debug flags",
            "Content-Type confusion: send JSON as form-encoded and vice versa — parser differences matter",
            "Host header injection: change Host header to internal hostnames or attacker domain",
            "Cache poisoning indicators: Vary header missing, X-Cache present, user-supplied data in response",
            "Test second-order issues: input stored now, rendered later — check profile/dashboard pages",
        ],
    ),
    PipelinePhase.EXPLOIT: PhaseConfig(
        phase=PipelinePhase.EXPLOIT,
        max_iterations=800,
        objective="Test and exploit vulnerabilities: fuzzing, injection testing, authentication bypass",
        recommended_tools=[
            "execute", "quick_fuzz", "advanced_fuzz", "deep_fuzz",
            "browser_action", "spawn_agent", "caido_send_request",
            "caido_automate", "caido_list_requests", "caido_get_findings",
            "schemathesis_fuzz", "create_vulnerability_report",
        ],
        transition_criteria=[
            "vulnerabilities_tested",     # session.vulnerabilities is non-empty
        ],
    ),
    PipelinePhase.REPORT: PhaseConfig(
        phase=PipelinePhase.REPORT,
        max_iterations=100,
        objective="Generate final report: document all findings with PoC, CVSS, and remediation",
        recommended_tools=[
            "create_vulnerability_report", "create_file", "read_file",
        ],
        transition_criteria=[
            "reports_generated",          # vulnerabilities have reports
        ],
    ),
}


# Soft tool budgets per phase. 0 = strongly discouraged, None = unlimited.
# These are warning thresholds, NOT hard blocks. Exceeding budget injects
# a guidance message to steer the agent toward phase-appropriate tools.
_PHASE_TOOL_BUDGETS: dict[str, dict[str, int]] = {
    "RECON": {
        "quick_fuzz": 10,
        "advanced_fuzz": 5,
        "deep_fuzz": 0,
        "caido_automate": 5,
        "create_vulnerability_report": 2,
    },
    "ANALYSIS": {
        "advanced_fuzz": 15,
        "deep_fuzz": 5,
        "create_vulnerability_report": 5,
    },
    "EXPLOIT": {
        "advanced_fuzz": 50,
        "deep_fuzz": 25,
        "quick_fuzz": 60,
        "caido_automate": 40,
    },
    "REPORT": {
        "execute": 10,
        "advanced_fuzz": 0,
        "deep_fuzz": 0,
        "quick_fuzz": 0,
    },
}

# One-line skill directory hints injected into the phase prompt so the LLM
# knows which skill categories are relevant for the active phase.
_PHASE_SKILL_HINTS: dict[str, str] = {
    "RECON": "Phase skills: reconnaissance/, protocols/, tools/",
    "ANALYSIS": "Phase skills: vulnerabilities/, frameworks/, technologies/, protocols/",
    "EXPLOIT": "Phase skills: payloads/, vulnerabilities/, postexploit/, frameworks/",
    "REPORT": "Phase skills: reporting/, vulnerabilities/, remediation/",
}


class PipelineEngine:
    """Phase-based pipeline engine for systematic security testing.

    Integrates with the AgentLoop to inject phase-specific prompts
    and manage transitions between phases.
    """

    # Minimum iterations to spend in a phase before allowing transition.
    # Prevents instant skip-through when prior phase data already satisfies
    # criteria.
    MIN_ITERATIONS_PER_PHASE = 10

    def __init__(self, session: Any, config: Any = None) -> None:
        self.session = session
        self._phase_prompts: dict[PipelinePhase, str] = {}
        self._phase_entry_iteration: int = 0   # iteration when current phase started
        self._current_iteration: int = 0       # updated by AgentLoop each checkpoint
        self._ctf_mode: bool = False           # bypass standard phase heuristics

        # Depth requirements for RECON → ANALYSIS transition (loaded lazily from config)
        cfg = config if config is not None else _get_config()
        self._recon_min_subdomains: int = getattr(cfg, "pipeline_recon_min_subdomains", 3)
        self._recon_min_urls: int = getattr(cfg, "pipeline_recon_min_urls", 1)
        self._recon_soft_timeout: int = getattr(cfg, "pipeline_recon_soft_timeout", 30)
        # Hard timeout: forces RECON → ANALYSIS even when data exists but live
        # hosts are never confirmed.  Prevents the agent from looping through
        # MAX_TOOL_ITERATIONS (2000) when the target never responds to probes.
        # Defaults to 2× soft_timeout; configurable via pipeline_recon_hard_timeout.
        self._recon_hard_timeout: int = getattr(
            cfg, "pipeline_recon_hard_timeout", self._recon_soft_timeout * 2
        )

        self._load_phase_prompts()

    def _load_phase_prompts(self) -> None:
        """Load phase-specific prompt templates from files."""
        for phase in PipelinePhase:
            if phase == PipelinePhase.COMPLETE:
                continue
            prompt_file = _PROMPTS_DIR / f"{phase.value.lower()}.txt"
            try:
                if prompt_file.exists():
                    self._phase_prompts[phase] = prompt_file.read_text(
                        encoding="utf-8")
                else:
                    self._phase_prompts[phase] = self._default_prompt(phase)
            except Exception as e:
                logger.warning("Failed to load phase prompt for %s: %s", phase.value, e)
                self._phase_prompts[phase] = self._default_prompt(phase)

    def _default_prompt(self, phase: PipelinePhase) -> str:
        """Generate a default phase prompt if file is missing."""
        config = DEFAULT_PHASES.get(phase)
        if not config:
            return ""
        return (
            f"[PIPELINE PHASE: {phase.value}]\n"
            f"Objective: {config.objective}\n"
            "Use the most suitable available capabilities for this phase objective.\n"
            f"Complete this phase thoroughly before moving to the next."
        )

    def get_current_phase(self) -> PipelinePhase:
        """Get the current pipeline phase from session state."""
        phase_str = getattr(self.session, "current_phase", "RECON")
        try:
            return PipelinePhase(phase_str)
        except ValueError:
            return PipelinePhase.RECON

    def set_phase(self, phase: PipelinePhase) -> None:
        """Set the current phase in session state."""
        self.session.current_phase = phase.value
        self._phase_entry_iteration = self._current_iteration
        logger.info("Pipeline phase set to: %s", phase.value)

    def set_ctf_mode(self, enabled: bool = True) -> None:
        """Activate CTF/benchmark mode.

        In CTF mode:
        - Phase transition heuristics are bypassed (no subdomains/host count checks).
        - The pipeline jumps directly to EXPLOIT phase objective.
        - Phase prompt is replaced with a short, exploit-first directive.
        """
        self._ctf_mode = enabled
        if enabled:
            # Immediately advance past RECON into EXPLOIT if still in RECON
            current = self.get_current_phase()
            if current == PipelinePhase.RECON:
                self.set_phase(PipelinePhase.EXPLOIT)
            logger.info("Pipeline CTF mode enabled — skipped to EXPLOIT phase")

    def should_transition(self) -> bool:
        """Check if the current phase's transition criteria are met."""
        # CTF mode: do not drive further transitions via heuristics;
        # the agent finishes when it finds the flag and calls [TASK_COMPLETE].
        if self._ctf_mode:
            return False

        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return False

        config = DEFAULT_PHASES.get(current)
        if not config:
            return False

        # Cooldown: must spend MIN_ITERATIONS_PER_PHASE in current phase first.
        # Prevents skipping a phase because prior-phase data already satisfies
        # criteria.
        iterations_in_phase = self._current_iteration - self._phase_entry_iteration
        if iterations_in_phase < self.MIN_ITERATIONS_PER_PHASE:
            return False

        # Soft timeout: if RECON has gone on too long, force transition regardless
        # of depth criteria to prevent infinite loops on difficult targets.
        # Guard: live_hosts_validated is still mandatory — even on timeout we
        # must have confirmed at least one live host to produce meaningful ANALYSIS.
        # Exception: if target is completely unreachable (no data at all), allow
        # transition with a warning so the operator can investigate.
        if (current == PipelinePhase.RECON
                and iterations_in_phase >= self._recon_soft_timeout):
            met_criteria = self._evaluate_criteria(current)
            has_live_hosts = "live_hosts_validated" in met_criteria
            has_any_data = bool(
                getattr(self.session, "urls", [])
                or getattr(self.session, "open_ports", {})
                or getattr(self.session, "subdomains", [])
                or getattr(self.session, "live_hosts", [])
            )
            if not has_live_hosts and has_any_data:
                # Hard timeout: if live hosts are still unconfirmed after
                # _recon_hard_timeout iterations, force transition anyway to
                # prevent the agent burning all 2000 iterations in RECON.
                if iterations_in_phase >= self._recon_hard_timeout:
                    logger.warning(
                        "RECON hard timeout (%d iter, limit=%d) — live_hosts_validated "
                        "never met but data was collected.  Forcing transition to ANALYSIS "
                        "with low confidence; manual review recommended.",
                        iterations_in_phase,
                        self._recon_hard_timeout,
                    )
                    return True
                logger.warning(
                    "RECON soft timeout (%d iter) but live_hosts_validated not met — "
                    "agent must validate live hosts before ANALYSIS. Blocking transition.",
                    iterations_in_phase,
                )
                return False
            if not has_any_data:
                logger.warning(
                    "RECON soft timeout (%d iter) with NO data collected — "
                    "target may be unreachable.  Forcing transition to ANALYSIS "
                    "anyway; agent will likely produce a low-confidence report.",
                    iterations_in_phase,
                )
            else:
                logger.info(
                    "RECON soft timeout reached (%d iterations) — forcing transition to ANALYSIS",
                    iterations_in_phase,
                )
            return True

        met_criteria = self._evaluate_criteria(current)
        total = len(config.transition_criteria)

        # RECON gate: live_hosts_validated is MANDATORY — ANALYSIS on dead hosts is useless.
        # Without confirmed live hosts, the model will hallucinate findings or scan /dev/null.
        if current == PipelinePhase.RECON and "live_hosts_validated" not in met_criteria:
            return False

        # Transition when at least 60% of criteria are met AND phase confidence
        # is sufficiently high.
        coverage_ok = len(met_criteria) >= max(1, int(total * 0.6))
        if not coverage_ok:
            return False
        confidence = self._phase_transition_confidence(
            current,
            met_criteria=met_criteria,
            total_criteria=total,
            iterations_in_phase=iterations_in_phase,
        )
        threshold = _PHASE_CONFIDENCE_THRESHOLDS.get(current, 0.55)
        return confidence >= threshold

    def _phase_transition_confidence(
        self,
        phase: PipelinePhase,
        *,
        met_criteria: list[str],
        total_criteria: int,
        iterations_in_phase: int,
    ) -> float:
        """Estimate readiness confidence for phase transition (0.0–1.0).

        The score intentionally models causal readiness instead of relying on
        fixed additive bonuses:
        - Criteria coverage: how much of the phase objective is satisfied.
        - Evidence quality: are downstream-relevant artifacts actually present.
        - Maturity: has the phase run long enough to stabilize observations.
        - Consistency penalty: contradictory state reduces transition trust.
        """
        if total_criteria <= 0:
            return 0.0
        coverage = len(met_criteria) / max(1, total_criteria)
        maturity = min(1.0, iterations_in_phase / max(1, self.MIN_ITERATIONS_PER_PHASE))
        evidence_quality, consistency_penalty = self._phase_causal_signals(phase)

        base = coverage * (0.55 + (0.25 * evidence_quality) + (0.20 * maturity))
        confidence = (
            base
            + (evidence_quality * 0.25)
            + (maturity * 0.08)
            - consistency_penalty
        )
        return round(min(1.0, max(0.0, confidence)), 3)

    @staticmethod
    def _vulnerability_severity(vuln: dict[str, Any]) -> str:
        """Normalize vulnerability severity into INFO/LOW/MEDIUM/HIGH/CRITICAL."""
        sev = str(vuln.get("severity", "")).strip().upper()
        if sev in {"1", "2", "3", "4", "5"}:
            return {"1": "INFO", "2": "LOW", "3": "MEDIUM", "4": "HIGH", "5": "CRITICAL"}[sev]
        if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            return sev
        finding = str(vuln.get("finding", "")).upper()
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if f"[{label}]" in finding:
                return label
        return "MEDIUM"

    def _phase_causal_signals(self, phase: PipelinePhase) -> tuple[float, float]:
        """Return (evidence_quality, consistency_penalty) for phase readiness."""
        s = self.session
        penalty = 0.0

        if phase == PipelinePhase.RECON:
            subdomains = max(1, len(getattr(s, "subdomains", [])))
            live_hosts = len(getattr(s, "live_hosts", []))
            urls = len(getattr(s, "urls", []))
            open_ports = sum(
                len(ports)
                for ports in getattr(s, "open_ports", {}).values()
                if isinstance(ports, list)
            )

            host_coverage = min(1.0, live_hosts / subdomains)
            service_coverage = min(1.0, open_ports / max(1, live_hosts * 2))
            endpoint_depth = min(1.0, urls / max(1, live_hosts * 2))

            if open_ports > 0 and live_hosts == 0:
                penalty += 0.18
            if urls > 0 and live_hosts == 0:
                penalty += 0.10

            quality = (
                (host_coverage * 0.40)
                + (service_coverage * 0.35)
                + (endpoint_depth * 0.25)
            )
            return quality, min(0.40, penalty)

        if phase == PipelinePhase.ANALYSIS:
            urls = len(getattr(s, "urls", []))
            tech_count = len(getattr(s, "technologies", {}))
            inj_points = len(getattr(s, "injection_points", []))
            vuln_count = len(getattr(s, "vulnerabilities", []))

            injection_density = min(1.0, inj_points / max(1, min(20, urls if urls > 0 else 4)))
            tech_context = min(1.0, tech_count / 6)
            vuln_signal = min(1.0, vuln_count / max(1, inj_points if inj_points > 0 else 3))

            if inj_points > 0 and urls == 0:
                penalty += 0.15
            if vuln_count > 0 and inj_points == 0:
                penalty += 0.12
            if urls >= 5 and tech_count == 0:
                penalty += 0.06

            quality = (
                (injection_density * 0.45)
                + (tech_context * 0.35)
                + (vuln_signal * 0.20)
            )
            return quality, min(0.40, penalty)

        if phase == PipelinePhase.EXPLOIT:
            vulns = getattr(s, "vulnerabilities", [])
            if not vulns:
                return 0.0, 0.0

            severe = 0
            confirmed = 0
            poc_backed = 0
            for vuln in vulns:
                sev = self._vulnerability_severity(vuln)
                if sev in {"CRITICAL", "HIGH", "MEDIUM"}:
                    severe += 1
                if bool(vuln.get("report_generated") or vuln.get("replay_verified") or vuln.get("verified")):
                    confirmed += 1
                if bool(vuln.get("proof") or vuln.get("evidence") or vuln.get("poc_script_code")):
                    poc_backed += 1

            severe_ratio = severe / len(vulns)
            confirmation_ratio = confirmed / len(vulns)
            exploitability_ratio = poc_backed / len(vulns)

            if severe > 0 and poc_backed == 0:
                penalty += 0.12
            if confirmation_ratio < 0.2 and len(vulns) >= 3:
                penalty += 0.08

            quality = (
                (confirmation_ratio * 0.45)
                + (exploitability_ratio * 0.35)
                + (severe_ratio * 0.20)
            )
            return quality, min(0.35, penalty)

        if phase == PipelinePhase.REPORT:
            vulns = getattr(s, "vulnerabilities", [])
            if not vulns:
                return 0.0, 0.0

            reported = 0
            replay_verified = 0
            technical_complete = 0
            for vuln in vulns:
                if vuln.get("report_generated"):
                    reported += 1
                if (
                    vuln.get("replay_verified")
                    or vuln.get("verified")
                    or float(vuln.get("verification_score", 0.0)) >= 0.6
                ):
                    replay_verified += 1
                if vuln.get("technical_analysis") and vuln.get("remediation"):
                    technical_complete += 1

            report_ratio = reported / len(vulns)
            replay_ratio = replay_verified / len(vulns)
            technical_ratio = technical_complete / len(vulns)

            if reported > 0 and replay_verified == 0:
                penalty += 0.15
            if report_ratio < 0.5 and len(vulns) >= 2:
                penalty += 0.08

            quality = (
                (report_ratio * 0.40)
                + (replay_ratio * 0.40)
                + (technical_ratio * 0.20)
            )
            return quality, min(0.35, penalty)

        return 0.0, 0.0

    def get_phase_transition_confidence(self) -> float:
        """Expose current phase transition confidence for observability."""
        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return 1.0
        config = DEFAULT_PHASES.get(current)
        if not config:
            return 0.0
        met = self._evaluate_criteria(current)
        iterations_in_phase = self._current_iteration - self._phase_entry_iteration
        return self._phase_transition_confidence(
            current,
            met_criteria=met,
            total_criteria=len(config.transition_criteria),
            iterations_in_phase=iterations_in_phase,
        )

    def _evaluate_criteria(self, phase: PipelinePhase) -> list[str]:
        """Evaluate which transition criteria are met for a phase."""
        met: list[str] = []
        session = self.session

        if phase == PipelinePhase.RECON:
            if getattr(session, "subdomains", []):
                met.append("subdomains_discovered")
            # live_hosts_validated: agent ran host probing and confirmed at least one host responds.
            # This forces the agent to filter dead subdomains before proceeding.
            if getattr(session, "live_hosts", []):
                met.append("live_hosts_validated")
            if getattr(session, "open_ports", {}):
                met.append("ports_scanned")
            # Check if output/ directory actually contains recon files on disk
            _recon_extensions = {".txt", ".out", ".nmap",
                                 ".csv", ".json", ".xml", ".html", ".log"}
            _has_output_files = False
            try:
                from ..config import get_workspace_root
                target = getattr(session, "target", "") or "unknown"
                output_dir = get_workspace_root() / target / "output"
                if output_dir.exists():
                    _has_output_files = any(
                        os.path.splitext(f)[1].lower() in _recon_extensions
                        for f in os.listdir(output_dir)
                        if os.path.getsize(output_dir / f) > 0
                    )
            except Exception as _e:
                logger.debug("Could not check workspace artifacts: %s", _e)
            # Prefer real output artifacts on disk.
            # Fallback for lightweight/in-memory runs (e.g. tests) where files are
            # not persisted but recon activity clearly produced usable signals.
            _scan_count = 0
            try:
                _scan_count = int(getattr(session, "scan_count", 0) or 0)
            except Exception:
                _scan_count = 0
            _has_recon_signals = bool(
                getattr(session, "open_ports", {})
                or getattr(session, "urls", [])
                or (
                    getattr(session, "subdomains", [])
                    and getattr(session, "live_hosts", [])
                )
            )
            if _has_output_files or (_scan_count >= 3 and _has_recon_signals):
                met.append("recon_artifacts_saved")
            # Depth checks: require minimum subdomain and URL discovery
            if len(getattr(session, "subdomains", [])) >= self._recon_min_subdomains:
                met.append("subdomain_depth_met")
            if len(getattr(session, "urls", [])) >= self._recon_min_urls:
                met.append("url_discovery_met")

        elif phase == PipelinePhase.ANALYSIS:
            if getattr(session, "urls", []):
                met.append("urls_collected")
            if getattr(session, "technologies", {}):
                met.append("technologies_identified")
            # Require at least 3 distinct injection points OR at least one
            # point with a security-relevant type (not just tracking params
            # like utm_source that inflate the count without adding value).
            _MEANINGFUL_TYPES = frozenset({
                "IDOR", "SSRF", "PATH_TRAVERSAL", "SQLi",
                "XSS", "AUTH", "BUSINESS_LOGIC", "RCE",
            })
            _ips = getattr(session, "injection_points", [])
            _has_meaningful = any(
                p.get("type_hint") in _MEANINGFUL_TYPES for p in _ips
            )
            if len(_ips) >= 3 or _has_meaningful:
                met.append("injection_points_found")

        elif phase == PipelinePhase.EXPLOIT:
            vulns = getattr(session, "vulnerabilities", [])
            # Require a *confirmed* vuln (explicit create_vulnerability_report call)
            # OR an auto-parsed finding of severity MEDIUM/HIGH/CRITICAL (>= 3).
            # A single [LOW]/[INFO] text-match is not sufficient to conclude
            # that exploitation was actually attempted and succeeded.
            _SIGNIFICANT_SEV_RE = re.compile(
                r"^\[(CRITICAL|HIGH|MEDIUM)\]", re.IGNORECASE
            )
            _confirmed = any(v.get("report_generated") for v in vulns)
            _has_significant = any(
                _SIGNIFICANT_SEV_RE.match(str(v.get("finding", "")))
                for v in vulns
            )
            if _confirmed or _has_significant:
                met.append("vulnerabilities_tested")

        elif phase == PipelinePhase.REPORT:
            vulns = getattr(session, "vulnerabilities", [])
            if any(v.get("report_generated") for v in vulns):
                met.append("reports_generated")

        return met

    def transition(self) -> PipelinePhase | None:
        """Advance to the next phase. Returns the new phase or None if already complete."""
        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return None

        # Soft-timeout bypass: if RECON has exceeded the timeout, allow transition
        # without requiring criteria to be met (target may be unreachable).
        iterations_in_phase = self._current_iteration - self._phase_entry_iteration
        _soft_timeout_bypass = (
            current == PipelinePhase.RECON
            and iterations_in_phase >= self._recon_soft_timeout
        )

        # Validate phase readiness (skipped on timeout bypass).
        if not _soft_timeout_bypass and not self.should_transition():
            logger.warning(
                "Attempted transition from %s without meeting confidence/criteria gate",
                current.value,
            )
            return current

        # Mark current phase as completed
        if current.value not in self.session.completed_phases:
            self.session.completed_phases.append(current.value)

        # Find next phase
        idx = _PHASE_ORDER.index(current)
        if idx + 1 >= len(_PHASE_ORDER):
            self.set_phase(PipelinePhase.COMPLETE)
            return PipelinePhase.COMPLETE

        next_phase = _PHASE_ORDER[idx + 1]
        self.set_phase(next_phase)
        # Reset cooldown timer for the new phase
        self._phase_entry_iteration = self._current_iteration
        logger.info("Pipeline transition: %s → %s", current.value, next_phase.value)
        return next_phase

    def get_phase_prompt(self) -> str:
        """Get the system prompt for the current phase."""
        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return "[PIPELINE: ALL PHASES COMPLETE] — Target fully tested."

        # CTF mode: replace long phase prompt with a focused exploit directive
        if self._ctf_mode:
            return (
                "[CTF MODE ACTIVE]\n"
                "Objective: find the exact runtime flag value from the target.\n"
                "Placeholder values like FLAG{...} are INVALID.\n"
                "Use short direct actions; avoid long generated scripts unless strictly necessary.\n"
                "Do not repeat the same strategy more than twice without new evidence.\n"
                "When a concrete flag is found, return it immediately with minimal proof."
            )

        config = DEFAULT_PHASES.get(current)
        base_prompt = self._phase_prompts.get(current, "")

        # Add progress info
        met = self._evaluate_criteria(current)
        total_criteria = len(config.transition_criteria) if config else 0
        confidence = self.get_phase_transition_confidence()
        progress = (
            f"Progress: {len(met)}/{total_criteria} criteria met"
            f" | transition_confidence={confidence:.0%}"
        )

        # Add completed phases
        completed = ", ".join(
            self.session.completed_phases) if self.session.completed_phases else "none"

        skill_hint = _PHASE_SKILL_HINTS.get(current.value, "")
        skill_line = f"\n{skill_hint}" if skill_hint else ""

        # Inject 2 randomly sampled exploration hints each checkpoint.
        # Randomisation prevents the LLM from memorising a fixed sequence and
        # encourages diverse recon approaches across sessions.
        exploration_line = ""
        if config and config.exploration_hints:
            sampled = random.sample(
                config.exploration_hints,
                min(2, len(config.exploration_hints)),
            )
            hints_str = "\n".join(f"  • {h}" for h in sampled)
            exploration_line = (
                f"\nEXPLORATION ANGLE (try one you haven't used yet):\n{hints_str}"
            )

        return (
            f"{base_prompt}\n\n"
            f"Completed phases: {completed}\n"
            f"{progress}"
            f"{skill_line}"
            f"{exploration_line}"
        )

    # Tools reserved for EXPLOIT/REPORT that should not be used earlier
    _EXPLOIT_SPECIFIC_TOOLS = frozenset({
        "quick_fuzz", "advanced_fuzz", "deep_fuzz",
        "caido_automate", "schemathesis_fuzz",
        "create_vulnerability_report",
    })

    def check_tool_phase_fit(self, tool_name: str) -> str | None:
        """Return a soft guidance warning if tool is used in the wrong phase.

        Does NOT block execution — only informs the agent that it is using an
        exploit-phase tool before completing reconnaissance/analysis objectives.
        Returns None when the tool is appropriate for the current phase.
        """
        current = self.get_current_phase()
        # Exploit/Report/Complete phases: all tools are fair game
        if current in (PipelinePhase.EXPLOIT, PipelinePhase.REPORT,
                       PipelinePhase.COMPLETE):
            return None

        config = DEFAULT_PHASES.get(current)
        if config and tool_name in config.recommended_tools:
            return None  # Explicitly recommended for this phase

        if tool_name in self._EXPLOIT_SPECIFIC_TOOLS:
            criteria_met = self._evaluate_criteria(current)
            total = len(config.transition_criteria) if config else 0
            return (
                f"[PHASE GUIDANCE] Tool '{tool_name}' is optimised for the EXPLOIT phase. "
                f"Current phase: {current.value} ({len(criteria_met)}/{total} transition criteria met). "
                "Proceed only if you have specific evidence justifying early exploitation. "
                "Otherwise, complete the current phase objectives first."
            )
        return None

    def get_tool_budget(self, phase: str, tool_name: str) -> int | None:
        """Return soft budget for tool_name in phase, or None if unconstrained."""
        return _PHASE_TOOL_BUDGETS.get(phase, {}).get(tool_name)

    def get_transition_prompt(self, new_phase: PipelinePhase) -> str:
        """Get a transition announcement prompt."""
        config = DEFAULT_PHASES.get(new_phase)
        if not config:
            return ""
        return (
            f"\n[PIPELINE TRANSITION → {new_phase.value}]\n"
            f"Phase objective: {config.objective}\n"
            "Use capabilities that maximize evidence quality for this phase.\n"
            f"You are now in the {new_phase.value} phase. Focus on the objective above.\n"
        )
