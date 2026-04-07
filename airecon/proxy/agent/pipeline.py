from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any
import os
import random
from dataclasses import dataclass, field
from enum import Enum

from ..config import get_config as _get_config
from ..data_loader import load_tools_meta

logger = logging.getLogger("airecon.agent.pipeline")

_PROMPTS_DIR = Path(__file__).parent.parent / "prompts" / "phases"

_TOOLS_META = load_tools_meta()
_RECON_HINTS: dict[str, str] = _TOOLS_META.get("recon_phase_hints", {})
_ANALYSIS_HINTS: list[str] = _TOOLS_META.get("analysis_phase_hints", [])

_LIVE_HOST_HINT: str = _RECON_HINTS.get(
    "live_host_validation",
    "CRITICAL: After subdomain enumeration, ALWAYS validate which hosts are alive before "
    "port scanning or directory brute-force. Use host probing tools to filter dead/unresolved hosts. "
    "Never scan dead hosts.",
)


class PipelinePhase(Enum):
    RECON = "RECON"
    ANALYSIS = "ANALYSIS"
    EXPLOIT = "EXPLOIT"
    REPORT = "REPORT"
    COMPLETE = "COMPLETE"


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
    phase: PipelinePhase
    max_iterations: int
    objective: str
    recommended_tools: list[str] = field(default_factory=list)
    transition_criteria: list[str] = field(default_factory=list)

    exploration_hints: list[str] = field(default_factory=list)


DEFAULT_PHASES: dict[PipelinePhase, PhaseConfig] = {
    PipelinePhase.RECON: PhaseConfig(
        phase=PipelinePhase.RECON,
        max_iterations=_get_config().pipeline_recon_max_iterations,
        objective=(
            "Understand the target deeply — choose the recon approach best suited to this "
            "specific target. Prioritise breadth initially; pivot to unusual entry points "
            "if standard paths yield nothing. " + _LIVE_HOST_HINT
        ),
        recommended_tools=[
            "execute",
            "web_search",
            "browser_action",
            "create_file",
            "read_file",
            "list_files",
            "caido_set_scope",
            "caido_sitemap",
            "caido_list_requests",
        ],
        transition_criteria=[
            "subdomains_discovered",
            "live_hosts_validated",
            "ports_scanned",
            "recon_artifacts_saved",
            "subdomain_depth_met",
            "url_discovery_met",
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
        max_iterations=_get_config().pipeline_analysis_max_iterations,
        objective=(
            "Identify exploitable weaknesses — go beyond standard injection points. "
            "Look for logic flaws, misconfigured access controls, trust boundary violations, "
            "and technology-specific vulnerabilities based on the identified stack."
        ),
        recommended_tools=[
            "execute",
            "browser_action",
            "code_analysis",
            "web_search",
            "read_file",
            "create_file",
            "caido_list_requests",
            "caido_send_request",
            "caido_sitemap",
        ],
        transition_criteria=[
            "urls_collected",
            "technologies_identified",
            "injection_points_found",
        ],
        exploration_hints=_ANALYSIS_HINTS,
    ),
    PipelinePhase.EXPLOIT: PhaseConfig(
        phase=PipelinePhase.EXPLOIT,
        max_iterations=_get_config().pipeline_exploit_max_iterations,
        objective="Test and exploit vulnerabilities: fuzzing, injection testing, authentication bypass",
        recommended_tools=[
            "execute",
            "quick_fuzz",
            "advanced_fuzz",
            "deep_fuzz",
            "browser_action",
            "spawn_agent",
            "caido_send_request",
            "caido_automate",
            "caido_list_requests",
            "caido_get_findings",
            "schemathesis_fuzz",
            "create_vulnerability_report",
        ],
        transition_criteria=[
            "vulnerabilities_tested",
        ],
    ),
    PipelinePhase.REPORT: PhaseConfig(
        phase=PipelinePhase.REPORT,
        max_iterations=_get_config().pipeline_report_max_iterations,
        objective="Generate final report: document all findings with PoC, CVSS, and remediation",
        recommended_tools=[
            "create_vulnerability_report",
            "create_file",
            "read_file",
        ],
        transition_criteria=[
            "reports_generated",
        ],
    ),
}

_PHASE_TOOL_BUDGETS: dict[str, dict[str, int]] = {
    "RECON": {
        "quick_fuzz": _get_config().pipeline_recon_budget,
        "advanced_fuzz": 5,
        "deep_fuzz": 0,
        "caido_automate": 5,
        "create_vulnerability_report": 2,
    },
    "ANALYSIS": {
        "advanced_fuzz": _get_config().pipeline_analysis_budget,
        "deep_fuzz": 5,
        "create_vulnerability_report": 5,
    },
    "EXPLOIT": {
        "advanced_fuzz": 50,
        "deep_fuzz": 25,
        "quick_fuzz": _get_config().pipeline_exploit_budget,
        "caido_automate": 40,
    },
    "REPORT": {
        "execute": _get_config().pipeline_report_budget,
        "advanced_fuzz": 2,
        "deep_fuzz": 1,
        "quick_fuzz": 2,
    },
}

_TOOL_ADVISORY_LEVELS: dict[str, dict[str, str]] = {
    "RECON": {
        "quick_fuzz": "courageous",
        "advanced_fuzz": "useful",
        "deep_fuzz": "courageous",
        "caido_automate": "optional",
        "create_vulnerability_report": "premature",
    },
    "ANALYSIS": {
        "quick_fuzz": "optional",
        "advanced_fuzz": "optimal",
        "deep_fuzz": "useful",
        "caido_automate": "useful",
        "create_vulnerability_report": "premature",
    },
    "EXPLOIT": {
        "quick_fuzz": "optimal",
        "advanced_fuzz": "optimal",
        "deep_fuzz": "useful",
        "caido_automate": "useful",
        "create_vulnerability_report": "optimal",
    },
    "REPORT": {
        "execute": "optimal",
        "create_vulnerability_report": "optimal",
        "advanced_fuzz": "validation",
        "deep_fuzz": "validation",
        "quick_fuzz": "validation",
    },
}

_PHASE_SKILL_HINTS: dict[str, str] = {
    "RECON": "Phase skills: reconnaissance/, protocols/, tools/",
    "ANALYSIS": "Phase skills: vulnerabilities/, frameworks/, technologies/, protocols/",
    "EXPLOIT": "Phase skills: payloads/, vulnerabilities/, postexploit/, frameworks/",
    "REPORT": "Phase skills: reporting/, vulnerabilities/, remediation/",
}


class PipelineEngine:
    MIN_ITERATIONS_PER_PHASE = 10

    def __init__(self, session: Any, config: Any = None) -> None:
        self.session = session
        self._phase_prompts: dict[PipelinePhase, str] = {}
        self._phase_entry_iteration: int = 0
        self._current_iteration: int = 0
        self._ctf_mode: bool = False

        cfg = config if config is not None else _get_config()
        self._recon_min_subdomains: int = getattr(
            cfg, "pipeline_recon_min_subdomains", 3
        )
        self._recon_min_urls: int = getattr(cfg, "pipeline_recon_min_urls", 1)
        self._recon_soft_timeout: int = getattr(cfg, "pipeline_recon_soft_timeout", 30)

        self._recon_hard_timeout: int = getattr(
            cfg, "pipeline_recon_hard_timeout", self._recon_soft_timeout * 2
        )

        # Stagnation escape: max iterations per phase before forced transition
        self._exploit_max_iterations: int = getattr(
            cfg, "pipeline_exploit_max_iterations", 800
        )
        self._analysis_max_iterations: int = getattr(
            cfg, "pipeline_analysis_max_iterations", 300
        )
        self._recon_max_iterations: int = getattr(
            cfg, "pipeline_recon_max_iterations", 500
        )

        # Track vuln count at phase entry to detect stagnation (no new vulns)
        self._phase_vuln_baseline: int = 0

        self._load_phase_prompts()

    def _load_phase_prompts(self) -> None:
        for phase in PipelinePhase:
            if phase == PipelinePhase.COMPLETE:
                continue
            prompt_file = _PROMPTS_DIR / f"{phase.value.lower()}.txt"
            try:
                if prompt_file.exists():
                    self._phase_prompts[phase] = prompt_file.read_text(encoding="utf-8")
                else:
                    self._phase_prompts[phase] = self._default_prompt(phase)
            except Exception as e:
                logger.warning("Failed to load phase prompt for %s: %s", phase.value, e)
                self._phase_prompts[phase] = self._default_prompt(phase)

    def _default_prompt(self, phase: PipelinePhase) -> str:
        config = DEFAULT_PHASES.get(phase)
        if not config:
            return ""
        return (
            f"[PIPELINE PHASE: {phase.value}]\n"
            f"Objective: {config.objective}\n"
            "Use the most suitable available capabilities for this phase objective.\n"
            "Complete this phase thoroughly before moving to the next."
        )

    def get_current_phase(self) -> PipelinePhase:
        phase_str = getattr(self.session, "current_phase", "RECON")
        try:
            return PipelinePhase(phase_str)
        except ValueError:
            return PipelinePhase.RECON

    def set_phase(self, phase: PipelinePhase) -> None:
        self.session.current_phase = phase.value
        self._phase_entry_iteration = self._current_iteration
        logger.info("Pipeline phase set to: %s", phase.value)

    def set_ctf_mode(self, enabled: bool = True) -> None:
        self._ctf_mode = enabled
        if enabled:
            current = self.get_current_phase()
            if current == PipelinePhase.RECON:
                self.set_phase(PipelinePhase.EXPLOIT)
            logger.info("Pipeline CTF mode enabled — skipped to EXPLOIT phase")

    def should_transition(self) -> bool:
        """Determine if phase transition is ready. Uses SOFT gates, not hard blocks."""
        if self._ctf_mode:
            logger.debug("[Pipeline] CTF mode — blocking transition")
            return False

        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            logger.debug("[Pipeline] Phase COMPLETE — blocking transition")
            return False

        config = DEFAULT_PHASES.get(current)
        if not config:
            logger.debug(
                "[Pipeline] No config for phase %s — blocking transition", current.value
            )
            return False

        iterations_in_phase = self._current_iteration - self._phase_entry_iteration

        # Dynamic minimum: based on evidence collected, not just iteration count
        min_iterations = self._calculate_dynamic_min_iterations(
            current, iterations_in_phase
        )
        if iterations_in_phase < min_iterations:
            logger.debug(
                "[Pipeline] Phase %s: %d iterations < dynamic min %d (based on evidence collected) — continue",
                current.value,
                iterations_in_phase,
                min_iterations,
            )
            return False

        # Hard cap: prevent infinite loops
        MAX_PHASE_ITERATIONS = 350
        if iterations_in_phase > MAX_PHASE_ITERATIONS:
            logger.warning(
                "Phase %s has run for %d iterations (limit=%d) - forcing transition to prevent stagnation",
                current.value,
                iterations_in_phase,
                MAX_PHASE_ITERATIONS,
            )
            return True

        # Phase-specific transition logic (soft gates)
        if current == PipelinePhase.RECON:
            met_criteria = self._evaluate_criteria(current)
            has_any_data = bool(
                getattr(self.session, "urls", [])
                or getattr(self.session, "open_ports", {})
                or getattr(self.session, "subdomains", [])
                or getattr(self.session, "live_hosts", [])
            )

            # Check soft timeout: suggest transition but allow override
            if iterations_in_phase >= self._recon_soft_timeout:
                if has_any_data:
                    # Mandatory check: live_hosts_validated must be met to transition early
                    if "live_hosts_validated" in met_criteria:
                        logger.info(
                            "RECON soft timeout (%d iter) reached with data and mandatory met. Transitioning.",
                            iterations_in_phase,
                        )
                        return True
                    else:
                        # Missing mandatory (e.g., live hosts); may continue until hard timeout
                        if iterations_in_phase >= self._recon_hard_timeout:
                            logger.warning(
                                "RECON hard timeout (%d iter) with data but mandatory not met. Forcing transition.",
                                iterations_in_phase,
                            )
                            return True
                        logger.info(
                            "RECON soft timeout reached with data but mandatory not met; continuing exploration."
                        )
                        return False
                else:
                    # No data at all — force transition after soft timeout
                    logger.info(
                        "RECON soft timeout (%d iter) with no data; forcing transition.",
                        iterations_in_phase,
                    )
                    return True

            # Flexible criteria: need ANY 2+ strong signals (was: need 3)
            has_subs = "subdomains_discovered" in met_criteria
            has_live = "live_hosts_validated" in met_criteria
            has_urls = "url_discovery_met" in met_criteria
            has_ports = "ports_scanned" in met_criteria
            has_artifacts = "recon_artifacts_saved" in met_criteria

            strong_signals = sum(
                [has_subs, has_live, has_urls, has_ports, has_artifacts]
            )
            if strong_signals >= 2:
                logger.info(
                    "RECON: %d strong signals found (subdomains=%s, live_hosts=%s, urls=%s, ports=%s, artifacts=%s) — ready to transition",
                    strong_signals,
                    has_subs,
                    has_live,
                    has_urls,
                    has_ports,
                    has_artifacts,
                )
                return True
            else:
                logger.debug(
                    "[Pipeline] RECON: only %d strong signals (need ≥2) — continue discovery",
                    strong_signals,
                )
                return False

        # For other phases: use confidence threshold (softer than before)
        met_criteria = self._evaluate_criteria(current)
        total = len(config.transition_criteria)
        coverage = len(met_criteria) / max(1, total) if total > 0 else 0

        logger.debug(
            "[Pipeline] Phase %s evaluation: coverage=%.0%% (met=%d/%d)",
            current.value,
            coverage * 100,
            len(met_criteria),
            total,
        )

        # Lower confidence threshold (was 0.55-0.60, now 0.50-0.55)
        confidence = self._phase_transition_confidence(
            current,
            met_criteria=met_criteria,
            total_criteria=total,
            iterations_in_phase=iterations_in_phase,
        )
        threshold = _PHASE_CONFIDENCE_THRESHOLDS.get(current, 0.50)
        decision = confidence >= threshold

        logger.info(
            "[Pipeline] %s transition: confidence=%.2f threshold=%.2f → %s",
            current.value,
            confidence,
            threshold,
            "ALLOW" if decision else "CONTINUE",
        )
        return decision

    def _calculate_dynamic_min_iterations(
        self, phase: PipelinePhase, current_iterations: int
    ) -> int:
        """Calculate minimum iterations based on evidence collected, not just time."""
        if phase == PipelinePhase.RECON:
            # If we have some data, min 10 iter (cooldown); if nothing, min 20 iter
            has_data = bool(
                getattr(self.session, "urls", [])
                or getattr(self.session, "open_ports", {})
                or getattr(self.session, "subdomains", [])
            )
            return 10 if has_data else 20
        elif phase == PipelinePhase.ANALYSIS:
            # Min 3 iterations to analyze
            return 3
        elif phase == PipelinePhase.EXPLOIT:
            # Min 2 iterations
            return 2
        return 5

    def _phase_transition_confidence(
        self,
        phase: PipelinePhase,
        *,
        met_criteria: list[str],
        total_criteria: int,
        iterations_in_phase: int,
    ) -> float:
        if total_criteria <= 0:
            return 0.0
        coverage = len(met_criteria) / max(1, total_criteria)
        maturity = min(1.0, iterations_in_phase / max(1, self.MIN_ITERATIONS_PER_PHASE))
        evidence_quality, consistency_penalty = self._phase_causal_signals(phase)

        base = coverage * (0.55 + (0.25 * evidence_quality) + (0.20 * maturity))
        confidence = (
            base + (evidence_quality * 0.25) + (maturity * 0.08) - consistency_penalty
        )
        result = round(min(1.0, max(0.0, confidence)), 3)
        logger.debug(
            "[Pipeline] Confidence calc: phase=%s coverage=%.2f maturity=%.2f "
            "evidence_quality=%.2f penalty=%.2f base=%.2f → %.3",
            phase.value,
            coverage,
            maturity,
            evidence_quality,
            consistency_penalty,
            base,
            result,
        )
        return result

    @staticmethod
    def _vulnerability_severity(vuln: dict[str, Any]) -> str:
        sev = str(vuln.get("severity", "")).strip().upper()
        if sev in {"1", "2", "3", "4", "5"}:
            return {
                "1": "INFO",
                "2": "LOW",
                "3": "MEDIUM",
                "4": "HIGH",
                "5": "CRITICAL",
            }[sev]
        if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            return sev
        finding = str(vuln.get("finding", "")).upper()
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if f"[{label}]" in finding:
                return label
        return "MEDIUM"

    def _phase_causal_signals(self, phase: PipelinePhase) -> tuple[float, float]:
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

            injection_density = min(
                1.0, inj_points / max(1, min(20, urls if urls > 0 else 4))
            )
            tech_context = min(1.0, tech_count / 6)
            vuln_signal = min(
                1.0, vuln_count / max(1, inj_points if inj_points > 0 else 3)
            )

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
                if bool(
                    vuln.get("report_generated")
                    or vuln.get("replay_verified")
                    or vuln.get("verified")
                ):
                    confirmed += 1
                if bool(
                    vuln.get("proo")
                    or vuln.get("evidence")
                    or vuln.get("poc_script_code")
                ):
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
                (report_ratio * 0.40) + (replay_ratio * 0.40) + (technical_ratio * 0.20)
            )
            return quality, min(0.35, penalty)

        return 0.0, 0.0

    def get_phase_transition_confidence(self) -> float:
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
        met: list[str] = []
        session = self.session

        if phase == PipelinePhase.RECON:
            if getattr(session, "subdomains", []):
                met.append("subdomains_discovered")

            if getattr(session, "live_hosts", []):
                met.append("live_hosts_validated")
            if getattr(session, "open_ports", {}):
                met.append("ports_scanned")

            _recon_extensions = {
                ".txt",
                ".out",
                ".nmap",
                ".csv",
                ".json",
                ".xml",
                ".html",
                ".log",
            }
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

            _scan_count = 0
            try:
                _scan_count = int(getattr(session, "scan_count", 0) or 0)
            except Exception as e:
                logger.warning("Operation failed: %s", e)
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

            if len(getattr(session, "subdomains", [])) >= self._recon_min_subdomains:
                met.append("subdomain_depth_met")
            if len(getattr(session, "urls", [])) >= self._recon_min_urls:
                met.append("url_discovery_met")

            logger.debug(
                "[Pipeline] RECON criteria evaluation: met=%s total=%d",
                met,
                len(DEFAULT_PHASES[PipelinePhase.RECON].transition_criteria),
            )

        elif phase == PipelinePhase.ANALYSIS:
            if getattr(session, "urls", []):
                met.append("urls_collected")
            if getattr(session, "technologies", {}):
                met.append("technologies_identified")

            _MEANINGFUL_TYPES = frozenset(
                {
                    "IDOR",
                    "SSRF",
                    "PATH_TRAVERSAL",
                    "SQLi",
                    "XSS",
                    "AUTH",
                    "BUSINESS_LOGIC",
                    "RCE",
                }
            )
            _ips = getattr(session, "injection_points", [])
            _has_meaningful = any(p.get("type_hint") in _MEANINGFUL_TYPES for p in _ips)
            if len(_ips) >= 3 or _has_meaningful:
                met.append("injection_points_found")

            logger.debug(
                "[Pipeline] ANALYSIS criteria evaluation: met=%s total=%d",
                met,
                len(DEFAULT_PHASES[PipelinePhase.ANALYSIS].transition_criteria),
            )

        elif phase == PipelinePhase.EXPLOIT:
            vulns = getattr(session, "vulnerabilities", [])

            _SIGNIFICANT_SEV_RE = re.compile(
                r"^\[(CRITICAL|HIGH|MEDIUM)\]", re.IGNORECASE
            )
            _confirmed = any(v.get("report_generated") for v in vulns)
            _has_significant = any(
                _SIGNIFICANT_SEV_RE.match(str(v.get("finding", ""))) for v in vulns
            )
            if _confirmed or _has_significant:
                met.append("vulnerabilities_tested")

        elif phase == PipelinePhase.REPORT:
            vulns = getattr(session, "vulnerabilities", [])
            if any(v.get("report_generated") for v in vulns):
                met.append("reports_generated")

        return met

    def transition(self) -> PipelinePhase | None:
        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return None

        iterations_in_phase = self._current_iteration - self._phase_entry_iteration
        current_vulns = len(getattr(self.session, "vulnerabilities", []))

        # ── Stagnation escape: force transition when iterations exhausted ──
        _stagnation_max = {
            PipelinePhase.RECON: self._recon_max_iterations,
            PipelinePhase.ANALYSIS: self._analysis_max_iterations,
            PipelinePhase.EXPLOIT: self._exploit_max_iterations,
        }.get(current, 999999)
        _stagnation_trigger = iterations_in_phase >= _stagnation_max

        # Also trigger if no new vulns appeared in last 30 iterations
        if current == PipelinePhase.EXPLOIT and not _stagnation_trigger:
            _vuln_new = current_vulns - self._phase_vuln_baseline
            if iterations_in_phase >= 30 and _vuln_new <= 0:
                _stagnation_trigger = True
                logger.info(
                    "[Pipeline] EXPLOIT stagnation: %d iters, no new vulns "
                    "(baseline=%d, current=%d) — forcing transition",
                    iterations_in_phase,
                    self._phase_vuln_baseline,
                    current_vulns,
                )

        _soft_timeout_bypass = (
            current == PipelinePhase.RECON
            and iterations_in_phase >= self._recon_soft_timeout
        )

        if (
            not _soft_timeout_bypass
            and not _stagnation_trigger
            and not self.should_transition()
        ):
            logger.warning(
                "Attempted transition from %s without meeting confidence/criteria gate",
                current.value,
            )
            return current

        if _stagnation_trigger and not _soft_timeout_bypass:
            logger.info(
                "[Pipeline] Phase %s stagnation escape activated (iters=%d, max=%d) — "
                "allowing transition despite unmet criteria",
                current.value,
                iterations_in_phase,
                _stagnation_max,
            )

        if current.value not in self.session.completed_phases:
            self.session.completed_phases.append(current.value)

        idx = _PHASE_ORDER.index(current)
        if idx + 1 >= len(_PHASE_ORDER):
            self.set_phase(PipelinePhase.COMPLETE)
            return PipelinePhase.COMPLETE

        next_phase = _PHASE_ORDER[idx + 1]
        self._phase_vuln_baseline = current_vulns
        self.set_phase(next_phase)

        self._phase_entry_iteration = self._current_iteration
        logger.info("Pipeline transition: %s → %s", current.value, next_phase.value)
        return next_phase

    def get_phase_prompt(self) -> str:
        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return "[PIPELINE: ALL PHASES COMPLETE] — Target fully tested."

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

        met = self._evaluate_criteria(current)
        total_criteria = len(config.transition_criteria) if config else 0
        confidence = self.get_phase_transition_confidence()
        progress = (
            f"Progress: {len(met)}/{total_criteria} criteria met"
            f" | transition_confidence={confidence:.0%}"
        )

        completed = (
            ", ".join(self.session.completed_phases)
            if self.session.completed_phases
            else "none"
        )

        skill_hint = _PHASE_SKILL_HINTS.get(current.value, "")
        skill_line = f"\n{skill_hint}" if skill_hint else ""

        exploration_line = ""
        if config and config.exploration_hints:
            # Show up to 5 hints for broader exploration options (was: 2 random)
            num_hints = min(5, len(config.exploration_hints))
            sampled = random.sample(config.exploration_hints, num_hints)
            hints_str = "\n".join(f"  • {h}" for h in sampled)
            exploration_line = f"\nEXPLORATION ANGLES (pick one unconventional angle you haven't tried):\n{hints_str}"

        return (
            f"{base_prompt}\n\n"
            f"Completed phases: {completed}\n"
            f"{progress}"
            f"{skill_line}"
            f"{exploration_line}"
        )

    _EXPLOIT_SPECIFIC_TOOLS = frozenset(
        {
            "quick_fuzz",
            "advanced_fuzz",
            "deep_fuzz",
            "caido_automate",
            "schemathesis_fuzz",
            "create_vulnerability_report",
        }
    )

    def get_tool_advisory(self, tool_name: str) -> str | None:
        """Get advisory level for tool in current phase (not blocking, just guidance)."""
        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return None
        advisory_map = _TOOL_ADVISORY_LEVELS.get(current.value, {})
        return advisory_map.get(tool_name)

    def check_tool_phase_fit(self, tool_name: str) -> str | None:
        """Non-blocking advisory hint — never blocks tool execution."""
        current = self.get_current_phase()

        if current in (
            PipelinePhase.EXPLOIT,
            PipelinePhase.REPORT,
            PipelinePhase.COMPLETE,
        ):
            return None

        advisory = self.get_tool_advisory(tool_name)
        if advisory is None or advisory == "optimal":
            return None

        config = DEFAULT_PHASES.get(current)
        criteria_met = self._evaluate_criteria(current)
        total = len(config.transition_criteria) if config else 0

        messages = {
            "courageous": (
                f"[ADVISORY] Tool '{tool_name}' is unconventional for {current.value} phase "
                f"({len(criteria_met)}/{total} criteria met). This is **allowed** if you have specific "
                "evidence justifying it — proceed if you have a hypothesis to test."
            ),
            "validation": (
                f"[ADVISORY] Tool '{tool_name}' is for validation/verification in {current.value} phase. "
                "Use only if confirming an existing finding, not exploring new areas."
            ),
            "premature": (
                f"[ADVISORY] Tool '{tool_name}' is premature for {current.value} phase. "
                "Complete current phase discovery first, but override if you must."
            ),
            "optional": (
                f"[ADVISORY] Tool '{tool_name}' is optional context in {current.value} phase. "
                "Consider more direct tools first, but this is available."
            ),
            "useful": (
                f"[ADVISORY] Tool '{tool_name}' provides useful context in {current.value} phase. "
                "Worth trying as a secondary option."
            ),
        }

        return messages.get(advisory)

    def get_tool_budget(self, phase: str, tool_name: str) -> int | None:
        return _PHASE_TOOL_BUDGETS.get(phase, {}).get(tool_name)

    def get_transition_prompt(self, new_phase: PipelinePhase) -> str:
        config = DEFAULT_PHASES.get(new_phase)
        if not config:
            return ""
        return (
            f"\n[PIPELINE TRANSITION → {new_phase.value}]\n"
            f"Phase objective: {config.objective}\n"
            "Use capabilities that maximize evidence quality for this phase.\n"
            f"You are now in the {new_phase.value} phase. Focus on the objective above.\n"
        )
