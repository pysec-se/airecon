from __future__ import annotations

import logging
import re
from typing import Any

from ..config import get_config
from .pipeline import PipelinePhase

logger = logging.getLogger("airecon.agent")


def _get_meaningful_evidence_threshold() -> float:
    return get_config().exploration_meaningful_evidence_threshold


class _ExplorationMixin:
    def _track_tool_usage(self, tool_name: str, arguments: dict | None = None) -> None:

        track_as = tool_name
        if self._ctf_mode and tool_name == "execute" and arguments:
            cmd = str(arguments.get("command", "")).strip()

            _ws_prefix = re.sub(r"^cd\s+\S+\s*&&\s*", "", cmd).strip()

            _binary = _ws_prefix.split()[0] if _ws_prefix else ""

            if _binary and _binary not in (
                "cd",
                "echo",
                "export",
                "source",
                ".",
                "for",
                "while",
                "if",
            ):
                track_as = _binary
        self._recent_tool_names.append(track_as)
        cfg = get_config()
        window = max(3, self._cfg_int(cfg, "agent_tool_diversity_window", 8))
        if len(self._recent_tool_names) > window:
            self._recent_tool_names = self._recent_tool_names[-window:]

    def _record_tool_to_memory(
        self,
        tool_name: str,
        success: bool,
        duration: float = 0.0,
        output_size: int = 0,
    ) -> None:
        """Record tool usage to cross-session memory for learning.

        This enables the agent to learn from experience across sessions:
        - Which tools work best for which targets
        - Historical success/failure rates
        - Average execution times
        """
        try:
            from ..memory import get_memory_manager

            target = ""
            if self._session:
                target = self._session.target or ""

            if target and tool_name not in (
                "create_file",
                "read_file",
                "list_files",
                "request_user_input",
            ):
                memory = get_memory_manager()
                memory.record_tool_usage(
                    tool_name=tool_name,
                    target=target,
                    success=success,
                    duration_sec=duration,
                    output_size=output_size,
                )
        except Exception as _e:
            pass

    def _get_same_tool_streak(self) -> int:
        if not self._recent_tool_names:
            return 0
        streak = 1
        last = self._recent_tool_names[-1]
        for tn in reversed(self._recent_tool_names[:-1]):
            if tn != last:
                break
            streak += 1
        return streak

    def _refresh_exploration_state(self) -> None:

        meaningful_now = sum(
            1
            for e in self.state.evidence_log
            if e.get("confidence", 0) >= _get_meaningful_evidence_threshold()
        )
        if meaningful_now > self._last_evidence_count:
            self._stagnation_iterations = 0
        else:
            self._stagnation_iterations += 1
        self._last_evidence_count = meaningful_now

    def _build_exploration_directive(self, phase: PipelinePhase) -> str:
        if getattr(self, "_scope_lock_active", False):
            return (
                "[SYSTEM: AGGRESSIVE EXPLORATION DISABLED — STRICT_SCOPE_MODE]\n"
                "User requested a focused scope. Do not broaden coverage beyond the explicit request."
            )

        cfg = get_config()
        if not self._cfg_bool(cfg, "agent_exploration_mode", True):
            return ""

        intensity = self._cfg_float(cfg, "agent_exploration_intensity", 0.8)
        stagnation_threshold = self._cfg_int(cfg, "agent_stagnation_threshold", 2)
        max_same_streak = self._cfg_int(cfg, "agent_max_same_tool_streak", 3)
        same_tool_streak = self._get_same_tool_streak()
        window = max(3, self._cfg_int(cfg, "agent_tool_diversity_window", 8))
        recent = self._recent_tool_names[-window:]
        unique_recent = len(set(recent)) if recent else 0

        is_stagnating = (
            self._stagnation_iterations >= stagnation_threshold
            or self._consecutive_failures >= 2
            or self._no_tool_iterations >= 1
            or same_tool_streak >= max_same_streak
        )

        is_creative_phase = phase in (PipelinePhase.ANALYSIS, PipelinePhase.EXPLOIT)

        if not is_stagnating and not is_creative_phase:
            return ""

        tactic_map: dict[PipelinePhase, list[str]] = {
            PipelinePhase.RECON: [
                "Breadth-first: map the FULL attack surface before going deep — subdomains, vhosts, port scan, then content discovery.",
                "Switch discovery families when stalled: passive OSINT → certificate transparency (crt.sh) → web archives → active probing → parameter mining.",
                "Certificate transparency logs reveal subdomains missed by brute-force. Check crt.sh or similar for '%.<target>' before active enumeration.",
                "Validate every discovered subdomain/host as live (httpx probe) before enumerating further — dead hosts waste iterations.",
                "No passive intelligence yet? Dork: site:<target> filetype:env OR inurl:config OR inurl:.git to find exposed configs.",
                "Crawl discovered endpoints for hidden paths, JS files, and API routes — automated crawlers find what directory brute-force misses.",
                "Check archived URLs (wayback, gau) for historical endpoints and parameters that may still be live.",
                "Fingerprint technologies precisely (headers, cookies, error pages, JS libs) — each tech narrows which exploit paths are viable.",
                "Enumerate ALL HTTP methods on interesting endpoints (OPTIONS, PUT, PATCH, DELETE) — unexpected methods are common misconfigs.",
                "Find API docs (swagger.json, openapi.yaml, /api/docs) — they reveal hidden endpoints and parameter names instantly.",
            ],
            PipelinePhase.ANALYSIS: [
                "MANUAL-FIRST: Do NOT start analysis with nuclei/nikto/sqlmap — these produce noise. "
                "Build one specific hypothesis first, then craft a targeted curl/python probe to test it.",
                "Think like an attacker, not a scanner: what does THIS application's unique logic enable? "
                "Misused trust, unexpected state transitions, privilege boundary leaks — these won't appear in scanner output.",
                "Baseline vs probe: send a benign request first, record the response, then send your mutated probe. "
                "The DIFF is the finding — not the response alone.",
                "Mutate parameters aggressively: encoding variants (URL, HTML, unicode), type confusion (string→int→array), boundary values.",
                "Correlate endpoints, auth flows, and object IDs for IDOR and privilege escalation — test same action with different user roles.",
                "Run parameter discovery on ALL confirmed endpoints — hidden params (X-Forwarded-For, debug=1, admin=true) are high-value.",
                "Mine proxy HTTP history for undocumented endpoints, auth token patterns, and IDOR candidates in response bodies.",
                "Test for reflected and stored XSS on every input field: HTML context, JS context, attribute context require different payloads.",
                "Check for SQL injection on every parameter: error-based first (quick confirmation), then blind boolean/time-based.",
                "Test SSRF on any URL-accepting parameter: internal metadata (169.254.169.254), localhost services, file:// protocol.",
                "Source code or repository accessible? Run static analysis — finds injection sinks and hardcoded secrets faster than manual testing.",
                "Generate at least one non-obvious hypothesis and test it — e.g., can parameter X influence server-side file path?",
                "If testing many variants (IDs/roles/encodings), write a script in tools/ to automate and log all results.",
            ],
            PipelinePhase.EXPLOIT: [
                "PROOF-OF-CONCEPT FIRST: do not rely on scanner output to confirm exploitability. "
                "Write a minimal Python/curl PoC that demonstrates the exact impact — data access, privilege change, or state modification.",
                "Rotate payload families every failed attempt — change the attack CLASS, not just the payload string.",
                "XSS: test all 3 contexts separately — HTML body (<img onerror>), attribute (\" onmouseover=), JavaScript (';alert//1).",
                "XSS: if WAF is blocking, try: case variation, HTML entity encoding, SVG vectors, DOM-based (location.hash, document.write).",
                "SQLi: if quotes are filtered, try: numeric injection, LIKE operator, comment variants (/**/, /*!...*/, %23 for #).",
                "SSRF: if direct IPs are blocked, try: decimal encoding (2130706433), octal (0177.0.0.1), IPv6 (::1), DNS rebinding.",
                "Auth bypass: try JWT alg:none, expired tokens, token for wrong user, admin=true hidden param, role ID manipulation.",
                "Chain medium findings: XSS + CSRF = account takeover; IDOR + info disclosure = full data breach.",
                "Prefer impact PROOF over scanner output: demonstrate state change, data access, or privilege escalation with concrete evidence.",
                "JavaScript-heavy target? Switch to browser automation for DOM-based XSS, OAuth flows, and client-side logic testing.",
                "When exploitation is multi-step, write a PoC script in tools/ instead of manual repetition.",
                "High-value complex finding? Spawn a specialist subagent for focused iterations.",
            ],
            PipelinePhase.REPORT: [
                "Convert strongest evidence into reproducible PoC steps with exact inputs, HTTP request/response, and expected output.",
                "Document what failed and why to avoid false positives in the report.",
            ],
            PipelinePhase.COMPLETE: [],
        }

        all_tactics = tactic_map.get(phase, [])
        if not all_tactics:
            return ""

        if is_stagnating:
            tactics = all_tactics[:7]
            pressure = "HIGH" if intensity >= 0.75 else "MEDIUM"
            lines = [
                f"[SYSTEM: AGGRESSIVE EXPLORATION MODE — {pressure}]",
                f"Phase={phase.value} | stagnation={self._stagnation_iterations} | "
                f"same_tool_streak={same_tool_streak} | diversity={unique_recent}/{max(1, len(recent))}",
                "You must avoid rigid repetitive behavior. Execute a novel, high-value next action now.",
                "Exploration tactics:",
            ]
        else:
            tactics = all_tactics[:3]
            lines = [
                f"[ANALYSIS GUIDANCE — Phase={phase.value}]",
                "Creative reasoning required. Prefer manual hypothesis testing over automated scanners.",
                "Tactics:",
            ]

        for tactic in tactics:
            lines.append(f"- {tactic}")

        if is_stagnating:
            if same_tool_streak >= max_same_streak:
                lines.append(
                    "[Suggestion]: Consider switching to a different tool family to break the current pattern."
                )
            if self._no_tool_iterations >= 1:
                lines.append("MANDATORY: reply with tool_call, not planning text.")
            lines.append(
                "Keep tests in-scope and non-destructive unless explicitly authorized."
            )

        # ── Self-Correcting Strategy Injection ─────────────────────────────
        strategy_hint = self._self_correcting_strategy(phase, recent, same_tool_streak)
        if strategy_hint:
            lines.append(f"\n[STRATEGY ADJUSTMENT] {strategy_hint}")

        return "\n".join(lines)

    @staticmethod
    def _load_recon_tools_from_meta() -> set[str]:
        """Load reconnaissance tool names from tools_meta.json data file."""
        import json
        from pathlib import Path
        try:
            meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
            if meta_path.exists():
                with open(meta_path) as f:
                    meta = json.load(f)
                recon = meta.get("categories", {}).get("reconnaissance", {})
                tools: set[str] = set()
                for subcat in recon.values():
                    if isinstance(subcat, list):
                        tools.update(subcat)
                # Agent-level recon tools (execute + browser are the wrappers)
                tools |= {"execute", "browser_action"}
                return tools
        except Exception as exc:
            logger.debug("Operation failed: %s", exc)
        # Fallback — minimal set
        return {
            "execute",
            "browser_action",
            "httpx",
            "subfinder",
            "assetfinder",
            "amass",
        }

    def _self_correcting_strategy(
        self,
        phase: PipelinePhase,
        recent_tools: list[str],
        same_tool_streak: int,
    ) -> str | None:
        """Detect stuck patterns and suggest strategic corrections."""
        if not recent_tools:
            return None

        # Detect: stuck on reconnaissance without moving to exploitation
        if phase == PipelinePhase.RECON:
            recon_tools = self._load_recon_tools_from_meta()
            recon_count = sum(1 for t in recent_tools if t in recon_tools)
            if recon_count >= len(recent_tools) * 0.8 and len(recent_tools) >= 5:
                hint = (
                    "You have been doing RECON for too long without transitioning. "
                    "You should have enough data now. Focus on ANALYSIS: pick the highest-value "
                    "discovered endpoint (admin panel, API, auth endpoint) and start testing it manually. "
                    "Do NOT run more subdomain enumeration or passive recon."
                )
                logger.info(
                    "[Strategy] RECON stagnation detected: %d/%d recon tools, suggesting transition to ANALYSIS",
                    recon_count,
                    len(recent_tools),
                )
                return hint

        # Detect: browser redirect loop trap
        browser_errors = sum(1 for t in recent_tools if t == "browser_action")
        if browser_errors >= 3 and same_tool_streak >= 2:
            hint = (
                "Browser actions are failing repeatedly — likely hitting tracking pixels or redirect loops. "
                "STOP using browser_action. Switch to command-line tools (curl, httpx, ffuf) for HTTP testing. "
                "Browser is only useful for JavaScript-heavy targets with interactive flows."
            )
            logger.info(
                "[Strategy] Browser redirect loop detected: %d browser_action errors, streak=%d",
                browser_errors,
                same_tool_streak,
            )
            return hint

        # Detect: fuzzing blog/content pages instead of real targets
        if phase in (PipelinePhase.RECON, PipelinePhase.ANALYSIS):
            fuzz_count = sum(1 for t in recent_tools if "fuzz" in t)
            if fuzz_count >= 3:
                hint = (
                    "Multiple fuzzing attempts with no findings — you may be fuzzing the wrong targets. "
                    "Stop fuzzing blog URLs, tracking pixels, or content pages. "
                    "Focus on: admin panels, API endpoints, authentication flows, file upload endpoints, "
                    "and any endpoint with user input parameters. Quality over quantity."
                )
                logger.info(
                    "[Strategy] Fuzzing stagnation: %d fuzz attempts with no findings, suggesting target refocus",
                    fuzz_count,
                )
                return hint

        # Detect: tool repetition without progress
        if same_tool_streak >= 3:
            hint = (
                f"You've used the same tool {same_tool_streak} times in a row without new findings. "
                "This pattern is not working. Switch to a completely different approach: "
                "if you were using scanners, switch to manual testing. If manual, try automation. "
                "If HTTP testing, try source code analysis. If passive, try active."
            )
            logger.info(
                "[Strategy] Tool repetition detected: same tool used %d times consecutively",
                same_tool_streak,
            )
            return hint

        return None

    def _record_adaptive_learning(
        self,
        tool_name: str,
        arguments: dict,
        result: dict,
        success: bool,
        duration: float,
        phase: str,
    ) -> None:
        """Record tool result to adaptive learning engine for reinforcement feedback."""
        try:
            cfg = get_config()
            if (
                not cfg.intelligence_enabled
                or not cfg.intelligence_adaptive_learning_enabled
            ):
                return

            # Determine session context
            session_target = ""
            session_id = ""
            session_techs: dict[str, str] = {}
            session_vulns: list[dict] = []
            if hasattr(self, "_session") and self._session:
                session_target = getattr(self._session, "target", "")
                session_id = getattr(self._session, "session_id", "")
                session_techs = getattr(self._session, "technologies", {})
                session_vulns = getattr(self._session, "vulnerabilities", [])

            # Lazy init the learning engine — persistent across sessions
            if not hasattr(self, "_adaptive_learning_engine"):
                from .adaptive_learning import AdaptiveLearningEngine

                self._adaptive_learning_engine = AdaptiveLearningEngine(
                    min_observations=cfg.intelligence_adaptive_min_observations,
                    session_id=session_id or "",
                )
                logger.info(
                    "[AdaptiveLearning] Engine initialized (session=%s, observations=%d)",
                    session_id or "new",
                    len(self._adaptive_learning_engine.observation_log),
                )

            engine = self._adaptive_learning_engine

            # Record per-target intelligence (endpoints, vulns, params, bypasses)
            self._record_target_memory(tool_name, arguments, result, success)

            # Extract confidence from result
            confidence = 0.0
            if isinstance(result, dict):
                confidence = float(result.get("confidence", 0.0))
                if not confidence and "findings" in result:
                    findings = result["findings"]
                    if isinstance(findings, list) and findings:
                        confidence = float(findings[0].get("confidence", 0.0))

            # Determine target type from tech stack
            tech_summary = ", ".join(session_techs.keys()) if session_techs else ""

            # Build context
            context = {"phase": phase}
            for tech_name in session_techs:
                context[f"tech={tech_name}"] = "detected"

            engine.record_tool_result(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                success=success,
                duration=duration,
                confidence=confidence,
                context=context,
                target_type=tech_summary or session_target,
            )

            # Also log observation for LLM abstraction layer
            result_summary = ""
            if isinstance(result, dict):
                # Compress findings to a short summary
                findings = result.get("findings", result.get("output", ""))
                if isinstance(findings, list) and findings:
                    result_summary = str(findings[0])[:300]
                elif findings:
                    result_summary = str(findings)[:300]
                # Check for discovered vulnerabilities
                vuln_found = None
                if success and isinstance(result.get("findings"), list) and result["findings"]:
                    for f in result["findings"]:
                        if isinstance(f, dict) and f.get("finding"):
                            vuln_found = str(f["finding"])[:200]
                            break
                if not vuln_found and hasattr(self, "_session") and self._session:
                    # Check if a new vuln was added this iteration
                    cur_count = len(session_vulns)
                    prev_count = getattr(self, "_vuln_count_last_learn", 0)
                    if cur_count > prev_count:
                        self._vuln_count_last_learn = cur_count
                        last_vuln = session_vulns[-1]
                        if isinstance(last_vuln, dict):
                            vuln_found = last_vuln.get("title", last_vuln.get("finding", ""))[:200]
            engine.record_observation(
                tool_name=tool_name,
                arguments=arguments,
                result_summary=result_summary,
                success=success,
                confidence=confidence,
                phase=phase,
                target_type=tech_summary or session_target,
                vuln_found=vuln_found,
            )

            # Periodic save (every 10 observations)
            if len(engine.observation_log) % 10 == 0:
                engine.save_state()

            # Periodic insight distillation every 30 observations
            if len(engine.observation_log) > 0 and len(engine.observation_log) % 30 == 0:
                insights = engine.distill_insights(
                    ollama_url=cfg.ollama_url,
                    model=cfg.ollama_model,
                )
                if insights:
                    logger.info(
                        "[AdaptiveLearning] Distilled %d new insights from %d observations",
                        len(insights),
                        len(engine.observation_log),
                    )

            logger.debug(
                "[AdaptiveLearning] Recorded: tool=%s success=%s duration=%.2fs phase=%s observations=%d",
                tool_name,
                success,
                duration,
                phase,
                len(engine.observation_log),
            )
        except Exception as exc:
            logger.debug("Operation failed: %s", exc)

    def _record_target_memory(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict,
        success: bool,
    ) -> None:
        """Record actionable intelligence to per-target memory.

        Captures: endpoints, vulns, WAF bypasses, sensitive params.
        """
        target = ""
        if self._session:
            target = getattr(self._session, "target", "")
        if not target:
            return

        # Lazy-init target memory store
        if not hasattr(self, "_target_memory_store"):
            from .adaptive_learning import TargetMemoryStore
            self._target_memory_store = TargetMemoryStore()

        store = self._target_memory_store

        # Record tech stack
        if self._session:
            techs = getattr(self._session, "technologies", {})
            for tech_name in techs:
                store.record_tech(target, tech_name)

        # Record endpoints from tool output
        if isinstance(result, dict):
            # Endpoints from httpx, katana, nmap, etc.
            for key in ("endpoints", "urls", "paths", "routes"):
                endpoints = result.get(key, [])
                if isinstance(endpoints, list):
                    for ep in endpoints[:50]:
                        store.record_endpoint(target, str(ep))

            # Sensitive parameters from results
            params = result.get("parameters", result.get("params", []))
            if isinstance(params, list):
                for p in params:
                    store.record_param(target, str(p))

        # Record vulns with payloads
        if self._session:
            cur_count = len(getattr(self._session, "vulnerabilities", []))
            prev_count = getattr(self, "_vuln_count_last_target_mem", 0)
            if cur_count > prev_count:
                self._vuln_count_last_target_mem = cur_count
                last_vuln = self._session.vulnerabilities[-1]
                if isinstance(last_vuln, dict):

                    vuln_entry = {
                        "type": last_vuln.get("type", last_vuln.get("finding", "unknown")),
                        "path": last_vuln.get("endpoint", last_vuln.get("url", "")),
                        "param": last_vuln.get("parameter", ""),
                        "payload": last_vuln.get("payload", ""),
                        "severity": last_vuln.get("severity", ""),
                        "confirmed": "true" if last_vuln.get("confirmed") else "false",
                    }
                    store.record_vulnerability(target, vuln_entry)

        # Record auth endpoints
        if tool_name in ("browser_action", "http_observe", "execute"):
            cmd_or_url = str(arguments.get("command", arguments.get("url", ""))).lower()
            if any(kw in cmd_or_url for kw in ("login", "auth", "token", "session", "register", "password")):
                path = arguments.get("url", "")
                if path:
                    store.record_auth_endpoint(target, str(path))

        # Save periodically (not every call — too expensive)
        if getattr(self, "_target_mem_save_counter", 0) % 15 == 0:
            # Save all loaded target memories
            for norm, tm in store._cache.items():
                store.save(norm, tm)
        self._target_mem_save_counter = getattr(self, "_target_mem_save_counter", 0) + 1
