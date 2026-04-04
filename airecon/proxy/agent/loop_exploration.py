from __future__ import annotations

import re

from ..config import get_config
from .pipeline import PipelinePhase

_MEANINGFUL_EVIDENCE_THRESHOLD: float = 0.65

class _ExplorationMixin:
    def _track_tool_usage(
        self, tool_name: str, arguments: dict | None = None
    ) -> None:

        track_as = tool_name
        if self._ctf_mode and tool_name == "execute" and arguments:
            cmd = str(arguments.get("command", "")).strip()

            _ws_prefix = re.sub(r"^cd\s+\S+\s*&&\s*", "", cmd).strip()

            _binary = _ws_prefix.split()[0] if _ws_prefix else ""

            if _binary and _binary not in ("cd", "echo", "export", "source", ".", "for", "while", "if"):
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

            if target and tool_name not in ("create_file", "read_file", "list_files", "request_user_input"):
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
            1 for e in self.state.evidence_log
            if e.get("confidence", 0) >= _MEANINGFUL_EVIDENCE_THRESHOLD
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
        return "\n".join(lines)
