from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

from .models import ToolExecution

from ..reporting import create_vulnerability_report

logger = logging.getLogger("airecon.agent")

# ── False-positive regex rules loaded once from verification_patterns.json ─
_fp_compiled: list[tuple[str, re.Pattern[str]]] = []


def _load_fp_indicators() -> list[tuple[str, re.Pattern[str]]]:
    global _fp_compiled
    if _fp_compiled:
        return _fp_compiled
    try:
        from ..data_loader import load_verification_patterns

        _verif_data = load_verification_patterns()
        _raw_indicators = _verif_data.get("false_positive_indicators", [])
        _fp_compiled = [
            (pat, re.compile(pat, re.IGNORECASE))
            for pat in _raw_indicators
            if isinstance(pat, str)
        ]
    except Exception as _e:
        logger.debug("Could not load FP indicators for pre-report check: %s", _e)
    return _fp_compiled


class _ReportingExecutorMixin:
    async def _execute_report_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        try:
            # ── Pre-report verification: catch false positives before file is written ──
            _verification_block = self._verify_before_report(arguments)
            if _verification_block:
                logger.warning("[Zero-FP] Report BLOCKED: %s", _verification_block)
                return (
                    False,
                    time.time() - start_time,
                    {
                        "success": False,
                        "blocked_by_verifier": True,
                        "reason": _verification_block,
                    },
                    None,
                )
            _report_params = {
                "title",
                "description",
                "target",
                "poc_description",
                "poc_script_code",
                "impact",
                "technical_analysis",
                "remediation_steps",
                "attack_vector",
                "attack_complexity",
                "privileges_required",
                "user_interaction",
                "scope",
                "confidentiality",
                "integrity",
                "availability",
                "endpoint",
                "method",
                "cve",
                "suggested_fix",
                "flag",
            }
            _report_kwargs = {k: v for k, v in arguments.items() if k in _report_params}
            _report_kwargs["_active_target"] = self.state.active_target
            result = await asyncio.to_thread(
                create_vulnerability_report,
                **_report_kwargs,
            )
            success = result.get("success", False)
            if success:
                result.setdefault("artifact_type", "vulnerability_report")
                result.setdefault("report_generated", True)
                result.setdefault(
                    "message",
                    "Final vulnerability report generated and saved under vulnerabilities/.",
                )
            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)

            if success and self._session:
                report_title = str(arguments.get("title", "") or "").strip()
                flag = arguments.get("flag", "")

                def _token_set(text: str) -> set[str]:
                    return {
                        tok
                        for tok in re.findall(r"[a-z0-9]{4,}", text.lower())
                        if tok not in {"vulnerability", "report", "issue", "finding"}
                    }

                def _scope_hints(data: dict[str, Any]) -> set[str]:
                    hints: set[str] = set()
                    for key in (
                        "url",
                        "endpoint",
                        "affected_endpoint",
                        "target",
                        "parameter",
                    ):
                        raw = str(data.get(key, "") or "").strip().lower()
                        if not raw:
                            continue
                        hints.add(raw)
                        try:
                            parsed = urlparse(raw)
                            if parsed.netloc:
                                hints.add(parsed.netloc.lower())
                            if parsed.path:
                                hints.add(parsed.path.lower())
                        except Exception as e:
                            logging.getLogger(__name__).debug(
                                "Expected failure parsing URL in report scope hints: %s",
                                e,
                            )
                    return hints

                report_scope = _scope_hints(arguments)
                report_tokens = _token_set(report_title)
                matched = False
                for vuln in self._session.vulnerabilities:
                    v_title = str(
                        vuln.get("title") or vuln.get("finding") or ""
                    ).strip()
                    if not report_title or not v_title:
                        continue

                    v_lower = v_title.lower()
                    r_lower = report_title.lower()
                    strict_title_hit = v_lower in r_lower or r_lower in v_lower
                    v_tokens = _token_set(v_title)
                    overlap_ratio = (
                        (len(report_tokens & v_tokens) / max(1, len(report_tokens)))
                        if report_tokens
                        else 0.0
                    )

                    vuln_scope = _scope_hints(vuln)
                    scope_hit = False
                    if report_scope and vuln_scope:
                        scope_hit = any(
                            rs in vs or vs in rs
                            for rs in report_scope
                            for vs in vuln_scope
                        )

                    title_confident = strict_title_hit or overlap_ratio >= 0.75
                    if title_confident and (
                        scope_hit or strict_title_hit or overlap_ratio >= 0.90
                    ):
                        vuln["report_generated"] = True
                        if flag:
                            vuln["flag"] = flag
                        matched = True

                if success and report_title and not matched:
                    logger.info(
                        "Report created but not bound to existing vulnerability: title=%r",
                        report_title[:120],
                    )

                # Record to attack surface tracker
                try:
                    _tracker = getattr(self, "_surface_tracker", None)
                    if _tracker and report_title:
                        _ep = str(
                            arguments.get("endpoint", "")
                            or arguments.get("target", "")
                            or ""
                        )
                        _vuln_type = _token_set(report_title)
                        _vt = (
                            " | ".join(sorted(_vuln_type))
                            if _vuln_type
                            else report_title
                        )
                        _n_findings = 1 if success else 0
                        _tracker.record_test(
                            endpoint=_ep,
                            vuln_type=_vt,
                            tool_used="create_vulnerability_report",
                            findings=_n_findings,
                        )
                except Exception as _e:
                    logger.debug("Surface tracker update failed: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Reporting tool exec error: %s", e)

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1
        return success, duration, result, self._last_output_file

    # ------------------------------------------------------------------
    # Pre-report false-positive prevention — data-driven, no hardcoded vuln types
    # ------------------------------------------------------------------

    @staticmethod
    def _token_set(text: str) -> set[str]:
        return {
            token
            for token in re.findall(r"[a-z0-9]{4,}", str(text or "").lower())
            if token not in {"vulnerability", "report", "issue", "finding"}
        }

    @staticmethod
    def _scope_hints(data: dict[str, Any]) -> set[str]:
        hints: set[str] = set()
        for key in ("url", "endpoint", "affected_endpoint", "target", "parameter"):
            raw = str(data.get(key, "") or "").strip().lower()
            if not raw:
                continue
            hints.add(raw)
            try:
                parsed = urlparse(raw)
                if parsed.netloc:
                    hints.add(parsed.netloc.lower())
                if parsed.path:
                    hints.add(parsed.path.lower())
            except Exception as e:
                logger.debug("Scope hint parse failed for %s: %s", raw, e)
        return hints

    def _collect_report_support(self, arguments: dict[str, Any]) -> dict[str, Any]:
        title = str(arguments.get("title", "") or "").strip()
        description = str(arguments.get("description", "") or "").strip()
        report_tokens = self._token_set(f"{title} {description}")
        report_scope = self._scope_hints(arguments)

        evidence_matches: list[dict[str, Any]] = []
        for ev in reversed(getattr(self.state, "evidence_log", [])[-60:]):
            if not isinstance(ev, dict):
                continue
            summary = str(ev.get("summary", "") or "")
            artifact = str(ev.get("artifact", "") or "")
            ev_scope = self._scope_hints(
                {
                    "target": artifact,
                    "endpoint": summary,
                }
            )
            ev_tokens = self._token_set(summary)
            overlap = len(report_tokens & ev_tokens)
            scope_hit = bool(report_scope and ev_scope and any(
                rs in es or es in rs for rs in report_scope for es in ev_scope
            ))
            if overlap >= 2 or scope_hit:
                evidence_matches.append(ev)

        session_matches: list[dict[str, Any]] = []
        if self._session:
            for vuln in getattr(self._session, "vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue
                vuln_title = str(vuln.get("title") or vuln.get("finding") or "")
                vuln_scope = self._scope_hints(vuln)
                vuln_tokens = self._token_set(vuln_title)
                overlap = len(report_tokens & vuln_tokens)
                scope_hit = bool(report_scope and vuln_scope and any(
                    rs in vs or vs in rs for rs in report_scope for vs in vuln_scope
                ))
                if overlap >= 2 or scope_hit:
                    session_matches.append(vuln)

        verified_session = any(
            bool(v.get("verified"))
            or bool(v.get("replay_verified"))
            or float(v.get("verified_confidence", 0.0) or 0.0) >= 0.65
            for v in session_matches
        )

        return {
            "report_scope": report_scope,
            "evidence_matches": evidence_matches,
            "session_matches": session_matches,
            "verified_session": verified_session,
        }

    def _assess_report_readiness(self, arguments: dict[str, Any]) -> str | None:
        poc_desc = str(arguments.get("poc_description", "") or "").strip()
        poc_code = str(arguments.get("poc_script_code", "") or "").strip()
        description = str(arguments.get("description", "") or "").strip()
        impact = str(arguments.get("impact", "") or "").strip()

        support = self._collect_report_support(arguments)
        report_scope = support["report_scope"]
        evidence_matches = support["evidence_matches"]
        session_matches = support["session_matches"]
        verified_session = support["verified_session"]

        if not report_scope:
            return "Report must include a concrete target/endpoint/scope, not only a generic title."

        combined_poc = f"{poc_desc}\n{poc_code}"
        has_repro_step = bool(
            re.search(
                r"(?i)(?:\bcurl\b|\bhttpie\b|\bpython\b|requests\.|browser_action|"
                r"sqlmap|nuclei|ffuf|wfuzz|(?:get|post|put|patch|delete)\s+/|https?://)",
                combined_poc,
            )
        )
        has_observable_effect = bool(
            re.search(
                r"(?i)\b(returned|response|status|body|cookie|token|credential|admin|"
                r"reflected|dump|leak|bypass|access|updated|deleted|created|downloaded|"
                r"charged|credited|approved|escalated|cross-tenant)\b",
                f"{poc_desc}\n{description}\n{impact}",
            )
        )
        if not has_repro_step or not has_observable_effect:
            return (
                "Report PoC must show a reproducible action plus an observable security outcome "
                "(for example response/status/data/state change)."
            )

        has_context = bool(getattr(self.state, "evidence_log", [])) or bool(
            getattr(self._session, "vulnerabilities", []) if self._session else []
        )
        if has_context and not evidence_matches and not session_matches:
            return (
                "Report is not grounded in current session evidence. Match it to recorded evidence "
                "or a tracked vulnerability before creating the final report."
            )

        if session_matches and not verified_session and len(evidence_matches) < 2:
            return (
                "Matched vulnerability exists, but corroboration is still weak. Gather replay/cross-tool evidence "
                "or additional session evidence before reporting."
            )

        return None

    def _verify_before_report(self, arguments: dict[str, Any]) -> str | None:
        """Synchronous pre-flight check against known-false-positive patterns.

        Does NOT classify vulnerability types — that's the LLM's job via prompts.
        Only rejects claims that match data-driven FP indicators.
        """
        poc_desc = str(arguments.get("poc_description", "")).strip()
        poc_code = str(arguments.get("poc_script_code", "")).strip()
        title = str(arguments.get("title", "")).strip()

        # 1. PoC is mandatory for any report
        if not poc_code:
            return "PoC script/code is required but missing in report arguments."

        # 2. Match against FP indicators from verification_patterns.json (data-driven)
        combined = f"{title} {poc_desc} {poc_code}"
        for pattern_str, compiled_regex in _load_fp_indicators():
            if compiled_regex.search(combined):
                return (
                    f"Vulnerability claim matches known false-positive pattern: "
                    f"{pattern_str[:100]}"
                )

        readiness_block = self._assess_report_readiness(arguments)
        if readiness_block:
            return readiness_block

        return None  # no blocking reason found
