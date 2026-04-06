from __future__ import annotations

import json
import logging
import re
import warnings
from pathlib import Path
from typing import Any

from ..config import get_config
from .executors import (
    _RECON_CONTENT_DISCOVERY_BINS,
    _RECON_LIVE_HOST_BINS,
    _RECON_PORT_SCAN_BINS,
    _RECON_SUBDOMAIN_BINS,
)
from .owasp import classify_owasp, severity_for_evidence
from .pipeline import _PHASE_TOOL_BUDGETS, PipelinePhase

logger = logging.getLogger("airecon.agent.loop_objectives")

_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    with open(_tools_meta_path) as _f:
        _TOOLS_META_OBJ: dict[str, Any] = json.load(_f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(f"tools_meta.json unavailable in loop_objectives ({_e})")
    _TOOLS_META_OBJ = {}

_ANALYSIS_VULN_TOOLS: frozenset[str] = frozenset(
    _TOOLS_META_OBJ.get("analysis_phase_vuln_tools", [])
)

class _ObjectivesMixin:
    _PHASE_OBJECTIVES: dict[str, list[str]] = {
        "RECON": [
            "Enumerate subdomains/hosts (passive sources first, then active validation)",
            "Filter to LIVE hosts only — validate with HTTP probing before any scanning",
            "Port scan and fingerprint ONLY the validated live hosts (two-pass: discover ports, then enrich with service detection)",
            "Crawl and map all endpoints, routes, and parameters on confirmed live services",
            "Persist all recon artifacts to output/ files for downstream tools to consume",
        ],
        "ANALYSIS": [
            "Map technologies, endpoints, and parameters",
            "Identify meaningful injection points or misconfigurations",
            "Correlate findings into exploit candidates",
        ],
        "EXPLOIT": [
            "Enumerate all application routes: /, /login, /api, /admin, /register, /dashboard, /api/v1/",
            "Test authentication: try default/common credentials, enumerate valid usernames",
            "Test authorization: modify session cookies, tokens, or IDs to access other accounts (IDOR)",
            "Test injection vectors: SQLi, XSS, SSTI, command injection on ALL discovered inputs",
            "Extract flags, sensitive data, or unauthorized capability from confirmed vulnerabilities",
        ],
        "REPORT": [
            "Create vulnerability reports for confirmed findings",
            "Document impact and remediation guidance",
            "Mark task complete when evidence is sufficient",
        ],
    }
    _EXPLOIT_HEAVY_TOOLS: frozenset[str] = frozenset({
        "quick_fuzz", "advanced_fuzz", "deep_fuzz",
        "schemathesis_fuzz", "create_vulnerability_report",
    })

    def _get_current_phase(self) -> PipelinePhase:
        if self.pipeline:
            return self.pipeline.get_current_phase()
        return PipelinePhase.RECON

    def _dynamic_phase_objectives(self, phase: PipelinePhase) -> list[str]:
        s = self._session
        if not s:
            return []

        dynamic: list[str] = []
        if phase == PipelinePhase.RECON:
            if s.subdomains and not s.live_hosts:
                dynamic.append(
                    "Validate liveness for newly discovered subdomains before deeper scans"
                )
            if s.open_ports:
                high_value_ports = sorted({
                    int(p)
                    for ports in s.open_ports.values()
                    for p in ports
                    if isinstance(p, int) and p not in (80, 443)
                })[:4]
                if high_value_ports:
                    dynamic.append(
                        f"Map HTTP/services on non-standard ports: {', '.join(str(p) for p in high_value_ports)}"
                    )

        elif phase == PipelinePhase.ANALYSIS:
            hints = {
                str(pt.get("type_hint", "")).upper()
                for pt in s.injection_points
                if pt.get("type_hint")
            }
            if "IDOR" in hints:
                dynamic.append("Correlate object IDs across endpoints for horizontal/vertical privilege abuse")
            if "SSRF" in hints:
                dynamic.append("Validate SSRF impact against internal metadata and localhost surfaces")
            if "OPEN_REDIRECT" in hints:
                dynamic.append("Differentiate open redirect from SSRF and confirm redirect-chain impact")
            if s.technologies:
                top_techs = ", ".join(list(s.technologies.keys())[:3])
                dynamic.append(f"Prioritize stack-specific checks for detected technologies: {top_techs}")

        elif phase == PipelinePhase.EXPLOIT:
            if s.waf_profiles:
                dynamic.append(
                    "Apply WAF-specific evasion strategy per host and compare blocked vs bypassed responses"
                )
            pending_hyp = self.state.get_pending_hypotheses(max_items=1)
            if pending_hyp:
                hyp = pending_hyp[0]
                dynamic.append(
                    f"Resolve top hypothesis [{hyp.get('id', 'h')}] with a concrete confirm/refute test"
                )
            if s.vulnerabilities and not any(v.get("report_generated") for v in s.vulnerabilities):
                dynamic.append("Convert highest-severity confirmed exploit into reproducible PoC evidence")

        elif phase == PipelinePhase.REPORT:
            unreported = [v for v in s.vulnerabilities if not v.get("report_generated")]
            if unreported:
                dynamic.append(
                    f"Generate reports for all unreported confirmed findings ({len(unreported)} remaining)"
                )

        return dynamic[:4]

    def _sync_phase_objectives(self, phase: PipelinePhase) -> None:
        defaults = self._PHASE_OBJECTIVES.get(phase.value, [])
        dynamic = self._dynamic_phase_objectives(phase)
        merged = defaults + [d for d in dynamic if d not in defaults]
        self.state.ensure_phase_objectives(phase.value, merged)

    def _update_objectives_from_session(self, phase: PipelinePhase) -> None:
        if not self._session:
            return
        defaults = self._PHASE_OBJECTIVES.get(phase.value, [])
        if len(defaults) < 3:
            return

        s = self._session
        if phase == PipelinePhase.RECON:

            if s.subdomains or s.live_hosts:
                self.state.mark_objective(phase.value, defaults[0], "done")

            if s.live_hosts and len(defaults) > 1:
                self.state.mark_objective(phase.value, defaults[1], "done")

            if s.open_ports and len(defaults) > 2:
                self.state.mark_objective(phase.value, defaults[2], "done")

            if s.urls and len(defaults) > 3:
                self.state.mark_objective(phase.value, defaults[3], "done")

            if s.scan_count >= 3 and len(defaults) > 4:
                self.state.mark_objective(phase.value, defaults[4], "done")
        elif phase == PipelinePhase.ANALYSIS:
            if s.technologies or s.urls:
                self.state.mark_objective(phase.value, defaults[0], "done")
            if s.injection_points:
                self.state.mark_objective(phase.value, defaults[1], "done")
            if s.vulnerabilities or len(self.state.evidence_log) >= 3:
                self.state.mark_objective(phase.value, defaults[2], "done")
        elif phase == PipelinePhase.EXPLOIT:
            _vuln_blob = " ".join(
                " ".join(
                    [
                        str(v.get("finding", "")),
                        str(v.get("title", "")),
                        str(v.get("proo", "")),
                        str(v.get("evidence", "")),
                        str(v.get("url", "")),
                        str(v.get("endpoint", "")),
                    ]
                )
                for v in s.vulnerabilities
            )
            _ev_blob = " ".join(str(e.get("summary", "")) for e in self.state.evidence_log)
            _combined = f"{_vuln_blob}\n{_ev_blob}"

            def _has(pat: str) -> bool:
                return bool(re.search(pat, _combined, re.IGNORECASE))

            if (s.urls or s.tested_endpoints or _has(r"https?://|/(api|admin|login|dashboard|register)\b")) and len(defaults) > 0:
                self.state.mark_objective(phase.value, defaults[0], "done")

            if _has(r"\b(login\s+success|authenticated|401|403|token|session|cookie|default\s+cred|weak\s+pass|brute)\b") and len(defaults) > 1:
                self.state.mark_objective(phase.value, defaults[1], "done")

            if _has(r"\b(idor|bola|broken\s+access|access\s+control|forbidden|unauthorized|privilege\s+escalation|horizontal|vertical)\b") and len(defaults) > 2:
                self.state.mark_objective(phase.value, defaults[2], "done")

            if _has(r"\b(sqli|sql\s+injection|xss|ssti|ssrf|xxe|rce|command\s+injection|lfi|rfi|union\s+select|sleep\s*\(|<script|onerror=)\b") and len(defaults) > 3:
                self.state.mark_objective(phase.value, defaults[3], "done")

            if (
                any(v.get("flag") or v.get("proo") or v.get("evidence") or v.get("poc_script_code") for v in s.vulnerabilities)
                or _has(r"\b(flag\{[^}\n]+\}|credential|secret|token|api[_-]?key|database\s+dump|exfiltrat|unauthorized\s+data|admin\s+access|read\s+/etc/passwd)\b")
            ) and len(defaults) > 4:
                self.state.mark_objective(phase.value, defaults[4], "done")
        elif phase == PipelinePhase.REPORT:
            if any(v.get("report_generated") for v in s.vulnerabilities):
                self.state.mark_objective(phase.value, defaults[0], "done")
            if s.vulnerabilities:
                self.state.mark_objective(phase.value, defaults[1], "done")
            if "REPORT" in s.completed_phases:
                self.state.mark_objective(phase.value, defaults[2], "done")

    def _update_objectives_from_tool(
        self,
        phase: PipelinePhase,
        tool_name: str,
        arguments: dict[str, Any],
        success: bool,
        result: dict[str, Any],
        output_file: str | None,
    ) -> None:
        if not success:
            return
        defaults = self._PHASE_OBJECTIVES.get(phase.value, [])
        if len(defaults) < 3:
            return

        cmd = ""
        if tool_name == "execute":
            cmd = str(arguments.get("command", "")).lower()

        if phase == PipelinePhase.RECON:

            _subdomain_hit = (
                cmd and any(b in cmd for b in _RECON_SUBDOMAIN_BINS)
            ) or tool_name in ("web_search", "browser_action")
            if _subdomain_hit:
                self.state.mark_objective(phase.value, defaults[0], "done")

            if cmd and any(b in cmd for b in _RECON_LIVE_HOST_BINS) and len(defaults) > 1:
                self.state.mark_objective(phase.value, defaults[1], "done")

            if cmd and any(b in cmd for b in _RECON_PORT_SCAN_BINS) and len(defaults) > 2:
                self.state.mark_objective(phase.value, defaults[2], "done")

            _crawl_hit = (
                cmd and any(b in cmd for b in _RECON_CONTENT_DISCOVERY_BINS)
            ) or (
                output_file
                and output_file.startswith("output/")
                and re.search(r"url|endpoint|path|dir", output_file, re.IGNORECASE)
            )
            if _crawl_hit and len(defaults) > 3:
                self.state.mark_objective(phase.value, defaults[3], "done")

            if output_file and output_file.startswith("output/") and len(defaults) > 4:
                self.state.mark_objective(phase.value, defaults[4], "done")

        elif phase == PipelinePhase.ANALYSIS:

            _result_text = self._extract_result_text(result)
            _has_tech_evidence = bool(re.search(
                r"\b(apache|nginx|iis|php|python|django|flask|express|rails|laravel|"
                r"wordpress|drupal|joomla|jquery|react|angular|vue|spring|struts|"
                r"server:|x-powered-by|content-type:|location:|set-cookie:)\b",
                _result_text,
                re.IGNORECASE,
            )) or bool(
                self._session and (self._session.technologies or self._session.urls)
            )
            if (
                tool_name in ("read_file", "browser_action", "web_search")
                or (tool_name == "execute" and _has_tech_evidence)
            ):
                self.state.mark_objective(phase.value, defaults[0], "done")

            if cmd and any(hint in cmd for hint in _ANALYSIS_VULN_TOOLS):
                self.state.mark_objective(phase.value, defaults[1], "done")

            meaningful_ev = [
                e for e in self.state.evidence_log
                if float(e.get("confidence", 0)) >= 0.65
            ]
            if len(meaningful_ev) >= 2:
                self.state.mark_objective(phase.value, defaults[2], "done")

        elif phase == PipelinePhase.EXPLOIT:
            result_text = self._extract_result_text(result)

            _enum_hit = tool_name in self._EXPLOIT_HEAVY_TOOLS or (
                tool_name == "execute"
                and bool(re.search(
                    r"(GET|POST|PUT|DELETE|PATCH)\s+/|status[:\s]+\d{3}|https?://",
                    result_text,
                    re.IGNORECASE,
                ))
            )
            if _enum_hit:
                self.state.mark_objective(phase.value, defaults[0], "done")

            _auth_hit = bool(re.search(
                r"(FLAG\{[^}\n]+\}|CVE-\d{4}-\d+|"
                r"login\s+success|authenticated|access\s+denied|"
                r"401|403|session\s+creat|token\s+issued|cookie)",
                result_text,
                re.IGNORECASE,
            ))
            if _auth_hit and len(defaults) > 1:
                self.state.mark_objective(phase.value, defaults[1], "done")

            _authz_hit = bool(re.search(
                r"(idor|bola|broken\s+access|access\s+control|forbidden|unauthorized|"
                r"privilege\s+escalation|horizontal|vertical)",
                result_text,
                re.IGNORECASE,
            ))
            if _authz_hit and len(defaults) > 2:
                self.state.mark_objective(phase.value, defaults[2], "done")

            _inject_hit = bool(re.search(
                r"(sqli|sql\s+injection|xss|ssti|command\s+injection|"
                r"ssrf|xxe|lfi|rfi|union\s+select|sleep\s*\(|"
                r"<script|onerror=|alert\s*\(|\{\{.*\}\}|%27|'--)",
                result_text,
                re.IGNORECASE,
            )) or tool_name in self._EXPLOIT_HEAVY_TOOLS
            if _inject_hit and len(defaults) > 3:
                self.state.mark_objective(phase.value, defaults[3], "done")

            _impact_hit = bool(re.search(
                r"(FLAG\{[^}\n]+\}|credential|secret|api[_-]?key|database\s+dump|"
                r"exfiltrat|unauthorized\s+data|admin\s+access|read\s+/etc/passwd)",
                result_text,
                re.IGNORECASE,
            )) or bool(
                output_file and re.search(r"(proof|poc|dump|credential|secret|flag)", output_file, re.IGNORECASE)
            )
            if _impact_hit and len(defaults) > 4:
                self.state.mark_objective(phase.value, defaults[4], "done")

        elif phase == PipelinePhase.REPORT:
            result_text = self._extract_result_text(result)
            _is_report_tool = tool_name == "create_vulnerability_report"
            _has_report_content = bool(re.search(
                r"\b(vulnerability report|executive summary|CVSS|severity[:\s]|"
                r"remediation|proof.of.concept|PoC|report generated|report written|"
                r"risk rating|findings? documented)\b",
                result_text,
                re.IGNORECASE,
            ))
            _is_report_output = bool(
                output_file
                and re.search(r"report|finding|vuln", output_file, re.IGNORECASE)
            )
            if _is_report_tool or _has_report_content or _is_report_output:
                self.state.mark_objective(phase.value, defaults[0], "done")
                self.state.mark_objective(phase.value, defaults[1], "done")
            if output_file and output_file.startswith("output/"):
                self.state.mark_objective(phase.value, defaults[2], "done")

    def _extract_result_text(self, result: dict[str, Any] | Any) -> str:
        if result is None:
            return ""
        if isinstance(result, str):
            return result
        if not isinstance(result, dict):
            return str(result)

        parts: list[str] = []
        for key in (
            "stdout", "stderr", "result", "summary", "error", "message",
            "note", "findings",
        ):
            value = result.get(key)
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                list_lines = [str(x) for x in value[:8]]
                if list_lines:
                    parts.append("\n".join(list_lines))
            elif isinstance(value, dict):
                for sub_key in ("summary", "result", "error", "message", "note"):
                    sub_val = value.get(sub_key)
                    if isinstance(sub_val, str):
                        parts.append(sub_val)
        merged = "\n".join(p for p in parts if p).strip()
        return merged[:7000]

    def _enrich_evidence(
        self,
        summary: str,
        base_tags: list[str],
        confidence: float,
        tool_name: str,
    ) -> tuple[list[str], int]:
        owasp_tags = classify_owasp(summary, base_tags, tool_name)
        enriched_tags = list(dict.fromkeys(base_tags + owasp_tags))
        sev = severity_for_evidence(summary, enriched_tags, confidence, tool_name)
        return enriched_tags, sev

    def _record_evidence_from_result(
        self,
        phase: str,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        success: bool,
        output_file: str | None,
    ) -> None:
        if output_file:
            _t, _s = self._enrich_evidence(f"Artifact saved to {output_file}", ["artifact", "file"], 0.9, tool_name)
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=f"Artifact saved to {output_file}",
                confidence=0.9,
                artifact=output_file,
                tags=_t,
                severity=_s,
            )

        blob = self._extract_result_text(result)
        if not blob:
            return

        if not success:
            err = str(result.get("error", "")).strip() if isinstance(result, dict) else ""
            if err:
                _summary = f"Execution error observed: {err[:240]}"
                _t, _s = self._enrich_evidence(_summary, ["error"], 0.4, tool_name)
                self.state.add_evidence(
                    phase=phase,
                    source_tool=tool_name,
                    summary=_summary,
                    confidence=0.4,
                    tags=_t,
                    severity=_s,
                )
            return

        for flag in re.findall(r"(?:FLAG|flag)\{[^}\n]{1,200}\}", blob):
            _summary = f"Flag pattern captured: {flag}"
            _t, _s = self._enrich_evidence(_summary, ["flag", "ct"], 1.0, tool_name)
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=1.0,
                tags=_t,
                severity=_s,
            )

        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", blob, re.IGNORECASE):
            _summary = f"CVE reference discovered: {cve.upper()}"
            _t, _s = self._enrich_evidence(_summary, ["cve", "vulnerability"], 0.75, tool_name)
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=0.75,
                tags=_t,
                severity=_s,
            )

        url_matches = list(
            dict.fromkeys(
                re.findall(r"https?://[^\s\"'<>]+", blob, re.IGNORECASE)
            )
        )

        _target_domain: str = ""
        if self._session and self._session.target:
            import urllib.parse as _up
            _parsed = _up.urlparse(
                self._session.target
                if "://" in self._session.target
                else f"http://{self._session.target}"
            )
            _host = _parsed.hostname or ""

            _parts = _host.split(".")
            _target_domain = ".".join(_parts[-2:]) if len(_parts) >= 2 else _host

        in_scope_urls: list[str] = []
        if _target_domain:
            import urllib.parse as _up2
            for _u in url_matches:
                try:
                    _h = _up2.urlparse(_u).hostname or ""
                except Exception as e:
                    logger.debug("Exception in %s: %s", __name__, e)
                    continue
                if _h.endswith(_target_domain):
                    in_scope_urls.append(_u)

        for url in in_scope_urls[:4]:
            _summary = f"Interesting URL collected: {url}"
            _t, _s = self._enrich_evidence(_summary, ["url", "endpoint"], 0.65, tool_name)
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=0.65,
                tags=_t,
                severity=_s,
            )

        port_hits = list(
            dict.fromkeys(
                re.findall(
                    r"\b\d{1,5}/(?:tcp|udp)\b|\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b",
                    blob,
                    re.IGNORECASE,
                )
            )
        )
        for hit in port_hits[:4]:
            _summary = f"Service/port evidence: {hit}"
            _t, _s = self._enrich_evidence(_summary, ["network", "recon"], 0.7, tool_name)
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=0.7,
                tags=_t,
                severity=_s,
            )

        high_signal_lines = []
        signal_re = re.compile(
            r"(?i)(vulnerab|injection|xss|sqli|idor|ssrf|rce|auth bypass|token|secret|credential)"
        )

        _FALSE_SIGNAL_RE = re.compile(
            r"(?i)\b("
            r"0\s+vuln|no\s+vuln|not\s+vuln|no\s+injection|not\s+found|not\s+detected|"
            r"no\s+xss|no\s+sqli|no\s+idor|no\s+ssrf|no\s+rce|"
            r"testing\s+for|checking\s+for|scanning\s+for|looking\s+for|"
            r"test(?:ing)?\s+(?:xss|sqli|injection|vulnerability)|"
            r"attempt(?:ing)?\s+to|trying\s+to|will\s+test|starting\s+test|"
            r"no\s+result|0\s+result|nothing\s+found"
            r")\b"
        )
        for line in blob.splitlines():
            line = line.strip()
            if not line or len(line) < 12:
                continue
            if signal_re.search(line) and not _FALSE_SIGNAL_RE.search(line):
                high_signal_lines.append(line[:260])
            if len(high_signal_lines) >= 3:
                break
        for line in high_signal_lines:
            _summary = f"Security signal: {line}"

            _t, _s = self._enrich_evidence(_summary, ["signal"], 0.6, tool_name)
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=0.6,
                tags=_t,
                severity=_s,
            )

        if tool_name == "execute":
            cmd = str(arguments.get("command", "")).strip()
            if cmd:
                _summary = f"Executed command: {cmd[:220]}"
                _t, _s = self._enrich_evidence(_summary, ["execution", "trace"], 0.55, tool_name)
                self.state.add_evidence(
                    phase=phase,
                    source_tool=tool_name,
                    summary=_summary,
                    confidence=0.55,
                    tags=_t,
                    severity=_s,
                )

        if success:
            self._auto_form_hypotheses(phase, tool_name, arguments, blob)

    _VULN_HYPO_PATTERNS: list[tuple[re.Pattern, str, str]] = [
        (re.compile(
            r"\b(sql\s*i(?:njection)?|sqli|union\s+select|error.based\s+sql|"
            r"boolean.based|time.based\s+blind)\b", re.IGNORECASE),
         "sql_injection", "sqlmap"),
        (re.compile(
            r"\b(xss|cross.site\s+script|reflected|stored\s+xss|dom.based)\b",
            re.IGNORECASE),
         "xss", "dalfox"),
        (re.compile(
            r"\b(ssrf|server.side\s+request|internal\s+host|metadata\s+endpoint|"
            r"169\.254\.169\.254)\b", re.IGNORECASE),
         "ssr", "ffu"),
        (re.compile(
            r"\b(idor|insecure\s+direct|object\s+reference|bola|broken\s+access\s+control)\b",
            re.IGNORECASE),
         "idor", "curl"),
        (re.compile(
            r"\b(rce|remote\s+code\s+exec|command\s+exec|os\s+command\s+inject)\b",
            re.IGNORECASE),
         "rce", "curl"),
        (re.compile(
            r"\b(ssti|server.side\s+template|template\s+inject)\b", re.IGNORECASE),
         "ssti", "tplmap"),
        (re.compile(
            r"\b(lfi|local\s+file\s+inclus|path\s+travers|directory\s+travers|"
            r"\.\./|etc/passwd)\b", re.IGNORECASE),
         "lfi", "ffu"),
        (re.compile(
            r"\b(auth\s+bypass|broken\s+auth|default\s+cred|weak\s+pass|"
            r"admin:admin|password123)\b", re.IGNORECASE),
         "auth_bypass", "hydra"),
        (re.compile(
            r"\b(jwt|json\s+web\s+token|hs256|alg.none|secret\s+key\s+exposed)\b",
            re.IGNORECASE),
         "jwt_weakness", "jwt_tool"),
        (re.compile(
            r"\b(open\s+redirect|location\s+header\s+inject|redirect\s+to)\b",
            re.IGNORECASE),
         "open_redirect", "curl"),
    ]

    _HYPO_FALSE_SIGNAL_RE = re.compile(
        r"(?i)\b("
        r"testing\s+for|checking\s+for|scanning\s+for|looking\s+for|"
        r"no\s+vuln|0\s+vuln|not\s+vuln|not\s+found|not\s+detected|"
        r"no\s+xss|no\s+sqli|no\s+idor|no\s+ssrf|no\s+rce|no\s+injection|"
        r"attempt(?:ing)?\s+to|trying\s+to|will\s+test|starting\s+test|"
        r"nothing\s+found|no\s+result|0\s+result"
        r")\b"
    )

    def _auto_form_hypotheses(
        self,
        phase: str,
        tool_name: str,
        arguments: dict[str, Any],
        result_text: str,
    ) -> None:
        _MAX_HYPO_PER_CALL = 2
        formed = 0

        _cmd = str(arguments.get("command", "")) if tool_name == "execute" else ""
        _url_m = re.search(r"https?://[^\s\"'<>{}\[\]]+", _cmd or result_text)
        _endpoint = _url_m.group(0)[:80] if _url_m else "the target"

        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", result_text, re.IGNORECASE):
            if formed >= _MAX_HYPO_PER_CALL:
                break
            _cve = cve.upper()
            self.state.add_hypothesis(
                claim=f"{_cve} is present and may be exploitable on this target",
                test_plan=(
                    f"Search for a public PoC for {_cve}. "
                    f"Run: nuclei -t cve/{_cve.lower()}.yaml "
                    f"or searchsploit {_cve}. "
                    "Verify exploitability against the installed version."
                ),
                phase=phase,
                tags=["cve", "vulnerability"],
            )
            formed += 1

        for _pat, _vuln_type, _confirm_tool in self._VULN_HYPO_PATTERNS:
            if formed >= _MAX_HYPO_PER_CALL:
                break
            if not _pat.search(result_text):
                continue
            if self._HYPO_FALSE_SIGNAL_RE.search(result_text):
                continue
            _label = _vuln_type.replace("_", " ").upper()
            self.state.add_hypothesis(
                claim=(
                    f"Potential {_label} vulnerability detected near {_endpoint}"
                ),
                test_plan=(
                    f"Use {_confirm_tool} to confirm. "
                    "Test all input parameters on the endpoint. "
                    "Look for error messages or behavioural differences "
                    "that distinguish positive from negative responses."
                ),
                phase=phase,
                tags=[_vuln_type, "needs_confirmation"],
            )
            formed += 1

        if phase == "RECON" and formed < _MAX_HYPO_PER_CALL:
            _port_hits = list(dict.fromkeys(
                re.findall(r"\b(\d{1,5})/open\b", result_text, re.IGNORECASE)
            ))
            if _port_hits:
                _ports_str = ", ".join(_port_hits[:3])
                self.state.add_hypothesis(
                    claim=(
                        f"Open port(s) {_ports_str} may expose exploitable services"
                    ),
                    test_plan=(
                        f"Run: nmap -sV -sC -p {','.join(_port_hits[:3])} <target>. "
                        "Check service versions against CVE databases. "
                        "Test for default credentials and known exploits."
                    ),
                    phase=phase,
                    tags=["network", "service"],
                )

    def _build_phase_gate_note(self, tool_name: str, success: bool) -> str:
        phase = self._get_current_phase()
        phase_name = phase.value
        phase_evidence = [
            e for e in self.state.evidence_log
            if str(e.get("phase", "")).upper() == phase_name
        ]
        cfg = get_config()
        explore_mode = self._cfg_bool(cfg, "agent_exploration_mode", True)
        intensity = self._cfg_float(cfg, "agent_exploration_intensity", 0.8)
        min_required_evidence = 1 if explore_mode and intensity >= 0.7 else 2

        if (
            phase in (PipelinePhase.RECON, PipelinePhase.ANALYSIS)
            and tool_name in self._EXPLOIT_HEAVY_TOOLS
            and len(phase_evidence) < min_required_evidence
        ):
            return (
                "[SYSTEM: PHASE GATE]\n"
                f"You used exploit-heavy tool '{tool_name}' while phase is {phase_name} "
                "with insufficient evidence.\n"
                "Before further exploitation, collect stronger artifacts first "
                "(live hosts, open ports, endpoints, injection points)."
            )

        if (
            phase == PipelinePhase.EXPLOIT
            and not success
            and self._consecutive_failures >= 2
        ):
            return (
                "[SYSTEM: PHASE GATE]\n"
                "Exploit attempts are failing repeatedly. Pivot strategy now:\n"
                "- Switch tool family (web -> network, or network -> browser)\n"
                "- Use evidence_log to choose a different vector\n"
                "- Avoid repeating same payload/command."
            )
        return ""

    def _check_tool_budget(self, tool_name: str, phase: str) -> str:
        budget = _PHASE_TOOL_BUDGETS.get(phase, {}).get(tool_name)
        if budget is None:

            eff = self.state.get_tool_effectiveness(phase, tool_name)
            calls = int(eff.get("calls", 0.0))
            hit_rate = float(eff.get("hit_rate", 0.0))
            if calls >= 6 and hit_rate < 0.15:
                return (
                    f"[TOOL BUDGET] '{tool_name}' is low-yield in {phase} "
                    f"(hit-rate={hit_rate:.0%}, calls={calls}). Pivot tool family."
                )
            return ""
        usage = self.state.get_phase_tool_count(phase, tool_name)
        eff = self.state.get_tool_effectiveness(phase, tool_name)
        calls = int(eff.get("calls", 0.0))
        hit_rate = float(eff.get("hit_rate", 0.0))

        effective_budget = budget
        if calls >= 3:
            if hit_rate < 0.20:
                effective_budget = max(1, int(budget * 0.70))
            elif hit_rate >= 0.60:
                effective_budget = int(budget * 1.15)

        if budget == 0 and usage >= 1:
            return (
                f"[TOOL BUDGET] '{tool_name}' is not recommended in {phase} phase "
                f"(used {usage}×). Switch to a phase-appropriate tool."
            )
        if usage >= effective_budget:
            return (
                f"[TOOL BUDGET] '{tool_name}' has exhausted its {phase} phase budget "
                f"({usage}/{effective_budget}, base={budget}, hit-rate={hit_rate:.0%}). "
                "Switch approach or tool family."
            )
        if effective_budget > 0 and usage >= int(effective_budget * 0.75):
            return (
                f"[TOOL BUDGET] '{tool_name}' is at {usage}/{effective_budget} of {phase} budget "
                f"(base={budget}, hit-rate={hit_rate:.0%}). Plan remaining calls carefully."
            )
        return ""
