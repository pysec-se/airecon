"""Validation helpers for AIRecon.

Two layers of validation live here:

1. **Command/path validation** (module-level functions):
   - `validate_target_path` — prevent path traversal out of /workspace
   - `has_dangerous_patterns` — detect rm -rf /, fork bombs, etc.
   - `validate_for_execution` — combined pre-execution check

2. **Tool-argument validation** (_ValidatorMixin):
   - `_validate_tool_args` — validate per-tool arguments before dispatch
"""

from __future__ import annotations

import ast
import json
import logging
import re
import shlex
from pathlib import Path
from typing import Any

from .tuning import get_tuning

logger = logging.getLogger("airecon.validation")


def _load_known_tools() -> frozenset[str]:
    """Load tool names from tools_meta.json once at module load time.

    Returns a frozenset of lowercase tool names so _validate_tool_args
    can check poc_description references without hardcoding names or
    doing file I/O on every call.
    """
    try:
        data_file = Path(__file__).parent.parent / "data" / "tools_meta.json"
        meta = json.loads(data_file.read_text(encoding="utf-8"))
        tools: set[str] = set()
        for category in meta.get("categories", {}).values():
            if isinstance(category, dict):
                for tool_list in category.values():
                    if isinstance(tool_list, list):
                        tools.update(t.lower() for t in tool_list if t)
            elif isinstance(category, list):
                tools.update(t.lower() for t in category if t)
        return frozenset(tools)
    except Exception as exc:
        logger.debug("Could not load tools_meta.json for validator: %s", exc)
        return frozenset()


_KNOWN_TOOLS: frozenset[str] = _load_known_tools()
_REPLAY_GAP_MESSAGES = {
    "request_logged": str(
        get_tuning(
            "validator.replay.gap_messages.request_logged",
            "describe the exact replay request that was executed",
        )
    ),
    "response_logged": str(
        get_tuning(
            "validator.replay.gap_messages.response_logged",
            "describe the exploit response that was observed",
        )
    ),
    "payload_observed": str(
        get_tuning(
            "validator.replay.gap_messages.payload_observed",
            "link the payload to the observed output",
        )
    ),
    "target_bound": str(
        get_tuning(
            "validator.replay.gap_messages.target_bound",
            "bind the PoC to the same target/endpoint as the finding",
        )
    ),
    "runtime_command_logged": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_command_logged",
            "include the exact replay command that was executed",
        )
    ),
    "runtime_response_logged": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_response_logged",
            "include runtime response details (status/body) for that replay",
        )
    ),
    "runtime_http": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_http",
            "include HTTP status evidence from runtime replay",
        )
    ),
    "runtime_signal": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_signal",
            "include impact evidence from runtime replay",
        )
    ),
    "runtime_impact": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_impact",
            "show runtime impact (data/error/access change), not only heartbeat output",
        )
    ),
    "runtime_host_bound": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_host_bound",
            "use the same PoC host in runtime replay evidence",
        )
    ),
    "runtime_payload_bound": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_payload_bound",
            "use the same PoC payload in runtime replay evidence",
        )
    ),
}
_REPLAY_SCORE_WEIGHTS = {
    "request_logged": float(get_tuning("validator.replay.score_weights.request_logged", 0.16)),
    "response_logged": float(get_tuning("validator.replay.score_weights.response_logged", 0.16)),
    "target_bound": float(get_tuning("validator.replay.score_weights.target_bound", 0.18)),
    "payload_observed": float(get_tuning("validator.replay.score_weights.payload_observed", 0.14)),
    "matching_finding": float(get_tuning("validator.replay.score_weights.matching_finding", 0.12)),
    "artifact_bound": float(get_tuning("validator.replay.score_weights.artifact_bound", 0.09)),
    "runtime_http": float(get_tuning("validator.replay.score_weights.runtime_http", 0.09)),
    "runtime_signal": float(get_tuning("validator.replay.score_weights.runtime_signal", 0.06)),
    "runtime_impact": float(get_tuning("validator.replay.score_weights.runtime_impact", 0.05)),
    "runtime_host_bound": float(get_tuning("validator.replay.score_weights.runtime_host_bound", 0.05)),
    "runtime_payload_bound": float(get_tuning("validator.replay.score_weights.runtime_payload_bound", 0.05)),
    "no_runtime_text_bonus": float(get_tuning("validator.replay.score_weights.no_runtime_text_bonus", 0.08)),
}
_REPLAY_THRESHOLDS = {
    "strict_with_runtime": float(get_tuning("validator.replay.thresholds.strict_with_runtime", 0.58)),
    "strict_no_runtime": float(get_tuning("validator.replay.thresholds.strict_no_runtime", 0.48)),
    "non_strict": float(get_tuning("validator.replay.thresholds.non_strict", 0.38)),
}


# ── Path / command validation ─────────────────────────────────────────────────

def validate_target_path(
    target: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str | Path]:
    """Validate that target path stays within base_dir.

    Returns: (is_valid, resolved_path_or_error_message)

    Prevents:
    - Path traversal attacks (../../../etc/passwd)
    - Symlink attacks (links to parent directories)
    - Shell metacharacters in paths
    """
    try:
        base_path = Path(base_dir).resolve()
        target_path = (base_path / target).resolve()

        try:
            target_path.relative_to(base_path)
        except ValueError:
            return False, f"Path traversal detected: {target} escapes {base_dir}"

        dangerous_chars = [";", "|", "$", "`", "(", ")", "&", "<", ">", "\n", "\r"]
        if any(char in target for char in dangerous_chars):
            return False, f"Invalid characters in path: {target}"

        return True, target_path

    except Exception as e:
        return False, f"Path validation error: {str(e)}"


def extract_paths_from_command(command: str) -> list[str]:
    """Extract file paths referenced by known output flags in a bash command.

    Note: only inspects known flag patterns (-o, >, -t, --targets).
    Positional arguments are NOT inspected — this is a deliberate design
    choice to avoid false positives on host/URL arguments.
    """
    # Each pattern captures: double-quoted path | single-quoted path | bare path
    # Three capture groups per pattern — only one will be non-empty per match.
    _Q = r'(?:"([^"]+)"|\'([^\']+)\'|(\S+))'
    patterns = [
        rf"-o\s+{_Q}",              # -o /path  or  -o "/path with spaces"
        rf"-output\s+{_Q}",         # -output /path
        rf">>\s*{_Q}",              # >> /path (append) — must come BEFORE single >
        rf"(?<!>)>(?!>)\s*{_Q}",   # > /path (redirect) — excludes >>
        rf"-t\s+{_Q}",              # -t /path/to/targets
        rf"--targets\s+{_Q}",       # --targets /path
    ]
    paths: list[str] = []
    for pattern in patterns:
        for groups in re.findall(pattern, command):
            # Take the first non-empty group (double-quoted, single-quoted, or bare)
            path = next((g for g in groups if g), None)
            if path:
                paths.append(path)
    return paths


def validate_command_paths(
    command: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str]:
    """Validate all flag-referenced paths in a command stay within base_dir.

    Returns: (is_valid, error_message or empty string)
    """
    for path in extract_paths_from_command(command):
        is_valid, error = validate_target_path(path, base_dir)
        if not is_valid:
            return False, str(error)
    return True, ""


def validate_paths_in_semgrep_args(
    target_path: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str]:
    """Validate semgrep target path."""
    return validate_target_path(target_path, base_dir)  # type: ignore[return-value]


def validate_paths_in_filesystem_args(
    file_path: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str]:
    """Validate filesystem operation paths (cat, grep, find, etc)."""
    return validate_target_path(file_path, base_dir)  # type: ignore[return-value]


# Precompiled dangerous patterns for faster checking
DANGEROUS_PATTERNS: list[tuple[str, str]] = [
    (r"rm\s+-rf\s+/", "Dangerous: rm -rf / detected"),
    (r"dd\s+if=.*of=/dev", "Dangerous: writing to /dev"),
    # Fork bomb: matches compact :(){:|:&};: and spaced variants
    (r":\s*\(\s*\)\s*\{.*:\s*\|.*:\s*&", "Dangerous: fork bomb detected"),
    (r"pkill\s+-9", "Dangerous: killing critical processes"),
    (r">\s*/dev/sd[a-z]", "Dangerous: writing to disk device"),
]


def _has_dangerous_chmod_mode(command: str) -> bool:
    """Detect SUID/SGID chmod patterns without false positives."""
    if "chmod" not in command.lower():
        return False

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    for i, token in enumerate(tokens):
        if token.lower() != "chmod":
            continue

        mode_idx = i + 1
        while mode_idx < len(tokens) and tokens[mode_idx].startswith("-"):
            mode_idx += 1
        if mode_idx >= len(tokens):
            continue
        mode_token = tokens[mode_idx]

        for clause in mode_token.split(","):
            clause = clause.strip().lower()
            if "+s" in clause or "=s" in clause:
                return True

        if re.fullmatch(r"[0-7]{4,}", mode_token):
            special_digit = int(mode_token[-4])
            if special_digit in {2, 4, 6, 7}:
                return True

    return False


def has_dangerous_patterns(command: str) -> tuple[bool, str]:
    """Check if command contains dangerous patterns.

    Returns: (has_dangerous, pattern_description or empty string)
    """
    for pattern, description in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True, description
    if _has_dangerous_chmod_mode(command):
        return True, "Dangerous: SUID/SGID bit change detected"
    return False, ""


def validate_for_execution(
    command: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str]:
    """Complete validation before command execution.

    Checks dangerous patterns first (fast), then path validity.
    Returns: (is_valid, error_message or empty string)
    """
    has_danger, danger_msg = has_dangerous_patterns(command)
    if has_danger:
        return False, danger_msg
    # Detect unbalanced quotes (LLM quoting bugs cause bash EOF errors).
    # shlex.split raises ValueError on unmatched ' or " — catch early so
    # the agent can retry with corrected quoting instead of sending a broken
    # command to the Docker sandbox.
    try:
        shlex.split(command)
    except ValueError as e:
        return False, (
            f"Shell syntax error (unbalanced quotes): {e}. "
            "Rewrite the command using double-quotes for the outer string "
            "or avoid embedding single-quotes inside single-quoted arguments."
        )
    return validate_command_paths(command, base_dir)


# ── Tool-argument validation (mixin for AgentLoop) ────────────────────────────

# Compiled once at import time — used in _validate_tool_args for reports
_HTTP_EVIDENCE_RE = re.compile(
    r"(http\s+[2345]\d{2}|status[:\s]+[2345]\d{2}|code\s+[2345]\d{2}|"
    r"\b[2345]\d{2}\s+(ok|found|forbidden|redirect|not found|created|"
    r"accepted|no content|moved|unauthorized|bad request|internal server error|"
    r"forbidden|unauthorized|forbidden)\b|"
    r"response[:\s]+[2345]\d{2}|→\s*[2345]\d{2}|"
    r"\[[2345]\d{2}\]|\([2345]\d{2}\)|\{[2345]\d{2}\}|"
    r"returned\s+[2345]\d{2}|returns\s+[2345]\d{2}|got\s+[2345]\d{2}|"
    r"observed[:\s]+[2345]\d{2}|status\s*[2345]\d{2}|"
    # JSON API response patterns: {"status": 200}, {"code": 401}, {"statusCode": 403}
    r"\"status(?:Code)?\"\s*:\s*[2345]\d{2}|"
    r"\"code\"\s*:\s*[2345]\d{2}|"
    r"\"http_status\"\s*:\s*[2345]\d{2})",
    re.IGNORECASE,
)

# Gap #1: HTTP evidence patterns that check for actual impact proof
_HTTP_EVIDENCE_PATTERNS = {
    "status_change": re.compile(
        r"(200|201|204|301|302|304|400|401|403|404|500|503)\s*→\s*(200|201|204|301|302|304|400|401|403|404|500|503)",
        re.IGNORECASE
    ),
    "response_content": re.compile(
        r"(response|returned|got|contain(?:s|ing)|found|showing|displays?|has|includes)\s+.*?"
        r"(admin|user|password|token|secret|key|cookie|session|data|record|list|table|error|exception|query|select|insert|update|delete|flag|id|username|email|api|credential)",
        re.IGNORECASE
    ),
    "error_indicator": re.compile(
        r"(error|exception|sql|syntax|warning|failed|denied|forbidden|timeout|connection|refused|unreachable|stack trace|traceback)",
        re.IGNORECASE
    ),
    "data_extraction": re.compile(
        r"(extracted|captured|dumped|found|leaked|exposed|retrieved|obtained|recovered|decrypted)\s+.*?"
        r"(password|token|api|key|secret|credential|session|cookie|hash|id|username|email|data)",
        re.IGNORECASE
    ),
}


class _ValidatorMixin:

    @staticmethod
    def _str_arg(arguments: dict[str, Any], key: str) -> str:
        """Return the string value of *key* or '' if missing or not a str.

        Guards against AttributeError when malformed LLM tool-call arguments
        pass a non-string type (e.g. a dict or int) for a field that is
        expected to be a string.
        """
        val = arguments.get(key)
        return val if isinstance(val, str) else ""

    _VALID_BROWSER_ACTIONS = frozenset({
        "launch", "goto", "click", "type", "scroll_down", "scroll_up", "back",
        "forward", "new_tab", "switch_tab", "close_tab", "wait", "execute_js",
        "double_click", "hover", "press_key", "save_pdf", "get_console_logs",
        "get_network_logs", "view_source", "close", "list_tabs",
        # Auth actions — implemented in browser.py, defined in tools.json
        "login_form", "handle_totp", "save_auth_state", "inject_cookies", "oauth_authorize",
    })

    def _collect_runtime_verification_texts(self, max_entries: int = 24) -> list[str]:
        """Collect recent runtime evidence snippets for replay verification.

        Sources:
        - self.state.tool_history (tool args + result excerpts)
        - self.state.evidence_log summaries (if available)
        """
        chunks: list[str] = []
        state = getattr(self, "state", None)
        if state is None:
            return chunks

        tool_history = list(getattr(state, "tool_history", []) or [])[-max_entries:]
        for entry in tool_history:
            try:
                tool_name = str(getattr(entry, "tool_name", "") or "")
                arguments = getattr(entry, "arguments", {}) or {}
                result = getattr(entry, "result", {}) or {}
                arg_blob = " ".join(f"{k}={v}" for k, v in list(arguments.items())[:6])
                out_blob = " ".join(
                    str(result.get(k, ""))[:500]
                    for k in ("stdout", "stderr", "output", "content", "summary")
                    if isinstance(result.get(k), str)
                )
                merged = f"{tool_name} {arg_blob} {out_blob}".strip()
                if merged:
                    chunks.append(merged)
            except Exception:
                continue

        evidence_log = list(getattr(state, "evidence_log", []) or [])[-max_entries:]
        for ev in evidence_log:
            try:
                if not isinstance(ev, dict):
                    continue
                summary = str(ev.get("summary", "")).strip()
                artifact = str(ev.get("artifact", "")).strip()
                if summary:
                    chunks.append(f"{summary} {artifact}".strip())
            except Exception:
                continue
        return chunks

    @staticmethod
    def _extract_payload_markers(text: str) -> list[str]:
        """Extract high-signal payload markers from PoC code/description."""
        markers: list[str] = []
        for m in re.findall(r"(['\"`])(.*?)\1", text):
            token = str(m[1]).strip()
            if len(token) < 4:
                continue
            if re.search(r"(or\s+1=1|union\s+select|<script|../|169\.254|cmd=|token=|jwt)", token, re.IGNORECASE):
                markers.append(token.lower()[:120])
        for m in re.findall(r"(?:payload|param|query|id|user|url)\s*[:=]\s*([^\s,&]+)", text, re.IGNORECASE):
            tok = str(m).strip().strip("'\"")
            if tok and len(tok) >= 3:
                markers.append(tok.lower()[:80])
        # Dedup while preserving order
        seen: set[str] = set()
        return [x for x in markers if not (x in seen or seen.add(x))]

    def _replay_verification_score(
        self,
        *,
        poc_code: str,
        poc_desc: str,
        report_finding: str,
        matching_finding: bool,
    ) -> tuple[float, list[str], bool, bool]:
        """Compute replay-verification confidence from runtime and textual evidence."""
        gaps: list[str] = []
        runtime_chunks = self._collect_runtime_verification_texts()
        has_runtime = bool(runtime_chunks)

        runtime_text = " ".join(runtime_chunks).lower()
        desc_lower = poc_desc.lower()
        code_lower = poc_code.lower()
        report_lower = report_finding.lower()
        host_matches = re.findall(r"https?://([^\s/\"']+)", poc_code, re.IGNORECASE)
        hosts = [h.split(":")[0].lower() for h in host_matches if h]

        request_logged = bool(
            re.search(r"\b(get|post|put|delete|patch|curl|request)\b", desc_lower)
            or re.search(r"\b(curl|requests\.|httpx\.|urllib|fetch\()", code_lower)
        )
        response_logged = bool(
            _HTTP_EVIDENCE_RE.search(poc_desc)
            or re.search(r"\b(response|returned|body|status|code)\b", desc_lower)
        )
        if not request_logged:
            gaps.append(_REPLAY_GAP_MESSAGES["request_logged"])
        if not response_logged:
            gaps.append(_REPLAY_GAP_MESSAGES["response_logged"])

        payload_markers = self._extract_payload_markers(poc_code + " " + poc_desc)
        payload_observed = bool(payload_markers) and any(
            marker in desc_lower or (has_runtime and marker in runtime_text)
            for marker in payload_markers[:8]
        )
        if payload_markers and not payload_observed and not has_runtime:
            payload_observed = bool(
                re.search(
                    r"\b(sql|sqli|xss|ssrf|idor|csrf|rce|lfi|token|admin|password|credential|bypass)\b",
                    desc_lower,
                )
            )
        if payload_markers and not payload_observed:
            gaps.append(_REPLAY_GAP_MESSAGES["payload_observed"])

        target_bound = False
        runtime_host_bound = False
        if hosts:
            if has_runtime:
                runtime_host_bound = any(h in runtime_text for h in hosts)
                target_bound = runtime_host_bound or any(h in desc_lower for h in hosts)
            else:
                target_bound = True
        elif report_lower:
            key_terms = [w for w in report_lower.split() if len(w) >= 5][:10]
            target_bound = bool(key_terms) and any(
                any(term in blob for term in key_terms)
                for blob in ([desc_lower] + ([runtime_text] if has_runtime else []))
            )
        if not target_bound:
            gaps.append(_REPLAY_GAP_MESSAGES["target_bound"])

        runtime_http = has_runtime and bool(re.search(r"\b(http/?\d\.\d|status|code)\s*[=:]?\s*[2345]\d{2}", runtime_text))
        runtime_command_logged = has_runtime and bool(
            re.search(r"\b(curl|requests\.|httpx\.|urllib|fetch\(|\bget\b|\bpost\b|\bput\b|\bdelete\b|\bpatch\b)\b", runtime_text)
        )
        runtime_response_logged = has_runtime and bool(
            re.search(r"\b(response|returned|body|status|code)\b", runtime_text)
        )
        runtime_signal = has_runtime and bool(
            re.search(
                r"\b(sql|xss|ssrf|idor|csrf|rce|lfi|auth|forbidden|unauthorized|credential|token)\b",
                runtime_text,
            )
        )
        runtime_impact = has_runtime and bool(
            re.search(
                r"\b(admin|credential|password|token|dump|leak|record|rows?|session opened|meterpreter|shell|forbidden|unauthorized|error)\b",
                runtime_text,
            )
        )
        runtime_payload_bound = has_runtime and (
            not payload_markers
            or any(marker in runtime_text for marker in payload_markers[:8])
        )
        if has_runtime and not runtime_command_logged:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_command_logged"])
        if has_runtime and not runtime_response_logged:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_response_logged"])
        if has_runtime and not runtime_http:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_http"])
        if has_runtime and not runtime_signal:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_signal"])
        if has_runtime and not runtime_impact:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_impact"])
        if has_runtime and hosts and not runtime_host_bound:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_host_bound"])
        if has_runtime and payload_markers and not runtime_payload_bound:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_payload_bound"])

        artifact_bound = bool(
            re.search(r"\b(output/|artifact|log|trace|capture|pcap|json)\b", desc_lower)
            or (has_runtime and re.search(r"\b(output/|artifact|log|trace|capture)\b", runtime_text))
        )

        score = 0.0
        if request_logged:
            score += _REPLAY_SCORE_WEIGHTS["request_logged"]
        if response_logged:
            score += _REPLAY_SCORE_WEIGHTS["response_logged"]
        if target_bound:
            score += _REPLAY_SCORE_WEIGHTS["target_bound"]
        if payload_observed or not payload_markers:
            score += _REPLAY_SCORE_WEIGHTS["payload_observed"]
        if matching_finding:
            score += _REPLAY_SCORE_WEIGHTS["matching_finding"]
        if artifact_bound:
            score += _REPLAY_SCORE_WEIGHTS["artifact_bound"]

        if has_runtime:
            if runtime_http:
                score += _REPLAY_SCORE_WEIGHTS["runtime_http"]
            if runtime_signal:
                score += _REPLAY_SCORE_WEIGHTS["runtime_signal"]
            if runtime_impact:
                score += _REPLAY_SCORE_WEIGHTS["runtime_impact"]
            if runtime_host_bound or not hosts:
                score += _REPLAY_SCORE_WEIGHTS["runtime_host_bound"]
            if runtime_payload_bound:
                score += _REPLAY_SCORE_WEIGHTS["runtime_payload_bound"]
        else:
            # No runtime context available (unit tests/offline path):
            # slightly favor strong textual replay descriptions.
            if request_logged and response_logged and target_bound:
                score += _REPLAY_SCORE_WEIGHTS["no_runtime_text_bonus"]

        runtime_bound = (
            runtime_command_logged
            and runtime_response_logged
            and runtime_http
            and runtime_signal
            and runtime_impact
            and (runtime_host_bound or not hosts)
            and runtime_payload_bound
        ) if has_runtime else False
        return min(1.0, score), gaps, has_runtime, runtime_bound

    def _validate_tool_args(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, str | None]:
        if tool_name == "execute":
            cmd = arguments.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                return False, "'command' must be a non-empty string."
            if len(cmd) > 20_000:
                return False, f"'command' is too long ({len(cmd)} chars). Split into smaller calls."
            has_danger, danger_msg = has_dangerous_patterns(cmd)
            if has_danger:
                return False, f"Command rejected: {danger_msg}"

        elif tool_name == "browser_action":
            action = self._str_arg(arguments, "action")
            if action not in self._VALID_BROWSER_ACTIONS:
                return False, (
                    f"Invalid browser action '{action}'. "
                    f"Valid actions: {sorted(self._VALID_BROWSER_ACTIONS)}"
                )
            if action in ("goto", "new_tab") and not self._str_arg(arguments, "url").strip():
                return False, f"browser_action '{action}' requires a non-empty 'url'."
            if action == "click" and not self._str_arg(arguments, "coordinate").strip():
                return False, "browser_action 'click' requires 'coordinate' (format: 'x,y')."
            if action == "type" and not isinstance(arguments.get("text"), str):
                return False, "browser_action 'type' requires a 'text' string argument."
            if action == "switch_tab" and not self._str_arg(arguments, "tab_id").strip():
                return False, "browser_action 'switch_tab' requires 'tab_id'."
            if action == "press_key" and not self._str_arg(arguments, "key").strip():
                return False, "browser_action 'press_key' requires 'key'."

        elif tool_name == "web_search":
            if not self._str_arg(arguments, "query").strip():
                return False, "'query' must be a non-empty string."

        elif tool_name == "create_file":
            path_str = self._str_arg(arguments, "path")
            if not path_str.strip():
                return False, "'path' must be a non-empty string."
            if "content" not in arguments:
                return False, "'content' argument is required."
            # Block writing security reports as markdown files — must use
            # create_vulnerability_report
            path_lower = path_str.strip().lower()
            _REPORT_NAMES = (
                "final_report", "report", "vuln", "vulnerability", "finding",
                "assessment", "security_report", "pentest_report", "summary_report",
            )
            if path_lower.endswith(".md") and any(
                    r in path_lower for r in _REPORT_NAMES):
                return False, (
                    "BLOCKED: Writing vulnerability findings to a markdown file is FORBIDDEN. "
                    "Use create_vulnerability_report for each confirmed finding. "
                    "create_file is for scripts, wordlists, config, and tool output only — "
                    "never for security reports."
                )

        elif tool_name == "read_file":
            if not self._str_arg(arguments, "path").strip():
                return False, "'path' must be a non-empty string."
            if "offset" in arguments:
                try:
                    if int(arguments["offset"]) < 0:
                        return False, "'offset' must be >= 0."
                except (TypeError, ValueError):
                    return False, "'offset' must be an integer."
            if "limit" in arguments:
                try:
                    lim = int(arguments["limit"])
                    if lim < 1 or lim > 5000:
                        return False, "'limit' must be between 1 and 5000."
                except (TypeError, ValueError):
                    return False, "'limit' must be an integer."

        elif tool_name == "list_files":
            pass  # path is optional; defaults to target root

        elif tool_name in ("caido_send_request", "caido_automate"):
            host_raw = self._str_arg(arguments, "host").removeprefix("https://").removeprefix("http://").rstrip("/")
            if not host_raw.strip():
                return False, (
                    f"'{tool_name}' requires a non-empty 'host' (e.g. 'target.com', not a full URL)."
                )
            if tool_name == "caido_automate":
                if not self._str_arg(arguments, "raw_http").strip():
                    return False, "'caido_automate' requires 'raw_http' with §FUZZ§ marker."
                if not arguments.get("payloads"):
                    return False, "'caido_automate' requires a non-empty 'payloads' list."

        elif tool_name == "schemathesis_fuzz":
            if not self._str_arg(arguments, "schema_url").strip():
                return False, "'schema_url' is required for schemathesis_fuzz."
            raw_examples = arguments.get("max_examples")
            if raw_examples is not None:
                try:
                    int(raw_examples)
                except (TypeError, ValueError):
                    return False, (
                        f"'max_examples' must be an integer, got {type(raw_examples).__name__}."
                    )

        elif tool_name == "create_vulnerability_report":
            _phase_obj = self._get_current_phase() if hasattr(self, "_get_current_phase") else None
            _phase_str = (_phase_obj.value if _phase_obj is not None else None)
            if _phase_str is None:
                _phase_str = "RECON"
            _phase_str = _phase_str.upper()
            is_strict_phase = _phase_str in ("EXPLOIT", "REPORT")
            poc_code = self._str_arg(arguments, "poc_script_code").strip()
            poc_desc = self._str_arg(arguments, "poc_description").strip()
            title = self._str_arg(arguments, "title").strip()
            technical = self._str_arg(arguments, "technical_analysis").strip()
            is_ctf = bool(self._str_arg(arguments, "flag").strip())
            report_finding = (
                self._str_arg(arguments, "description").strip().lower()
                or poc_desc.lower()
                or title.lower()
            )

            matching_finding = False
            if hasattr(self, "_session") and self._session and self._session.vulnerabilities:
                for v in self._session.vulnerabilities:
                    vuln_finding = str(v.get("finding", "")).lower()
                    if report_finding and any(
                        w in vuln_finding for w in report_finding.split() if len(w) > 4
                    ):
                        matching_finding = True
                        break

            if not poc_code:
                return False, (
                    "REPORT REJECTED: 'poc_script_code' is empty. "
                    "Provide actual exploit code or a curl command demonstrating the vulnerability."
                )
            if len(poc_code) < 50:
                return False, (
                    f"REPORT REJECTED: 'poc_script_code' is too short ({len(poc_code)} chars). "
                    "Provide a real exploit: Python script, curl command, or HTTP request."
                )

            # Determine PoC type and validate structure accordingly
            poc_lower = poc_code.lower()
            _is_python = any(sig in poc_lower for sig in (
                "import ", "def ", "#!/usr/bin/env python", "#!/usr/bin/python",
                "requests.", "urllib", "http.client",
            ))
            _is_curl = poc_lower.lstrip().startswith("curl ")
            _is_php = "<?php" in poc_lower
            _is_js = any(sig in poc_lower for sig in ("fetch(", "xmlhttprequest", "require("))
            _is_bash = "#!/bin/bash" in poc_lower or "#!/bin/sh" in poc_lower

            if _is_python:
                # Validate Python syntax with ast.parse()
                try:
                    ast.parse(poc_code)
                except SyntaxError as syn_err:
                    return False, (
                        f"REPORT REJECTED: 'poc_script_code' is not valid Python — "
                        f"SyntaxError at line {syn_err.lineno}: {syn_err.msg}. "
                        "Fix the syntax or provide a curl command instead."
                    )
            elif not (_is_curl or _is_php or _is_js or _is_bash):
                # Fallback: must contain at least one concrete code indicator
                NON_PYTHON_INDICATORS = (
                    "curl ", "http", "payload", "exploit", "fetch(",
                    "<?php", "<script", "burp", "#!/", "request",
                )
                if not any(ind in poc_lower for ind in NON_PYTHON_INDICATORS):
                    return False, (
                        "REPORT REJECTED: 'poc_script_code' does not look like code. "
                        "It must be a Python script (with valid syntax), a curl command, "
                        "PHP/JS snippet, or an HTTP request."
                    )
            if not poc_desc or len(poc_desc) < 40:
                return False, (
                    f"REPORT REJECTED: 'poc_description' is too short ({len(poc_desc)} chars). "
                    "Provide step-by-step reproduction with specific URLs, parameters, and observed behavior."
                )
            # technical_analysis is only mandatory for full reports, not CTF.
            # Minimum 40 chars as hard gate; richer detail is handled by scoring.
            if not is_ctf and (not technical or len(technical) < 40):
                return False, (
                    f"REPORT REJECTED: 'technical_analysis' is too short ({len(technical)} chars). "
                    "Explain the root cause with specific technical details."
                )
            GENERIC_TITLES = (
                "vulnerability found", "security issue", "bug found", "potential",
                "possible", "issue detected", "security bug",
            )
            UNVERIFIED_PHRASES = (
                "further verification needed", "needs verification", "needs to be verified",
                "may be vulnerable", "could be vulnerable", "appears to be vulnerable",
                "potentially vulnerable", "might be vulnerable", "possible vulnerability",
                "note:", "unconfirmed", "not confirmed", "could not confirm",
                "needs more testing", "requires further", "needs further",
            )
            combined_text = (poc_desc + " " + technical).lower()
            for phrase in UNVERIFIED_PHRASES:
                if phrase in combined_text:
                    return False, (
                        f"REPORT REJECTED: Report contains unverified language: '{phrase}'. "
                        "Only submit findings you have CONFIRMED by observing actual exploitation impact. "
                        "Do not submit speculative or unverified findings."
                    )
            if "http" not in poc_code.lower() and "curl" not in poc_code.lower():
                return False, (
                    "REPORT REJECTED: 'poc_script_code' must include the actual target URL. "
                    "Show the real HTTP request that demonstrates the vulnerability."
                )

            # Subdomain-friendly PoC URL validation
            scope_valid = True
            if hasattr(self, '_session') and self._session:
                # Helper: check if string is IP address
                def _is_ip_address(host: str) -> bool:
                    parts = host.split('.')
                    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
                
                # Helper: extract base domain for flexible subdomain matching
                def _get_base_domain(host: str) -> str:
                    host = host.lower().split(':')[0]  # Remove port
                    if _is_ip_address(host):
                        return host  # IPs use exact match
                    parts = host.split('.')
                    return '.'.join(parts[-2:]) if len(parts) >= 2 else host
                
                poc_url_match = re.search(r"https?://([^\s/\"']+)", poc_code.lower())
                if poc_url_match:
                    poc_host = poc_url_match.group(1).split(':')[0]  # Remove port
                    session_hosts = [self._session.target] + list(self._session.live_hosts)

                    # For IP addresses: require exact match
                    if _is_ip_address(poc_host):
                        direct_match = poc_host in session_hosts
                        if not direct_match:
                            scope_valid = False
                            return False, (
                                f"REPORT REJECTED: PoC targets '{poc_host}' which is not in session scan scope. "
                                f"Session target: {self._session.target}. Live hosts: {', '.join(self._session.live_hosts[:5])}. "
                                "PoC must target the actual session target IP."
                            )
                    else:
                        # For domains: allow subdomain matching
                        poc_base = _get_base_domain(poc_host)
                        session_bases = [_get_base_domain(h) for h in session_hosts]
                        
                        # Also check direct substring match (for exact host matches)
                        direct_match = any(poc_host == h.split(':')[0] for h in session_hosts)
                        base_match = any(poc_base == s_base for s_base in session_bases)
                        
                        if not (direct_match or base_match):
                            scope_valid = False
                            return False, (
                                f"REPORT REJECTED: PoC targets '{poc_host}' which is not in session scan scope. "
                                f"Session target: {self._session.target}. Live hosts: {', '.join(self._session.live_hosts[:5])}. "
                                "PoC must target the actual session target or its subdomains."
                            )
            
            if not is_ctf:
                # Flexible HTTP evidence validation: allow both tool references
                # and descriptive observations.
                if not _HTTP_EVIDENCE_RE.search(poc_desc):
                    return False, (
                        "REPORT REJECTED: 'poc_description' must include actual HTTP response evidence. "
                        "Show the real status code and response data you observed, e.g.: "
                        "'GET /api/data → HTTP 200, response contained {user records}'. "
                        "A 301 redirect alone, or 'endpoint exists', is not sufficient — show what data/access was obtained."
                    )
                
                # Flexible tool output reference (allow descriptive observations)
                # Uses module-level _KNOWN_TOOLS (loaded once from tools_meta.json)
                _desc_lower = poc_desc.lower()
                has_tool_reference = (
                    "output/" in _desc_lower or          # References saved file
                    "session" in _desc_lower or           # References session data
                    "response" in _desc_lower or          # Describes actual response
                    "→" in poc_desc or                    # Arrow notation for request/response
                    "http " in _desc_lower or             # HTTP protocol mention
                    "observed" in _desc_lower or          # Descriptive observation
                    "received" in _desc_lower or
                    "got" in _desc_lower or
                    "server returned" in _desc_lower or
                    "response body" in _desc_lower or
                    "response contained" in _desc_lower or
                    any(tool in _desc_lower for tool in _KNOWN_TOOLS)  # Tool mention
                )
                if not has_tool_reference:
                    return False, (
                        "REPORT REJECTED: 'poc_description' must reference actual tool output or observed response data. "
                        "Reference the tool output file (e.g., 'output/nmap_scan.txt') or describe the actual response observed."
                    )

                # Gap #1: Require impact proof, not only status line.
                has_status_change = bool(_HTTP_EVIDENCE_PATTERNS["status_change"].search(poc_desc))
                has_content_proof = bool(_HTTP_EVIDENCE_PATTERNS["response_content"].search(poc_desc))
                has_error_or_data = bool(
                    _HTTP_EVIDENCE_PATTERNS["error_indicator"].search(poc_desc)
                    or _HTTP_EVIDENCE_PATTERNS["data_extraction"].search(poc_desc)
                )
                impact_proven = has_status_change or has_content_proof or has_error_or_data
                if not impact_proven:
                    return False, (
                        "REPORT REJECTED: HTTP status shown but exploitation impact not documented. "
                        "You must describe what the response contained or what changed. Examples: "
                        "'HTTP 200 containing admin panel buttons', "
                        "'HTTP 200 with SQL error message', "
                        "'Status changed from 403 (forbidden) to 200 (allowed)', "
                        "'Response leaked 50 user records'. "
                        "Do not submit 'HTTP 200' alone without explaining the impact."
                    )

            # Replay-verification gate: prioritize end-to-end reproducibility.
            replay_score, replay_gaps, has_runtime_context, runtime_bound = self._replay_verification_score(
                poc_code=poc_code,
                poc_desc=poc_desc,
                report_finding=report_finding,
                matching_finding=matching_finding,
            )
            if not is_ctf:
                if is_strict_phase and has_runtime_context and not runtime_bound:
                    gap_hint = "; ".join(dict.fromkeys(replay_gaps[:3])) if replay_gaps else (
                        "ensure PoC host/payload/status are present in runtime replay evidence"
                    )
                    return False, (
                        "REPORT REJECTED: Replay verification confidence too low. "
                        "Runtime replay evidence is not bound to this PoC. "
                        "In strict phases, reports must be proven on the same runtime trace "
                        "(host + payload + status/impact). "
                        f"Fix: {gap_hint}."
                    )
                replay_threshold = (
                    _REPLAY_THRESHOLDS["strict_with_runtime"]
                    if (is_strict_phase and has_runtime_context)
                    else (
                        _REPLAY_THRESHOLDS["strict_no_runtime"]
                        if is_strict_phase
                        else _REPLAY_THRESHOLDS["non_strict"]
                    )
                )
                if replay_score < replay_threshold:
                    gap_hint = "; ".join(dict.fromkeys(replay_gaps[:3])) if replay_gaps else "add clearer replay evidence"
                    return False, (
                        "REPORT REJECTED: Replay verification confidence too low "
                        f"({replay_score:.2f}/{replay_threshold:.2f}). "
                        "The report must prove an end-to-end exploit flow (request → payload → response → impact). "
                        f"Fix: {gap_hint}."
                    )

            # Quality gate: strict in EXPLOIT/REPORT, lenient in RECON/ANALYSIS.
            score = 0
            improvements: list[str] = []

            if len(poc_code) >= 120:
                score += 20
            elif len(poc_code) >= 80:
                score += 14
            else:
                improvements.append("expand PoC code with full request and payload details")

            if _is_python or _is_curl or _is_php or _is_js or _is_bash:
                score += 15
            else:
                improvements.append("use a concrete script/HTTP snippet format")

            if len(poc_desc) >= 120:
                score += 20
            elif len(poc_desc) >= 80:
                score += 14
            else:
                improvements.append("make reproduction steps more explicit")

            if is_ctf:
                score += 10
            elif len(technical) >= 120:
                score += 15
            elif len(technical) >= 80:
                score += 10
            else:
                improvements.append("expand root-cause analysis")

            if title and len(title) >= 15 and not any(g in title.lower() for g in GENERIC_TITLES):
                score += 10
            else:
                improvements.append("use a specific vulnerability title with endpoint/parameter")

            if scope_valid:
                score += 5

            if matching_finding:
                score += 10
            elif not is_strict_phase:
                score += 5
                improvements.append("link finding to session evidence when available")

            if not is_ctf and _HTTP_EVIDENCE_RE.search(poc_desc):
                score += 10
            if not is_ctf and impact_proven:
                score += 10
            if not is_ctf:
                score += int(replay_score * 20)
                if replay_score < 0.65:
                    improvements.append("perkuat replay verification (request/payload/response/impact)")

            if is_strict_phase and hasattr(self, "_session") and self._session and self._session.vulnerabilities:
                if not matching_finding and len(poc_code) < 200:
                    return False, (
                        "REPORT REJECTED: Vulnerability not found in session discoveries and PoC is too short. "
                        "Report tool-discovered findings, or provide a stronger manual PoC (>200 chars) with explicit evidence."
                    )

            threshold = 45 if is_ctf else (70 if is_strict_phase else 55)
            if score < threshold:
                hint = "; ".join(dict.fromkeys(improvements[:3]))
                return False, (
                    f"REPORT REJECTED: Report quality score too low ({score}/{threshold}) for {_phase_str} phase. "
                    + (f"Improve: {hint}." if hint else "Add stronger evidence and technical detail.")
                )

        return True, None
