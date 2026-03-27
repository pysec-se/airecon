"""Session persistence — save/load findings per session across runs.

Sessions are identified by a unique ID (unix_timestamp_randomhex), not by target name.
Each `airecon start` creates a new session. Use `airecon start --session <id>` to resume.

Storage: ~/.airecon/sessions/<session_id>.json
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, TypeVar
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .models import (
    CausalHypothesis,
    CausalIntervention,
    CausalState,
    jaccard_similarity,
)
from .output_parser import ParsedOutput
from .tuning import get_tuning

logger = logging.getLogger("airecon.agent.session")

SESSIONS_DIR = Path.home() / ".airecon" / "sessions"

# ---------------------------------------------------------------------------
# Memory limits for bounded collections
# ---------------------------------------------------------------------------
_MAX_SUBDOMAINS = 10000
_MAX_LIVE_HOSTS = 5000
_MAX_URLS = 50000
_MAX_VULNERABILITIES = 1000
_MAX_ATTACK_CHAINS = 100
_MAX_INJECTION_POINTS = 5000
_MAX_AUTH_COOKIES = 100
_MAX_AUTH_TOKENS = 50
_MAX_TESTED_ENDPOINTS = 500
_MAX_TOOLS_RUN = 1000
_MAX_CORRELATION_SUGGESTIONS = 200
_MAX_COMPLETED_PHASES = 10

T = TypeVar("T")


class BoundedList(list[T]):
    """List with max length that drops oldest entries first."""

    __slots__ = ("maxlen",)

    def __init__(self, values: Iterable[T] = (), maxlen: int | None = None) -> None:
        self.maxlen = maxlen
        super().__init__(values)
        self._trim()

    def _trim(self) -> None:
        if self.maxlen is not None and self.maxlen >= 0 and len(self) > self.maxlen:
            del self[: len(self) - self.maxlen]

    def append(self, value: T) -> None:
        super().append(value)
        self._trim()

    def extend(self, values: Iterable[T]) -> None:
        super().extend(values)
        self._trim()

    def insert(self, index: int, value: T) -> None:
        super().insert(index, value)
        self._trim()

    def __iadd__(self, values: Iterable[T]):  # type: ignore[override]
        result = super().__iadd__(values)
        self._trim()
        return result

    def __setitem__(self, key, value):  # type: ignore[override]
        super().__setitem__(key, value)
        self._trim()


_DEQUE_SERIALIZED_RE = re.compile(
    r"""^deque\((\[[\s\S]*\])(?:,\s*maxlen=\d+)?\)$"""
)


def _coerce_sequence_field(
    value: Any,
    *,
    field_name: str,
    maxlen: int,
) -> BoundedList[Any]:
    """Normalize session collection fields from list/deque/legacy-string to BoundedList."""
    if isinstance(value, BoundedList):
        return BoundedList(value, maxlen=maxlen)
    if value is None:
        return BoundedList(maxlen=maxlen)
    if isinstance(value, list):
        return BoundedList(value, maxlen=maxlen)
    if isinstance(value, tuple):
        return BoundedList(list(value), maxlen=maxlen)
    if isinstance(value, str):
        text = value.strip()
        m = _DEQUE_SERIALIZED_RE.match(text)
        if m:
            text = m.group(1)
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, list):
                return BoundedList(parsed, maxlen=maxlen)
            if isinstance(parsed, tuple):
                return BoundedList(list(parsed), maxlen=maxlen)
        except Exception:
            logger.warning(
                "Failed to parse legacy %s field value; resetting to empty.",
                field_name,
            )
        return BoundedList(maxlen=maxlen)
    try:
        return BoundedList(list(value), maxlen=maxlen)
    except Exception:
        logger.warning(
            "Unsupported %s field type %s; resetting to empty.",
            field_name,
            type(value).__name__,
        )
        return BoundedList(maxlen=maxlen)


def _coerce_non_negative_int(value: Any, default: int = 0) -> int:
    """Parse integer values safely and clamp negative numbers."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


# ---------------------------------------------------------------------------
# Injection point extraction
# ---------------------------------------------------------------------------

# UUID v4 pattern for path segment detection
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Analytics/tracking parameters that are never injection points.
# Including them as IDOR/INJECT creates false positives that waste agent time.
_TRACKING_PARAMS: frozenset[str] = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_reader", "utm_name",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "twclid",
    "mc_cid", "mc_eid",
    "_ga", "_gl", "_hsenc", "_hsmi",
    "ref", "referrer", "source", "medium", "campaign",
})

# Numeric values that look like IDs but are actually common false positives.
# Exact-match set for O(1) lookup before the regex heuristic fires.
_NUMERIC_FP_VALUES: frozenset[str] = frozenset({
    # Common HTTP ports
    "80", "443", "8080", "8443", "8000", "8888", "3000", "4000", "5000",
    "9000", "9090", "3306", "5432", "6379", "27017",
    # HTTP status codes (100-599)
    *[str(s) for s in range(100, 600)],
    # Calendar years (reasonable range)
    *[str(y) for y in range(1990, 2035)],
})

# Canonical param→attack-type mapping, loaded from fuzzer_data.json.
# Fallback is empty dict — _guess_injection_type still works via heuristics.
def _load_param_type_map() -> dict[str, str]:
    """Build flat {param_lower: TYPE} dict from fuzzer_data.json PARAM_TYPE_MAP."""
    try:
        data_file = Path(__file__).parent.parent / "data" / "fuzzer_data.json"
        data = json.loads(data_file.read_text(encoding="utf-8"))
        result: dict[str, str] = {}
        for attack_type, params in data.get("PARAM_TYPE_MAP", {}).items():
            for param in params:
                result[param.lower()] = attack_type
        return result
    except Exception as e:
        logger.debug("Could not load PARAM_TYPE_MAP from fuzzer_data.json: %s", e)
        return {}


_PARAM_TYPE_MAP: dict[str, str] = _load_param_type_map()


def _load_redirect_path_indicators() -> frozenset[str]:
    """Load open-redirect path indicators from patterns.json.

    When a URL-accepting parameter (type=SSRF) sits on an endpoint whose PATH
    contains one of these words, the actual risk is open redirect, not SSRF.
    Example: /api/frontendweb.aredirurl?url=... → url param should be OPEN_REDIRECT.
    """
    try:
        data_file = Path(__file__).parent.parent / "data" / "patterns.json"
        data = json.loads(data_file.read_text(encoding="utf-8"))
        indicators: list[str] = data.get("open_redirect_url_param", {}).get("indicators", [])
        return frozenset(ind.lower() for ind in indicators if ind)
    except Exception as e:
        logger.debug("Could not load redirect path indicators from patterns.json: %s", e)
        return frozenset()


_REDIRECT_PATH_INDICATORS: frozenset[str] = _load_redirect_path_indicators()


def _guess_injection_type(param: str, value: str) -> str:
    """Infer the most likely injection type from parameter name and sample value.

    Lookup order:
    1. Canonical map from fuzzer_data.json PARAM_TYPE_MAP
    2. camelCase normalisation (userId → user_id)
    3. Regex suffix patterns (_id suffix → IDOR)
    4. Numeric/UUID value heuristic
    """
    p = param.lower().rstrip("[]")
    if p in _PARAM_TYPE_MAP:
        return _PARAM_TYPE_MAP[p]
    # Normalise camelCase: userId → user_id
    p_norm = re.sub(r"([a-z])([A-Z])", r"\1_\2", param).lower().rstrip("[]")
    if p_norm in _PARAM_TYPE_MAP:
        return _PARAM_TYPE_MAP[p_norm]
    # Suffix/prefix heuristics
    if re.search(r"_id$|^id_|id$", p):
        return "IDOR"
    # Numeric value heuristic — only flag as IDOR when value looks like a real
    # resource ID (4-10 digits) AND is NOT a known false positive (port numbers,
    # HTTP status codes, calendar years).
    if value and re.match(r"^\d{4,10}$", value) and value not in _NUMERIC_FP_VALUES:
        return "IDOR"
    return "INJECT"


def _extract_injection_points(url: str) -> list[dict[str, Any]]:
    """Extract testable injection point candidates from a URL.

    Detects:
    - Query string parameters (?id=1&user=admin)
    - Numeric / UUID path segments (/users/123, /items/uuid)

    Returns a list of dicts with keys: url, parameter, method, value_sample,
    type_hint.
    """
    points: list[dict[str, Any]] = []
    try:
        p = urlparse(url)
        # Only process http/https URLs — skip javascript:, data:, ftp:, etc.
        if p.scheme not in ("http", "https"):
            return points
        # Normalize base so dedup keys are consistent regardless of case or
        # trailing slash variations (e.g. /api/users/ == /api/users).
        base = urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            p.path.rstrip("/") or "/",
            "", "", "",
        ))

        # Pre-compute whether this endpoint's path indicates redirect behaviour.
        # Used to upgrade SSRF-typed URL params to OPEN_REDIRECT when the path
        # context reveals the parameter is used for redirecting, not fetching.
        _path_lower = p.path.lower()
        _path_is_redirect = any(ind in _path_lower for ind in _REDIRECT_PATH_INDICATORS)

        # Query string parameters — skip pure analytics/tracking params that
        # are never injection points and only inflate the injection_points list.
        for param, value in parse_qsl(p.query, keep_blank_values=True):
            if param.lower() in _TRACKING_PARAMS:
                continue
            type_hint = _guess_injection_type(param, value)
            # Reclassify SSRF → OPEN_REDIRECT when the endpoint path signals
            # redirect behaviour (e.g. /frontendweb.aredirurl?url=...).
            # URL-accepting parameters on redirect endpoints should be tested
            # with javascript:, //attacker.com etc., not with cloud metadata.
            if type_hint == "SSRF" and _path_is_redirect:
                type_hint = "OPEN_REDIRECT"
            points.append({
                "url": base,
                "parameter": param,
                "method": "GET",
                "value_sample": value[:30] if value else "",
                "type_hint": type_hint,
            })

        # Path segments that look like IDs (numeric or UUID).
        # Use the full URL so the LLM knows the complete endpoint context
        # (e.g. /api/users/123/orders — the ID belongs to 'users', and
        # /orders shows what sub-resource is being accessed).
        path_parts = [x for x in p.path.strip("/").split("/") if x]
        for i, seg in enumerate(path_parts):
            if re.match(r"^\d{1,10}$", seg) or _UUID_RE.match(seg):
                # Label: parent-resource/ID so the LLM knows which resource owns this ID
                parent = path_parts[i - 1] if i > 0 else ""
                param_label = f"path/{parent}/{seg}" if parent else f"path/{seg}"
                points.append({
                    "url": base,  # full URL preserves sub-resource context
                    "parameter": param_label,
                    "method": "GET",
                    "value_sample": seg,
                    "type_hint": "IDOR",
                })
    except Exception as _e:
        logger.debug("_extract_injection_points path traversal error: %s", _e)
    return points


def injection_point_key(url: str, parameter: str, method: str = "GET") -> str:
    """Build a stable string key for an injection point triple.

    The URL is normalized (lowercase scheme/host, trailing slash stripped,
    query params sorted) so that /api/ and /api produce the same key.
    """
    normalized = _normalize_url(url) if url else url
    return f"{normalized}||{parameter}||{method.upper()}"


def mark_injection_point_tested(session: "SessionData", url: str, parameter: str, method: str = "GET") -> None:
    """Mark an injection point as tested so the agent won't re-test it."""
    key = injection_point_key(url, parameter, method)
    if key not in session.tested_injection_points:
        session.tested_injection_points.append(key)


def get_untested_injection_points(session: "SessionData") -> list[dict[str, Any]]:
    """Return injection points that have NOT been tested yet this session."""
    tested_set = set(session.tested_injection_points)
    return [
        pt for pt in session.injection_points
        if injection_point_key(
            pt.get("url", ""), pt.get("parameter", ""), pt.get("method", "GET")
        ) not in tested_set
    ]


def _merge_injection_points(
    session_points: list[dict[str, Any]],
    new_points: list[dict[str, Any]],
) -> None:
    """Append new injection points to session list, skipping exact duplicates.

    Dedup key: (url, parameter, method) — mutates session_points in-place.
    """
    existing = {
        (p["url"], p["parameter"], p["method"])
        for p in session_points
    }
    for pt in new_points:
        key = (pt["url"], pt["parameter"], pt["method"])
        if key not in existing:
            session_points.append(pt)
            existing.add(key)


def generate_session_id() -> str:
    """Generate a unique session ID: <unix_timestamp>_<8_random_hex>.

    Example: 1740842400_a3b4c5d6
    """
    return f"{int(time.time())}_{uuid.uuid4().hex[:8]}"


def _normalize_url(url: str) -> str:
    """Normalize a URL for deduplication.

    - Lowercase scheme and host
    - Sort query parameters alphabetically
    - Strip URL fragment (#...)
    - Strip trailing slash from path (except root "/")

    Returns the original string unchanged if parsing fails.
    """
    try:
        p = urlparse(url)
        query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
        return urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            p.path.rstrip("/"),
            p.params,
            query,
            "",  # strip fragment
        ))
    except Exception:
        return url


def _calculate_similarity(v1: str, v2: str) -> float:
    """Calculate similarity between two vulnerability strings using simple approach."""
    v1_lower = v1.lower()
    v2_lower = v2.lower()

    # Two empty strings are technically identical but represent nothing — do not
    # treat as duplicates, as this would silently drop any second report with
    # an empty finding field.
    if not v1_lower or not v2_lower:
        return 0.0

    if v1_lower == v2_lower:
        return 1.0

    # Extract parameter context to avoid false dedup of diff params
    param_re = re.compile(
        r"(?:[?&]([a-z0-9_\[\]\-]+)=|parameter\s+['\"]?([a-z0-9_\[\]\-]+)['\"]?)")
    m1 = param_re.search(v1_lower)
    m2 = param_re.search(v2_lower)

    if m1 and m2:
        p1 = m1.group(1) or m1.group(2)
        p2 = m2.group(1) or m2.group(2)
        if p1 and p2 and p1 != p2:
            return 0.0  # Different targeted parameters = NOT duplicate

    # Token-overlap (Jaccard) similarity — shared with evidence dedup in models.py
    return jaccard_similarity(v1_lower, v2_lower)


def _is_duplicate_vulnerability(
        new_vuln: dict, existing_vulns: list[dict]) -> bool:
    """Check if a vulnerability is a duplicate of an existing one.

    Uses vuln_similarity_threshold from config (default: 0.7).
    
    Returns True (is duplicate) if:
    - new_vuln has empty finding field (invalid)
    - finding matches existing vulnerability by similarity threshold
    """
    try:
        from ..config import get_config
        threshold = get_config().vuln_similarity_threshold
    except Exception:
        from ..config import DEFAULT_CONFIG
        threshold = DEFAULT_CONFIG["vuln_similarity_threshold"]

    new_finding = new_vuln.get("finding", "")
    new_target = new_vuln.get("target", "")
    
    # FIX #1 (Critical): Reject empty findings immediately to prevent
    # silent data loss. Empty findings cannot be meaningfully deduplicated.
    if not new_finding or not str(new_finding).strip():
        logger.warning(
            "Skipping vulnerability with empty finding field: %s",
            new_vuln.get("source", "unknown")
        )
        return True  # Treat as duplicate to prevent adding invalid entry

    for existing in existing_vulns:
        existing_finding = existing.get("finding", "")
        existing_target = existing.get("target", "")
        
        # Skip empty existing findings (shouldn't happen, but defensive check)
        if not existing_finding or not str(existing_finding).strip():
            continue

        # Check finding similarity — _calculate_similarity already returns 0.0
        # when the two findings mention different URL parameters, preventing
        # false deduplication of findings on different parameters.
        finding_sim = _calculate_similarity(new_finding, existing_finding)

        # Check target similarity (if both have targets)
        target_sim = 1.0 if new_target == existing_target else 0.0

        # Combined similarity
        combined_sim = (finding_sim * 0.8) + (target_sim * 0.2)

        if combined_sim >= threshold:
            return True

    return False


@dataclass
class ApplicationModel:
    """Incrementally-built structural model of the target application.

    Populated from HTTP responses observed during RECON/ANALYSIS phases.
    Gives the LLM a persistent mental map of the app without re-reading
    raw tool outputs from history.

    Resources       — {endpoint: {methods, param_names, auth_required, content_type}}
    auth_map        — {endpoint_pattern: "none"|"cookie"|"bearer"|"basic"|"apikey"}
    param_relationships — {param_name: [related_params]}
    roles_detected  — distinct user roles observed (admin, user, guest, ...)
    api_schema      — discovered JSON keys per endpoint (from responses)
    """

    resources: dict[str, dict[str, Any]] = field(default_factory=dict)
    auth_map: dict[str, str] = field(default_factory=dict)
    param_relationships: dict[str, list[str]] = field(default_factory=dict)
    roles_detected: list[str] = field(default_factory=list)
    api_schema: dict[str, dict[str, Any]] = field(default_factory=dict)

    def update_from_response(
        self,
        url: str,
        method: str,
        status_code: int,
        headers: dict[str, str],
        body_excerpt: str,
        param_names: list[str] | None = None,
    ) -> None:
        """Incrementally update application model from a single HTTP observation."""
        try:
            parsed = urlparse(url)
            endpoint = parsed.path.rstrip("/") or "/"
        except Exception:
            endpoint = url

        # Update resources map
        entry = self.resources.setdefault(endpoint, {
            "methods": [],
            "param_names": [],
            "auth_required": False,
            "content_types": [],
        })
        if method.upper() not in entry["methods"]:
            entry["methods"].append(method.upper())

        for p in (param_names or []):
            if p and p not in entry["param_names"]:
                entry["param_names"].append(p)

        # Auth detection from response headers
        auth_header = headers.get("www-authenticate", headers.get("WWW-Authenticate", ""))
        set_cookie = headers.get("set-cookie", headers.get("Set-Cookie", ""))
        auth_header_val = headers.get("authorization", headers.get("Authorization", ""))

        if status_code == 401:
            entry["auth_required"] = True
            if "bearer" in auth_header.lower():
                self.auth_map[endpoint] = "bearer"
            elif "basic" in auth_header.lower():
                self.auth_map[endpoint] = "basic"
            else:
                self.auth_map[endpoint] = "auth_required"
        elif set_cookie and "session" in set_cookie.lower():
            self.auth_map[endpoint] = "cookie"
        elif "bearer" in auth_header_val.lower():
            self.auth_map[endpoint] = "bearer"

        # Content type
        ct = headers.get("content-type", headers.get("Content-Type", ""))
        if ct and ct not in entry["content_types"]:
            entry["content_types"].append(ct.split(";")[0].strip())

        # Role detection from response body
        if body_excerpt:
            body_lower = body_excerpt.lower()
            for role in ("admin", "superuser", "moderator", "staff", "manager"):
                if role in body_lower and role not in self.roles_detected:
                    self.roles_detected.append(role)

        # API schema: extract top-level JSON keys from body if it looks like JSON
        if "application/json" in ct and body_excerpt.strip().startswith("{"):
            try:
                obj = json.loads(body_excerpt[:2000])
                if isinstance(obj, dict):
                    schema = self.api_schema.setdefault(endpoint, {})
                    schema.update({k: type(v).__name__ for k, v in obj.items()})
            except Exception:
                pass

        # Prune resources if exceeding limits (keep most recent 500 endpoints)
        if len(self.resources) > 500:
            excess = list(self.resources.keys())[:-500]
            for k in excess:
                del self.resources[k]

    def build_context(self, max_endpoints: int = 8) -> str:
        """Return a compact XML summary of the application model for LLM injection."""
        if not self.resources and not self.roles_detected:
            return ""

        lines = ['<application_model>']
        if self.resources:
            # Prioritize endpoints that need auth or have params
            interesting = sorted(
                self.resources.items(),
                key=lambda kv: (
                    -len(kv[1].get("param_names", [])),
                    -int(kv[1].get("auth_required", False)),
                ),
            )[:max_endpoints]
            lines.append("  <endpoints>")
            for ep, info in interesting:
                methods_str = ",".join(info.get("methods", ["GET"]))
                params = info.get("param_names", [])
                params_str = f" params=[{','.join(params[:5])}]" if params else ""
                auth = " auth=required" if info.get("auth_required") else ""
                auth_type = self.auth_map.get(ep, "")
                auth_type_str = f"({auth_type})" if auth_type else ""
                lines.append(
                    f'    <endpoint path="{ep}" methods="{methods_str}"'
                    f'{auth}{auth_type_str}{params_str}/>'
                )
            lines.append("  </endpoints>")

        if self.roles_detected:
            lines.append(f"  <roles>{', '.join(self.roles_detected)}</roles>")

        if self.api_schema:
            for ep, schema in list(self.api_schema.items())[:3]:
                keys_str = ", ".join(list(schema.keys())[:10])
                lines.append(f'  <api_schema endpoint="{ep}" keys="{keys_str}"/>')

        lines.append('</application_model>')
        return "\n".join(lines)


def _serialize_app_model(model: ApplicationModel) -> dict[str, Any]:
    """Serialize ApplicationModel to JSON-safe dict."""
    return {
        "resources": dict(model.resources),
        "auth_map": dict(model.auth_map),
        "roles_detected": list(model.roles_detected),
        "api_schema": dict(model.api_schema),
    }


def _deserialize_app_model(raw: Any) -> ApplicationModel:
    """Deserialize ApplicationModel from persisted payload."""
    model = ApplicationModel()
    if not isinstance(raw, dict):
        return model
    resources = raw.get("resources", {})
    auth_map = raw.get("auth_map", {})
    roles = raw.get("roles_detected", [])
    api_schema = raw.get("api_schema", {})
    if isinstance(resources, dict):
        model.resources = resources
    if isinstance(auth_map, dict):
        model.auth_map = {str(k): str(v) for k, v in auth_map.items()}
    if isinstance(roles, list):
        model.roles_detected = [str(r) for r in roles]
    if isinstance(api_schema, dict):
        model.api_schema = api_schema
    return model


def _serialize_causal_state(state: CausalState) -> dict[str, Any]:
    """Serialize CausalState to JSON-safe dict."""
    return state.to_dict() if isinstance(state, CausalState) else CausalState().to_dict()


def _deserialize_causal_state(raw: Any) -> CausalState:
    """Deserialize CausalState from persisted payload."""
    if isinstance(raw, dict):
        return CausalState.from_dict(raw)
    return CausalState()


def _coerce_unit_float(value: Any, default: float = 0.0) -> float:
    """Parse float safely and clamp to [0.0, 1.0]."""
    try:
        return max(0.0, min(float(value), 1.0))
    except (TypeError, ValueError):
        return default


class _SafeFormatDict(dict[str, str]):
    """String formatter map that returns an empty string for missing keys."""

    def __missing__(self, key: str) -> str:
        return ""


_DEFAULT_CAUSAL_HYPOTHESIS_RULES: list[dict[str, Any]] = [
    {
        "observation_type": "endpoint_accessible",
        "id_prefix": "endpoint_access",
        "statement_template": "Reachable endpoint {entity} may expose actionable attack surface.",
        "prior": 0.50,
        "evidence_weight": 0.30,
        "allow_support": True,
    },
    {
        "observation_type": "service_exposed",
        "id_prefix": "service_exposure",
        "statement_template": "Exposed service on {entity}:{value} should be tested for service-level abuse.",
        "prior": 0.48,
        "evidence_weight": 0.32,
        "allow_support": True,
    },
    {
        "observation_type": "technology_detected",
        "id_prefix": "tech_risk",
        "statement_template": "Detected technology {entity} {value} may contain version-specific weaknesses.",
        "prior": 0.45,
        "evidence_weight": 0.26,
        "allow_support": True,
    },
    {
        "observation_type": "vulnerability_signal",
        "id_prefix": "vuln_signal",
        "statement_template": "Vulnerability signal from {source_tool} against {entity} should be replay-validated.",
        "prior": 0.56,
        "evidence_weight": 0.36,
        "allow_support": True,
    },
]


def _load_causal_hypothesis_rules() -> list[dict[str, Any]]:
    """Load causal-hypothesis rules from tuning with strict shape checks."""
    raw_rules = get_tuning(
        "causal_reasoning.hypothesis_rules",
        _DEFAULT_CAUSAL_HYPOTHESIS_RULES,
    )
    if not isinstance(raw_rules, list):
        return list(_DEFAULT_CAUSAL_HYPOTHESIS_RULES)

    rules: list[dict[str, Any]] = []
    for raw in raw_rules:
        if not isinstance(raw, dict):
            continue
        obs_type = str(raw.get("observation_type", "")).strip().lower()
        id_prefix = str(raw.get("id_prefix", "")).strip().lower() or obs_type
        template = str(raw.get("statement_template", "")).strip()
        if not obs_type or not template:
            continue
        rules.append(
            {
                "observation_type": obs_type,
                "id_prefix": id_prefix[:40],
                "statement_template": template[:320],
                "prior": _coerce_unit_float(raw.get("prior", 0.5), 0.5),
                "evidence_weight": _coerce_unit_float(
                    raw.get("evidence_weight", 0.3), 0.3
                ),
                "allow_support": bool(raw.get("allow_support", True)),
            }
        )
    return rules or list(_DEFAULT_CAUSAL_HYPOTHESIS_RULES)


_CAUSAL_HYPOTHESIS_RULES = _load_causal_hypothesis_rules()
_CAUSAL_SUPPORT_THRESHOLD = _coerce_unit_float(
    get_tuning("causal_reasoning.support_threshold", 0.72),
    0.72,
)
_CAUSAL_REFUTE_THRESHOLD = _coerce_unit_float(
    get_tuning("causal_reasoning.refute_threshold", 0.20),
    0.20,
)


def _stable_causal_hypothesis_id(id_prefix: str, entity: str, attribute: str) -> str:
    seed = f"{id_prefix}|{entity.strip().lower()}|{attribute.strip().lower()}"
    digest = hashlib.sha1(
        seed.encode("utf-8", errors="replace"), usedforsecurity=False
    ).hexdigest()[:12]
    return f"{id_prefix}_{digest}"


def _build_causal_context_block(
    state: CausalState,
    *,
    max_observations: int = 6,
    max_hypotheses: int = 6,
    max_interventions: int = 3,
) -> str:
    """Build concise causal reasoning context for prompt injection."""
    if not isinstance(state, CausalState):
        return ""
    if not state.observations and not state.hypotheses and not state.interventions:
        return ""

    lines = [
        (
            f"<causal_reasoning observations=\"{len(state.observations)}\" "
            f"hypotheses=\"{len(state.hypotheses)}\" "
            f"interventions=\"{len(state.interventions)}\">"
        )
    ]

    if state.observations:
        lines.append("  <recent_observations>")
        for obs in state.observations[-max_observations:]:
            value = f"={obs.value}" if obs.value else ""
            attribute = f" {obs.attribute}{value}" if obs.attribute else ""
            lines.append(
                f"    - [{obs.observation_type}] {obs.entity}{attribute} "
                f"(conf={obs.confidence:.0%})"
            )
        lines.append("  </recent_observations>")

    if state.hypotheses:
        ranked = sorted(
            state.hypotheses,
            key=lambda h: (h.status == "supported", h.posterior),
            reverse=True,
        )[:max_hypotheses]
        lines.append("  <top_hypotheses>")
        for hyp in ranked:
            lines.append(
                f"    - [{hyp.status.upper()} {hyp.posterior:.0%}] {hyp.statement}"
            )
        lines.append("  </top_hypotheses>")

    if state.interventions:
        lines.append("  <recent_interventions>")
        for iv in state.interventions[-max_interventions:]:
            status = "success" if iv.success else "unknown" if iv.success is None else "failed"
            lines.append(
                f"    - [{status}] {iv.action[:120]} => {iv.observed_effect[:120]}"
            )
        lines.append("  </recent_interventions>")

    lines.append(
        "  <instruction>Use supported hypotheses as priority targets and choose next tests that disambiguate pending hypotheses.</instruction>"
    )
    lines.append("</causal_reasoning>")
    return "\n".join(lines)


def _update_causal_hypotheses_from_observation(
    session: "SessionData",
    observation: dict[str, Any],
) -> None:
    """Map a structured observation to posterior updates on causal hypotheses."""
    state = session.causal_state
    obs_type = str(observation.get("observation_type", "")).strip().lower()
    if not obs_type:
        return
    entity = str(observation.get("entity", "")).strip()
    attribute = str(observation.get("attribute", "")).strip()
    value = str(observation.get("value", "")).strip()
    source_tool = str(observation.get("source_tool", "")).strip()
    evidence = str(observation.get("evidence", "")).strip()[:180]
    confidence = _coerce_unit_float(observation.get("confidence", 0.5), 0.5)
    if not entity:
        return

    for rule in _CAUSAL_HYPOTHESIS_RULES:
        if rule.get("observation_type") != obs_type:
            continue
        id_prefix = str(rule.get("id_prefix", obs_type)).strip().lower() or obs_type
        hyp_id = _stable_causal_hypothesis_id(id_prefix, entity, attribute)

        current = next(
            (h for h in state.hypotheses if h.hypothesis_id == hyp_id),
            None,
        )
        prior = _coerce_unit_float(rule.get("prior", 0.5), 0.5)
        old_post = current.posterior if current else prior
        blend = _coerce_unit_float(rule.get("evidence_weight", 0.3), 0.3)
        new_post = max(0.0, min(old_post + ((confidence - old_post) * blend), 1.0))

        status = current.status if current else "pending"
        if bool(rule.get("allow_support", True)) and new_post >= _CAUSAL_SUPPORT_THRESHOLD:
            status = "supported"
        elif new_post <= _CAUSAL_REFUTE_THRESHOLD:
            status = "refuted"
        elif status not in {"supported", "refuted"}:
            status = "pending"

        refs = list(current.evidence_refs) if current else []
        if evidence:
            ref = f"{obs_type}:{evidence}"
            if ref not in refs:
                refs.append(ref)
        refs = refs[-30:]

        statement_template = str(rule.get("statement_template", "{entity}"))
        statement = statement_template.format_map(
            _SafeFormatDict(
                {
                    "entity": entity,
                    "attribute": attribute,
                    "value": value,
                    "source_tool": source_tool,
                    "observation_type": obs_type,
                }
            )
        ).strip()
        if not statement:
            statement = f"{obs_type} observed on {entity}"

        state.upsert_hypothesis(
            CausalHypothesis(
                hypothesis_id=hyp_id,
                statement=statement[:320],
                prior=prior,
                posterior=new_post,
                status=status,
                evidence_refs=refs,
            )
        )
        state.add_edge(
            {
                "cause": f"obs:{obs_type}:{entity[:80]}",
                "effect": f"hyp:{hyp_id}",
                "relation": "supports" if confidence >= 0.5 else "weakens",
                "confidence": confidence,
            }
        )


def _record_causal_intervention_from_parse(
    session: "SessionData",
    command: str,
    parsed: ParsedOutput,
    observations: list[dict[str, Any]],
) -> None:
    """Persist action→effect links from parser output as interventions."""
    state = session.causal_state
    cmd = str(command or "").strip()
    if not cmd or not observations:
        return

    meaningful = [
        obs
        for obs in observations
        if str(obs.get("observation_type", "")).strip().lower() != "tool_output_observed"
    ]
    if not meaningful:
        return

    iv_id = (
        f"iv_{session.scan_count}_"
        f"{hashlib.sha1(cmd.encode('utf-8', errors='replace'), usedforsecurity=False).hexdigest()[:8]}"
    )
    avg_conf = sum(
        _coerce_unit_float(obs.get("confidence", 0.5), 0.5) for obs in meaningful
    ) / max(1, len(meaningful))
    target = str(meaningful[0].get("entity", "")).strip() or parsed.tool
    observed_effect = parsed.summary or str(meaningful[0].get("evidence", ""))[:160]
    success = bool(parsed.total_count or parsed.items)

    state.add_intervention(
        CausalIntervention(
            intervention_id=iv_id,
            action=cmd[:180],
            target=target[:120],
            expected_effect="Collect falsifiable evidence",
            observed_effect=str(observed_effect)[:220],
            success=success,
            confidence=max(0.0, min(avg_conf, 1.0)),
        )
    )
    for obs in meaningful[:4]:
        obs_type = str(obs.get("observation_type", "")).strip().lower()
        entity = str(obs.get("entity", "")).strip()
        if not obs_type or not entity:
            continue
        state.add_edge(
            {
                "cause": f"iv:{iv_id}",
                "effect": f"obs:{obs_type}:{entity[:80]}",
                "relation": "influences",
                "confidence": avg_conf,
            }
        )


@dataclass
class SessionData:
    """Persistent per-session state, identified by a unique session_id."""

    # Session identity
    session_id: str = ""
    target: str = ""

    # Findings
    subdomains: list[str] = field(default_factory=lambda: BoundedList(maxlen=_MAX_SUBDOMAINS))
    live_hosts: list[str] = field(default_factory=lambda: BoundedList(maxlen=_MAX_LIVE_HOSTS))
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    urls: list[str] = field(default_factory=lambda: BoundedList(maxlen=_MAX_URLS))
    technologies: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=lambda: BoundedList(maxlen=_MAX_VULNERABILITIES))
    attack_chains: list[dict[str, Any]] = field(default_factory=lambda: BoundedList(maxlen=_MAX_ATTACK_CHAINS))
    completed_phases: list[str] = field(default_factory=lambda: BoundedList(maxlen=_MAX_COMPLETED_PHASES))
    current_phase: str = "RECON"
    tools_run: list[str] = field(default_factory=lambda: BoundedList(maxlen=_MAX_TOOLS_RUN))
    scan_count: int = 0
    created_at: str = ""
    updated_at: str = ""

    # Token accounting (session cumulative)
    token_total: int = 0
    token_prompt_total: int = 0
    token_completion_total: int = 0
    token_last_used: int = 0

    # Injection points discovered during ANALYSIS phase.
    # Each entry: {url, parameter, method, value_sample, type_hint}
    # Populated automatically from URLs by update_from_parsed_output().
    # The EXPLOIT phase uses this list to target specific parameters.
    injection_points: list[dict[str, Any]] = field(default_factory=lambda: BoundedList(maxlen=_MAX_INJECTION_POINTS))

    # Browser auth state (persisted so re-runs skip re-login)
    auth_cookies: list[dict[str, Any]] = field(default_factory=lambda: BoundedList(maxlen=_MAX_AUTH_COOKIES))
    auth_tokens: dict[str, str] = field(default_factory=dict)
    auth_type: str = ""  # "form", "totp", "oauth", "cookie"

    # Tracks which injection points have already been tested this session.
    # Key format: "<url>||<parameter>||<method>" — exact dedup to prevent
    # re-testing the same (url, param, method) triple across iterations.
    # Populated by loop.py after execute/quick_fuzz/advanced_fuzz tool calls.
    tested_injection_points: list[str] = field(default_factory=lambda: BoundedList(maxlen=_MAX_TESTED_ENDPOINTS * 2))
    # Transient flag: True after prior-session findings have been merged this run.
    # Stored in JSON so it survives a session reload and prevents duplicate merges.
    _prior_merged: bool = field(default=False)

    # Dedup set for correlation engine suggestions: stores fingerprints of
    # chains/patterns already injected into context this session so the
    # correlation engine doesn't repeat the same hints every 10 iterations.
    # Format: "<type>:<key>" e.g. "port:80", "technology:wordpress",
    # "expert_test:idor_hotspot", "attack_chain:XSS → CSRF"
    suggested_correlations: list[str] = field(default_factory=lambda: BoundedList(maxlen=_MAX_CORRELATION_SUGGESTIONS))

    # Endpoints that have been actively tested this session.
    # Format: "METHOD url" e.g. "GET https://example.com/api/users"
    # Capped at 500 entries (LRU — oldest dropped first).
    # Persisted to disk so the LLM never re-tests the same endpoint after
    # a crash or extreme context truncation.
    tested_endpoints: list[str] = field(default_factory=lambda: BoundedList(maxlen=_MAX_TESTED_ENDPOINTS))

    # Tracks skills that have been auto-loaded this session to prevent re-injection.
    # Format: skill relative path e.g. "vulnerabilities/sql_injection.md"
    # Persisted to disk so skills aren't re-loaded after session resume.
    loaded_skills: list[str] = field(default_factory=lambda: BoundedList(maxlen=200))

    # Application Model Builder — incrementally updated from HTTP observations.
    # Persisted so resumed sessions keep endpoint/auth/schema understanding.
    app_model: ApplicationModel = field(default_factory=ApplicationModel)
    # Causal reasoning state — structured observations/hypotheses/interventions.
    causal_state: CausalState = field(default_factory=CausalState)

    # WAF profiles detected during testing.
    # Key: target host, Value: {waf_name, confidence, evidence, ...}
    waf_profiles: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Recovery state persisted across session reloads.
    # Keeps post-crash context limits stable instead of bouncing back to large
    # defaults that can immediately trigger another OOM.
    adaptive_num_ctx: int = 0
    adaptive_num_predict_cap: int = 0
    vram_crash_count: int = 0

    def __post_init__(self) -> None:
        if not self.session_id:
            self.session_id = generate_session_id()
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.prune_old_data()

    def prune_old_data(self) -> None:
        """Coerce all collection fields to BoundedList and clamp token fields."""
        self.subdomains = _coerce_sequence_field(
            self.subdomains, field_name="subdomains", maxlen=_MAX_SUBDOMAINS)
        self.live_hosts = _coerce_sequence_field(
            self.live_hosts, field_name="live_hosts", maxlen=_MAX_LIVE_HOSTS)
        self.urls = _coerce_sequence_field(
            self.urls, field_name="urls", maxlen=_MAX_URLS)
        self.vulnerabilities = _coerce_sequence_field(
            self.vulnerabilities, field_name="vulnerabilities", maxlen=_MAX_VULNERABILITIES)
        self.attack_chains = _coerce_sequence_field(
            self.attack_chains, field_name="attack_chains", maxlen=_MAX_ATTACK_CHAINS)
        self.completed_phases = _coerce_sequence_field(
            self.completed_phases, field_name="completed_phases", maxlen=_MAX_COMPLETED_PHASES)
        self.tools_run = _coerce_sequence_field(
            self.tools_run, field_name="tools_run", maxlen=_MAX_TOOLS_RUN)
        self.injection_points = _coerce_sequence_field(
            self.injection_points, field_name="injection_points", maxlen=_MAX_INJECTION_POINTS)
        self.auth_cookies = _coerce_sequence_field(
            self.auth_cookies, field_name="auth_cookies", maxlen=_MAX_AUTH_COOKIES)
        self.tested_injection_points = _coerce_sequence_field(
            self.tested_injection_points, field_name="tested_injection_points",
            maxlen=_MAX_TESTED_ENDPOINTS * 2)
        self.suggested_correlations = _coerce_sequence_field(
            self.suggested_correlations, field_name="suggested_correlations",
            maxlen=_MAX_CORRELATION_SUGGESTIONS)
        self.tested_endpoints = _coerce_sequence_field(
            self.tested_endpoints, field_name="tested_endpoints", maxlen=_MAX_TESTED_ENDPOINTS)
        if not isinstance(self.causal_state, CausalState):
            self.causal_state = _deserialize_causal_state(self.causal_state)
        if not isinstance(self.waf_profiles, dict):
            self.waf_profiles = {}
        # Trim auth_tokens dict
        if isinstance(self.auth_tokens, dict) and len(self.auth_tokens) > _MAX_AUTH_TOKENS:
            keys = list(self.auth_tokens.keys())
            for k in keys[:-_MAX_AUTH_TOKENS]:
                del self.auth_tokens[k]
        # Clamp token accounting fields
        self.token_total = _coerce_non_negative_int(self.token_total)
        self.token_prompt_total = _coerce_non_negative_int(self.token_prompt_total)
        self.token_completion_total = _coerce_non_negative_int(self.token_completion_total)
        self.token_last_used = _coerce_non_negative_int(self.token_last_used)
        self.adaptive_num_ctx = _coerce_non_negative_int(self.adaptive_num_ctx)
        self.adaptive_num_predict_cap = _coerce_non_negative_int(self.adaptive_num_predict_cap)
        self.vram_crash_count = _coerce_non_negative_int(self.vram_crash_count)


def record_tested_endpoint(session: SessionData, url: str, method: str = "GET") -> None:
    """Record a URL as tested so it survives context truncation and crashes.

    Normalises to "METHOD URL" format and deduplicates.  BoundedList handles
    the capacity cap automatically (oldest entries dropped first).
    """
    if not url or not url.strip():
        return
    key = f"{method.upper()} {url.strip()}"
    if key not in session.tested_endpoints:
        session.tested_endpoints.append(key)


def load_session(session_id: str) -> SessionData | None:
    """Load a session by its unique ID.

    Returns None if the session file does not exist.
    """
    filepath = SESSIONS_DIR / f"{session_id}.json"
    if not filepath.exists():
        return None

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        session = SessionData(
            session_id=data.get("session_id", session_id),
            target=data.get("target", ""),
            subdomains=_coerce_sequence_field(
                data.get("subdomains", []), field_name="subdomains", maxlen=_MAX_SUBDOMAINS),
            live_hosts=_coerce_sequence_field(
                data.get("live_hosts", []), field_name="live_hosts", maxlen=_MAX_LIVE_HOSTS),
            open_ports=data.get("open_ports", {}),
            urls=_coerce_sequence_field(
                data.get("urls", []), field_name="urls", maxlen=_MAX_URLS),
            technologies=data.get("technologies", {}),
            vulnerabilities=_coerce_sequence_field(
                data.get("vulnerabilities", []), field_name="vulnerabilities",
                maxlen=_MAX_VULNERABILITIES),
            attack_chains=_coerce_sequence_field(
                data.get("attack_chains", []), field_name="attack_chains",
                maxlen=_MAX_ATTACK_CHAINS),
            completed_phases=_coerce_sequence_field(
                data.get("completed_phases", []), field_name="completed_phases",
                maxlen=_MAX_COMPLETED_PHASES),
            current_phase=data.get("current_phase", "RECON"),
            tools_run=_coerce_sequence_field(
                data.get("tools_run", []), field_name="tools_run", maxlen=_MAX_TOOLS_RUN),
            scan_count=data.get("scan_count", 0),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            token_total=_coerce_non_negative_int(data.get("token_total", 0)),
            token_prompt_total=_coerce_non_negative_int(data.get("token_prompt_total", 0)),
            token_completion_total=_coerce_non_negative_int(
                data.get("token_completion_total", 0)),
            token_last_used=_coerce_non_negative_int(data.get("token_last_used", 0)),
            injection_points=_coerce_sequence_field(
                data.get("injection_points", []), field_name="injection_points",
                maxlen=_MAX_INJECTION_POINTS),
            auth_cookies=_coerce_sequence_field(
                data.get("auth_cookies", []), field_name="auth_cookies",
                maxlen=_MAX_AUTH_COOKIES),
            auth_tokens=data.get("auth_tokens", {}),
            auth_type=data.get("auth_type", ""),
            tested_injection_points=_coerce_sequence_field(
                data.get("tested_injection_points", []),
                field_name="tested_injection_points",
                maxlen=_MAX_TESTED_ENDPOINTS * 2),
            suggested_correlations=_coerce_sequence_field(
                data.get("suggested_correlations", []),
                field_name="suggested_correlations",
                maxlen=_MAX_CORRELATION_SUGGESTIONS),
            tested_endpoints=_coerce_sequence_field(
                data.get("tested_endpoints", []), field_name="tested_endpoints",
                maxlen=_MAX_TESTED_ENDPOINTS),
            loaded_skills=_coerce_sequence_field(
                data.get("loaded_skills", []), field_name="loaded_skills", maxlen=200),
            app_model=_deserialize_app_model(data.get("app_model", {})),
            causal_state=_deserialize_causal_state(data.get("causal_state", {})),
            waf_profiles=data.get("waf_profiles", {}) if isinstance(data.get("waf_profiles", {}), dict) else {},
            adaptive_num_ctx=_coerce_non_negative_int(data.get("adaptive_num_ctx", 0)),
            adaptive_num_predict_cap=_coerce_non_negative_int(
                data.get("adaptive_num_predict_cap", 0)
            ),
            vram_crash_count=_coerce_non_negative_int(data.get("vram_crash_count", 0)),
            _prior_merged=data.get("_prior_merged", False),
        )
        session.prune_old_data()
        logger.info(
            "Loaded session %s (target=%s): %d subs, %d live, %d vulns",
            session_id, session.target,
            len(session.subdomains), len(session.live_hosts), len(session.vulnerabilities),
        )
        return session
    except Exception as e:
        logger.warning("Failed to load session %s: %s", session_id, e)
        return None


def save_session(session: SessionData) -> None:
    """Save session data to disk using session_id as filename.

    Sessions without a target are never persisted — they are throwaway
    placeholders created by subagents, file-analyze mini-agents, and the
    initial AgentLoop state before a target is established.
    """
    if not session.target:
        logger.debug(
            "Skipping save for session %s — no target set", session.session_id
        )
        return
    try:
        session.prune_old_data()
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        session.updated_at = datetime.now().isoformat()
        filepath = SESSIONS_DIR / f"{session.session_id}.json"
        payload = asdict(session)
        payload["app_model"] = _serialize_app_model(session.app_model)
        payload["causal_state"] = _serialize_causal_state(session.causal_state)
        if not isinstance(payload.get("waf_profiles"), dict):
            payload["waf_profiles"] = {}
        # Convert BoundedList fields to plain list for JSON serialization
        _bounded_fields = (
            "subdomains", "live_hosts", "urls", "vulnerabilities",
            "attack_chains", "completed_phases", "tools_run",
            "injection_points", "auth_cookies", "tested_injection_points",
            "suggested_correlations", "tested_endpoints", "loaded_skills",
        )
        for key in _bounded_fields:
            payload[key] = list(payload.get(key, []))
        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        logger.info("Saved session %s (target=%s)", session.session_id, session.target)
    except Exception as e:
        logger.error("Failed to save session %s: %s", session.session_id, e)


def list_sessions() -> list[dict]:
    """Return a list of all saved sessions, sorted by most recently updated first.

    Each entry contains summary information (not the full data).
    """
    sessions: list[dict] = []
    if not SESSIONS_DIR.exists():
        return sessions

    for path in SESSIONS_DIR.glob("*.json"):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            target = data.get("target", "")
            # Skip sessions that have no target — placeholder sessions from
            # subagents, mini-agents, and pre-target init.
            # NOTE: list_sessions is a read-only operation; no file deletion here.
            # Use cleanup_empty_sessions() for explicit maintenance.
            if not target:
                continue
            sessions.append({
                "session_id": data.get("session_id", path.stem),
                "target": target,
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
                "scan_count": data.get("scan_count", 0),
                "subdomains": len(data.get("subdomains", [])),
                "live_hosts": len(data.get("live_hosts", [])),
                "vulnerabilities": len(data.get("vulnerabilities", [])),
            })
        except Exception as _e:
            logger.debug("Could not load session metadata: %s", _e)

    sessions.sort(
        key=lambda s: s.get("updated_at") or s.get("created_at", ""),
        reverse=True,
    )
    return sessions


def cleanup_empty_sessions() -> int:
    """Delete session files that have no target (placeholder/subagent sessions).

    This is an explicit maintenance operation — intentionally separate from
    list_sessions() to avoid silent data loss during normal listing.

    Returns the number of files deleted.
    """
    if not SESSIONS_DIR.exists():
        return 0
    deleted = 0
    for path in SESSIONS_DIR.glob("*.json"):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if not data.get("target"):
                path.unlink()
                logger.info("Cleaned up empty session: %s", path.name)
                deleted += 1
        except Exception as _e:
            logger.debug("cleanup_empty_sessions: could not process %s: %s", path.name, _e)
    return deleted


def find_prior_session(target: str) -> SessionData | None:
    """Find the most recent completed session for the given target.

    Returns None if no prior session exists or the target has never been scanned.
    Only considers sessions that made meaningful progress (scan_count >= 3 or
    at least one completed phase) to avoid pre-populating from aborted runs.
    """
    if not SESSIONS_DIR.exists():
        return None

    target_norm = target.strip().lower()
    candidates: list[tuple[str, str]] = []  # (updated_at, session_id)

    for path in SESSIONS_DIR.glob("*.json"):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if data.get("target", "").strip().lower() != target_norm:
                continue
            # Only consider sessions with meaningful progress
            has_progress = (
                data.get("scan_count", 0) >= 3
                or bool(data.get("completed_phases"))
            )
            if not has_progress:
                continue
            ts = data.get("updated_at") or data.get("created_at", "")
            candidates.append((ts, data.get("session_id", path.stem)))
        except Exception as _e:
            logger.debug("Could not inspect session file %s: %s", path, _e)

    if not candidates:
        return None

    # Most recently updated session
    candidates.sort(reverse=True)
    _, best_id = candidates[0]
    return load_session(best_id)


def merge_prior_findings(new_session: SessionData, prior: SessionData) -> None:
    """Merge findings from a prior session into a new session for the same target.

    Only merges factual reconnaissance data (subdomains, ports, URLs, technologies,
    injection points, attack_chains). Does NOT merge vulnerabilities (may be patched),
    phase state (always restart from RECON), or auth state (tokens may be expired).

    This gives the new session a head-start without polluting it with stale vuln data.
    """
    if prior.target.strip().lower() != new_session.target.strip().lower():
        logger.warning(
            "merge_prior_findings: target mismatch (%r vs %r) — skipping",
            prior.target, new_session.target,
        )
        return

    merged_count = 0

    # Subdomains — deduplicated
    existing_subs = set(new_session.subdomains)
    for sub in prior.subdomains:
        if sub not in existing_subs:
            new_session.subdomains.append(sub)
            existing_subs.add(sub)
            merged_count += 1

    # Live hosts — deduplicated
    existing_hosts = set(new_session.live_hosts)
    for host in prior.live_hosts:
        if host not in existing_hosts:
            new_session.live_hosts.append(host)
            existing_hosts.add(host)

    # Open ports — merge dict (host → sorted unique port list)
    for host, ports in prior.open_ports.items():
        if host not in new_session.open_ports:
            new_session.open_ports[host] = list(ports)
        else:
            merged = sorted(set(new_session.open_ports[host]) | set(ports))
            new_session.open_ports[host] = merged

    # URLs — deduplicated (cap at 500 to avoid flooding context)
    existing_urls = set(new_session.urls)
    for url in prior.urls:
        if url not in existing_urls and len(new_session.urls) < 500:
            new_session.urls.append(url)
            existing_urls.add(url)
            merged_count += 1

    # Technologies — merge dict (newer value wins on conflict)
    for name, version in prior.technologies.items():
        if name not in new_session.technologies:
            new_session.technologies[name] = version

    # Injection points — deduplicate by (url, parameter, method) key
    existing_ips = {
        (ip.get("url", ""), ip.get("parameter", ""), ip.get("method", ""))
        for ip in new_session.injection_points
    }
    for ip in prior.injection_points:
        key = (ip.get("url", ""), ip.get("parameter", ""), ip.get("method", ""))
        if key not in existing_ips:
            new_session.injection_points.append(ip)
            existing_ips.add(key)
            merged_count += 1

    # Attack chains — merge by name
    existing_chains = {c.get("name", "") for c in new_session.attack_chains}
    for chain in prior.attack_chains:
        if chain.get("name", "") not in existing_chains:
            new_session.attack_chains.append(chain)

    logger.info(
        "Merged prior session %s into new session %s "
        "(%d items: %d subs, %d urls, %d injection_points)",
        prior.session_id, new_session.session_id,
        merged_count,
        len(new_session.subdomains), len(new_session.urls),
        len(new_session.injection_points),
    )


def update_from_parsed_output(
    session: SessionData,
    parsed: ParsedOutput,
    command: str = "",
) -> None:
    """Update session data based on WHAT THE DATA LOOKS LIKE, not which tool produced it.

    Classification logic:
    - Items that look like subdomains (e.g. "sub.example.com") → session.subdomains
    - Items that look like URLs (start with http) → session.urls or session.live_hosts
    - Items that look like host:port → session.open_ports
    - Items that look like port/proto lines → session.open_ports
    - Items with severity tags [CRITICAL] [HIGH] etc → session.vulnerabilities
    - Everything else: logged but not stored (no false assumptions)
    """
    session.scan_count += 1

    # Track which tools have been run (use actual binary name)
    tool_key = parsed.tool
    if tool_key and tool_key not in session.tools_run:
        session.tools_run.append(tool_key)

    # Merge technologies from tool output (whatweb, httpx -tech-detect)
    if parsed.technologies:
        for name, version in parsed.technologies.items():
            if name and name not in session.technologies:
                session.technologies[name] = version
            elif name and version and not session.technologies.get(name):
                # Upgrade an empty-version entry when a version is now
                # available
                session.technologies[name] = version

    # Merge causal observations extracted by output parser.
    if parsed.causal_observations and session.causal_state:
        newly_added_observations: list[dict[str, Any]] = []
        for obs in parsed.causal_observations:
            if isinstance(obs, dict):
                obs.setdefault("source_tool", tool_key)
                obs.setdefault("phase", session.current_phase)
                if session.causal_state.record_observation(obs):
                    newly_added_observations.append(obs)
                    _update_causal_hypotheses_from_observation(session, obs)
        if newly_added_observations and command:
            _record_causal_intervention_from_parse(
                session,
                command=command,
                parsed=parsed,
                observations=newly_added_observations,
            )

    if not parsed.items:
        return

    # Classify each item by its content pattern
    _SUBDOMAIN_RE = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$"
    )
    _URL_RE = re.compile(r"^https?://")
    _ANY_URL_RE = re.compile(r"https?://\S+")
    _HOST_PORT_RE = re.compile(r"^([a-zA-Z0-9.\-]+):(\d+)")
    # Match nmap port lines in multiple formats:
    #   "80/tcp   open  http"           (plain nmap -sV)
    #   "| 80/tcp  open  http"          (nmap script block with pipe prefix)
    #   "  443/tcp filtered https"      (leading whitespace variants)
    _PORT_PROTO_RE = re.compile(r"(?:^|[|\s])(\d+)/(tcp|udp)\s+(open|filtered)")
    # Set-Cookie header detection for cookie-based injection point capture.
    # Handles both plain HTTP response lines and curl -v verbose format (< prefix).
    _SET_COOKIE_RE = re.compile(
        r"^(?:<\s*)?[Ss]et-[Cc]ookie:\s*([A-Za-z0-9_\-\.]+)=([^;\r\n]*)",
        re.IGNORECASE,
    )
    # Extract URL from shell command so cookie injection points are linked to endpoint.
    _CMD_URL_RE = re.compile(r"https?://\S+")
    _SEVERITY_RE = re.compile(
        r"^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]",
        re.IGNORECASE)
    # Secondary vulnerability patterns for tools without dedicated parsers:
    # catches metasploit [+] success, CVE IDs in context, "vulnerable to" patterns.
    #
    # IMPORTANT: avoid broad "not" filtering. Phrases like "not authenticated"
    # are often valid vulnerabilities (auth bypass), while phrases such as
    # "not vulnerable" should be excluded.
    _NEGATIVE_VULN_PHRASE_RE = re.compile(
        r"\b(?:"
        r"not\s+vulnerable(?:\s+to)?"
        r"|not\s+affected"
        r"|unaffected"
        r"|not\s+impacted"
        r"|no\s+impact"
        r"|no\s+vulnerabilit(?:y|ies)"
        r"|no\s+exploit(?:ation)?"
        r"|not\s+exploitable"
        r"|false\s+positive"
        r"|already\s+patched"
        r"|fully\s+patched"
        r"|fixed\s+in"
        r"|patch\s+available"
        r")\b",
        re.IGNORECASE,
    )
    _VULN_PATTERN_RE = re.compile(
        r"^\[\+\].{0,120}(vulnerab|exploit|session opened|shell|meterpreter|"
        r"access granted|credentials? found|credential found)|"
        r"CVE-\d{4}-\d{4,7}.{0,80}(vulnerab|exploit|found|\baffected\b|\bimpacted\b)|"
        r"^(VULN|VULNERABLE|EXPLOIT|PWNED)\s*[:!]",
        re.IGNORECASE)
    _ACTIONABLE_VULN_SIGNAL_RE = re.compile(
        r"\b("
        r"vulnerab\w*|exploit\w*|sqli|sql injection|xss|ssrf|idor|csrf|rce|lfi|xxe|"
        r"auth(?:entication|orization)?\s*bypass|session opened|meterpreter|shell|"
        r"credential|token|leak(?:ed)?|cve-\d{4}-\d{4,7}"
        r")\b",
        re.IGNORECASE,
    )
    _VULN_CONTEXT_RE = re.compile(
        r"(https?://|/[a-z0-9_\-./]{2,}|\b("
        r"endpoint|parameter|param|payload|response|status|http/?\d\.\d|"
        r"cookie|header|access|admin|database|record|dump|error|forbidden|unauthorized"
        r")\b)",
        re.IGNORECASE,
    )
    # httpx outputs URL followed by [STATUS] bracket — handle multiple common formats:
    #   https://host.com [200]                     (httpx -sc)
    #   https://host.com [200] [title] [tech]      (httpx default)
    #   https://host.com [200 OK]                  (httpx extended)
    #   https://host.com [200,text/html,...]       (httpx -json piped)
    _HTTP_STATUS_RE = re.compile(r"(https?://\S+?)\s+\[(\d{3})[^\]]*\]")
    # DNS-only label prefixes that are not HTTP-probeable hosts (e.g. _dmarc, _domainkey)
    _DNS_ONLY_PREFIX_RE = re.compile(r"^_")
    # Private/loopback IP ranges — not valid external scan targets
    _PRIVATE_IP_RE = re.compile(
        r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1|fd)"
    )
    # Custom script output prefixes — normalize "URL: https://...", "SUBDOMAIN=host", etc.
    # so script output is auto-parsed into the session without manual post-processing.
    _SCRIPT_PREFIX_RE = re.compile(
        r"^(url|endpoint|link|host|domain|subdomain|live|target|asset|hostport)\s*[:=]\s*(\S+)",
        re.IGNORECASE,
    )

    def _is_actionable_vuln_line(text: str, *, severity_tagged: bool) -> bool:
        candidate = text.strip()
        if not candidate:
            return False
        if _NEGATIVE_VULN_PHRASE_RE.search(candidate):
            return False
        has_signal = bool(_ACTIONABLE_VULN_SIGNAL_RE.search(candidate))
        has_context = bool(_VULN_CONTEXT_RE.search(candidate))
        if severity_tagged:
            # Severity tags alone are noisy; require at least one exploit signal
            # plus either context or sufficiently descriptive content.
            return has_signal and (has_context or len(candidate) >= 35)
        return has_signal and (has_context or len(candidate) >= 30)

    for item in parsed.items:
        item_stripped = item.strip()
        if not item_stripped:
            continue
        # Normalize common script output prefixes (e.g., "URL: https://...",
        # "SUBDOMAIN=api.example.com") so custom scripts integrate with
        # session parsing.
        prefix_match = _SCRIPT_PREFIX_RE.match(item_stripped)
        if prefix_match:
            item_stripped = prefix_match.group(2).strip()

        # 1. Severity-tagged finding → vulnerability
        if _SEVERITY_RE.match(item_stripped):
            if not _is_actionable_vuln_line(item_stripped, severity_tagged=True):
                continue
            new_vuln = {
                "finding": item_stripped,
                "source": tool_key,
                "timestamp": datetime.now().isoformat(),
            }
            # Check for duplicates before adding
            if not _is_duplicate_vulnerability(
                    new_vuln, session.vulnerabilities):
                session.vulnerabilities.append(new_vuln)
            continue

        # 1b. Secondary vuln patterns — tools without dedicated parsers:
        # metasploit [+] success, CVE findings, explicit VULN:/EXPLOIT: prefixes.
        if (
            _VULN_PATTERN_RE.search(item_stripped)
            and _is_actionable_vuln_line(item_stripped, severity_tagged=False)
        ):
            new_vuln = {
                "finding": item_stripped,
                "source": tool_key,
                "timestamp": datetime.now().isoformat(),
            }
            if not _is_duplicate_vulnerability(new_vuln, session.vulnerabilities):
                session.vulnerabilities.append(new_vuln)
            continue

        # 2. URL with HTTP status code (httpx-style output) → live_hosts.
        # Matches: https://host [200], https://host [200 OK], https://host [200] [nginx]
        status_match = _HTTP_STATUS_RE.search(item_stripped)
        if status_match:
            url = _normalize_url(status_match.group(1).rstrip(".,;:)]}>\"'"))
            if url and url not in session.live_hosts:
                session.live_hosts.append(url)
            # Also add to urls if not already there
            if url and url not in session.urls:
                session.urls.append(url)
            continue

        # 3. URL (plain or embedded in prefixed line) → urls collection
        # + auto-extract injection points.
        url_token: str | None = None
        if _URL_RE.match(item_stripped):
            url_token = item_stripped.split()[0]
        else:
            embedded = _ANY_URL_RE.search(item_stripped)
            if embedded:
                url_token = embedded.group(0)

        if url_token:
            url = _normalize_url(url_token.rstrip(".,;:)]}>\"'"))
            if url not in session.urls:
                session.urls.append(url)
            # Extract any testable parameters from the URL
            new_pts = _extract_injection_points(url)
            if new_pts:
                _merge_injection_points(session.injection_points, new_pts)
            continue

        # 4. host:port format → open_ports
        hp_match = _HOST_PORT_RE.match(item_stripped)
        if hp_match:
            host, port_str = hp_match.group(1), hp_match.group(2)
            if port_str.isdigit():
                port = int(port_str)
                session.open_ports.setdefault(host, [])
                if port not in session.open_ports[host]:
                    session.open_ports[host].append(port)
            continue

        # 5. port/proto state service (nmap-style) → open_ports under target
        # Use search() (not match()) to handle pipe-prefixed nmap script output.
        pp_match = _PORT_PROTO_RE.search(item_stripped)
        if pp_match:
            port_str = pp_match.group(1)
            if port_str.isdigit():
                port = int(port_str)
                session.open_ports.setdefault(session.target, [])
                if port not in session.open_ports[session.target]:
                    session.open_ports[session.target].append(port)
            continue

        # 5b. Set-Cookie response header → cookie injection point.
        # Captures session tokens and auth cookies from curl -v / HTTP tool output
        # so the agent knows what cookie parameters can be manipulated.
        cookie_m = _SET_COOKIE_RE.match(item_stripped)
        if cookie_m:
            cookie_name = cookie_m.group(1).strip()
            cookie_value = cookie_m.group(2).strip()[:50]
            # Link cookie to the endpoint URL from the shell command if available.
            _cmd_url_m = _CMD_URL_RE.search(command)
            _cookie_url: str | None = None
            if _cmd_url_m:
                try:
                    _raw_url = _cmd_url_m.group(0).rstrip(".,;:)]}>\"'")
                    _pu = urlparse(_raw_url)
                    _cookie_url = urlunparse((
                        _pu.scheme.lower(), _pu.netloc.lower(),
                        _pu.path.rstrip("/") or "/", "", "", "",
                    ))
                except Exception:
                    pass
            if _cookie_url and cookie_name:
                _merge_injection_points(session.injection_points, [{
                    "url": _cookie_url,
                    "parameter": f"cookie/{cookie_name}",
                    "method": "GET",
                    "value_sample": cookie_value,
                    "type_hint": "COOKIE_PARAM",
                }])
            continue

        # 6. Looks like a subdomain → subdomains
        # Must have at least one dot, no spaces, no special chars.
        # Exclude DNS-only labels (e.g. _dmarc.target.com) — these cannot be
        # HTTP-probed. Exclude private/loopback IPs to avoid dead scan targets.
        clean = item_stripped.split()[0]  # first token only
        if (
            _SUBDOMAIN_RE.match(clean)
            and len(clean) > 4
            and not _DNS_ONLY_PREFIX_RE.match(clean)
            and not _PRIVATE_IP_RE.match(clean)
        ):
            if clean not in session.subdomains:
                session.subdomains.append(clean)
            continue

        # 7. Anything else: we DON'T store it to avoid false assumptions.
        # It stays in the parsed output for the LLM to see but doesn't
        # pollute structured session data.


def session_to_context(session: SessionData) -> str:
    """Format session data as a context string for injection into conversation."""
    target_label = session.target or "unknown target"
    parts = [
        f"[SYSTEM: RESUMED SESSION — {session.session_id} for {target_label}]",
        "YOU ARE RESUMING A PREVIOUS SESSION. The data below was already collected.",
    ]

    # Build explicit skip-list FIRST so LLM sees it before phase prompts override behaviour.
    skip_items: list[str] = []
    if session.subdomains:
        skip_items.append(
            f"Subdomain enumeration — {len(session.subdomains)} already found"
        )
    if session.live_hosts:
        skip_items.append(
            f"Live host validation — {len(session.live_hosts)} already confirmed"
        )
    if session.open_ports:
        total_ports = sum(len(p) for p in session.open_ports.values())
        skip_items.append(f"Port scanning — {total_ports} open ports already recorded")
    if session.urls:
        skip_items.append(f"URL/route discovery — {len(session.urls)} already collected")

    if skip_items:
        parts.append(
            "DO NOT REDO the following (already complete):\n"
            + "\n".join(f"  ✓ {item}" for item in skip_items)
        )
        parts.append(
            "Focus ONLY on what is MISSING or UNTESTED based on the data below."
        )

    parts.append(f"Session created: {session.created_at}")
    parts.append(
        f"Tools previously run: {', '.join(session.tools_run) if session.tools_run else 'none'}"
    )
    parts.append(f"Total scans: {session.scan_count}")

    if session.subdomains:
        count = len(session.subdomains)
        # Prioritized preview: show subdomains with open ports first, then alphabetical
        # This ensures high-value targets are visible to LLM (not just first-inserted)
        subdomains_with_ports = [
            sd for sd in session.subdomains
            if any(sd in host for host in session.open_ports.keys())
        ]
        subdomains_without_ports = [
            sd for sd in session.subdomains
            if sd not in subdomains_with_ports
        ]
        # Show up to 5 with ports, then 5 without ports (total 10)
        preview_items = (subdomains_with_ports[:5] + subdomains_without_ports[:5])[:10]
        preview = ", ".join(preview_items)
        parts.append(
            f"Subdomains found: {count} — {preview}"
            + (f" ... +{count - 10} more" if count > 10 else "")
        )
        if subdomains_with_ports and count > 10:
            parts.append(f"  [!]{len(subdomains_with_ports)} subdomains have open ports (prioritized above)")

    if session.live_hosts:
        count = len(session.live_hosts)
        # Prioritized preview: show hosts with open ports or injection points first
        hosts_with_ports = [
            h for h in session.live_hosts
            if any(h in host for host in session.open_ports.keys())
        ]
        hosts_with_injections = [
            h for h in session.live_hosts
            if any(h in pt.get("url", "") for pt in session.injection_points)
        ]
        # Deduplicate while preserving order
        seen = set()
        priority_hosts = []
        for h in hosts_with_ports + hosts_with_injections:
            if h not in seen:
                priority_hosts.append(h)
                seen.add(h)
        other_hosts = [h for h in session.live_hosts if h not in seen]
        # Show up to 10: priority first, then others
        preview_items = (priority_hosts + other_hosts)[:10]
        preview = ", ".join(preview_items)
        parts.append(
            f"Live hosts: {count} — {preview}"
            + (f" ... +{count - 10} more" if count > 10 else "")
        )
        if priority_hosts and count > 10:
            parts.append(f"  [!]{len(priority_hosts)} hosts have ports/injections (prioritized above)")

    if session.open_ports:
        total_ports = sum(len(p) for p in session.open_ports.values())
        port_preview = []
        for host, ports in list(session.open_ports.items())[:5]:
            port_preview.append(
                f"{host}: {','.join(str(p) for p in sorted(ports)[:10])}"
            )
        parts.append(
            f"Open ports: {total_ports} total — " +
            "; ".join(port_preview))

    if session.urls:
        parts.append(f"URLs collected: {len(session.urls)}")

    if session.injection_points:
        count = len(session.injection_points)
        untested = get_untested_injection_points(session)
        tested_count = count - len(untested)

        # Show UNTESTED injection points first — these are highest priority.
        # Fall back to all IPs if everything is already tested.
        show_list = untested if untested else session.injection_points

        # Prioritize by type_hint (IDOR/SSRF first as most critical), then alphabetically
        # Type priority based on exploitability: IDOR > SSRF > PATH_TRAVERSAL > OPEN_REDIRECT > SQLi_XSS > AUTH > INJECT
        type_priority = {"IDOR": 0, "SSRF": 1, "PATH_TRAVERSAL": 2, "OPEN_REDIRECT": 3, "SQLi_XSS": 4, "AUTH": 5, "INJECT": 6}
        def get_type_priority(pt: dict) -> int:
            t = pt.get("type_hint", "INJECT").upper()
            return type_priority.get(t, 6)
        
        # Sort untested points by type priority (most critical first), then by type_hint
        sorted_points = sorted(
            show_list,
            key=lambda pt: (get_type_priority(pt), pt.get("type_hint", "INJECT"))
        )

        # Group by type_hint for clarity, but show HIGH/CRITICAL first across all types
        by_type: dict[str, list[dict[str, Any]]] = {}
        for pt in sorted_points:
            t = pt.get("type_hint", "INJECT")
            by_type.setdefault(t, []).append(pt)

        preview_lines: list[str] = []
        shown = 0
        # Show up to 25 untested injection points (increased from 9 for better coverage)
        # Prioritize CRITICAL/HIGH severity
        for type_hint, pts in by_type.items():
            # Show all CRITICAL/HIGH first, regardless of type
            critical_high = [pt for pt in pts if get_type_priority(pt) <= 3]  # IDOR, SSRF, PATH_TRAVERSAL, OPEN_REDIRECT
            others = [pt for pt in pts if get_type_priority(pt) > 3]
            for pt in critical_high[:5]:  # Up to 5 high-priority per type
                param = pt.get("parameter", "?")
                url_short = pt.get("url", "")
                path = urlparse(url_short).path or url_short
                type_hint = pt.get("type_hint", "INJECT").upper()
                preview_lines.append(f"  [{type_hint}] {param} @ {path}")
                shown += 1
            if shown >= 15:  # Show max 15 high-priority total
                break
        # Then show lower-priority if space remains
        if shown < 25:
            for type_hint, pts in by_type.items():
                others = [pt for pt in pts if get_type_priority(pt) > 3]
                for pt in others[:3]:  # Up to 3 lower-priority per type
                    param = pt.get("parameter", "?")
                    url_short = pt.get("url", "")
                    path = urlparse(url_short).path or url_short
                    type_hint = pt.get("type_hint", "INJECT").upper()
                    preview_lines.append(f"  [{type_hint}] {param} @ {path}")
                    shown += 1
                if shown >= 25:  # Max 25 total
                    break

        suffix = f" ... +{len(show_list) - shown} more" if len(show_list) > shown else ""
        untested_note = (
            f"[!]{len(untested)} UNTESTED — prioritize these!" if untested
            else f"✓ all {tested_count} tested"
        )
        parts.append(
            f"Injection points: {count} total ({untested_note}):\n"
            + "\n".join(preview_lines) + suffix
        )

    if session.technologies:
        count = len(session.technologies)
        # Format as "Name/version" where version is known, else just "Name"
        tech_parts = [
            f"{name}/{ver}" if ver else name
            for name, ver in list(session.technologies.items())[:15]
        ]
        parts.append(
            f"Technologies fingerprinted: {count} — {', '.join(tech_parts)}"
            + (f" ... +{count - 15} more" if count > 15 else "")
        )

    causal_ctx = _build_causal_context_block(session.causal_state)
    if causal_ctx:
        parts.append(causal_ctx)

    if session.vulnerabilities:
        parts.append(f"Vulnerabilities found: {len(session.vulnerabilities)}")
        for v in session.vulnerabilities[:5]:
            flag_info = f" (FLAG: {v.get('flag')})" if v.get("flag") else ""
            parts.append(f"  - {v.get('finding', '?')}{flag_info}")

    if session.attack_chains:
        parts.append(f"Attack chains identified: {len(session.attack_chains)}")
        for chain in session.attack_chains[:3]:
            parts.append(f"  - Chain: {' -> '.join(chain.get('steps', []))}")

    if session.completed_phases:
        parts.append(f"Completed phases: {', '.join(session.completed_phases)}")

    if session.auth_cookies or session.auth_tokens:
        auth_info = f"Auth state: {session.auth_type or 'unknown'} — "
        if session.auth_cookies:
            auth_info += f"{len(session.auth_cookies)} cookies captured"
        if session.auth_tokens:
            auth_info += f", tokens: {', '.join(session.auth_tokens.keys())}"
        parts.append(
            auth_info +
            " (use inject_cookies action to restore session)")

    if session.waf_profiles:
        waf_preview = []
        for host, prof in list(session.waf_profiles.items())[:4]:
            waf_name = str(prof.get("waf_name", "Unknown"))
            conf = float(prof.get("confidence", 0.0))
            waf_preview.append(f"{host}={waf_name}({conf:.0%})")
        parts.append(
            f"WAF profiles: {len(session.waf_profiles)} — "
            + ", ".join(waf_preview)
            + (f" ... +{len(session.waf_profiles) - 4} more" if len(session.waf_profiles) > 4 else "")
        )

    parts.append(
        "Use this data to RESUME work — do NOT re-run scans that already have results above."
    )
    return "\n".join(parts)
