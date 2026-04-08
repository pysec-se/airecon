from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from .utils import tool_finish

logger = logging.getLogger("airecon.agent")

_CAIDO_LIST_REQ_TIMEOUT = 60
_CAIDO_AUTOMATE_TIMEOUT = 90
_CAIDO_CLEANUP_TIMEOUT = 5.0

_REQUESTS_GQL = """
query {
    requests(first: 200) {
        edges {
            node {
                id
                method
                host
                path
                response { statusCode }
            }
        }
    }
}
""".strip()

_FINDINGS_GQL = """
query GetFindings($first: Int) {
    findings(first: $first) {
        edges {
            node {
                id
                title
                description
                reporter
                request {
                    id method host path
                    response { statusCode }
                }
            }
        }
    }
}
"""

_INTERCEPT_MESSAGES_GQL = """
query {
    interceptMessages(first: 20, kind: REQUEST) {
        edges {
            node {
                id
                ... on InterceptRequestMessage {
                    request { method host path }
                }
            }
        }
    }
}
"""

_SITEMAP_ROOT_GQL = """
{
    sitemapRootEntries {
        edges {
            node { id label kind hasDescendants }
        }
    }
}
"""

_SITEMAP_CHILDREN_GQL = """
query SitemapChildren($parentId: ID!) {
    sitemapDescendantEntries(parentId: $parentId, depth: DIRECT) {
        edges {
            node { id label kind hasDescendants }
        }
    }
}
"""


def _gql_err(data: dict[str, Any]) -> str | None:
    if "errors" in data and data["errors"]:
        return str(data["errors"][0].get("message", "GQL error"))
    return None


def _parse_gql_response(
    data: dict[str, Any],
    *key_path: str,
) -> Any | None:
    result = data.get("data", {})
    for key in key_path:
        result = (result or {}).get(key, {})
    return result or {}


def _host_tuple(host: str, is_tls: bool, port_arg: Any) -> tuple[str, bool, int]:
    host = host.removeprefix("https://").removeprefix("http://").rstrip("/")
    try:
        port = int(port_arg) if port_arg is not None else (443 if is_tls else 80)
    except (TypeError, ValueError):
        port = 443 if is_tls else 80
    return host, is_tls, port


def _tls_from_arg(raw: Any) -> bool:
    if isinstance(raw, str):
        return raw.lower() not in ("false", "0", "no", "")
    return bool(raw)


def _tool_err(
    self, tool_name, arguments, start_time, e, context_name: str = ""
) -> tuple[bool, float, dict[str, Any], str | None]:
    logger.error("caido_%s error: %s", context_name or tool_name, e)
    res = {"success": False, "error": str(e)}
    return tool_finish(self, tool_name, arguments, res, start_time, success=False)


class _CaidoExecutorMixin:
    async def _execute_caido_list_requests_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient

        self._last_output_file = None
        start_time = time.time()
        filter_query = str(arguments.get("filter", "")).strip().lower()
        try:
            limit = min(max(int(arguments.get("limit", 50)), 1), 200)
        except (TypeError, ValueError):
            limit = 50

        try:
            data = await CaidoClient.gql(_REQUESTS_GQL)
            if err := _gql_err(data):
                return _tool_err(
                    self,
                    tool_name,
                    arguments,
                    start_time,
                    RuntimeError(err),
                    "list_requests",
                )
            edges = _parse_gql_response(data, "requests", "edges")
            requests = [
                {
                    "id": e["node"]["id"],
                    "method": e["node"]["method"],
                    "host": e["node"]["host"],
                    "path": e["node"]["path"],
                    "status": (e["node"].get("response") or {}).get("statusCode"),
                }
                for e in edges
            ]
            if filter_query:
                requests = [
                    r
                    for r in requests
                    if filter_query
                    in f"{r.get('method', '')} {r.get('host', '')}{r.get('path', '')} {r.get('status', '')}".lower()
                ]
            requests = requests[:limit]
            res_dict = {
                "success": True,
                "requests": requests,
                "total": len(requests),
                "limit": limit,
                "filter": filter_query,
            }
        except Exception as e:
            res_dict = {"success": False, "error": str(e)}
            if "All connection attempts failed" in str(e):
                res_dict["next_action"] = (
                    "Caido host service is unreachable. Start/login Caido outside sandbox first, "
                    "then verify using caido_intercept with action='status'."
                )
        return tool_finish(
            self,
            tool_name,
            arguments,
            res_dict,
            start_time,
            res_dict.get("success", False),
        )

    async def _execute_caido_send_request_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient

        self._last_output_file = None
        start_time = time.time()

        request_id = self._str_arg(arguments, "request_id")
        raw_http = self._str_arg(arguments, "raw_http")
        is_tls = _tls_from_arg(arguments.get("is_tls", True))
        host, is_tls, port = _host_tuple(
            self._str_arg(arguments, "host"), is_tls, arguments.get("port")
        )

        try:
            async with asyncio.timeout(_CAIDO_LIST_REQ_TIMEOUT):
                create_vars: dict[str, Any] = {"input": {}}
                if request_id:
                    create_vars["input"]["requestSource"] = {"id": request_id}
                create_data = await CaidoClient.gql(
                    """mutation CreateReplay($input: CreateReplaySessionInput!) {
                        createReplaySession(input: $input) { session { id } }
                    }""",
                    create_vars,
                )
                if err := _gql_err(create_data):
                    raise RuntimeError(err)
                session_id = create_data["data"]["createReplaySession"]["session"]["id"]

                task_input: dict[str, Any] = {
                    "connection": {"host": host, "port": port, "isTLS": is_tls},
                    "settings": {
                        "closeConnection": False,
                        "updateContentLength": True,
                        "placeholders": [],
                    },
                }
                if raw_http:
                    task_input["raw"] = CaidoClient.encode_raw_http(raw_http)

                start_data = await CaidoClient.gql(
                    """mutation StartReplay($sessionId: ID!, $input: StartReplayTaskInput!) {
                        startReplayTask(sessionId: $sessionId, input: $input) { task { id } }
                    }""",
                    {"sessionId": session_id, "input": task_input},
                )
                if err := _gql_err(start_data):
                    raise RuntimeError(err)
                task_id = start_data["data"]["startReplayTask"]["task"]["id"]

            res_dict = {
                "success": True,
                "session_id": session_id,
                "task_id": task_id,
                "host": host,
                "port": port,
            }
        except asyncio.TimeoutError:
            logger.error("caido_send_request timeout (%ds)", _CAIDO_LIST_REQ_TIMEOUT)
            res_dict = {
                "success": False,
                "error": f"Caido did not respond within {_CAIDO_LIST_REQ_TIMEOUT} seconds",
            }
        except Exception as e:
            logger.error("caido_send_request error: %s", e)
            res_dict = {"success": False, "error": str(e)}
        return tool_finish(
            self,
            tool_name,
            arguments,
            res_dict,
            start_time,
            res_dict.get("success", False),
        )

    async def _execute_caido_automate_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient

        self._last_output_file = None
        start_time = time.time()

        raw_http = self._str_arg(arguments, "raw_http")
        is_tls = _tls_from_arg(arguments.get("is_tls", True))
        host, is_tls, port = _host_tuple(
            self._str_arg(arguments, "host"), is_tls, arguments.get("port")
        )
        raw_payloads = arguments.get("payloads", [])
        if not isinstance(raw_payloads, list):
            return _tool_err(
                self,
                tool_name,
                arguments,
                start_time,
                ValueError("payloads must be a list of strings"),
                "automate",
            )
        payloads = [
            str(p)
            for p in raw_payloads
            if isinstance(p, (str, int, float)) and str(p).strip()
        ]
        if not payloads:
            return _tool_err(
                self,
                tool_name,
                arguments,
                start_time,
                ValueError("payloads list is empty"),
                "automate",
            )
        if len(payloads) > 10_000:
            return _tool_err(
                self,
                tool_name,
                arguments,
                start_time,
                ValueError(f"payloads list too large ({len(payloads)})"),
                "automate",
            )
        workers = min(int(arguments.get("workers", 10)), 50)
        placeholders = CaidoClient.find_fuzz_offsets(raw_http)
        clean_http = raw_http.replace("§FUZZ§", "")
        encoded_raw = CaidoClient.encode_raw_http(clean_http)

        auto_id: str | None = None
        task_id: str | None = None

        async def _cleanup() -> None:
            if not auto_id:
                return
            try:
                await asyncio.wait_for(
                    CaidoClient.gql(
                        "mutation DeleteSession($id: ID!) { deleteAutomateSession(id: $id) { deletedId } }",
                        {"id": auto_id},
                    ),
                    timeout=_CAIDO_CLEANUP_TIMEOUT,
                )
                logger.info("Cleaned up orphaned Caido automate session %s", auto_id)
            except (asyncio.TimeoutError, Exception) as _e:
                logger.debug("Could not clean up Caido session %s: %s", auto_id, _e)

        try:
            async with asyncio.timeout(_CAIDO_AUTOMATE_TIMEOUT):
                create_data = await CaidoClient.gql(
                    "mutation { createAutomateSession(input: {}) { session { id } } }"
                )
                if err := _gql_err(create_data):
                    raise RuntimeError(err)
                auto_id = create_data["data"]["createAutomateSession"]["session"]["id"]

                update_input: dict[str, Any] = {
                    "connection": {"host": host, "port": port, "isTLS": is_tls},
                    "raw": encoded_raw,
                    "settings": {
                        "closeConnection": False,
                        "updateContentLength": True,
                        "strategy": "SEQUENTIAL",
                        "concurrency": {"workers": workers, "delay": 0},
                        "placeholders": placeholders,
                        "payloads": [
                            {
                                "preprocessors": [],
                                "options": {"simpleList": {"list": payloads}},
                            }
                        ],
                        "retryOnFailure": "FAILED",
                    },
                }
                update_data = await CaidoClient.gql(
                    """mutation UpdateAutomate($id: ID!, $input: UpdateAutomateSessionInput!) {
                        updateAutomateSession(id: $id, input: $input) { session { id } }
                    }""",
                    {"id": auto_id, "input": update_input},
                )
                if err := _gql_err(update_data):
                    raise RuntimeError(err)

                start_data = await CaidoClient.gql(
                    "mutation StartAutomate($id: ID!) { startAutomateTask(automateSessionId: $id) { automateTask { id paused } } }",
                    {"id": auto_id},
                )
                if err := _gql_err(start_data):
                    raise RuntimeError(err)
                task_id = start_data["data"]["startAutomateTask"]["automateTask"]["id"]

            res_dict = {
                "success": True,
                "automate_session_id": auto_id,
                "task_id": task_id,
                "payloads_count": len(payloads),
                "placeholders": len(placeholders),
                "workers": workers,
            }
        except asyncio.TimeoutError:
            logger.error("caido_automate timeout (%ds)", _CAIDO_AUTOMATE_TIMEOUT)
            if task_id is None:
                await _cleanup()
            res_dict = {
                "success": False,
                "error": f"Caido did not respond within {_CAIDO_AUTOMATE_TIMEOUT} seconds",
            }
        except Exception as e:
            logger.error("caido_automate error: %s", e)
            if task_id is None:
                await _cleanup()
            res_dict = {"success": False, "error": str(e)}
        return tool_finish(
            self,
            tool_name,
            arguments,
            res_dict,
            start_time,
            res_dict.get("success", False),
        )

    async def _execute_caido_get_findings_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient

        self._last_output_file = None
        start_time = time.time()
        limit = min(int(arguments.get("limit", 50)), 200)

        try:
            data = await CaidoClient.gql(_FINDINGS_GQL, {"first": limit})
            if err := _gql_err(data):
                return _tool_err(
                    self,
                    tool_name,
                    arguments,
                    start_time,
                    RuntimeError(err),
                    "get_findings",
                )
            edges = _parse_gql_response(data, "findings", "edges")
            findings = [
                {
                    "id": e["node"]["id"],
                    "title": e["node"]["title"],
                    "description": e["node"].get("description", ""),
                    "reporter": e["node"].get("reporter", ""),
                    "request": {
                        "id": (req := e["node"].get("request") or {}).get("id"),
                        "method": req.get("method"),
                        "host": req.get("host"),
                        "path": req.get("path"),
                        "status": (req.get("response") or {}).get("statusCode"),
                    },
                }
                for e in edges
            ]
            res_dict = {"success": True, "findings": findings, "total": len(findings)}
        except Exception as e:
            res_dict = {"success": False, "error": str(e)}
            logger.error("caido_get_findings error: %s", e)
        return tool_finish(
            self,
            tool_name,
            arguments,
            res_dict,
            start_time,
            res_dict.get("success", False),
        )

    async def _execute_caido_set_scope_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient

        self._last_output_file = None
        start_time = time.time()
        allowlist = arguments.get("allowlist", [])
        denylist = arguments.get("denylist", [])
        scope_name = f"airecon-{self.state.active_target or 'scope'}"

        existing_id: str | None = None
        try:
            list_data = await CaidoClient.gql("query ListScopes { scopes { id name } }")
            for scope in _parse_gql_response(list_data, "scopes"):
                if scope.get("name") == scope_name:
                    existing_id = scope["id"]
                    break
        except (asyncio.TimeoutError, Exception) as _e:
            logger.debug("Could not list Caido scopes — will create new: %s", _e)

        variables: dict[str, Any] = {
            "input": {"name": scope_name, "allowlist": allowlist, "denylist": denylist},
        }
        try:
            if existing_id:
                variables["id"] = existing_id
                data = await CaidoClient.gql(
                    """mutation UpdateScope($id: ID!, $input: UpdateScopeInput!) {
                        updateScope(id: $id, input: $input) { scope { id name } }
                    }""",
                    variables,
                )
                scope_key = "updateScope"
            else:
                data = await CaidoClient.gql(
                    """mutation CreateScope($input: CreateScopeInput!) {
                        createScope(input: $input) { scope { id name } }
                    }""",
                    variables,
                )
                scope_key = "createScope"

            if err := _gql_err(data):
                res_dict = {"success": False, "error": err}
            else:
                scope = _parse_gql_response(data, scope_key, "scope")
                res_dict = {
                    "success": True,
                    "scope_id": scope.get("id"),
                    "scope_name": scope.get("name"),
                    "action": "updated" if existing_id else "created",
                    "allowlist": allowlist,
                    "denylist": denylist,
                }
        except Exception as e:
            logger.error("caido_set_scope error: %s", e)
            res_dict = {"success": False, "error": str(e)}
        return tool_finish(
            self,
            tool_name,
            arguments,
            res_dict,
            start_time,
            res_dict.get("success", False),
        )

    async def _execute_caido_intercept_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient  # noqa: F401

        self._last_output_file = None
        start_time = time.time()
        action = arguments.get("action", "status")
        message_id = arguments.get("message_id")
        raw_http = arguments.get("raw_http")

        handlers = {
            "status": lambda: self._caido_intercept_simple(
                "interceptStatus", "interceptStatus"
            ),
            "pause": lambda: self._caido_intercept_simple(
                "pauseIntercept", "pauseIntercept"
            ),
            "resume": lambda: self._caido_intercept_simple(
                "resumeIntercept", "resumeIntercept"
            ),
            "list": self._caido_intercept_list,
            "forward": lambda: self._caido_intercept_forward(message_id, raw_http),
            "drop": lambda: self._caido_intercept_drop(message_id),
        }

        handler = handlers.get(action)
        if handler is None:
            res_dict = {
                "success": False,
                "error": f"Unknown action: {action}. Use status/pause/resume/list/forward/drop",
            }
        else:
            res_dict = await handler()

        return tool_finish(
            self,
            tool_name,
            arguments,
            res_dict,
            start_time,
            res_dict.get("success", False),
        )

    async def _caido_intercept_simple(self, query: str, key: str) -> dict[str, Any]:
        from ..caido_client import CaidoClient

        try:
            data = await CaidoClient.gql(f"mutation {{ {query} {{ status }} }}")
            if err := _gql_err(data):
                return {"success": False, "error": err}
            return {
                "success": True,
                "status": _parse_gql_response(data, key).get("status", "UNKNOWN"),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _caido_intercept_list(self) -> dict[str, Any]:
        from ..caido_client import CaidoClient

        try:
            data = await CaidoClient.gql(_INTERCEPT_MESSAGES_GQL)
            if err := _gql_err(data):
                return {"success": False, "error": err}
            edges = _parse_gql_response(data, "interceptMessages", "edges")
            messages = [
                {
                    "id": e["node"]["id"],
                    "method": e["node"].get("request", {}).get("method"),
                    "host": e["node"].get("request", {}).get("host"),
                    "path": e["node"].get("request", {}).get("path"),
                }
                for e in edges
            ]
            return {"success": True, "queued": len(messages), "messages": messages}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _caido_intercept_forward(
        self, message_id: str | None, raw_http: str | None
    ) -> dict[str, Any]:
        from ..caido_client import CaidoClient

        if not message_id:
            return {"success": False, "error": "message_id required for forward"}
        variables: dict[str, Any] = {"id": message_id, "input": {}}
        if raw_http:
            encoded = CaidoClient.encode_raw_http(raw_http)
            variables["input"] = {
                "request": {"updateRaw": encoded, "updateContentLength": True}
            }
        try:
            data = await CaidoClient.gql(
                """mutation ForwardMessage($id: ID!, $input: ForwardInterceptMessageInput!) {
                    forwardInterceptMessage(id: $id, input: $input) {
                        ... on ForwardInterceptMessageSuccess { deletedId }
                        ... on Error { code message }
                    }
                }""",
                variables,
            )
            if err := _gql_err(data):
                return {"success": False, "error": err}
            payload = _parse_gql_response(data, "forwardInterceptMessage")
            if "code" in payload:
                return {"success": False, "error": payload.get("message")}
            return {
                "success": True,
                "action": "forwarded",
                "deleted_id": payload.get("deletedId"),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _caido_intercept_drop(self, message_id: str | None) -> dict[str, Any]:
        from ..caido_client import CaidoClient

        if not message_id:
            return {"success": False, "error": "message_id required for drop"}
        try:
            data = await CaidoClient.gql(
                """mutation DropMessage($id: ID!) {
                    dropInterceptMessage(id: $id) {
                        ... on DropInterceptMessageSuccess { deletedId }
                        ... on Error { code message }
                    }
                }""",
                {"id": message_id},
            )
            if err := _gql_err(data):
                return {"success": False, "error": err}
            payload = _parse_gql_response(data, "dropInterceptMessage")
            if "code" in payload:
                return {"success": False, "error": payload.get("message")}
            return {
                "success": True,
                "action": "dropped",
                "deleted_id": payload.get("deletedId"),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _execute_caido_sitemap_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient

        self._last_output_file = None
        start_time = time.time()
        parent_id = arguments.get("parent_id")

        try:
            if parent_id is None:
                data = await CaidoClient.gql(_SITEMAP_ROOT_GQL)
                key = "sitemapRootEntries"
                extra: dict[str, Any] = {"level": "root"}
            else:
                data = await CaidoClient.gql(
                    _SITEMAP_CHILDREN_GQL, {"parentId": str(parent_id)}
                )
                key = "sitemapDescendantEntries"
                extra = {"level": "children", "parent_id": parent_id}

            if err := _gql_err(data):
                return _tool_err(
                    self, tool_name, arguments, start_time, RuntimeError(err), "sitemap"
                )
            edges = _parse_gql_response(data, key, "edges")
            entries = [
                {
                    "id": e["node"]["id"],
                    "label": e["node"]["label"],
                    "kind": e["node"]["kind"],
                    "has_children": e["node"]["hasDescendants"],
                }
                for e in edges
            ]
            res_dict = {
                "success": True,
                **extra,
                "count": len(entries),
                "entries": entries,
            }
        except Exception as e:
            logger.error("caido_sitemap error: %s", e)
            res_dict = {"success": False, "error": str(e)}
        return tool_finish(
            self,
            tool_name,
            arguments,
            res_dict,
            start_time,
            res_dict.get("success", False),
        )
