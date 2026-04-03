from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from .models import ToolExecution

logger = logging.getLogger("airecon.agent")


class _CaidoExecutorMixin:
    async def _execute_caido_list_requests_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient

        self._last_output_file = None
        start_time = time.time()
        filter_query = str(arguments.get("filter", "")).strip().lower()
        try:
            limit = min(max(int(arguments.get("limit", 50)), 1), 200)
        except (TypeError, ValueError):
            limit = 50

        query = """
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

        try:
            data = await CaidoClient.gql(query)
            if "errors" in data:
                res_dict = {"success": False, "error": data["errors"][0]["message"]}
                success = False
            else:
                edges = data.get("data", {}).get("requests", {}).get("edges", [])
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
                success = True
        except Exception as e:
            logger.error("caido_list_requests error: %s", e)
            err = str(e)
            res_dict = {"success": False, "error": err}
            if "All connection attempts failed" in err:
                res_dict["next_action"] = (
                    "Caido host service is unreachable. Start/login Caido outside sandbox first, "
                    "then verify using caido_intercept with action='status'."
                )
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=res_dict,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return (success, duration, res_dict, None)

    async def _execute_caido_send_request_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        request_id = self._str_arg(arguments, "request_id")
        raw_http = self._str_arg(arguments, "raw_http")

        host = self._str_arg(arguments, "host").removeprefix("https://").removeprefix("http://").rstrip("/")

        _is_tls_raw = arguments.get("is_tls", True)
        if isinstance(_is_tls_raw, str):
            is_tls = _is_tls_raw.lower() not in ("false", "0", "no", "")
        else:
            is_tls = bool(_is_tls_raw)

        _port_raw = arguments.get("port")
        try:
            port = int(_port_raw) if _port_raw is not None else (443 if is_tls else 80)
        except (TypeError, ValueError):
            port = 443 if is_tls else 80

        try:
            async with asyncio.timeout(60):

                create_q = """
                mutation CreateReplay($input: CreateReplaySessionInput!) {
                    createReplaySession(input: $input) {
                        session { id }
                    }
                }
                """
                source: dict[str, Any] = {}
                if request_id:
                    source = {"id": request_id}
                create_vars: dict[str, Any] = {"input": {}}
                if source:
                    create_vars["input"]["requestSource"] = source

                create_data = await CaidoClient.gql(create_q, create_vars)
                if "errors" in create_data:
                    raise RuntimeError(create_data["errors"][0]["message"])
                session_id = create_data["data"]["createReplaySession"]["session"]["id"]

                start_q = """
                mutation StartReplay($sessionId: ID!, $input: StartReplayTaskInput!) {
                    startReplayTask(sessionId: $sessionId, input: $input) {
                        task { id }
                    }
                }
                """
                task_input: dict[str, Any] = {
                    "connection": {"host": host, "port": port, "isTLS": is_tls},
                    "settings": {"closeConnection": False, "updateContentLength": True, "placeholders": []},
                }
                if raw_http:
                    task_input["raw"] = CaidoClient.encode_raw_http(raw_http)

                start_data = await CaidoClient.gql(start_q, {"sessionId": session_id, "input": task_input})
                if "errors" in start_data:
                    raise RuntimeError(start_data["errors"][0]["message"])

                task_id = start_data["data"]["startReplayTask"]["task"]["id"]
            res_dict = {"success": True, "session_id": session_id, "task_id": task_id,
                        "host": host, "port": port}
            success = True
        except asyncio.TimeoutError:
            logger.error("caido_send_request timeout (60s)")
            res_dict = {
                "success": False,
                "error": "Caido did not respond within 60 seconds"}
            success = False
        except Exception as e:
            logger.error("caido_send_request error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_caido_automate_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        raw_http = self._str_arg(arguments, "raw_http")
        host = self._str_arg(arguments, "host").removeprefix("https://").removeprefix("http://").rstrip("/")
        _is_tls_raw = arguments.get("is_tls", True)
        if isinstance(_is_tls_raw, str):
            is_tls = _is_tls_raw.lower() not in ("false", "0", "no", "")
        else:
            is_tls = bool(_is_tls_raw)
        _port_raw = arguments.get("port")
        try:
            port = int(_port_raw) if _port_raw is not None else (443 if is_tls else 80)
        except (TypeError, ValueError):
            port = 443 if is_tls else 80
        raw_payloads = arguments.get("payloads", [])
        if not isinstance(raw_payloads, list):
            return False, 0.0, {"success": False, "error": "payloads must be a list of strings"}, None
        payloads = [str(p) for p in raw_payloads if isinstance(p, (str, int, float)) and str(p).strip()]
        if not payloads:
            return False, 0.0, {"success": False, "error": "payloads list is empty or contains no valid string items"}, None
        if len(payloads) > 10_000:
            return False, 0.0, {"success": False, "error": f"payloads list too large ({len(payloads)}); max 10,000 items"}, None
        workers = min(int(arguments.get("workers", 10)), 50)

        placeholders = CaidoClient.find_fuzz_offsets(raw_http)
        clean_http = raw_http.replace("§FUZZ§", "")
        encoded_raw = CaidoClient.encode_raw_http(clean_http)

        auto_id: str | None = None
        task_id: str | None = None

        async def _cleanup_orphan_session() -> None:
            if not auto_id:
                return
            try:
                delete_q = """
                mutation DeleteSession($id: ID!) {
                    deleteAutomateSession(id: $id) { deletedId }
                }
                """
                await asyncio.wait_for(
                    CaidoClient.gql(delete_q, {"id": auto_id}), timeout=5.0
                )
                logger.info("Cleaned up orphaned Caido automate session %s", auto_id)
            except Exception as cleanup_err:
                logger.debug(
                    "Could not clean up Caido session %s (manual cleanup may be needed): %s",
                    auto_id, cleanup_err,
                )

        try:
            async with asyncio.timeout(90):

                create_q = "mutation { createAutomateSession(input: {}) { session { id } } }"
                create_data = await CaidoClient.gql(create_q)
                if "errors" in create_data:
                    raise RuntimeError(create_data["errors"][0]["message"])
                auto_id = create_data["data"]["createAutomateSession"]["session"]["id"]

                update_q = """
                mutation UpdateAutomate($id: ID!, $input: UpdateAutomateSessionInput!) {
                    updateAutomateSession(id: $id, input: $input) {
                        session { id }
                    }
                }
                """
                update_input: dict[str, Any] = {
                    "connection": {"host": host, "port": port, "isTLS": is_tls},
                    "raw": encoded_raw,
                    "settings": {
                        "closeConnection": False,
                        "updateContentLength": True,
                        "strategy": "SEQUENTIAL",
                        "concurrency": {"workers": workers, "delay": 0},
                        "placeholders": placeholders,
                        "payloads": [{"preprocessors": [], "options": {"simpleList": {"list": payloads}}}],
                        "retryOnFailure": "FAILED",
                    },
                }
                update_data = await CaidoClient.gql(update_q, {"id": auto_id, "input": update_input})
                if "errors" in update_data:
                    raise RuntimeError(update_data["errors"][0]["message"])

                start_q = """
                mutation StartAutomate($id: ID!) {
                    startAutomateTask(automateSessionId: $id) {
                        automateTask { id paused }
                    }
                }
                """
                start_data = await CaidoClient.gql(start_q, {"id": auto_id})
                if "errors" in start_data:
                    raise RuntimeError(start_data["errors"][0]["message"])

                task_id = start_data["data"]["startAutomateTask"]["automateTask"]["id"]
            res_dict = {
                "success": True,
                "automate_session_id": auto_id,
                "task_id": task_id,
                "payloads_count": len(payloads),
                "placeholders": len(placeholders),
                "workers": workers,
            }
            success = True
        except asyncio.TimeoutError:
            logger.error("caido_automate timeout (90s)")

            if task_id is None:
                await _cleanup_orphan_session()
            res_dict = {
                "success": False,
                "error": "Caido did not respond within 90 seconds"}
            success = False
        except Exception as e:
            logger.error("caido_automate error: %s", e)

            if task_id is None:
                await _cleanup_orphan_session()
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_caido_get_findings_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        limit = min(int(arguments.get("limit", 50)), 200)

        query = """
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
        try:
            data = await CaidoClient.gql(query, {"first": limit})
            if "errors" in data:
                res_dict = {
                    "success": False,
                    "error": data["errors"][0]["message"]}
                success = False
            else:
                edges = data.get(
                    "data",
                    {}).get(
                    "findings",
                    {}).get(
                    "edges",
                    [])
                findings = [
                    {
                        "id": e["node"]["id"],
                        "title": e["node"]["title"],
                        "description": e["node"].get("description", ""),
                        "reporter": e["node"].get("reporter", ""),
                        "request": {
                            "id": (e["node"].get("request") or {}).get("id"),
                            "method": (e["node"].get("request") or {}).get("method"),
                            "host": (e["node"].get("request") or {}).get("host"),
                            "path": (e["node"].get("request") or {}).get("path"),
                            "status": ((e["node"].get("request") or {}).get("response") or {}).get("statusCode"),
                        },
                    }
                    for e in edges
                ]
                res_dict = {
                    "success": True,
                    "findings": findings,
                    "total": len(findings)}
                success = True
        except Exception as e:
            logger.error("caido_get_findings error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_caido_set_scope_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        allowlist = arguments.get("allowlist", [])
        denylist = arguments.get("denylist", [])
        scope_name = f"airecon-{self.state.active_target or 'scope'}"

        try:

            list_q = """
            query ListScopes {
                scopes { id name }
            }
            """
            existing_id: str | None = None
            try:
                list_data = await CaidoClient.gql(list_q)
                scopes_list = (
                    list_data.get("data", {})
                    .get("scopes", [])
                )
                for scope in scopes_list:
                    if scope.get("name") == scope_name:
                        existing_id = scope["id"]
                        break
            except Exception as _list_err:
                logger.debug("Could not list Caido scopes: %s — will create new", _list_err)

            if existing_id:

                update_q = """
                mutation UpdateScope($id: ID!, $input: UpdateScopeInput!) {
                    updateScope(id: $id, input: $input) {
                        scope { id name }
                    }
                }
                """
                variables: dict[str, Any] = {
                    "id": existing_id,
                    "input": {
                        "name": scope_name,
                        "allowlist": allowlist,
                        "denylist": denylist,
                    },
                }
                data = await CaidoClient.gql(update_q, variables)
                scope_key = "updateScope"
            else:

                create_q = """
                mutation CreateScope($input: CreateScopeInput!) {
                    createScope(input: $input) {
                        scope { id name }
                    }
                }
                """
                variables = {
                    "input": {
                        "name": scope_name,
                        "allowlist": allowlist,
                        "denylist": denylist,
                    },
                }
                data = await CaidoClient.gql(create_q, variables)
                scope_key = "createScope"

            if "errors" in data:
                res_dict = {
                    "success": False,
                    "error": data["errors"][0]["message"],
                }
                success = False
            else:
                scope = (
                    data.get("data", {})
                    .get(scope_key, {})
                    .get("scope", {})
                )
                res_dict = {
                    "success": True,
                    "scope_id": scope.get("id"),
                    "scope_name": scope.get("name"),
                    "action": "updated" if existing_id else "created",
                    "allowlist": allowlist,
                    "denylist": denylist,
                }
                success = True
        except Exception as e:
            logger.error("caido_set_scope error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_caido_intercept_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        action = arguments.get("action", "status")
        message_id = arguments.get("message_id")
        raw_http = arguments.get("raw_http")

        try:
            if action == "status":
                data = await CaidoClient.gql("{ interceptStatus }")
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    status = data.get("data", {}).get("interceptStatus", "UNKNOWN")
                    res_dict = {"success": True, "status": status}
                    success = True

            elif action == "pause":
                data = await CaidoClient.gql(
                    "mutation { pauseIntercept { status } }"
                )
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    status = (
                        data.get("data", {})
                        .get("pauseIntercept", {})
                        .get("status", "UNKNOWN")
                    )
                    res_dict = {"success": True, "status": status}
                    success = True

            elif action == "resume":
                data = await CaidoClient.gql(
                    "mutation { resumeIntercept { status } }"
                )
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    status = (
                        data.get("data", {})
                        .get("resumeIntercept", {})
                        .get("status", "UNKNOWN")
                    )
                    res_dict = {"success": True, "status": status}
                    success = True

            elif action == "list":
                query = """
                query {
                    interceptMessages(first: 20, kind: REQUEST) {
                        edges {
                            node {
                                id
                                ... on InterceptRequestMessage {
                                    request {
                                        method
                                        host
                                        path
                                    }
                                }
                            }
                        }
                    }
                }
                """
                data = await CaidoClient.gql(query)
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    edges = (
                        data.get("data", {})
                        .get("interceptMessages", {})
                        .get("edges", [])
                    )
                    messages = [
                        {
                            "id": e["node"]["id"],
                            "method": e["node"].get("request", {}).get("method"),
                            "host": e["node"].get("request", {}).get("host"),
                            "path": e["node"].get("request", {}).get("path"),
                        }
                        for e in edges
                    ]
                    res_dict = {"success": True, "queued": len(messages), "messages": messages}
                    success = True

            elif action == "forward":
                if not message_id:
                    res_dict = {"success": False, "error": "message_id required for forward"}
                    success = False
                else:
                    variables: dict[str, Any] = {"id": message_id}
                    if raw_http:
                        encoded = CaidoClient.encode_raw_http(raw_http)
                        variables["input"] = {
                            "request": {"updateRaw": encoded, "updateContentLength": True}
                        }
                    else:
                        variables["input"] = {}
                    mutation = """
                    mutation ForwardMessage($id: ID!, $input: ForwardInterceptMessageInput!) {
                        forwardInterceptMessage(id: $id, input: $input) {
                            ... on ForwardInterceptMessageSuccess { deletedId }
                            ... on Error { code message }
                        }
                    }
                    """
                    data = await CaidoClient.gql(mutation, variables)
                    if "errors" in data:
                        res_dict = {"success": False, "error": data["errors"][0]["message"]}
                        success = False
                    else:
                        payload = data.get("data", {}).get("forwardInterceptMessage", {})
                        if "code" in payload:
                            res_dict = {"success": False, "error": payload.get("message")}
                            success = False
                        else:
                            res_dict = {
                                "success": True,
                                "action": "forwarded",
                                "deleted_id": payload.get("deletedId"),
                            }
                            success = True

            elif action == "drop":
                if not message_id:
                    res_dict = {"success": False, "error": "message_id required for drop"}
                    success = False
                else:
                    mutation = """
                    mutation DropMessage($id: ID!) {
                        dropInterceptMessage(id: $id) {
                            ... on DropInterceptMessageSuccess { deletedId }
                            ... on Error { code message }
                        }
                    }
                    """
                    data = await CaidoClient.gql(mutation, {"id": message_id})
                    if "errors" in data:
                        res_dict = {"success": False, "error": data["errors"][0]["message"]}
                        success = False
                    else:
                        payload = data.get("data", {}).get("dropInterceptMessage", {})
                        if "code" in payload:
                            res_dict = {"success": False, "error": payload.get("message")}
                            success = False
                        else:
                            res_dict = {
                                "success": True,
                                "action": "dropped",
                                "deleted_id": payload.get("deletedId"),
                            }
                            success = True

            else:
                res_dict = {
                    "success": False,
                    "error": f"Unknown action: {action}. Use status/pause/resume/list/forward/drop",
                }
                success = False

        except Exception as e:
            logger.error("caido_intercept error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_caido_sitemap_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        parent_id = arguments.get("parent_id")

        try:
            if parent_id is None:

                query = """
                {
                    sitemapRootEntries {
                        edges {
                            node {
                                id
                                label
                                kind
                                hasDescendants
                            }
                        }
                    }
                }
                """
                data = await CaidoClient.gql(query)
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    edges = (
                        data.get("data", {})
                        .get("sitemapRootEntries", {})
                        .get("edges", [])
                    )
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
                        "level": "root",
                        "count": len(entries),
                        "entries": entries,
                    }
                    success = True
            else:

                query = """
                query SitemapChildren($parentId: ID!) {
                    sitemapDescendantEntries(parentId: $parentId, depth: DIRECT) {
                        edges {
                            node {
                                id
                                label
                                kind
                                hasDescendants
                            }
                        }
                    }
                }
                """
                data = await CaidoClient.gql(query, {"parentId": str(parent_id)})
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    edges = (
                        data.get("data", {})
                        .get("sitemapDescendantEntries", {})
                        .get("edges", [])
                    )
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
                        "level": "children",
                        "parent_id": parent_id,
                        "count": len(entries),
                        "entries": entries,
                    }
                    success = True

        except Exception as e:
            logger.error("caido_sitemap error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None
