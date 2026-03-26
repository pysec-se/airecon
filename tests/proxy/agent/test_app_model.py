"""Tests for ApplicationModel (Priority 3: Application Model Builder)."""
from __future__ import annotations

import pytest

from airecon.proxy.agent.session import ApplicationModel, SessionData


@pytest.fixture()
def model() -> ApplicationModel:
    return ApplicationModel()


class TestUpdateFromResponse:
    def test_records_endpoint_and_method(self, model: ApplicationModel) -> None:
        model.update_from_response(
            url="https://example.com/api/users",
            method="GET",
            status_code=200,
            headers={},
            body_excerpt="",
        )
        assert "/api/users" in model.resources
        assert "GET" in model.resources["/api/users"]["methods"]

    def test_records_param_names(self, model: ApplicationModel) -> None:
        model.update_from_response(
            url="https://example.com/api/profile",
            method="GET",
            status_code=200,
            headers={},
            body_excerpt="",
            param_names=["user_id", "format"],
        )
        entry = model.resources["/api/profile"]
        assert "user_id" in entry["param_names"]
        assert "format" in entry["param_names"]

    def test_detects_bearer_auth_from_401(self, model: ApplicationModel) -> None:
        model.update_from_response(
            url="https://example.com/api/admin",
            method="GET",
            status_code=401,
            headers={"www-authenticate": "Bearer realm=api"},
            body_excerpt="",
        )
        assert model.auth_map.get("/api/admin") == "bearer"
        assert model.resources["/api/admin"]["auth_required"] is True

    def test_detects_basic_auth_from_401(self, model: ApplicationModel) -> None:
        model.update_from_response(
            url="https://example.com/api/secret",
            method="GET",
            status_code=401,
            headers={"www-authenticate": "Basic realm=app"},
            body_excerpt="",
        )
        assert model.auth_map.get("/api/secret") == "basic"

    def test_detects_cookie_auth_from_set_cookie(self, model: ApplicationModel) -> None:
        model.update_from_response(
            url="https://example.com/login",
            method="POST",
            status_code=200,
            headers={"set-cookie": "sessionid=abc123; HttpOnly"},
            body_excerpt="",
        )
        assert model.auth_map.get("/login") == "cookie"

    def test_detects_role_from_body(self, model: ApplicationModel) -> None:
        model.update_from_response(
            url="https://example.com/dashboard",
            method="GET",
            status_code=200,
            headers={},
            body_excerpt="Welcome admin, you have superuser privileges",
        )
        assert "admin" in model.roles_detected
        assert "superuser" in model.roles_detected

    def test_extracts_api_schema_from_json(self, model: ApplicationModel) -> None:
        model.update_from_response(
            url="https://example.com/api/user",
            method="GET",
            status_code=200,
            headers={"content-type": "application/json"},
            body_excerpt='{"id": 1, "username": "alice", "email": "a@b.com"}',
        )
        schema = model.api_schema.get("/api/user", {})
        assert "id" in schema
        assert "username" in schema
        assert "email" in schema

    def test_multiple_methods_on_same_endpoint(self, model: ApplicationModel) -> None:
        model.update_from_response("https://example.com/api/item", "GET", 200, {}, "")
        model.update_from_response("https://example.com/api/item", "POST", 201, {}, "")
        model.update_from_response("https://example.com/api/item", "DELETE", 204, {}, "")
        entry = model.resources["/api/item"]
        assert "GET" in entry["methods"]
        assert "POST" in entry["methods"]
        assert "DELETE" in entry["methods"]


class TestBuildContext:
    def test_returns_empty_when_no_data(self, model: ApplicationModel) -> None:
        ctx = model.build_context()
        assert ctx == ""

    def test_returns_xml_with_endpoints(self, model: ApplicationModel) -> None:
        model.update_from_response("https://example.com/api/users", "GET", 200, {}, "")
        ctx = model.build_context()
        assert "<application_model>" in ctx
        assert "/api/users" in ctx

    def test_includes_auth_info(self, model: ApplicationModel) -> None:
        model.update_from_response(
            "https://example.com/api/private",
            "GET",
            401,
            {"www-authenticate": "Bearer realm=api"},
            "",
        )
        ctx = model.build_context()
        assert "auth=required" in ctx or "bearer" in ctx.lower()

    def test_includes_roles(self, model: ApplicationModel) -> None:
        model.update_from_response(
            "https://example.com/page",
            "GET",
            200,
            {},
            "Hello admin, you have staff access",
        )
        ctx = model.build_context()
        assert "<roles>" in ctx
        assert "admin" in ctx


class TestSessionDataAppModel:
    def test_session_has_app_model(self) -> None:
        session = SessionData(target="https://example.com")
        assert hasattr(session, "app_model")
        assert isinstance(session.app_model, ApplicationModel)

    def test_session_has_waf_profiles(self) -> None:
        session = SessionData(target="https://example.com")
        assert hasattr(session, "waf_profiles")
        assert isinstance(session.waf_profiles, dict)
