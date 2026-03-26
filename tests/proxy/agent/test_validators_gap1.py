"""
Test Gap #1: HTTP Evidence Validation

Verifies that HTTP evidence requires actual impact proof, not just status codes.
"""

import pytest
from airecon.proxy.agent.validators import _ValidatorMixin
from airecon.proxy.agent.models import ToolExecution


class MockAgentLoop(_ValidatorMixin):
    """Mock for testing _ValidatorMixin validation methods."""
    pass


class TestHTTPEvidenceValidationGap1:
    """Test Gap #1: HTTP Evidence requires impact proof"""
    
    def setup_method(self):
        self.validator = MockAgentLoop()
    
    # ── FALSE POSITIVE REJECTION TESTS ────────────────────────────────────
    
    def test_reject_http_status_alone(self):
        """REJECT: Just 'HTTP 200' without impact proof"""
        poc = "Sent request to http://target/admin and received HTTP 200 response status code back from the server"
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl -v http://target/admin 2>&1 | grep HTTP",
            "poc_description": poc,
            "title": "Admin Panel Access",
            "technical_analysis": "The vulnerability allows unauthorized admin access to protected resources without authentication checks",
        })
        is_valid, msg = result
        assert not is_valid, "Should reject HTTP 200 without impact proof"
        assert msg is not None and "impact not documented" in msg.lower()

    def test_reject_generic_200_response(self):
        """REJECT: Generic '200 OK' without explaining what was in response"""
        poc = "The request was sent to http://target/api/users and returned a status code of HTTP 200 from the server"
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl -v http://target/api/users 2>&1 | head -20",
            "poc_description": poc,
            "title": "API Endpoint Accessible",
            "technical_analysis": "The endpoint is accessible without proper authentication checks implemented on the server side",
        })
        is_valid, msg = result
        assert not is_valid, "Should reject generic 200 status"
        assert msg is not None and "impact not documented" in msg.lower()

    def test_reject_redirect_alone(self):
        """REJECT: Status change shown but no impact explained"""
        poc = "Request changed status from HTTP 302 to HTTP 200 after following the redirect but no impact data provided"
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl -L http://target/bypass 2>&1 | grep -A5 HTTP",
            "poc_description": poc,
            "title": "Redirect Bypass",
            "technical_analysis": "We bypassed a redirect, but we need to explain what the bypass achieved and what access was granted",
        })
        is_valid, msg = result
        assert not is_valid, "Should reject status change without explaining what access was gained"
        assert msg is not None and "impact not documented" in msg.lower()
    
    # ── VALID ACCEPTANCE TESTS ────────────────────────────────────────────
    
    def test_accept_response_contains_admin_panel(self):
        """ACCEPT: Response contains evidence of admin access"""
        poc = (
            "curl http://target/admin returned HTTP 200 "
            "containing admin dashboard with user management panel and settings options visible"
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl -v http://target/admin 2>&1 | tee admin_response.txt | head -50",
            "poc_description": poc,
            "title": "Admin Panel Accessible",
            "technical_analysis": "Bypass allows unauthorized admin access without authentication. The admin interface was fully accessible.",
        })
        is_valid, msg = result
        assert is_valid, f"Should accept response with admin panel proof: {msg}"
    
    def test_accept_data_extraction_proof(self):
        """ACCEPT: Data was actually extracted"""
        poc = (
            "SQLi payload 1' OR 1=1 -- extracted user passwords from database via HTTP 200. "
            "Captured 5 admin credentials: admin:pass123, root:secret, etc."
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\necho \"Testing SQL injection\"\ncurl \"http://target/login?user=1' OR 1=1 --\" | grep -i password",
            "poc_description": poc,
            "title": "SQL Injection - Password Extraction",
            "technical_analysis": "SQL injection in login form allows direct database queries and credential theft without proper input validation",
        })
        is_valid, msg = result
        assert is_valid, f"Should accept password extraction proof: {msg}"
    
    def test_accept_error_message_proof(self):
        """ACCEPT: Error message proves SQL vulnerability"""
        poc = (
            "Request returned HTTP 200 with SQL syntax error: "
            "Uncaught mysqli exception: You have an error in your SQL syntax. "
            "This confirms the input is not properly sanitized."
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl \"http://target/search?q=1' AND 1=1\" 2>&1 | grep -i 'sql\\|error\\|syntax'",
            "poc_description": poc,
            "title": "SQL Injection via Search Parameter",
            "technical_analysis": "User input in search parameter is directly used in SQL queries without sanitization or parameterized statements",
        })
        is_valid, msg = result
        assert is_valid, f"Should accept SQL error proof: {msg}"
    
    def test_accept_status_code_change(self):
        """ACCEPT: Status code changed between requests"""
        poc = (
            "First request: GET /secret → HTTP 403 (Forbidden). "
            "With JWT token in cookie: GET /secret → HTTP 200 with user data. "
            "Status changed from 403 to 200 indicating access was granted."
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl -H 'Cookie: jwt=eyJ0eXAi' http://target/secret 2>&1 | head -30",
            "poc_description": poc,
            "title": "Authentication Bypass via JWT Manipulation",
            "technical_analysis": "JWT validation can be bypassed by modifying the token. Access controls are not properly enforced.",
        })
        is_valid, msg = result
        assert is_valid, f"Should accept status code change proof: {msg}"
    
    def test_accept_token_leaked(self):
        """ACCEPT: Security token was leaked"""
        poc = (
            "Response contains leaked API tokens: "
            "X-API-Key: sk_live_51234567890abcdefg, "
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIs... with HTTP 200 and exposed credentials"
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl -v http://target/api/config 2>&1 | grep -i 'x-api-key\\|authorization\\|token'",
            "poc_description": poc,
            "title": "API Keys Exposed in Configuration",
            "technical_analysis": "Sensitive API keys are stored in world-readable configuration files and leaked in HTTP 200 responses",
        })
        is_valid, msg = result
        assert is_valid, f"Should accept leaked token proof: {msg}"
    
    def test_accept_query_results_leaked(self):
        """ACCEPT: Query results show data extraction"""
        poc = (
            "HTTP 200 response contains: SELECT * FROM users returned 1247 records. "
            "Full database dump including emails, usernames, and password hashes obtained."
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl \"http://target/api/export?query=SELECT * FROM users\" 2>&1 | head -50",
            "poc_description": poc,
            "title": "Unrestricted Database Export",
            "technical_analysis": "User can export arbitrary database records without authentication or authorization checks. Database is completely exposed.",
        })
        is_valid, msg = result
        assert is_valid, f"Should accept query results proof: {msg}"
    
    # ── REAL-WORLD EXPLOITATION SCENARIOS ─────────────────────────────────
    
    def test_real_world_sqli_detection(self):
        """Real world SQLi: Error message + HTTP 200 proves vulnerability"""
        poc = (
            "GET /search?id=1' UNION SELECT NULL,version(),USER() -- returns HTTP 200\n"
            "Response contains: MySQL version 5.7.32 and current user mysql@localhost\n"
            "Error indicator: SQL syntax recognized the UNION statement"
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": (
                "#!/bin/bash\necho 'Testing SQL injection'\n"
                "curl \"http://target/search?id=1' UNION SELECT NULL,version(),USER() --\" | tee sqli_response.txt | head -50"
            ),
            "poc_description": poc,
            "title": "SQL Injection in Product ID Parameter",
            "technical_analysis": (
                "The /search endpoint concatenates user input directly into SQL queries. "
                "UNION-based SQLi allows extracting database version and user information."
            ),
        })
        is_valid, msg = result
        assert is_valid, f"Should accept real SQLi scenario: {msg}"
    
    def test_real_world_auth_bypass(self):
        """Real world auth bypass: Panel access proves vulnerability"""
        poc = (
            "Request with admin=1 parameter: GET /dashboard?admin=1 returns HTTP 200\n"
            "Response shows admin user management interface with options to:\n"
            "- Create new users\n"
            "- Reset passwords\n"
            "- Delete accounts\n"
            "Access granted without valid credentials."
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl 'http://target/dashboard?admin=1' 2>&1 | grep -i 'admin\\|user\\|delete\\|password' | head -20",
            "poc_description": poc,
            "title": "Admin Panel Accessible via Parameter Injection",
            "technical_analysis": (
                "Admin check relies on client-side admin parameter. "
                "Server does not verify authentication before showing admin interface. Complete bypass."
            ),
        })
        is_valid, msg = result
        assert is_valid, f"Should accept real auth bypass scenario: {msg}"
    
    def test_real_world_rce_detection(self):
        """Real world RCE: Command output proves code execution"""
        poc = (
            "Request: http://target/calc.php?expr=system('id') returns HTTP 200\n"
            "Response contains: uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            "This confirms arbitrary command execution on the server."
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\necho 'Testing RCE'\ncurl \"http://target/calc.php?expr=system('whoami')\" | tee rce_output.txt",
            "poc_description": poc,
            "title": "Remote Code Execution via PHP Expression Injection",
            "technical_analysis": (
                "The eval() function processes unsanitized user input, "
                "allowing arbitrary PHP code execution with web server privileges."
            ),
        })
        is_valid, msg = result
        assert is_valid, f"Should accept real RCE scenario: {msg}"
    
    def test_real_world_lfi_detection(self):
        """Real world LFI: File content proves local file inclusion"""
        poc = (
            "Request: GET /download?file=../../../../etc/passwd returns HTTP 200 with file content. "
            "Response successfully retrieved /etc/passwd with root:x:0:0:root:/root:/bin/bash and daemon user entries."
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": (
                "#!/bin/bash\necho 'Testing LFI'\n"
                "curl 'http://target/download?file=../../../../etc/passwd' 2>&1 | head -20"
            ),
            "poc_description": poc,
            "title": "Local File Inclusion via Path Traversal",
            "technical_analysis": (
                "The /download endpoint does not validate the file parameter, "
                "allowing path traversal to read arbitrary files from the server filesystem."
            ),
        })
        is_valid, msg = result
        assert is_valid, f"Should accept real LFI scenario: {msg}"
    
    # ── EDGE CASES ────────────────────────────────────────────────────────
    
    def test_ctf_flag_capture(self):
        """CTF: Flag capture is exempt from strict impact validation"""
        poc = "Accessed the secret endpoint via HTTP 200 and found the flag in the response body of the server"
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\necho 'CTF'\ncurl 'http://target/secret' 2>&1 | grep flag",
            "poc_description": poc,
            "title": "CTF Flag Retrieved",
            "technical_analysis": "Flag extraction method used for CTF challenge",
            "flag": "CTF{found_the_flag}",  # Setting flag makes is_ctf = True
        })
        is_valid, msg = result
        # CTF bypasses strict HTTP evidence check
        assert is_valid, f"CTF flags should bypass strict validation: {msg}"
    
    def test_multiple_status_codes_documented(self):
        """Accept: Multiple status code changes documented"""
        poc = (
            "First request without auth: GET /api/admin → HTTP 401 Unauthorized\n"
            "With role=admin header: GET /api/admin → HTTP 200 OK with admin data returned\n"
            "Status changed from 401 to 200, and user data was retrieved successfully."
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\ncurl -H 'role: admin' -v http://target/api/admin 2>&1 | grep HTTP",
            "poc_description": poc,
            "title": "Role-Based Access Control Bypass",
            "technical_analysis": "Role is checked via HTTP header without server-side verification or validation logic implementation",
        })
        is_valid, msg = result
        assert is_valid, f"Should accept multiple status code changes: {msg}"
    
    def test_sensitive_data_keywords(self):
        """Accept: Mentions of sensitive data extraction"""
        poc = (
            "Response contains sensitive information: password reset token retrieved for user admin@target.com, "
            "session cookie PHPSESSID=hijacked_session_id extracted from HTTP 200 response, credentials leaked"
        )
        result = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": "#!/bin/bash\necho 'Token extraction'\ncurl 'http://target/admin/reset' 2>&1 | grep -i 'token\\|session\\|cookie'",
            "poc_description": poc,
            "title": "Session Hijacking via Exposed Token",
            "technical_analysis": "Reset tokens are exposed in HTTP response and can be reused by attackers for session hijacking attacks",
        })
        is_valid, msg = result
        assert is_valid, f"Should accept sensitive data keywords: {msg}"

    def test_runtime_replay_mismatch_rejected_in_strict_phase(self):
        """Runtime context present but unrelated evidence should fail replay-verification."""
        self.validator._get_current_phase = lambda: type("P", (), {"value": "EXPLOIT"})()  # type: ignore[attr-defined]
        self.validator.state = type("S", (), {
            "tool_history": [
                ToolExecution(
                    tool_name="execute",
                    arguments={"command": "curl http://target/health"},
                    result={"stdout": "service alive"},
                    status="success",
                )
            ],
            "evidence_log": [],
        })()

        is_valid, msg = self.validator._validate_tool_args("create_vulnerability_report", {
            "poc_script_code": (
                "#!/bin/bash\n"
                "curl \"http://target/search?q=1' OR 1=1 --\" 2>&1 | head -20"
            ),
            "poc_description": (
                "Request returned HTTP 200 with SQL error and leaked user data from vulnerable endpoint."
            ),
            "title": "SQL Injection in Search Endpoint",
            "technical_analysis": (
                "Unsanitized user input is concatenated into SQL query and allows attacker-controlled predicates."
            ),
        })
        assert not is_valid
        assert msg is not None and "Replay verification confidence too low" in msg


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
