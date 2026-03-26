import os
from airecon.proxy.reporting import create_vulnerability_report, calculate_cvss_and_severity


def test_calculate_cvss():
    # Base CVSS 3.1 Network / Low complexity / No privs / No interaction / Unchanged / High CIA
    score, severity, vector = calculate_cvss_and_severity(
        "N", "L", "N", "N", "U", "H", "H", "H"
    )
    assert score == 9.8
    assert severity == "critical"
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_reporting_validation_fails_missing_required():
    result = create_vulnerability_report(
        title="",  # Missing
        description="description",
        target="target.com",
        poc_description="poc",
        poc_script_code="code"
    )

    assert result["success"] is False
    assert "Title cannot be empty" in result["errors"]


def test_reporting_validation_fails_invalid_cve():
    result = create_vulnerability_report(
        title="Test",
        description="description",
        target="target.com",
        poc_description="poc",
        poc_script_code="code",
        cve="INVALID-CVE-FORMAT"
    )

    assert result["success"] is False
    assert "Invalid CVE format" in result["message"]


def test_reporting_success_and_file_creation(tmp_path):
    workspace = str(tmp_path)

    result = create_vulnerability_report(
        title="SQL Injection in Login",
        description="A classic SQLi.",
        target="example.com",
        poc_description="Drop tables.",
        poc_script_code="' OR 1=1--",
        # Providing CVSS Metrics
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="H",
        _workspace_root=workspace
    )

    assert result["success"] is True
    assert result["severity"] == "critical"

    filepath = result["report_path"]
    assert os.path.exists(filepath)

    with open(filepath, "r") as f:
        content = f.read()
        assert "# SQL Injection in Login" in content
        assert "CVSS: 9.8" in content
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in content
        assert "' OR 1=1--" in content


def test_reporting_duplicate_collision(tmp_path):
    workspace = str(tmp_path)

    # Create first time
    create_vulnerability_report(
        title="Identical Finding",
        description="desc",
        target="example.com",
        poc_description="poc",
        poc_script_code="code",
        _workspace_root=workspace
    )

    # Try again
    result2 = create_vulnerability_report(
        title="Identical Finding",
        description="desc",
        target="example.com",
        poc_description="poc",
        poc_script_code="code",
        _workspace_root=workspace
    )

    assert result2["success"] is False
    assert "already exists" in result2["message"]
    assert result2["duplicate_of"] == "identical_finding"


def test_reporting_uses_active_target_for_filesystem_reference(tmp_path):
    workspace = str(tmp_path)

    result = create_vulnerability_report(
        title="Binary Overflow in Challenge",
        description="Overflow found during local file analysis.",
        target="/workspace/challenge/uploads/challenge.exe",
        poc_description="Trigger overflow payload.",
        poc_script_code="python3 exploit.py",
        _workspace_root=workspace,
        _active_target="challenge",
    )

    assert result["success"] is True
    report_path = result["report_path"]
    assert "/challenge/vulnerabilities/" in report_path.replace("\\", "/")
    assert os.path.exists(report_path)


def test_reporting_uses_active_target_for_at_file_reference(tmp_path):
    workspace = str(tmp_path)

    result = create_vulnerability_report(
        title="Code Injection in Local Script",
        description="Detected risky eval on user-controlled input.",
        target="@/tmp/project/app.py",
        poc_description="PoC with malicious payload.",
        poc_script_code="python3 -c \"print('poc')\"",
        _workspace_root=workspace,
        _active_target="project",
    )

    assert result["success"] is True
    report_path = result["report_path"]
    assert "/project/vulnerabilities/" in report_path.replace("\\", "/")
    assert os.path.exists(report_path)


def test_reporting_uses_active_target_for_at_folder_reference(tmp_path):
    workspace = str(tmp_path)

    result = create_vulnerability_report(
        title="Misconfiguration in Local Folder Target",
        description="Detected insecure settings in local folder scan.",
        target="@/tmp/project/src",
        poc_description="Use crafted request to hit weak endpoint.",
        poc_script_code="curl -i http://localhost:8080/debug",
        _workspace_root=workspace,
        _active_target="project",
    )

    assert result["success"] is True
    report_path = result["report_path"]
    assert "/project/vulnerabilities/" in report_path.replace("\\", "/")
    assert os.path.exists(report_path)


def test_reporting_uses_domain_token_for_scheme_less_url_path(tmp_path):
    workspace = str(tmp_path)

    result = create_vulnerability_report(
        title="Scheme-less URL target parsing",
        description="Ensure host extraction for domain/path targets.",
        target="example.com/login",
        poc_description="Simple proof.",
        poc_script_code="curl -i https://example.com/login",
        _workspace_root=workspace,
    )

    assert result["success"] is True
    report_path = result["report_path"]
    assert "/example.com/vulnerabilities/" in report_path.replace("\\", "/")
    assert os.path.exists(report_path)


def test_reporting_full_cvss_integration(tmp_path):
    """INTEGRATION TEST: Full report generation with all CVSS fields and optional metadata."""
    workspace = str(tmp_path)

    result = create_vulnerability_report(
        title="Critical SQL Injection in Authentication Endpoint",
        description=(
            "A critical SQL injection vulnerability exists in the login endpoint. "
            "Attackers can bypass authentication and gain unauthorized access to user accounts. "
            "The vulnerability was confirmed with error-based SQL injection techniques."
        ),
        target="https://example.com/api/v1/login",
        poc_description=(
            "Send POST request with SQL payload in username parameter. "
            "Database error messages confirm SQL injection. "
            "Authentication bypass achieved with admin'-- payload."
        ),
        poc_script_code=(
            "curl -X POST https://example.com/api/v1/login \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -d '{\"username\": \"admin\\'--\", \"password\": \"x\"}' \\\n"
            "  | grep -i 'welcome'"
        ),
        # Full CVSS 3.1 metrics - Critical severity
        attack_vector="N",        # Network
        attack_complexity="L",    # Low
        privileges_required="N",  # None
        user_interaction="N",     # None
        scope="U",                # Unchanged
        confidentiality="H",      # High
        integrity="H",            # High
        availability="H",         # High
        # Optional metadata
        cve="CVE-2024-12345",
        impact="Complete system compromise possible. Attackers can bypass authentication and access all user accounts.",
        technical_analysis="Error-based SQL injection confirmed via verbose database error messages.",
        remediation_steps="Use parameterized queries or prepared statements. Validate and sanitize all user inputs.",
        suggested_fix="Replace string concatenation with parameterized query: cursor.execute('SELECT * FROM users WHERE username = ?', (username,))",
        _workspace_root=workspace,
    )

    # Assert success
    assert result["success"] is True
    assert "errors" not in result or len(result["errors"]) == 0

    # Assert CVSS calculation
    assert result["cvss_score"] == 9.8
    assert result.get("severity") == "critical"

    # Assert report file created
    report_path = result["report_path"]
    assert report_path is not None
    assert os.path.exists(report_path)
    assert "/example.com/vulnerabilities/" in report_path.replace("\\", "/")

    # Assert report content
    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "# Critical SQL Injection" in content
    assert "9.8" in content
    assert "CVE-2024-12345" in content
    assert "parameterized" in content.lower() or "Parameterized" in content
    assert "curl -X POST" in content
