import json
from airecon.proxy.agent.output_parser import (
    parse_tool_output,
    detect_tool,
    _parse_metasploit,
)


def test_detect_tool():
    assert detect_tool("nmap -sV -p- 10.0.0.1") == "nmap"
    assert detect_tool("sudo      nmap -v example.com") == "nmap"
    assert detect_tool(
        "ffuf -w wordlist.txt -u http://example.com/FUZZ") == "ffuf"
    assert detect_tool("unknowncommand arg1 arg2") is None


def test_detect_tool_with_common_wrappers():
    assert detect_tool("timeout 30 nmap -sV example.com") == "nmap"
    assert detect_tool("stdbuf -oL -eL nuclei -u https://example.com") == "nuclei"
    assert detect_tool("env FOO=1 BAR=2 httpx -u https://example.com") == "httpx"


def test_parse_tool_output_empty():
    assert parse_tool_output("nmap localhost", "") is None
    assert parse_tool_output("nmap localhost", "    \n   ") is None


def test_parse_nmap_text():
    output = """
Starting Nmap 7.94
Host is up (0.01s latency).
Not shown: 998 closed tcp ports
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.41
443/tcp open  https    nginx 1.18.0
    """
    parsed = parse_tool_output("nmap localhost", output)
    assert parsed is not None
    assert parsed.tool == "nmap"
    assert parsed.total_count == 2
    assert "80/tcp open http" in parsed.items[0]
    assert "443/tcp open https" in parsed.items[1]


def test_parse_ffuf_jsonl():
    ffuf_out = json.dumps({"results": [
        {"url": "http://example.com/admin",
            "status": 200, "length": 421, "words": 15},
        {"url": "http://example.com/login", "status": 403, "length": 190, "words": 5}
    ]})

    parsed = parse_tool_output("ffuf", ffuf_out)
    assert parsed is not None
    assert parsed.tool == "ffuf"
    assert parsed.total_count == 2
    assert "http://example.com/admin" in parsed.items[0]
    assert "Status: 200" in parsed.items[0]


def test_parse_httpx_jsonl_with_tech():
    httpx_out = json.dumps({
        "url": "https://example.com",
        "status_code": 200,
        "title": "Welcome",
        "tech": ["nginx/1.24", "PHP/8.1", "React"]
    }) + "\n"

    parsed = parse_tool_output("httpx", httpx_out)
    assert parsed is not None
    assert parsed.tool == "httpx"
    assert parsed.total_count == 1

    # Ensures technology parsing logic extracts pairs properly
    assert parsed.technologies.get("nginx") == "1.24"
    assert parsed.technologies.get("React") == ""


def test_generic_list_parser():
    output = """
http://example.com/api
http://example.com/login
http://example.com/dashboard
    """
    parsed = parse_tool_output("katana", output)
    # The detect_tool identifies katana as using generic list
    assert parsed is not None
    assert parsed.tool == "url_list"
    assert parsed.total_count == 3
    assert parsed.items[0] == "http://example.com/api"


def test_generic_smart_parser_fallback():
    output = """
=== Unrecognized Tool V1 ===
[+] Target1 : Exposed DB
[!] Target2 : Permission Denied
[-] Target3 : Offline
    """
    # Force generic parser explicitly by giving a command with no known tool
    parsed = parse_tool_output("someunknowntool", output)
    assert parsed is not None
    assert parsed.tool == "someunknowntool"
    # The Generic Tagged parser retains non-tagged lines (like the header)
    assert parsed.total_count == 4
    assert "[+]" in parsed.items[1]


def test_detect_tool_with_shell_trampoline():
    assert detect_tool("bash -lc 'nmap -sV example.com'") == "nmap"
    assert detect_tool("sh -c \"httpx -u https://example.com\"") == "httpx"


def test_detect_tool_with_timeout_env_options():
    assert detect_tool("timeout --signal=KILL 30 nmap -sV example.com") == "nmap"
    assert detect_tool("env -i FOO=1 BAR=2 httpx -u https://example.com") == "httpx"
    assert detect_tool("/usr/bin/sudo /usr/bin/nuclei -u https://example.com") == "nuclei"


def test_parse_metasploit_ignores_negative_vulnerable_claims():
    output = "\n".join(
        [
            "[+] Target is NOT vulnerable to CVE-2024-1234",
            "[+] Meterpreter session opened (10.10.14.2:4444 -> 10.10.10.10:9999)",
        ]
    )
    parsed = _parse_metasploit(output)
    assert parsed.total_count == 1
    assert any("meterpreter session opened" in item.lower() for item in parsed.items)
    assert all("not vulnerable" not in item.lower() for item in parsed.items)


def test_parse_tool_output_emits_causal_observations_with_phase():
    output = """
http://example.com/admin [200]
http://example.com/login [403]
    """
    parsed = parse_tool_output("httpx -silent", output, phase="ANALYSIS")
    assert parsed is not None
    assert parsed.causal_observations
    obs_types = {obs.get("observation_type") for obs in parsed.causal_observations}
    assert "endpoint_observed" in obs_types
    assert "endpoint_accessible" in obs_types
    assert all(obs.get("phase") == "ANALYSIS" for obs in parsed.causal_observations)


def test_parse_tool_output_fallback_has_causal_observation():
    output = "Some unstructured but non-empty tool output"
    parsed = parse_tool_output("custombinary --scan", output, phase="RECON")
    assert parsed is not None
    assert parsed.causal_observations
    first = parsed.causal_observations[0]
    assert first.get("observation_type") in {"tool_output_observed", "endpoint_discovered"}
