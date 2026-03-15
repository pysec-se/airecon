import pytest
import httpx
from unittest.mock import AsyncMock
from airecon.proxy.fuzzer import Fuzzer, ExpertHeuristics, FuzzResult, MutationEngine


@pytest.fixture
def base_fuzzer():
    return Fuzzer(target="http://example.com/api?id=1")


@pytest.mark.asyncio
async def test_fuzzer_baseline_and_run(base_fuzzer, mocker):
    mock_get = AsyncMock()

    # baseline get and fuzz get both mocked
    mock_response_baseline = mocker.MagicMock()
    mock_response_baseline.text = '{"status": "ok"}'
    mock_response_baseline.status_code = 200

    # Fuzzed response simulating SQL Injection detection via Error Payload Heuristics
    mock_response_fuzz = mocker.MagicMock()
    mock_response_fuzz.text = '{"error": "mysql_fetch array expected"}'
    mock_response_fuzz.status_code = 500

    # _fetch_baseline now sends 2 requests to measure length variance;
    # then 1 request for the actual fuzz probe.
    mock_get.side_effect = [mock_response_baseline, mock_response_baseline, mock_response_fuzz]

    mock_client = mocker.MagicMock()
    mock_client.__aenter__.return_value.get = mock_get
    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    # Run
    # Base heuristic wait loop logic uses real time
    results = await base_fuzzer.fuzz_parameters(["id"], ["sql_injection"])

    assert len(results) > 0
    sql_finding = results[0]

    assert sql_finding.vuln_type == "sql_injection"
    # SQL error heuristic overrides confidence mapping to critical
    assert sql_finding.severity == "critical"
    assert sql_finding.response_code == 500


def test_heuristics_differential():
    baseline = "Clean page"
    fuzzed = "Clean page <b>syntax error near</b> unclosed"

    # Need to simulate the fact that ExpertHeuristics requires specific SQL error phrase presence
    # to hit the 0.5 confidence threshold for "vuln_confirmed"

    res = ExpertHeuristics.analyze_response_differential(
        baseline_body=baseline,
        baseline_status=200,
        baseline_time_ms=50,
        fuzz_body=fuzzed,
        fuzz_status=200,
        fuzz_time_ms=50,
        payload="'",
        vuln_type="sql_injection"
    )

    assert res["vuln_type"] == "sql_injection"
    assert "syntax error near" in str(res["evidence"]).lower()


def test_mutation_engine_wordlists():
    base = ["user"]
    combos = MutationEngine.generate_wordlist_combinations(base, max_size=50)

    # Check if a few expected combos are naturally crafted by the engine
    assert "user_admin" in combos or "admin_user" in combos
    assert "user_test" in combos or "test_user" in combos


# ── auth headers + WAF skip fix ──────────────────────────────────────────────

def test_fuzzer_accepts_headers_param():
    fuzzer = Fuzzer(target="http://example.com/", headers={"Authorization": "Bearer tok"})
    assert fuzzer.headers == {"Authorization": "Bearer tok"}


def test_fuzzer_default_headers_empty():
    assert Fuzzer(target="http://example.com/").headers == {}


def _fuzzer_with_baseline(status: int, headers: dict | None = None) -> Fuzzer:
    f = Fuzzer(target="http://example.com/?id=1", headers=headers)
    f._baseline["id"] = {
        "body": "ok", "status": status,
        "time_ms": 50.0, "length": 2, "length_variance": 0,
    }
    return f


@pytest.mark.asyncio
async def test_fuzzer_skips_429_with_auth():
    """Rate-limited → skip even when auth headers present."""
    fuzzer = _fuzzer_with_baseline(429, headers={"Cookie": "s=abc"})
    with pytest.MonkeyPatch().context() as mp:
        calls = []
        async def fake_fuzz(*a, **kw): calls.append(1); return None
        mp.setattr(fuzzer, "_fuzz_single", fake_fuzz)
        await fuzzer.fuzz_parameters(["id"], ["xss"])
    assert calls == []


@pytest.mark.asyncio
async def test_fuzzer_skips_401_without_auth():
    """401 with no auth → skip (unauthenticated WAF block)."""
    fuzzer = _fuzzer_with_baseline(401, headers=None)
    with pytest.MonkeyPatch().context() as mp:
        calls = []
        async def fake_fuzz(*a, **kw): calls.append(1); return None
        mp.setattr(fuzzer, "_fuzz_single", fake_fuzz)
        await fuzzer.fuzz_parameters(["id"], ["xss"])
    assert calls == []


@pytest.mark.asyncio
async def test_fuzzer_keeps_401_with_auth():
    """401 with auth headers → fuzz (may reveal auth bypass)."""
    fuzzer = _fuzzer_with_baseline(401, headers={"Cookie": "s=abc"})
    with pytest.MonkeyPatch().context() as mp:
        calls = []
        async def fake_fuzz(*a, **kw): calls.append(1); return None
        mp.setattr(fuzzer, "_fuzz_single", fake_fuzz)
        await fuzzer.fuzz_parameters(["id"], ["xss"])
    assert len(calls) > 0


# ── timeout false positive — 2x confirmation ─────────────────────────────────

@pytest.mark.asyncio
async def test_single_timeout_not_reported(mocker):
    """First timeout → None (needs 2 hits)."""
    fuzzer = Fuzzer(target="http://example.com/?id=1")
    fuzzer._baseline["id"] = {
        "body": "", "status": 200, "time_ms": 50.0, "length": 0, "length_variance": 0
    }
    mock_client = mocker.MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    result = await fuzzer._fuzz_single("id", "' OR SLEEP(5)--", "sql_injection")
    assert result is None
    assert fuzzer._timeout_counts.get("id:sql_injection", 0) == 1


@pytest.mark.asyncio
async def test_second_timeout_reported(mocker):
    """Second timeout → FuzzResult with confidence 0.75 and multi-sample note."""
    fuzzer = Fuzzer(target="http://example.com/?id=1")
    fuzzer._baseline["id"] = {
        "body": "", "status": 200, "time_ms": 50.0, "length": 0, "length_variance": 0
    }
    fuzzer._timeout_counts["id:sql_injection"] = 1  # pre-seed first hit

    mock_client = mocker.MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    result = await fuzzer._fuzz_single("id", "' OR SLEEP(5)--", "sql_injection")
    assert isinstance(result, FuzzResult)
    assert "time_based" in result.vuln_type
    assert result.confidence == 0.75
    assert "multi-sample" in result.evidence
