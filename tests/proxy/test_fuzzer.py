import pytest
from unittest.mock import AsyncMock
import httpx
from airecon.proxy.fuzzer import Fuzzer, ExpertHeuristics, MutationEngine


@pytest.fixture
def base_fuzzer():
    return Fuzzer(target="http://example.com/api?id=1")


@pytest.mark.asyncio
async def test_fuzzer_baseline_and_run(base_fuzzer, mocker):
    mock_post = AsyncMock()
    mock_get = AsyncMock()

    # baseline get and fuzz get both mocked
    mock_response_baseline = mocker.MagicMock()
    mock_response_baseline.text = '{"status": "ok"}'
    mock_response_baseline.status_code = 200

    # Fuzzed response simulating SQL Injection detection via Error Payload Heuristics
    mock_response_fuzz = mocker.MagicMock()
    mock_response_fuzz.text = '{"error": "mysql_fetch array expected"}'
    mock_response_fuzz.status_code = 500

    # We assign them in sequence to our side_effect
    mock_get.side_effect = [mock_response_baseline, mock_response_fuzz]

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
