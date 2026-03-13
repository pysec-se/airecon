from airecon.proxy.agent.executors import _ExecutorMixin, _RECON_SUBDOMAIN_BINS


class _DummyPhase:
    value = "RECON"


class _DummyAgent(_ExecutorMixin):
    def __init__(self):
        self._executed_tool_counts = {}

    def _get_current_phase(self):
        return _DummyPhase()


def test_extract_command_binary_handles_cd_and_sudo():
    agent = _DummyAgent()
    cmd = "cd /workspace/example.com && sudo /usr/bin/subfinder -d example.com"
    assert agent._extract_command_binary(cmd) == "subfinder"


def test_extract_command_binary_handles_wrappers():
    agent = _DummyAgent()
    cmd = "cd /workspace/example.com && timeout 30 stdbuf -oL env FOO=1 /usr/bin/amass enum -d example.com"
    assert agent._extract_command_binary(cmd) == "amass"


def test_recon_subdomain_bins_loaded_from_metadata():
    # Must come from tools_meta.json, not hardcoded in executors.py
    assert "subfinder" in _RECON_SUBDOMAIN_BINS
    assert "amass" in _RECON_SUBDOMAIN_BINS
    assert "assetfinder" in _RECON_SUBDOMAIN_BINS


def test_recon_repeat_blocked_for_subfinder_after_first_run():
    agent = _DummyAgent()
    blocked = agent._is_recon_phase_repeat_blocked(
        "execute",
        {"command": "subfinder -d example.com -silent"},
        count=1,
    )
    assert blocked is True


def test_recon_repeat_not_blocked_for_non_recon_binary():
    agent = _DummyAgent()
    blocked = agent._is_recon_phase_repeat_blocked(
        "execute",
        {"command": "python exploit.py"},
        count=1,
    )
    assert blocked is False


def test_extract_command_binary_handles_shell_trampoline():
    agent = _DummyAgent()
    cmd = "bash -lc 'timeout 20 /usr/bin/subfinder -d example.com -silent'"
    assert agent._extract_command_binary(cmd) == "subfinder"


def test_extract_command_binary_handles_timeout_and_env_options():
    agent = _DummyAgent()
    cmd = "timeout --signal=KILL 25 env -i FOO=1 /usr/bin/subfinder -d example.com"
    assert agent._extract_command_binary(cmd) == "subfinder"
