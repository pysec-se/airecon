import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from airecon.proxy.docker import DockerEngine


@pytest.fixture
def docker_engine():
    engine = DockerEngine()
    return engine


@pytest.mark.asyncio
async def test_ensure_image_skip_if_exists(docker_engine, mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/docker")

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.wait = AsyncMock()

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)

    result = await docker_engine.ensure_image()
    assert result is True
    # create_subprocess_exec should be called with "docker image inspect"
    asyncio.create_subprocess_exec.assert_called_with(
        "docker",
        "image",
        "inspect",
        docker_engine.IMAGE_NAME,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )


@pytest.mark.asyncio
async def test_start_container_success(docker_engine, mocker):
    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"abcdef1234567890\n", b""))

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)

    # Mocking get_workspace_root to prevent folder creation during test
    mocker.patch(
        "airecon.proxy.docker.get_workspace_root", return_value="/tmp/test_workspace"
    )

    # Needs to bypass the `apt update` background task waiting around
    mocker.patch.object(docker_engine, "execute", new_callable=AsyncMock)

    result = await docker_engine.start_container()

    assert result is True
    assert docker_engine.is_connected is True
    assert docker_engine._container_id == "abcdef123456"


@pytest.mark.asyncio
async def test_execute_success(docker_engine, mocker):
    docker_engine._connected = True
    docker_engine._container_name = "test-container"

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.wait = AsyncMock()

    # Stream readers need mock data yielding
    mock_stdout = AsyncMock()
    mock_stdout.read = AsyncMock(side_effect=[b"Command output test\n", b""])
    mock_stderr = AsyncMock()
    mock_stderr.read = AsyncMock(return_value=b"")

    mock_proc.stdout = mock_stdout
    mock_proc.stderr = mock_stderr

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)

    result = await docker_engine.execute("echo 'test'")

    assert result["success"] is True
    assert "Command output test\n" in result["stdout"]
    assert result["exit_code"] == 0


@pytest.mark.asyncio
async def test_execute_timeout(docker_engine, mocker):
    docker_engine._connected = True
    docker_engine._container_name = "test-container"

    mock_proc = AsyncMock()
    # returncode=None means the process is still running — required so the
    # TimeoutError handler's `if proc.returncode is None: proc.kill()` branch fires.
    mock_proc.returncode = None
    # Making the process block forever until timeout
    mock_proc.wait = AsyncMock(side_effect=asyncio.TimeoutError())

    mock_stdout = AsyncMock()
    mock_stdout.read = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_stderr = AsyncMock()
    mock_stderr.read = AsyncMock(side_effect=asyncio.TimeoutError())

    mock_proc.stdout = mock_stdout
    mock_proc.stderr = mock_stderr
    mock_proc.kill = MagicMock()

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)

    result = await docker_engine.execute("sleep 100", timeout=0.1)

    assert result["success"] is False
    assert result["exit_code"] == -1
    assert "timed out" in result["error"]
    mock_proc.kill.assert_called_once()


# ---------------------------------------------------------------------------
# exit_code=1 partial-success tests (grep/find pipeline false-negative fix)
# ---------------------------------------------------------------------------


def _make_exec_mock(
    mocker, docker_engine, returncode: int, stdout: bytes, stderr: bytes = b""
):
    """Helper: set up docker_engine.execute() with given returncode + output."""
    docker_engine._connected = True
    docker_engine._container_name = "test-container"

    mock_proc = AsyncMock()
    mock_proc.returncode = returncode
    mock_proc.wait = AsyncMock()

    mock_stdout = AsyncMock()
    mock_stdout.read = AsyncMock(side_effect=[stdout, b""])
    mock_stderr = AsyncMock()
    mock_stderr.read = AsyncMock(side_effect=[stderr, b""])

    mock_proc.stdout = mock_stdout
    mock_proc.stderr = mock_stderr

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
    return mock_proc


@pytest.mark.asyncio
async def test_execute_exit1_with_stdout_is_partial_success(docker_engine, mocker):
    """exit_code=1 + non-empty stdout → success=True (bash pipeline grep case)."""
    _make_exec_mock(
        mocker,
        docker_engine,
        returncode=1,
        stdout=b"Location: https://example.com/author/foo/\r\n",
    )
    result = await docker_engine.execute(
        "for i in 1 2 3; do curl -sk -I https://example.com/?p=$i | grep -i location; done"
    )

    assert result["success"] is True
    assert result["exit_code"] == 1
    assert "Location" in result["stdout"]


@pytest.mark.asyncio
async def test_execute_exit1_empty_stdout_is_failure(docker_engine, mocker):
    """exit_code=1 + empty stdout → success=False (real error)."""
    _make_exec_mock(
        mocker,
        docker_engine,
        returncode=1,
        stdout=b"",
        stderr=b"grep: invalid option",
    )
    result = await docker_engine.execute("grep --bad-flag foo")

    assert result["success"] is False
    assert result["exit_code"] == 1


@pytest.mark.asyncio
async def test_execute_exit2_with_stdout_is_failure(docker_engine, mocker):
    """exit_code=2 (real error) → success=False even if stdout has content."""
    _make_exec_mock(
        mocker,
        docker_engine,
        returncode=2,
        stdout=b"some partial output",
        stderr=b"command error",
    )
    result = await docker_engine.execute("somecommand --bad")

    assert result["success"] is False
    assert result["exit_code"] == 2


@pytest.mark.asyncio
async def test_execute_exit0_no_stdout_is_success(docker_engine, mocker):
    """exit_code=0 + empty stdout → success=True (normal zero-exit)."""
    _make_exec_mock(
        mocker,
        docker_engine,
        returncode=0,
        stdout=b"",
    )
    result = await docker_engine.execute("touch /tmp/test")

    assert result["success"] is True
    assert result["exit_code"] == 0


@pytest.mark.asyncio
async def test_start_container_tracks_background_task(docker_engine, mocker):
    """CRITICAL: Background apt-get update task should be tracked for cleanup."""
    mocker.patch("shutil.which", return_value="/usr/bin/docker")

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"abcdef1234567890\n", b""))
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
    mocker.patch("airecon.proxy.docker.get_workspace_root", return_value="/tmp/test")
    mocker.patch.object(docker_engine, "execute", new_callable=AsyncMock)

    await docker_engine.start_container()

    # Background task should be tracked
    assert len(docker_engine._background_tasks) == 1
    task = list(docker_engine._background_tasks)[0]
    assert isinstance(task, asyncio.Task)


@pytest.mark.asyncio
async def test_stop_container_cancels_background_tasks(docker_engine, mocker):
    """CRITICAL: stop_container must cancel and await background tasks to prevent leaks."""
    mocker.patch("shutil.which", return_value="/usr/bin/docker")

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"abcdef1234567890\n", b""))
    mock_proc.wait = AsyncMock()
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
    mocker.patch("airecon.proxy.docker.get_workspace_root", return_value="/tmp/test")
    mocker.patch.object(docker_engine, "execute", new_callable=AsyncMock)

    await docker_engine.start_container()
    assert len(docker_engine._background_tasks) == 1

    await docker_engine.stop_container()

    # Background tasks should be cleared after stop
    assert len(docker_engine._background_tasks) == 0
    assert docker_engine._connected is False


@pytest.mark.asyncio
async def test_force_stop_with_straggler_processes(docker_engine, mocker):
    """CRITICAL: force_stop must handle straggler processes gracefully."""
    docker_engine._container_name = "test-container"
    docker_engine._connected = True

    # Mock active processes
    mock_proc1 = AsyncMock()
    mock_proc1.returncode = None
    mock_proc1.kill = MagicMock(side_effect=ProcessLookupError("Process not found"))
    mock_proc1.wait = AsyncMock()

    mock_proc2 = AsyncMock()
    mock_proc2.returncode = 0
    mock_proc2.kill = MagicMock()
    mock_proc2.wait = AsyncMock()

    docker_engine._active_procs = {mock_proc1, mock_proc2}

    # Mock docker exec command for pkill
    mock_pkill_proc = AsyncMock()
    mock_pkill_proc.wait = AsyncMock()

    call_count = [0]

    def create_proc(*args, **kwargs):
        call_count[0] += 1
        # First call is pkill, second is docker rm (not used here)
        return mock_pkill_proc

    mocker.patch("asyncio.create_subprocess_exec", side_effect=create_proc)

    # force_stop should not raise even with straggler processes
    await docker_engine.force_stop()

    # All processes should be cleared
    assert len(docker_engine._active_procs) == 0
    # Note: force_stop doesn't set _connected=False, only stop_container does
