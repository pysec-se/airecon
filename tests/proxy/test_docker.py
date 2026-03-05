import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
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
        "docker", "image", "inspect", docker_engine.IMAGE_NAME,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )


@pytest.mark.asyncio
async def test_start_container_success(docker_engine, mocker):
    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"abcdef1234567890\n", b""))
    
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
    
    # Mocking get_workspace_root to prevent folder creation during test
    mocker.patch("airecon.proxy.docker.get_workspace_root", return_value="/tmp/test_workspace")
    
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
