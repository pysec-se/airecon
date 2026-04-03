from __future__ import annotations

import asyncio
import logging
import secrets
import shutil
import time
from pathlib import Path

logger = logging.getLogger("airecon.searxng")

SEARXNG_IMAGE = "docker.io/searxng/searxng:latest"
CONTAINER_NAME = "airecon-searxng"
INTERNAL_PORT = 8080
HEALTH_TIMEOUT = 30

def _config_dir() -> Path:
    d = Path.home() / ".airecon" / "searxng"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _write_settings(config_dir: Path) -> None:
    settings_path = config_dir / "settings.yml"
    if settings_path.exists():
        return

    source = Path(__file__).parent.parent / "containers" / "settings.yml"
    if not source.exists():
        logger.error(f"Source settings.yml not found at {source}")
        return

    content = source.read_text()

    secret_key = secrets.token_hex(32)
    content = content.replace(
        "  # secret_key is injected at runtime by AIRecon",
        f'  secret_key: "{secret_key}"',
    )

    settings_path.write_text(content)
    logger.info(f"SearXNG settings.yml copied to {settings_path}")

_shared_manager: SearXNGManager | None = None

_recovery_lock: asyncio.Lock | None = None

def _get_recovery_lock() -> asyncio.Lock:
    global _recovery_lock
    if _recovery_lock is None:
        _recovery_lock = asyncio.Lock()
    return _recovery_lock

def get_shared_manager(host_port: int = INTERNAL_PORT) -> SearXNGManager:
    global _shared_manager
    if _shared_manager is None:
        _shared_manager = SearXNGManager(host_port)
    return _shared_manager

async def ensure_searxng_running() -> bool:
    mgr = get_shared_manager()
    lock = _get_recovery_lock()
    if lock.locked():

        async with lock:
            return await mgr._is_running()
    async with lock:
        if await mgr._is_running():
            return True
        logger.warning("SearXNG appears down — attempting auto-recovery...")

        try:
            await mgr.stop_container()
        except Exception as _stop_err:
            logger.debug("Failed to stop old SearXNG container (may not exist): %s", _stop_err)

        try:
            url = await asyncio.wait_for(
                mgr.ensure_running(),
                timeout=60.0
            )
            if url:
                logger.info("SearXNG recovered successfully at %s", url)
                return True
        except asyncio.TimeoutError:
            logger.error("SearXNG recovery timed out after 60s — using DDG fallback")
        except Exception as _err:
            logger.error("SearXNG recovery failed: %s — using DDG fallback", _err)

        logger.error("SearXNG recovery failed — web_search will use DDG fallback")
        return False

class SearXNGManager:
    def __init__(self, host_port: int = INTERNAL_PORT) -> None:
        self.host_port = host_port
        self._config_dir = _config_dir()
        self._data_dir = self._config_dir / "data"
        self._data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def url(self) -> str:
        return f"http://localhost:{self.host_port}"

    async def ensure_running(self) -> str | None:
        if not shutil.which("docker"):
            logger.warning("Docker not found — skipping SearXNG auto-start")
            return None

        if await self._is_running():
            logger.info(f"SearXNG already running at {self.url}")
            return self.url

        _write_settings(self._config_dir)

        if not await self._image_exists():
            logger.info(f"Pulling SearXNG image ({SEARXNG_IMAGE})...")

            try:
                pull_result = await asyncio.wait_for(
                    self._pull_image(),
                    timeout=300.0
                )
                if not pull_result:
                    return None
            except asyncio.TimeoutError:
                logger.error("SearXNG image pull timed out after 5 minutes")
                return None
        else:
            logger.info("SearXNG image already present locally, skipping pull")

        logger.info("Starting SearXNG container...")
        if not await self._start_container():
            return None

        logger.info("Waiting for SearXNG to be ready...")
        if not await self._wait_healthy():
            logger.error("SearXNG did not become healthy in time")
            return None

        logger.info("SearXNG is ready")
        return self.url

    async def stop_container(self) -> None:
        if not shutil.which("docker"):
            return
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", CONTAINER_NAME,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        logger.info("SearXNG container stopped")

    async def is_running(self) -> bool:
        return await self._is_running()

    async def _is_running(self) -> bool:
        proc_exist = await asyncio.create_subprocess_exec(
            "docker", "ps", "-a",
            "--filter", f"name={CONTAINER_NAME}",
            "--format", "{{.Names}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout_exist, _ = await proc_exist.communicate()
        if CONTAINER_NAME not in stdout_exist.decode():

            logger.debug("SearXNG container does not exist — will auto-start")
            return False

        proc = await asyncio.create_subprocess_exec(
            "docker", "ps",
            "--filter", f"name={CONTAINER_NAME}",
            "--filter", "status=running",
            "--format", "{{.Names}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if CONTAINER_NAME not in stdout.decode():

            logger.debug("SearXNG container exists but not running — will restart")
            return False

        return await self._health_check()

    async def _image_exists(self) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "docker", "images", "-q", SEARXNG_IMAGE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return bool(stdout.decode().strip())

    async def _pull_image(self) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "docker", "pull", SEARXNG_IMAGE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        if proc.returncode != 0:
            logger.error(f"Failed to pull {SEARXNG_IMAGE}")
            return False
        return True

    async def _start_container(self) -> bool:
        logger.info("Removing any existing SearXNG container...")
        stop_proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", CONTAINER_NAME,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stop_stdout, stop_stderr = await stop_proc.communicate()
        if stop_proc.returncode == 0:
            logger.debug("Existing container removed")
        else:
            logger.debug("No existing container to remove (or rm failed): %s",
                        stop_stderr.decode()[:200] if stop_stderr else "unknown")

        cmd = [
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            "--restart", "unless-stopped",
            "-p", f"{self.host_port}:{INTERNAL_PORT}",
            "-v", f"{self._config_dir}:/etc/searxng",
            "-v", f"{self._data_dir}:/var/cache/searxng",
            "-e", f"SEARXNG_BASE_URL=http://localhost:{self.host_port}/",
            "--network", "bridge",
        ]

        cmd.append(SEARXNG_IMAGE)

        logger.info("Starting SearXNG container: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            stderr_text = stderr.decode() if stderr else "no stderr"
            logger.error(
                "Failed to start SearXNG (returncode=%d): %s",
                proc.returncode, stderr_text[:500]
            )

            if "address already in use" in stderr_text.lower() or "bind: address already in use" in stderr_text.lower():
                logger.error(
                    "Port %d is already in use! Check: sudo lsof -i:%d or ss -tlnp | grep :%d",
                    self.host_port, self.host_port, self.host_port
                )
            elif "permission denied" in stderr_text.lower():
                logger.error("Docker permission denied - try: sudo usermod -aG docker $USER && newgrp docker")
            return False

        container_id = stdout.decode().strip()[:12]
        if not container_id or len(container_id) < 5:
            logger.error("SearXNG container started but got invalid ID: %s", stdout.decode()[:200])
            return False

        logger.info(
            "✓ SearXNG container started: %s (ID: %s, port: %d)",
            CONTAINER_NAME, container_id, self.host_port
        )
        
        # Capture initial container logs for debugging
        await asyncio.sleep(2)  # Wait for container to initialize
        log_proc = await asyncio.create_subprocess_exec(
            "docker", "logs", "--tail", "20", CONTAINER_NAME,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        log_stdout, log_stderr = await log_proc.communicate()
        if log_stdout:
            logger.debug("SearXNG initial logs: %s", log_stdout.decode()[:1000])
        if log_stderr:
            logger.debug("SearXNG initial stderr: %s", log_stderr.decode()[:1000])
        
        return True

    async def _health_check(self) -> bool:
        import aiohttp

        fallback_allowed = False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.url}/healthz",
                    timeout=aiohttp.ClientTimeout(total=2),
                ) as resp:
                    if resp.status == 200:
                        body = (await resp.text()).strip().upper()
                        if body == "OK":
                            return True
                        logger.debug("SearXNG healthz unexpected body: %r", body[:80])
                        return False

                    if resp.status in (404, 405):
                        # Older builds may not expose /healthz.
                        fallback_allowed = True
                    else:
                        logger.debug("SearXNG healthz returned status=%d", resp.status)
                        return False
        except asyncio.TimeoutError:
            logger.debug("SearXNG healthz timeout (2s)")
            return False
        except aiohttp.ClientError as e:
            logger.debug("SearXNG healthz connection error: %s", e)
            return False
        except Exception as e:
            logger.debug("SearXNG healthz error: %s", e)
            return False

        if not fallback_allowed:
            return False

        # Fallback probe only when /healthz is unavailable.
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.url}/",
                    timeout=aiohttp.ClientTimeout(total=2),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _wait_healthy(self, timeout: int = HEALTH_TIMEOUT) -> bool:
        deadline = time.monotonic() + timeout
        consecutive_successes = 0
        required_successes = 2

        logger.info("Waiting for SearXNG to be healthy (timeout=%ds, need %d consecutive successes)...",
                   timeout, required_successes)

        while time.monotonic() < deadline:
            # Check if container is still running before health check
            container_running = await self._container_exists_and_running()
            if not container_running:
                logger.error("SearXNG container crashed during startup - check logs with: docker logs %s", CONTAINER_NAME)
                return False
            
            try:
                if await self._health_check():
                    consecutive_successes += 1
                    logger.debug("SearXNG health check #%d passed (%d/%d consecutive)",
                               consecutive_successes, consecutive_successes, required_successes)

                    if consecutive_successes >= required_successes:
                        logger.info("✓ SearXNG is healthy (%d consecutive successes)", consecutive_successes)
                        return True
                else:
                    if consecutive_successes > 0:
                        logger.debug("SearXNG health check failed — resetting consecutive counter")
                    consecutive_successes = 0

            except Exception as e:
                logger.debug("SearXNG health check error: %s", e)
                consecutive_successes = 0

            await asyncio.sleep(2)

        logger.error("SearXNG did not become healthy in %ds (max consecutive successes: %d/%d)",
                    timeout, consecutive_successes, required_successes)
        return False

    async def _container_exists_and_running(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                status = stdout.decode().strip().lower()
                return status == "true"
        except Exception:
            pass
        return False
