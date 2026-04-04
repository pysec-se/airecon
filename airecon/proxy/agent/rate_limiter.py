from __future__ import annotations

import asyncio
import logging
import random
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("airecon.proxy.agent.rate_limiter")


class AdaptiveRateLimiter:
    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_retries: int = 5,
        timeout: int = 30,
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.timeout = timeout

        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
        )

        self.domain_delays: dict[str, float] = {}
        self.last_request_time: dict[str, float] = {}
        self.rate_limit_hits: dict[str, int] = {}

        self.domain_locks: dict[str, asyncio.Lock] = {}

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self) -> "AdaptiveRateLimiter":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response | None:
        domain = urlparse(url).netloc

        for attempt in range(self.max_retries):
            try:
                await self._apply_rate_limit(domain)

                loop = asyncio.get_running_loop()
                request_started = loop.time()
                response = await self.client.request(method, url, **kwargs)
                request_elapsed_ms = (loop.time() - request_started) * 1000.0
                response.extensions["airecon_request_ms"] = request_elapsed_ms

                self.last_request_time[domain] = loop.time()

                if response.status_code == 429:
                    logger.warning("Rate limit hit (429) on %s", domain)
                    await self._handle_rate_limit(response, domain)
                    continue

                if response.status_code == 503:
                    logger.warning("Service unavailable (503) on %s", domain)
                    await self._handle_503(response, domain)
                    continue

                return response

            except httpx.TimeoutException:
                logger.warning("Request timeout on attempt %d", attempt + 1)
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.base_delay * (2**attempt))
                    continue
                return None

            except Exception as e:
                logger.error("Request error: %s", e)
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.base_delay)
                    continue
                return None

        logger.error("All %d retries exhausted for %s", self.max_retries, url)
        return None

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kwargs)

    async def _apply_rate_limit(self, domain: str) -> None:
        if domain not in self.domain_locks:
            self.domain_locks[domain] = asyncio.Lock()
        async with self.domain_locks[domain]:
            current_time = asyncio.get_running_loop().time()
            last_time = self.last_request_time.get(domain, 0)

            delay = self.domain_delays.get(domain, self.base_delay)
            elapsed = current_time - last_time

            if elapsed < delay:
                wait_time = delay - elapsed
                logger.debug("Rate limiting: waiting %.2fs for %s", wait_time, domain)
                await asyncio.sleep(wait_time)

            self.last_request_time[domain] = asyncio.get_running_loop().time()

    async def _handle_rate_limit(
        self,
        response: httpx.Response,
        domain: str,
    ) -> None:
        retry_after = response.headers.get("Retry-After")

        if retry_after:
            try:
                delay = int(retry_after)
                logger.info("Retry-After header: %ds", delay)
            except ValueError:
                delay = self.base_delay * 2
        else:
            hit_count = self.rate_limit_hits.get(domain, 0) + 1
            self.rate_limit_hits[domain] = hit_count

            delay = min(self.base_delay * (2**hit_count), self.max_delay)

        jitter = random.uniform(0.8, 1.2)
        delay *= jitter

        logger.info("Rate limit delay: %.2fs for %s", delay, domain)
        await asyncio.sleep(delay)

    async def _handle_503(
        self,
        response: httpx.Response,
        domain: str,
    ) -> None:
        hit_count = self.rate_limit_hits.get(domain, 0) + 1
        self.rate_limit_hits[domain] = hit_count

        delay = min(self.base_delay * (2**hit_count), self.max_delay)

        jitter = random.uniform(0.5, 1.5)
        delay *= jitter

        logger.info("503 backoff delay: %.2fs for %s", delay, domain)
        await asyncio.sleep(delay)

    def set_rate_limit(self, domain: str, requests_per_second: float) -> None:
        if requests_per_second > 0:
            delay = 1.0 / requests_per_second
            self.domain_delays[domain] = delay
            logger.info("Rate limit set for %s: %s req/s", domain, requests_per_second)

    def reset_rate_limit(self, domain: str) -> None:
        if domain in self.domain_delays:
            del self.domain_delays[domain]
        if domain in self.rate_limit_hits:
            del self.rate_limit_hits[domain]
        logger.info("Rate limit reset for %s", domain)

    async def rotate_ip(self) -> bool:
        logger.warning("IP rotation requested but not configured")
        return False

    def configure_proxy(self, proxy_url: str) -> None:
        old_client = self.client
        self.client = httpx.AsyncClient(
            proxy=proxy_url,
            timeout=self.timeout,
            follow_redirects=True,
        )

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(old_client.aclose())
        except RuntimeError:
            try:
                asyncio.run(old_client.aclose())
            except Exception as e:
                logger.debug("Expected failure closing old httpx client: %s", e)
        logger.info("Proxy configured: %s", proxy_url)
