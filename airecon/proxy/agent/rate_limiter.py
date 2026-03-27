"""Adaptive Rate Limiter - Automatic rate limit handling and retry logic.

This module provides adaptive rate limiting for AIRecon,
enabling testing of rate-limited targets with automatic retry and backoff.

Usage:
    rate_limiter = AdaptiveRateLimiter()
    response = await rate_limiter.request(url)
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("airecon.proxy.agent.rate_limiter")


class AdaptiveRateLimiter:
    """Adaptive rate limiting with retry logic."""
    
    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_retries: int = 5,
        timeout: int = 30,
    ):
        """Initialize rate limiter.
        
        Args:
            base_delay: Base delay between requests (seconds)
            max_delay: Maximum delay for exponential backoff (seconds)
            max_retries: Maximum retry attempts
            timeout: Request timeout (seconds)
        """
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.timeout = timeout
        
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
        )
        
        # Rate limit state per domain
        self.domain_delays: dict[str, float] = {}
        self.last_request_time: dict[str, float] = {}
        self.rate_limit_hits: dict[str, int] = {}
    
    async def close(self):
        """Close HTTP client."""
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
        """Make HTTP request with automatic rate limit handling.
        
        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Additional arguments for httpx
        
        Returns:
            HTTP response or None if all retries exhausted
        """
        domain = urlparse(url).netloc
        
        for attempt in range(self.max_retries):
            try:
                # Apply rate limiting delay
                await self._apply_rate_limit(domain)

                # Make request — store loop once to avoid repeated calls
                loop = asyncio.get_running_loop()
                request_started = loop.time()
                response = await self.client.request(method, url, **kwargs)
                request_elapsed_ms = (loop.time() - request_started) * 1000.0
                response.extensions["airecon_request_ms"] = request_elapsed_ms

                # Update last request time
                self.last_request_time[domain] = loop.time()
                
                # Check for rate limit response
                if response.status_code == 429:
                    logger.warning(f"Rate limit hit (429) on {domain}")
                    await self._handle_rate_limit(response, domain)
                    continue
                
                if response.status_code == 503:
                    logger.warning(f"Service unavailable (503) on {domain}")
                    await self._handle_503(response, domain)
                    continue
                
                # Success or other error - return response
                return response
                
            except httpx.TimeoutException:
                logger.warning(f"Request timeout on attempt {attempt + 1}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.base_delay * (2 ** attempt))
                    continue
                return None
            
            except Exception as e:
                logger.error(f"Request error: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.base_delay)
                    continue
                return None
        
        # All retries exhausted
        logger.error(f"All {self.max_retries} retries exhausted for {url}")
        return None
    
    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        """Make GET request with rate limiting."""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        """Make POST request with rate limiting."""
        return await self.request("POST", url, **kwargs)
    
    async def _apply_rate_limit(self, domain: str) -> None:
        """Apply rate limiting delay for domain.
        
        Args:
            domain: Target domain
        """
        current_time = asyncio.get_running_loop().time()
        last_time = self.last_request_time.get(domain, 0)
        
        # Get delay for this domain
        delay = self.domain_delays.get(domain, self.base_delay)
        
        # Calculate time since last request
        elapsed = current_time - last_time
        
        # Wait if necessary
        if elapsed < delay:
            wait_time = delay - elapsed
            logger.debug(f"Rate limiting: waiting {wait_time:.2f}s for {domain}")
            await asyncio.sleep(wait_time)
    
    async def _handle_rate_limit(
        self,
        response: httpx.Response,
        domain: str,
    ) -> None:
        """Handle 429 rate limit response.
        
        Args:
            response: 429 response
            domain: Target domain
        """
        # Parse Retry-After header
        retry_after = response.headers.get("Retry-After")
        
        if retry_after:
            try:
                delay = int(retry_after)
                logger.info(f"Retry-After header: {delay}s")
            except ValueError:
                # Retry-After might be HTTP date
                delay = self.base_delay * 2
        else:
            # Exponential backoff
            hit_count = self.rate_limit_hits.get(domain, 0) + 1
            self.rate_limit_hits[domain] = hit_count
            
            delay = min(
                self.base_delay * (2 ** hit_count),
                self.max_delay
            )
        
        # Add jitter to prevent thundering herd
        jitter = random.uniform(0.8, 1.2)
        delay *= jitter
        
        logger.info(f"Rate limit delay: {delay:.2f}s for {domain}")
        await asyncio.sleep(delay)
    
    async def _handle_503(
        self,
        response: httpx.Response,
        domain: str,
    ) -> None:
        """Handle 503 service unavailable response.
        
        Args:
            response: 503 response
            domain: Target domain
        """
        # Exponential backoff for 503
        hit_count = self.rate_limit_hits.get(domain, 0) + 1
        self.rate_limit_hits[domain] = hit_count
        
        delay = min(
            self.base_delay * (2 ** hit_count),
            self.max_delay
        )
        
        # Add jitter
        jitter = random.uniform(0.5, 1.5)
        delay *= jitter
        
        logger.info(f"503 backoff delay: {delay:.2f}s for {domain}")
        await asyncio.sleep(delay)
    
    def set_rate_limit(self, domain: str, requests_per_second: float) -> None:
        """Set rate limit for specific domain.
        
        Args:
            domain: Target domain
            requests_per_second: Maximum requests per second
        """
        if requests_per_second > 0:
            delay = 1.0 / requests_per_second
            self.domain_delays[domain] = delay
            logger.info(f"Rate limit set for {domain}: {requests_per_second} req/s")
    
    def reset_rate_limit(self, domain: str) -> None:
        """Reset rate limit for domain.
        
        Args:
            domain: Target domain
        """
        if domain in self.domain_delays:
            del self.domain_delays[domain]
        if domain in self.rate_limit_hits:
            del self.rate_limit_hits[domain]
        logger.info(f"Rate limit reset for {domain}")
    
    async def rotate_ip(self) -> bool:
        """Rotate source IP (requires proxy configuration).
        
        Returns:
            True if IP rotation successful
        """
        # Note: Actual IP rotation requires proxy pool integration
        # This is a placeholder for future implementation
        
        logger.warning("IP rotation requested but not configured")
        return False
    
    def configure_proxy(self, proxy_url: str) -> None:
        """Configure proxy for requests.

        Args:
            proxy_url: Proxy URL (e.g., http://proxy:8080)

        Note:
            This method must be called BEFORE starting async work.  If called
            while a running event loop exists the old client is scheduled for
            cleanup via ``loop.create_task``; if not, the caller is responsible
            for awaiting ``close()`` on the old client before replacing it.
            Do NOT call this mid-operation in an async context.
        """
        old_client = self.client
        self.client = httpx.AsyncClient(
            proxy=proxy_url,
            timeout=self.timeout,
            follow_redirects=True,
        )
        # Schedule cleanup without blocking.  If there is a running event loop
        # (the normal AIRecon async context) use create_task so the coroutine
        # runs on that loop.  asyncio.run() must NEVER be called from within a
        # running loop — it raises RuntimeError and is not safe here.
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(old_client.aclose())
        except RuntimeError:
            # No running loop at all (e.g. unit-test / sync context).
            # Close synchronously via a fresh temporary loop.
            import asyncio as _asyncio  # local import to keep namespace clean
            _asyncio.get_event_loop().run_until_complete(old_client.aclose())
        logger.info("Proxy configured: %s", proxy_url)
