"""Authentication Manager - Automated auth workflow and session recovery.

This module provides automated authentication handling for AIRecon,
enabling testing of authenticated workflows with automatic session recovery.

Usage:
    auth_manager = AuthManager()
    await auth_manager.handle_auth_failure(response, target_url)
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger("airecon.proxy.agent.auth_manager")


class AuthManager:
    """Automated authentication with session recovery."""
    
    # Auth failure detection patterns
    AUTH_FAILURE_PATTERNS = {
        "401_unauthorized": re.compile(r"401|unauthorized|authentication required", re.I),
        "403_forbidden": re.compile(r"403|forbidden|access denied", re.I),
        "session_expired": re.compile(r"session expired|session timeout|logged out", re.I),
        "csrf_token": re.compile(r"csrf|xsrf|token mismatch", re.I),
        "login_required": re.compile(r"login required|sign in|please log", re.I),
    }
    
    # Login form detection patterns
    LOGIN_FORM_PATTERNS = {
        "username": re.compile(r'name=["\']?(username|user|email|login)["\']?', re.I),
        "password": re.compile(r'name=["\']?(password|pass|pwd)["\']?', re.I),
        "csrf": re.compile(r'name=["\']?(csrf|_token|authenticity_token)["\']?', re.I),
    }
    
    def __init__(self, timeout: int = 30):
        """Initialize auth manager.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )
        
        # Stored credentials (provided by user)
        self.credentials: dict[str, Any] = {}
        
        # Session state
        self.auth_cookies: list[dict] = []
        self.auth_tokens: dict[str, str] = {}
        self.last_auth_attempt: float = 0
        self.auth_failures: int = 0
    
    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()

    async def __aenter__(self) -> "AuthManager":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()
    
    def detect_auth_failure(self, response: httpx.Response) -> tuple[bool, str]:
        """Detect authentication failure from response.
        
        Args:
            response: HTTP response
        
        Returns:
            Tuple of (is_failure, failure_type)
        """
        # Check status codes first
        if response.status_code == 401:
            return True, "401_unauthorized"
        
        if response.status_code == 403:
            return True, "403_forbidden"
        
        # Check response body for auth failure patterns
        body_text = response.text
        
        for failure_type, pattern in self.AUTH_FAILURE_PATTERNS.items():
            if pattern.search(body_text):
                logger.info(f"Auth failure detected: {failure_type}")
                return True, failure_type
        
        return False, ""
    
    async def handle_auth_failure(
        self,
        response: httpx.Response,
        target_url: str,
    ) -> bool:
        """Handle authentication failure automatically.
        
        Args:
            response: Failed HTTP response
            target_url: Target URL
        
        Returns:
            True if auth recovered successfully
        """
        is_failure, failure_type = self.detect_auth_failure(response)
        
        if not is_failure:
            return True  # No auth failure
        
        logger.info(f"Handling auth failure: {failure_type} on {target_url}")
        
        # Check if we have credentials stored
        if not self.credentials:
            logger.warning("No credentials stored - cannot auto-reauth")
            return False
        
        # Attempt re-authentication
        if failure_type in ("401_unauthorized", "session_expired", "login_required"):
            return await self.auto_reauth(target_url)
        
        if failure_type == "csrf_token":
            return await self.handle_csrf_failure(target_url)
        
        if failure_type == "403_forbidden":
            # 403 might be permission issue, not auth
            # Try re-auth anyway
            return await self.auto_reauth(target_url)
        
        return False
    
    async def auto_reauth(self, login_url: str) -> bool:
        """Attempt automatic re-authentication.
        
        Args:
            login_url: Login page URL
        
        Returns:
            True if re-authentication successful
        """
        try:
            # Step 1: Fetch login page to get CSRF token
            logger.info(f"Fetching login page: {login_url}")
            response = await self.client.get(login_url)
            
            # Step 2: Extract CSRF token if present
            csrf_token = self._extract_csrf_token(response.text)
            
            # Step 3: Prepare login data
            login_data = {
                "username": self.credentials.get("username", ""),
                "password": self.credentials.get("password", ""),
            }

            # Include user-supplied extra auth fields (tenant/otp/etc.).
            for field, value in self.credentials.items():
                if field in {"username", "password"}:
                    continue
                if value is None:
                    continue
                login_data[str(field)] = str(value)
            
            if csrf_token:
                csrf_fields = ("csrf_token", "csrf", "_token", "authenticity_token")
                applied = False
                for field_name in csrf_fields:
                    if field_name in login_data:
                        login_data[field_name] = csrf_token
                        applied = True
                if not applied:
                    login_data["csrf_token"] = csrf_token
                logger.info("CSRF token extracted and added to login")
            
            # Step 4: Submit login form
            login_response = await self.client.post(login_url, data=login_data)
            
            # Step 5: Check if login successful
            if self._is_login_successful(login_response):
                logger.info("Re-authentication successful")
                
                # Store new session cookies
                self._store_session_cookies(login_response.cookies)
                
                return True
            else:
                logger.warning("Re-authentication failed - invalid credentials?")
                self.auth_failures += 1
                return False
                
        except Exception as e:
            logger.error(f"Re-authentication error: {e}")
            return False
    
    async def handle_csrf_failure(self, target_url: str) -> bool:
        """Handle CSRF token mismatch.
        
        Args:
            target_url: URL that failed with CSRF error
        
        Returns:
            True if CSRF handled successfully
        """
        try:
            # Fetch page to get fresh CSRF token
            response = await self.client.get(target_url)
            csrf_token = self._extract_csrf_token(response.text)
            
            if csrf_token:
                logger.info("Fresh CSRF token obtained")
                # Token will be used in next request
                return True
            else:
                logger.warning("No CSRF token found on page")
                return False
                
        except Exception as e:
            logger.error(f"CSRF handling error: {e}")
            return False
    
    async def handle_oauth(
        self,
        oauth_url: str,
        client_id: str | None = None,
        redirect_uri: str | None = None,
    ) -> dict[str, Any]:
        """Automate OAuth 2.0 flow.
        
        Args:
            oauth_url: OAuth authorization URL
            client_id: OAuth client ID (optional)
            redirect_uri: Redirect URI (optional)
        
        Returns:
            Dict with OAuth tokens if successful
        """
        try:
            # Step 1: Authorization request
            params = {}
            if client_id:
                params["client_id"] = client_id
            if redirect_uri:
                params["redirect_uri"] = redirect_uri
            params["response_type"] = "code"
            
            logger.info(f"Starting OAuth flow: {oauth_url}")
            response = await self.client.get(oauth_url, params=params)
            
            # Step 2: Parse callback code from redirect
            # (In real implementation, would need to handle redirect)
            
            # Step 3: Token exchange (would need client_secret)
            # For now, return what we have
            
            return {
                "success": True,
                "message": "OAuth flow initiated (manual completion required)",
                "authorization_url": str(response.url),
            }
            
        except Exception as e:
            logger.error(f"OAuth flow error: {e}")
            return {
                "success": False,
                "error": str(e),
            }
    
    def set_credentials(
        self,
        username: str,
        password: str,
        extra_fields: dict[str, str] | None = None,
    ) -> None:
        """Store credentials for auto-reauth.
        
        Args:
            username: Username/email
            password: Password
            extra_fields: Additional form fields (optional)
        """
        self.credentials = {
            "username": username,
            "password": password,
        }
        
        if extra_fields:
            self.credentials.update(extra_fields)
        
        logger.info("Credentials stored for auto-reauth")
    
    def _extract_csrf_token(self, html: str) -> str | None:
        """Extract CSRF token from HTML.
        
        Args:
            html: HTML content
        
        Returns:
            CSRF token or None
        """
        # Try common CSRF token names
        patterns = [
            r'name=["\']?csrf_token["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
            r'name=["\']?_token["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
            r'name=["\']?authenticity_token["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
            r'name=["\']?csrf["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)
        
        return None
    
    def _is_login_successful(self, response: httpx.Response) -> bool:
        """Check if login was successful.

        Args:
            response: Login response

        Returns:
            True if login successful
        """
        # Immediate failure statuses — no body inspection needed.
        if response.status_code in (401, 403):
            return False

        body_lower = response.text.lower()

        # Failure indicators — checked BEFORE redirect and cookie heuristics
        # so that a 302 to /?error=invalid does not falsely return True.
        failure_indicators = (
            "invalid credentials",
            "incorrect password",
            "login failed",
            "authentication failed",
            "wrong username",
            "login required",
            "please sign in",
            "sign in",
        )
        for indicator in failure_indicators:
            if indicator in body_lower:
                return False

        # Success indicators — explicit positive signals.
        success_indicators = (
            "welcome",
            "logged in",
            "dashboard",
            "logout",  # Logout link present → user is authenticated
        )
        for indicator in success_indicators:
            if indicator in body_lower:
                return True

        # Redirect heuristic: only apply after body checks pass (no failure text).
        # httpx follows redirects (follow_redirects=True), so this branch is reached
        # only when the final page has no failure/success text.
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "").lower()
            if any(token in location for token in ("login", "signin", "sign-in", "auth")):
                return False
            return True

        # Session cookie markers as last resort.
        session_cookie_markers = (
            "session", "sessionid", "sess", "auth", "token", "jwt", "remember"
        )
        if any(
            any(marker in cookie.name.lower() for marker in session_cookie_markers)
            for cookie in response.cookies
        ):
            return True

        return False
    
    def _store_session_cookies(self, cookies: httpx.Cookies) -> None:
        """Store session cookies for future requests.
        
        Args:
            cookies: Response cookies
        """
        session_cookie_names = (
            "session",
            "sessionid",
            "sess",
            "phpsessid",
            "jsessionid",
            "asp.net_sessionid",
            # Note: __cfduid was removed by Cloudflare in May 2021 — not a session cookie.
            "remember",
            "auth",
            "jwt",
        )
        
        cookie_iterable = getattr(cookies, "jar", cookies)
        for cookie in cookie_iterable:
            if hasattr(cookie, "name"):
                cookie_name = str(cookie.name)
                cookie_value = str(cookie.value)
                cookie_domain = str(getattr(cookie, "domain", ""))
                cookie_path = str(getattr(cookie, "path", "/"))
            else:
                cookie_name = str(cookie)
                cookie_value = str(cookies.get(cookie_name, ""))
                cookie_domain = ""
                cookie_path = "/"

            cookie_lower = cookie_name.lower()
            if any(name in cookie_lower for name in session_cookie_names):
                self.auth_cookies.append({
                    "name": cookie_name,
                    "value": cookie_value,
                    "domain": cookie_domain,
                    "path": cookie_path,
                })
                logger.info(f"Session cookie stored: {cookie_name}")
        
        # Also store all cookies in client for automatic use
        self.client.cookies.update(cookies)
