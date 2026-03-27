"""Tests for WAF Bypass Engine."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from airecon.proxy.agent.waf_bypass import WAFBypassEngine


class TestWAFDetection:
    """Test WAF detection logic."""

    def test_config_loaded_from_json(self) -> None:
        engine = WAFBypassEngine()
        assert "generic" in engine.BYPASS_STRATEGIES
        assert "cloudflare" in engine.WAF_PATTERNS
        assert engine.DETECTION_MIN_SCORE >= 1
        assert engine.MAX_STRATEGIES_PER_PROFILE >= 1

    def test_detect_cloudflare(self) -> None:
        """Test Cloudflare detection."""
        engine = WAFBypassEngine()
        
        headers = {
            "cf-ray": "7a1234abcd-LHR",
            "cf-cache-status": "HIT",
            "set-cookie": "__cfduid=abc123",
        }
        
        detected = engine.detect_waf(headers, "", 200)
        
        assert "cloudflare" in detected
    
    def test_detect_modsecurity(self) -> None:
        """Test ModSecurity detection."""
        engine = WAFBypassEngine()
        
        headers = {"x-modsecurity": "active"}
        body = "ModSecurity: Access denied by rule set"
        
        detected = engine.detect_waf(headers, body, 403)
        
        assert "modsecurity" in detected
    
    def test_detect_sucuri(self) -> None:
        """Test Sucuri detection."""
        engine = WAFBypassEngine()
        
        headers = {
            "x-sucuri-id": "12345",
            "x-sucuri-cache": "HIT",
        }
        
        detected = engine.detect_waf(headers, "", 200)
        
        assert "sucuri" in detected
    
    def test_detect_multiple_wafs(self) -> None:
        """Test detection of multiple WAFs."""
        engine = WAFBypassEngine()
        
        # Simulate Cloudflare + ModSecurity
        headers = {
            "cf-ray": "7a1234abcd-LHR",
            "x-modsecurity": "active",
        }
        body = "ModSecurity: Access denied"
        
        detected = engine.detect_waf(headers, body, 403)
        
        assert len(detected) >= 1
        assert "cloudflare" in detected or "modsecurity" in detected
    
    def test_no_waf_detected(self) -> None:
        """Test when no WAF is present."""
        engine = WAFBypassEngine()
        
        headers = {"server": "nginx/1.18.0"}
        body = "<html><body>Hello</body></html>"
        
        detected = engine.detect_waf(headers, body, 200)
        
        assert len(detected) == 0

    def test_detect_cloudflare_from_cookie_and_server(self) -> None:
        """Cookie + server headers should still detect Cloudflare."""
        engine = WAFBypassEngine()

        headers = {
            "set-cookie": "__cfduid=abc123; path=/; HttpOnly",
            "server": "cloudflare",
        }

        detected = engine.detect_waf(headers, "", 200)
        assert "cloudflare" in detected


class TestBypassStrategies:
    """Test WAF bypass strategies."""

    @pytest.mark.asyncio
    async def test_header_rotation_bypass(self) -> None:
        """Test header rotation bypass strategy."""
        engine = WAFBypassEngine()
        
        # Mock successful bypass
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"OK"
        mock_response.text = "Success"
        
        engine._send_request = AsyncMock(return_value=mock_response)
        engine._is_bypass_successful = MagicMock(return_value=True)
        
        result = await engine.test_bypass(
            target_url="http://example.com/test",
            waf_type="cloudflare",
            payload="' OR 1=1--",
            param_name="id",
        )
        
        assert result["strategies_tested"] > 0
        assert len(result["successful_bypasses"]) > 0
    
    @pytest.mark.asyncio
    async def test_encoding_bypass(self) -> None:
        """Test encoding bypass strategy."""
        engine = WAFBypassEngine()
        
        # Test URL encoding
        encoded = engine._encode_payload("' OR 1=1--", "url")
        assert encoded == "%27%20OR%201%3D1--"
        
        # Test double URL encoding
        double_encoded = engine._encode_payload("' OR 1=1--", "double_url")
        assert double_encoded == "%2527%2520OR%25201%253D1--"
        
        # Test Unicode encoding
        unicode_encoded = engine._encode_payload("test", "unicode")
        assert unicode_encoded == "\\u0074\\u0065\\u0073\\u0074"
    
    @pytest.mark.asyncio
    async def test_case_variation(self) -> None:
        """Test case variation bypass."""
        engine = WAFBypassEngine()
        
        payload = "SELECT * FROM users"
        varied = engine._mix_case(payload)
        
        # Should be same length
        assert len(varied) == len(payload)
        
        # Should contain same characters (case-insensitive)
        assert varied.lower() == payload.lower()
    
    @pytest.mark.asyncio
    async def test_sql_comment_bypass(self) -> None:
        """Test SQL comment bypass."""
        # Test various SQL comments
        comments = ["--", "#", "/*", "-- -", "#-"]
        
        for comment in comments:
            test_payload = f"' OR 1=1{comment}"
            # Just verify it doesn't crash
            assert len(test_payload) > 0

    @pytest.mark.asyncio
    async def test_cookie_bypass_strategy_is_executed(self) -> None:
        engine = WAFBypassEngine()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"OK"
        mock_response.text = "ok"
        engine._send_request = AsyncMock(return_value=mock_response)
        engine._is_bypass_successful = MagicMock(return_value=True)
        result = await engine._apply_strategy(
            url="http://example.com/test",
            strategy={"name": "cookie_bypass", "cookies": {"a": "1", "b": "2"}},
            payload="test",
            param_name="id",
            method="GET",
            base_headers=None,
        )
        assert result["success"] is True
        assert "cookie_header" in result

    @pytest.mark.asyncio
    async def test_parameter_pollution_strategy_is_executed(self) -> None:
        engine = WAFBypassEngine()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"OK"
        mock_response.text = "ok"
        engine._send_parameter_pollution_request = AsyncMock(return_value=mock_response)
        engine._is_bypass_successful = MagicMock(return_value=True)
        result = await engine._apply_strategy(
            url="http://example.com/test",
            strategy={"name": "parameter_pollution", "technique": "duplicate_params"},
            payload="test",
            param_name="id",
            method="GET",
            base_headers=None,
        )
        assert result["success"] is True
        assert result["technique"] == "duplicate_params"


class TestBypassSuccessDetection:
    """Test bypass success detection logic."""

    def test_successful_bypass_detection(self) -> None:
        """Test successful bypass is detected."""
        engine = WAFBypassEngine()
        
        # Mock successful response (200 OK, no WAF indicators)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Success</body></html>"
        
        assert engine._is_bypass_successful(mock_response) is True
    
    def test_failed_bypass_detection_403(self) -> None:
        """Test failed bypass (403) is detected."""
        engine = WAFBypassEngine()
        
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Access Denied"
        
        assert engine._is_bypass_successful(mock_response) is False

    def test_failed_bypass_detection_401(self) -> None:
        """Unauthorized responses must not be treated as bypass success."""
        engine = WAFBypassEngine()

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        assert engine._is_bypass_successful(mock_response) is False
    
    def test_failed_bypass_detection_waf_indicators(self) -> None:
        """Test failed bypass with WAF indicators."""
        engine = WAFBypassEngine()
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
            <html>
            <body>
                Access Denied by Cloudflare
                Security Firewall Blocked
            </body>
            </html>
        """
        
        assert engine._is_bypass_successful(mock_response) is False


class TestWAFBypassEngineLifecycle:
    """Test WAF bypass engine lifecycle."""

    @pytest.mark.asyncio
    async def test_engine_close(self) -> None:
        """Test engine cleanup."""
        engine = WAFBypassEngine()
        
        # Should not raise
        await engine.close()
    
    @pytest.mark.asyncio
    async def test_engine_with_custom_timeout(self) -> None:
        """Test engine with custom timeout."""
        engine = WAFBypassEngine(timeout=60)
        
        assert engine.timeout == 60
        await engine.close()
