"""
Kasbah Guard Python SDK — Test Suite

Run: python -m pytest tests/ -v
"""

import pytest
from kasbah import KasbahClient
from kasbah.models import ScanResult, Decision


class TestKasbahClient:
    """Test KasbahClient functionality"""

    def test_client_initialization(self):
        """Test client can be initialized"""
        client = KasbahClient(api_key="test-key")
        assert client is not None
        assert client.api_key == "test-key"

    def test_client_initialization_no_key(self):
        """Test client requires API key"""
        with pytest.raises(ValueError):
            KasbahClient()

    def test_client_base_url(self):
        """Test default base URL"""
        client = KasbahClient(api_key="test-key")
        assert client.base_url == "https://api.bekasbah.com"

    def test_client_custom_base_url(self):
        """Test custom base URL"""
        client = KasbahClient(api_key="test-key", base_url="https://custom.api.com")
        assert client.base_url == "https://custom.api.com"


class TestScanResult:
    """Test ScanResult model"""

    def test_scan_result_creation(self):
        """Test ScanResult can be created"""
        result = ScanResult(
            risk=85,
            decision=Decision.DENY,
            reason="AWS key detected",
            violations=["AWS_KEY"]
        )
        assert result.risk == 85
        assert result.decision == Decision.DENY
        assert result.reason == "AWS key detected"

    def test_scan_result_default_values(self):
        """Test ScanResult default values"""
        result = ScanResult(risk=0, decision=Decision.ALLOW, reason="", violations=[])
        assert result.reason == ""
        assert result.violations == []

    def test_scan_result_is_blocked(self):
        """Test is_blocked property"""
        result_deny = ScanResult(risk=85, decision=Decision.DENY, reason="Test", violations=[])
        assert result_deny.is_blocked is True

        result_allow = ScanResult(risk=10, decision=Decision.ALLOW, reason="", violations=[])
        assert result_allow.is_blocked is False

    def test_scan_result_to_dict(self):
        """Test to_dict method"""
        result = ScanResult(risk=85, decision=Decision.DENY, reason="Test", violations=["AWS"])
        d = result.to_dict()
        assert d["risk"] == 85
        assert d["decision"] == "DENY"
        assert d["reason"] == "Test"


class TestDecision:
    """Test Decision enum"""

    def test_decision_values(self):
        """Test Decision enum values"""
        assert Decision.ALLOW.value == "ALLOW"
        assert Decision.DENY.value == "DENY"
        assert Decision.REVIEW.value == "REVIEW"


class TestIntegration:
    """Integration tests (mocked)"""

    def test_scan_text(self, monkeypatch):
        """Test text scanning"""
        # Mock the HTTP request
        def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self):
                    return {"risk": 85, "decision": "DENY", "reason": "AWS key detected"}
                def raise_for_status(self):
                    pass
            return MockResponse()

        monkeypatch.setattr("requests.Session.post", mock_post)

        client = KasbahClient(api_key="test-key")
        result = client.scan("AKIAIOSFODNN7EXAMPLE")

        assert result.risk == 85
        assert result.decision == Decision.DENY

    def test_scan_file(self, monkeypatch, tmp_path):
        """Test file scanning"""
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("AKIAIOSFODNN7EXAMPLE")

        # Mock the HTTP request
        def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self):
                    return {"risk": 85, "decision": "DENY", "reason": "AWS key detected"}
                def raise_for_status(self):
                    pass
            return MockResponse()

        monkeypatch.setattr("requests.Session.post", mock_post)

        client = KasbahClient(api_key="test-key")
        result = client.scan_file(str(test_file))

        assert result.risk == 85
        assert result.decision == Decision.DENY

    def test_redact_text(self, monkeypatch):
        """Test text redaction"""
        # Mock the HTTP request
        def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self):
                    return {"redacted": "[REDACTED::AWS_KEY]"}
                def raise_for_status(self):
                    pass
            return MockResponse()

        monkeypatch.setattr("requests.Session.post", mock_post)

        client = KasbahClient(api_key="test-key")
        result = client.redact("AKIAIOSFODNN7EXAMPLE")

        assert "[REDACTED" in result


class TestErrorHandling:
    """Test error handling"""

    def test_invalid_api_key(self, monkeypatch):
        """Test invalid API key handling"""
        def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 401
                def json(self):
                    return {"error": "Invalid API key"}
                def raise_for_status(self):
                    raise Exception("401 Unauthorized")
            return MockResponse()

        monkeypatch.setattr("requests.Session.post", mock_post)

        client = KasbahClient(api_key="invalid-key")
        with pytest.raises(Exception):
            client.scan("test text")

    def test_network_error(self, monkeypatch):
        """Test network error handling"""
        def mock_post(*args, **kwargs):
            raise Exception("Network error")

        monkeypatch.setattr("requests.Session.post", mock_post)

        client = KasbahClient(api_key="test-key")
        with pytest.raises(Exception):
            client.scan("test text")

    def test_file_not_found(self):
        """Test file not found handling"""
        client = KasbahClient(api_key="test-key")
        with pytest.raises(FileNotFoundError):
            client.scan_file("/nonexistent/file.txt")


class TestEdgeCases:
    """Test edge cases"""

    def test_empty_text(self, monkeypatch):
        """Test empty text scanning"""
        def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self):
                    return {"risk": 0, "decision": "ALLOW", "reason": "Empty text"}
                def raise_for_status(self):
                    pass
            return MockResponse()

        monkeypatch.setattr("requests.Session.post", mock_post)

        client = KasbahClient(api_key="test-key")
        result = client.scan("")

        assert result.risk == 0
        assert result.decision == Decision.ALLOW

    def test_large_text(self, monkeypatch):
        """Test large text scanning"""
        large_text = "A" * 100000

        def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self):
                    return {"risk": 10, "decision": "ALLOW", "reason": "Large text"}
                def raise_for_status(self):
                    pass
            return MockResponse()

        monkeypatch.setattr("requests.Session.post", mock_post)

        client = KasbahClient(api_key="test-key")
        result = client.scan(large_text)

        assert result.risk == 10
        assert result.decision == Decision.ALLOW

    def test_unicode_text(self, monkeypatch):
        """Test unicode text scanning"""
        unicode_text = "Hello 世界 🌍 مرحبا"

        def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self):
                    return {"risk": 0, "decision": "ALLOW", "reason": "Unicode text"}
                def raise_for_status(self):
                    pass
            return MockResponse()

        monkeypatch.setattr("requests.Session.post", mock_post)

        client = KasbahClient(api_key="test-key")
        result = client.scan(unicode_text)

        assert result.risk == 0
        assert result.decision == Decision.ALLOW
