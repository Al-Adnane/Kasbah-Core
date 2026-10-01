"""Tests for KasbahClient (canonical — api.bekasbah.com)."""

import pytest
from unittest.mock import MagicMock, patch

from kasbah.client import KasbahClient
from kasbah.models import ScanResult, Decision


# ── Initialization ─────────────────────────────────────────────────────────────

class TestClientInitialization:
    """Test KasbahClient initialization."""

    def test_default_base_url(self):
        """Default base URL must be api.bekasbah.com."""
        client = KasbahClient(api_key="test-key")
        assert client.base_url == "https://api.bekasbah.com"

    def test_custom_base_url(self):
        """Custom base URL is accepted."""
        client = KasbahClient(api_key="test-key", base_url="https://custom.api.com")
        assert client.base_url == "https://custom.api.com"

    def test_trailing_slash_stripped(self):
        """Trailing slashes on base_url are stripped."""
        client = KasbahClient(api_key="test-key", base_url="https://api.bekasbah.com/")
        assert client.base_url == "https://api.bekasbah.com"

    def test_api_key_stored(self):
        """API key is stored on the client."""
        client = KasbahClient(api_key="kg_live_abc123")
        assert client.api_key == "kg_live_abc123"

    def test_no_api_key_raises(self):
        """Missing API key raises ValueError."""
        with pytest.raises(ValueError, match="api_key"):
            KasbahClient()

    def test_api_key_from_env(self, monkeypatch):
        """API key can be set via KASBAH_API_KEY environment variable."""
        monkeypatch.setenv("KASBAH_API_KEY", "kg_env_key")
        client = KasbahClient()
        assert client.api_key == "kg_env_key"

    def test_explicit_key_overrides_env(self, monkeypatch):
        """Explicit api_key takes precedence over environment variable."""
        monkeypatch.setenv("KASBAH_API_KEY", "kg_env_key")
        client = KasbahClient(api_key="kg_explicit")
        assert client.api_key == "kg_explicit"

    def test_default_timeout(self):
        """Default timeout is 30 seconds."""
        client = KasbahClient(api_key="test-key")
        assert client.timeout == 30.0

    def test_custom_timeout(self):
        """Custom timeout is accepted."""
        client = KasbahClient(api_key="test-key", timeout=60.0)
        assert client.timeout == 60.0

    def test_authorization_header(self):
        """Authorization header uses Bearer scheme."""
        client = KasbahClient(api_key="test-key")
        assert client._session.headers["Authorization"] == "Bearer test-key"

    def test_user_agent_header(self):
        """User-Agent header identifies the SDK."""
        client = KasbahClient(api_key="test-key")
        assert "kasbah-guard-python" in client._session.headers["User-Agent"]


# ── scan() ─────────────────────────────────────────────────────────────────────

class TestScan:
    """Test KasbahClient.scan()."""

    def _mock_post(self, monkeypatch, payload: dict):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = payload
        mock_response.raise_for_status = MagicMock()
        monkeypatch.setattr("requests.Session.post", lambda *a, **kw: mock_response)
        return mock_response

    def test_scan_deny(self, monkeypatch):
        """Scan returns DENY for high-risk content."""
        self._mock_post(monkeypatch, {"risk": 90, "decision": "DENY", "reason": "AWS key detected"})
        client = KasbahClient(api_key="test-key")
        result = client.scan("AKIAIOSFODNN7EXAMPLE")
        assert result.risk == 90
        assert result.decision == Decision.DENY
        assert result.reason == "AWS key detected"

    def test_scan_allow(self, monkeypatch):
        """Scan returns ALLOW for clean content."""
        self._mock_post(monkeypatch, {"risk": 0, "decision": "ALLOW", "reason": ""})
        client = KasbahClient(api_key="test-key")
        result = client.scan("Hello, world!")
        assert result.decision == Decision.ALLOW
        assert result.is_blocked is False

    def test_scan_warn(self, monkeypatch):
        """Scan returns REVIEW for medium-risk content."""
        self._mock_post(monkeypatch, {"risk": 50, "decision": "REVIEW", "reason": "Possible credential"})
        client = KasbahClient(api_key="test-key")
        result = client.scan("password=abc123")
        assert result.decision == Decision.REVIEW
        assert result.is_blocked is False

    def test_scan_posts_to_bekasbah(self, monkeypatch):
        """scan() POSTs to api.bekasbah.com/api/scan."""
        captured = {}

        def mock_post(self_session, url, **kwargs):
            captured["url"] = url
            mock_response = MagicMock()
            mock_response.json.return_value = {"risk": 0, "decision": "ALLOW"}
            mock_response.raise_for_status = MagicMock()
            return mock_response

        monkeypatch.setattr("requests.Session.post", mock_post)
        client = KasbahClient(api_key="test-key")
        client.scan("test")
        assert "api.bekasbah.com" in captured["url"]
        assert "/api/scan" in captured["url"]

    def test_scan_returns_scan_result(self, monkeypatch):
        """scan() returns a ScanResult instance."""
        self._mock_post(monkeypatch, {"risk": 0, "decision": "ALLOW"})
        client = KasbahClient(api_key="test-key")
        result = client.scan("test")
        assert isinstance(result, ScanResult)

    def test_scan_network_error(self, monkeypatch):
        """Network errors propagate as exceptions."""
        monkeypatch.setattr(
            "requests.Session.post", lambda *a, **kw: (_ for _ in ()).throw(Exception("Network error"))
        )
        client = KasbahClient(api_key="test-key")
        with pytest.raises(Exception, match="Network error"):
            client.scan("test")


# ── scan_file() ────────────────────────────────────────────────────────────────

class TestScanFile:
    """Test KasbahClient.scan_file()."""

    def test_scan_file_success(self, monkeypatch, tmp_path):
        """scan_file() reads file and returns ScanResult."""
        test_file = tmp_path / "secrets.txt"
        test_file.write_text("AKIAIOSFODNN7EXAMPLE")

        mock_response = MagicMock()
        mock_response.json.return_value = {"risk": 85, "decision": "DENY", "reason": "AWS key"}
        mock_response.raise_for_status = MagicMock()
        monkeypatch.setattr("requests.Session.post", lambda *a, **kw: mock_response)

        client = KasbahClient(api_key="test-key")
        result = client.scan_file(str(test_file))
        assert result.decision == Decision.DENY
        assert result.risk == 85

    def test_scan_file_not_found(self):
        """scan_file() raises FileNotFoundError for missing files."""
        client = KasbahClient(api_key="test-key")
        with pytest.raises(FileNotFoundError):
            client.scan_file("/nonexistent/path/file.txt")


# ── redact() ───────────────────────────────────────────────────────────────────

class TestRedact:
    """Test KasbahClient.redact()."""

    def test_redact_returns_redacted_text(self, monkeypatch):
        """redact() returns the redacted string from the API."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"redacted": "[REDACTED::AWS_KEY]"}
        mock_response.raise_for_status = MagicMock()
        monkeypatch.setattr("requests.Session.post", lambda *a, **kw: mock_response)

        client = KasbahClient(api_key="test-key")
        result = client.redact("AKIAIOSFODNN7EXAMPLE")
        assert "[REDACTED" in result

    def test_redact_posts_to_bekasbah(self, monkeypatch):
        """redact() POSTs to api.bekasbah.com."""
        captured = {}

        def mock_post(self_session, url, **kwargs):
            captured["url"] = url
            mock_response = MagicMock()
            mock_response.json.return_value = {"redacted": "clean"}
            mock_response.raise_for_status = MagicMock()
            return mock_response

        monkeypatch.setattr("requests.Session.post", mock_post)
        client = KasbahClient(api_key="test-key")
        client.redact("test")
        assert "api.bekasbah.com" in captured["url"]


# ── health() ───────────────────────────────────────────────────────────────────

class TestHealth:
    """Test KasbahClient.health()."""

    def test_health_check(self, monkeypatch):
        """health() returns the API status dict."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()
        monkeypatch.setattr("requests.Session.get", lambda *a, **kw: mock_response)

        client = KasbahClient(api_key="test-key")
        result = client.health()
        assert result["status"] == "ok"

    def test_health_hits_bekasbah(self, monkeypatch):
        """health() GETs from api.bekasbah.com/health."""
        captured = {}

        def mock_get(self_session, url, **kwargs):
            captured["url"] = url
            mock_response = MagicMock()
            mock_response.json.return_value = {"status": "ok"}
            mock_response.raise_for_status = MagicMock()
            return mock_response

        monkeypatch.setattr("requests.Session.get", mock_get)
        client = KasbahClient(api_key="test-key")
        client.health()
        assert "api.bekasbah.com" in captured["url"]
        assert "/health" in captured["url"]


# ── Context manager ────────────────────────────────────────────────────────────

class TestContextManager:
    """Test KasbahClient context manager protocol."""

    def test_context_manager_enters(self):
        """Client works as a context manager."""
        with KasbahClient(api_key="test-key") as client:
            assert client is not None
            assert client.api_key == "test-key"

    def test_context_manager_closes_session(self, monkeypatch):
        """Context manager closes the session on exit."""
        closed = []
        original_close = KasbahClient.close

        def tracking_close(self):
            closed.append(True)
            original_close(self)

        monkeypatch.setattr(KasbahClient, "close", tracking_close)

        with KasbahClient(api_key="test-key"):
            pass

        assert len(closed) == 1
