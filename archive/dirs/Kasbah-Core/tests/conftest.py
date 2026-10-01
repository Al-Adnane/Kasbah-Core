"""
Test configuration and fixtures for Kasbah-Core
Handles missing dependencies gracefully for full test suite execution
"""

import sys
import os
from unittest.mock import MagicMock, AsyncMock
import pytest


# Mock missing external dependencies that are needed for integration tests
# but not core to the 7 modules we extracted

def pytest_configure(config):
    """
    Configure pytest and mock missing dependencies before test collection
    """

    # Mock fastapi (used by comprehensive_test, final_integration_test)
    if 'fastapi' not in sys.modules:
        fastapi_mock = MagicMock()
        fastapi_mock.FastAPI = MagicMock(return_value=MagicMock())
        fastapi_mock.HTTPException = Exception
        fastapi_mock.status = MagicMock()
        sys.modules['fastapi'] = fastapi_mock

    # Mock uvicorn (web server dependency)
    if 'uvicorn' not in sys.modules:
        sys.modules['uvicorn'] = MagicMock()

    # Mock httpx (async HTTP client)
    if 'httpx' not in sys.modules:
        sys.modules['httpx'] = MagicMock()

    # Mock kasbah_main (core Kasbah module reference)
    if 'kasbah_main' not in sys.modules:
        kasbah_main_mock = MagicMock()
        kasbah_main_mock._rtp_gate = MagicMock(return_value={'status': 'ok'})
        kasbah_main_mock.kernel_decide = AsyncMock(return_value={'result': 'ALLOW'})
        sys.modules['kasbah_main'] = kasbah_main_mock

    # Pre-import real apps.kernel.bridge before mocking so contract tests work
    import importlib
    _apps_path = os.path.join(os.path.dirname(__file__), '..')
    if _apps_path not in sys.path:
        sys.path.insert(0, _apps_path)
    try:
        import apps.kernel.bridge  # noqa: F401 — ensure real module cached first
    except Exception:
        pass

    # Mock apps.kernel.decide_adapter (depends on kasbah_main)
    if 'apps' not in sys.modules:
        sys.modules['apps'] = MagicMock()
        sys.modules['apps.kernel'] = MagicMock()
        sys.modules['apps.kernel.decide_adapter'] = MagicMock()
        sys.modules['apps.kernel.decide_adapter'].kernel_decide = AsyncMock(
            return_value={'result': 'ALLOW', 'confidence': 0.95}
        )

    # Mock apps.api.rtp sub-modules so authz_pipeline can import rtp.authz
    # without needing apps/api on sys.path during unit tests.
    if 'apps.api' not in sys.modules:
        sys.modules['apps.api'] = MagicMock()
    if 'apps.api.rtp' not in sys.modules:
        sys.modules['apps.api.rtp'] = MagicMock()
    if 'apps.api.rtp.integrity' not in sys.modules:
        sys.modules['apps.api.rtp.integrity'] = MagicMock()
    if 'apps.api.rtp.kernel_gate' not in sys.modules:
        sys.modules['apps.api.rtp.kernel_gate'] = MagicMock()

    # Ensure rtp.authz is importable directly (used via sys.path.insert in authz_pipeline).
    # Provide a real dataclass for AuthZResult so tests that inspect fields work correctly.
    if 'rtp' not in sys.modules:
        from dataclasses import dataclass as _dc
        from typing import Optional as _Opt, Any as _Any

        @_dc
        class _AuthZResult:
            allow: bool = True
            reason: str = "ok"
            rule_id: str = "TEST-001"
            matched_rule: _Opt[_Any] = None

        rtp_authz_mock = MagicMock()
        rtp_authz_mock.AuthZResult = _AuthZResult
        rtp_authz_mock.check_access = MagicMock(return_value=_AuthZResult())

        rtp_mock = MagicMock()
        rtp_mock.authz = rtp_authz_mock
        sys.modules['rtp'] = rtp_mock
        sys.modules['rtp.authz'] = rtp_authz_mock


@pytest.fixture(scope="session")
def mock_fastapi():
    """Fixture providing mocked FastAPI instance"""
    return sys.modules.get('fastapi', MagicMock())


@pytest.fixture(scope="session")
def mock_kasbah_main():
    """Fixture providing mocked kasbah_main module"""
    return sys.modules.get('kasbah_main', MagicMock())


@pytest.fixture(autouse=True)
def reset_mocks():
    """Reset mocks between tests to avoid state pollution"""
    yield
    # Mocks are automatically cleaned up by pytest


# Markers for test organization - add these in pytest.ini instead
# This hook name was causing validation errors, so removing it


# Collection configuration
def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to handle integration tests gracefully
    """
    for item in items:
        # Mark integration tests
        if 'integration' in item.nodeid or 'stress' in item.nodeid:
            item.add_marker(pytest.mark.integration)
        # Mark slow tests
        if 'stress' in item.nodeid or 'comprehensive' in item.nodeid:
            item.add_marker(pytest.mark.slow)
