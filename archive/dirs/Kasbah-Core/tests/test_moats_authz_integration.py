"""
Moat Integration Tests — Phase 4 AuthZ Pipeline wired into Kasbah Moats
========================================================================
Verifies that the authz pipeline:
  1. Is importable via the top-level `core.moats` package
  2. Feeds denials into the dynamic_thresholds threat system
  3. Runs adversarial detection pre-screen on CCL text
  4. Exports all expected Phase 4 symbols
"""
import os
import pytest
from unittest.mock import patch, MagicMock


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_req(**kwargs):
    from core.moats import AuthZPipelineRequest
    defaults = dict(
        principal="agent:moat-test",
        action="read",
        resource="docs",
        estimated_tokens=100,
        estimated_cost_cents=1,
    )
    defaults.update(kwargs)
    return AuthZPipelineRequest(**defaults)


def _stub_ledger():
    mock = MagicMock()
    mock.add_audit_entry.return_value = MagicMock(id="audit-moat-001")
    return mock


def _stub_budget(allowed=True):
    from core.moats import BudgetCheckResult, SpendPolicy
    policy = SpendPolicy(
        principal="agent:moat-test",
        max_tokens_per_minute=100_000,
        max_tokens_per_day=5_000_000,
        max_cost_cents_per_day=5000,
        max_cost_cents_total=None,
        hard_block_on_exceed=True,
    )
    return BudgetCheckResult(
        allowed=allowed,
        reason="within_budget" if allowed else "daily_token_limit: exceeded",
        remaining_tokens_today=4_900_000,
        remaining_cost_cents_today=4999,
        policy=policy,
    )


def _stub_authz(allow=True):
    from rtp.authz import AuthZResult
    return AuthZResult(allow=allow, reason="ok", rule_id="TEST-001", matched_rule=None)


# ── Fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture()
def patched(tmp_path, monkeypatch):
    """Patch external deps; import authz_pipeline via core.moats package."""
    monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))

    with patch("core.moats.authz_pipeline._ledger", _stub_ledger()), \
         patch("core.moats.authz_pipeline.check_budget", return_value=_stub_budget()), \
         patch("core.moats.authz_pipeline.check_access", return_value=_stub_authz()), \
         patch("core.moats.authz_pipeline.verify_credential", return_value=True), \
         patch("core.moats.authz_pipeline.verify_delegation_chain") as mock_d, \
         patch("core.moats.authz_pipeline._get_ccl", return_value=None), \
         patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", False):

        mock_d.return_value = MagicMock(valid=True, reason="ok", chain=[], effective_depth=1)

        import core.moats.authz_pipeline as pipeline
        yield pipeline


# ── Phase 4 symbol exports ────────────────────────────────────────────────────

class TestPhase4Exports:
    """All Phase 4 symbols must be importable from core.moats directly."""

    def test_authorize_importable(self):
        from core.moats import authorize
        assert callable(authorize)

    def test_authz_pipeline_request_importable(self):
        from core.moats import AuthZPipelineRequest
        req = AuthZPipelineRequest(principal="a", action="read", resource="r")
        assert req.principal == "a"

    def test_authz_pipeline_result_importable(self):
        from core.moats import AuthZPipelineResult
        result = AuthZPipelineResult(allow=True, reason="ok")
        assert result.allow is True

    def test_consume_ticket_and_record_spend_importable(self):
        from core.moats import consume_ticket_and_record_spend
        assert callable(consume_ticket_and_record_spend)

    def test_agent_identity_importable(self):
        from core.moats import (
            AgentCredential, issue_credential, verify_credential,
            rotate_credential, revoke_credential, get_credential, list_credentials,
        )
        assert callable(issue_credential)
        assert callable(verify_credential)

    def test_delegation_chain_importable(self):
        from core.moats import (
            DelegationToken, DelegationVerifyResult,
            grant_delegation, verify_delegation_chain, revoke_delegation,
            get_delegation_token, list_delegations,
        )
        assert callable(grant_delegation)
        assert callable(verify_delegation_chain)

    def test_spend_ledger_importable(self):
        from core.moats import (
            SpendPolicy, SpendRecord, BudgetCheckResult,
            set_spend_policy, get_spend_policy, check_budget,
            record_spend, get_spend_summary,
        )
        assert callable(check_budget)
        assert callable(record_spend)


# ── Threat feedback integration ───────────────────────────────────────────────

class TestThreatFeedback:
    """Pipeline denials must fire into dynamic_thresholds."""

    def _patched_with_threat_mock(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
        threat_mock = MagicMock()
        return threat_mock

    def test_identity_failure_fires_evasion_threat(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
        threat_mock = MagicMock()

        with patch("core.moats.authz_pipeline._ledger", _stub_ledger()), \
             patch("core.moats.authz_pipeline.verify_credential", return_value=False), \
             patch("core.moats.authz_pipeline._THREAT_FEEDBACK_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._record_threat_event", threat_mock), \
             patch("core.moats.authz_pipeline.check_budget", return_value=_stub_budget()), \
             patch("core.moats.authz_pipeline.check_access", return_value=_stub_authz()), \
             patch("core.moats.authz_pipeline._get_ccl", return_value=None), \
             patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", False):

            import core.moats.authz_pipeline as pipeline
            result = pipeline.authorize(_make_req(agent_secret="wrong"))

        assert result.allow is False
        assert result.stage_failed == "identity"
        threat_mock.assert_called_once()
        call_args = threat_mock.call_args
        assert call_args[0][0] == "evasion_attempt"

    def test_delegation_failure_fires_evasion_threat(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
        threat_mock = MagicMock()

        with patch("core.moats.authz_pipeline._ledger", _stub_ledger()), \
             patch("core.moats.authz_pipeline.verify_credential", return_value=True), \
             patch("core.moats.authz_pipeline.verify_delegation_chain") as mock_d, \
             patch("core.moats.authz_pipeline._THREAT_FEEDBACK_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._record_threat_event", threat_mock), \
             patch("core.moats.authz_pipeline.check_budget", return_value=_stub_budget()), \
             patch("core.moats.authz_pipeline.check_access", return_value=_stub_authz()), \
             patch("core.moats.authz_pipeline._get_ccl", return_value=None), \
             patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", False):

            mock_d.return_value = MagicMock(valid=False, reason="no token found")
            import core.moats.authz_pipeline as pipeline
            result = pipeline.authorize(_make_req(acting_as="agent:grantor"))

        assert result.allow is False
        assert result.stage_failed == "delegation"
        threat_mock.assert_called_once()
        assert threat_mock.call_args[0][0] == "evasion_attempt"

    def test_ccl5_fires_known_malicious_threat(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
        threat_mock = MagicMock()

        mock_ccl_fw = MagicMock()
        mock_assessment = MagicMock()
        mock_assessment.ccl_level = 5
        mock_ccl_fw.assess.return_value = mock_assessment

        with patch("core.moats.authz_pipeline._ledger", _stub_ledger()), \
             patch("core.moats.authz_pipeline.verify_credential", return_value=True), \
             patch("core.moats.authz_pipeline._get_ccl", return_value=mock_ccl_fw), \
             patch("core.moats.authz_pipeline._THREAT_FEEDBACK_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._record_threat_event", threat_mock), \
             patch("core.moats.authz_pipeline.check_budget", return_value=_stub_budget()), \
             patch("core.moats.authz_pipeline.check_access", return_value=_stub_authz()), \
             patch("core.moats.authz_pipeline.verify_delegation_chain") as mock_d, \
             patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", False):

            mock_d.return_value = MagicMock(valid=True, reason="ok", chain=[], effective_depth=0)
            import core.moats.authz_pipeline as pipeline
            result = pipeline.authorize(_make_req(ccl_text="dangerous content"))

        assert result.allow is False
        assert result.stage_failed == "ccl"
        threat_mock.assert_called_once()
        assert threat_mock.call_args[0][0] == "known_malicious"

    def test_budget_exceeded_fires_api_abuse_threat(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
        threat_mock = MagicMock()

        with patch("core.moats.authz_pipeline._ledger", _stub_ledger()), \
             patch("core.moats.authz_pipeline.verify_credential", return_value=True), \
             patch("core.moats.authz_pipeline._get_ccl", return_value=None), \
             patch("core.moats.authz_pipeline.check_budget", return_value=_stub_budget(allowed=False)), \
             patch("core.moats.authz_pipeline._THREAT_FEEDBACK_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._record_threat_event", threat_mock), \
             patch("core.moats.authz_pipeline.check_access", return_value=_stub_authz()), \
             patch("core.moats.authz_pipeline.verify_delegation_chain") as mock_d, \
             patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", False):

            mock_d.return_value = MagicMock(valid=True, reason="ok", chain=[], effective_depth=0)
            import core.moats.authz_pipeline as pipeline
            result = pipeline.authorize(_make_req())

        assert result.allow is False
        assert result.stage_failed == "budget"
        threat_mock.assert_called_once()
        assert threat_mock.call_args[0][0] == "api_abuse"

    def test_rules_denial_fires_suspicious_pattern_threat(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
        threat_mock = MagicMock()

        with patch("core.moats.authz_pipeline._ledger", _stub_ledger()), \
             patch("core.moats.authz_pipeline.verify_credential", return_value=True), \
             patch("core.moats.authz_pipeline._get_ccl", return_value=None), \
             patch("core.moats.authz_pipeline.check_budget", return_value=_stub_budget()), \
             patch("core.moats.authz_pipeline.check_access", return_value=_stub_authz(allow=False)), \
             patch("core.moats.authz_pipeline._THREAT_FEEDBACK_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._record_threat_event", threat_mock), \
             patch("core.moats.authz_pipeline.verify_delegation_chain") as mock_d, \
             patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", False):

            mock_d.return_value = MagicMock(valid=True, reason="ok", chain=[], effective_depth=0)
            import core.moats.authz_pipeline as pipeline
            result = pipeline.authorize(_make_req())

        assert result.allow is False
        assert result.stage_failed == "rules"
        threat_mock.assert_called_once()
        assert threat_mock.call_args[0][0] == "suspicious_pattern"

    def test_allow_does_not_fire_threat(self, patched):
        threat_mock = MagicMock()
        with patch("core.moats.authz_pipeline._THREAT_FEEDBACK_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._record_threat_event", threat_mock):
            result = patched.authorize(_make_req())
        assert result.allow is True
        threat_mock.assert_not_called()

    def test_threat_feedback_unavailable_does_not_break_pipeline(self, patched):
        """If dynamic_thresholds unavailable, deny still returns correct result."""
        with patch("core.moats.authz_pipeline._THREAT_FEEDBACK_AVAILABLE", False), \
             patch("core.moats.authz_pipeline.verify_credential", return_value=False):
            result = patched.authorize(_make_req(agent_secret="bad"))
        assert result.allow is False
        assert result.stage_failed == "identity"


# ── Adversarial detection pre-screen ─────────────────────────────────────────

class TestAdversarialPreScreen:
    """High-confidence evasion patterns in CCL text are blocked at Stage 3."""

    def test_high_evasion_risk_blocks_at_ccl_stage(self, patched):
        mock_adv_result = MagicMock()
        mock_adv_result.evasion_risk = 0.95  # above 0.8 threshold

        with patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._detect_adversarial", return_value=mock_adv_result):
            result = patched.authorize(_make_req(ccl_text="hom\u0430glyph content"))

        assert result.allow is False
        assert result.stage_failed == "ccl"
        assert "adversarial_evasion" in result.reason

    def test_low_evasion_risk_falls_through(self, patched):
        mock_adv_result = MagicMock()
        mock_adv_result.evasion_risk = 0.3  # below 0.8 threshold — not blocked

        with patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._detect_adversarial", return_value=mock_adv_result):
            result = patched.authorize(_make_req(ccl_text="normal content"))

        assert result.allow is True  # CCL framework is None in patched fixture

    def test_adversarial_detection_exception_does_not_block(self, patched):
        """Adversarial pre-screen is best-effort; an exception must not block allow."""
        with patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._detect_adversarial", side_effect=RuntimeError("detector crash")):
            result = patched.authorize(_make_req(ccl_text="some text"))

        assert result.allow is True  # must fall through after exception

    def test_no_ccl_text_skips_adversarial_screen(self, patched):
        """No ccl_text means adversarial pre-screen is never called."""
        adv_mock = MagicMock()
        with patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", True), \
             patch("core.moats.authz_pipeline._detect_adversarial", adv_mock):
            result = patched.authorize(_make_req())

        adv_mock.assert_not_called()
        assert result.allow is True


# ── End-to-end moat package usage ─────────────────────────────────────────────

class TestMoatPackageEndToEnd:
    """Use core.moats top-level API exclusively — no direct submodule imports."""

    def test_full_allow_via_moats_package(self, patched, tmp_path, monkeypatch):
        monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
        from core.moats import authorize, AuthZPipelineRequest

        with patch("core.moats.authz_pipeline._ledger", _stub_ledger()), \
             patch("core.moats.authz_pipeline.check_budget", return_value=_stub_budget()), \
             patch("core.moats.authz_pipeline.check_access", return_value=_stub_authz()), \
             patch("core.moats.authz_pipeline.verify_credential", return_value=True), \
             patch("core.moats.authz_pipeline.verify_delegation_chain") as mock_d, \
             patch("core.moats.authz_pipeline._get_ccl", return_value=None), \
             patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", False):

            mock_d.return_value = MagicMock(valid=True, reason="ok", chain=[], effective_depth=0)

            result = authorize(AuthZPipelineRequest(
                principal="agent:billing-v2",
                action="read",
                resource="billing:invoices",
                estimated_tokens=500,
            ))

        assert result.allow is True
        assert result.reason == "authorized"
        assert result.budget_remaining is not None

    def test_full_deny_via_moats_package(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
        from core.moats import authorize, AuthZPipelineRequest

        with patch("core.moats.authz_pipeline._ledger", _stub_ledger()), \
             patch("core.moats.authz_pipeline.verify_credential", return_value=False), \
             patch("core.moats.authz_pipeline.check_budget", return_value=_stub_budget()), \
             patch("core.moats.authz_pipeline.check_access", return_value=_stub_authz()), \
             patch("core.moats.authz_pipeline._get_ccl", return_value=None), \
             patch("core.moats.authz_pipeline._ADVERSARIAL_DETECTION_AVAILABLE", False), \
             patch("core.moats.authz_pipeline._THREAT_FEEDBACK_AVAILABLE", False):

            result = authorize(AuthZPipelineRequest(
                principal="agent:untrusted",
                action="write",
                resource="billing:invoices",
                agent_secret="wrong-secret",
                estimated_tokens=500,
            ))

        assert result.allow is False
        assert result.stage_failed == "identity"
