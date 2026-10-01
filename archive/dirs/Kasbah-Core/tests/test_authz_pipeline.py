"""
Tests for core/moats/authz_pipeline.py
Full 7-stage authorization pipeline integration tests.
"""
import os
import pytest
from unittest.mock import patch, MagicMock


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_req(**kwargs):
    from core.moats.authz_pipeline import AuthZPipelineRequest
    defaults = dict(
        principal="agent:test",
        action="read",
        resource="docs",
        estimated_tokens=100,
        estimated_cost_cents=1,
    )
    defaults.update(kwargs)
    return AuthZPipelineRequest(**defaults)


def _stub_ledger():
    mock = MagicMock()
    mock.add_audit_entry.return_value = MagicMock(id="audit-001")
    return mock


def _stub_budget(allowed=True, reason="within_budget"):
    from core.moats.spend_ledger import BudgetCheckResult, SpendPolicy
    policy = SpendPolicy(
        principal="agent:test",
        max_tokens_per_minute=100_000,
        max_tokens_per_day=5_000_000,
        max_cost_cents_per_day=5000,
        max_cost_cents_total=None,
        hard_block_on_exceed=True,
    )
    return BudgetCheckResult(
        allowed=allowed,
        reason=reason,
        remaining_tokens_today=4_900_000,
        remaining_cost_cents_today=4999,
        policy=policy,
    )


def _stub_authz(allow=True, reason="ok"):
    from rtp.authz import AuthZResult
    return AuthZResult(allow=allow, reason=reason, rule_id="TEST-001", matched_rule=None)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def patched_pipeline(tmp_path, monkeypatch):
    """Patch all external dependencies of authz_pipeline for unit isolation."""
    monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))

    with patch("core.moats.authz_pipeline._ledger", _stub_ledger()), \
         patch("core.moats.authz_pipeline.check_budget", return_value=_stub_budget()), \
         patch("core.moats.authz_pipeline.check_access", return_value=_stub_authz()), \
         patch("core.moats.authz_pipeline.verify_credential", return_value=True), \
         patch("core.moats.authz_pipeline.verify_delegation_chain") as mock_deleg, \
         patch("core.moats.authz_pipeline._get_ccl", return_value=None):

        mock_deleg.return_value = MagicMock(valid=True, reason="ok", chain=[], effective_depth=1)

        import core.moats.authz_pipeline as pipeline
        yield pipeline


# ── Stage 1: Identity ─────────────────────────────────────────────────────────

class TestStage1Identity:
    def test_valid_credential_passes(self, patched_pipeline):
        with patch("core.moats.authz_pipeline.verify_credential", return_value=True):
            result = patched_pipeline.authorize(_make_req(agent_secret="validsecret"))
        assert result.allow is True

    def test_invalid_credential_denied(self, patched_pipeline):
        with patch("core.moats.authz_pipeline.verify_credential", return_value=False):
            result = patched_pipeline.authorize(_make_req(agent_secret="badsecret"))
        assert result.allow is False
        assert result.stage_failed == "identity"
        assert "identity_failed" in result.reason

    def test_no_secret_skips_identity_stage(self, patched_pipeline):
        result = patched_pipeline.authorize(_make_req())
        assert result.allow is True  # no secret = identity stage skipped


# ── Stage 2: Delegation ───────────────────────────────────────────────────────

class TestStage2Delegation:
    def test_valid_delegation_passes(self, patched_pipeline):
        result = patched_pipeline.authorize(_make_req(acting_as="agent:grantor"))
        assert result.allow is True

    def test_invalid_delegation_denied(self, patched_pipeline):
        with patch("core.moats.authz_pipeline.verify_delegation_chain") as mock_d:
            mock_d.return_value = MagicMock(valid=False, reason="no token found")
            result = patched_pipeline.authorize(_make_req(acting_as="agent:grantor"))
        assert result.allow is False
        assert result.stage_failed == "delegation"
        assert "delegation_failed" in result.reason

    def test_no_acting_as_skips_delegation(self, patched_pipeline):
        result = patched_pipeline.authorize(_make_req())
        assert result.allow is True


# ── Stage 3: CCL ──────────────────────────────────────────────────────────────

class TestStage3CCL:
    def test_ccl5_unconditional_deny(self, patched_pipeline):
        mock_ccl = MagicMock()
        mock_assessment = MagicMock()
        mock_assessment.ccl_level = 5
        mock_ccl.assess.return_value = mock_assessment

        with patch("core.moats.authz_pipeline._get_ccl", return_value=mock_ccl):
            result = patched_pipeline.authorize(_make_req(ccl_text="dangerous content"))

        assert result.allow is False
        assert result.stage_failed == "ccl"
        assert "systemic_risk" in result.reason

    def test_ccl4_still_proceeds_to_rules(self, patched_pipeline):
        mock_ccl = MagicMock()
        mock_assessment = MagicMock()
        mock_assessment.ccl_level = 4
        mock_ccl.assess.return_value = mock_assessment

        with patch("core.moats.authz_pipeline._get_ccl", return_value=mock_ccl):
            result = patched_pipeline.authorize(_make_req(ccl_text="some content"))

        # CCL-4 is not unconditional deny — result depends on rules
        assert result.stage_failed != "ccl"

    def test_no_ccl_text_skips_assessment(self, patched_pipeline):
        result = patched_pipeline.authorize(_make_req())
        assert result.allow is True
        assert result.ccl_level == 0


# ── Stage 4: Budget ───────────────────────────────────────────────────────────

class TestStage4Budget:
    def test_budget_exceeded_denied(self, patched_pipeline):
        with patch("core.moats.authz_pipeline.check_budget",
                   return_value=_stub_budget(allowed=False, reason="daily_token_limit: 5000 > 100/day")):
            result = patched_pipeline.authorize(_make_req())
        assert result.allow is False
        assert result.stage_failed == "budget"
        assert "budget_exceeded" in result.reason

    def test_within_budget_passes(self, patched_pipeline):
        result = patched_pipeline.authorize(_make_req())
        assert result.allow is True
        assert result.budget_remaining is not None
        assert "tokens_today" in result.budget_remaining


# ── Stage 5: Rules ────────────────────────────────────────────────────────────

class TestStage5Rules:
    def test_authz_denied_fails(self, patched_pipeline):
        with patch("core.moats.authz_pipeline.check_access",
                   return_value=_stub_authz(allow=False, reason="no matching rule")):
            result = patched_pipeline.authorize(_make_req())
        assert result.allow is False
        assert result.stage_failed == "rules"
        assert "authz_denied" in result.reason

    def test_authz_allowed_passes(self, patched_pipeline):
        result = patched_pipeline.authorize(_make_req())
        assert result.allow is True


# ── Stage 6: Ticket ───────────────────────────────────────────────────────────

class TestStage6Ticket:
    def test_no_ticket_by_default(self, patched_pipeline):
        result = patched_pipeline.authorize(_make_req(require_ticket=False))
        assert result.ticket is None

    def test_ticket_issued_when_requested(self, patched_pipeline):
        mock_ticket = MagicMock()
        mock_ticket.id = "ticket-abc"
        with patch("core.moats.authz_pipeline.generate_ticket", return_value=mock_ticket):
            result = patched_pipeline.authorize(_make_req(require_ticket=True))
        assert result.ticket is not None

    def test_ticket_issued_for_ccl2(self, patched_pipeline):
        mock_ccl = MagicMock()
        mock_assessment = MagicMock()
        mock_assessment.ccl_level = 2
        mock_ccl.assess.return_value = mock_assessment
        mock_ticket = MagicMock()
        mock_ticket.id = "ticket-ccl2"

        with patch("core.moats.authz_pipeline._get_ccl", return_value=mock_ccl), \
             patch("core.moats.authz_pipeline.generate_ticket", return_value=mock_ticket):
            result = patched_pipeline.authorize(_make_req(ccl_text="moderate content"))

        assert result.ticket is not None


# ── Stage 7: Audit ────────────────────────────────────────────────────────────

class TestStage7Audit:
    def test_audit_entry_written_on_allow(self, patched_pipeline):
        mock_ledger = _stub_ledger()
        with patch("core.moats.authz_pipeline._ledger", mock_ledger):
            result = patched_pipeline.authorize(_make_req())
        assert result.allow is True
        mock_ledger.add_audit_entry.assert_called()

    def test_audit_entry_written_on_deny(self, patched_pipeline):
        mock_ledger = _stub_ledger()
        with patch("core.moats.authz_pipeline._ledger", mock_ledger), \
             patch("core.moats.authz_pipeline.verify_credential", return_value=False):
            result = patched_pipeline.authorize(_make_req(agent_secret="bad"))
        assert result.allow is False
        mock_ledger.add_audit_entry.assert_called()

    def test_audit_entry_id_returned(self, patched_pipeline):
        mock_ledger = _stub_ledger()
        with patch("core.moats.authz_pipeline._ledger", mock_ledger):
            result = patched_pipeline.authorize(_make_req())
        assert result.audit_entry_id == "audit-001"


# ── Full pipeline result shape ────────────────────────────────────────────────

class TestPipelineResult:
    def test_allow_result_has_budget_remaining(self, patched_pipeline):
        result = patched_pipeline.authorize(_make_req())
        assert result.budget_remaining is not None
        assert result.budget_remaining["tokens_today"] > 0

    def test_delegation_chain_populated(self, patched_pipeline):
        with patch("core.moats.authz_pipeline.verify_delegation_chain") as mock_d:
            fake_token = MagicMock()
            fake_token.token_id = "tok-1"
            fake_token.grantor_id = "agent:grantor"
            fake_token.grantee_id = "agent:test"
            mock_d.return_value = MagicMock(
                valid=True, reason="ok", chain=[fake_token], effective_depth=1
            )
            result = patched_pipeline.authorize(_make_req(acting_as="agent:grantor"))
        assert result.delegation_chain is not None
        assert len(result.delegation_chain) == 1
        assert result.delegation_chain[0]["token_id"] == "tok-1"
