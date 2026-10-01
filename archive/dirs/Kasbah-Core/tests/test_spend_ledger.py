"""
Tests for core/moats/spend_ledger.py
Spend policy management, rolling-window budget checks, and spend recording.
"""
import time
import os
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    """Return spend_ledger with isolated DATA_DIR and mocked audit_ledger."""
    monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
    import core.moats.spend_ledger as m
    m.DATA_DIR = str(tmp_path)
    m.POLICIES_PATH = os.path.join(str(tmp_path), "spend_policies.json")
    m.RECORDS_PATH = os.path.join(str(tmp_path), "spend_records.jsonl")

    # Stub out audit_ledger so tests don't need the full ledger initialised
    mock_ledger = MagicMock()
    mock_ledger.add_audit_entry.return_value = MagicMock(id="test-audit-id")
    m._ledger = mock_ledger
    return m


class TestSetSpendPolicy:
    def test_stores_and_retrieves_policy(self, mod):
        policy = mod.set_spend_policy(
            "agent:billing",
            max_tokens_per_minute=500,
            max_tokens_per_day=10_000,
            max_cost_cents_per_day=200,
        )
        assert policy.principal == "agent:billing"
        assert policy.max_tokens_per_minute == 500

        fetched = mod.get_spend_policy("agent:billing")
        assert fetched.max_tokens_per_minute == 500
        assert fetched.max_tokens_per_day == 10_000

    def test_default_policy_for_unknown_principal(self, mod):
        policy = mod.get_spend_policy("agent:unknown")
        assert policy.max_tokens_per_minute == mod.DEFAULT_POLICY["max_tokens_per_minute"]
        assert policy.hard_block_on_exceed is True

    def test_lifetime_cap_stored(self, mod):
        mod.set_spend_policy("agent:capped", max_cost_cents_total=10000)
        p = mod.get_spend_policy("agent:capped")
        assert p.max_cost_cents_total == 10000

    def test_overwrite_policy(self, mod):
        mod.set_spend_policy("agent:upd", max_tokens_per_minute=100)
        mod.set_spend_policy("agent:upd", max_tokens_per_minute=999)
        p = mod.get_spend_policy("agent:upd")
        assert p.max_tokens_per_minute == 999


class TestCheckBudget:
    def test_within_budget_allowed(self, mod):
        mod.set_spend_policy("agent:ok", max_tokens_per_day=10_000, max_cost_cents_per_day=500)
        result = mod.check_budget("agent:ok", estimated_tokens=100, estimated_cost_cents=5)
        assert result.allowed is True
        assert result.reason == "within_budget"

    def test_daily_token_limit_blocked(self, mod):
        mod.set_spend_policy("agent:tblock", max_tokens_per_day=100, hard_block_on_exceed=True)
        # Record spend that fills the daily bucket
        mod.record_spend("agent:tblock", tokens_used=95, cost_cents=0, jti="j1", action="read", resource="r")
        result = mod.check_budget("agent:tblock", estimated_tokens=10, estimated_cost_cents=0)
        assert result.allowed is False
        assert "daily_token_limit" in result.reason

    def test_daily_cost_limit_blocked(self, mod):
        mod.set_spend_policy("agent:cblock", max_cost_cents_per_day=50, hard_block_on_exceed=True)
        mod.record_spend("agent:cblock", tokens_used=0, cost_cents=48, jti="j2", action="read", resource="r")
        result = mod.check_budget("agent:cblock", estimated_tokens=0, estimated_cost_cents=5)
        assert result.allowed is False
        assert "daily_cost_limit" in result.reason

    def test_hard_block_false_allows_over_limit(self, mod):
        mod.set_spend_policy("agent:soft", max_tokens_per_day=10, hard_block_on_exceed=False)
        mod.record_spend("agent:soft", tokens_used=10, cost_cents=0, jti="j3", action="r", resource="r")
        result = mod.check_budget("agent:soft", estimated_tokens=5)
        assert result.allowed is True  # soft block = allow

    def test_remaining_tokens_decreases(self, mod):
        mod.set_spend_policy("agent:rem", max_tokens_per_day=1000)
        mod.record_spend("agent:rem", tokens_used=300, cost_cents=0, jti="j4", action="r", resource="r")
        result = mod.check_budget("agent:rem", estimated_tokens=0)
        assert result.remaining_tokens_today == 700

    def test_lifetime_cap_blocked(self, mod):
        mod.set_spend_policy("agent:life", max_cost_cents_total=100, hard_block_on_exceed=True)
        mod.record_spend("agent:life", tokens_used=0, cost_cents=98, jti="j5", action="r", resource="r")
        result = mod.check_budget("agent:life", estimated_cost_cents=5)
        assert result.allowed is False
        assert "lifetime_cost_cap" in result.reason


class TestRecordSpend:
    def test_record_appended(self, mod, tmp_path):
        mod.record_spend("agent:rec", tokens_used=100, cost_cents=10, jti="abc", action="read", resource="r")
        assert os.path.exists(mod.RECORDS_PATH)
        with open(mod.RECORDS_PATH) as f:
            lines = f.readlines()
        assert len(lines) == 1

    def test_record_fields(self, mod):
        rec = mod.record_spend("agent:fields", tokens_used=50, cost_cents=3, jti="xyz", action="write", resource="docs")
        assert rec.principal == "agent:fields"
        assert rec.tokens_used == 50
        assert rec.cost_cents == 3
        assert rec.jti == "xyz"
        assert rec.action == "write"
        assert rec.resource == "docs"

    def test_audit_ledger_called(self, mod):
        mod.record_spend("agent:audit", tokens_used=10, cost_cents=1, jti="j6", action="r", resource="r")
        mod._ledger.add_audit_entry.assert_called_once()

    def test_multiple_records_accumulate(self, mod):
        mod.record_spend("agent:multi", tokens_used=10, cost_cents=1, jti="j7", action="r", resource="r")
        mod.record_spend("agent:multi", tokens_used=20, cost_cents=2, jti="j8", action="r", resource="r")
        summary = mod.get_spend_summary("agent:multi")
        assert summary["total_tokens"] == 30
        assert summary["total_cost_cents"] == 3
        assert summary["action_count"] == 2


class TestGetSpendSummary:
    def test_empty_summary(self, mod):
        summary = mod.get_spend_summary("agent:empty")
        assert summary["total_tokens"] == 0
        assert summary["action_count"] == 0

    def test_summary_within_window(self, mod):
        mod.record_spend("agent:win", tokens_used=200, cost_cents=20, jti="j9", action="r", resource="r")
        summary = mod.get_spend_summary("agent:win", window_hours=24)
        assert summary["total_tokens"] == 200

    def test_summary_includes_policy(self, mod):
        mod.set_spend_policy("agent:pol", max_tokens_per_minute=777)
        summary = mod.get_spend_summary("agent:pol")
        assert summary["policy"]["max_tokens_per_minute"] == 777
