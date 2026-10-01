"""
Tests for core/moats/agent_identity.py
Agent credential issuance, verification, rotation, and revocation.
"""
import time
import os
import pytest


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    """Reload agent_identity with an isolated tmp DATA_DIR."""
    monkeypatch.setenv("KASBAH_DATA_DIR", str(tmp_path))
    import core.moats.agent_identity as m
    m.DATA_DIR = str(tmp_path)
    m.CREDENTIALS_PATH = os.path.join(str(tmp_path), "agent_credentials.json")
    return m


class TestIssueCredential:
    def test_returns_credential_and_secret(self, mod):
        cred, secret = mod.issue_credential("agent:test")
        assert cred.agent_id == "agent:test"
        assert len(secret) == 64

    def test_secret_not_stored_in_plaintext(self, mod):
        cred, secret = mod.issue_credential("agent:plaintext")
        assert cred.secret_hash != secret
        assert len(cred.secret_hash) == 64

    def test_credential_default_fields(self, mod):
        cred, _ = mod.issue_credential("agent:defaults")
        assert cred.revoked is False
        assert cred.revoked_at is None
        assert cred.expires_at is None
        assert cred.max_delegation_depth == 3

    def test_ttl_sets_expires_at(self, mod):
        before = int(time.time())
        cred, _ = mod.issue_credential("agent:ttl", ttl_seconds=3600)
        assert cred.expires_at is not None
        assert cred.expires_at >= before + 3600

    def test_max_delegation_depth_stored(self, mod):
        cred, _ = mod.issue_credential("agent:depth", max_delegation_depth=2)
        assert cred.max_delegation_depth == 2

    def test_metadata_stored(self, mod):
        cred, _ = mod.issue_credential("agent:meta", metadata={"team": "billing"})
        assert cred.metadata.get("team") == "billing"

    def test_parent_agent_id_stored(self, mod):
        cred, _ = mod.issue_credential("agent:child", parent_agent_id="agent:parent")
        assert cred.parent_agent_id == "agent:parent"

    def test_unique_credential_ids(self, mod):
        mod.issue_credential("agent:u1")
        mod.issue_credential("agent:u2")
        c1 = mod.get_credential("agent:u1")
        c2 = mod.get_credential("agent:u2")
        assert c1.credential_id != c2.credential_id


class TestVerifyCredential:
    def test_valid_secret_returns_true(self, mod):
        _, secret = mod.issue_credential("agent:verify")
        assert mod.verify_credential("agent:verify", secret) is True

    def test_wrong_secret_returns_false(self, mod):
        mod.issue_credential("agent:wrong")
        assert mod.verify_credential("agent:wrong", "badsecret") is False

    def test_unknown_agent_returns_false(self, mod):
        assert mod.verify_credential("agent:ghost", "anything") is False

    def test_revoked_credential_returns_false(self, mod):
        _, secret = mod.issue_credential("agent:revtest")
        mod.revoke_credential("agent:revtest")
        assert mod.verify_credential("agent:revtest", secret) is False

    def test_expired_credential_returns_false(self, mod):
        _, secret = mod.issue_credential("agent:expired", ttl_seconds=1)
        time.sleep(2)
        assert mod.verify_credential("agent:expired", secret) is False

    def test_non_expired_still_valid(self, mod):
        _, secret = mod.issue_credential("agent:fresh", ttl_seconds=300)
        assert mod.verify_credential("agent:fresh", secret) is True


class TestRotateCredential:
    def test_rotation_issues_new_secret(self, mod):
        _, secret1 = mod.issue_credential("agent:rotate")
        _, secret2 = mod.rotate_credential("agent:rotate")
        assert secret1 != secret2
        assert mod.verify_credential("agent:rotate", secret2) is True
        assert mod.verify_credential("agent:rotate", secret1) is False

    def test_rotation_preserves_metadata(self, mod):
        mod.issue_credential("agent:rotmeta", metadata={"env": "prod"})
        cred2, _ = mod.rotate_credential("agent:rotmeta")
        assert cred2.metadata.get("env") == "prod"

    def test_rotation_preserves_parent_agent_id(self, mod):
        mod.issue_credential("agent:rotchild", parent_agent_id="agent:rotparent")
        cred2, _ = mod.rotate_credential("agent:rotchild")
        assert cred2.parent_agent_id == "agent:rotparent"

    def test_rotation_unknown_agent_raises(self, mod):
        with pytest.raises(ValueError, match="No credential"):
            mod.rotate_credential("agent:nobody")

    def test_rotation_new_credential_id(self, mod):
        cred1, _ = mod.issue_credential("agent:rotid")
        cred2, _ = mod.rotate_credential("agent:rotid")
        assert cred1.credential_id != cred2.credential_id


class TestRevokeCredential:
    def test_revoke_returns_true_for_existing(self, mod):
        mod.issue_credential("agent:rev")
        assert mod.revoke_credential("agent:rev") is True

    def test_revoke_returns_false_for_unknown(self, mod):
        assert mod.revoke_credential("agent:nope") is False

    def test_revoked_flag_set(self, mod):
        mod.issue_credential("agent:revflag")
        mod.revoke_credential("agent:revflag")
        cred = mod.get_credential("agent:revflag")
        assert cred.revoked is True

    def test_revoked_at_set(self, mod):
        before = int(time.time())
        mod.issue_credential("agent:revat")
        mod.revoke_credential("agent:revat")
        cred = mod.get_credential("agent:revat")
        assert cred.revoked_at is not None
        assert cred.revoked_at >= before


class TestListCredentials:
    def test_secret_hash_redacted(self, mod):
        mod.issue_credential("agent:list1")
        result = mod.list_credentials()
        for item in result:
            assert item["secret_hash"] == "***"

    def test_returns_all_issued(self, mod):
        mod.issue_credential("agent:all1")
        mod.issue_credential("agent:all2")
        ids = [c["agent_id"] for c in mod.list_credentials()]
        assert "agent:all1" in ids
        assert "agent:all2" in ids

    def test_empty_when_no_credentials(self, mod):
        assert mod.list_credentials() == []
