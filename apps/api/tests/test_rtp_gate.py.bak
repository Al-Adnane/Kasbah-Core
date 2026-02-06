import time
from apps.api.rtp.kernel_gate import KernelGate
from apps.api.rtp.kernel_enforcer import KernelEnforcer

def test_signature_verification_is_real():
    gate = KernelGate(tpm_enabled=False, policy={"shell.exec": "allow"})
    t = gate.generate_ticket("shell.exec", {"command": "echo hi"}, True, {"maxTokens": 10, "maxCostCents": 100})
    assert t is not None
    assert gate._verify_signature(t) is True

def test_monotonic_ttl_expiry():
    gate = KernelGate(tpm_enabled=False, policy={"shell.exec": "allow"})
    t = gate.generate_ticket("shell.exec", {"command": "echo hi"}, True, {"maxTokens": 10, "maxCostCents": 100})
    assert t is not None
    t.issued_mono_ns = time.monotonic_ns() - (t.ttl + 1_000_000)
    res = gate.validate_ticket(t, {"tokens": 0, "cost": 0})
    assert res.valid is False
    assert "expired" in res.reason.lower()

def test_one_time_use_replay_blocked():
    gate = KernelGate(tpm_enabled=False, policy={"shell.exec": "allow"})
    enforcer = KernelEnforcer(gate)
    t = gate.generate_ticket("shell.exec", {"command": "echo hi"}, True, {"maxTokens": 10, "maxCostCents": 100})
    assert t is not None
    enforcer.store_ticket(t)

    ok = enforcer.intercept_execution("shell.exec", t.jti, {"tokens": 0, "cost": 0})
    assert ok.valid is True

    replay = enforcer.intercept_execution("shell.exec", t.jti, {"tokens": 0, "cost": 0})
    assert replay.valid is False
    assert "replay" in replay.reason.lower()

