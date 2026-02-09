from apps.kernel.bridge import run_governed_action

def _dummy_decide(req: dict) -> dict:
    # deterministic dummy kernel for contract testing
    return {"decision": "ALLOW", "kernel_state": "NORMAL", "risk_score": 0.1, "threshold": 0.5, "ticket": {"ok": True}}

def test_bridge_runs_for_ai_tool():
    raw = {"agent_id": "smoke", "consistency": 0.9, "accuracy": 0.9, "normality": 0.9, "rate_pressure": 0.0}
    out = run_governed_action(adapter_id="ai_tool", raw_event=raw, decide_fn=_dummy_decide, enforce=True)
    assert out["decision"]["decision"] == "ALLOW"
    assert out["adapter_id"] == "ai_tool"
    assert isinstance(out["request"], dict)

def test_bridge_runs_for_human_finance():
    raw = {"user_id": "u1", "policy_deviation": 0.0, "time_pressure": 0.2, "override_rate": 0.0, "amount_z": 0.1}
    out = run_governed_action(adapter_id="human_finance", raw_event=raw, decide_fn=_dummy_decide, enforce=True)
    assert out["decision"]["decision"] == "ALLOW"

def test_bridge_runs_for_dao_exec():
    raw = {"dao_id": "dao1", "quorum_strength": 0.8, "proposal_drift": 0.1, "execution_delay": 0.0, "revert_rate": 0.0}
    out = run_governed_action(adapter_id="dao_exec", raw_event=raw, decide_fn=_dummy_decide, enforce=True)
    assert out["decision"]["decision"] == "ALLOW"
