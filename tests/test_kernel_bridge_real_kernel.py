from apps.kernel.bridge import run_governed_action
from apps.kernel.decide_adapter import kernel_decide

def test_real_kernel_bridge_ai_tool():
    raw = {
        "agent_id": "bridge-smoke",
        "consistency": 0.95,
        "accuracy": 0.95,
        "normality": 0.95,
        "rate_pressure": 0.0,
    }

    out = run_governed_action(
        adapter_id="ai_tool",
        raw_event=raw,
        decide_fn=kernel_decide,
        enforce=False,  # no side effects in test
    )

    assert "decision" in out
    assert "decision" in out["decision"]
    assert out["adapter_id"] == "ai_tool"
