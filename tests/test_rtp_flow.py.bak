import os, time, requests

BASE = os.environ.get("KASBAH_BASE", "http://localhost:8002")
TIMEOUT = float(os.environ.get("KASBAH_CAT_TIMEOUT", "25"))

def wait_health():
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE}/health", timeout=2)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("health timeout")

def test_decide_consume_replay():
    wait_health()

    decide = requests.post(
        f"{BASE}/api/rtp/decide",
        json={
            "tool_name": "read.me",
            "agent_id": "pytest",
            "signals": {"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99},
        },
        timeout=5,
    )
    assert decide.status_code == 200
    d = decide.json()
    assert d["decision"] == "ALLOW"
    assert "ticket" in d and isinstance(d["ticket"], dict)

    ticket = d["ticket"]
    for k in ["jti","tool_name","iat","exp","nonce","v","sig","args"]:
        assert k in ticket

    c1 = requests.post(f"{BASE}/api/rtp/consume", json={"ticket": ticket, "tool_name": "read.me"}, timeout=5).json()
    assert c1["valid"] is True and c1["reason"] == "consumed"

    c2 = requests.post(f"{BASE}/api/rtp/consume", json={"ticket": ticket, "tool_name": "read.me"}, timeout=5).json()
    assert c2["valid"] is False and c2["reason"] == "replay"
