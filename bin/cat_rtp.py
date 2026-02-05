#!/usr/bin/env python3
import json, os, subprocess, sys, time

BASE = os.environ.get("KASBAH_BASE", "http://localhost:8002")
TIMEOUT_S = float(os.environ.get("KASBAH_CAT_TIMEOUT", "25"))

def sh(cmd, check=True):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}")
    return p

def http_json(method, path, payload=None, check=True):
    cmd = ["curl","-sS","-X",method, f"{BASE}{path}", "-H","Content-Type: application/json"]
    if payload is not None:
        cmd += ["-d", json.dumps(payload)]
    out = sh(cmd, check=check).stdout.strip()
    if not out:
        raise RuntimeError(f"empty response from {path}")
    try:
        return json.loads(out)
    except Exception:
        raise RuntimeError(f"non-json response from {path}:\n{out[:4000]}")

def wait_health():
    deadline = time.time() + TIMEOUT_S
    last = None
    while time.time() < deadline:
        try:
            r = subprocess.run(
                ["curl","-sS", f"{BASE}/health"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            if r.returncode == 0 and '"status"' in r.stdout:
                return
            last = (r.returncode, r.stdout, r.stderr)
        except Exception as e:
            last = str(e)
        time.sleep(0.2)
    raise RuntimeError(f"health timeout after {TIMEOUT_S}s; last={last}")

def main():
    wait_health()

    decide = http_json("POST", "/api/rtp/decide", {
        "tool_name": "read.me",
        "agent_id": "smoke",
        "signals": {"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99},
    })

    if decide.get("decision") != "ALLOW":
        raise RuntimeError(f"expected ALLOW, got: {decide.get('decision')} reason={decide.get('reason')}")

    ticket = decide.get("ticket")
    if not isinstance(ticket, dict):
        raise RuntimeError(f"missing/invalid ticket in decide response. keys={sorted(decide.keys())}")

    required = {"jti","tool_name","iat","exp","nonce","v","sig","args"}
    missing = sorted(list(required - set(ticket.keys())))
    if missing:
        raise RuntimeError(f"ticket missing keys: {missing}")

    c1 = http_json("POST", "/api/rtp/consume", {"ticket": ticket, "tool_name": "read.me"})
    if not (c1.get("valid") is True and c1.get("reason") == "consumed"):
        raise RuntimeError(f"expected consumed, got: {c1}")

    c2 = http_json("POST", "/api/rtp/consume", {"ticket": ticket, "tool_name": "read.me"})
    if not (c2.get("valid") is False and c2.get("reason") == "replay"):
        raise RuntimeError(f"expected replay, got: {c2}")

    print("CAT_OK: decide->ticket->consume->replay works")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"CAT_FAIL: {e}", file=sys.stderr)
        sys.exit(1)
