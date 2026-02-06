#!/usr/bin/env python3
import json, sys, time, hashlib, urllib.request, urllib.error

BASE = "http://127.0.0.1:8002"
TIMEOUT = 5

def die(msg): print("FAIL:", msg, file=sys.stderr); sys.exit(1)

def http_json(method, path, body=None):
    url = BASE + path
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        die(f"{method} {path} HTTP {e.code}: {raw}")
    except Exception as e:
        die(f"{method} {path} error: {repr(e)}")

def get(path): return http_json("GET", path)
def post(path, body): return http_json("POST", path, body)
def audit_tail(n=220): return get(f"/api/rtp/audit?limit={int(n)}")

def assert_audit(events, kind, reason_contains=None):
    for e in reversed(events):
        if e.get("kind") != kind:
            continue
        if reason_contains is None:
            return e
        reason = str((e.get("payload") or {}).get("reason",""))
        if reason_contains in reason:
            return e
    die(f"audit missing kind={kind} reason_contains={reason_contains}")

def verify_chain(events):
    if not events: die("audit empty")
    prev = events[0]["prev_hash"]
    for i,e in enumerate(events):
        if e["prev_hash"] != prev: die(f"BAD_LINK idx={i}")
        payload_json = json.dumps(e["payload"], sort_keys=True, separators=(",",":"), ensure_ascii=False)
        expect = hashlib.sha256((prev+"|"+payload_json).encode()).hexdigest()
        if expect != e["row_hash"]: die(f"BAD_HASH idx={i}")
        prev = e["row_hash"]

def decide(agent, signals, tool="read.me"):
    return post("/api/rtp/decide", {"tool_name": tool, "agent_id": agent, "signals": signals})

def consume(ticket, tool, agent):
    return post("/api/rtp/consume", {"ticket": ticket, "tool": tool, "agent_id": agent})

def flip_sig(ticket):
    t = dict(ticket)
    if "sig" in t and isinstance(t["sig"], str) and len(t["sig"]) > 5:
        s=list(t["sig"]); s[-1]="0" if s[-1]!="0" else "1"; t["sig"]="".join(s); return t
    if "signature" in t and isinstance(t["signature"], str) and len(t["signature"]) > 5:
        s=list(t["signature"]); s[-1]="0" if s[-1]!="0" else "1"; t["signature"]="".join(s); return t
    die(f"no signature field to flip in {sorted(t.keys())}")

def main():
    h = get("/health")
    if h.get("status") != "operational": die(f"bad health {h}")

    # geometry block
    bad = decide("geo-smoke", {"consistency":0.99,"accuracy":0.99,"normality":0.01,"latency_score":0.99})
    if bad.get("decision") != "DENY" or "GEOMETRY_BLOCK" not in str(bad.get("reason","")):
        die(f"geometry gate failed {bad}")

    # replay
    good = decide("replay-smoke", {"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99})
    t = good.get("ticket"); 
    if not isinstance(t, dict) or "jti" not in t: die(f"missing ticket {good}")
    if consume(t,"read.me","replay-smoke").get("valid") is not True: die("consume1 should pass")
    r2 = consume(t,"read.me","replay-smoke")
    if not (r2.get("valid") is False and r2.get("reason")=="replay"): die(f"replay failed {r2}")

    # mismatch
    t2 = decide("mismatch-smoke", {"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99})["ticket"]
    mm = consume(t2,"shell.exec","mismatch-smoke")
    if not (mm.get("valid") is False and "tool mismatch" in str(mm.get("reason",""))): die(f"mismatch failed {mm}")

    # expired
    t3 = dict(decide("expired-smoke", {"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99})["ticket"])
    t3["exp"] = int(time.time()) - 10
    ex = consume(t3,"read.me","expired-smoke")
    if not (ex.get("valid") is False and "expired" in str(ex.get("reason",""))): die(f"expired failed {ex}")

    # sig tamper
    t4 = decide("sig-smoke", {"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99})["ticket"]
    st = consume(flip_sig(t4),"read.me","sig-smoke")
    if not (st.get("valid") is False and "bad signature" in str(st.get("reason",""))): die(f"sig tamper failed {st}")

    # drift
    t5 = dict(decide("drift-smoke", {"consistency":0.99,"accuracy":0.99,"normality":0.10,"latency_score":0.99})["ticket"])
    t5["ema"] = 0.99
    dr = consume(t5,"read.me","drift-smoke")
    if not (dr.get("valid") is False and "state drift" in str(dr.get("reason",""))): die(f"drift failed {dr}")

    # botnet deny
    bn = decide("botnet-smoke", {"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99})
    if bn.get("decision") != "DENY": die(f"botnet should DENY {bn}")

    # audit assertions
    tail = audit_tail(300)
    assert_audit(tail, "DECIDE_DENY_GEOMETRY", "GEOMETRY_BLOCK")
    assert_audit(tail, "CONSUME_OK")
    assert_audit(tail, "REPLAY")
    assert_audit(tail, "CONSUME_DENY", "tool mismatch")
    assert_audit(tail, "CONSUME_DENY", "expired")
    assert_audit(tail, "CONSUME_DENY", "bad signature")
    assert_audit(tail, "DRIFT", "state drift")
    assert_audit(tail, "DECIDE_DENY_BOTNET")

    verify_chain(tail)
    print("PASS: RTP FULL SMOKE LOCKED ✅")

if __name__ == "__main__":
    main()
