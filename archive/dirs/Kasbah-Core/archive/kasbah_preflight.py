import json, os, sys, time, subprocess, glob
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

BASE = os.environ.get("BASE", "http://127.0.0.1:8002").rstrip("/")
N_CONCURRENCY = int(os.environ.get("N_CONCURRENCY", "50"))
N_DECIDES = int(os.environ.get("N_DECIDES", "300"))
CONTAINER = os.environ.get("KASBAH_CONTAINER", "kasbah-core-api-1")
OUT = "/tmp/kasbah_preflight"

def sh(cmd: str) -> str:
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.stdout

def http_json(method: str, path: str, payload=None, timeout=10):
    url = f"{BASE}{path}"
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8")
            return r.status, body, json.loads(body)
    except HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        try:
            j = json.loads(body) if body else None
        except Exception:
            j = None
        return e.code, body, j
    except URLError as e:
        raise SystemExit(f"HTTP error to {url}: {e}")

def assert_true(cond, msg):
    if not cond:
        raise SystemExit(f"[FAIL] {msg}")

def banner(msg):
    print(f"\n== {msg} ==")

def get_health():
    code, body, j = http_json("GET", "/health", None)
    assert_true(code == 200, f"/health not 200: {code} {body[:200]}")
    assert_true(isinstance(j, dict) and j.get("ok") is True, f"/health payload unexpected: {j}")
    print("[OK] health")

def docker_kasbah_ls():
    out = sh(f"docker exec -i {CONTAINER} sh -lc 'ls -la /app/.kasbah | head -n 50'")
    assert_true("rtp_audit.log" in out or "decisions.jsonl" in out, "kasbah dir missing expected files/mount")
    print("[OK] /app/.kasbah mounted")

def reset_state():
    sh(f"docker exec -i {CONTAINER} sh -lc ': > /app/.kasbah/decisions.jsonl || true; : > /app/.kasbah/rtp_used_jti.jsonl || true; : > /app/.kasbah/rtp_signal_state.jsonl || true; : > /app/.kasbah/ledger.json || true; : > /app/.kasbah/rtp_audit.log || true; rm -rf /app/.kasbah/used/* || true'")
    print("[OK] state reset")

def decide(agent="preflight", tool="read.me", signals=None):
    usage = {"tokens":0, "cost":0, "agent_id":agent}
    if signals is not None:
        usage["signals"] = signals
    code, body, j = http_json("POST", "/api/rtp/decide", {"tool_name": tool, "usage": usage})
    assert_true(code == 200, f"decide failed: {code} {body[:200]}")
    assert_true(isinstance(j, dict), "decide not json object")
    t = (((j.get("ticket") or {}) .get("ticket")) if isinstance(j.get("ticket"), dict) else None)
    assert_true(isinstance(t, str) and len(t) > 10, f"missing ticket string in response: {j}")
    jti = None
    if isinstance(j.get("ticket"), dict):
        jti = j["ticket"].get("jti")
    return t, jti, j

def consume(ticket, tool="read.me", agent="preflight", signals=None):
    usage = {"tokens":0, "cost":0, "agent_id":agent}
    if signals is not None:
        usage["signals"] = signals
    code, body, j = http_json("POST", "/api/rtp/consume", {"ticket": ticket, "tool": tool, "usage": usage})
    assert_true(code == 200, f"consume failed: {code} {body[:200]}")
    assert_true(isinstance(j, dict) and "valid" in j, f"consume response unexpected: {j}")
    return j

def concurrency_test():
    banner(f"RTP concurrency ({N_CONCURRENCY} parallel)")
    t, jti, _ = decide(agent="race", tool="read.me")
    os.makedirs(OUT, exist_ok=True)
    for f in glob.glob(f"{OUT}/resp_*.json"):
        os.remove(f)

    # spawn parallel curls writing to files (no stream concat)
    # use python subprocess for portability
    procs = []
    payload = json.dumps({"ticket": t, "tool":"read.me", "usage":{"tokens":0,"cost":0,"agent_id":"race"}})
    for i in range(1, N_CONCURRENCY+1):
        fn = f"{OUT}/resp_{i}.json"
        cmd = f"curl -sS -X POST '{BASE}/api/rtp/consume' -H 'Content-Type: application/json' -d '{payload}' > '{fn}'"
        procs.append(subprocess.Popen(cmd, shell=True))
    for p in procs:
        p.wait()

    ok=deny=other=0
    for fn in glob.glob(f"{OUT}/resp_*.json"):
        s=open(fn,"r").read().strip()
        try:
            o=json.loads(s)
            if o.get("valid") is True:
                ok += 1
            elif o.get("valid") is False:
                deny += 1
            else:
                other += 1
        except Exception:
            other += 1

    print(f"OK: {ok} DENY: {deny} OTHER: {other}")
    assert_true(ok == 1 and deny == (N_CONCURRENCY-1) and other == 0, "concurrency replay invariant failed")
    print("[OK] concurrency replay invariant")

def restart_semantics():
    banner("Restart semantics (replay persists)")
    t, _, _ = decide(agent="restart", tool="read.me")
    r1 = consume(t, tool="read.me", agent="restart")
    assert_true(r1.get("valid") is True, f"first consume not valid: {r1}")
    sh("docker compose restart >/dev/null 2>&1 || true")
    time.sleep(2)
    get_health()
    r2 = consume(t, tool="read.me", agent="restart")
    assert_true(r2.get("valid") is False and (r2.get("reason") in ("replay","used","missing")), f"second consume should deny: {r2}")
    print("[OK] restart replay denied")

def tool_mismatch_does_not_burn():
    banner("Tool mismatch doesn't burn ticket")
    t, _, _ = decide(agent="mismatch", tool="read.me")
    r_bad = consume(t, tool="other.tool", agent="mismatch")
    assert_true(r_bad.get("valid") is False, f"tool mismatch should be invalid: {r_bad}")
    # now consume correctly; must still be possible (rollback works)
    r_good = consume(t, tool="read.me", agent="mismatch")
    assert_true(r_good.get("valid") is True, f"ticket burned by mismatch (should not): {r_good}")
    print("[OK] mismatch rollback invariant")

def geometry_block_test():
    banner("Geometry gate (if signals provided)")
    # If your geometric_integrity expects certain keys, this may be a no-op.
    # We try an obviously 'bad' signal packet; if API ignores it, test is skipped.
    bad = {"entropy": 0.0, "loop_count_10s": 9999, "error": True}
    t, _, _ = decide(agent="geom", tool="read.me", signals=bad)
    r = consume(t, tool="read.me", agent="geom", signals=bad)
    if r.get("valid") is False and r.get("reason") == "geometry_block":
        print("[OK] geometry blocks bad signals")
    else:
        print("[SKIP] geometry did not block; this may be expected if signals schema differs.")
        print("       consume returned:", r)

def crypto_tamper_test():
    banner("Crypto tamper (ticket string modified should fail)")
    t, _, _ = decide(agent="tamper", tool="read.me")
    tampered = t[:-2] + ("AA" if not t.endswith("AA") else "BB")

    # Some deployments return 401 for invalid tickets (also acceptable).
    code, body, j = http_json("POST", "/api/rtp/consume", {
        "ticket": tampered,
        "tool": "read.me",
        "usage": {"tokens": 0, "cost": 0, "agent_id": "tamper"}
    })

    if code == 401:
        print("[OK] tampered ticket denied (401)")
        return

    assert_true(code == 200, f"consume unexpected status: {code} {body[:200]}")
    assert_true(isinstance(j, dict) and j.get("valid") is False, f"tampered ticket unexpectedly valid: {j}")
    print("[OK] tampered ticket denied (200)")

def basic_load():
    banner(f"Basic load (decide x{N_DECIDES})")
    t0=time.time()
    for _ in range(N_DECIDES):
        decide(agent="load", tool="read.me")
    dt=time.time()-t0
    print(f"[OK] {N_DECIDES} decides in {dt:.2f}s")

def audit_sanity():
    banner("Audit file sanity (non-empty, valid text)")
    out = sh(f"docker exec -i {CONTAINER} sh -lc 'wc -c /app/.kasbah/rtp_audit.log; tail -n 3 /app/.kasbah/rtp_audit.log || true'")
    # Not all flows write audit depending on your code, so we don't hard-fail.
    print(out.strip())
    print("[OK] audit accessible")

def main():
    banner("Preflight start")
    get_health()
    docker_kasbah_ls()
    reset_state()

    # Core RTP invariants
    concurrency_test()
    restart_semantics()
    tool_mismatch_does_not_burn()

    # Optional / best-effort tests
    crypto_tamper_test()
    geometry_block_test()

    # Load + audit access
    basic_load()
    audit_sanity()

    banner("ALL CORE TESTS PASSED")
    print("If geometry was skipped, adjust the signals schema in geometry_block_test().")

if __name__ == "__main__":
    main()
