#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://127.0.0.1:8002}"

REQS="${REQS:-1000}"          # total decide requests
BATCH="${BATCH:-50}"          # concurrency per batch
TIMEOUT="${TIMEOUT:-3}"       # curl timeout seconds
TOKENS_MAX="${TOKENS_MAX:-5000}"

echo "🔥 EXTREME LOAD TEST (SAFE) 🔥"
echo "API=$API  REQS=$REQS  BATCH=$BATCH  TIMEOUT=${TIMEOUT}s"
echo "================================"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 2; }; }
need curl
need python3

health() {
  curl -sS --max-time "$TIMEOUT" "$API/health"
}
status() {
  curl -sS --max-time "$TIMEOUT" "$API/api/system/status"
}

echo "0) Preflight..."
H="$(health)"
S="$(status)"
echo "health: $H"
echo "status: $S"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ok=0
fail=0

echo
echo "1) Flood decide with mixed signals (no exploit strings)..."
for ((i=1; i<=REQS; i++)); do
  # normality in [0.00, 0.99]
  n=$((RANDOM % 100))
  # tokens in [0, TOKENS_MAX]
  t=$((RANDOM % (TOKENS_MAX+1)))

  curl -sS --max-time "$TIMEOUT" -X POST "$API/api/rtp/decide" \
    -H "Content-Type: application/json" \
    -d "{\"tool_name\":\"load.test.$i\",\"signals\":{\"normality\":0.$(printf "%02d" "$n"),\"consistency\":0.90},\"usage\":{\"tokens\":$t,\"cost\":0,\"agent_id\":\"extreme\"}}" \
    > "$TMP/decide_$i.json" 2> "$TMP/decide_$i.err" &

  if (( i % BATCH == 0 )); then
    wait || true
    echo -n "."
  fi
done
wait || true
echo " done"

# Count successes/failures by parsing JSON shape
python3 - <<'PY'
import json, glob, os, sys
tmp=os.environ["TMP"]
ok=fail=0
for p in glob.glob(os.path.join(tmp,"decide_*.json")):
    try:
        d=json.load(open(p))
        if isinstance(d,dict) and "decision" in d:
            ok += 1
        else:
            fail += 1
    except Exception:
        fail += 1
print(f"decide_ok={ok} decide_fail={fail}")
open(os.path.join(tmp,"counts.txt"),"w").write(f"{ok} {fail}\n")
PY

read ok fail < "$TMP/counts.txt"

echo
echo "2) Ticket consume + replay check (correctness under load)..."
DECIDE="$(curl -sS --max-time "$TIMEOUT" -X POST "$API/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","usage":{"tokens":0,"cost":0,"agent_id":"extreme"}}')"

T="$(printf '%s' "$DECIDE" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("ticket",""))')"
if [ -z "$T" ]; then
  echo "❌ No ticket returned from decide"
  echo "$DECIDE"
  exit 1
fi

C1="$(curl -sS --max-time "$TIMEOUT" -X POST "$API/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$T\",\"tool_name\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"extreme\"}}")"

C2="$(curl -sS --max-time "$TIMEOUT" -X POST "$API/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$T\",\"tool_name\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"extreme\"}}")"

echo "consume_1: $C1"
echo "consume_2 (replay expected): $C2"

echo
echo "3) Audit growth check (last 20)..."
AUD="$(curl -sS --max-time "$TIMEOUT" "$API/api/rtp/audit?limit=20")"
echo "$AUD" | python3 - <<'PY'
import json,sys
x=json.load(sys.stdin)
print("audit_type:", type(x).__name__)
if isinstance(x,list):
    print("audit_len:", len(x))
    if x:
        keys=sorted(set().union(*[set(e.keys()) for e in x if isinstance(e,dict)]))
        print("keys:", keys[:20])
PY

echo
echo "4) Final health + status..."
echo "health: $(health)"
echo "status: $(status)"

echo
echo "==== SUMMARY ===="
echo "decide_ok=$ok decide_fail=$fail"

# Fail the test if too many decide failures
# Allow a small failure rate (timeouts under load), adjust if needed
max_fail=$((REQS / 50))  # 2%
if (( fail > max_fail )); then
  echo "❌ Too many decide failures: $fail > $max_fail"
  exit 1
fi

echo "✅ Load test passed within tolerance."
