#!/usr/bin/env bash
set -u  # no -e: we want full diagnostics, not silent exits

BASE="http://127.0.0.1:8002"
PASS=0
FAIL=0

green() { echo "✅ $1"; PASS=$((PASS+1)); }
red()   { echo "❌ $1"; FAIL=$((FAIL+1)); }

echo "==============================="
echo "STEP 7 — FINAL KILLSHOT CHECK (v3)"
echo "==============================="

# ---------- 1) HEALTH ----------
echo "[1] Health check"
HEALTH="$(curl -sS "$BASE/health" 2>/dev/null || true)"
echo "health_raw=${HEALTH:-<empty>}"

python3 - <<'PY' "$HEALTH" >/dev/null 2>&1
import sys, json
raw=sys.argv[1]
d=json.loads(raw)
ok=d.get("ok", None)
status=str(d.get("status","")).lower()
is_ok = (ok is True) or (str(ok).lower()=="true") or (status=="ok")
raise SystemExit(0 if is_ok else 1)
PY
if [[ $? -eq 0 ]]; then green "Health OK"; else red "Health FAIL"; fi

# ---------- 2) DECIDE ----------
echo "[2] Decide (issue ticket)"
DECIDE="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"step7","signals":{"consistency":0.99}}' 2>/dev/null || true)"

if [[ -z "${DECIDE:-}" ]]; then
  red "Decide call returned empty (endpoint down or path wrong)"
  echo "---- RAW DECIDE ----"
  echo "<empty>"
else
  echo "decide_raw=$(echo "$DECIDE" | head -c 220)"
  TICKET="$(echo "$DECIDE" | python3 - <<'PY' 2>/dev/null || true
import sys,json
d=json.load(sys.stdin)
print(d["ticket"]["jti"])
PY
)"
  if [[ -n "${TICKET:-}" ]]; then green "Ticket issued"; else red "Ticket missing in decide response"; fi
fi

# If no ticket, stop here with a clear verdict
if [[ -z "${TICKET:-}" ]]; then
  echo "-------------------------------"
  echo "PASS=$PASS  FAIL=$FAIL"
  echo "-------------------------------"
  exit 1
fi

# ---------- 3) CONSUME ONCE ----------
echo "[3] First consume (should ALLOW)"
OUT1="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"step7\"}" 2>/dev/null || true)"
echo "consume1_raw=$(echo "$OUT1" | head -c 220)"
echo "$OUT1" | grep -qi "ALLOWED" && green "First consume allowed" || red "First consume failed"

# ---------- 4) REPLAY ----------
echo "[4] Replay consume (should DENY)"
OUT2="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"step7\"}" 2>/dev/null || true)"
echo "replay_raw=$(echo "$OUT2" | head -c 220)"
echo "$OUT2" | grep -qi "deny\|invalid\|used\|replay" && green "Replay denied" || red "Replay NOT denied"

# ---------- 5) TOOL MISMATCH ----------
echo "[5] Tool mismatch (should DENY)"
OUT3="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"shell.exec\",\"agent_id\":\"step7\"}" 2>/dev/null || true)"
echo "mismatch_raw=$(echo "$OUT3" | head -c 220)"
echo "$OUT3" | grep -qi "deny\|mismatch\|invalid" && green "Tool mismatch denied" || red "Tool mismatch NOT denied"

# ---------- 6) TAMPER ----------
echo "[6] Tamper ticket (should DENY)"
BAD="${TICKET%?}x"
OUT4="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"step7\"}" 2>/dev/null || true)"
echo "tamper_raw=$(echo "$OUT4" | head -c 220)"
echo "$OUT4" | grep -qi "deny\|invalid\|signature\|bad" && green "Tamper denied" || red "Tamper NOT denied"

echo "-------------------------------"
echo "PASS=$PASS  FAIL=$FAIL"
echo "-------------------------------"

if [[ "$FAIL" -eq 0 ]]; then
  echo "🎯 STEP 7 COMPLETE"
  exit 0
else
  echo "🚨 STEP 7 NOT COMPLETE"
  exit 1
fi
