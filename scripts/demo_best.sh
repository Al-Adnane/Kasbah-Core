#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8002}"

echo "== Kasbah-Core demo_best =="

boot() {
  docker compose down -v >/dev/null 2>&1 || true
  docker compose up -d --build >/dev/null
}

wait_health() {
  for i in $(seq 1 30); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "$BASE/health" || true)"
    if [ "$code" = "200" ]; then
      echo "✅ health OK"
      return 0
    fi
    sleep 0.2
  done
  echo "❌ health never reached 200"
  docker compose ps || true
  docker compose logs --tail=120 api || true
  exit 1
}

decide() {
  local tool="$1" agent="$2"
  local dec_body
  dec_body="$(python3 -c 'import json,sys; print(json.dumps({"tool_name":sys.argv[1],"agent_id":sys.argv[2],"signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}))' "$tool" "$agent")"
  curl -sS -X POST "$BASE/api/rtp/decide" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer dev-master-key" \
    -d "$dec_body"
}

get_jwt() {
  python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("ticket",""))' "$1"
}

mkbody() {
  local jwt="$1" tool="$2" agent="$3"
  python3 -c 'import json,sys; print(json.dumps({"ticket":sys.argv[1],"tool_name":sys.argv[2],"agent_id":sys.argv[3],"usage":{"tokens":0,"cost":0}}))' "$jwt" "$tool" "$agent"
}

consume_code() {
  local body="$1"
  curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/api/rtp/consume" \
    -H "Content-Type: application/json" \
    -d "$body" || true
}

consume_json() {
  local body="$1"
  curl -sS -X POST "$BASE/api/rtp/consume" \
    -H "Content-Type: application/json" \
    -d "$body" | python3 -m json.tool
}

echo "1) boot"
boot
echo "✅ up"

echo "2) health"
wait_health
echo "Docs: $BASE/docs"

# ----------------------------
# A) Tamper must be blocked (fresh, unconsumed ticket)
# ----------------------------
echo "3) decide (fresh ticket for tamper)"
DEC1="$(decide "read.me" "smoke")"
JWT1="$(get_jwt "$DEC1")"
[ -n "$JWT1" ] || { echo "❌ NO_JWT_FROM_DECIDE"; echo "$DEC1"; exit 2; }
echo "✅ got ticket (len=${#JWT1})"

echo "4) ✅ tamper blocked (expect 401/400) BEFORE any consume"
BAD1="${JWT1%?}x"
BODY_BAD1="$(mkbody "$BAD1" "read.me" "smoke")"
CODE="$(consume_code "$BODY_BAD1")"
if [ "$CODE" = "401" ] || [ "$CODE" = "400" ]; then
  echo "✅ tamper blocked ($CODE)"
else
  echo "❌ tamper not blocked ($CODE)"
  exit 3
fi

# ----------------------------
# B) Happy path consume (fresh ticket)
# ----------------------------
echo "5) ✅ happy path consume"
BODY1="$(mkbody "$JWT1" "read.me" "smoke")"
consume_json "$BODY1" >/dev/null
echo "✅ consume allowed"

# ----------------------------
# C) Tool/agent mismatch blocked (fresh, NOT consumed)
# ----------------------------
echo "6) ✅ drift/tool mismatch blocked (expect 400/401)"
DEC2="$(decide "read.me" "smoke")"
JWT2="$(get_jwt "$DEC2")"
[ -n "$JWT2" ] || { echo "❌ NO_JWT_FROM_DECIDE #2"; echo "$DEC2"; exit 4; }
BODY_MISMATCH="$(mkbody "$JWT2" "shell.exec" "evil")"
CODE="$(consume_code "$BODY_MISMATCH")"
if [ "$CODE" = "400" ] || [ "$CODE" = "401" ]; then
  echo "✅ tool/agent mismatch blocked ($CODE)"
else
  echo "❌ tool/agent mismatch not blocked ($CODE)"
  exit 5
fi

# ----------------------------
# D) Replay blocked (consume same JWT twice)
# ----------------------------
echo "7) ✅ replay blocked (409)"
DEC3="$(decide "read.me" "smoke")"
JWT3="$(get_jwt "$DEC3")"
[ -n "$JWT3" ] || { echo "❌ NO_JWT_FROM_DECIDE #3"; echo "$DEC3"; exit 6; }
BODY3="$(mkbody "$JWT3" "read.me" "smoke")"

CODE="$(consume_code "$BODY3")"
[ "$CODE" = "200" ] || { echo "❌ first consume not 200 ($CODE)"; exit 7; }

CODE="$(consume_code "$BODY3")"
[ "$CODE" = "409" ] && echo "✅ replay blocked (409)" || { echo "❌ replay not blocked ($CODE)"; exit 8; }

echo "== ✅ DEMO PASSED =="
