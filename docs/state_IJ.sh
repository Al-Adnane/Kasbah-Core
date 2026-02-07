#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"
AGENT="${AGENT:-agentA}"
AG2="${AG2:-agentB}"

post_decide() { ./demo/_post_json.sh "/api/rtp/decide" "$1"; }
post_consume() { ./demo/_post_json.sh "/api/rtp/consume" "$1"; }

echo "[I0] mint ticket as agentA"
T="$(post_decide "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.95,\"latency_score\":0.99}}" \
 | python3 -c 'import sys,json; d=json.load(sys.stdin); print(json.dumps(d["ticket"]))')"
echo "$T" | python3 -c 'import sys,json; json.load(sys.stdin); print("TICKET_JSON_OK")'

echo "[I1] consume as agentB -> agent mismatch"
post_consume "{\"ticket\":$T,\"tool\":\"read.me\",\"agent_id\":\"$AG2\"}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); print(d)' \
| grep -q "agent mismatch" && echo "OK agent mismatch"

echo "[I2] consume as agentA -> consumed"
post_consume "{\"ticket\":$T,\"tool\":\"read.me\",\"agent_id\":\"$AGENT\"}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); print(d)' \
| grep -q "consumed" && echo "OK consumed"

echo "[I3] replay as agentA -> replay"
post_consume "{\"ticket\":$T,\"tool\":\"read.me\",\"agent_id\":\"$AGENT\"}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); print(d)' \
| grep -q "replay" && echo "OK replay"

echo "[J0] drift test (mint low EMA, then push EMA high, then consume old ticket -> state drift)"
AG="driftA"
T2="$(post_decide "{\"tool_name\":\"read.me\",\"agent_id\":\"$AG\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.95,\"latency_score\":0.99}}" \
 | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)["ticket"]))')"

for i in $(seq 1 20); do
  post_decide "{\"tool_name\":\"read.me\",\"agent_id\":\"$AG\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.01,\"latency_score\":0.99}}" >/dev/null
done

post_consume "{\"ticket\":$T2,\"tool\":\"read.me\",\"agent_id\":\"$AG\"}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); print(d)' \
| grep -q "state drift" && echo "OK state drift"

echo "PASS_LOCK_IJ"
