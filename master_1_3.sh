#!/usr/bin/env bash
set -euo pipefail

# MASTER CAT for:
# (1) Step 8 scaffold (next moat pipeline placeholder)
# (3) Threat-model pass (prints + writes a focused checklist)
# plus: re-verify Step 7 closure before moving on

BASE="http://127.0.0.1:8002"

die(){ echo "❌ $1"; exit 1; }
ok(){ echo "✅ $1"; }

echo "==============================="
echo "MASTER (1 + 3) — PREP + VERIFY"
echo "==============================="

# --- sanity: repo root ---
[[ -f docker-compose.yml ]] || die "Run from repo root (docker-compose.yml not found)."

# --- read DEV_MASTER_KEY from .env ---
[[ -f .env ]] || die ".env missing (expected DEV_MASTER_KEY)."
DEV_MASTER_KEY="$(python3 -c 'import re; s=open(".env","r",encoding="utf-8").read(); m=re.search(r"^DEV_MASTER_KEY=(.*)$", s, re.M); print((m.group(1).strip() if m else ""))')"
[[ -n "${DEV_MASTER_KEY:-}" ]] || die "DEV_MASTER_KEY missing in .env"
AUTH="Authorization: Bearer ${DEV_MASTER_KEY}"

echo "[A] Current git head + tag state"
git --no-pager log -1 --oneline
git tag --points-at HEAD || true
echo

echo "[B] Ensure stack is up"
docker compose up -d --build >/dev/null
sleep 1

echo "[C] Health"
curl -sS "$BASE/health" | grep -q '"ok":true' && ok "Health OK" || die "Health FAIL"

echo
echo "==============================="
echo "STEP 7 — QUICK RE-VERIFY"
echo "==============================="

echo "[1] Decide"
DECIDE="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d '{"tool_name":"read.me","agent_id":"master-1-3","signals":{"consistency":0.99}}')"

TICKET="$(printf '%s' "$DECIDE" | python3 -c 'import sys,json
d=json.loads(sys.stdin.read())
t=d.get("ticket")
print(t["jti"] if isinstance(t,dict) and "jti" in t else (t if isinstance(t,str) else ""))
')"
[[ -n "${TICKET:-}" ]] || die "No ticket from decide"

echo "[2] Consume once (ALLOW)"
OUT1="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"master-1-3\"}")"
echo "$OUT1" | grep -qi "ALLOWED" && ok "Consume allowed" || die "Consume failed: $OUT1"

echo "[3] Replay (DENY)"
OUT2="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"master-1-3\"}")"
echo "$OUT2" | grep -qi "replay\|deny\|invalid\|used" && ok "Replay denied" || die "Replay NOT denied: $OUT2"

echo "[4] Tool mismatch (DENY)"
OUT3="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"shell.exec\",\"agent_id\":\"master-1-3\"}")"
echo "$OUT3" | grep -qi "mismatch\|deny\|invalid" && ok "Mismatch denied" || die "Mismatch NOT denied: $OUT3"

echo "[5] Tamper (DENY)"
BAD="${TICKET%?}x"
OUT4="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"master-1-3\"}")"
echo "$OUT4" | grep -qi "bad signature\|signature\|deny\|invalid" && ok "Tamper denied" || die "Tamper NOT denied: $OUT4"

ok "Step 7 still closed ✅"

echo
echo "==============================="
echo "(1) STEP 8 — SCAFFOLD"
echo "==============================="

mkdir -p docs scripts

# Step 8 backlog skeleton (edit after)
cat <<'MD' > docs/STEP8_BACKLOG.md
# Step 8 Backlog (Next Moat / Next Capability)

## Goal
Define the next moat to implement, with:
- clear acceptance tests
- explicit non-goals
- rollback plan

## Candidate Step 8 options (pick one)
- A) Stronger authz: principal/action/resource enforced for RTP + system endpoints
- B) Audit export: signed audit bundle + deterministic replay verifier
- C) Abuse controls: per-principal budgets + anomaly alerts
- D) Hardening: middleware correctness (401/403 without 500), structured errors

## Acceptance tests (must pass)
- [ ] Threat-model item coverage mapped to tests
- [ ] Negative tests: bypass attempts fail
- [ ] Restart persistence proven (where relevant)
- [ ] Clean repo + reproducible build

## Notes
Write the exact endpoints, expected responses, and any env required.
MD

# Step 8 quick env checker placeholder
cat <<'SH' > scripts/step8_env_check.sh
#!/usr/bin/env bash
set -euo pipefail
echo "=== Step 8 env check ==="
echo "Repo: $(pwd)"
echo "Git:  $(git rev-parse --short HEAD)"
echo "Docker:"
docker compose ps
echo
echo "Health:"
curl -sS http://127.0.0.1:8002/health ; echo
SH
chmod +x scripts/step8_env_check.sh

ok "Created docs/STEP8_BACKLOG.md and scripts/step8_env_check.sh"

echo
echo "==============================="
echo "(3) THREAT MODEL — FAST PASS"
echo "==============================="

cat <<'MD' > docs/THREAT_MODEL_STEP7.md
# Threat Model (Step 7 Closure Baseline)

## Assets
- Ticket integrity (signature)
- One-time consumption (replay protection)
- Tool binding (ticket → tool_name)
- Auth boundary (bearer token enforcement)
- Persistence (replay survives restart)

## Verified (Evidence from your run)
- Replay denied: {"detail":"replay"}
- Tool mismatch denied: {"detail":"tool mismatch"}
- Tamper denied: {"detail":"bad signature"}
- Restart persistence confirmed

## Remaining realistic threats to address in Step 8+
- [ ] Auth middleware returns correct status codes (401/403) without leaking 500s
- [ ] Rate limiting per principal (not only per agent/tool)
- [ ] Audit log tamper-evidence (hash chain / signature of audit bundles)
- [ ] Key management hygiene (dev vs prod keys, rotation, storage)
- [ ] Endpoint surface review: ensure only intended endpoints require auth, and public endpoints are safe
- [ ] Multi-instance consistency: replay guard consistency across api/api2 with Redis/fallback rules clearly defined

## Abuse scenarios to test next
- [ ] Attempt ticket reuse across api and api2
- [ ] Attempt tool_name casing/whitespace bypass
- [ ] Attempt very large payload / JSON bomb
- [ ] Attempt missing/invalid Authorization header (expect 401, not 500)
MD

ok "Wrote docs/THREAT_MODEL_STEP7.md"

echo
echo "==============================="
echo "DONE (1 + 3)"
echo "==============================="

echo "Next: run this anytime:"
echo "  ./scripts/step8_env_check.sh"
echo
echo "Repo status:"
git status --porcelain=v1 || true
