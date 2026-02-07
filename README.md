# Kasbah Core

Deterministic policy control for autonomous systems.

Kasbah Core is a minimal control plane that sits between AI agents and execution:
it evaluates intent, enforces tool gates, and writes an append-only audit log.

This repo ships a runnable prototype for security engineers and CTOs.

---

## Quick start (2 commands)

```bash
docker compose up --build


---

## 🔐 Minimal real API example (no demo, no UI)

This is a real Kasbah-Core runtime flow.
No simulation. No frontend. No policy-only logic.

STEP 1 — Ask Kasbah if an action is allowed

curl -s http://localhost:8002/api/rtp/decide \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer DEV_KEY" \
  -d '{
    "agent_id": "support-bot",
    "tool_name": "db.query",
    "signals": {
      "consistency": 0.95,
      "context": 0.90
    }
  }'

Example response:

{
  "decision": "ALLOW",
  "ticket": {
    "jti": "5a3bde1e887e000116e8943663b5088d",
    "expires_at": 1770307384
  }
}

STEP 2 — Execute the action using the issued ticket

curl -s http://localhost:8002/api/rtp/consume \
  -H "Content-Type: application/json" \
  -d '{
    "ticket": "5a3bde1e887e000116e8943663b5088d",
    "tool_name": "db.query",
    "usage": { "tokens": 120 }
  }'

Response:

{ "status": "ALLOWED" }

STEP 3 — Replay the same ticket (blocked by Kasbah)

curl -s http://localhost:8002/api/rtp/consume \
  -H "Content-Type: application/json" \
  -d '{
    "ticket": "5a3bde1e887e000116e8943663b5088d",
    "tool_name": "db.query"
  }'

Response:

{
  "status": "DENIED",
  "reason": "replay_detected"
}

This denial is stateful and irreversible.
Tickets are single-use, tool-bound, time-bound, and verified at runtime.


---

## 🔐 Minimal real API example (no demo, no UI)

This is a real Kasbah-Core runtime flow.
No simulation. No frontend. No policy-only logic.

STEP 1 — Ask Kasbah if an action is allowed

curl -s http://localhost:8002/api/rtp/decide \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer DEV_KEY" \
  -d '{
    "agent_id": "support-bot",
    "tool_name": "db.query",
    "signals": {
      "consistency": 0.95,
      "context": 0.90
    }
  }'

Example response:

{
  "decision": "ALLOW",
  "ticket": {
    "jti": "5a3bde1e887e000116e8943663b5088d",
    "expires_at": 1770307384
  }
}

STEP 2 — Execute the action using the issued ticket

curl -s http://localhost:8002/api/rtp/consume \
  -H "Content-Type: application/json" \
  -d '{
    "ticket": "5a3bde1e887e000116e8943663b5088d",
    "tool_name": "db.query",
    "usage": { "tokens": 120 }
  }'

Response:

{ "status": "ALLOWED" }

STEP 3 — Replay the same ticket (blocked by Kasbah)

curl -s http://localhost:8002/api/rtp/consume \
  -H "Content-Type: application/json" \
  -d '{
    "ticket": "5a3bde1e887e000116e8943663b5088d",
    "tool_name": "db.query"
  }'

Response:

{
  "status": "DENIED",
  "reason": "replay_detected"
}

This denial is stateful and irreversible.
Tickets are single-use, tool-bound, time-bound, and verified at runtime.

