# Kasbah Core — Moats Registry (Source of Truth)

This document lists the moats that exist in the current build, what evidence proves them, and what is explicitly out of scope.

## 0) Explicitly Out of Scope (Intentionally NOT implemented)
- Brittleness moat: **NO**
- Thermo lockdown: **NO**
- Bearer-token identity auth: **NO** (Kasbah uses signed tickets + optional authz-claims; no bearer identity layer)

## 1) Ticketing + Integrity Moats
1. **Signed tickets (HMAC-SHA256)** — tamper fails with `bad signature`.
2. **Tool binding** — ticket is bound to `tool_name`; tool swap fails with `tool mismatch`.
3. **Args binding (tool_hash)** — ticket is bound to args hash; args swap fails with `args mismatch`.
4. **Short TTL** — expiry enforced (`expired`).
5. **Replay protection (consume-once)** — Redis `SET NX` on ticket fingerprint; replays return `replay`.
6. **Concurrency-safe replay guard** — under concurrent consume calls, exactly one succeeds; rest are `replay`.

## 2) Rate-Limiting Moats (Redis-backed)
7. **Decide rate limiting** — `rate limited (decide)` after window threshold.
8. **Consume rate limiting** — `rate limited (consume)` after window threshold.

## 3) Kill-Switch / Emergency Moats
9. **Emergency disable all** — consume denied with `emergency:all`.
10. **Emergency re-enable all** — normal operations restored.

## 4) Authorization Moats (Optional, claims-based)
11. **Claims-based authz enforcement** (when enabled) — requires `principal/action/resource` claims; deny if missing.
12. **Role / policy evaluation** via `apps/api/rtp/authz.py` and `apps/api/rtp/authz_api.py` (admin ops).

## 5) Audit + Forensics Moats
13. **Append-only audit log** (`.kasbah/audit.jsonl`).
14. **Hash-chained audit entries** — each record includes `prev_hash` and `hash` to detect tampering.
15. **Audit query endpoint(s)** — ability to retrieve and inspect traces (e.g., explain by jti).

## 6) Multi-Instance Correctness Moats
16. **Shared replay + RL state** across multiple API instances via Redis (api + api2).
17. **Restart behavior** — replay state remains after Redis restart when persistence is enabled (AOF/RDB).

## Evidence (How we prove these)
- Replay race test result: `COUNTS {403: 49, 200: 1}`
- Ship rate limit proof: first 429 at request #61 with `rate limited (decide)`
- Redis persistence enabled: `appendonly yes` with RDB `save` policy
- Audit hash-chain proven by `prev_hash`/`hash` sequence in trace output

