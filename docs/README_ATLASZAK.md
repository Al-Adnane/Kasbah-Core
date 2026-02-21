# AtlasZak (Local Hands-On Test)

## What this is
A local “proof of gate” that demonstrates multiple security/compliance moats:
- Signed tickets + TTL
- Tool/agent binding
- Replay lock (fail-closed if Redis unavailable)
- Rate limits (fail-closed)
- Optional args binding (hash-bound ticket)
- Verify endpoint
- Tamper-evident audit hash-chain + verifier
- Deterministic deny hooks
- Chaos restart resilience

## Requirements
- Docker Desktop installed and running
- Terminal

## Run
From repo root:

  ./atlaszak.sh

Recommended order:
1) Boot
3) Moats 1–5
7) TTL expiry live
8) Args binding
9) Rate limit
10) Audit hash-chain verify
12) Fail-closed Redis test
13) Chaos restart resilience

## Notes
- Everything runs locally on http://127.0.0.1:8002
