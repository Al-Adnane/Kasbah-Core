# Kasbah Guard

**Use any AI. Leak nothing. Prove everything.** — local-first governance for AI:
a deterministic detector that blocks hostile input before it leaves the machine,
a tiered "seatbelt" intervention layer, and portable, offline-verifiable receipts
(Ed25519 + ML-DSA) for every decision.

Three surfaces, one receipt format:

| Surface | Promise |
|---|---|
| **Proof** | Portable cryptographic evidence of every AI action — signed, offline-verifiable, Merkle-batchable |
| **Seatbelt** | Silent Pass · Warning Toast · Hard Block (never DENY) before damage |
| **Kernel** | Single-use tool+args agent tickets, kill switch, cost governor |

## Run

```bash
# API server (the engine)
npm install
PORT=8788 node packages/api-server/server.js
curl -s localhost:8788/v1/health          # {"status":"ok",...}

# Governance in one call
curl -s -X POST localhost:8788/v1/govern \
  -H 'content-type: application/json' \
  -d '{"prompt":"my aws key is AKIAIOSFODNN7EXAMPLE"}'

# Desktop app (Electron)
cd packages/desktop && npm start
```

The proof surface is at `/century` (UI) and `/verify/:id` (public receipt check).

## Test

```bash
npm test                       # core suites (runtime, enforcer, mcp, receipts…)
npm run bench:detection        # detector regression gate (fails below baseline)
node bench/run.js --api http://127.0.0.1:8788   # full detection benchmark → BENCHMARK.md
```

In `packages/api-server`, `npm test` runs the Jest suites; the `src/*.test.js`
files are standalone scripts (`node src/intervention.test.js`).

## Honest scope

Not everything is wired. Known gaps are tracked in
[`docs/audits/KASBAH-FULL-AUDIT-2026-10-11.md`](docs/audits/KASBAH-FULL-AUDIT-2026-10-11.md)
(82 findings). `/v1/coverage` publishes the live capability matrix, and the
unified-engine routes return an honest `503 ENGINE_UNAVAILABLE` when the engine
is absent. Competitor coverage lives in [`docs/COMPETITIVE-MAP.md`](docs/COMPETITIVE-MAP.md);
the architecture is in [`docs/PRODUCT.md`](docs/PRODUCT.md).

## Layout

| Path | What |
|---|---|
| `packages/api-server/` | HTTP engine (`server.js`), governance detectors, receipts, audit |
| `packages/desktop/` | Electron app (VPN, browser, vault, seatbelt) |
| `src/` | Core detector, enforcer, sentinel |
| `packages/kasbah-receipts/` | Offline-verifiable signed receipts |
| `bench/` | Detection benchmark + regression scorecard |
| `docs/` | Product, competitive, and audit documents |
