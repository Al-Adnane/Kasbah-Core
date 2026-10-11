# Kasbah docs

All product and competitive docs live here.

| File | Contents |
|------|----------|
| [PRODUCT.md](./PRODUCT.md) | Architecture: Proof · Seatbelt · Kernel, decision path, APIs |
| [COMPETITIVE-MAP.md](./COMPETITIVE-MAP.md) | Honest 2026 competitor map vs Kasbah |
| [COMPETITIVE-RESEARCH.md](./COMPETITIVE-RESEARCH.md) | Vendor-level evidence (primary sources) |
| [GAPS.md](./GAPS.md) | What is shipped / partial / intentional non-goals |

## Quick start

```bash
# from repo root
PORT=8788 node packages/api-server/server.js
open http://127.0.0.1:8788/century
```

## Key APIs

```bash
curl -s localhost:8788/v1/century
curl -s localhost:8788/v1/coverage
curl -s localhost:8788/v1/bom
curl -s localhost:8788/v1/intervention/digest
curl -s localhost:8788/v1/trust-grade
curl -s -X POST localhost:8788/v1/scan -H 'content-type: application/json' \
  -d '{"prompt":"my aws key is AKIA…","surface":"chatgpt.com","share":true}'
```
