# Kasbah

**The trust + cost runtime for agentic AI.**
Every AI action signed. Every receipt verifiable. Every token tracked.

[https://bekasbah.com](https://bekasbah.com) · [Receipt Spec v2](docs/RECEIPT-SPEC.md)

---

## What this repo actually ships

| Surface | What it does | How to use it |
|---|---|---|
| **`packages/api-server`** | The engine. HTTP API on `:8788`. Receipts, governance, audit, well-known keys, model catalog, LLM proxy. | `node packages/api-server/server.js` |
| **`packages/api-server/src/engine-key.js`** | Ed25519 keypair. Signs every receipt. Public key published at `/.well-known/kasbah-keys.json`. | Auto-loaded; key persists in `data/engine-key.{pub,priv}.pem` |
| **`packages/api-server/src/model-catalog.js`** | **72 LLM models** across **20 providers** (Western + Chinese + open-source) with current 2026 prices. Auto-detects provider from request URL/body. | `GET /v1/models?region=cn` |
| **`packages/api-server/src/llm-proxy.js`** | **18-provider drop-in proxy.** Sit transparently between your SDK and the real upstream — Kasbah signs every call, redacts PII, computes real $ from the catalog. | `OPENAI_BASE_URL=http://localhost:8788/v1/proxy/openai/v1` |
| **`packages/kasbah-mcp`** | MCP server. Two tools: `kasbah_attest` + `kasbah_verify`. Drops into Claude Desktop / Claude Code / Cursor / Cline. | `npx @kasbah/mcp-server` *(npm publish pending)* |
| **`packages/kasbah-sdk`** | TypeScript SDK. `receipt.sign / verify / canonicalJSON / fetchPublicKey`. | `import Kasbah from '@kasbah/sdk'` |
| **`packages/kasbah-cli`** | CLI. `kasbah scan / govern / explain / receipt verify / multiverse / ethics / …`. | `node packages/kasbah-cli/bin/kasbah.js scan "…"` |
| **`packages/desktop`** | Electron cockpit. Linear/Stripe-style monitor. 5 verbs (Govern / Optimize / Scan / Audit / Verify) + Models tab. | `npm --prefix packages/desktop run dev` |
| **`apps/web`** | Next.js landing + `/dashboard` (live audit feed) + `/verify` (standalone WebCrypto verifier). | `npm --prefix apps/web run dev` |
| **`docs/RECEIPT-SPEC.md`** | The receipt format spec. v2 Ed25519 + canonical JSON + 4 reproducible test vectors. | Open-source. Anyone can implement a verifier. |
| **`bench/`** | Reproducible benchmark — 77 adversarial cases, governance precision/recall/F1 against multiple baselines. | `node bench/run.js` |

---

## The 5-minute test

```bash
# 1. Boot the engine
node packages/api-server/server.js
# → http://127.0.0.1:8788 · core mode · Ed25519 kid 029e59…

# 2. Mint and verify a receipt
curl -X POST localhost:8788/v1/sign \
  -H 'content-type: application/json' \
  -d '{"verdict":"ALLOW","risk":0,"subject":"hello"}'
# → kasbah_receipt:v2:ed25519:029e59…

# 3. Run an LLM call through Kasbah (no API key needed — mock mode)
curl -X POST localhost:8788/v1/proxy/deepseek/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"deepseek-r1","messages":[{"role":"user","content":"hello"}]}'
# → response includes x-kasbah-receipt, x-kasbah-cost, x-kasbah-tokens headers

# 4. See aggregated spend per model
curl localhost:8788/v1/track/usage
# → { totalSpent: 0.0001, rows: [{ id: 'deepseek-r1', cost: 0.0001, … }] }

# 5. Browse the model catalog
curl 'localhost:8788/v1/models?region=cn' | jq '.count'
# → 42  (DeepSeek, Qwen, Kimi, GLM, Yi, Ernie, Doubao, Hunyuan, MiniMax, Spark, Step)
```

---

## What Kasbah does that LLM safety filters don't

1. **Cryptographic receipts.** Every governance decision signed Ed25519, verifiable offline, forever — even if Kasbah ceased to exist tomorrow. [Spec](docs/RECEIPT-SPEC.md) is open with reproducible test vectors.
2. **The 42 Chinese models other tools ignore.** DeepSeek-R1 ($0.55/1M vs OpenAI o1 $15/1M), Qwen3-Max, Kimi K2.5, GLM-5, Doubao, Hunyuan, MiniMax, Spark — all auto-detected, priced, tracked. Lakera / Helicone / LangSmith / Portkey don't recognize these.
3. **Drop-in proxy for 18 providers.** Change one environment variable and Kasbah sits between your code and the upstream. PII redacted before egress. Real $ tracked per model. Receipt minted per call.
4. **Pre-execution blocking.** Agents can't run `rm -rf` or exfiltrate `.env` because the proxy denies the request before it hits the upstream.

---

## Honest scope · what's complete vs in-progress

| | Status |
|---|---|
| Receipt spec + reference verifier | ✅ Complete |
| Engine `/v1/govern`, `/v1/sign`, `/v1/verify`, `/v1/keys`, `/.well-known/kasbah-keys.json` | ✅ Complete |
| Model catalog (72 models · 20 providers · 4 regions) | ✅ Complete |
| LLM proxy (18 providers · PII redaction · receipts) | ✅ Complete · JSON only (streaming pending) |
| MCP server with `kasbah_attest` / `kasbah_verify` | ✅ Complete · not yet on npm public |
| TypeScript SDK | ✅ Complete |
| CLI | ✅ Complete |
| Desktop cockpit + Models / Optimize / Verify tabs | ✅ Complete |
| Web landing + `/verify` + `/dashboard` | ✅ Complete |
| Governance pipeline | ⚠ Currently regex-based — multi-detector v2 in progress |
| Streaming proxy (SSE chunked passthrough) | ⏳ Not yet |
| `@kasbah/mcp-server` on npm | ⏳ Not yet |
| Browser extension · Mobile app | ⏳ Beta waitlist |
| SOC 2 Type II · EU AI Act audit | ⏳ In progress |

If a claim is on the website, it's backed by a working endpoint in this repo. We will not claim what doesn't ship.

---

## Brand

Terracotta `#C1440E` on cream `#FEFCFA`. Real shield + keyhole logo from `Kasbah-site/kasbah-guard-dist/apps/vscode/media/icon.svg`. Inter font.

## License

MIT. Receipts your customers verify don't need our permission to be valid.

## Contact

Repo: [github.com/Al-Adnane/Kasbah-Core](https://github.com/Al-Adnane/Kasbah-Core) · Site: [bekasbah.com](https://bekasbah.com)
