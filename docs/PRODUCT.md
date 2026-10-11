# Kasbah Product Architecture (22nd-century control plane)

**Thesis:** Use any AI. Leak nothing. Prove everything.

Three product surfaces, one receipt format:

| Surface | Promise | Core |
|---------|---------|------|
| **Kasbah Proof** | Portable cryptographic evidence of every AI action | Ed25519 + ML-DSA receipts, offline verify, `/verify/:id`, Merkle batch |
| **Kasbah Seatbelt** | Silent Pass · Warning Toast · Hard Block before damage | Local scan, hysteresis, dialog budgets, Mute Block, Authority Verbs |
| **Kasbah Kernel** | Non-bypassable agent execution control | Single-use tool+args tickets, kill switch, cost governor, MCP, eBPF/WASM |

## Decision path (no second brain)

```
detector / governance-engine / agent-guard   ← engines (existing truth)
        │
        ▼
  intervention.fromGovern()                 ← product UX only
  aiTrustGrade.fromProtectionScore()        ← letter grade on desktop score
        │
        ▼
  desktop UI · extension · /v1/scan · receipts/share · digest
```

## Seatbelt tiers

| Intervention | Risk band | UI | Authority verb |
|--------------|-----------|-----|----------------|
| Silent Pass | &lt; 0.30 | none / rare micro-toast | SIMULATE (0) |
| Warning Toast | 0.30–0.70 | toast | (optional REDACT = 5) |
| Hard Block | ≥ 0.70 | modal | SHIELD (1) |
| Mute Block | block w/ budget 0 | modal “would have blocked” | charged 0 |

Hysteresis: enter block at 0.70, exit at 0.55; enter warn at 0.30, exit at 0.22.
Dialog budgets: 1 modal / 30s, 3 toasts / 10min.

## Authority Verbs

`SIMULATE 0 · SHIELD 1 · REDACT 5 · CERTIFY 20 · EXPORT_BUNDLE 5`

Billing (`billing.js` / `usage-meter.js`) remains request-quota + credits.
`enforcementBudget` on scan/govern enables Mute Block when SHIELD units are spent.

## Surfaces covered (browser seatbelt)

ChatGPT, Claude, Gemini, Perplexity, Poe, Grok, Copilot, Bing,
**Duck.ai, DuckDuckGo, Brave, Opera**, Phind, You, Mistral, DeepSeek, Kimi,
Qwen, Meta AI, X, AI Studio.

## Key modules

| Path | Role |
|------|------|
| `packages/api-server/src/intervention.js` | Seatbelt UX + verbs + mute |
| `packages/api-server/src/ai-trust-grade.js` | A–F trust grade (+ protection-score bridge) |
| `packages/api-server/src/ai-bom.js` | AI bill of materials |
| `packages/api-server/src/nl-policy.js` | Natural-language policy drafts |
| `packages/api-server/src/digest.js` | “Kasbah saved you” digest |
| `packages/kasbah-receipts/` | Offline-verifiable receipts |
| `packages/kasbah-vpn/` | WireGuard + PQ PSK + kill-switch + AI split-tunnel |
| `packages/desktop/` | Privacy app (VPN, browser, vault, seatbelt UI) |
| `packages/kasbah-browser-extension/` | AI seatbelt in-browser |

## Product pages

| URL | What |
|-----|------|
| `/century` | Proof · Seatbelt · Kernel shell |
| `/verify` | Public receipt verification |
| `/verify/:id` | Shared proof link |
| `/v1/century` | Control-plane API map |
| `/v1/coverage` | Honest competitor coverage matrix |
| `/v1/bom` | AI-BOM |
| `/v1/policy/nl` | NL policy authoring |
| `/v1/intervention/verbs` | Pricing transparency |
| `/v1/intervention/digest` | Saved-you digest |
| `/v1/trust-grade` | AI Trust Grade |

## Docs in this folder

- `COMPETITIVE-RESEARCH.md` — vendor-level evidence
- `COMPETITIVE-MAP.md` — honest map + truth table
- `PRODUCT.md` — this file
- `GAPS.md` — remaining gaps (honest)
