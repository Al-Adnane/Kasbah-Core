# Honest gaps (not shipped / partial)

Updated: 2026-10-01 after seatbelt, proof, parity (BOM, NL policy, coverage),
and the Electron overhaul (digest UI, trust chip, IPC bridge, orphan wiring).

## Shipped this session

- Seatbelt Silent/Warning/Block + hysteresis + dialog budgets + Mute Block
- Authority Verbs exposure + `/v1/intervention/*`
- Portable share (`/v1/receipt/share`, `/verify/:id`, auto-share on hard block)
- AI Trust Grade A–F + protection-score bridge
- `century.html` / `/v1/century` packaging
- Extension: Duck.ai / Brave / Opera + seatbelt labels + share button + popup.html/content.css/icons
- Desktop `handleScan` → `intervention.fromGovern`
- AI-BOM (`/v1/bom`), NL policy (`/v1/policy/nl`), coverage (`/v1/coverage`)
- Saved-you digest (`/v1/intervention/digest`) + desktop Home digest card
- Export footer string for proof bundles
- API/desktop race fixes (reuse full API on :8788)
- **Electron overhaul:** Home seatbelt tier + digest + trust chip; `kasbah.on()` IPC bridge (allow-listed channels); protection:score consumed in renderer
- **Orphan wiring:** spectral-residual + info-flow-complexity into sentinel; advisory-suite mounted at `/v1/advisory/*`; OS↔Frontier integration ready
- **Stub honesty:** sentinel `_LayerStub` reports `{available:false, stub:true}` instead of silent `{}`
- **Repo hygiene:** git re-anchored (fresh history; broken `.git` backed up as `.git-broken-*`); `.env.example` documents signing secrets; `sk_live`-looking test vector rotated to obviously-fake

## Partial (working, not complete product)

| Gap | State | Next |
|-----|-------|------|
| Billing ↔ mute block | `enforcementBudget` honored; auto-budget from usage meter wired for API keys | Stripe credit pack → SHIELD units |
| Red-team *product* | `live-redteam`, zeroday, self-play present | Packaged SaaS red-team UI |
| Air-gapped cert | Local-first gateway | Formal air-gap build + docs |
| Model supply-chain | `vuln-scanner` | Artifact/deserialization CA |
| SIEM connectors | Webhooks | Splunk / CrowdStrike / Datadog apps |
| Multimodal prompt gate | Biometric/stego forensics | Unified image/video prompt scan |
| MCP inventory UI | `multi-mcp-governor`, discovery | Full inventory + block UI |

## Intentional non-goals

| Gap | Why |
|-----|-----|
| Private AI chat (Leo/Duck.ai/Aria clone) | Kasbah guards every host; browsers own assistants |
| SaaS data lineage (Nightfall-class) | Different product; huge data plumbing |
| Workforce coaching UX | Not core seatbelt/proof |
| Gartner / SOC2 / logo wall | GTM process, not a feature PR |

## Competitive ranking (honest)

- Unique: receipts, seatbelt contract, kernel tickets, maqasid, threshold crypto
- Behind: brand, enterprise certs, lineage, coaching, SIEM depth
- See `COMPETITIVE-MAP.md`
