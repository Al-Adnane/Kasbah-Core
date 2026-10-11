# Kasbah Competitive Map (2026-10)

Honest map of the AI-security field vs Kasbah. Evidence: `COMPETITIVE-RESEARCH.md`
(browser-primary vendor pages) + codebase inventory in this repo.

## Market structure

**Consolidated:** Protect AI + Portkey → Palo Alto Prisma AIRS · CalypsoAI + Robust → F5 ·
Lakera → Check Point · Prompt Security → SentinelOne · Guardrails AI → Harvey ·
TrojAI → A10 · Gretel → NVIDIA · Helicone → Mintlify · Gradient exited.

**Independent / platform-native:** HiddenLayer, Arthur, Lasso, Pillar, Nightfall,
Prompt Armor, LiteLLM, LangSmith, Braintrust, NeMo, Purview, Holistic AI,
Brave, DuckDuckGo, Opera, model-native safety (OpenAI/Anthropic).

## Categories

| Layer | Players | What they sell |
|-------|---------|----------------|
| A. Enterprise AI security | Prisma, F5, HiddenLayer, Lasso, Pillar, Nightfall, Arthur, Lakera/CP, Purview, Holistic, TrojAI | Firewall / agent / DLP at scale |
| B. Gateways + observability | LiteLLM, LangSmith, Portkey, Braintrust | Route, spend, govern |
| C. Guardrails libs | NeMo, Guardrails→Harvey, model providers | Programmable rails / native safety |
| D. Privacy browsers + private AI | Brave Leo, DuckDuckGo Duck.ai, Opera Aria | Private assistants |
| E. Receipts niche | VeridexCore, IETF attestation drafts | Portable proof primitives |
| **F. Kasbah** | **this repo** | **Proof + Seatbelt + Kernel** (local-first) |

## Capability truth (summary)

| Capability | Field | Kasbah |
|------------|-------|--------|
| Pre-exec prompt block | Common (Lakera, Lasso, F5, …) | **Live** |
| Injection ML | Common | **Live** |
| Secrets / PII DLP | Nightfall, Purview, Lasso | **Live** |
| Agent tickets + kill switch | Rare (identity/audit more common) | **Live** (stronger primitive) |
| Cost governance | Arthur, LiteLLM | **Live** |
| Shadow AI discovery | Common in platforms | **Live** |
| AI-BOM | Lasso | **Live** (`/v1/bom`) |
| NL policy | F5 | **Live** (`/v1/policy/nl`) |
| Red team packaging | Lakera RT, TrojAI, Pillar | **Partial** (runtime/self-play) |
| Air-gap cert | F5, TrojAI, NeMo | **Partial** (local-first) |
| SIEM connectors | Arthur, Lasso | **Partial** (webhooks) |
| SaaS data lineage | Nightfall | **Gap** |
| Workforce coaching | Nightfall | **Gap** |
| Private AI chat host | Brave, DDG, Opera | **Gap (intentional)** |
| **Crypto portable receipts** | Contested since 2026: two IETF individual drafts, `agent-receipts`, Arkforge | **Live** (not unique; see `KASBAH.md` §1) |
| **Seatbelt 3-tier + mute** | Uncontested | **Live (unique)** |
| **Maqasid / multi-ethics** | Uncontested | **Live (unique)** |
| **Threshold crypto / ZK / WGAS** | Uncontested | **Live (unique)** |

## Positioning

```
Firewalls     = detect + policy at scale
Agent platforms = discover + govern agents
DLP           = find sensitive data in motion
Gateways      = route + spend
Browsers      = private assistants
Kasbah        = PROOF + SEATBELT + KERNEL on top of all of them
```

## Do not overclaim

- Not “better Lakera” at population-scale injection benchmarks.
- Not SaaS lineage / Purview-class DLP.
- Not a Brave/DuckDuckGo assistant (guard them instead).
- SOC2 / Gartner / air-gap certs are GTM process, not shipped features.

> **Updated 2026-10-11:** receipts and human approval are no longer uncontested. The
> defensible claim is the combination — Private + Guard + Consent + Proof in one
> local-first app. Positioning now lives in `KASBAH.md`.

## Unique thesis

> Use any AI. Leak nothing. Prove everything.

Only commercial stack in this map shipping **portable cryptographic receipts +
seatbelt intervention contract + single-use agent tickets** together, local-first.

Live matrix: `GET /v1/coverage` · `GET /v1/century` · `GET /v1/bom`.
