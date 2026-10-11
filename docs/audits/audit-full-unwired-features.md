# Kasbah Full Repo Unwired / Not-Working Features Audit
**Date:** 2026-10-01  
**Scope:** Full repo-wide grep-based scan for stubs, 503 not-available, ENGINE_STUB, interface-only stubs, orphan modules, and documented gaps.

## Executive Summary
Core governance pipeline works. Multiple subsystems are stubbed/optional and return 503 “not available”. The Kasbah Unified Engine was removed 2026-07 and all its routes now return ENGINE_STUB. Several modules are instantiated but never used. 8 sentinel layers are dead stubs.

## 1. API Server Stubs & Not-Available Routes
`packages/api-server/server.js`

### 1.1 Unified Engine Removed → ENGINE_STUB
Line 72-108: `kasbah-unified-engine.js` require wrapped in try/catch. On failure:
```js
const _stub503 = () => ({ error: 'unified engine not available in this build', code: 'ENGINE_STUB' });
```
Routes now using stub engine:
- `/v1/analyze` → `kasbahEngine.analyze`
- `/v1/analyze/batch` → `kasbahEngine.analyzeBatch`
- `/v1/workflows/create` → `kasbahEngine.createWorkflow`
- `/v1/workflows/:id/execute` → `kasbahEngine.executeWorkflow`
- `/v1/workflows/:id/status` → `kasbahEngine.getWorkflowStatus`
- `/v1/workflows/:id/audit` → `kasbahEngine.getWorkflowAudit`
- `/v1/workflows/stats` → `kasbahEngine.getWorkflowStats`
- `/v1/governance/evaluate` → `kasbahEngine.evaluateGovernance`
- `/v1/governance/dimensions` → `kasbahEngine.getGovernanceDimensions`
- `/v1/identity/generate` → `kasbahEngine.generateAgentIdentity`
- `/v1/identity/verify` → `kasbahEngine.verifyAgentIdentity`
- `/v1/cost/track` → `kasbahEngine.trackCost`
- ZK grapheme / valid unicode / equivalence routes → `zkProve*` / `zkVerify*` stubs
- BBS / DP / TAVC / Threat / CrossModal helpers → all via `kasbahEngine.*`

Evidence: `kasbahEngine.` usage lines 6717, 6725, 6735, 6744, 6749, 6752, 6755, 6758, 6761, 6764, 6770, 6775, 6780, ...

### 1.2 Governance Proxy not available → 503
Lines 4389, 4398, 4403, 4411, 4418
```js
if (!_govProxy) return res.status(503).json({ error: 'governance proxy not available' });
```
Routes affected: governance proxy endpoints under `/v1/governance/*` when proxy not instantiated.

### 1.3 Kasbah OS bridge not available → 503
Line 4440: `_kosGuard` returns 503 if `!_kasbahOS` with error 'kasbah-os bridge not available'.

### 1.4 Multi-MCP Governor not available → 503
Lines 7532, 7537, 7544, 7551, 7558, 7563, 7570, 7587, 7597, 7601
All `/v1/mcp/*` inventory/block routes return 503 when `multiMcpGovernor` missing.

### 1.5 CodeWhale / Semantic detector not available → 503
Line 7692: `if (!codeWhaleGovernor) return res.status(503).json({ error: 'CodeWhale governor not available' });`
Line 7704: `if (!semanticDetector) return res.status(503).json({ error: 'Semantic detector not available', hint: 'Install: pip install sentence-transformers' });`

### 1.6 Crypto utils missing → 503
Lines 7787, 7799, 7809
Shamir, MMR, VDF modules return 503 if `kasbahProducts.cryptoUtils` missing.

### 1.7 Deploy manager not available → 503
Lines 7821, 7826, 7831, 7837
Deploy routes return 503 if `deployManager` missing.

### 1.8 VPN module not available → 503 / interface-only stub
Lines 8177, 8182, 8189, 8200, 8222, 8236
`if (!_vpn) return res.status(503).json({ error: 'VPN module not available' });`
Lines 8214-8216: when server peer not configured, config endpoint returns interface-only stub without Peer section:
```js
conf = `[Interface]\nPrivateKey = ${profile.privateKey}\nAddress = ${profile.address || '10.77.0.2/24'}\nDNS = 1.1.1.1\n\n# Add [Peer] section with your server's PublicKey and Endpoint\n`;
```
Line 8246: AI lane not available if `!_vpn.startAiLane`.

### 1.9 QuranFrontier routes not available
Line 8262: `console.warn('[server] ⚠️  QuranFrontier routes not available:', e.message);`

## 2. Sentinel Stub Layers
`src/kasbah-sentinel.js`

Instantiated but documented as dead stubs per BENCHMARK-COMPETITIVE.md §3.2:
- EigenEthicsDrift
- ShadowConsensus
- TopoShield
- CausalLoopBreaker
- ZKGovernanceProof
- ReynoldsFlow
- PunctuatedEquilibrium
- HarmonicDissonance

These load as `_LayerStub` and return `{available:false, stub:true}`. They inflate “48 innovations” claim.

Additional orphan instantiations never used in sentinelCheck:
- `this.spectralResidual = new SpectralResidualDetector({});` line 1073
- `this.infoFlow = new InfoFlowComplexity({});` line 1074
Grep shows no further usage of these instances in `sentinelCheck`.

## 3. Orphaned Modules — 0 refs
From BENCHMARK-COMPETITIVE.md §3.1 and grep:
- `src/advisory-analyzers.js` — Orthogonality / CUSUM / DO-BFT analyzers
- `src/advisory-suite.js` — Standalone advisory capability surface
- `src/info-flow-complexity.js` — Permutation entropy / Reynolds / vorticity
- `src/kasbah-os-integration.js` — Local OS ↔ Frontier Shield sync
- `src/spectral-residual.js` — STFT spectral-residual anomaly

## 4. Documented Partial Gaps
`docs/GAPS.md`

Partial:
- Billing ↔ mute block — `enforcementBudget` honored; Stripe credit pack → SHIELD units needed
- Red-team product — `live-redteam`, zeroday, self-play present; needs SaaS UI
- Air-gapped cert — local-first gateway; needs formal air-gap build + docs
- Model supply-chain — `vuln-scanner` present; needs artifact/deserialization CA
- SIEM connectors — webhooks exist; needs Splunk/CrowdStrike/Datadog apps
- Multimodal prompt gate — biometric/stego forensics; needs unified image/video scan
- MCP inventory UI — `multi-mcp-governor` discovery; needs full inventory + block UI

Intentional non-goals:
- Private AI chat clone
- SaaS data lineage Nightfall-class
- Workforce coaching UX
- Gartner/SOC2/logo wall

## 5. Availability-Conditional Returns
`src/` modules return `{available:false}` when history insufficient:
- `src/shadow-consensus.js:109` — insufficient_history
- `src/eigen-ethics-drift.js:30` — insufficient_history
- `src/punctuated-equilibrium.js:30` — insufficient_history
- `src/topo-shield.js:22` — insufficient_agents
- `src/reynolds-flow.js:30` — insufficient_history
- `src/kasbah-os-bridge.js` — `this.available = false` on init error / stop

These are conditional, not permanent stubs, but surface as “not working” until warm-up.

## 6. Repo Hygiene Issues Affecting Functionality
From BENCHMARK-COMPETITIVE.md §3.4
- Git broken: HEAD invalid, refs/.DS_Store
- Secrets env unset: KASBAH_RECEIPT_SECRET / KASBAH_TICKET_SECRET
- Persistence memory-only
- No linter wired
- Test vector `sk_live_...` looks real
- Repo bloat audit-export-*, archive/

## 7. Recommendations
1. Remove or implement all ENGINE_STUB routes; audit the 30+ `kasbahEngine.*` usages.
2. Make governance proxy, kasbah-os bridge, multi-mcp governor, codewhale, semantic detector, crypto utils, deploy manager, VPN first-class dependencies with clear install docs or remove routes.
3. Wire or archive the 5 orphan modules; actually call `spectralResidual` and `infoFlow` in sentinelCheck or remove instantiation.
4. Remove 8 sentinel stub layers from composition or implement them.
5. Complete partial gaps starting with Billing ↔ mute block and Desktop digest UI.
6. Fix git/history and env defaults to avoid silent failures.

---
*Evidence sources: packages/api-server/server.js grep results, src/kasbah-sentinel.js lines 1072-1074, docs/GAPS.md, BENCHMARK-COMPETITIVE.md §3.1-3.4*

## Appendix (merged 2026-10-06 from audit-unwired-features.md)
Short audit merged here; see archive/top-level-cleanup-20261006/ for removed docs. Advisory-suite (`/v1/advisory/*`) and kasbah-os-integration verified wired in packages/api-server/server.js. Remaining: unified-engine ENGINE_STUB 503s by design (engine deleted 2026-07).
