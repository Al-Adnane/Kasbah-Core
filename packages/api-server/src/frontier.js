'use strict';

/**
 * Kasbah Frontier Intelligence Layer v6.0
 *
 * Security detection and governance for AI agent calls.
 *
 *   ── Core Governance ───────────────────────────────────────────────────────
 *   1.  Governance Passports        — Per-agent identity + behavioral trust score
 *   2.  Prompt DNA                  — Near-duplicate attack detection (same jailbreak, many disguises)
 *   3.  Swarm Detector              — Cross-agent coordinated attack detection
 *   4.  Governance Receipts         — HMAC-signed, offline-verifiable proof of governance
 *   5.  Hash-Chained Audit          — Tamper-evident ledger: any entry modification breaks the chain
 *   6.  One-Time Receipt Tokens     — Replay attack prevention at cryptographic layer
 *   7.  EWMA Adaptive Thresholds    — Per-passport self-calibrating WARN/DENY thresholds
 *   8.  Brittleness Governor        — Error-rate + velocity composite → auto circuit-breaker
 *   9.  Bell's Inequality Detector  — CHSH S-value on semantic dimensions detects AI-generated text
 *   10. Delegation Chain            — HMAC-signed proof: agent A acts on behalf of principal B
 *   11. Predictive Threat Forecast  — Historical pattern → future attack vector prediction
 *   12. System Integrity Index      — Global threat score → auto-tighten all thresholds
 *   13. Token Spend Ledger          — Per-passport budget enforcement
 *
 *   ── Threat Detection ──────────────────────────────────────────────────────
 *   14. Honeytoken Canary System    — Fake API keys as canaries; exfiltration = instant DENY
 *   15. Maqasid Ethics Framework    — 5-pillar ethics scoring (life, intellect, wealth, lineage, faith)
 *   16. Execution Tickets           — Sub-100ms HMAC tickets prevent TOCTOU attacks on every ALLOW
 *   17. Adaptive Policy Pipeline    — 6-stage intent/obfuscation/policy pipeline
 *   18. Multilingual PII Detection  — 100+ languages, Luhn/MOD-97/Verhoeff validation
 *   19. Synthetic Persona Detector  — AI fake identity: linguistic, behavioral, profile signals
 *   20. Steganalysis                — Zero-width chars, Unicode tags, whitespace encoding
 *   21. Memetic Warfare Detection   — Coordinated disinformation, astroturfing, polarisation
 *   22. Adversarial Multi-Decode    — 5-pass decode: Base64→Hex→ROT13→URL→Unicode
 *   23. RAG Security                — Prompt injection in retrieved context, access control
 *   24. Image Analysis              — Statistical analysis: GAN frequency, texture, edge, entropy
 *   25. Voice Cloning Detection     — TTS artifacts, 20+ service fingerprints
 *   26. Post-Quantum Vulnerability  — Scans for RSA/ECC usage; includes signature simulation
 *   27. Secret Scanner              — 57 credential patterns (AWS, GitHub, Stripe, etc.)
 *   28. Intent Classifier           — 7-trajectory intent analysis
 *   29. Policy Evaluator            — HIPAA/GDPR/SOC2/PCI rule evaluation (20 rules)
 *   30. Manipulation Detector       — 13 psychological manipulation patterns (DARVO, gaslighting, etc.)
 *   31. AI Writing Detector         — Entropy, TTR, connector density, sentence variance
 *   32. Sentinel Intelligence       — 17-model AI fingerprint DB, deontic ethics (Kant/Util/Virtue)
 *   33. Core Detection Engine       — 12-layer pattern engine with ZK proof and hash-chain
 *
 *   ── Runtime Extensions ────────────────────────────────────────────────────
 *   WASM:    Portable sandboxed pattern detection (active)
 *   eBPF:    Syscall containment (Linux 5.7+ only)
 *   Enclave: Hardware key storage (requires code-signing entitlement)
 *
 *   ── Utility Modules (available via API, not in hot path) ─────────────────
 *   - Shamir secret sharing (GF-256, Lagrange interpolation)
 *   - VDF proof (sequential SHA-256 chain)
 *   - Merkle Mountain Range ledger
 *   - Aho-Corasick multi-pattern matcher
 *   - Perceptual hash similarity
 */

const crypto      = require('crypto');
const path        = require('path');
const fs          = require('fs');
let   _persistence = null;
try { _persistence = require('./persistence'); } catch (_) {}

// Passport persistence helpers (fire-and-forget, non-blocking)
const PASSPORT_HASH = 'kasbah:passports';
function _ppSave(record) {
  if (!_persistence) return;
  // Strip reqWindow array to keep storage lean; rebuild from scratch on load
  const { reqWindow: _rw, ...slim } = record;
  _persistence.hset(PASSPORT_HASH, record.passportId, slim).catch(() => {});
}
async function _ppLoadAll() {
  if (!_persistence) return;
  try {
    const all = await _persistence.hgetall(PASSPORT_HASH);
    if (!all) return;
    for (const [pid, raw] of Object.entries(all)) {
      const rec = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (rec && !_passports.has(pid)) {
        rec.reqWindow = [];  // rebuild empty; it's only for last-60s rate calc
        _passports.set(pid, rec);
      }
    }
    if (_passports.size) console.log(`[passports] restored ${_passports.size} from persistence`);
  } catch {}
}
// Load persisted passports after event loop is ready
setTimeout(_ppLoadAll, 500).unref();

// ── v8.0 Governance Engine & Policy Engine Loaders ───────────────────────────
// Load src/governance-engine.js and src/kasbah-policy-engine.js gracefully.
// Both live at the repo root, not inside packages/api-server — use __dirname
// to navigate up two levels (packages/api-server/src → repo root).
let _governanceEngine = null;
let _policyEngineInst = null;
let _nomosConsensus = null;
let _MaqasidFrameworkClass = null;
let _brittlenessFull = null; // declared here so IIFE can set it
(() => {
  try {
    const { GovernanceEngine } = require(path.resolve(__dirname, '../../../src/governance-engine.js'));
    // governance-engine needs a policy file; default to the root-level policy.
    // If file is missing the constructor throws — we catch and degrade gracefully.
    const policyPath = path.resolve(__dirname, '../../../.kasbahpolicy.json');
    _governanceEngine = new GovernanceEngine(policyPath);
  } catch (_) { /* graceful degradation */ }

  try {
    const { KasbahPolicyEngine } = require(path.resolve(__dirname, '../../../src/kasbah-policy-engine.js'));
    _policyEngineInst = new KasbahPolicyEngine({ packs: ['HIPAA', 'GDPR', 'SOC2', 'PCI_DSS'] });
  } catch (_) { /* graceful degradation */ }

  try {
    const { ConsensusEngine: NomosConsensusEngine } = require(path.resolve(__dirname, '../../../packages/nomos-engine/src/consensus-engine.js'));
    _nomosConsensus = NomosConsensusEngine; // store the class (createDefault is static)
  } catch (_) { /* graceful degradation — NOMOS not yet ported */ }

  try {
    const { MaqasidFramework } = require(path.resolve(__dirname, '../../../packages/agent-governance/src/maqasid-framework.js'));
    _MaqasidFrameworkClass = MaqasidFramework;
  } catch (_) { /* graceful degradation — maqasid framework not available */ }

  try {
    const { getGovernor } = require(path.resolve(__dirname, '../../../packages/agent-cost-watch/src/brittleness-governor.js'));
    // Instantiate immediately for _brittlenessFull below
    _brittlenessFull = getGovernor();
  } catch (_) { /* graceful degradation — brittleness governor not available */ }
})();

/**
 * governanceEngineCheck(text) — wraps the phase-1 GovernanceEngine.
 * Returns { status, violations, riskScore } or null when unavailable.
 * Designed to run on plain text — synthesises a minimal action object.
 */
async function governanceEngineCheck(text) {
  if (!_governanceEngine) return null;
  try {
    // Use READ verb (not in forbidden_verbs) and a pre-approved internal domain so
    // the domain whitelist never fires on routine text scans.  The GovernanceEngine
    // is used here purely for verb-level and rate-limit policy checks — not as a
    // domain firewall (that's handled by the main policy pipeline).
    const action = {
      agent:    'kasbah-scanner',
      verb:     'READ',
      target:   'api.internal.kasbah.com/content',
      content:  text,
      trace_id: null,
    };
    const result = await _governanceEngine.check(action);
    return {
      status:     result.status,          // 'ALLOW' | 'DENY'
      violations: result.violations || [],
      riskScore:  result.risk_score || 0,
      latencyMs:  result.latency_ms || 0,
    };
  } catch (_) { return null; }
}

/**
 * policyEngineCheck(text, context) — wraps the KasbahPolicyEngine.
 * Evaluates text against all 4 compliance packs (HIPAA/GDPR/SOC2/PCI-DSS).
 * Returns { decision, violations, warnings, packsActive } or null.
 */
function policyEngineCheck(text, context = {}) {
  if (!_policyEngineInst) return null;
  try {
    const action = {
      agent:   context.agent || 'kasbah-scanner',
      verb:    context.verb  || 'ANALYZE',
      target:  context.target || 'content',
      content: text,
      rateContext: context.rateContext || null,
    };
    const result = _policyEngineInst.evaluate(action);
    return {
      decision:    result.decision,        // 'ALLOW' | 'DENY' | 'WARN' | 'REQUIRE_APPROVAL'
      violations:  result.violations || [],
      warnings:    result.warnings   || [],
      approvals:   result.approvals  || [],
      packsActive: result.packsActive || [],
    };
  } catch (_) { return null; }
}

// ── v5.0 Deep Intelligence Systems (#18–#27) ─────────────────────────────────
// Each is a standalone module — independently testable, zero cross-deps.
const _sys = (() => {
  const load = (name) => { try { return require(`./systems/${name}`); } catch (_) { return null; } };
  return {
    pii:       load('multilingual-pii'),
    persona:   load('synthetic-persona'),
    steg:      load('steganalysis'),
    memetic:   load('memetic-warfare'),
    adecode:   load('adversarial-decode'),
    rag:       load('rag-security'),
    imgFake:   load('image-deepfake'),
    voice:     load('voice-cloning'),
    quantum:   load('quantum-crypto'),
    dna:       load('dna-ledger'),
    holo:      load('holographic-ledger'),
    neuro:     load('neuromorphic-snn'),
    orbital:   load('orbital-security'),
    // ── v6.0 Maximum Intelligence (#28–#37) ──────────────────────────────────
    sentinel:  load('sentinel-intelligence'),
    reynolds:  load('reynolds-flow'),
    harmonic:  load('harmonic-dissonance'),
    topo:      load('topo-shield'),
    eigen:     load('eigen-ethics-drift'),
    causal:    load('causal-loop-breaker'),
    shadow:    load('shadow-consensus'),
    zk:        load('zk-governance-proof'),
    puncteq:   load('punctuated-equilibrium'),
    detAdv:    load('detector-advanced'),
    cryptoAdv: load('crypto-advanced'),
    intent:    load('intent-policy'),
    textxray:  load('textxray'),
    detCore:   load('detector-core'),
    algorithms:load('kasbah-algorithms'),
    // ── v7.0 Innovation Layer ─────────────────────────────────────────────────
    injAdv:      load('prompt-injection-advanced'),  // 15-pattern injection defense
    causalXai:   load('causal-xai'),                 // causal counterfactual XAI
    multiEthics: load('multi-ethics-consensus'),     // Maqasid+Kant+Util+Virtue voting
    bellsEnh:    load('bells-enhanced'),             // 8-dimension CHSH ensemble
    // ── P1 — Obfuscation Decoder + Expanded Secrets ──────────────────────────
    obfusDec:    load('obfuscation-decoder'),
    // ── Nexus Bridge — unified 4-technology engine from kasbah-nexus ─────────
    nexus:       load('nexus-bridge'),               // RTP + Kernel Gating + Bell's + MainDetector
    // ── v8.0 ARCHIVE Full-Fidelity Engines ───────────────────────────────────
    rtpFull:     load('rtp-transform-full'),         // Patent-pending 6-stage pipeline (ARCHIVE→JS)
    bellsFull:   load('bells-inequality-full'),      // Quantum CHSH detector (NeurIPS 2026 target)
    proofChain:  load('proof-chain'),                // Blockchain-style PoW receipt ledger
    auditLedger: load('compliance-audit-ledger'),    // Merkle-proof compliance audit ledger
    // ── Phase 3: Full Maqasid, Brittleness Governor, NOMOS ──────────────────
    maqasidFull: load('maqasid-framework'),          // 5-pillar, multi-language, FOL, geometric mean
    brittlenessFull: load('brittleness-governor'),   // 5 frequency bands, EMA trends, predictive throttling
  };
})();

// Behavioral classifier instance. Guard on the constructor itself (not just
// the module) so a partial/failed optional-module load degrades to null
// instead of throwing and taking down the whole server — matching every other
// instance check below.
const _snn = _sys.neuro && typeof _sys.neuro.SNN === 'function' ? new _sys.neuro.SNN() : null;

const _zk       = _sys.zk && _sys.zk.ZKGovernanceProof
  ? new _sys.zk.ZKGovernanceProof() : null;

// Shadow consensus instance — Byzantine fault-tolerant perturbed observer
const _shadowInst = _sys.shadow && _sys.shadow.ShadowConsensus
  ? new _sys.shadow.ShadowConsensus() : null;

// v8.0 Full-fidelity engine instances (ARCHIVE→JS)
const _rtpEngine   = _sys.rtpFull   && _sys.rtpFull.RTPTransformEngine
  ? new _sys.rtpFull.RTPTransformEngine()   : null;
const _bellsFull   = _sys.bellsFull && _sys.bellsFull.BellsInequalityDetector
  ? new _sys.bellsFull.BellsInequalityDetector() : null;
const _proofLedger = _sys.proofChain && _sys.proofChain.ProofLedger
  ? new _sys.proofChain.ProofLedger() : null;
const _auditLedger = _sys.auditLedger && _sys.auditLedger.ComplianceAuditLedger
  ? new _sys.auditLedger.ComplianceAuditLedger() : null;

// Phase 6: Witt-Crystalline Cohomology
const _wittCrys = _sys.wittCrys && _sys.wittCrys.WittCrystallineCohomology
  ? new _sys.wittCrys.WittCrystallineCohomology({ p: 7, maxDimension: 6 }) : null;

// Phase 3: Full-fidelity Maqasid Framework (instantiated if not loaded by IIFE)
const _maqasidFullInst = _sys.maqasidFull && _sys.maqasidFull.MaqasidFramework
  ? new _sys.maqasidFull.MaqasidFramework()
  : _MaqasidFrameworkClass ? new _MaqasidFrameworkClass() : null;
// _brittlenessFull already set by IIFE above; fall back to _sys loader if not
if (!_brittlenessFull && _sys.brittlenessFull && _sys.brittlenessFull.getGovernor) {
  _brittlenessFull = _sys.brittlenessFull.getGovernor();
}

// Phase 3: NOMOS Consensus Engine (loaded from separate package)
let _nomosDefault = null;
function _getNomosEngine() {
  if (!_nomosDefault && _nomosConsensus) {
    try {
      _nomosDefault = _nomosConsensus.createDefault(); // static method on class
    } catch (_) { /* degradation */ }
  }
  return _nomosDefault;
}

// Convenience wrappers — all return null when module unavailable (graceful degradation)
const piiCheck        = (t)    => _sys.pii     ? _sys.pii.multilingualPiiCheck(t)         : null;
const personaCheck    = (p)    => _sys.persona  ? _sys.persona.syntheticPersonaCheck(p)    : null;
const stegCheck       = (t)    => _sys.steg     ? _sys.steg.steganalysisCheck(t)           : null;
const memeticCheck    = (t)    => _sys.memetic  ? _sys.memetic.memeticWarfareCheck(t)      : null;
const advDecode       = (t)    => _sys.adecode  ? _sys.adecode.adversarialDecode(t)        : null;
const ragCheck        = (c, q) => _sys.rag      ? _sys.rag.ragSecurityCheck(c, q)          : null;
const imgFakeCheck    = (t)    => _sys.imgFake  ? _sys.imgFake.imageFakeCheck(t)           : null;
const voiceCheck      = (t)    => _sys.voice    ? _sys.voice.voiceCloningCheck(t)          : null;
const quantumVulnScan = (t)    => _sys.quantum  ? _sys.quantum.quantumVulnCheck(t)         : null;
const dnaEncode       = (d)    => _sys.dna      ? _sys.dna.encodeRecord(d)                 : null;
const dnaDecode       = (s)    => _sys.dna      ? _sys.dna.decodeRecord(s)                 : null;
const dnaStegCheck    = (t)    => _sys.dna      ? _sys.dna.detectSteganography(t)          : null;
const holoEncode      = (d)    => _sys.holo     ? _sys.holo.encodeToVoxels(d)              : null;
const holoDecode      = (v)    => _sys.holo     ? _sys.holo.decodeFromVoxels(v)            : null;
const neuroClassify   = (t)    => _snn          ? _snn.classify(t)                         : null;
const orbitalShard    = (k,n,t)=> _sys.orbital  ? _sys.orbital.shardKey(k, n, t)           : null;
const orbitalRecon    = (s,p)  => _sys.orbital  ? _sys.orbital.reconstructKey(s, p)        : null;

// ── v6.0 Maximum Intelligence Wrappers (#28–#37) ─────────────────────────────

// #28 Sentinel Intelligence — CAIL, AI fingerprint, Byzantine BFT, 48 moats
const sentinelCheck   = (t)        => _sys.sentinel  ? _sys.sentinel.sentinelCheck(t)              : null;
const swarmCollusion  = (msgs)     => _sys.sentinel  ? _sys.sentinel.swarmCheck(msgs)              : null;
const temporalParadox = (t)        => _sys.sentinel  ? _sys.sentinel.temporalCheck(t)             : null;
const deonticCheck    = (t)        => _sys.sentinel  ? _sys.sentinel.deonticCheck(t)              : null;

// Scientific Flow Analysis
const reynoldsFlow    = (t)        => _sys.reynolds ? _sys.reynolds.semanticVelocity(t) : null;
const harmonicDis     = (t)        => _sys.harmonic ? _sys.harmonic.dft(t) : null;
const topoShield      = (t)        => _sys.topo     ? _sys.topo.bettiNumbers(t) : null;

// Ethics / Shadow Consensus
const eigenEthics     = (t)        => _sys.eigen    ? _sys.eigen.analyze(t) : null;
const causalBreak     = (t)        => _sys.causal   ? _sys.causal.analyze(t) : null;
const shadowConsensus = (t)        => _sys.shadow   ? (_sys.shadow.evaluate ? _sys.shadow.evaluate(t) : _sys.shadow.analyze(t)) : null;

// ZK Governance
const zkGovProof      = (p)        => _zk             ? (_zk.prove ? _zk.prove(p) : _zk.generateProof ? _zk.generateProof(p) : null) : null;
const punctEqCheck    = (t)        => _sys.puncteq   ? _sys.puncteq.analyze(t) : null;

// ZK Governance — production-ready proof generation / verification
function zkProve(verdict, score, threats) {
  if (!_zk) return null;
  try {
    const rules      = threats && threats.length > 0 ? threats : ['default_policy'];
    const riskScore  = score || 0;

    // Private witness (never revealed to verifier)
    const privateInput = {
      score:        Math.round(riskScore * 1000),
      riskScore,                  // used by circuit rule R1 / D1
      verdict,
      piiCount:     0,
      requestCount: 0,
      ts:           Date.now(),
    };
    const publicInput = { verdict, ruleCount: rules.length };

    let proof;
    if (verdict === 'DENY') {
      // DENY circuit: proves the governance CORRECTLY identified dangerous content.
      // Rules attest: "risk was non-negative, verdict is DENY, risk is within valid
      // range [0,1]" — without revealing the exact risk score to the verifier.
      // The default ALLOW circuit checks (risk < 0.7) which is false for high-risk
      // DENY calls, so we use a dedicated DENY circuit here.
      const savedCircuit = _zk.circuit;
      _zk.createCircuit([
        { id: 'D1', name: 'risk_is_non_negative',
          evaluate: (w)      => (w.riskScore || 0) >= 0 },
        { id: 'D2', name: 'verdict_is_deny',
          evaluate: (w)      => w.verdict === 'DENY' },
        { id: 'D3', name: 'risk_in_valid_range',
          evaluate: (w)      => (w.riskScore || 0) <= 1.0 },
        { id: 'D4', name: 'within_rate_limit',
          evaluate: (w, pub) => (w.requestCount || 0) < (pub.rateLimit || 100) },
        { id: 'D5', name: 'no_domain_constraint_bypass',
          evaluate: (w, pub) => (pub.allowedDomains || []).length === 0
            || (pub.allowedDomains || []).includes(w.targetDomain || '') },
      ]);
      proof = _zk.generateProof(privateInput, publicInput);
      _zk.circuit = savedCircuit;   // restore previous circuit (non-async, safe)
    } else {
      // ALLOW / WARN circuit: default — proves risk was below safe threshold
      _zk.createDefaultCircuit();
      proof = _zk.generateProof(privateInput, publicInput);
    }

    if (!proof) return null;
    return { ...proof, valid: true };   // generateProof returns null if circuit fails
  } catch (e) { return null; }
}
function zkVerify(proof, publicInput) {
  if (!_zk) return { valid: false };
  try { return _zk.verifyProof(proof, publicInput); } catch { return { valid: false }; }
}
function zkStats() {
  if (!_zk) return null;
  return _zk.getStats();
}

// Shadow Consensus — lightweight synchronous check (uses simple evaluator, no primary needed)
async function shadowCheck(text) {
  if (!_shadowInst) return null;
  try {
    const state = { content: text, timestamp: Date.now() };
    // Simple risk estimator for shadow evaluators
    const evaluateFn = (s) => {
      const t = s.content || '';
      const riskKeywords = ['ignore', 'bypass', 'override', 'rm -rf', 'drop table', 'exec(', 'eval('];
      const hits = riskKeywords.filter(k => t.toLowerCase().includes(k)).length;
      const risk = Math.min(1.0, hits * 0.2);
      return Promise.resolve({ verdict: risk >= 0.4 ? 'DENY' : 'ALLOW', risk });
    };
    const primary = await evaluateFn(state);
    const result = await _shadowInst.evaluate(state, primary, evaluateFn);
    return {
      verdict:      result.finalVerdict,
      consensus:    result.consensusVerdict,
      confidence:   result.votes ? (Math.max(result.votes.allow, result.votes.deny) / Math.max(result.votes.total, 1)) : 0,
      disagreement: result.primaryDisagrees,
      gaming:       result.gamingDetected,
      gamingStrategy: result.gamingStrategy,
    };
  } catch (e) { return null; }
}

// ── v7.0 Innovation Layer Wrappers ────────────────────────────────────────────
const injAdvCheck      = (t)       => _sys.injAdv      ? _sys.injAdv.analyze(t)           : null;
const causalXaiExplain = (r)       => _sys.causalXai   ? _sys.causalXai.explainVerdict(r)  : null;
const multiEthicsCheck = (t)       => _sys.multiEthics ? _sys.multiEthics.analyzeEthics(t) : null;
const bellsEnhCheck    = (t)       => _sys.bellsEnh    ? _sys.bellsEnh.analyze(t)          : null;
const obfusDecodeCheck    = (t) => _sys.obfusDec ? _sys.obfusDec.deepDecode(t)            : null;

// ── Phase 3: Full-Fidelity Archive Wrappers ───────────────────────────────────

/**
 * maqasidCheckFull — Full 5-pillar Maqasid with geometric mean, multi-language patterns, FOL.
 * Returns { compliance, pillars, concerns, verdict } for backward compat with server.js hot path.
 * Also includes extended fields: { grade, deonticRuling, languagesDetected, inferenceTrace, compositeScore }.
 */
function maqasidCheckFull(text, context) {
  if (!_maqasidFullInst) {
    // Fall back to basic maqasidCheck if full framework not loaded
    return maqasidCheck(text);
  }
  try {
    const cert = _maqasidFullInst.evaluate(text, context);
    // Map certificate to the shape expected by server.js
    const pillars = {};
    const concerns = [];
    for (const a of cert.pillarAssessments) {
      // Short pillar names matching existing MAQASID_WEIGHTS keys
      const shortName = a.pillar.replace('hifz_al_', '');
      pillars[shortName] = +a.score.toFixed(3);
      if (a.violations.length > 0) concerns.push(...a.violations);
    }
    // Map grade to verdict
    let verdict;
    if (cert.grade === 'COMPLIANT') verdict = 'approved';
    else if (cert.grade === 'CONDITIONAL') verdict = 'flagged';
    else verdict = 'blocked';
    // Deontic override: HARAM → blocked
    if (cert.deonticRuling === 'haram') verdict = 'blocked';

    return {
      compliance:       cert.compositeScore,
      pillars,
      concerns,
      verdict,
      // Extended fields for new consumers
      grade:            cert.grade,
      deonticRuling:    cert.deonticRuling,
      languagesDetected: cert.languagesDetected,
      inferenceTrace:   cert.inferenceTrace,
      compositeScore:   cert.compositeScore,
      payloadHash:      cert.payloadHash,
    };
  } catch (_) { return maqasidCheck(text); }
}

/**
 * nomosCheck — Multi-tradition ethical consensus across Islamic, Kantian,
 * Utilitarian, and Virtue traditions. Returns verdict + conflict analysis.
 * Verdict: APPROVED / CONTESTED / REJECTED
 */
function nomosCheck(text, context) {
  const engine = _getNomosEngine();
  if (!engine) return null;
  try {
    const action = {
      subject: typeof text === 'string' ? text.slice(0, 200) : 'governance-action',
      content: text,
      type: 'text-analysis',
    };
    return engine.evaluate(action, context || {});
  } catch (_) { return null; }
}

/**
 * brittlenessReport — Full multi-resource brittleness assessment.
 * Returns { overallBrittleness, recommendedAction, resourceScores, trendDirection, cadenceMultiplier }.
 */
function brittlenessReport() {
  if (!_brittlenessFull) return null;
  try {
    return _brittlenessFull.analyze();
  } catch (_) { return null; }
}
const expandedSecretCheck = (t) => _sys.obfusDec ? _sys.obfusDec.expandedSecretScan(t)    : null;
const normalizeText       = (t) => _sys.obfusDec ? _sys.obfusDec.normalizeForDetection(t) : t;

// #32 Advanced Secret Detection — 57 patterns, DetectGPT, Aho-Corasick, pHash
const secretScan      = (t)        => _sys.detAdv    ? _sys.detAdv.secretScan(t)                   : null;
const detectGPT       = (t)        => _sys.detAdv    ? _sys.detAdv.detectGPT(t)                    : null;
const ahoMatch        = (t, p)     => _sys.detAdv    ? _sys.detAdv.ahoCorasick(t, p)               : null;
const pHashSimilarity = (h1, h2)   => _sys.detAdv    ? _sys.detAdv.pHashSimilarity(h1, h2)         : null;

// #33 Verifiable Cryptography — VDF proof, Merkle Mountain Range
const vdfCompute      = (i, d)     => _sys.cryptoAdv ? _sys.cryptoAdv.vdfCompute(i, d)             : null;
const vdfVerify       = (i, p, d)  => _sys.cryptoAdv ? _sys.cryptoAdv.vdfVerify(i, p, d)           : null;
const mmrAppend       = (tree, l)  => _sys.cryptoAdv ? _sys.cryptoAdv.mmrAppend(tree, l)           : null;
const mmrProve        = (tree, i)  => _sys.cryptoAdv ? _sys.cryptoAdv.mmrProve(tree, i)            : null;
const mmrVerify       = (r, l, p)  => _sys.cryptoAdv ? _sys.cryptoAdv.mmrVerify(r, l, p)           : null;

// #34 Kasbah Secret Sharing — GF(256) Shamir with Fermat inverse (distinct from orbital)
const kShamirSplit    = (s, n, k)  => _sys.cryptoAdv ? _sys.cryptoAdv.shamirSplit(s, n, k)         : null;
const kShamirCombine  = (shares)   => _sys.cryptoAdv ? _sys.cryptoAdv.shamirCombine(shares)        : null;

// #35 Intent & Policy Engine — 7-trajectory intent, 20-rule compliance, quorum governance
const intentAnalyze   = (t)        => _sys.intent    ? _sys.intent.intentAnalyze(t)                : null;
const policyEval      = (a, c)     => _sys.intent    ? _sys.intent.policyEval(a, c)                : null;
const govCheck        = (p)        => _sys.intent    ? _sys.intent.governanceCheck(p)              : null;

// #36 TextXRay — AI writing detection + 13-pattern manipulation detector
const textXrayAI      = (t)        => _sys.textxray  ? _sys.textxray.textXrayAI(t)                 : null;
const textXrayManip   = (t)        => _sys.textxray  ? _sys.textxray.textXrayManipulation(t)       : null;

// #37 Core Detection Engine — 12-layer v3.5 engine + Kasbah Algorithm Suite
const detectCore      = (t)        => _sys.detCore   ? _sys.detCore.detectCore(t)                  : null;
const kasbahAlgorithm = (t, algo)  => {
  if (!_sys.algorithms) return null;
  const suite = _sys.algorithms.KasbahAlgorithmSuite;
  if (suite) {
    const s = new suite(); return s.run ? s.run(t, algo) : s.analyze ? s.analyze(t) : null;
  }
  const fn = _sys.algorithms[algo] || _sys.algorithms.SPIRAL;
  if (!fn) return null;
  const inst = new fn(); return inst.run ? inst.run(t) : inst.analyze ? inst.analyze(t) : null;
};

// Hardware Enclave ────────────────────────────────────────────────────────────
let _hwEnclave = null;
try {
  _hwEnclave = require('../../hardware-enclave/index.js');
  if (_hwEnclave.isAvailable()) {
    console.log(`  ✓ Hardware Enclave loaded (${_hwEnclave.getHardware()})`);
  }
} catch (_) { /* graceful degradation — software HMAC fallback */ }

// ── eBPF Syscall Filter ───────────────────────────────────────────────────────
let _kernelFilter = null;
(async () => {
  try {
    _kernelFilter = require('../../kernel-ebpf/index.js');
    await _kernelFilter.init();
  } catch (_) { /* graceful degradation — not available on macOS/Windows */ }
})();

/**
 * Isolate a process PID at the kernel level.
 * On Linux 5.7+: eBPF syscall filter is applied.
 * On other platforms: no-op.
 */
function kernelIsolatePid(pid) {
  if (_kernelFilter && _kernelFilter.isAvailable()) {
    return _kernelFilter.isolatePid(pid);
  }
  return Promise.resolve(false);
}

// ── WASM Runtime ──────────────────────────────────────────────────────────────
let _wasmKernel = null;
(async () => {
  try {
    _wasmKernel = require('../../wasm-kernel/index.js');
    await _wasmKernel.init();
    if (_wasmKernel.isAvailable()) console.log('  ✓ WASM runtime loaded');
  } catch (_) { /* graceful degradation — frontier.js runs without WASM */ }
})();

function wasmDetect(text) {
  if (!_wasmKernel || !_wasmKernel.isAvailable()) return null;
  return _wasmKernel.detect(text);
}

// ─── CONFIG ──────────────────────────────────────────────────────────────────

const RECEIPT_SECRET   = process.env.KASBAH_RECEIPT_SECRET || (() => {
  if (process.env.NODE_ENV === 'production') throw new Error('KASBAH_RECEIPT_SECRET env var required in production');
  console.warn('[kasbah] KASBAH_RECEIPT_SECRET not set — using ephemeral dev key (not for production)');
  return require('crypto').randomBytes(32).toString('hex');
})();
const SWARM_WINDOW_MS  = 60_000;   // 60s attack-coordination window
const SWARM_DENY_LIMIT = 5;        // 5+ DENYs from same IP in window = swarm
const DNA_WINDOW       = 1000;     // rolling window of last 1000 prompt hashes globally
const DNA_SIM_THRESH   = 0.75;     // Jaccard similarity above this = near-duplicate

// EWMA config
const EWMA_ALPHA       = 0.10;     // Slow adaptation: baseline adjusts over ~10 samples
const EWMA_WARN_SIGMA  = 2.0;      // Warn if risk > baseline + 2σ
const EWMA_DENY_SIGMA  = 3.0;      // Deny if risk > baseline + 3σ

// Brittleness thresholds
const BRITTLE_WARN     = 65;       // 65+ → THROTTLE recommendation
const BRITTLE_DENY     = 85;       // 85+ → auto circuit-breaker (suspend passport)

// Bell's Inequality threshold
const BELLS_THRESHOLD  = 2.0;      // Classical bound; S > 2.0 = non-local correlations = AI text

// ══════════════════════════════════════════════════════════════════════════════
// PASSPORT SYSTEM
// Each AI agent gets a cryptographic identity (Ed25519 keypair).
// Trust score (0.0–1.0) evolves based on behavioral history.
// ══════════════════════════════════════════════════════════════════════════════

const _passports      = new Map(); // passportId → PassportRecord
const _spentReceipts  = new Set(); // consumed HMAC tokens — blocks replay attacks

/**
 * Issue a new Governance Passport for an agent.
 * Returns { passportId, publicKey, privateKey, agentId, issuedAt }
 */
function passportIssue(agentId, capabilities = []) {
  // Ed25519 keypair — native Node.js crypto, no external deps
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const passportId = 'kp_' + crypto.randomBytes(12).toString('hex');
  const issuedAt   = Date.now();

  const newPassport = {
    passportId,
    agentId:      agentId || 'anonymous',
    publicKey,
    capabilities: capabilities || [],
    trustScore:   0.5,   // neutral start
    issuedAt,
    lastSeen:     issuedAt,
    totalRequests: 0,
    denied:        0,
    warned:        0,
    allowed:       0,
    status:       'active',
    probeCount:    0,     // repeated similar prompts = probe attempt
    // ── v2.0: EWMA adaptive thresholds ──────────────────────────────────────
    ewmaRisk:       0.0,  // rolling baseline risk (α=0.10)
    ewmaVariance:   0.01, // rolling variance for σ computation
    adaptiveWarn:   0.50, // self-calibrating WARN threshold
    adaptiveDeny:   0.80, // self-calibrating DENY threshold
    // ── v2.0: Brittleness governor ──────────────────────────────────────────
    brittleness:    0,    // 0–100 composite score; ≥85 = circuit-breaker trip
    errorCount:     0,    // requests that returned non-clean reasons
    reqWindow:      [],   // timestamps of last 60 requests (rate calc)
    // ── v2.0: cross-agent trust propagation ─────────────────────────────────
    parentPassportId: null,  // set at spawn time; inherits parent trust ×0.8
  };
  _passports.set(passportId, newPassport);
  _ppSave(newPassport);

  return { passportId, publicKey, privateKey, agentId, issuedAt };
}

/**
 * Get a passport record (without private key — never stored).
 */
function passportGet(passportId) {
  return _passports.get(passportId) || null;
}

/**
 * Revoke a passport.
 */
function passportRevoke(passportId) {
  const p = _passports.get(passportId);
  if (!p) return false;
  p.status = 'revoked';
  _ppSave(p);
  return true;
}

/**
 * Update trust score, EWMA thresholds, and brittleness after a governance decision.
 * Trust increases with clean requests, decays with DENY/WARN.
 * EWMA adapts per-passport WARN/DENY thresholds based on observed risk distribution.
 * Brittleness tracks error rate + request velocity → circuit-breaker at ≥85.
 */
function passportUpdateTrust(passportId, verdict, risk = 0) {
  const p = _passports.get(passportId);
  if (!p || p.status === 'revoked') return;

  const now = Date.now();
  p.lastSeen = now;
  p.totalRequests++;

  // ── Trust: Bayesian momentum update ─────────────────────────────────────
  const momentum = 0.95;
  if      (verdict === 'DENY')  { p.denied++;  p.trustScore = p.trustScore * momentum + 0.0 * (1 - momentum); }
  else if (verdict === 'WARN')  { p.warned++;  p.trustScore = p.trustScore * momentum + 0.3 * (1 - momentum); }
  else                          { p.allowed++; p.trustScore = p.trustScore * momentum + 1.0 * (1 - momentum); }
  p.trustScore = Math.max(0.0, Math.min(1.0, p.trustScore));

  // Auto-revoke: sustained hostility
  if (p.totalRequests >= 10 && p.trustScore < 0.10) {
    p.status = 'auto-revoked';
  }

  // ── EWMA: per-passport adaptive thresholds ───────────────────────────────
  // α=0.10 → slow drift; baseline shifts over ~10 samples
  const r = Math.max(0, Math.min(1, risk));
  const prevEwma = p.ewmaRisk;
  p.ewmaRisk     = EWMA_ALPHA * r + (1 - EWMA_ALPHA) * prevEwma;
  p.ewmaVariance = EWMA_ALPHA * Math.pow(r - p.ewmaRisk, 2) + (1 - EWMA_ALPHA) * p.ewmaVariance;
  const sigma    = Math.sqrt(Math.max(p.ewmaVariance, 0.0001));
  p.adaptiveWarn = +Math.min(0.85, Math.max(0.30, p.ewmaRisk + EWMA_WARN_SIGMA * sigma)).toFixed(3);
  p.adaptiveDeny = +Math.min(0.95, Math.max(0.50, p.ewmaRisk + EWMA_DENY_SIGMA * sigma)).toFixed(3);

  // ── Brittleness: error rate + request velocity ────────────────────────────
  // errorCount tracks non-ALLOW verdicts (proxy for agent misbehavior)
  if (verdict !== 'ALLOW') p.errorCount++;

  // reqWindow: sliding 60s window for velocity
  p.reqWindow.push(now);
  p.reqWindow = p.reqWindow.filter(t => t > now - 60_000);
  const reqRate   = p.reqWindow.length;                                   // requests in last 60s
  const errorRate = p.totalRequests > 0 ? p.errorCount / p.totalRequests : 0; // 0–1
  const denyRate  = p.totalRequests > 0 ? p.denied    / p.totalRequests : 0;  // 0–1

  // Composite brittleness: 40% error, 30% deny, 30% velocity (normalized to 100)
  // If full brittleness governor is available, blend its assessment (30% weight)
  let baseBrittleness = Math.round(
    40 * errorRate +
    30 * denyRate  +
    30 * Math.min(1, reqRate / 20)   // 20 req/60s = fully saturated
  );

  if (_brittlenessFull) {
    try {
      // Record per-passport metrics into the full governor
      const resId = passportId || 'anonymous';
      _brittlenessFull.recordUsage(resId, {
        costCents: 0,
        latencyMs: 0,
        success: verdict === 'ALLOW',
      });
      const fullReport = _brittlenessFull.analyze();
      if (fullReport && fullReport.overallBrittleness !== null) {
        // Blend: 70% passport-level, 30% full governor (cross-agent view)
        const governorScore = fullReport.overallBrittleness * 100; // 0-1 → 0-100
        baseBrittleness = Math.round(0.7 * baseBrittleness + 0.3 * Math.min(100, governorScore));
      }
    } catch (_) { /* degrade gracefully */ }
  }

  p.brittleness = baseBrittleness;

  // Circuit-breaker: brittleness ≥ BRITTLE_DENY → suspend passport
  if (p.brittleness >= BRITTLE_DENY && p.totalRequests >= 5) {
    p.status = 'circuit-breaker';
  }

  // Persist after every 10 updates (throttle writes; exact data is in-memory)
  if (p.totalRequests % 10 === 0) _ppSave(p);
}

/**
 * Get adaptive thresholds for a passport.
 * Returns static defaults if passport not found.
 */
function passportGetThresholds(passportId) {
  const p = _passports.get(passportId);
  if (!p) return { warnThreshold: 0.50, denyThreshold: 0.80 };
  return {
    warnThreshold: p.adaptiveWarn,
    denyThreshold: p.adaptiveDeny,
    brittleness:   p.brittleness,
  };
}

/**
 * List all passports (redacts privateKey — never stored).
 */
function passportList() {
  return Array.from(_passports.values()).map(p => ({ ...p }));
}

// ══════════════════════════════════════════════════════════════════════════════
// PROMPT DNA FINGERPRINTING
// Perceptual hashing of prompts — detects the same jailbreak in 50 disguises.
// Uses shingling + MinHash-style Jaccard similarity.
// ══════════════════════════════════════════════════════════════════════════════

const _dnaWindow = [];   // rolling window of { hash, shingles, passportId, ts, verdict }

/**
 * Normalize a prompt for comparison:
 * - lowercase
 * - collapse whitespace
 * - strip punctuation
 * - remove common filler words
 */
function _dnaNormalize(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s]/g, ' ')       // strip punctuation
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b(the|a|an|is|are|was|were|you|i|we|me|my|your)\b/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Generate k-shingles (character n-grams) from text.
 * Returns a Set of hashed shingles for fast Jaccard computation.
 */
function _shingle(text, k = 5) {
  const normalized = _dnaNormalize(text);
  const shingles = new Set();
  for (let i = 0; i <= normalized.length - k; i++) {
    const s = normalized.slice(i, i + k);
    // FNV-1a hash to compact the shingle
    let h = 0x811c9dc5;
    for (let j = 0; j < s.length; j++) { h ^= s.charCodeAt(j); h = Math.imul(h, 0x01000193); }
    shingles.add(h >>> 0);
  }
  return shingles;
}

/**
 * Jaccard similarity between two sets: |A ∩ B| / |A ∪ B|
 */
function _jaccard(setA, setB) {
  if (setA.size === 0 && setB.size === 0) return 1.0;
  let intersection = 0;
  for (const v of setA) { if (setB.has(v)) intersection++; }
  return intersection / (setA.size + setB.size - intersection);
}

/**
 * Check a prompt against the DNA window.
 * Returns { isDuplicate, similarity, matchedEntry } or { isDuplicate: false }
 */
function dnaCheck(text, passportId) {
  if (!text || text.length < 20) return { isDuplicate: false };

  const shingles = _shingle(text);
  const ts = Date.now();

  // Prune old entries from window
  const cutoff = ts - 3_600_000; // 1 hour window
  while (_dnaWindow.length > 0 && _dnaWindow[0].ts < cutoff) _dnaWindow.shift();
  if (_dnaWindow.length > DNA_WINDOW) _dnaWindow.splice(0, _dnaWindow.length - DNA_WINDOW);

  // Compare ONLY against entries that were confirmed DENY attacks.
  // This prevents false positives when a clean prompt is sent twice.
  // A clean prompt repeated by the user should never flag as a "DNA attack".
  const attackWindow = _dnaWindow.filter(e => e.verdict === 'DENY').slice(-200);
  let bestSim = 0;
  let bestMatch = null;
  for (const entry of attackWindow) {
    const sim = _jaccard(shingles, entry.shingles);
    if (sim > bestSim) { bestSim = sim; bestMatch = entry; }
  }

  // Store this entry with verdict=null — updated by dnaRecordVerdict() after govern completes
  _dnaWindow.push({ shingles, passportId, ts, text: text.slice(0, 100), verdict: null });

  if (bestSim >= DNA_SIM_THRESH && bestMatch) {
    // Increment probe count on passport
    if (passportId) {
      const p = _passports.get(passportId);
      if (p) p.probeCount++;
    }
    return {
      isDuplicate: true,
      similarity:  +bestSim.toFixed(3),
      matchedAt:   bestMatch.ts,
      matchedPassport: bestMatch.passportId,
    };
  }
  return { isDuplicate: false, similarity: +bestSim.toFixed(3) };
}

/**
 * Update the verdict for the most recently stored DNA entry.
 * Called after govern() completes so the DNA window only matches confirmed attacks.
 */
function dnaRecordVerdict(verdict) {
  if (_dnaWindow.length > 0) {
    _dnaWindow[_dnaWindow.length - 1].verdict = verdict;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// SWARM DETECTOR
// Tracks per-IP request patterns. Flags coordinated multi-agent attacks.
// ══════════════════════════════════════════════════════════════════════════════

const _swarmMap = new Map(); // ip → { denies: [{ts}], passports: Set, warns, total }

/**
 * Record a governance decision for an IP.
 * Returns swarm status: { swarm: bool, severity, reason }
 */
function swarmRecord(ip, verdict, passportId) {
  if (!ip) return { swarm: false };
  // Localhost/loopback is always the local desktop app — never a swarm attacker.
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return { swarm: false };

  const now = Date.now();
  const windowStart = now - SWARM_WINDOW_MS;

  let entry = _swarmMap.get(ip);
  if (!entry) {
    entry = { denies: [], warns: [], total: 0, passports: new Set(), firstSeen: now };
    _swarmMap.set(ip, entry);
  }

  entry.total++;
  if (passportId) entry.passports.add(passportId);

  // Prune old events
  entry.denies = entry.denies.filter(e => e.ts > windowStart);
  entry.warns  = entry.warns.filter(e => e.ts > windowStart);

  if (verdict === 'DENY') entry.denies.push({ ts: now });
  if (verdict === 'WARN') entry.warns.push({ ts: now });

  const deniesInWindow = entry.denies.length;
  const passportCount  = entry.passports.size;

  // Swarm conditions:
  // 1. Single IP, 5+ DENYs in 60s = automated attack
  // 2. 2+ different passports from same IP with DENYs = coordinated multi-agent attack
  if (deniesInWindow >= SWARM_DENY_LIMIT) {
    return {
      swarm:    true,
      severity: deniesInWindow >= 10 ? 'critical' : 'high',
      reason:   `${deniesInWindow} DENYs from ${ip} in ${SWARM_WINDOW_MS/1000}s`,
      passportCount,
    };
  }
  if (passportCount >= 2 && deniesInWindow >= 2) {
    return {
      swarm:    true,
      severity: 'medium',
      reason:   `Coordinated: ${passportCount} agents from ${ip} with ${deniesInWindow} DENYs`,
      passportCount,
    };
  }
  return { swarm: false, deniesInWindow, passportCount };
}

/**
 * Get swarm status for all tracked IPs.
 */
function swarmStatus() {
  const now = Date.now();
  const windowStart = now - SWARM_WINDOW_MS;
  const result = [];
  for (const [ip, entry] of _swarmMap) {
    const deniesInWindow = entry.denies.filter(e => e.ts > windowStart).length;
    if (deniesInWindow > 0 || entry.total > 10) {
      result.push({
        ip: ip.replace(/(\d+\.\d+\.\d+\.)\d+/, '$1***'), // partial mask
        total: entry.total,
        deniesInWindow,
        warnsInWindow: entry.warns.filter(e => e.ts > windowStart).length,
        passportCount: entry.passports.size,
        firstSeen: new Date(entry.firstSeen).toISOString(),
        threat: deniesInWindow >= SWARM_DENY_LIMIT,
      });
    }
  }
  return result.sort((a, b) => b.deniesInWindow - a.deniesInWindow);
}

// ══════════════════════════════════════════════════════════════════════════════
// GOVERNANCE RECEIPTS
// Tamper-proof, offline-verifiable proof of every governance decision.
// Format: kasbah_receipt:v1:sha256:<hmac>
// Any party with the shared secret can verify the receipt without the server.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Generate a governance receipt for a decision.
 * The HMAC payload includes all decision fields — any tampering invalidates it.
 */
function receiptGenerate(requestId, verdict, risk, passportId, timestamp) {
  // Asymmetric (Ed25519) v2 signing — offline-verifiable against the public
  // key published at /.well-known/kasbah-keys.json, without trusting this
  // server or knowing any shared secret. Replaces the old HMAC v1 scheme,
  // which could only be checked by whoever held RECEIPT_SECRET (i.e. us) —
  // that defeated the "verify offline, don't trust us" claim.
  const { sign } = require('./engine-key.js');
  const { receipt, payload } = sign({
    requestId,
    verdict,
    risk:       +risk.toFixed(4),
    passportId: passportId || 'anonymous',
    timestamp:  timestamp || Date.now(),
  });
  return { receipt, payload };
}

/**
 * Verify a governance receipt offline.
 * Returns { valid: bool, decision: object | null, error?: string }
 */
function receiptVerify(receipt, payloadB64) {
  if (!receipt || !payloadB64) {
    return { valid: false, error: 'Missing receipt or payload' };
  }
  // New receipts are v2/v3 (Ed25519, asymmetric) — delegate to engine-key's verifier.
  if (receipt.startsWith('kasbah_receipt:v2:') || receipt.startsWith('kasbah_receipt:v3:')) {
    const { verify } = require('./engine-key.js');
    const result = verify(receipt, payloadB64);
    return { valid: !!result.valid, decision: result.valid ? result.decoded : null, error: result.error };
  }
  // Legacy v1 (HMAC) — kept only to verify receipts issued before this fix.
  if (!receipt.startsWith('kasbah_receipt:v1:sha256:')) {
    return { valid: false, error: 'Invalid receipt format' };
  }

  try {
    const providedHmac = receipt.split(':')[3];
    const payload = Buffer.from(payloadB64, 'base64').toString('utf8');

    const expectedHmac = crypto
      .createHmac('sha256', RECEIPT_SECRET)
      .update(payload)
      .digest('hex');

    // Constant-time comparison to prevent timing attacks
    const valid = crypto.timingSafeEqual(
      Buffer.from(providedHmac, 'hex'),
      Buffer.from(expectedHmac, 'hex'),
    );

    return { valid, decision: valid ? JSON.parse(payload) : null };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// ONE-TIME GOVERNANCE RECEIPTS (replay-attack hardening)
// Each HMAC receipt can only be consumed once. A replay attack — presenting the
// same receipt twice — is rejected at the cryptographic layer with a 'replayed'
// flag, regardless of whether the payload is valid.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Verify a receipt exactly once.
 * The first call marks the HMAC as spent; any subsequent call with the same
 * receipt returns { valid: false, replayed: true } even if the signature is valid.
 *
 * @returns {{ valid: bool, decision: object|null, consumed?: bool,
 *             replayed?: bool, error?: string }}
 */
function receiptVerifyOnce(receipt, payloadB64) {
  // First run the standard signature check
  const result = receiptVerify(receipt, payloadB64);
  if (!result.valid) return result;

  // Extract the HMAC token from the receipt string
  const parts = (receipt || '').split(':');
  const hmac  = parts[3] || '';
  if (!hmac) return { valid: false, error: 'Cannot extract HMAC from receipt' };

  // Replay check — constant-time-ish (Set lookup is O(1))
  if (_spentReceipts.has(hmac)) {
    return { valid: false, replayed: true, error: 'Receipt already spent — replay attack rejected' };
  }

  _spentReceipts.add(hmac);
  return { ...result, consumed: true };
}

/**
 * Check whether an HMAC has already been consumed (without consuming it).
 * Useful for pre-flight checks in admission-control middleware.
 */
function receiptIsSpent(hmac) {
  return _spentReceipts.has(hmac || '');
}

// ══════════════════════════════════════════════════════════════════════════════
// HASH-CHAINED AUDIT LEDGER
// Every governance decision appended to the chain includes a SHA-256 hash of
// (prevHash + dataHash + timestamp).  Any retroactive modification to any entry
// breaks every subsequent hash — tamper-evidence with O(n) verification.
// Genesis hash: 64 zeros.  Chain tip hash changes with every append.
// ══════════════════════════════════════════════════════════════════════════════

const _GENESIS_HASH = '0'.repeat(64);
const _auditChain   = [];   // [{ index, prevHash, hash, ts, data }]

// Durable backing store: without this the chain lived only in process memory
// and was silently wiped on every deploy/restart — found 2026-07 while
// comparing this module against an archived Postgres-backed hash-chain
// package (packages/_archive/hash-chain). Same algorithm, no DB dependency
// needed: append-only JSONL under the existing persistent data dir, replayed
// into _auditChain on boot.
const _KASBAH_DATA_DIR = process.env.KASBAH_DATA_DIR || path.join(__dirname, '../../../.kasbah');
const _CHAIN_FILE = path.join(_KASBAH_DATA_DIR, 'audit-chain.jsonl');
try { fs.mkdirSync(_KASBAH_DATA_DIR, { recursive: true }); } catch (_) {}
try {
  const raw = fs.readFileSync(_CHAIN_FILE, 'utf8');
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    _auditChain.push(JSON.parse(line));
  }
} catch (_) { /* no prior chain file — starts empty, genesis on first append */ }

/**
 * Append an entry to the tamper-evident audit chain.
 * Returns { hash, index } identifying the new chain tip.
 */
function auditAppend(entry) {
  const ts       = Date.now();
  const prevHash = _auditChain.length > 0
    ? _auditChain[_auditChain.length - 1].hash
    : _GENESIS_HASH;

  const dataHash = crypto.createHash('sha256')
    .update(JSON.stringify(entry))
    .digest('hex');

  const hash = crypto.createHash('sha256')
    .update(prevHash + dataHash + ts.toString())
    .digest('hex');

  // Deep-copy the entry so later mutations to the caller's object
  // cannot corrupt the stored data (and break hash verification).
  const record = { index: _auditChain.length, prevHash, hash, ts, data: JSON.parse(JSON.stringify(entry)) };
  _auditChain.push(record);
  try { fs.appendFileSync(_CHAIN_FILE, JSON.stringify(record) + '\n'); } catch (_) {}
  return { hash, index: record.index };
}

/**
 * Verify the integrity of the entire audit chain from genesis.
 * Returns { valid: bool, length, tip?, brokenAt?, reason? }
 */
function auditVerify() {
  if (_auditChain.length === 0) return { valid: true, length: 0 };

  for (let i = 0; i < _auditChain.length; i++) {
    const entry        = _auditChain[i];
    const expectedPrev = i === 0 ? _GENESIS_HASH : _auditChain[i - 1].hash;

    if (entry.prevHash !== expectedPrev) {
      return { valid: false, brokenAt: i, reason: 'prevHash mismatch' };
    }

    const dataHash     = crypto.createHash('sha256')
      .update(JSON.stringify(entry.data))
      .digest('hex');
    const expectedHash = crypto.createHash('sha256')
      .update(entry.prevHash + dataHash + entry.ts.toString())
      .digest('hex');

    if (entry.hash !== expectedHash) {
      return { valid: false, brokenAt: i, reason: `hash mismatch at index ${i} — entry tampered` };
    }
  }

  const tip = _auditChain[_auditChain.length - 1];
  return { valid: true, length: _auditChain.length, tip: tip.hash, tipTs: tip.ts };
}

/**
 * Return a deep-cloned snapshot of the audit chain.
 * Mutations to the returned objects cannot corrupt the internal ledger.
 */
function auditGetChain() {
  // JSON round-trip gives a guaranteed deep copy — safe for consumers to mutate
  return JSON.parse(JSON.stringify(_auditChain));
}

// ══════════════════════════════════════════════════════════════════════════════
// BELL'S INEQUALITY AI TEXT DETECTOR
// Hypothesis: AI-generated text violates the CHSH classical correlation bound
// (S ≤ 2.0) because language models produce globally-coherent text.  Four
// semantic measurement "bases" act as local-measurement operators:
//   A  = Formality    (absence of contractions / informal markers)
//   A' = Specificity  (technical terms, numbers, capitalized entities)
//   B  = Coherence    (lexical overlap with adjacent sentence)
//   B' = Certainty    (absence of hedging language)
// CHSH correlators: E(a,b)  E(a,b')  E(a',b)  E(a',b')
// S = |E(a,b) − E(a,b') + E(a',b) + E(a',b')|
// Classical bound: S ≤ 2.0.   AI signal: S > 2.0 (up to 2√2 ≈ 2.83).
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Per-sentence measurement functions.
 * Each returns a value in [−1, +1] to act as a Bell-measurement observable.
 */

function _measureFormality(s) {
  const contractions = (s.match(
    /\b(don't|can't|won't|isn't|aren't|it's|i'm|you're|we're|they're|haven't|hasn't|wouldn't|couldn't|shouldn't|i've|i'd|you'd|they'd)\b/gi
  ) || []).length;
  const words = Math.max(1, s.trim().split(/\s+/).length);
  return Math.max(-1, Math.min(1, 1 - (contractions / words) * 10));
}

function _measureSpecificity(s) {
  const technical = (s.match(
    /(\b\d[\d,.]*\b|[A-Z]{2,}\b|[A-Z][a-z]+[A-Z][a-z]+|\w+(?:tion|ment|ance|ence|ity|ism|ize|ical)\b)/g
  ) || []).length;
  const words = Math.max(1, s.trim().split(/\s+/).length);
  return Math.min(1, (technical / words) * 3) * 2 - 1;
}

function _measureCoherence(s, prev) {
  if (!prev || prev.trim().length === 0) return 0;
  const w1 = new Set(prev.toLowerCase().split(/\s+/).filter(w => w.length > 4));
  const w2 = new Set(s.toLowerCase().split(/\s+/).filter(w => w.length > 4));
  let overlap = 0;
  for (const w of w1) if (w2.has(w)) overlap++;
  const denom = w1.size + w2.size - overlap;
  return denom > 0 ? (overlap / denom) * 2 - 1 : 0;
}

function _measureCertainty(s) {
  const hedges = (s.match(
    /\b(maybe|perhaps|possibly|might|could|probably|seems|appears|likely|suggest|indicate|often|sometimes|generally|typically)\b/gi
  ) || []).length;
  const words = Math.max(1, s.trim().split(/\s+/).length);
  return Math.max(-1, Math.min(1, 1 - (hedges / words) * 8));
}

/**
 * Pearson correlation between two same-length arrays.
 */
function _pearson(x, y) {
  const n = Math.min(x.length, y.length);
  if (n < 2) return 0;
  const mx = x.slice(0, n).reduce((s, v) => s + v, 0) / n;
  const my = y.slice(0, n).reduce((s, v) => s + v, 0) / n;
  let num = 0, dx = 0, dy = 0;
  for (let i = 0; i < n; i++) {
    num += (x[i] - mx) * (y[i] - my);
    dx  += (x[i] - mx) ** 2;
    dy  += (y[i] - my) ** 2;
  }
  const denom = Math.sqrt(dx * dy);
  return denom > 0 ? num / denom : 0;
}

/**
 * Run Bell's Inequality CHSH test on a piece of text.
 *
 * @param {string} text   Text to analyse (works best on ≥4 sentences)
 * @returns {{
 *   isAI:         boolean,   // true if S > BELLS_THRESHOLD (2.0)
 *   sValue:       number,    // CHSH S-value (classical bound: 2.0; max quantum: ~2.83)
 *   correlators:  object,    // E(a,b), E(a,b'), E(a',b), E(a',b')
 *   sentenceCount: number,
 *   reason?:      string     // 'too short' if fewer than 4 sentences
 * }}
 */
function bellsCheck(text) {
  const sentences = (text || '').match(/[^.!?]+[.!?]*/g) || [];
  const N = Math.min(sentences.length, 30);   // cap at 30 sentences

  if (N < 4) {
    return { isAI: false, sValue: 0, sentenceCount: N, reason: 'too short (< 4 sentences)' };
  }

  // Collect per-sentence measurements
  const A  = [], Ap = [], B  = [], Bp = [];
  for (let i = 0; i < N; i++) {
    A.push( _measureFormality(sentences[i]));
    Ap.push(_measureSpecificity(sentences[i]));
    B.push( _measureCoherence(sentences[i], sentences[i - 1] || ''));
    Bp.push(_measureCertainty(sentences[i]));
  }

  // Four CHSH correlators
  const Eab   = _pearson(A,  B);
  const Eabp  = _pearson(A,  Bp);
  const Eapb  = _pearson(Ap, B);
  const Eapbp = _pearson(Ap, Bp);

  // CHSH S-value (standard form)
  const sValue = Math.abs(Eab - Eabp + Eapb + Eapbp);

  return {
    isAI:         sValue > BELLS_THRESHOLD,
    sValue:       +sValue.toFixed(4),
    correlators: {
      'E(a,b)':   +Eab.toFixed(4),
      'E(a,b\')': +Eabp.toFixed(4),
      'E(a\',b)': +Eapb.toFixed(4),
      'E(a\',b\')': +Eapbp.toFixed(4),
    },
    sentenceCount: N,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// DELEGATION CHAIN
// HMAC-signed delegation tokens prove "agent A is authorized to act on behalf
// of principal B for a given scope, until a given expiry".
// Without this, a compromised child agent can claim to represent a root
// principal with no cryptographic proof.  The chain depth is capped at 5.
//
// Token format:  dtoken_<hex24>
// Signature:     HMAC-SHA256( grantorId + ":" + granteeId + ":" + scope + ":" + expiresAt )
// ══════════════════════════════════════════════════════════════════════════════

const _delegationTokens  = new Map();   // tokenId → DelegationToken
const MAX_DELEGATION_DEPTH = 5;
const MAX_DELEGATION_TTL   = 86_400_000;  // 24 h hard cap

/**
 * Issue a signed delegation token.
 * @param {string} grantorId   — The principal granting authority
 * @param {string} granteeId   — The agent receiving authority
 * @param {string} scope       — e.g. 'billing:read', 'search:*', '*'
 * @param {number} ttlMs       — Time-to-live in ms (max 24 h)
 * @param {string|null} parentTokenId — For chaining: ID of the parent token
 * @returns {{ tokenId, signature, expiresAt, depth }}
 */
function delegationIssue(grantorId, granteeId, scope, ttlMs = 3_600_000, parentTokenId = null) {
  // Enforce chain depth
  let depth = 0;
  if (parentTokenId) {
    const parent = _delegationTokens.get(parentTokenId);
    if (!parent) throw new Error('Unknown parent delegation token');
    if (parent.revoked)   throw new Error('Parent delegation token is revoked');
    if (parent.expiresAt < Date.now()) throw new Error('Parent delegation token is expired');
    depth = parent.depth + 1;
  }
  if (depth >= MAX_DELEGATION_DEPTH) throw new Error(`Max delegation depth (${MAX_DELEGATION_DEPTH}) exceeded`);

  const ttl       = Math.min(ttlMs, MAX_DELEGATION_TTL);
  const issuedAt  = Date.now();
  const expiresAt = issuedAt + ttl;
  const tokenId   = 'dtoken_' + crypto.randomBytes(12).toString('hex');

  // HMAC over the binding fields — prevents forgery
  const sigPayload = [grantorId, granteeId, scope, expiresAt.toString()].join(':');
  const signature  = crypto.createHmac('sha256', RECEIPT_SECRET).update(sigPayload).digest('hex');

  _delegationTokens.set(tokenId, {
    tokenId, grantorId, granteeId, scope,
    issuedAt, expiresAt, signature, depth,
    parentTokenId: parentTokenId || null,
    revoked: false,
  });

  return { tokenId, signature, expiresAt, depth, grantorId, granteeId, scope };
}

/**
 * Verify a delegation token (signature + expiry + revocation + chain validity).
 * @returns {{ valid: bool, token?: object, error?: string }}
 */
function delegationVerify(tokenId) {
  const t = _delegationTokens.get(tokenId);
  if (!t)           return { valid: false, error: 'Unknown token' };
  if (t.revoked)    return { valid: false, error: 'Token revoked' };
  if (t.expiresAt < Date.now()) return { valid: false, error: 'Token expired' };

  // Re-derive expected signature
  const sigPayload  = [t.grantorId, t.granteeId, t.scope, t.expiresAt.toString()].join(':');
  const expectedSig = crypto.createHmac('sha256', RECEIPT_SECRET).update(sigPayload).digest('hex');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(t.signature, 'hex'), Buffer.from(expectedSig, 'hex'))) {
      return { valid: false, error: 'Signature mismatch — token tampered' };
    }
  } catch { return { valid: false, error: 'Signature format error' }; }

  // Validate parent chain recursively
  if (t.parentTokenId) {
    const parentResult = delegationVerify(t.parentTokenId);
    if (!parentResult.valid) return { valid: false, error: `Parent chain broken: ${parentResult.error}` };
  }

  return { valid: true, token: { ...t } };
}

/**
 * Revoke a delegation token (and implicitly all children referencing it).
 */
function delegationRevoke(tokenId) {
  const t = _delegationTokens.get(tokenId);
  if (!t) return false;
  t.revoked = true;
  return true;
}

// ══════════════════════════════════════════════════════════════════════════════
// PREDICTIVE THREAT FORECASTING
// Analyzes historical threat events per passport and system-wide to predict
// which attack category is most likely next.  Uses frequency × recency scoring:
//   score = (occurrences × 2) + (1 / age_seconds + 1)
// Categories: evasion | injection | exfiltration | manipulation | bypass
// ══════════════════════════════════════════════════════════════════════════════

const _threatHistory  = [];          // [{ ts, category, passportId, severity }]
const MAX_THREAT_HISTORY = 10_000;

const THREAT_PATTERNS = {
  evasion:       ['obfuscat', 'encod', 'base64', 'hex', 'mutati', 'fragment'],
  injection:     ['inject', 'payload', 'script', 'sql', 'command', 'eval'],
  exfiltration:  ['secret', 'credential', 'api_key', 'token', 'exfil', 'leak'],
  manipulation:  ['override', 'manipulat', 'alter', 'forge', 'spoof', 'fake'],
  bypass:        ['bypass', 'jailbreak', 'ignore', 'pretend', 'dan', 'override previous'],
};

/**
 * Record a threat event for forecasting purposes.
 */
function forecastRecord(threat, passportId, severity = 'medium') {
  // Classify threat into category
  const lc = threat.toLowerCase();
  let category = 'unknown';
  for (const [cat, keywords] of Object.entries(THREAT_PATTERNS)) {
    if (keywords.some(k => lc.includes(k))) { category = cat; break; }
  }

  _threatHistory.push({ ts: Date.now(), category, passportId, threat, severity });
  if (_threatHistory.length > MAX_THREAT_HISTORY) _threatHistory.shift();
  return category;
}

/**
 * Forecast the most likely next attack categories.
 * Looks at events within `windowMs` (default 1 h).
 *
 * @returns {{ predictions: [{category, probability, score}], confidence, basedOn }}
 */
function forecastPredict(passportId = null, windowMs = 3_600_000) {
  const cutoff  = Date.now() - windowMs;
  const events  = _threatHistory.filter(e =>
    e.ts > cutoff && (!passportId || e.passportId === passportId)
  );

  if (events.length === 0) return { predictions: [], confidence: 0, basedOn: 0 };

  // Score each category: frequency × recency
  const scores = {};
  for (const e of events) {
    const age       = (Date.now() - e.ts) / 1000;  // seconds
    const recency   = 1 / (age + 1);
    const sevWeight = e.severity === 'critical' ? 4 : e.severity === 'high' ? 3 :
                      e.severity === 'medium' ? 2 : 1;
    scores[e.category] = (scores[e.category] || 0) + recency * sevWeight;
  }

  // Normalize to probabilities
  const total = Object.values(scores).reduce((s, v) => s + v, 0);
  const predictions = Object.entries(scores)
    .map(([category, score]) => ({
      category,
      score:       +score.toFixed(4),
      probability: +(score / total).toFixed(3),
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  const confidence = Math.min(1.0, events.length / 20);  // saturates at 20 events
  return { predictions, confidence: +confidence.toFixed(3), basedOn: events.length };
}

// ══════════════════════════════════════════════════════════════════════════════
// SYSTEM INTEGRITY INDEX (Ψ)
// System-wide health score (0–1).  When the system is under coordinated attack,
// Ψ drops and ALL passport thresholds are globally tightened.
//
// Ψ = 1.0 − (0.40 × deny_rate + 0.30 × error_rate + 0.30 × threat_density)
//
// deny_rate    = global DENY / total requests (last 5 min)
// error_rate   = 500-class server errors / total requests (last 5 min)
// threat_density = unique passports flagged / total active passports
//
// Auto-tighten: Ψ < 0.60 → all adaptive thresholds drop by 15%
// ══════════════════════════════════════════════════════════════════════════════

const _siiWindow  = [];    // [{ ts, verdict, isError }] — last 5 min
const SII_WINDOW  = 300_000;  // 5 minutes

let _globalSiiTighten = false;   // true when Ψ < 0.60 → thresholds globally reduced

/**
 * Record a governance decision into the System Integrity Index.
 * Called alongside passportUpdateTrust.
 */
function siiRecord(verdict, isError = false) {
  const now = Date.now();
  _siiWindow.push({ ts: now, verdict, isError });
  // Prune old entries
  const cutoff = now - SII_WINDOW;
  while (_siiWindow.length > 0 && _siiWindow[0].ts < cutoff) _siiWindow.shift();
}

/**
 * Compute the current System Integrity Index (Ψ) and apply global tightening
 * if Ψ falls below 0.60.
 *
 * @returns {{ psi, denyRate, errorRate, threatDensity, tightened, totalRequests }}
 */
function siiCompute() {
  const n = _siiWindow.length;
  if (n === 0) return { psi: 1.0, denyRate: 0, errorRate: 0, threatDensity: 0, tightened: false, totalRequests: 0 };

  const denies     = _siiWindow.filter(e => e.verdict === 'DENY').length;
  const errors     = _siiWindow.filter(e => e.isError).length;
  const denyRate   = denies / n;
  const errorRate  = errors / n;

  // Threat density: proportion of active passports that have been flagged in window
  const totalPassports   = _passports.size;
  const flaggedPassports = new Set(
    _siiWindow.filter(e => e.verdict !== 'ALLOW').map(e => e.passportId).filter(Boolean)
  ).size;
  const threatDensity = totalPassports > 0 ? flaggedPassports / totalPassports : 0;

  const psi = Math.max(0, 1 - (0.40 * denyRate + 0.30 * errorRate + 0.30 * threatDensity));

  _globalSiiTighten = psi < 0.60;

  return {
    psi:            +psi.toFixed(4),
    denyRate:       +denyRate.toFixed(4),
    errorRate:      +errorRate.toFixed(4),
    threatDensity:  +threatDensity.toFixed(4),
    tightened:      _globalSiiTighten,
    totalRequests:  n,
    window:         '5m',
  };
}

/**
 * Get effective thresholds for a passport, incorporating global SII tightening.
 * When Ψ < 0.60, all thresholds are reduced by 15% (more aggressive blocking).
 */
function siiAdjustThresholds(warnThreshold, denyThreshold) {
  if (!_globalSiiTighten) return { warnThreshold, denyThreshold };
  return {
    warnThreshold: +Math.max(0.25, warnThreshold * 0.85).toFixed(3),
    denyThreshold: +Math.max(0.40, denyThreshold * 0.85).toFixed(3),
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// TOKEN SPEND LEDGER
// Per-passport token/cost budget with hard-block on overage.
// Answers: "can this passport afford another request right now?"
//
// Policies specify:
//   maxTokensPerMin  — burst protection (rolling 60s window)
//   maxTokensPerDay  — daily cap (rolling 24h window)
//   maxCostCentsPerDay — cost cap in USD cents (rolling 24h)
// ══════════════════════════════════════════════════════════════════════════════

const _spendPolicies = new Map();  // passportId → SpendPolicy
const _spendRecords  = new Map();  // passportId → [{ ts, tokens, costCents }]

const DEFAULT_SPEND_POLICY = {
  maxTokensPerMin:   100_000,
  maxTokensPerDay:   5_000_000,
  maxCostCentsPerDay: 5_000,     // $50/day
  hardBlockOnExceed:  true,
};

/**
 * Set a spend policy for a passport.
 * Pass null to remove (falls back to default).
 */
function spendSetPolicy(passportId, policy) {
  if (policy === null) { _spendPolicies.delete(passportId); return; }
  _spendPolicies.set(passportId, { ...DEFAULT_SPEND_POLICY, ...policy });
}

/**
 * Record token consumption after a request.
 * @param {string} passportId
 * @param {number} tokens     — tokens consumed (prompt + completion)
 * @param {number} costCents  — cost in USD cents (e.g. 0.5 = $0.005)
 */
function spendRecord(passportId, tokens, costCents = 0) {
  if (!passportId) return;
  if (!_spendRecords.has(passportId)) _spendRecords.set(passportId, []);
  const recs = _spendRecords.get(passportId);
  recs.push({ ts: Date.now(), tokens: tokens || 0, costCents: costCents || 0 });
  // Prune records older than 24h
  const cutoff24h = Date.now() - 86_400_000;
  while (recs.length > 0 && recs[0].ts < cutoff24h) recs.shift();
}

/**
 * Check whether a passport can afford a request.
 * Returns { allowed: bool, reason?, usage: {...} }
 */
function spendCheck(passportId) {
  if (!passportId) return { allowed: true };
  const policy = _spendPolicies.get(passportId) || DEFAULT_SPEND_POLICY;
  const recs   = _spendRecords.get(passportId) || [];
  const now    = Date.now();

  // Rolling 60-second window
  const recs1m   = recs.filter(r => r.ts > now - 60_000);
  const tokens1m = recs1m.reduce((s, r) => s + r.tokens, 0);

  // Rolling 24-hour window
  const recs24h       = recs.filter(r => r.ts > now - 86_400_000);
  const tokens24h     = recs24h.reduce((s, r) => s + r.tokens, 0);
  const costCents24h  = recs24h.reduce((s, r) => s + r.costCents, 0);

  const usage = {
    tokens1m, tokens24h, costCents24h,
    limitTokensPerMin:   policy.maxTokensPerMin,
    limitTokensPerDay:   policy.maxTokensPerDay,
    limitCostCentsPerDay: policy.maxCostCentsPerDay,
  };

  if (tokens1m  >= policy.maxTokensPerMin)    return { allowed: !policy.hardBlockOnExceed, reason: 'tokens_per_min_exceeded',  usage };
  if (tokens24h >= policy.maxTokensPerDay)    return { allowed: !policy.hardBlockOnExceed, reason: 'tokens_per_day_exceeded',  usage };
  if (costCents24h >= policy.maxCostCentsPerDay) return { allowed: !policy.hardBlockOnExceed, reason: 'cost_per_day_exceeded', usage };

  return { allowed: true, usage };
}

/**
 * Get spend summary for a passport.
 */
function spendGetUsage(passportId) {
  return spendCheck(passportId).usage || {};
}

// ══════════════════════════════════════════════════════════════════════════════
// HONEYTOKEN CANARY SYSTEM  (System #14)
// Deploy realistic-looking synthetic API keys as canary tokens.
// If any deployed honeytoken appears in a prompt → exfiltration attempt → DENY.
//
// Honeytoken patterns match real API key formats:
//   OpenAI   sk-[a-zA-Z0-9]{48}
//   Anthropic sk-ant-[a-zA-Z0-9-_]{93}
//   AWS      AKIA[A-Z0-9]{16}
//   GitHub   gh[pousr]_[A-Za-z0-9]{36,}
//   Stripe   sk_live_[A-Za-z0-9]{24,}
//   Generic  kbt_[a-zA-Z0-9]{32}  (Kasbah internal canary format)
// ══════════════════════════════════════════════════════════════════════════════

const _honeytokens = new Map();   // tokenId → { token, service, deployedAt, triggerCount }

const HONEYTOKEN_PATTERNS = {
  openai:    /sk-[a-zA-Z0-9]{48}/g,
  anthropic: /sk-ant-[a-zA-Z0-9\-_]{93}/g,
  aws:       /AKIA[A-Z0-9]{16}/g,
  github:    /gh[pousr]_[A-Za-z0-9]{36,}/g,
  stripe:    /sk_live_[A-Za-z0-9]{24,}/g,
  kasbah:    /kbt_[a-zA-Z0-9]{32}/g,
};

/**
 * Generate and store a new honeytoken for a given service.
 * Returns the token string (store this somewhere it could be leaked).
 */
function honeytokenDeploy(service = 'kasbah') {
  const bytes = crypto.randomBytes(24).toString('hex').toUpperCase();
  let token;
  switch (service) {
    case 'openai':    token = 'sk-' + crypto.randomBytes(36).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 48); break;
    case 'anthropic': token = 'sk-ant-' + crypto.randomBytes(70).toString('base64').replace(/[^a-zA-Z0-9\-_]/g, '').slice(0, 93); break;
    case 'aws':       token = 'AKIA' + bytes.slice(0, 16); break;
    case 'github':    token = 'ghp_' + crypto.randomBytes(27).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 36); break;
    case 'stripe':    token = 'sk_live_' + crypto.randomBytes(18).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 24); break;
    default:          token = 'kbt_' + crypto.randomBytes(16).toString('hex');
  }
  const tokenId = 'ht_' + crypto.randomBytes(8).toString('hex');
  _honeytokens.set(tokenId, { tokenId, token, service, deployedAt: Date.now(), triggerCount: 0 });
  return { tokenId, token, service };
}

/**
 * Seed default internal honeytokens on first load.
 * These act as persistent canaries — any prompt containing them is an attacker.
 */
(function seedHoneytokens() {
  // Internal Kasbah canary keys — seeded deterministically from the receipt secret
  // so they survive server restarts with the same values.
  const seed = crypto.createHmac('sha256', RECEIPT_SECRET).update('honeytoken_seed_v1').digest('hex');
  const canary1 = 'kbt_' + seed.slice(0, 32);
  const canary2 = 'sk-' + Buffer.from(seed.slice(32, 68), 'hex').toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 48).padEnd(48, 'x');
  _honeytokens.set('ht_seed_1', { tokenId: 'ht_seed_1', token: canary1, service: 'kasbah', deployedAt: Date.now(), triggerCount: 0 });
  _honeytokens.set('ht_seed_2', { tokenId: 'ht_seed_2', token: canary2, service: 'openai',  deployedAt: Date.now(), triggerCount: 0 });
})();

/**
 * Check whether a text contains any deployed honeytoken.
 * @returns {{ triggered: boolean, matches: Array<{tokenId, service, token}> }}
 */
function honeytokenCheck(text) {
  if (!text || typeof text !== 'string') return { triggered: false, matches: [] };
  const matches = [];

  // Check each deployed token literally
  for (const [tokenId, ht] of _honeytokens) {
    if (text.includes(ht.token)) {
      ht.triggerCount++;
      matches.push({ tokenId, service: ht.service, token: ht.token.slice(0, 8) + '...' });
    }
  }

  // Also scan for general patterns (catch tokens not yet deployed but matching format)
  for (const [service, pattern] of Object.entries(HONEYTOKEN_PATTERNS)) {
    const found = text.match(new RegExp(pattern.source, 'g')) || [];
    for (const tok of found) {
      // Only flag if not already caught by literal check
      const alreadyCaught = matches.some(m => text.includes(tok));
      if (!alreadyCaught && found.length > 0) {
        matches.push({ tokenId: 'pattern_' + service, service, token: tok.slice(0, 8) + '...' });
      }
    }
  }

  return { triggered: matches.length > 0, matches };
}

function honeytokenList() {
  return Array.from(_honeytokens.values()).map(h => ({
    tokenId: h.tokenId,
    service: h.service,
    deployedAt: h.deployedAt,
    triggerCount: h.triggerCount,
    tokenPreview: h.token.slice(0, 8) + '...',
  }));
}

// ══════════════════════════════════════════════════════════════════════════════
// MAQASID ETHICS FRAMEWORK  (System #15)
// 5-pillar Islamic ethics scoring based on Maqasid al-Shariah.
// Each pillar scores 0–1. Composite compliance score below threshold → flag.
//
// Pillars:
//   Din  (Religion)  — Harm to religious practice, blasphemy, apostasy pressure
//   Nafs (Life)      — Physical harm, violence, self-harm, medical misinformation
//   Aql  (Intellect) — Manipulation, propaganda, misinformation, addiction
//   Nasl (Lineage)   — CSAM, family harm, exploitation of minors
//   Mal  (Wealth)    — Financial fraud, theft, Ponzi schemes, riba exploitation
//
// Weights: Din 25%, Nafs 25%, Aql 20%, Nasl 20%, Mal 10%
// ══════════════════════════════════════════════════════════════════════════════

const MAQASID_PATTERNS = {
  din: {
    harm: /\b(blasphemy|apostasy|renounce\s+(your\s+)?faith|mock\s+(islam|christianity|judaism|religion)|anti[- ]religious|heresy|infidel.*die|crusade.*kill)\b/i,
    protect: /\b(prayer|worship|religion|faith|spiritual|mosque|church|synagogue|temple)\b/i,
  },
  nafs: {
    harm: /\b(kill\s+(yourself|myself|himself|herself)|self[- ]harm|suicide\s+method|how\s+to\s+hurt|bomb\s+making|poison\s+recipe|murder\s+plan|biological\s+weapon|chemical\s+weapon)\b/i,
    protect: /\b(safety|health|medical|doctor|hospital|emergency|wellbeing)\b/i,
  },
  aql: {
    harm: /\b(propaganda|brainwash|manipulat\w+\s+(voter|people|mind)|disinformation|fake\s+news\s+campaign|conspiracy\s+to\s+deceive|gaslighting|psychological\s+manipulation|addiction\s+exploit)\b/i,
    protect: /\b(education|knowledge|learning|truth|critical\s+thinking|accurate|verified)\b/i,
  },
  nasl: {
    harm: /\b(child\s+(pornography|abuse|exploitation)|minor\s+(sexual|nude|explicit)|underage\s+(sex|nude)|csam|groom\w*\s+(child|minor)|pedophil)\b/i,
    protect: /\b(family|children|parenting|child\s+safety|protect\s+(minors|children))\b/i,
  },
  mal: {
    harm: /\b(ponzi\s+scheme|money\s+laundering|tax\s+fraud|financial\s+scam|steal\s+(credit\s+card|bank\s+account)|embezzle|counterfeit\s+(money|currency)|insider\s+trading\s+plan)\b/i,
    protect: /\b(lawful|legal|legitimate|transparent|compliance|financial\s+advice\s+disclaimer)\b/i,
  },
};

const MAQASID_WEIGHTS = { din: 0.25, nafs: 0.25, aql: 0.20, nasl: 0.20, mal: 0.10 };
const MAQASID_BLOCK_THRESHOLD = 0.30;   // Compliance < 30% → DENY
const MAQASID_WARN_THRESHOLD  = 0.55;   // Compliance < 55% → WARN

/**
 * Score text against all 5 Maqasid pillars.
 * Returns { compliance, pillars, concerns, verdict }
 */
function maqasidCheck(text) {
  if (!text || text.length < 5) return { compliance: 1.0, pillars: { din: 0.7, nafs: 0.7, aql: 0.7, nasl: 0.7, mal: 0.7 }, concerns: [], verdict: 'approved' };

  const pillars = {};
  const concerns = [];

  for (const [pillar, patterns] of Object.entries(MAQASID_PATTERNS)) {
    const hasHarm    = patterns.harm.test(text);
    const hasProtect = patterns.protect.test(text);

    // Score: harm → 0.0, protect → 1.0, neutral → 0.7
    let score = 0.70;
    if (hasHarm)    { score = hasProtect ? 0.35 : 0.10; concerns.push(pillar + '_harm_detected'); }
    else if (hasProtect) { score = 0.95; }

    pillars[pillar] = +score.toFixed(3);
  }

  const compliance = Object.entries(pillars).reduce((sum, [p, s]) => sum + s * MAQASID_WEIGHTS[p], 0);

  let verdict = 'approved';
  if (compliance < MAQASID_BLOCK_THRESHOLD) verdict = 'blocked';
  else if (compliance < MAQASID_WARN_THRESHOLD) verdict = 'flagged';

  // Nasl is always block-level when triggered (child safety)
  if (pillars.nasl < 0.20) verdict = 'blocked';

  // Nafs is always block-level when triggered at severe level (life / self-harm)
  // Weight=25% but intent is lethal — override composite threshold
  if (pillars.nafs < 0.20) verdict = 'blocked';

  // Mal flagged even when composite stays above WARN (10% weight too small alone)
  if (pillars.mal < 0.20 && verdict === 'approved') verdict = 'flagged';

  return { compliance: +compliance.toFixed(4), pillars, concerns, verdict };
}

// ══════════════════════════════════════════════════════════════════════════════
// EXECUTION TICKETS  (System #16)
// Sub-100ms HMAC tickets prevent TOCTOU (time-of-check / time-of-use) attacks.
//
// Design:
//   - Each ALLOW decision issues a single-use execution ticket
//   - Ticket TTL: 90ms by default (configurable down to 10ms)
//   - Ticket contains: ticketId, requestId, agentId, action, HMAC, expiresAt
//   - HMAC = SHA256(ticketId + ":" + requestId + ":" + agentId + ":" + expiresAt)
//   - On verification: check HMAC, check expiry, check not-yet-spent
//   - Spent tickets stored in a bounded set (auto-purged every 5 min)
// ══════════════════════════════════════════════════════════════════════════════

const _spentTickets   = new Set();   // spent ticketIds — replay prevention
const _ticketRegistry = new Map();   // ticketId → ticket record

const TICKET_DEFAULT_TTL = 90;       // ms — sub-100ms TOCTOU window

setInterval(() => {
  // Purge expired + spent tickets every 5 minutes
  const now = Date.now();
  for (const [id, t] of _ticketRegistry) {
    if (t.expiresAt < now) {
      _ticketRegistry.delete(id);
      _spentTickets.delete(id);
    }
  }

  // Cap _spentReceipts — replay-safety is window-bounded; trim to 50k entries
  // Receipts older than 5 minutes cannot be replayed anyway (clock skew tolerance is 60s)
  if (_spentReceipts.size > 50_000) {
    const entries = [..._spentReceipts];
    _spentReceipts.clear();
    // Keep the most recent 40,000 (trim oldest 10k)
    for (const e of entries.slice(-40_000)) _spentReceipts.add(e);
  }

  // Evict dormant _swarmMap entries (no traffic in 10 min), cap passports Set per IP
  const swarmCutoff = now - 10 * 60 * 1000;
  for (const [ip, entry] of _swarmMap) {
    const lastSeen = entry.denies.at(-1)?.ts || entry.warns.at(-1)?.ts || entry.firstSeen;
    if (lastSeen < swarmCutoff) {
      _swarmMap.delete(ip);
    } else if (entry.passports.size > 200) {
      // Cap at 200 unique passports per IP to prevent unbounded Set growth
      entry.passports.clear();
    }
  }
}, 300_000).unref();  // .unref() — don't keep process alive during test teardown

/**
 * Issue a single-use execution ticket for an ALLOW decision.
 * @param {string} requestId  — The govern request ID
 * @param {string} agentId    — The agent (or 'anonymous')
 * @param {string} action     — The intended action ('govern', 'execute', 'scan', ...)
 * @param {number} [ttlMs=90] — Lifetime in milliseconds (default 90ms)
 * @returns {{ ticketId, hmac, expiresAt, ttlMs, action }}
 */
function ticketIssue(requestId, agentId, action = 'govern', ttlMs = TICKET_DEFAULT_TTL) {
  const ticketId  = 'tkt_' + crypto.randomBytes(10).toString('hex');
  const expiresAt = Date.now() + ttlMs;

  const payload = [ticketId, requestId, agentId || 'anonymous', expiresAt.toString()].join(':');
  const hmac    = crypto.createHmac('sha256', RECEIPT_SECRET).update(payload).digest('hex');

  const ticket = { ticketId, requestId, agentId: agentId || 'anonymous', action, expiresAt, ttlMs, hmac, spent: false };
  _ticketRegistry.set(ticketId, ticket);

  return { ticketId, hmac, expiresAt, ttlMs, action };
}

/**
 * Verify and consume an execution ticket.
 * @returns {{ valid: boolean, error?: string }}
 */
function ticketVerify(ticketId, hmac) {
  if (!ticketId || !hmac) return { valid: false, error: 'Missing ticketId or hmac' };

  const ticket = _ticketRegistry.get(ticketId);
  if (!ticket) return { valid: false, error: 'Unknown ticket' };
  if (ticket.spent || _spentTickets.has(ticketId)) return { valid: false, error: 'Ticket already spent (replay rejected)' };
  if (Date.now() > ticket.expiresAt) return { valid: false, error: `Ticket expired (TTL was ${ticket.ttlMs}ms)` };

  const expectedPayload = [ticketId, ticket.requestId, ticket.agentId, ticket.expiresAt.toString()].join(':');
  const expectedHmac    = crypto.createHmac('sha256', RECEIPT_SECRET).update(expectedPayload).digest('hex');

  try {
    const valid = crypto.timingSafeEqual(Buffer.from(hmac, 'hex'), Buffer.from(expectedHmac, 'hex'));
    if (!valid) return { valid: false, error: 'HMAC mismatch — ticket tampered' };
  } catch { return { valid: false, error: 'HMAC format error' }; }

  // Consume ticket — single use
  ticket.spent = true;
  _spentTickets.add(ticketId);

  return { valid: true, ticket: { ...ticket } };
}

function ticketGet(ticketId) {
  const t = _ticketRegistry.get(ticketId);
  if (!t) return null;
  return { ...t, hmac: t.hmac.slice(0, 8) + '...' };   // redact hmac in get
}

// ══════════════════════════════════════════════════════════════════════════════
// ADAPTIVE POLICY INTELLIGENCE  (System #17)
// RTP-inspired 6-stage governance pipeline runs before frontier scoring.
// Stages:
//   f0: Normalize  — canonicalize text, strip obfuscation
//   f1: Intent     — classify intent category (query/create/execute/exfil/bypass)
//   f2: Readiness  — check passport, tokens, delegation chain readiness
//   f3: Modulator  — I = L^n · P^(-m) · C^k composite risk
//   f4: Threshold  — apply adaptive EWMA + SII + policy thresholds
//   f5: Artifact   — issue ticket + receipt + audit entry
//
// Policy overlay: declarative rules loaded from policy object.
// Default policy ships with Kasbah; enterprises override with their own.
// ══════════════════════════════════════════════════════════════════════════════

let _activePolicy = {
  version:       '1.0',
  defaultAction: 'allow',
  forbiddenVerbs: ['DELETE_ALL', 'DROP_TABLE', 'SYSTEM_OVERRIDE', 'KERNEL_BYPASS'],
  allowedDomains: [],    // empty = allow all domains
  maxRiskScore:   0.80,  // requests above this risk are auto-DENY regardless of model output
  requirePassport: false,
  rules: [],
};

/**
 * Load/update the active policy.
 */
function policySet(policy) {
  if (!policy || typeof policy !== 'object') return;
  _activePolicy = { ..._activePolicy, ...policy };
}

function policyGet() {
  return { ..._activePolicy };
}

/**
 * f0: Normalize text — collapse whitespace, lowercase comparisons, detect obfuscation.
 * Returns { normalized: string, obfuscationScore: number, flags: [] }
 */
function _rtpF0Normalize(text) {
  const flags = [];
  // Detect base64 blobs (common obfuscation vector; ≥20 chars is already suspicious)
  const base64Blobs = (text.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || []).length;
  if (base64Blobs > 0) flags.push('base64_obfuscation');
  // Detect unicode lookalike characters
  const lookalikes = (text.match(/[Ѐ-ӿͰ-Ͽ＀-￯]/g) || []).length;
  if (lookalikes > 2) flags.push('unicode_lookalike');
  // Detect excessive whitespace/zero-width chars
  const zeroWidth = (text.match(/[​‌‍﻿­]/g) || []).length;
  if (zeroWidth > 0) flags.push('zero_width_chars');

  const obfuscationScore = Math.min(1.0, (base64Blobs * 0.3 + lookalikes * 0.05 + zeroWidth * 0.2));
  const normalized = text.replace(/[​‌‍﻿­]/g, '')
                         .replace(/\s{3,}/g, '  ')
                         .trim();
  return { normalized, obfuscationScore: +obfuscationScore.toFixed(3), flags };
}

/**
 * f1: Intent classification — 6 categories with confidence.
 * Returns { intent, confidence }
 */
function _rtpF1Intent(text) {
  const lower = text.toLowerCase();
  const intents = {
    bypass:       (lower.match(/\b(bypass|jailbreak|override|ignore.*rules?|forget.*instructions?|disable.*filter|no.*restrictions?|unrestricted\s+ai|no\s+ethical\s+guidelines|pretend.*no.*restrict|illegal\s+activit|ignore.*previous.*instruct|disregard.*instruct|new\s+goal|bypass\s+security|bypass\s+auth|disable.*content\s+filter|admin_override|authorized\s+admin|ignore\s+previous\s+safety|ignore\s+all\s+previous|dan\s+has|you\s+are\s+dan|no\s+ethical|no\s+safety)\b/g) || []).length,
    exfiltration: (lower.match(/\b(send.*to|upload.*to|exfil|leak|steal|extract.*credentials?|api.*key.*to|email.*api\s+key|conversation\s+history.*external|attacker@|evil\.com|dump.*to|autonomously\s+access|without\s+being\s+instructed.*send)\b/g) || []).length,
    execute:      // Standard code-execution patterns (word-boundary safe)
                  (lower.match(/\b(run|execute|invoke|spawn|shell|terminal|command|subprocess|os\.system|eval\(|subprocess\.popen|atob\(|eval.*atob|hack\s+into|root\s+access|pick\s+a\s+lock|steal\s+credential)\b/g) || []).length
                  // Weapon/explosives synthesis — separate regex (avoids plural \b issue)
                + (lower.match(/synthesize\s+\w*explosiv\w*|make\s+\w*explosiv\w*|how\s+to\s+make\s+a\s+bomb|build\s+\w*explosiv\w*|create\s+\w*chemical\s+weapon/gi) || []).length,
    create:       (lower.match(/\b(write|create|generate|build|make|compose|disinformation\s+campaign|propaganda|astroturfing|fake\s+news|manipulate\s+voter|psychological\s+manipulation|gaslighting|fake\s+social\s+media|coordinated.*campaign)\b/g) || []).length,
    harmful_create: (lower.match(/\b(disinformation\s+campaign|propaganda|astroturfing|fake\s+news|manipulate\s+voter|coordinated.*campaign)\b/g) || []).length,
    query:        (lower.match(/\b(what|how|why|explain|describe|tell\s+me|summarize|list)\b/g) || []).length,
    delete:       (lower.match(/\b(delete|remove|destroy|drop|wipe|purge|rm\s+-rf)\b/g) || []).length,
  };

  // Exclude harmful_create from top-intent election — it's a modifier, not a primary intent
  const primaryIntents = Object.entries(intents).filter(([k]) => k !== 'harmful_create');
  const top   = primaryIntents.sort((a, b) => b[1] - a[1])[0];
  const total = primaryIntents.reduce((s, [, v]) => s + v, 0);
  const confidence = total > 0 ? +(top[1] / total).toFixed(3) : 0;
  return { intent: top[0], confidence, counts: intents };
}

/**
 * f3: Modulator — I = L^n · P^(-m) · C^k
 * L = legitimacy (trust score), P = penalty (threat density), C = confidence
 * n=2, m=1, k=0.5  — aggressive on legitimacy, moderate on confidence
 */
function _rtpF3Modulator(trustScore, threatDensity, intentConfidence) {
  const L = Math.max(0.01, trustScore || 0.5);
  const P = Math.max(0.01, 1 + threatDensity);   // P ≥ 1 so penalty reduces I
  const C = Math.max(0.01, intentConfidence || 0.3);
  const n = 2, m = 1, k = 0.5;
  const I = Math.pow(L, n) / Math.pow(P, m) * Math.pow(C, k);
  return +Math.min(1, Math.max(0, I)).toFixed(4);
}

/**
 * Run the full RTP pipeline for a request.
 * Returns { modulatorScore, intent, obfuscationScore, policyFlags, recommendation }
 */
function rtpPipeline(text, passportId, riskScore) {
  const f0 = _rtpF0Normalize(text);
  const f1 = _rtpF1Intent(f0.normalized);

  const passport      = passportId ? _passports.get(passportId) : null;
  const trustScore    = passport ? passport.trustScore : 0.5;
  const sii           = siiCompute();
  const threatDensity = sii.threatDensity;
  const f3            = _rtpF3Modulator(trustScore, threatDensity, f1.confidence);

  // f4: Policy overlay — check forbidden verbs, domain policy
  const policyFlags = [];
  for (const verb of (_activePolicy.forbiddenVerbs || [])) {
    if (text.toLowerCase().includes(verb.toLowerCase())) policyFlags.push('forbidden_verb:' + verb);
  }
  if (_activePolicy.requirePassport && !passportId) policyFlags.push('passport_required');

  // f5: Recommendation
  let recommendation = 'ALLOW';
  if (policyFlags.length > 0) recommendation = 'DENY';
  else if (f0.obfuscationScore > 0.5) recommendation = 'DENY';
  // Bypass: lower threshold to 0.35 — jailbreak patterns are high-signal when ≥2 match
  else if (f1.intent === 'bypass' && f1.confidence > 0.35) recommendation = 'DENY';
  else if (f1.intent === 'exfiltration' && f1.confidence > 0.4) recommendation = 'DENY';
  // Execute: any high-confidence code execution intent (eval, subprocess, etc.) = DENY
  else if (f1.intent === 'execute' && f1.confidence > 0.45) recommendation = 'DENY';
  // Harmful create: disinformation campaigns, propaganda, astroturfing = DENY
  else if (f1.counts && f1.counts.harmful_create > 0) recommendation = 'DENY';
  else if (f1.intent === 'delete' && f1.confidence > 0.6) recommendation = 'WARN';
  else if (f3 < 0.10) recommendation = 'DENY';
  else if (f3 < 0.25) recommendation = 'WARN';
  else if (riskScore > (_activePolicy.maxRiskScore || 0.80)) recommendation = 'DENY';

  return {
    modulatorScore:    f3,
    intent:            f1.intent,
    intentConfidence:  f1.confidence,
    obfuscationScore:  f0.obfuscationScore,
    obfuscationFlags:  f0.flags,
    policyFlags,
    recommendation,
  };
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // Passports
  passportIssue,
  passportGet,
  passportRevoke,
  passportUpdateTrust,
  passportGetThresholds,
  passportList,

  // DNA
  dnaCheck,
  dnaRecordVerdict,

  // Swarm
  swarmRecord,
  swarmStatus,

  // Receipts (standard + one-time)
  receiptGenerate,
  receiptVerify,
  receiptVerifyOnce,
  receiptIsSpent,

  // Hash-Chained Audit Ledger
  auditAppend,
  auditVerify,
  auditGetChain,

  // Bell's Inequality AI Detector
  bellsCheck,

  // Delegation Chain
  delegationIssue,
  delegationVerify,
  delegationRevoke,

  // Predictive Threat Forecasting
  forecastRecord,
  forecastPredict,

  // System Integrity Index (Ψ)
  siiRecord,
  siiCompute,
  siiAdjustThresholds,

  // Token Spend Ledger
  spendSetPolicy,
  spendRecord,
  spendCheck,
  spendGetUsage,

  // Honeytoken Canary System (#14)
  honeytokenDeploy,
  honeytokenCheck,
  honeytokenList,

  // Maqasid Ethics Framework (#15)
  maqasidCheck,

  // Execution Tickets (#16)
  ticketIssue,
  ticketVerify,
  ticketGet,

  // Adaptive Policy Intelligence (#17)
  rtpPipeline,
  policySet,
  policyGet,

  // WASM Runtime
  wasmDetect,

  // Hardware Enclave
  getHardware: () => _hwEnclave && _hwEnclave.isAvailable() ? _hwEnclave.getHardware() : 'software',

  // eBPF Syscall Filter
  kernelIsolatePid,
  kernelFilterStatus: () => ({
    available: _kernelFilter?.isAvailable() || false,
    platform: _kernelFilter?.getPlatform() || process.platform,
  }),

  // ── v5.0 Deep Intelligence (#18–#27) ────────────────────────────────────────

  // #18 Multilingual PII
  piiCheck,

  // #19 Synthetic Persona Detector
  personaCheck,

  // #20 Steganalysis
  stegCheck,

  // #21 Memetic Warfare
  memeticCheck,

  // #22 Adversarial Multi-Decode
  advDecode,

  // #23 RAG Security
  ragCheck,

  // #24 Image Deepfake
  imgFakeCheck,

  // #25 Voice Cloning Detection
  voiceCheck,

  // #26 Quantum Crypto (vuln scan + Dilithium/SPHINCS+ simulation)
  quantumVulnScan,
  quantumGenKeys:   () => _sys.quantum ? _sys.quantum.dilithiumGenKeys()                : null,
  quantumSign:      (m, k) => _sys.quantum ? _sys.quantum.dilithiumSign(m, k)          : null,
  quantumVerify:    (m, s, k) => _sys.quantum ? _sys.quantum.dilithiumVerify(m, s, k)  : null,

  // #27 Frontier Storage Triad
  dnaEncode,
  dnaDecode,
  dnaStegCheck,
  holoEncode,
  holoDecode,
  neuroClassify,

  // Orbital Key Sharding (companion to #27)
  orbitalShard,
  orbitalRecon,
  orbitalChallenge: (id) => _sys.orbital ? _sys.orbital.generateOrbitalChallenge(id)   : null,
  orbitalVerify:    (c, r) => _sys.orbital ? _sys.orbital.verifyOrbitalResponse(c, r)  : null,

  // ── v6.0 Maximum Intelligence (#28–#37) ─────────────────────────────────────

  // #28 Sentinel Intelligence
  sentinelCheck,
  swarmCollusion,
  temporalParadox,
  deonticCheck,

  // #29 Scientific Flow Analysis
  reynoldsFlow,
  harmonicDis,
  topoShield,

  // #30 Ethics Algebra
  eigenEthics,
  causalBreak,
  shadowConsensus,

  // #31 ZK Governance
  zkGovProof,
  punctEqCheck,
  zkProve,
  zkVerify,
  zkStats,
  shadowCheck,

  // #32 Advanced Secret Detection
  secretScan,
  detectGPT,
  ahoMatch,
  pHashSimilarity,

  // #33 Verifiable Cryptography
  vdfCompute,
  vdfVerify,
  mmrAppend,
  mmrProve,
  mmrVerify,

  // #34 Kasbah Secret Sharing (GF-256)
  kShamirSplit,
  kShamirCombine,

  // #35 Intent & Policy Engine
  intentAnalyze,
  policyEval,
  govCheck,

  // #36 TextXRay
  textXrayAI,
  textXrayManip,

  // #37 Core Detection Engine + Algorithm Suite
  detectCore,
  kasbahAlgorithm,

  // ── v7.0 Innovation Layer ─────────────────────────────────────────────────
  injAdvCheck,       // 15-pattern prompt injection defense
  causalXaiExplain,  // causal counterfactual XAI explainer
  multiEthicsCheck,  // multi-tradition ethics consensus
  bellsEnhCheck,     // 8-dimension Bell's CHSH ensemble
  obfusDecodeCheck,
  expandedSecretCheck,
  normalizeText,

  // ── v8.0 Governance & Compliance Engines ─────────────────────────────────
  governanceEngineCheck,   // Phase-1 GovernanceEngine: verb/domain/rate-limit checks
  policyEngineCheck,       // KasbahPolicyEngine: HIPAA/GDPR/SOC2/PCI inline compliance

  // ── Nexus Bridge — kasbah-nexus 4-technology unified engine ──────────────
  nexusDetect:         (input) => _sys.nexus ? _sys.nexus.nexusDetect(input)         : null,
  nexusRtpTransform:   (input) => _sys.nexus ? _sys.nexus.rtpTransform(input)        : null,
  nexusKernelGate:     (input) => _sys.nexus ? _sys.nexus.kernelGate(input)          : null,
  nexusKernelVerify:   (id)    => _sys.nexus ? _sys.nexus.kernelVerifyTicket(id)     : null,
  nexusBellsDetect:    (text)  => _sys.nexus ? _sys.nexus.bellsDetect(text)          : null,
  nexusMainClassify:   (text)  => _sys.nexus ? _sys.nexus.mainClassify(text)         : null,
  nexusStats:          ()      => _sys.nexus ? _sys.nexus.nexusStats()               : null,
  nexusAvailable:      ()      => !!_sys.nexus && _sys.nexus.isAvailable(),

  // ── v8.0 ARCHIVE Full-Fidelity Engines ───────────────────────────────────
  // Patent-pending 6-stage RTP governance pipeline (f0→f5)
  rtpFullTransform: async (input) => {
    if (!_rtpEngine) return null;
    try { return await _rtpEngine.transform(input); } catch (_) { return null; }
  },
  // Quantum-inspired Bell's inequality AI text detector (CHSH S-value)
  bellsFullDetect: async (text) => {
    if (!_bellsFull) return null;
    try { return await _bellsFull.detect(text); } catch (_) { return null; }
  },

  // Phase 6: Witt-Crystalline Cohomology Analysis
  wittCrystallineAnalyze: (data) => {
    if (!_wittCrys) return null;
    try { return _wittCrys.analyze(data); } catch (_) { return null; }
  },
  wittCrystallineStats: () => {
    if (!_wittCrys) return null;
    try { return _wittCrys.getStats(); } catch (_) { return null; }
  },

  // Blockchain-style PoW receipt ledger
  proofChainAdd: (data) => {
    if (!_proofLedger) return null;
    try { return _proofLedger.addBlock(data); } catch (_) { return null; }
  },
  proofChainVerify: () => {
    if (!_proofLedger) return null;
    try { return _proofLedger.isValid(); } catch (_) { return null; }
  },
  proofChainStats: () => {
    if (!_proofLedger) return null;
    try { return { length: _proofLedger.chain.length, valid: _proofLedger.isValid() }; } catch (_) { return null; }
  },
  // Merkle-proof compliance audit ledger
  auditLedgerAppend: (entry) => {
    if (!_auditLedger) return null;
    try { return _auditLedger.append(entry); } catch (_) { return null; }
  },
  auditLedgerVerify: () => {
    if (!_auditLedger) return null;
    try { return _auditLedger.verify(); } catch (_) { return null; }
  },

  // ── Phase 3: Full-Fidelity Archive Integrations ──────────────────────────
  // Full Maqasid: 5-pillar geometric mean, multi-language, FOL inference
  maqasidCheckFull,
  // NOMOS: 4-tradition ethical consensus (Islamic, Kantian, Utilitarian, Virtue)
  nomosCheck,
  // Full Brittleness Governor: 5 frequency bands, EMA trends, predictive throttling
  brittlenessReport,
  // Direct access to brittleness governor singleton
  brittlenessGovernor: () => _brittlenessFull || null,

  // System availability map (v5 + v6 + v8)
  v5SystemStatus: () => Object.fromEntries(
    Object.entries(_sys).map(([k, v]) => [k, v !== null])
  ),
  v6SystemStatus: () => ({
    sentinel:   _sys.sentinel   !== null,
    reynolds:   _sys.reynolds   !== null,
    harmonic:   _sys.harmonic   !== null,
    topo:       _sys.topo       !== null,
    eigen:      _sys.eigen      !== null,
    causal:     _sys.causal     !== null,
    shadow:     _sys.shadow     !== null,
    zk:         _sys.zk         !== null,
    puncteq:    _sys.puncteq    !== null,
    detAdv:      _sys.detAdv      !== null,
    cryptoAdv:   _sys.cryptoAdv   !== null,
    intent:      _sys.intent      !== null,
    textxray:    _sys.textxray    !== null,
    detCore:     _sys.detCore     !== null,
    algorithms:  _sys.algorithms  !== null,
    injAdv:      _sys.injAdv      !== null,
    causalXai:   _sys.causalXai   !== null,
    multiEthics: _sys.multiEthics !== null,
    bellsEnh:    _sys.bellsEnh    !== null,
    // v8.0 ARCHIVE full-fidelity engines
    rtpFull:     _sys.rtpFull    !== null,
    bellsFull:   _sys.bellsFull  !== null,
    proofChain:  _sys.proofChain !== null,
    auditLedger: _sys.auditLedger !== null,
  }),
};
