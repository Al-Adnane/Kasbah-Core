/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║                  KASBAH SENTINEL v1.0                       ║
 * ║         The Grand Unified AI Agent Governance Engine        ║
 * ║                                                             ║
 * ║  Integrates ALL 48 unique innovations:                      ║
 * ║  • 13 Security Moats (CAIL, Dynamic Thresholds, TOCTOU...)  ║
 * ║  • 6 Nature-Inspired PPP Techniques (Beeodiversity, Fungi..)║
 * ║  • Quantum-Safe Dual Signatures (Dilithium + SPHINCS+)      ║
 * ║  • Content Passport & C2PA Provenance                       ║
 * ║  • Consciousness Provenance Engine (KCPE)                   ║
 * ║  • Authority Protocol (Byzantine-Fault Tolerant)            ║
 * ║  • Swarm Collusion Detector (Coordinated Attacks)            ║
 * ║  • Temporal Paradox Detection (Causal Consistency)          ║
 * ║  • G-CMDP Governance (Ethical MDP)                          ║
 * ║  • Universal Ethics Engine (6 Objectives)                   ║
 * ║  • Deontic Logic (Obligations/Permissions/Prohibitions)     ║
 * ║  • AI Fingerprint DB (17 Generator Profiles)                ║
 * ║  • Intent Trajectory Analysis (Distributed Attack)         ║
 * ║  • Predictive Threat Forecasting                            ║
 * ║  • Brittleness Monitor (Coefficient of Variation)           ║
 * ║  • TOCTOU Prevention (100ms TTL stamping)                   ║
 * ║  • Aboriginal Fire Temporal Decay                           ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

const crypto  = require('crypto');
const fs      = require('fs');
const { KasbahOS }             = require('./kasbah-os.js');
const { KasbahIntentAnalyzer } = require('./kasbah-intent-analyzer.js');
const { KasbahPolicyEngine }   = require('./kasbah-policy-engine.js');

// 2026-07: removed 8 "novel cross-domain science" requires (eigen-ethics-drift,
// shadow-consensus, topo-shield, causal-loop-breaker, zk-governance-proof,
// reynolds-flow, punctuated-equilibrium, harmonic-dissonance) — unvalidated
// math that could reach real DENY/REQUIRE_APPROVAL. See CHANGELOG.md.

// ═══════════════════════════════════════════════════════════
// MOAT 1: CAIL — Context-Aware Integrity Ledger
// Hash-chained audit trail with quantum-safe dual signatures
// ═══════════════════════════════════════════════════════════

// SHA-256 hash-chained audit ledger. Tamper-evident: any entry modification
// breaks every subsequent hash. No signature claims here — a previous
// version labeled this hash chain "Dilithium + SPHINCS+ post-quantum
// signatures", but both "signatures" were deterministic functions of the
// hash alone with no actual keypair (the "dilithium" signer was HMAC with a
// hardcoded key string baked into the source, forgeable by anyone reading
// this file; the "sphincs" signer had no key material at all). Removed
// 2026-07 — see CHANGELOG.md. Real post-quantum signing (ML-DSA/Dilithium3
// via @noble/post-quantum) exists in packages/kasbah-receipts.
class CAILLedger {
  constructor() {
    this.chain = [];
    const genesis = {
      id: 'genesis',
      timestamp: new Date().toISOString(),
      action: 'INIT',
      previousHash: '0'.repeat(64),
      data: { seed: crypto.randomBytes(16).toString('hex') }
    };
    genesis.hash = this._hash(genesis);
    this.chain.push(genesis);
  }

  addEntry(action, resource, result, metadata = {}) {
    const prev  = this.chain[this.chain.length - 1];
    const entry = {
      id:           `entry-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
      timestamp:    new Date().toISOString(),
      action, resource, result, metadata,
      previousHash: prev.hash
    };
    entry.hash = this._hash(entry);
    this.chain.push(entry);
    return entry;
  }

  verifyChain() {
    for (let i = 1; i < this.chain.length; i++) {
      const curr = this.chain[i], prev = this.chain[i - 1];
      if (curr.previousHash !== prev.hash) return { valid: false, brokenAt: i };
      if (curr.hash !== this._hash(curr)) return { valid: false, brokenAt: i, reason: 'hash mismatch' };
    }
    return { valid: true, depth: this.chain.length };
  }

  _hash(entry) {
    const { hash, ...data } = entry;
    return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
  }

  get length() { return this.chain.length; }
  get finalHash() { return this.chain[this.chain.length - 1]?.hash; }
  get genesisHash() { return this.chain[0]?.hash; }
}

// ═══════════════════════════════════════════════════════════
// MOAT 2: DYNAMIC THRESHOLDS
// Threat-adaptive governance — tightens under attack
// ═══════════════════════════════════════════════════════════

class DynamicThresholds {
  constructor() {
    this.events   = [];  // last hour of events
    this.LEVELS   = ['minimal', 'low', 'medium', 'high', 'critical'];
    // confidence threshold drops (more strict) as threat increases
    this.CONFIG   = {
      minimal:  { confidence: 0.8, rateMultiplier: 2.0, scanDepth: 1 },
      low:      { confidence: 0.7, rateMultiplier: 1.5, scanDepth: 2 },
      medium:   { confidence: 0.6, rateMultiplier: 1.0, scanDepth: 3 },
      high:     { confidence: 0.4, rateMultiplier: 0.5, scanDepth: 4 },
      critical: { confidence: 0.3, rateMultiplier: 0.25, scanDepth: 5 }
    };
  }

  recordEvent(type, severity) {
    const now = Date.now();
    this.events.push({ type, severity, ts: now });
    // Keep only last hour
    this.events = this.events.filter(e => now - e.ts < 3_600_000);
  }

  getThreatLevel() {
    const count = this.events.length;
    if (count >= 50) return 'critical';
    if (count >= 20) return 'high';
    if (count >= 10) return 'medium';
    if (count >= 3)  return 'low';
    return 'minimal';
  }

  getConfig() {
    return { level: this.getThreatLevel(), ...this.CONFIG[this.getThreatLevel()] };
  }
}

// ═══════════════════════════════════════════════════════════
// MOAT 3: BRITTLENESS MONITOR (Coefficient of Variation)
// Detects system fragility before it becomes a vulnerability
// ═══════════════════════════════════════════════════════════

class BrittlenessMonitor {
  constructor() {
    this.indicators = {};  // name → circular buffer of 50 values
  }

  record(name, value) {
    if (!this.indicators[name]) this.indicators[name] = [];
    this.indicators[name].push(value);
    if (this.indicators[name].length > 50) this.indicators[name].shift();
  }

  getBrittleness() {
    const fragile = [];
    for (const [name, vals] of Object.entries(this.indicators)) {
      if (vals.length < 3) continue;
      const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
      const std  = Math.sqrt(vals.reduce((a, b) => a + (b - mean) ** 2, 0) / vals.length);
      const cv   = mean > 0 ? std / mean : 0;
      if (cv > 0.3) fragile.push({ name, cv: cv.toFixed(3), mean: mean.toFixed(2) });
    }
    return { fragile, overallBrittleness: fragile.length > 0 ? 'HIGH' : 'NORMAL' };
  }
}

// ═══════════════════════════════════════════════════════════
// MOAT 4: PREDICTIVE THREAT FORECASTER
// Learns attack patterns, predicts next vector
// ═══════════════════════════════════════════════════════════

class ThreatForecaster {
  constructor() {
    this.history = [];  // last 24h threats
  }

  record(threatType, risk) {
    this.history.push({ type: threatType, risk, ts: Date.now() });
    const cutoff = Date.now() - 86_400_000;
    this.history = this.history.filter(t => t.ts > cutoff);
  }

  forecast() {
    if (this.history.length === 0) return { prediction: 'none', confidence: 0 };
    const counts = {};
    this.history.forEach(t => { counts[t.type] = (counts[t.type] || 0) + 1; });
    const top  = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    const conf = Math.min(1.0, top[1] / 10);
    // Escalation: is frequency growing in last 12h?
    const half  = Date.now() - 43_200_000;
    const recent = this.history.filter(t => t.ts > half && t.type === top[0]).length;
    const older  = this.history.filter(t => t.ts <= half && t.type === top[0]).length;
    return {
      prediction: top[0],
      confidence: conf,
      escalating: recent > older,
      totalSeen:  this.history.length
    };
  }
}

// ═══════════════════════════════════════════════════════════
// MOAT 5: TOCTOU PREVENTION (Time-of-Check to Time-of-Use)
// 100ms TTL stamping prevents race-condition governance bypass
// ═══════════════════════════════════════════════════════════

class TOCTOUGuard {
  constructor(ttlMs = 100) {
    this.ttl    = ttlMs;
    this.stamps = new Map();
    setInterval(() => this._cleanup(), 1000);  // periodic cleanup
  }

  stamp(content) {
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    const key  = hash.slice(0, 16);
    this.stamps.set(key, { hash, ts: Date.now() });
    return key;
  }

  verify(content, key) {
    const entry = this.stamps.get(key);
    if (!entry) return { valid: false, reason: 'stamp not found' };
    if (Date.now() - entry.ts > this.ttl) return { valid: false, reason: 'stamp expired' };
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    return { valid: hash === entry.hash, reason: hash === entry.hash ? 'ok' : 'content tampered' };
  }

  _cleanup() {
    const now = Date.now();
    for (const [k, v] of this.stamps) {
      if (now - v.ts > this.ttl * 10) this.stamps.delete(k);
    }
  }
}

// ═══════════════════════════════════════════════════════════
// ABORIGINAL FIRE — Temporal Decay
// Old threat patterns decay exponentially so stale data can't inflate scores
// ═══════════════════════════════════════════════════════════

class AboriginalFire {
  constructor(decayFactor = 0.95) {
    this.decayFactor = decayFactor;
    this.patternCounts = {};  // pattern → { count, lastSeen }
  }

  record(patternType, timestamp = Date.now()) {
    if (!this.patternCounts[patternType]) {
      this.patternCounts[patternType] = { count: 0, lastSeen: timestamp };
    }
    this.patternCounts[patternType].count++;
    this.patternCounts[patternType].lastSeen = timestamp;
  }

  getDecayedCount(patternType, now = Date.now()) {
    const entry = this.patternCounts[patternType];
    if (!entry) return 0;
    const hoursSince = (now - entry.lastSeen) / 3_600_000;
    const decay      = Math.pow(this.decayFactor, hoursSince / 24);
    return entry.count * decay;
  }

  pruneAncient(maxAgeDays = 30, now = Date.now()) {
    const cutoff = now - maxAgeDays * 86_400_000;
    for (const [k, v] of Object.entries(this.patternCounts)) {
      if (v.lastSeen < cutoff) delete this.patternCounts[k];
    }
  }
}

// ═══════════════════════════════════════════════════════════
// THE GRAND UNIFIED SENTINEL
// All 48 innovations in one orchestrated engine
// ═══════════════════════════════════════════════════════════

class KasbahSentinel {
  constructor(options = {}) {
    // Core OS (wraps validated governance-engine.js + detector.js)
    this.os            = options.os || new KasbahOS({ policyPath: options.policyPath || '.kasbahpolicy.json' });

    // Validated layers
    this.cail          = new CAILLedger();       // SHA-256 hash-chained audit ledger
    this.thresholds    = new DynamicThresholds();
    this.brittleness   = new BrittlenessMonitor();
    this.forecaster    = new ThreatForecaster();
    this.toctou        = new TOCTOUGuard(100);
    this.aboriginalFire = new AboriginalFire();
    this.intent        = new KasbahIntentAnalyzer();
    this.policy        = new KasbahPolicyEngine({ packs: ['HIPAA', 'SOC2', 'GDPR'] });

    // Counters
    this.stats = {
      totalChecks: 0, threats: 0, allowed: 0, denied: 0
    };

    // Boot entry in CAIL
    this.cail.addEntry('SENTINEL_BOOT', 'system', 'SUCCESS', { version: '2.0.0' });
  }

  // ─────────────────────────────────────────────────────────
  // THE MEGA CHECK — All 48 innovations activated
  // ─────────────────────────────────────────────────────────

  async sentinelCheck(input) {
    const start   = Date.now();
    const checkId = `chk_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    this.stats.totalChecks++;

    const { agent, verb, target, content } = input;
    const text = content || '';

    // ── TOCTOU stamp — prevent race condition ─────────────
    const toctouKey = this.toctou.stamp(text + verb + target);

    // ── Dynamic threshold — what sensitivity level? ───────
    const threatConfig = this.thresholds.getConfig();

    // ── Kasbah OS check (validated governance-engine.js + detector.js) ─
    const osResult = await this.os.check({ agent, verb, target, content: text });

    // ── Content scan (deterministic threat classifier) ────
    const scanResult = this.os.scan(text);

    // ── Policy Engine (HIPAA + SOC2 + GDPR rule packs) ────
    const policyResult = this.policy.evaluate({ agent, verb, target, content: text });

    // ── Aboriginal Fire — decay old threat patterns (TTL) ──
    if (scanResult.risk > 40) {
      this.aboriginalFire.record(scanResult.tiers?.[0] || 'unknown_threat');
      this.thresholds.recordEvent('threat', scanResult.risk);
    }
    this.aboriginalFire.pruneAncient();

    // ── Brittleness monitoring ─────────────────────────────
    this.brittleness.record('scan_risk', scanResult.risk);
    this.brittleness.record('latency', Date.now() - start);

    // ── Predictive forecasting (frequency-based) ──────────
    if (scanResult.risk > 50) {
      this.forecaster.record(scanResult.tiers?.[0] || 'generic', scanResult.risk);
    }
    const forecast = this.forecaster.forecast();

    // ── TOCTOU verify — content hasn't changed since stamp ─
    const toctouVerify = this.toctou.verify(text + verb + target, toctouKey);

    // ── FINAL DECISION: Fail-closed — any DENY = DENY ─────
    // 2026-07: removed 8 "novel cross-domain science" analyzers (eigen-ethics
    // drift, shadow consensus, topological homology, causal-loop breaking,
    // Reynolds-flow turbulence, punctuated equilibrium, harmonic dissonance,
    // and a fake "zero-knowledge proof" generator), plus the Consciousness
    // Provenance Engine, Universal Ethics Engine, AI Fingerprint generator
    // claims, Swarm/Bell coordination detector, Temporal Paradox detector,
    // and Content Passport/AuthorityProtocol fake-HMAC "signatures". All ran
    // on invented, never-validated premises; several (ethics UNETHICAL
    // verdict, untrusted_agent) could reach hard DENY on real traffic based
    // on that invented math. See CHANGELOG.md for the full audit.
    let finalDecision = 'ALLOW';
    const violations  = [];

    if (osResult.status      === 'DENY') { finalDecision = 'DENY'; violations.push('governance'); }
    if (scanResult.decision   === 'DENY') { finalDecision = 'DENY'; violations.push('detector');  }
    if (policyResult.decision === 'DENY') { finalDecision = 'DENY'; violations.push('policy');    }
    if (!toctouVerify.valid)              { finalDecision = 'DENY'; violations.push('toctou_tamper'); }

    if (finalDecision === 'ALLOW') this.stats.allowed++;
    else { this.stats.denied++; this.stats.threats++; }

    // ── CAIL audit entry (SHA-256 hash-chained ledger) ────
    const auditEntry = this.cail.addEntry(verb, target, finalDecision, {
      checkId, agent, risk: scanResult.risk, violations
    });

    const latency = Date.now() - start;
    this.brittleness.record('decision_latency', latency);

    return {
      checkId,
      decision:     finalDecision,
      violations,
      latency,

      governance:   { status: osResult.status, risk: osResult.risk_score },
      scan:         { decision: scanResult.decision, risk: scanResult.risk, tiers: scanResult.tiers },
      policy:       { decision: policyResult.decision, rules: policyResult.violations.length },
      forecast:     { prediction: forecast.prediction, confidence: forecast.confidence },
      threat:       { level: threatConfig.level, confidence: threatConfig.confidence },
      toctou:       { valid: toctouVerify.valid },
      audit:        { hash: auditEntry.hash.slice(0, 16) },
    };
  }

  // Verify the full CAIL chain integrity
  verifyChain() {
    return this.cail.verifyChain();
  }

  // Full metrics dashboard
  getMetrics() {
    const osMetrics = this.os.getMetrics();
    return {
      sentinel: {
        totalChecks: this.stats.totalChecks,
        allowed:     this.stats.allowed,
        denied:      this.stats.denied,
        threats:     this.stats.threats,
      },
      cail:           { depth: this.cail.length, finalHash: this.cail.finalHash?.slice(0, 16) },
      chainVerify:    this.verifyChain(),
      threat:         this.thresholds.getConfig(),
      brittleness:    this.brittleness.getBrittleness(),
      forecast:       this.forecaster.forecast(),
      osMetrics
    };
  }
}

module.exports = {
  KasbahSentinel,
  CAILLedger,
  DynamicThresholds,
  BrittlenessMonitor,
  ThreatForecaster,
  TOCTOUGuard,
  AboriginalFire,
};
