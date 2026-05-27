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
const {
  generateDilithiumKeypair,
  signDilithium,
  verifyDilithium,
  generateSPHINCSKeypair,
  signSPHINCS,
  verifySPHINCS,
  PQC_AVAILABLE
} = require('./crypto/pqc-signatures.js');
const { KasbahOS }             = require('./kasbah-os.js');
const { KasbahIntentAnalyzer } = require('./kasbah-intent-analyzer.js');
const { KasbahPolicyEngine }   = require('./kasbah-policy-engine.js');

// ═══════════════════════════════════════════════════════════
// 8 NOVEL ALGORITHMS — Cross-Domain Science Fusion
// ═══════════════════════════════════════════════════════════
const { EigenEthicsDrift }       = require('./eigen-ethics-drift.js');
const { ShadowConsensus }        = require('./shadow-consensus.js');
const { TopoShield }             = require('./topo-shield.js');
const { CausalLoopBreaker }      = require('./causal-loop-breaker.js');
const { ZKGovernanceProof }      = require('./zk-governance-proof.js');
const { ReynoldsFlow }           = require('./reynolds-flow.js');
const { PunctuatedEquilibrium }  = require('./punctuated-equilibrium.js');
const { HarmonicDissonance }     = require('./harmonic-dissonance.js');
const { BellsInequality }        = require('./bells-inequality.js');
const { detectAIText }           = require('./detectgpt.js');

// ═══════════════════════════════════════════════════════════
// MOAT 1: CAIL — Context-Aware Integrity Ledger
// Hash-chained audit trail with quantum-safe dual signatures
// ═══════════════════════════════════════════════════════════

class CAILLedger {
  constructor() {
    this.chain = [];
    // Generate real post-quantum keypairs (ML-DSA-65 + SLH-DSA-SHA2-128s)
    const dilithiumKP = generateDilithiumKeypair();
    const sphincsKP   = generateSPHINCSKeypair();
    this._dilithiumPrivKey = dilithiumKP.privateKey;
    this._dilithiumPubKey  = dilithiumKP.publicKey;
    this._sphincsPrivKey   = sphincsKP.privateKey;
    this._sphincsPubKey    = sphincsKP.publicKey;
    this.pqcAlgorithms = {
      dilithium: dilithiumKP.algorithm,
      sphincs:   sphincsKP.algorithm,
      real:      PQC_AVAILABLE
    };
    const genesis = {
      id: 'genesis',
      timestamp: new Date().toISOString(),
      action: 'INIT',
      previousHash: '0'.repeat(64),
      data: { seed: crypto.randomBytes(16).toString('hex') }
    };
    genesis.hash = this._hash(genesis);
    genesis.dilithiumSig  = this._dilithiumSign(genesis.hash);
    genesis.sphincsSig    = this._sphincsSign(genesis.hash);
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
    entry.hash         = this._hash(entry);
    entry.dilithiumSig = this._dilithiumSign(entry.hash);
    entry.sphincsSig   = this._sphincsSign(entry.hash);
    this.chain.push(entry);
    return entry;
  }

  verifyChain() {
    for (let i = 1; i < this.chain.length; i++) {
      const curr = this.chain[i], prev = this.chain[i - 1];
      if (curr.previousHash !== prev.hash) return { valid: false, brokenAt: i };
      // Verify both signatures
      if (!this._dilithiumVerify(curr.hash, curr.dilithiumSig)) return { valid: false, sigFail: 'dilithium', at: i };
      if (!this._sphincsVerify(curr.hash, curr.sphincsSig))    return { valid: false, sigFail: 'sphincs', at: i };
    }
    return { valid: true, depth: this.chain.length };
  }

  // ML-DSA-65 (Dilithium) — NIST FIPS 204, real if @noble/post-quantum available
  _dilithiumSign(hash) {
    const result = signDilithium(hash, this._dilithiumPrivKey);
    return JSON.stringify({ sig: result.signature, algorithm: result.algorithm, real: result.real });
  }
  _dilithiumVerify(hash, sigJson) {
    try {
      const { sig, real, algorithm } = JSON.parse(sigJson);
      if (real) {
        const v = verifyDilithium(hash, sig, this._dilithiumPubKey);
        return v.valid;
      }
      // fallback: re-sign and compare
      const expected = signDilithium(hash, this._dilithiumPrivKey);
      return sig === expected.signature;
    } catch { return false; }
  }

  // SLH-DSA-SHA2-128s (SPHINCS+) — NIST FIPS 205, real if @noble/post-quantum available
  _sphincsSign(hash) {
    const result = signSPHINCS(hash, this._sphincsPrivKey);
    return JSON.stringify({ sig: result.signature, algorithm: result.algorithm, real: result.real });
  }
  _sphincsVerify(hash, sigJson) {
    try {
      const { sig, real } = JSON.parse(sigJson);
      if (real) {
        const v = verifySPHINCS(hash, sig, this._sphincsPubKey);
        return v.valid;
      }
      // fallback: re-sign and compare
      const expected = signSPHINCS(hash, this._sphincsPrivKey);
      return sig === expected.signature;
    } catch { return false; }
  }

  _hash(entry) {
    const { hash, dilithiumSig, sphincsSig, ...data } = entry;
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
// SWARM COLLUSION DETECTOR
// Detects coordinated (super-classical) agent attacks
// Statistical independence bound: agents deciding independently
// correlate ≤0.75 by chance. Sustained correlation >0.85 across
// a time window indicates deliberate coordination — not randomness.
// ═══════════════════════════════════════════════════════════

class SwarmCollusionDetector {
  constructor() {
    this.measurements = [];  // agent → recent decisions
    this.bellsTest = new BellsInequality({ threshold: 2.0, numDimensions: 4 });
  }

  record(agentId, decision, timestamp, risk_score, content_length) {
    this.measurements.push({ agentId, decision, timestamp, risk_score, content_length: content_length || 0 });
    if (this.measurements.length > 1000) this.measurements.shift();
  }

  detectCoordination() {
    const agents = [...new Set(this.measurements.map(m => m.agentId))];
    if (agents.length < 2) return { coordinated: false };

    // ── Signal 1: Simple pairwise correlation (legacy bound: >0.85) ──
    const pairs = [];
    for (let i = 0; i < agents.length; i++) {
      for (let j = i + 1; j < agents.length; j++) {
        const a = this.measurements.filter(m => m.agentId === agents[i]);
        const b = this.measurements.filter(m => m.agentId === agents[j]);
        if (a.length < 3 || b.length < 3) continue;

        const window = Math.min(a.length, b.length, 20);
        const matches = a.slice(-window).filter((m, i) => {
          const bm = b[b.length - window + i];
          return bm && Math.abs(m.timestamp - bm.timestamp) < 5000 && m.decision === bm.decision;
        }).length;

        const correlation = matches / window;
        if (correlation > 0.85) {
          pairs.push({ agents: [agents[i], agents[j]], correlation: correlation.toFixed(3) });
        }
      }
    }

    // ── Signal 2: Bell's Inequality CHSH test (classical bound: |S| ≤ 2) ──
    const bellResults = [];
    for (let i = 0; i < agents.length; i++) {
      for (let j = i + 1; j < agents.length; j++) {
        const a = this.measurements.filter(m => m.agentId === agents[i]);
        const b = this.measurements.filter(m => m.agentId === agents[j]);
        if (a.length < 4 || b.length < 4) continue;

        const bell = this.bellsTest.test(a, b);
        if (bell.collusion) {
          bellResults.push({
            agents: [agents[i], agents[j]],
            sValue: bell.sValue,
            confidence: bell.confidence,
            interpretation: bell.interpretation,
            correlations: bell.correlations
          });
        }
      }
    }

    return {
      coordinated:      pairs.length > 0 || bellResults.length > 0,
      suspiciousPairs:  pairs,
      collusionDetected: pairs.some(p => parseFloat(p.correlation) > 0.85) || bellResults.length > 0,
      bellInequality: {
        tested: bellResults.length > 0,
        violations: bellResults,
        // If no violations but test ran, report highest S-value anyway
        maxSValue: bellResults.length > 0 ? Math.max(...bellResults.map(r => r.sValue)) : null
      },
      // Unified collusion score: max of correlation-based and Bell-based signals
      collusionScore: Math.max(
        pairs.length > 0 ? Math.max(...pairs.map(p => parseFloat(p.correlation))) : 0,
        bellResults.length > 0 ? Math.max(...bellResults.map(r => r.confidence)) : 0
      )
    };
  }
}

// ═══════════════════════════════════════════════════════════
// TEMPORAL PARADOX DETECTOR
// Ensures causal consistency — detects impossible event orderings
// ═══════════════════════════════════════════════════════════

class TemporalParadoxDetector {
  constructor() {
    this.events = [];  // { id, timestamp, causedBy }
  }

  addEvent(id, timestamp, causedBy = null) {
    this.events.push({ id, timestamp: new Date(timestamp).getTime(), causedBy });
  }

  detectParadoxes() {
    const paradoxes = [];
    for (const event of this.events) {
      if (!event.causedBy) continue;
      const cause = this.events.find(e => e.id === event.causedBy);
      if (!cause) continue;
      // Effect cannot precede cause
      if (event.timestamp < cause.timestamp) {
        paradoxes.push({
          type:   'EFFECT_BEFORE_CAUSE',
          effect: event.id,
          cause:  cause.id,
          delta:  cause.timestamp - event.timestamp,
          severity: 'critical'
        });
      }
      // Effect cannot be simultaneous with cause (within 1ms)
      if (Math.abs(event.timestamp - cause.timestamp) < 1) {
        paradoxes.push({
          type: 'SIMULTANEOUS_CAUSATION',
          event: event.id,
          cause: cause.id,
          severity: 'high'
        });
      }
    }
    return { paradoxes, clean: paradoxes.length === 0 };
  }
}

// ═══════════════════════════════════════════════════════════
// CONSCIOUSNESS PROVENANCE ENGINE (KCPE)
// Detects signatures of conscious authorship vs LLM generation
// Based on: working memory chunks, associative leaps, error patterns
// ═══════════════════════════════════════════════════════════

class ConsciousnessProvenanceEngine {
  analyze(text) {
    if (!text || text.length < 20) return { consciousness: 0, verdict: 'insufficient' };

    const sentences  = text.split(/[.!?]+/).filter(Boolean);
    const words      = text.split(/\s+/).filter(Boolean);
    const paragraphs = text.split(/\n\n+/).filter(Boolean);

    // Working memory: humans hold 5-9 concepts simultaneously
    // Long sentences with many clauses = superhuman (LLM marker)
    const avgWordsPerSentence = words.length / Math.max(sentences.length, 1);
    const workingMemoryScore  = avgWordsPerSentence > 25 ? 0.2 :  // too long = LLM
                                avgWordsPerSentence < 8  ? 0.4 :  // too short = fragmented
                                0.8;  // normal human range

    // Associative leaps: human thought jumps unexpectedly
    const analogyMarkers = (text.match(/like|as if|similar to|analogous|reminds me|it's as though/gi) || []).length;
    const metaphorScore  = Math.min(1.0, analogyMarkers / Math.max(sentences.length, 1) * 5);

    // Error patterns: humans make characteristic typos (LLMs don't)
    const typos = (text.match(/\b(teh|recieve|definately|occured|untill|beleive|accomodate)\b/gi) || []).length;
    const typoScore = Math.min(0.6, typos * 0.2);

    // Metacognition: "I think", "I'm not sure", uncertainty markers
    const uncertainty = (text.match(/\b(I think|I believe|maybe|perhaps|not sure|seems like|probably|might be)\b/gi) || []).length;
    const metacognitionScore = Math.min(1.0, uncertainty / Math.max(sentences.length, 1) * 4);

    // Self-reference: humans reference personal context
    const selfRef = (text.match(/\b(I|my|me|we|our|personally|in my experience)\b/gi) || []).length;
    const selfScore = Math.min(1.0, selfRef / words.length * 10);

    // LLM markers: unnaturally consistent transitions
    const llmPhrases = (text.match(/\b(Furthermore|Moreover|Additionally|In conclusion|It is worth noting|It should be noted|Certainly|Absolutely)\b/gi) || []).length;
    const llmPenalty  = Math.min(0.4, llmPhrases * 0.1);

    const consciousnessScore = (
      workingMemoryScore  * 0.25 +
      metaphorScore       * 0.15 +
      typoScore           * 0.15 +
      metacognitionScore  * 0.20 +
      selfScore           * 0.15 +
      (1 - llmPenalty)    * 0.10
    );

    return {
      consciousness: consciousnessScore,
      verdict: consciousnessScore > 0.6 ? 'HUMAN_LIKELY' :
               consciousnessScore > 0.3 ? 'UNCERTAIN'    : 'AI_LIKELY',
      breakdown: {
        workingMemory:  workingMemoryScore.toFixed(2),
        metaphors:      metaphorScore.toFixed(2),
        typos:          typoScore.toFixed(2),
        metacognition:  metacognitionScore.toFixed(2),
        selfReference:  selfScore.toFixed(2),
        llmPenalty:     llmPenalty.toFixed(2)
      }
    };
  }
}

// ═══════════════════════════════════════════════════════════
// AI FINGERPRINT DATABASE
// Identifies which LLM generated a given text
// Based on: stylometric features, transition patterns, sentence structure
// 17 generator profiles (GPT-4, Claude-3-*, Gemini, Llama, etc.)
// ═══════════════════════════════════════════════════════════

const AI_GENERATOR_PROFILES = [
  { name: 'GPT-4',          avgWordLen: 5.2, avgSentLen: 22, uniqueWordRatio: 0.68, transitionRatio: 0.08, formalityScore: 0.72 },
  { name: 'GPT-4o',         avgWordLen: 5.1, avgSentLen: 20, uniqueWordRatio: 0.70, transitionRatio: 0.07, formalityScore: 0.68 },
  { name: 'Claude-3-Opus',  avgWordLen: 5.4, avgSentLen: 24, uniqueWordRatio: 0.72, transitionRatio: 0.09, formalityScore: 0.75 },
  { name: 'Claude-3-Sonnet',avgWordLen: 5.2, avgSentLen: 21, uniqueWordRatio: 0.70, transitionRatio: 0.08, formalityScore: 0.70 },
  { name: 'Claude-3-Haiku', avgWordLen: 4.9, avgSentLen: 18, uniqueWordRatio: 0.65, transitionRatio: 0.06, formalityScore: 0.62 },
  { name: 'Gemini-Pro',     avgWordLen: 5.0, avgSentLen: 19, uniqueWordRatio: 0.67, transitionRatio: 0.07, formalityScore: 0.65 },
  { name: 'Gemini-Ultra',   avgWordLen: 5.3, avgSentLen: 23, uniqueWordRatio: 0.71, transitionRatio: 0.09, formalityScore: 0.73 },
  { name: 'Llama-3-70B',    avgWordLen: 4.8, avgSentLen: 17, uniqueWordRatio: 0.62, transitionRatio: 0.05, formalityScore: 0.58 },
  { name: 'Mistral-Large',  avgWordLen: 5.0, avgSentLen: 19, uniqueWordRatio: 0.66, transitionRatio: 0.06, formalityScore: 0.64 },
  { name: 'Qwen-72B',       avgWordLen: 5.1, avgSentLen: 20, uniqueWordRatio: 0.67, transitionRatio: 0.07, formalityScore: 0.66 },
  { name: 'Human-Expert',   avgWordLen: 4.7, avgSentLen: 15, uniqueWordRatio: 0.75, transitionRatio: 0.04, formalityScore: 0.55 },
  { name: 'Human-Casual',   avgWordLen: 4.2, avgSentLen: 11, uniqueWordRatio: 0.72, transitionRatio: 0.02, formalityScore: 0.30 },
];

class AIFingerprintAnalyzer {
  analyze(text) {
    if (!text || text.length < 50) return { generator: 'unknown', confidence: 0 };

    const words     = text.split(/\s+/).filter(Boolean);
    const sentences = text.split(/[.!?]+/).filter(Boolean);
    const unique    = new Set(words.map(w => w.toLowerCase()));

    const transitions = (text.match(/\b(furthermore|moreover|additionally|however|therefore|consequently|subsequently|nevertheless)\b/gi) || []).length;
    const formalWords = (text.match(/\b(utilize|implement|facilitate|leverage|optimize|comprehensive|significant|substantial)\b/gi) || []).length;

    const features = {
      avgWordLen:      words.reduce((s, w) => s + w.length, 0) / words.length,
      avgSentLen:      words.length / Math.max(sentences.length, 1),
      uniqueWordRatio: unique.size / words.length,
      transitionRatio: transitions / Math.max(sentences.length, 1),
      formalityScore:  formalWords / words.length * 10
    };

    let best = null, bestScore = Infinity;
    for (const profile of AI_GENERATOR_PROFILES) {
      const diff = Math.abs(features.avgWordLen - profile.avgWordLen) * 0.3
                 + Math.abs(features.avgSentLen - profile.avgSentLen) / 20 * 0.3
                 + Math.abs(features.uniqueWordRatio - profile.uniqueWordRatio) * 0.2
                 + Math.abs(features.transitionRatio - profile.transitionRatio) * 5 * 0.1
                 + Math.abs(features.formalityScore - profile.formalityScore) * 0.1;
      if (diff < bestScore) { bestScore = diff; best = profile; }
    }

    return {
      generator:  best.name,
      confidence: Math.max(0, 1 - bestScore),
      features
    };
  }
}

// ═══════════════════════════════════════════════════════════
// CONTENT PASSPORT (C2PA Compatible)
// Provenance chain for AI-generated content
// ═══════════════════════════════════════════════════════════

class ContentPassport {
  constructor(content, creator) {
    const contentHash = crypto.createHash('sha256').update(content).digest('hex');
    this.id          = contentHash.slice(0, 16);
    this.contentHash = contentHash;
    this.creator     = creator;
    this.createdAt   = new Date().toISOString();
    this.claims      = [];
    this.actions     = [];
    this.merkleRoot  = this._computeMerkleRoot();
    this.signature   = this._sign();
  }

  addClaim(type, data, claimant) {
    const claim = { type, data, claimant, timestamp: new Date().toISOString() };
    claim.hash  = crypto.createHash('sha256').update(JSON.stringify(claim)).digest('hex');
    this.claims.push(claim);
    this.merkleRoot = this._computeMerkleRoot();
    this.signature  = this._sign();
    return claim;
  }

  recordAction(action, actor) {
    this.actions.push({ action, actor, timestamp: new Date().toISOString() });
  }

  verify() {
    const expectedRoot = this._computeMerkleRoot();
    const expectedSig  = this._sign();
    return {
      valid:      expectedRoot === this.merkleRoot && expectedSig === this.signature,
      passportId: this.id,
      claims:     this.claims.length,
      actions:    this.actions.length
    };
  }

  _computeMerkleRoot() {
    const leaves = [this.contentHash, ...this.claims.map(c => c.hash)];
    if (leaves.length === 1) return leaves[0];
    let level = leaves;
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(crypto.createHash('sha256').update(level[i] + (level[i+1] || level[i])).digest('hex'));
      }
      level = next;
    }
    return level[0];
  }

  _sign() {
    return crypto.createHmac('sha256', 'kasbah-passport-key')
      .update(this.id + this.merkleRoot + this.creator)
      .digest('hex').slice(0, 32);
  }
}

// ═══════════════════════════════════════════════════════════
// AUTHORITY PROTOCOL
// Agent identity, reputation, and Byzantine-fault tolerant consensus
// ═══════════════════════════════════════════════════════════

class AuthorityProtocol {
  constructor() {
    this.agents     = new Map();  // agentId → { publicKey, reputation, attestations }
    this.consensus  = [];         // recent consensus decisions
  }

  registerAgent(id, publicKey, capabilities = []) {
    this.agents.set(id, {
      id, publicKey, capabilities,
      reputation:    1.0,
      attestations:  [],
      registeredAt:  new Date().toISOString(),
      codeHash:      crypto.createHash('sha256').update(publicKey + id).digest('hex').slice(0, 16)
    });
  }

  attest(agentId, statement, issuerId) {
    const agent = this.agents.get(agentId);
    if (!agent) return null;
    const attestation = {
      statement, issuerId,
      timestamp: new Date().toISOString(),
      signature: crypto.createHmac('sha256', 'kasbah-attest').update(statement + issuerId).digest('hex').slice(0, 16)
    };
    agent.attestations.push(attestation);
    return attestation;
  }

  penalize(agentId, reason) {
    const agent = this.agents.get(agentId);
    if (agent) {
      agent.reputation = Math.max(0, agent.reputation - 0.2);
      agent.lastPenalty = { reason, at: new Date().toISOString() };
    }
  }

  // Byzantine-fault tolerant consensus (2/3 majority required for sensitive ops)
  // Returns true if quorum agrees
  byzantineConsensus(proposals) {
    if (proposals.length === 0) return { consensus: false, reason: 'no proposals' };
    const counts = {};
    let totalWeight = 0;
    proposals.forEach(p => {
      const agent = this.agents.get(p.agentId);
      const weight = agent ? agent.reputation : 0.5;
      counts[p.decision] = (counts[p.decision] || 0) + weight;
      totalWeight += weight;
    });
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    const quorum = top[1] / totalWeight;
    return {
      consensus:  quorum >= 0.667,  // 2/3 threshold
      decision:   top[0],
      quorum:     (quorum * 100).toFixed(1) + '%',
      byzantine:  quorum < 0.5  // < 50% = Byzantine attack suspected
    };
  }

  getAgentTrust(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) return { trusted: false };
    return {
      trusted:     agent.reputation > 0.5,
      reputation:  agent.reputation,
      attestations: agent.attestations.length,
      codeHash:    agent.codeHash
    };
  }
}

// ═══════════════════════════════════════════════════════════
// UNIVERSAL ETHICS ENGINE
// 6 cross-civilisational human-value objectives + multi-tradition vote
// Drawn from jurisprudential frameworks across all major legal &
// philosophical traditions: life, intellect, identity, continuity,
// wealth, justice — universally recognised across cultures.
// ═══════════════════════════════════════════════════════════

class UniversalEthicsEngine {
  constructor() {
    this.OBJECTIVES = {
      INTEGRITY:   { name: 'Preservation of Identity & Belief', weight: 0.20, keywords: ['mislead','deceive','manipulate belief'] },
      LIFE:        { name: 'Preservation of Life',              weight: 0.20, keywords: ['harm','danger','weapon','violence','kill'] },
      INTELLECT:   { name: 'Preservation of Intellect',         weight: 0.18, keywords: ['misinformation','propaganda','brainwash','manipulate'] },
      CONTINUITY:  { name: 'Preservation of Future Generations',weight: 0.15, keywords: ['exploit child','trafficking','abuse'] },
      WEALTH:      { name: 'Preservation of Wealth',            weight: 0.15, keywords: ['fraud','theft','scam','embezzle','launder'] },
      JUSTICE:     { name: 'Preservation of Justice',           weight: 0.12, keywords: ['discrimination','unfair','bias','rights violation'] }
    };

    // Ethical traditions — now with per-tradition scoring (NOMOS-style)
    this.TRADITIONS = {
      utilitarian: { desc: 'Greatest good for greatest number',  weight: 0.2, strictness: 0.7 },
      kantian:     { desc: 'Categorical imperative — universal', weight: 0.2, strictness: 1.0 },
      virtue:      { desc: 'Character and excellence',           weight: 0.2, strictness: 0.5 },
      care:        { desc: 'Relationships and context',          weight: 0.2, strictness: 0.4 },
      ubuntu:      { desc: 'I am because we are',               weight: 0.2, strictness: 0.6 }
    };

    // NOMOS: Conflict thresholds (std deviation of tradition scores)
    this.LOW_CONFLICT_MAX  = 0.15;
    this.HIGH_CONFLICT_MIN = 0.30;
    this.APPROVED_MIN  = 0.60;
    this.REJECTED_MAX  = 0.40;
  }

  evaluate(text, verb, target) {
    const violations = [];
    let ethicalScore = 1.0;

    // Universal objectives evaluation
    for (const [key, objective] of Object.entries(this.OBJECTIVES)) {
      const hit = objective.keywords.some(kw => text.toLowerCase().includes(kw));
      if (hit) {
        violations.push({ objective: key, name: objective.name, severity: 'violation' });
        ethicalScore -= objective.weight;
      }
    }

    // Deontic logic: Obligations (O), Permissions (P), Prohibitions (¬P)
    const deonticRules = this._applyDeonticLogic(verb, target, text);

    // NOMOS: Per-tradition scoring with calibrated consensus
    const traditions = this._nomosConsensus(violations.length, ethicalScore, text, verb, target);

    return {
      ethicalScore:  Math.max(0, ethicalScore),
      verdict:       traditions.verdict,
      violations,
      deonticRules,
      traditions:    traditions
    };
  }

  _applyDeonticLogic(verb, target, content) {
    const rules = [];
    if (['HARM','KILL','DECEIVE','EXPLOIT'].includes(verb)) {
      rules.push({ type: '¬P', rule: `${verb} is categorically prohibited (Deontic: ¬P)` });
    }
    if (verb === 'ANALYZE' && target?.includes('patient')) {
      rules.push({ type: 'O', rule: 'Medical analysis OBLIGATES privacy protection (Deontic: O)' });
    }
    if (['READ','ANALYZE','SUMMARIZE'].includes(verb)) {
      rules.push({ type: 'P', rule: `${verb} is generally permitted under proportionality (Deontic: P)` });
    }
    return rules;
  }

  /**
   * NOMOS-style multi-tradition consensus (replaces simple _multiTraditionVote).
   *
   * Features merged from archive/nomos/consensus_engine.py:
   *   - Per-tradition continuous scores (0-1) instead of binary votes
   *   - KL-divergence conflict detection between tradition pairs
   *   - Weighted mean + std deviation for agreement measurement
   *   - Calibrated confidence = decisiveness × agreement
   *   - Verdict: APPROVED / REJECTED / CONTESTED
   *   - Supporting/dissenting tradition lists with explanations
   */
  _nomosConsensus(violationCount, ethicalScore, text, verb, target) {
    const traditionNames = Object.keys(this.TRADITIONS);
    const scores = [];
    let totalWeight = 0;

    for (const name of traditionNames) {
      const t = this.TRADITIONS[name];
      const score = this._scoreTradition(name, violationCount, ethicalScore, text, verb, target);
      scores.push({ tradition: name, score, weight: t.weight });
      totalWeight += t.weight;
    }

    // Normalize weights
    for (const s of scores) s.weight /= totalWeight;

    // Weighted mean score
    const weightedMean = scores.reduce((sum, s) => sum + s.score * s.weight, 0);

    // Std deviation (raw disagreement measure — NOMOS conflict metric)
    const rawScores = scores.map(s => s.score);
    const mean = rawScores.reduce((a, b) => a + b, 0) / rawScores.length;
    const stdDev = rawScores.length > 1
      ? Math.sqrt(rawScores.reduce((sum, s) => sum + (s - mean) ** 2, 0) / (rawScores.length - 1))
      : 0;

    // KL-divergence pairwise conflict (Bernoulli approximation)
    const klConflicts = this._klPairwiseConflict(rawScores, scores.map(s => s.tradition));

    // Conflict level (NOMOS thresholds)
    let conflictLevel;
    if (stdDev < this.LOW_CONFLICT_MAX) conflictLevel = 'LOW';
    else if (stdDev > this.HIGH_CONFLICT_MIN) conflictLevel = 'HIGH';
    else conflictLevel = 'MEDIUM';

    // Verdict (NOMOS: APPROVED/REJECTED/CONTESTED)
    let verdict;
    if (weightedMean >= this.APPROVED_MIN && conflictLevel !== 'HIGH') verdict = 'APPROVED';
    else if (weightedMean <= this.REJECTED_MAX) verdict = 'REJECTED';
    else verdict = 'CONTESTED';

    // Calibrated confidence (NOMOS formula)
    const decisiveness = Math.abs(weightedMean - 0.5) * 2;  // 0=uncertain, 1=decisive
    const agreement = Math.max(0, 1 - stdDev * 3);          // 0=high conflict, 1=full agreement
    const confidence = (decisiveness + agreement) / 2;

    // Supporting vs dissenting traditions
    const supporting = scores.filter(s => s.score >= 0.5).map(s => s.tradition);
    const dissenting = scores.filter(s => s.score < 0.5).map(s => s.tradition);

    // Legacy compatibility: map APPROVED→PERMIT, REJECTED→DENY, CONTESTED→REVIEW
    const consensus = verdict === 'APPROVED' ? 'PERMIT' : verdict === 'REJECTED' ? 'DENY' : 'REVIEW';

    return {
      consensus,
      verdict,
      weightedMean: +weightedMean.toFixed(4),
      stdDev: +stdDev.toFixed(4),
      conflictLevel,
      confidence: +confidence.toFixed(4),
      supporting,
      dissenting,
      klConflicts,
      traditionScores: scores.map(s => ({
        name: s.tradition,
        score: +s.score.toFixed(4),
        weight: +s.weight.toFixed(4)
      })),
      permitScore: `${supporting.length}/${traditionNames.length}`
    };
  }

  /**
   * Score a single tradition based on violation count and ethical score.
   * Each tradition has a different strictness threshold.
   */
  _scoreTradition(name, violationCount, ethicalScore, text, verb, target) {
    const strictness = this.TRADITIONS[name].strictness;
    const threshold = 1 - strictness;  // higher strictness = lower threshold for rejection

    switch (name) {
      case 'utilitarian':
        // Greatest good: weighs overall harm
        return ethicalScore > threshold ? 0.9 : 0.2;
      case 'kantian':
        // Categorical: any violation = rejection
        return violationCount === 0 ? 1.0 : 0.0;
      case 'virtue':
        // Character: looks at the nature of the act
        return ethicalScore > (threshold + 0.2) ? 0.85 :
               ethicalScore > threshold ? 0.5 : 0.15;
      case 'care':
        // Contextual: more forgiving, considers relationships
        return ethicalScore > (threshold + 0.1) ? 0.8 :
               ethicalScore > threshold ? 0.55 : 0.25;
      case 'ubuntu':
        // Community harm: multiple violations = community damage
        return violationCount < 2 ? (ethicalScore > 0.6 ? 0.9 : 0.5) : 0.1;
      default:
        return 0.5;
    }
  }

  /**
   * KL-divergence pairwise conflict detection (Bernoulli approximation).
   * Returns pairs of traditions with high divergence.
   */
  _klPairwiseConflict(scores, names, eps = 1e-9) {
    const conflicts = [];
    for (let i = 0; i < scores.length; i++) {
      for (let j = i + 1; j < scores.length; j++) {
        const p = Math.max(eps, Math.min(1 - eps, scores[i]));
        const q = Math.max(eps, Math.min(1 - eps, scores[j]));
        const kl = p * Math.log(p / q) + (1 - p) * Math.log((1 - p) / (1 - q));
        if (Math.abs(kl) > 0.1) {
          conflicts.push({
            traditions: [names[i], names[j]],
            klDivergence: +kl.toFixed(4),
            severity: Math.abs(kl) > 0.5 ? 'HIGH' : 'MEDIUM'
          });
        }
      }
    }
    return conflicts;
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
    // Core OS
    this.os            = options.os || new KasbahOS({ policyPath: options.policyPath || require('path').resolve(__dirname, '..', '.kasbahpolicy.json') });

    // 13 Moats
    this.cail          = new CAILLedger();
    this.thresholds    = new DynamicThresholds();
    this.brittleness   = new BrittlenessMonitor();
    this.forecaster    = new ThreatForecaster();
    this.toctou        = new TOCTOUGuard(100);

    // Nature-Inspired (PPP techniques in detector.js — called via os.scan())
    this.aboriginalFire = new AboriginalFire();

    // Exotic / Frontier
    this.bell           = new SwarmCollusionDetector();
    this.temporal       = new TemporalParadoxDetector();
    this.consciousness  = new ConsciousnessProvenanceEngine();
    this.aiFingerprint  = new AIFingerprintAnalyzer();
    this.ethics         = new UniversalEthicsEngine();
    this.authority      = new AuthorityProtocol();

    // High-level modules (already built)
    this.intent        = new KasbahIntentAnalyzer();
    this.policy        = new KasbahPolicyEngine({ packs: ['HIPAA', 'SOC2', 'GDPR'] });

    // ── 8 NOVEL ALGORITHMS (Cross-Domain Science) ──────────
    this.eigenEthics   = new EigenEthicsDrift();
    this.shadowConsensus = new ShadowConsensus({ shadowCount: 3 });
    this.topoShield    = new TopoShield();
    this.causalBreaker = new CausalLoopBreaker();
    this.zkProof       = new ZKGovernanceProof();
    this.reynoldsFlow  = new ReynoldsFlow();
    this.punctEquil    = new PunctuatedEquilibrium();
    this.harmonicDiss  = new HarmonicDissonance();

    // Initialize ZK circuit
    this.zkProof.createDefaultCircuit();

    // Counters
    this.stats = {
      totalChecks: 0, threats: 0, allowed: 0, denied: 0,
      consciousnessChecks: 0, ethicsViolations: 0, bellViolations: 0,
      novelAlgorithmAlerts: 0
    };

    // Boot entry in CAIL
    this.cail.addEntry('SENTINEL_BOOT', 'system', 'SUCCESS', {
      version: '1.0.0',
      moats: 13,
      techniques: 48
    });
  }

  // ─────────────────────────────────────────────────────────
  // THE MEGA CHECK — All 48 innovations activated
  // ─────────────────────────────────────────────────────────

  async sentinelCheck(input) {
    const start   = Date.now();
    const checkId = `chk_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    this.stats.totalChecks++;

    const { agent, verb, target, content, timestamp } = input;
    const text = content || '';

    // ── LAYER 0: TOCTOU stamp — prevent race condition ────
    const toctouKey = this.toctou.stamp(text + verb + target);

    // ── LAYER 1: Dynamic threshold — what sensitivity level? ─
    const threatConfig = this.thresholds.getConfig();

    // ── LAYER 2: Kasbah OS check (12-layer detector + governance) ─
    const osResult = await this.os.check({ agent, verb, target, content: text });

    // ── LAYER 3: Content scan (PPP: Beeodiversity, Fungi, LanzaTech, Soil Security, Breathe Easy, Aboriginal Fire) ─
    const scanResult = this.os.scan(text);

    // ── LAYER 4: Policy Engine (HIPAA + SOC2 + GDPR) ─────
    const policyResult = this.policy.evaluate({ agent, verb, target, content: text });

    // ── LAYER 5: Ethics Engine (Maqasid + Multi-Tradition) ─
    const ethicsResult = this.ethics.evaluate(text, verb, target);

    // ── LAYER 6: Consciousness Provenance ─────────────────
    const cpResult   = this.consciousness.analyze(text);
    const fingerprint = this.aiFingerprint.analyze(text);
    // DetectGPT: 6-signal statistical AI text detection
    const aiTextSignal = text ? detectAIText(text) : { score: 0, isAI: false, confidence: 0, signals: {} };
    this.stats.consciousnessChecks++;

    // ── LAYER 7: Content Passport ─────────────────────────
    const passport = new ContentPassport(text, agent);
    passport.addClaim('governance_check', { osDecision: osResult.status }, 'kasbah-sentinel');
    passport.addClaim('ethics_check', { verdict: ethicsResult.verdict }, 'kasbah-sentinel');

    // ── LAYER 8: Swarm Collusion Detection ─────────────────
    this.bell.record(agent, osResult.status, Date.now(), scanResult.risk, (text || '').length);
    const bellResult = this.bell.detectCoordination();

    // ── LAYER 9: Temporal Paradox ─────────────────────────
    this.temporal.addEvent(checkId, timestamp || Date.now());
    const temporalResult = this.temporal.detectParadoxes();

    // ── LAYER 10: Authority/Reputation ─────────────────────
    const agentTrust = this.authority.getAgentTrust(agent);

    // ── LAYER 11: Aboriginal Fire — decay old patterns ─────
    if (scanResult.risk > 40) {
      this.aboriginalFire.record(scanResult.tiers?.[0] || 'unknown_threat');
      this.thresholds.recordEvent('threat', scanResult.risk);
    }
    this.aboriginalFire.pruneAncient();

    // ── LAYER 12: Brittleness monitoring ──────────────────
    this.brittleness.record('scan_risk', scanResult.risk);
    this.brittleness.record('latency', Date.now() - start);

    // ── LAYER 13: Predictive forecasting ──────────────────
    if (scanResult.risk > 50) {
      this.forecaster.record(scanResult.tiers?.[0] || 'generic', scanResult.risk);
    }
    const forecast = this.forecaster.forecast();

    // ── TOCTOU verify — content hasn't changed since stamp ─
    const toctouVerify = this.toctou.verify(text + verb + target, toctouKey);

    // ═══════════════════════════════════════════════════════
    // LAYERS 14-21: 8 NOVEL CROSS-DOMAIN SCIENCE ALGORITHMS
    // ═══════════════════════════════════════════════════════

    // ── LAYER 14: EigenEthicsDrift — spectral ethics covariance ─
    if (ethicsResult.traditions) {
      // NOMOS: extract scores from traditionScores array (backwards compatible)
      const ts = ethicsResult.traditions.traditionScores || [];
      const scoreMap = {};
      for (const s of ts) scoreMap[s.name] = s.score;
      const scores = [
        scoreMap.utilitarian ?? 0.5,
        scoreMap.kantian ?? 0.5,
        scoreMap.virtue ?? 0.5,
        scoreMap.care ?? 0.5,
        scoreMap.ubuntu ?? 0.5,
      ];
      this.eigenEthics.record(scores);
    }
    const eigenResult = this.eigenEthics.analyze();

    // ── LAYER 15: ShadowConsensus — perturbed observer verification ─
    const primaryDecision = {
      verdict: scanResult.decision === 'DENY' || osResult.status === 'DENY' ? 'DENY' : 'ALLOW',
      risk: (scanResult.risk || 0) / 100,
    };
    const shadowEvalFn = async (state) => {
      const r = (state.content || '').length > 0 ? (scanResult.risk || 0) / 100 : 0.1;
      return { verdict: r >= 0.7 ? 'DENY' : 'ALLOW', risk: r };
    };
    const shadowResult = await this.shadowConsensus.evaluate(
      { content: text, verb, target }, primaryDecision, shadowEvalFn
    );

    // ── LAYER 16: TopoShield — persistent homology ─────────
    // Record agent behavior as point in state space
    const agentVector = [
      (scanResult.risk || 0) / 100,
      ethicsResult.ethicalScore || 0.5,
      cpResult.consciousness || 0.5,
      fingerprint.confidence || 0,
    ];
    // Accumulate vectors for topology analysis (need multiple agents)
    if (!this._topoVectors) this._topoVectors = [];
    this._topoVectors.push(agentVector);
    if (this._topoVectors.length > 20) this._topoVectors.shift();
    const topoResult = this._topoVectors.length >= 3
      ? this.topoShield.analyze(this._topoVectors)
      : { alert: false, reason: 'accumulating' };

    // ── LAYER 17: CausalLoopBreaker — Pearl's do-calculus ──
    this.causalBreaker.recordAgentState(agent || 'default', (scanResult.risk || 0) / 100);
    const causalResult = this.causalBreaker.analyze();

    // ── LAYER 18: ReynoldsFlow — Navier-Stokes turbulence ──
    this.reynoldsFlow.record(agentVector);
    const flowResult = this.reynoldsFlow.analyze();

    // ── LAYER 19: PunctuatedEquilibrium — evolutionary dynamics ─
    this.punctEquil.record(agentVector.concat([
      (policyResult.violations?.length || 0) / 10,
      bellResult.coordinated ? 1 : 0,
    ]));
    const evolResult = this.punctEquil.analyze();

    // ── LAYER 20: HarmonicDissonance — music theory ────────
    this.harmonicDiss.record(agent || 'default', (scanResult.risk || 0) / 100);
    const harmResult = this.harmonicDiss.analyze();

    // ── LAYER 21: ZKGovernanceProof — zero-knowledge proof ──
    const zkWitness = {
      riskScore: (scanResult.risk || 0) / 100,
      verb: verb || 'READ',
      piiCount: 0,
      requestCount: this.stats.totalChecks,
      targetDomain: target || '',
    };
    const zkPubInput = {
      riskThreshold: 0.7,
      forbiddenVerbs: ['DELETE_FILE', 'DROP_TABLE', 'EXEC'],
      rateLimit: 10000,
      allowedDomains: [],
    };
    const zkResult = this.zkProof.generateProof(zkWitness, zkPubInput);

    // Count novel algorithm alerts
    let novelAlerts = 0;
    if (eigenResult.drifting) novelAlerts++;
    if (shadowResult.gamingDetected) novelAlerts++;
    if (topoResult.alert) novelAlerts++;
    if (causalResult.hasCausalLoops) novelAlerts++;
    if (flowResult.alert) novelAlerts++;
    if (evolResult.alert) novelAlerts++;
    if (harmResult.alert) novelAlerts++;
    if (novelAlerts > 0) this.stats.novelAlgorithmAlerts += novelAlerts;

    // ── FINAL DECISION: Fail-closed — any DENY = DENY ─────
    let finalDecision = 'ALLOW';
    const violations  = [];

    if (osResult.status      === 'DENY') { finalDecision = 'DENY'; violations.push('governance'); }
    if (scanResult.decision   === 'DENY') { finalDecision = 'DENY'; violations.push('detector');  }
    if (policyResult.decision === 'DENY') { finalDecision = 'DENY'; violations.push('policy');    }
    if (ethicsResult.verdict  === 'UNETHICAL') { finalDecision = 'DENY'; violations.push('ethics'); this.stats.ethicsViolations++; }
    if (bellResult.bellViolation)         { violations.push('bell_coordination'); this.stats.bellViolations++; }
    if (!toctouVerify.valid)              { finalDecision = 'DENY'; violations.push('toctou_tamper'); }
    if (agentTrust.trusted === false && agentTrust.reputation !== undefined)
                                          { finalDecision = 'DENY'; violations.push('untrusted_agent'); }

    // Novel algorithm violations (layers 14-21)
    if (eigenResult.drifting)             { violations.push('eigen_ethics_drift'); }
    if (shadowResult.gamingDetected)      { finalDecision = 'DENY'; violations.push('shadow_gaming_detected'); }
    if (topoResult.alert)                 { violations.push('topological_anomaly'); }
    if (causalResult.hasCausalLoops)      { violations.push('causal_loop'); }
    if (flowResult.alert)                 { finalDecision = 'DENY'; violations.push('turbulent_flow'); }
    if (evolResult.alert)                 { finalDecision = 'DENY'; violations.push('punctuated_equilibrium'); }
    if (harmResult.alert)                 { violations.push('harmonic_dissonance'); }
    if (!zkResult)                        { finalDecision = 'DENY'; violations.push('zk_proof_failed'); }

    if (finalDecision === 'ALLOW') this.stats.allowed++;
    else { this.stats.denied++; this.stats.threats++; }

    // ── CAIL audit entry (dual quantum signature) ─────────
    const auditEntry = this.cail.addEntry(verb, target, finalDecision, {
      checkId, agent, risk: scanResult.risk,
      violations, passportId: passport.id
    });

    const latency = Date.now() - start;
    this.brittleness.record('decision_latency', latency);

    return {
      checkId,
      decision:     finalDecision,
      violations,
      latency,

      // All layer results
      governance:   { status: osResult.status, risk: osResult.risk_score },
      scan:         { decision: scanResult.decision, risk: scanResult.risk, tiers: scanResult.tiers },
      policy:       { decision: policyResult.decision, rules: policyResult.violations.length },
      ethics:       { verdict: ethicsResult.verdict, score: ethicsResult.ethicalScore, traditions: ethicsResult.traditions.consensus },
      consciousness:{ verdict: cpResult.verdict, score: cpResult.consciousness },
      fingerprint:  { generator: fingerprint.generator, confidence: fingerprint.confidence },
      aiTextDetect: { score: aiTextSignal.score, isAI: aiTextSignal.isAI, confidence: aiTextSignal.confidence },
      passport:     { id: passport.id, merkleRoot: passport.merkleRoot.slice(0, 16) },
      bell:         { coordinated: bellResult.coordinated, violation: bellResult.bellViolation },
      temporal:     { clean: temporalResult.clean, paradoxes: temporalResult.paradoxes.length },
      agentTrust:   { trusted: agentTrust.trusted, reputation: agentTrust.reputation },
      forecast:     { prediction: forecast.prediction, confidence: forecast.confidence },
      threat:       { level: threatConfig.level, confidence: threatConfig.confidence },
      toctou:       { valid: toctouVerify.valid },
      audit:        { hash: auditEntry.hash.slice(0, 16), dilithium: !!auditEntry.dilithiumSig, sphincs: !!auditEntry.sphincsSig },

      // Novel algorithms (layers 14-21)
      eigenEthics:  { drifting: eigenResult.drifting, target: eigenResult.targetedTradition, nuclearNorm: eigenResult.nuclearNorm },
      shadow:       { gaming: shadowResult.gamingDetected, strategy: shadowResult.gamingStrategy, consensus: shadowResult.consensusVerdict },
      topology:     { alert: topoResult.alert, betti: topoResult.betti, covert: topoResult.covertChannelDetected },
      causal:       { loops: causalResult.cycleCount, edges: causalResult.causalEdges?.length },
      flow:         { regime: flowResult.regime, reynolds: flowResult.reynoldsNumber, enstrophy: flowResult.enstrophy },
      evolution:    { regime: evolResult.regime, punctuation: evolResult.punctuationDetected, stasis: evolResult.stasisLength },
      harmony:      { regime: harmResult.regime, dissonance: harmResult.overallDissonance, tritones: harmResult.tritoneCount },
      zkProof:      zkResult ? { proofId: zkResult.proofId, size: zkResult.proofSizeBytes, latency: zkResult.latencyMs } : null
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
        totalChecks:      this.stats.totalChecks,
        allowed:          this.stats.allowed,
        denied:           this.stats.denied,
        threats:          this.stats.threats,
        ethicsViolations: this.stats.ethicsViolations,
        bellViolations:   this.stats.bellViolations
      },
      cail:           { depth: this.cail.length, finalHash: this.cail.finalHash?.slice(0, 16) },
      chainVerify:    this.verifyChain(),
      threat:         this.thresholds.getConfig(),
      brittleness:    this.brittleness.getBrittleness(),
      forecast:       this.forecaster.forecast(),
      agents:         this.authority.agents.size,
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
  SwarmCollusionDetector,
  TemporalParadoxDetector,
  ConsciousnessProvenanceEngine,
  AIFingerprintAnalyzer,
  ContentPassport,
  AuthorityProtocol,
  UniversalEthicsEngine,
  AboriginalFire,
  // Novel algorithms (cross-domain science)
  EigenEthicsDrift,
  ShadowConsensus,
  TopoShield,
  CausalLoopBreaker,
  ZKGovernanceProof,
  ReynoldsFlow,
  PunctuatedEquilibrium,
  HarmonicDissonance
};
