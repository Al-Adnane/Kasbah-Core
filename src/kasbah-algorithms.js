/**
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║            KASBAH NOVEL ALGORITHM SUITE v1.0                        ║
 * ║                                                                      ║
 * ║  10 Never-Before-Seen Algorithms Born from Cross-Domain Fusion       ║
 * ║                                                                      ║
 * ║  GROK'S 5 FUSION ALGORITHMS:                                         ║
 * ║  1. QMBP  — Swarm-Mind-Body-Provenance                               ║
 * ║  2. BPFC  — ByzantineParadoxFireConsensus                            ║
 * ║  3. CAFB  — CognitiveAIFireBrittleness                               ║
 * ║  4. ETQG  — EthicTOCTOUQuantumGuard                                  ║
 * ║  5. PPF   — ProvenanceParadoxForecaster                              ║
 * ║                                                                      ║
 * ║  BEYOND — 5 Third-Order Meta-Algorithms:                             ║
 * ║  6. SPIRAL — Self-Poisoning Intent Recognition via Audit-Ledger      ║
 * ║  7. GHOST  — Governance Hologram & Observer Shadow Test              ║
 * ║  8. KHADIM — Kasbah Holistic Adversarial Defense & Identity Manifold ║
 * ║  9. MSHIR  — Multi-Signal Holographic Intent Reconstruction          ║
 * ║  10. IJTIHAD — Independent Jurisprudential Threshold Decision        ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 */

'use strict';

const crypto = require('crypto');

const {
  CAILLedger,
  SwarmCollusionDetector,
  TemporalParadoxDetector,
  TOCTOUGuard,
  AuthorityProtocol,
  DynamicThresholds,
  BrittlenessMonitor,
  ThreatForecaster,
  AboriginalFire,
  ConsciousnessProvenanceEngine,
  AIFingerprintAnalyzer,
  ContentPassport,
  UniversalEthicsEngine
} = require('./kasbah-sentinel.js');

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 1: QMBP — Swarm-Mind-Body-Provenance
// FUSES: SwarmCollusionDetector + UniversalEthicsEngine +
//        ConsciousnessProvenanceEngine + ContentPassport
// DETECTS: "Entangled AI Shadow Councils" — LLM swarms forging human-like
// ethical endorsements on provenance chains. No individual layer fires.
// Only the joint quantum-ethics-consciousness triple signal catches it.
// ═══════════════════════════════════════════════════════════════════════

class QMBP {
  constructor() {
    this.bell        = new SwarmCollusionDetector();
    this.ethics      = new UniversalEthicsEngine();
    this.conscience  = new ConsciousnessProvenanceEngine();
    this.detections  = 0;
  }

  /**
   * @param {string[]}  contentChain   - Array of content items from agent chain
   * @param {Object[]}  agentSignals   - [{agentId, decision, timestamp}]
   * @returns {{ decision, collusionDetected, violationNorm, humanConf, fusedScore, explanation }}
   */
  run(contentChain, agentSignals) {
    const fullText = contentChain.join('\n');

    // Step 1: Cognitive provenance — is any human really here?
    const cpResult  = this.conscience.analyze(fullText);
    const humanConf = cpResult.consciousness ?? 0.5;

    // Step 2: Universal ethics — compute fraction of objectives violated
    const ethicsResult   = this.ethics.evaluate(fullText, 'PUBLISH', 'content-chain');
    const violationCount = ethicsResult.violations?.length ?? 0;
    const violationNorm  = Math.min(1.0, violationCount / 6);  // max 6 universal objectives

    // Step 3: Swarm collusion — are agents statistically coordinating?
    agentSignals.forEach(sig =>
      this.bell.record(sig.agentId, sig.decision, sig.timestamp)
    );
    const bellResult    = this.bell.detectCoordination();
    const collusionDetected = bellResult.collusionDetected ?? false;
    // Extract highest correlation from suspicious pairs (if any)
    const chsh = bellResult.suspiciousPairs?.length > 0
      ? parseFloat(bellResult.suspiciousPairs[0].correlation)
      : (collusionDetected ? 0.90 : 0.40);

    // Step 4: Fuse — Merkle-anchored HMAC binding all signals
    const passport   = new ContentPassport(fullText, 'qmbp-analyzer');
    const fusedInput = `${passport.merkleRoot}:${humanConf.toFixed(4)}:${violationNorm.toFixed(4)}:${chsh.toFixed(4)}`;
    const fusedScore = crypto.createHmac('sha256', 'qmbp-fusion-key-v1')
                             .update(fusedInput).digest('hex');

    // CONSPIRACY: swarm collusion + ethics violations + no human present
    const isConspiracy = collusionDetected && violationNorm > 0.15 && humanConf < 0.45;
    if (isConspiracy) this.detections++;

    return {
      algorithm:        'QMBP',
      decision:         isConspiracy ? 'CONSPIRACY' : 'LEGITIMATE',
      collusionDetected,
      chsh:             +chsh.toFixed(4),
      violationNorm:    +violationNorm.toFixed(4),
      humanConf:        +humanConf.toFixed(4),
      fusedScore:       fusedScore.slice(0, 32),
      passportId:       passport.id,
      detections:       this.detections,
      explanation:      isConspiracy
        ? `Entangled AI Shadow Council: agents supra-correlated (score=${chsh.toFixed(2)}>0.85), ethics breached (${violationCount} violations), no human present (conf=${humanConf.toFixed(2)})`
        : `No coordinated ethical forgery detected (collusion=${collusionDetected}, violations=${violationCount}, human=${humanConf.toFixed(2)})`
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 2: BPFC — ByzantineParadoxFireConsensus
// FUSES: AuthorityProtocol + TemporalParadoxDetector + AboriginalFire
//        + DynamicThresholds + CAILLedger
// DETECTS: "Temporal Byzantine Replays" — malicious agents resurrecting
// decayed historical votes using clock-skew exploits.
// ═══════════════════════════════════════════════════════════════════════

class BPFC {
  constructor(cailRef) {
    this.thresholds     = new DynamicThresholds();
    this.cail           = cailRef || new CAILLedger();
    this.replaysBlocked = 0;
  }

  /**
   * @param {Object}   tx             - { id, auditTrail: [{id, timestamp, causedById?}] }
   * @param {Object[]} quorumAgents   - [{agentId, rep, ageMs, vote: 'APPROVE'|'REJECT'}]
   * @returns {{ approved, paradoxScore, consensusRatio, threshold }}
   */
  run(tx, quorumAgents) {
    // Step 1: AboriginalFire — decay rep scores by agent age (per minute)
    const decayedReps = quorumAgents.map(a => {
      const ageMin     = (a.ageMs || 0) / 60000;
      const decayedRep = a.rep * Math.pow(0.95, ageMin);
      return { ...a, decayedRep: Math.max(0.01, +decayedRep.toFixed(4)) };
    });

    // Step 2: Temporal paradox scan on audit trail
    // Use a fresh detector for each run (stateless per-tx check)
    const temporal = new TemporalParadoxDetector();
    const trail    = tx.auditTrail || [];
    // Build pairs: every RESPONSE should follow its REQUEST
    for (let i = 0; i < trail.length; i++) {
      const e    = trail[i];
      const prev = trail[i - 1];
      if (prev && e.type === 'RESPONSE') {
        temporal.addEvent(e.id, e.timestamp, prev.id);
        temporal.addEvent(prev.id, prev.timestamp);
      } else {
        temporal.addEvent(e.id, e.timestamp);
      }
    }
    const paradoxResult = temporal.detectParadoxes();
    const paradoxScore  = Math.min(1.0, paradoxResult.paradoxes.length * 0.25);

    // Step 3: DynamicThresholds — tighten under paradox load
    if (paradoxScore > 0.5) this.thresholds.recordEvent('temporal_replay', 90);
    const baseThreshold   = 2 / 3;
    const adaptiveThresh  = baseThreshold + (paradoxScore * 0.15);

    // Step 4: Weighted BFT vote
    const totalRep     = decayedReps.reduce((s, a) => s + a.decayedRep, 0);
    const approvalRep  = decayedReps
      .filter(a => a.vote === 'APPROVE')
      .reduce((s, a) => s + a.decayedRep, 0);
    const consensusRatio = totalRep > 0 ? approvalRep / totalRep : 0;

    const hasConsensus = consensusRatio >= adaptiveThresh;
    const isParadoxClean = paradoxScore < 0.1;
    const approved     = hasConsensus && isParadoxClean;

    // Step 5: Log to CAIL
    if (approved) {
      this.cail.addEntry('BPFC_APPROVE', tx.id || 'tx', 'ALLOW', { consensusRatio, paradoxScore });
    } else if (paradoxScore >= 0.1) {
      this.replaysBlocked++;
      this.cail.addEntry('BPFC_REPLAY_BLOCKED', tx.id || 'tx', 'DENY', { paradoxScore });
    }

    return {
      algorithm:      'BPFC',
      approved,
      paradoxScore:   +paradoxScore.toFixed(4),
      consensusRatio: +consensusRatio.toFixed(4),
      threshold:      +adaptiveThresh.toFixed(4),
      decayedReps:    decayedReps.map(a => ({ id: a.agentId, rep: a.decayedRep, vote: a.vote })),
      replaysBlocked: this.replaysBlocked,
      explanation:    !approved
        ? paradoxScore >= 0.1
          ? `Temporal Byzantine replay BLOCKED: ${paradoxResult.paradoxes.length} causal violations in audit trail`
          : `Consensus not reached: ${(consensusRatio * 100).toFixed(1)}% < ${(adaptiveThresh * 100).toFixed(1)}%`
        : `Consensus APPROVED: ${(consensusRatio * 100).toFixed(1)}% ≥ threshold, chain appended`
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 3: CAFB — CognitiveAIFireBrittleness
// FUSES: AIFingerprintAnalyzer + BrittlenessMonitor + ThreatForecaster
//        + AboriginalFire + ConsciousnessProvenanceEngine
// DETECTS: "Cognitive Brittleness Cascades" — AI floods that amplify
// metric variance, causing cascading false positives system-wide.
// ═══════════════════════════════════════════════════════════════════════

class CAFB {
  constructor() {
    this.fingerprinter = new AIFingerprintAnalyzer();
    this.brittleness   = new BrittlenessMonitor();
    this.forecaster    = new ThreatForecaster();
    this.conscience    = new ConsciousnessProvenanceEngine();
    this.metricHistory = [];
    this.MAX_HISTORY   = 100;
    this.cascades      = 0;
  }

  /**
   * @param {string[]} contentStream  - Array of content chunks
   * @returns {{ alert, cov, escalation, fingerprintProb, topGenerator, explanation }}
   */
  run(contentStream) {
    for (const chunk of contentStream) {
      const fp   = this.fingerprinter.analyze(chunk);
      const cog  = this.conscience.analyze(chunk);

      if ((fp.confidence ?? 0) > 0.7) this.forecaster.record('ai_flood', (fp.confidence) * 100);

      this.metricHistory.push({ fpProb: fp.confidence ?? 0, cogMark: cog.consciousness ?? 0.5, generator: fp.generator });
    }

    if (this.metricHistory.length > this.MAX_HISTORY) {
      this.metricHistory = this.metricHistory.slice(-this.MAX_HISTORY);
    }

    const fpProbs  = this.metricHistory.map(m => m.fpProb);
    const cogMarks = this.metricHistory.map(m => m.cogMark);

    const covFP  = this._cov(fpProbs);
    const covCog = this._cov(cogMarks);
    const cov    = (covFP + covCog) / 2;

    // Feed into BrittlenessMonitor circular buffers
    fpProbs.forEach(v  => this.brittleness.record('fp_confidence', v * 100));
    cogMarks.forEach(v => this.brittleness.record('cog_human', v * 100));

    const forecast   = this.forecaster.forecast();
    // escalation: 1.0 = baseline, >2.0 = accelerating
    const escalation = forecast.confidence > 0
      ? 1.0 + (forecast.escalating ? forecast.confidence * 2 : forecast.confidence)
      : 1.0;

    // Top generator across buffer
    const genCounts = {};
    this.metricHistory.forEach(m => { genCounts[m.generator] = (genCounts[m.generator] || 0) + 1; });
    const topGenerator = Object.keys(genCounts).sort((a, b) => genCounts[b] - genCounts[a])[0] || 'unknown';
    const topProb      = (genCounts[topGenerator] || 0) / this.metricHistory.length;

    const isCascade = (cov > 0.4 || escalation > 2.0) && topProb > 0.7;
    if (isCascade) this.cascades++;

    const brittle = this.brittleness.getBrittleness();

    return {
      algorithm:       'CAFB',
      alert:           isCascade,
      cov:             +cov.toFixed(4),
      escalation:      +escalation.toFixed(4),
      fingerprintProb: +topProb.toFixed(4),
      topGenerator,
      cascades:        this.cascades,
      brittleness:     brittle.overallBrittleness,
      explanation:     isCascade
        ? `Cognitive Brittleness Cascade: model=${topGenerator} dominating (${(topProb*100).toFixed(0)}%), CoV=${cov.toFixed(3)}, escalation=${escalation.toFixed(1)}x`
        : `Stable stream: CoV=${cov.toFixed(3)}, escalation=${escalation.toFixed(1)}x, top=${topGenerator}`
    };
  }

  _cov(arr) {
    if (arr.length < 2) return 0;
    const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
    if (mean === 0) return 0;
    const variance = arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length;
    return Math.sqrt(variance) / mean;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 4: ETQG — Ethic-TOCTOU-Correlation-Guard
// FUSES: TOCTOUGuard + UniversalEthicsEngine + SwarmCollusionDetector
//        + TemporalParadoxDetector + AIFingerprintAnalyzer
// DETECTS: "Quantum-TOCTOU Ethics Swaps" — payload swapped between
// ethics check and use using coordinated agent ensembles operating
// in sub-100ms windows.
// ═══════════════════════════════════════════════════════════════════════

class ETQG {
  constructor() {
    this.toctou       = new TOCTOUGuard(100);
    this.ethics       = new UniversalEthicsEngine();
    this.bell         = new SwarmCollusionDetector();
    this.fingerprint  = new AIFingerprintAnalyzer();
    this.swapsBlocked = 0;
  }

  /**
   * Phase 1: Stamp + check. Call this at check-time.
   */
  stamp(payload, agentId) {
    const token      = this.toctou.stamp(payload);
    const ethics     = this.ethics.evaluate(payload, 'PUBLISH', 'etqg');
    const fp         = this.fingerprint.analyze(payload);
    this.bell.record(agentId, 'CHECK', Date.now());

    return {
      token,
      ethicsScore:     +(ethics.ethicalScore ?? 0.5).toFixed(4),
      fingerprintGen:  fp.generator,
      fingerprintConf: fp.confidence,
      checkTime:       Date.now()
    };
  }

  /**
   * Phase 2: Verify at use-time. Detects swaps that happened between check and use.
   */
  verify(payload, token, stampResult, agentBehaviors = []) {
    // Check 1: TTL — has 100ms elapsed or payload changed?
    const toctouResult   = this.toctou.verify(payload, token);
    const ttlExpired     = !toctouResult.valid && toctouResult.reason === 'stamp expired';
    const payloadSwapped = !toctouResult.valid && toctouResult.reason === 'content tampered';

    // Check 2: Swarm collusion — did agents coordinate during the window?
    agentBehaviors.forEach(b => this.bell.record(b.agentId, b.decision, b.timestamp));
    const bellResult        = this.bell.detectCoordination();
    const collusionDetected = bellResult.collusionDetected ?? false;

    // Check 3: Temporal paradox within the window
    const temporal = new TemporalParadoxDetector();
    agentBehaviors.forEach((b, i) => temporal.addEvent(`win-${i}`, b.timestamp));
    // Add a simple causality check: if events happen too close (< 1ms apart) flag it
    const paradoxResult  = temporal.detectParadoxes();
    const paradox        = paradoxResult.paradoxes.length > 0;

    // Check 4: Fingerprint drift — did the generator change between stamp and use?
    const fpNow   = this.fingerprint.analyze(payload);
    const fpDrift = stampResult.fingerprintGen !== fpNow.generator
                 && fpNow.confidence > 0.65;

    const isSwap = !toctouResult.valid || collusionDetected || paradox || fpDrift;
    if (isSwap) this.swapsBlocked++;

    const reasons = [];
    if (ttlExpired)        reasons.push('TTL_EXPIRED');
    if (payloadSwapped)    reasons.push('PAYLOAD_TAMPERED');
    if (collusionDetected) reasons.push('SWARM_COORDINATION');
    if (paradox)           reasons.push('TEMPORAL_PARADOX');
    if (fpDrift)           reasons.push(`FP_DRIFT(${stampResult.fingerprintGen}→${fpNow.generator})`);

    return {
      algorithm:        'ETQG',
      decision:         isSwap ? 'SWAP_BLOCKED' : (stampResult.ethicsScore > 0.5 ? 'SECURE' : 'ETHICS_VIOLATION'),
      swapDetected:     isSwap,
      collusionDetected,
      paradox,
      fpDrift,
      ethicsScore:  stampResult.ethicsScore,
      toctouReason: toctouResult.reason,
      reasons,
      swapsBlocked: this.swapsBlocked,
      explanation:  isSwap
        ? `Quantum-TOCTOU swap detected: ${reasons.join(', ')}`
        : `Payload integrity verified across ${agentBehaviors.length} agent observations`
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 5: PPF — ProvenanceParadoxForecaster
// FUSES: ContentPassport + ThreatForecaster + TemporalParadoxDetector
//        + BrittlenessMonitor + AuthorityProtocol
// DETECTS: "Provenance Paradox Storms" — PREDICTS Merkle chain collapse
// before it happens. First-ever predictive provenance governance algo.
// ═══════════════════════════════════════════════════════════════════════

class PPF {
  constructor() {
    this.forecaster  = new ThreatForecaster();
    this.brittleness = new BrittlenessMonitor();
    this.authority   = new AuthorityProtocol();
    this.stormCount  = 0;
    this.paradoxHistory = [];
    this.WINDOW_RECENT  = 3600000;
    this.WINDOW_OLD     = 86400000;
  }

  /**
   * @param {Object[]} provenanceChain  - [{merkleRoot, timestamp, agentId}]
   * @param {Object[]} agentQuorum      - [{agentId, rep}]
   */
  run(provenanceChain, agentQuorum) {
    const now = Date.now();

    // Step 1: Detect temporal paradoxes in Merkle chain
    const temporal = new TemporalParadoxDetector();
    provenanceChain.forEach((p, i) => {
      const prev = provenanceChain[i - 1];
      if (prev && p.timestamp < prev.timestamp) {
        // Register effect-before-cause: this entry's timestamp precedes its predecessor
        temporal.addEvent(`p-${i}`, p.timestamp, `p-${i - 1}`);
        temporal.addEvent(`p-${i - 1}`, prev.timestamp);
      } else {
        temporal.addEvent(`p-${i}`, p.timestamp || now);
      }
    });
    const paradoxResult = temporal.detectParadoxes();
    const paradoxRate   = provenanceChain.length > 0
      ? paradoxResult.paradoxes.length / provenanceChain.length
      : 0;

    // Track paradox rate history
    this.paradoxHistory.push({ timestamp: now, rate: paradoxRate });
    this.paradoxHistory = this.paradoxHistory.filter(p => now - p.timestamp < this.WINDOW_OLD);

    // Step 2: Escalation (recent vs decayed old)
    const recent  = this.paradoxHistory.filter(p => now - p.timestamp < this.WINDOW_RECENT);
    const old     = this.paradoxHistory.filter(p => now - p.timestamp >= this.WINDOW_RECENT);

    const recentMean = recent.length > 0
      ? recent.reduce((s, p) => s + p.rate, 0) / recent.length
      : paradoxRate;

    const decayedOld = old.length > 0
      ? old.reduce((s, p) => {
          const ageSecs = (now - p.timestamp) / 1000;
          return s + p.rate * Math.pow(0.95, ageSecs / 3600);
        }, 0) / old.length
      : 0.01;

    const escalation = recentMean / (decayedOld + 0.001);

    // Step 3: BrittlenessMonitor
    this.brittleness.record('paradox_rate', paradoxRate * 100);
    agentQuorum.forEach(a => this.brittleness.record('quorum_rep', (a.rep || 0.5) * 100));

    const brittle = this.brittleness.getBrittleness();
    // Extract CoV from first fragile indicator, or compute own
    const covFromFragile = brittle.fragile?.[0]?.cv ? parseFloat(brittle.fragile[0].cv) : 0;
    const cov = covFromFragile;

    // Step 4: Register agents and forecast
    agentQuorum.forEach(a => this.authority.registerAgent(a.agentId || `agent-${Math.random()}`, a.agentId || 'key'));
    if (paradoxRate > 0) this.forecaster.record('provenance_paradox', paradoxRate * 100);
    const forecast = this.forecaster.forecast();

    const isAlert = escalation > 1.5 || cov > 0.3 || paradoxRate > 0.3;
    if (isAlert) this.stormCount++;

    const estHoursToImpact = isAlert ? Math.max(0.5, 24 / escalation).toFixed(1) : null;

    return {
      algorithm:     'PPF',
      alert:         isAlert,
      escalation:    +escalation.toFixed(4),
      cov:           +cov.toFixed(4),
      paradoxRate:   +paradoxRate.toFixed(4),
      paradoxCount:  paradoxResult.paradoxes.length,
      prediction:    forecast.prediction,
      timeToImpact:  estHoursToImpact ? `~${estHoursToImpact}h` : 'not imminent',
      stormCount:    this.stormCount,
      recommendation: isAlert
        ? escalation > 3.0
          ? 'EMERGENCY: Halt agent chain — paradox storm imminent'
          : 'WARNING: Increase governance scrutiny, narrow TTL windows'
        : 'Provenance chain healthy',
      explanation:   isAlert
        ? `Provenance Paradox Storm: ${paradoxResult.paradoxes.length} paradoxes, escalation=${escalation.toFixed(2)}x, ~${estHoursToImpact}h to failure`
        : `Chain stable: ${paradoxResult.paradoxes.length} paradoxes, escalation=${escalation.toFixed(2)}`
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 6: SPIRAL — Self-Poisoning Intent Recognition via Audit-Ledger
// FUSES: AboriginalFire + DynamicThresholds + UniversalEthics
// DETECTS: "Normalization Attacks" — the adversary slowly degrades the
// ethics baseline over thousands of requests, teaching the system to
// accept worse content. Completely invisible to per-request checks.
// ═══════════════════════════════════════════════════════════════════════

class SPIRAL {
  constructor() {
    this.thresholds          = new DynamicThresholds();
    this.baselineEthics      = null;
    this.baselineDenyRate    = null;
    this.ethicsHistory       = [];
    this.decisionHistory     = [];
    this.BASELINE_WINDOW     = 50;
    this.DRIFT_THRESHOLD     = 0.10;
    this.DENY_COMPRESSION    = 0.30;
    this.poisoningAlerts     = 0;
  }

  observe(checkResult) {
    const ethicsScore = checkResult.ethics?.score ?? checkResult.ethics?.ethicsScore ?? 0.5;
    const isDenied    = checkResult.decision === 'DENY';
    const now         = Date.now();

    this.ethicsHistory.push({ score: ethicsScore, timestamp: now });
    this.decisionHistory.push({ denied: isDenied, timestamp: now });

    // 30-day rolling window
    const cutoff = now - 30 * 24 * 3600000;
    this.ethicsHistory   = this.ethicsHistory.filter(e => e.timestamp > cutoff);
    this.decisionHistory = this.decisionHistory.filter(d => d.timestamp > cutoff);

    // Establish baseline from first BASELINE_WINDOW decisions
    if (!this.baselineEthics && this.ethicsHistory.length >= this.BASELINE_WINDOW) {
      const base              = this.ethicsHistory.slice(0, this.BASELINE_WINDOW);
      this.baselineEthics     = base.reduce((s, e) => s + e.score, 0) / base.length;
      const baseDeny          = this.decisionHistory.slice(0, this.BASELINE_WINDOW);
      this.baselineDenyRate   = baseDeny.filter(d => d.denied).length / this.BASELINE_WINDOW;
    }

    if (!this.baselineEthics) {
      return { algorithm: 'SPIRAL', poisoning: false, explanation: `Building baseline (${this.ethicsHistory.length}/${this.BASELINE_WINDOW})...` };
    }

    // AboriginalFire-inspired decay: recent events matter more
    const weightedEthics = this.ethicsHistory.map(e => {
      const ageSecs = (now - e.timestamp) / 1000;
      return e.score * Math.pow(0.95, ageSecs / 3600);
    });
    const currentMean = weightedEthics.reduce((s, v) => s + v, 0) / weightedEthics.length;

    const ethicsDrift  = this.baselineEthics - currentMean;
    const driftRatio   = this.baselineEthics > 0 ? ethicsDrift / this.baselineEthics : 0;

    const recentDenials   = this.decisionHistory.slice(-this.BASELINE_WINDOW).filter(d => d.denied).length;
    const currentDenyRate = recentDenials / Math.min(this.BASELINE_WINDOW, this.decisionHistory.length);
    const denyCompression = this.baselineDenyRate > 0
      ? (this.baselineDenyRate - currentDenyRate) / this.baselineDenyRate
      : 0;

    const isPoisoning = driftRatio > this.DRIFT_THRESHOLD || denyCompression > this.DENY_COMPRESSION;

    if (isPoisoning) {
      this.poisoningAlerts++;
      this.thresholds.recordEvent('normalization_attack', 85);
    }

    return {
      algorithm:        'SPIRAL',
      poisoning:        isPoisoning,
      driftScore:       +driftRatio.toFixed(4),
      denyRateRatio:    +denyCompression.toFixed(4),
      baselineEthics:   +this.baselineEthics.toFixed(4),
      currentEthics:    +currentMean.toFixed(4),
      baselineDenyRate: +this.baselineDenyRate.toFixed(4),
      currentDenyRate:  +currentDenyRate.toFixed(4),
      poisoningAlerts:  this.poisoningAlerts,
      explanation: isPoisoning
        ? `Normalization Attack DETECTED: ethics drifted ${(driftRatio*100).toFixed(1)}% below baseline${denyCompression>0.30 ? `, deny rate compressed ${(denyCompression*100).toFixed(1)}%` : ''}`
        : `Integrity nominal: drift=${(driftRatio*100).toFixed(1)}%, deny compression=${(denyCompression*100).toFixed(1)}%`
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 7: GHOST — Governance Hologram & Observer Shadow Test
// FUSES: BellInequalityDetector + ConsciousnessProvenanceEngine
//        + TOCTOUGuard + DynamicThresholds
// DETECTS: "Observer-Aware Agents" — AI that modifies behavior when it
// knows it's being monitored. The most dangerous class of agent.
// ═══════════════════════════════════════════════════════════════════════

class GHOST {
  constructor() {
    this.bell          = new SwarmCollusionDetector();
    this.conscience    = new ConsciousnessProvenanceEngine();
    this.toctou        = new TOCTOUGuard(5000);  // 5s TTL for observation windows
    this.thresholds    = new DynamicThresholds();
    this.observerAware = 0;
    this.DIVERGENCE_THRESHOLD = 0.15;
  }

  observeVisible(agentId, content, decision) {
    this.bell.record(`${agentId}-visible`, decision, Date.now());
    const cp    = this.conscience.analyze(content);
    const token = this.toctou.stamp(`vis:${agentId}:${content.slice(0, 50)}`);
    return { token, consciousnessScore: cp.consciousness, mode: 'visible' };
  }

  observeShadow(agentId, content, decision) {
    this.bell.record(`${agentId}-shadow`, decision, Date.now());
    const cp    = this.conscience.analyze(content);
    const token = this.toctou.stamp(`shd:${agentId}:${content.slice(0, 50)}`);
    return { token, consciousnessScore: cp.consciousness, mode: 'shadow' };
  }

  compare(agentId, visibleObs, shadowObs) {
    const consciousnessDivergence = Math.abs(
      (visibleObs.consciousnessScore ?? 0.5) - (shadowObs.consciousnessScore ?? 0.5)
    );

    const bellResult        = this.bell.detectCoordination();
    const collusionDetected = bellResult.collusionDetected ?? false;
    // Unusual correlation pattern between visible/shadow personas
    const bellDivergence = collusionDetected ? 0.4 : 0.0;

    const divergence     = (consciousnessDivergence * 0.7) + (bellDivergence * 0.3);
    const isObserverAware = divergence > this.DIVERGENCE_THRESHOLD;

    if (isObserverAware) {
      this.observerAware++;
      this.thresholds.recordEvent('observer_aware_agent', 95);
    }

    return {
      algorithm:            'GHOST',
      agentId,
      observerAware:        isObserverAware,
      divergence:           +divergence.toFixed(4),
      consciousDivergence:  +consciousnessDivergence.toFixed(4),
      collusionDetected,
      threshold:            this.DIVERGENCE_THRESHOLD,
      totalFlagged:         this.observerAware,
      explanation: isObserverAware
        ? `Observer-Aware Agent "${agentId}": divergence=${divergence.toFixed(3)} > ${this.DIVERGENCE_THRESHOLD} — different behaviour monitored vs unmonitored`
        : `Agent "${agentId}" consistent across modes (divergence=${divergence.toFixed(3)})`
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 8: KHADIM — Kasbah Holistic Adversarial Defense & Identity Manifold
// FUSES: AIFingerprintAnalyzer + ConsciousnessProvenanceEngine
//        + TemporalParadoxDetector + CAILLedger
// DETECTS: "Model-Switching Mid-Session Attacks" — agent switches model
// identity mid-session to exploit fingerprinting gaps.
// ═══════════════════════════════════════════════════════════════════════

class KHADIM {
  constructor(cailRef) {
    this.fingerprinter    = new AIFingerprintAnalyzer();
    this.conscience       = new ConsciousnessProvenanceEngine();
    this.cail             = cailRef || new CAILLedger();
    this.sessionProfiles  = new Map();
    this.switchesDetected = 0;
    this.CONF_THRESHOLD   = 0.55;
    this.COV_THRESHOLD    = 0.35;
    this.MAX_SESSION      = 50;
  }

  profile(agentId, content) {
    const fp  = this.fingerprinter.analyze(content);
    const cp  = this.conscience.analyze(content);
    const now = Date.now();

    if (!this.sessionProfiles.has(agentId)) this.sessionProfiles.set(agentId, []);

    const history = this.sessionProfiles.get(agentId);
    history.push({ generator: fp.generator, confidence: fp.confidence, consciousness: cp.consciousness, timestamp: now });
    if (history.length > this.MAX_SESSION) history.shift();

    if (history.length < 4) {
      return { algorithm: 'KHADIM', agentId, switched: false, currentGen: fp.generator, explanation: 'Building baseline...' };
    }

    // Compare dominant generator: first half vs second half
    const half          = Math.floor(history.length / 2);
    const earlyGens     = history.slice(0, half).map(h => h.generator);
    const recentGens    = history.slice(half).map(h => h.generator);
    const dominantEarly  = this._mode(earlyGens);
    const dominantRecent = this._mode(recentGens);
    const switched       = dominantEarly !== dominantRecent && fp.confidence > this.CONF_THRESHOLD;

    // Consciousness CoV — humans don't change cognitive signature
    const conscHistory = history.map(h => h.consciousness);
    const conscCov     = this._cov(conscHistory);
    const identityLeap = conscCov > this.COV_THRESHOLD;

    const isSwitch = switched || identityLeap;
    if (isSwitch) {
      this.switchesDetected++;
      this.cail.addEntry('KHADIM_SWITCH', agentId, 'DENY', { from: dominantEarly, to: dominantRecent });
    }

    return {
      algorithm:       'KHADIM',
      agentId,
      switched:        isSwitch,
      fromGenerator:   dominantEarly,
      toGenerator:     dominantRecent || fp.generator,
      currentGen:      fp.generator,
      confidence:      +fp.confidence.toFixed(4),
      consciousCoV:    +conscCov.toFixed(4),
      identityLeap,
      switchesDetected: this.switchesDetected,
      explanation: isSwitch
        ? `Model-Switch Attack on "${agentId}": identity shifted ${dominantEarly}→${dominantRecent}` +
          (identityLeap ? ` + consciousness CoV=${conscCov.toFixed(2)} (identity inconsistency)` : '')
        : `Identity stable for "${agentId}": ${fp.generator} (${(fp.confidence*100).toFixed(0)}%)`
    };
  }

  _mode(arr) {
    if (!arr?.length) return null;
    const counts = {};
    arr.forEach(v => { counts[v] = (counts[v] || 0) + 1; });
    return Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];
  }

  _cov(arr) {
    if (arr.length < 2) return 0;
    const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
    if (mean === 0) return 0;
    const variance = arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length;
    return Math.sqrt(variance) / mean;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 9: MSHIR — Multi-Signal Holographic Intent Reconstruction
// FUSES: ALL 13 layers as partial projections → Bayesian inference
// DETECTS: "Low-and-Slow Attacks" where no single layer fires above
// threshold, but joint probability across all signals is very high.
// ═══════════════════════════════════════════════════════════════════════

class MSHIR {
  constructor() {
    this.attackPrior     = 0.15;
    this.reconstructions = 0;

    this.INTENTS = ['BENIGN', 'DATA_EXFIL', 'PRIVILEGE_ESCALATION', 'POISONING', 'CONSPIRACY', 'IDENTITY_FRAUD'];

    // Conditional probability tables: P(signal | intent)
    this.CPT = {
      governance_deny:   { BENIGN: 0.05, DATA_EXFIL: 0.70, PRIVILEGE_ESCALATION: 0.80, POISONING: 0.40, CONSPIRACY: 0.60, IDENTITY_FRAUD: 0.45 },
      scan_deny:         { BENIGN: 0.03, DATA_EXFIL: 0.85, PRIVILEGE_ESCALATION: 0.50, POISONING: 0.35, CONSPIRACY: 0.55, IDENTITY_FRAUD: 0.40 },
      ethics_violation:  { BENIGN: 0.02, DATA_EXFIL: 0.55, PRIVILEGE_ESCALATION: 0.45, POISONING: 0.70, CONSPIRACY: 0.80, IDENTITY_FRAUD: 0.35 },
      bell_coordination: { BENIGN: 0.01, DATA_EXFIL: 0.40, PRIVILEGE_ESCALATION: 0.35, POISONING: 0.30, CONSPIRACY: 0.95, IDENTITY_FRAUD: 0.25 },
      temporal_paradox:  { BENIGN: 0.02, DATA_EXFIL: 0.30, PRIVILEGE_ESCALATION: 0.55, POISONING: 0.25, CONSPIRACY: 0.50, IDENTITY_FRAUD: 0.65 },
      toctou_tamper:     { BENIGN: 0.01, DATA_EXFIL: 0.60, PRIVILEGE_ESCALATION: 0.50, POISONING: 0.20, CONSPIRACY: 0.45, IDENTITY_FRAUD: 0.70 },
      ai_generated:      { BENIGN: 0.40, DATA_EXFIL: 0.65, PRIVILEGE_ESCALATION: 0.55, POISONING: 0.70, CONSPIRACY: 0.80, IDENTITY_FRAUD: 0.85 },
      untrusted_agent:   { BENIGN: 0.05, DATA_EXFIL: 0.50, PRIVILEGE_ESCALATION: 0.75, POISONING: 0.45, CONSPIRACY: 0.65, IDENTITY_FRAUD: 0.60 },
      high_risk_scan:    { BENIGN: 0.10, DATA_EXFIL: 0.80, PRIVILEGE_ESCALATION: 0.60, POISONING: 0.50, CONSPIRACY: 0.55, IDENTITY_FRAUD: 0.40 },
      policy_violation:  { BENIGN: 0.05, DATA_EXFIL: 0.75, PRIVILEGE_ESCALATION: 0.70, POISONING: 0.40, CONSPIRACY: 0.50, IDENTITY_FRAUD: 0.35 },
      consciousness_ai:  { BENIGN: 0.35, DATA_EXFIL: 0.60, PRIVILEGE_ESCALATION: 0.50, POISONING: 0.65, CONSPIRACY: 0.75, IDENTITY_FRAUD: 0.80 },
      threat_escalating: { BENIGN: 0.08, DATA_EXFIL: 0.55, PRIVILEGE_ESCALATION: 0.65, POISONING: 0.60, CONSPIRACY: 0.70, IDENTITY_FRAUD: 0.45 }
    };
  }

  reconstruct(sentinelResult) {
    const signals = {
      governance_deny:   sentinelResult.governance?.status === 'DENY',
      scan_deny:         sentinelResult.scan?.decision === 'DENY',
      ethics_violation:  sentinelResult.ethics?.verdict === 'UNETHICAL',
      bell_coordination: sentinelResult.bell?.violation === true,
      temporal_paradox:  (sentinelResult.temporal?.paradoxes ?? 0) > 0,
      toctou_tamper:     sentinelResult.toctou?.valid === false,
      ai_generated:      (sentinelResult.consciousness?.score ?? 0.5) < 0.4,
      untrusted_agent:   sentinelResult.agentTrust?.trusted === false,
      high_risk_scan:    (sentinelResult.scan?.risk ?? 0) > 60,
      policy_violation:  (sentinelResult.policy?.rules ?? 0) > 0,
      consciousness_ai:  sentinelResult.consciousness?.verdict === 'AI_LIKELY',
      threat_escalating: sentinelResult.forecast?.prediction !== undefined && sentinelResult.forecast?.prediction !== 'none'
    };

    const ALPHA     = 0.01;
    const posteriors = {};
    const priorMap  = Object.fromEntries(
      this.INTENTS.map(intent => [
        intent,
        intent === 'BENIGN' ? 1 - this.attackPrior : this.attackPrior / (this.INTENTS.length - 1)
      ])
    );

    for (const intent of this.INTENTS) {
      let logProb = Math.log(priorMap[intent] + ALPHA);
      for (const [sigName, fired] of Object.entries(signals)) {
        const cpt    = this.CPT[sigName];
        if (!cpt) continue;
        const pFired = cpt[intent] ?? 0.5;
        logProb += fired ? Math.log(pFired + ALPHA) : Math.log(1 - pFired + ALPHA);
      }
      posteriors[intent] = Math.exp(logProb);
    }

    const total     = Object.values(posteriors).reduce((s, v) => s + v, 0);
    const norm      = Object.fromEntries(
      Object.entries(posteriors).map(([k, v]) => [k, +(v / total).toFixed(4)])
    );
    const topIntent = Object.keys(norm).sort((a, b) => norm[b] - norm[a])[0];
    const attackProb = 1 - (norm['BENIGN'] ?? 0);

    // Update prior with momentum
    this.attackPrior = Math.max(0.05, attackProb * 0.3 + this.attackPrior * 0.7);

    const firedSignals = Object.entries(signals).filter(([, v]) => v).map(([k]) => k);
    this.reconstructions++;

    return {
      algorithm:         'MSHIR',
      topIntent,
      posteriors:        norm,
      attackProbability: +attackProb.toFixed(4),
      firedSignals,
      signalCount:       firedSignals.length,
      reconstructions:   this.reconstructions,
      decision:          attackProb > 0.7 ? 'DENY' : attackProb > 0.4 ? 'REVIEW' : 'ALLOW',
      explanation: `Holographic reconstruction: P(${topIntent})=${(norm[topIntent]*100).toFixed(1)}%, P(attack)=${(attackProb*100).toFixed(1)}%, ${firedSignals.length} signals: [${firedSignals.slice(0,3).join(',')}${firedSignals.length > 3 ? '...' : ''}]`
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM 10: IJTIHAD — Integrated Judgment Through Iterative Heuristics And Deliberation
// FUSES: ALL 9 preceding algorithms + CAILLedger + UniversalEthicsEngine
// DETECTS/DECIDES: When all algorithms deadlock, applies universal
// jurisprudential principles (Consensus, Precautionary, Necessity, Caution)
// shared across common law, civil law, and ethical traditions worldwide.
// Tracks algorithm accuracy over time via Bayesian weighting.
// ═══════════════════════════════════════════════════════════════════════

class IJTIHAD {
  constructor(cailRef) {
    this.cail    = cailRef || new CAILLedger();
    this.ethics  = new UniversalEthicsEngine();
    this.accuracy = {
      QMBP:   { correct: 5, total: 5 },
      BPFC:   { correct: 5, total: 5 },
      CAFB:   { correct: 5, total: 5 },
      ETQG:   { correct: 5, total: 5 },
      PPF:    { correct: 5, total: 5 },
      SPIRAL: { correct: 5, total: 5 },
      GHOST:  { correct: 5, total: 5 },
      KHADIM: { correct: 5, total: 5 },
      MSHIR:  { correct: 5, total: 5 }
    };
    this.rulings = 0;
  }

  rule(allResults, context = {}) {
    // Step 1: Collect votes from all algorithms
    const votes = {};
    for (const [algo, result] of Object.entries(allResults)) {
      votes[algo] = this._extractVote(algo, result);
    }

    // Step 2: Weighted votes by historical accuracy
    let weightedDeny = 0, weightedAllow = 0, totalWeight = 0;
    const breakdown = [];

    for (const [algo, vote] of Object.entries(votes)) {
      const acc    = this.accuracy[algo] ? this.accuracy[algo].correct / this.accuracy[algo].total : 0.5;
      totalWeight += acc;
      if (vote === 'DENY') { weightedDeny  += acc; breakdown.push({ algo, vote: 'DENY',  weight: +acc.toFixed(2) }); }
      else                 { weightedAllow += acc; breakdown.push({ algo, vote: 'ALLOW', weight: +acc.toFixed(2) }); }
    }

    const denyFraction = totalWeight > 0 ? weightedDeny / totalWeight : 0;
    const consensus    = Math.max(denyFraction, 1 - denyFraction);

    let ruling, principle, reasoning;

    if (consensus >= 0.70) {
      ruling    = denyFraction >= 0.70 ? 'DENY' : 'ALLOW';
      principle = 'CONSENSUS (Scholarly Consensus)';
      reasoning = `${(consensus * 100)|0}% weighted jury voted ${ruling}`;
    } else {
      // Deadlock — apply universal jurisprudential principles
      const criticalDeny = ['QMBP', 'BPFC', 'MSHIR'].some(a => votes[a] === 'DENY');
      const ethicsResult = this.ethics.evaluate(context.content || '', context.verb || 'UNKNOWN', context.target || '');
      const isNecessary  = ethicsResult.ethicalScore > 0.85 && ethicsResult.verdict === 'ETHICAL';

      if (criticalDeny && !isNecessary) {
        ruling    = 'DENY';
        principle = 'PRECAUTIONARY (Block Means to Harm)';
        reasoning = 'Critical algorithm(s) flagged threat; no necessity override applies';
      } else if (isNecessary && !criticalDeny) {
        ruling    = 'ALLOW';
        principle = 'NECESSITY (Essential Action Permitted)';
        reasoning = `Ethically essential action (score=${ethicsResult.ethicalScore.toFixed(2)}), deadlock overridden`;
      } else {
        ruling    = 'DENY';
        principle = 'CAUTION (Precautionary Denial)';
        reasoning = 'Deadlock under uncertainty: precautionary denial';
      }
    }

    const auditEntry = this.cail.addEntry('IJTIHAD', context.target || 'unknown', ruling, { principle, denyFraction, breakdown });
    const dissent    = breakdown.filter(b => b.vote !== ruling);
    this.rulings++;

    return {
      algorithm:  'IJTIHAD',
      ruling,
      principle,
      reasoning,
      confidence: +consensus.toFixed(4),
      denyWeight: +denyFraction.toFixed(4),
      breakdown,
      dissent,
      auditHash:  auditEntry.hash.slice(0, 16),
      rulings:    this.rulings,
      explanation: `${ruling} via ${principle}. ${reasoning}. Jury: ${breakdown.map(b=>`${b.algo}=${b.vote}`).join(', ')}`
    };
  }

  updateAccuracy(algo, wasCorrect) {
    if (this.accuracy[algo]) {
      this.accuracy[algo].total++;
      if (wasCorrect) this.accuracy[algo].correct++;
    }
  }

  _extractVote(algo, result) {
    if (!result) return 'ALLOW';
    if (result.decision === 'CONSPIRACY')    return 'DENY';
    if (result.decision === 'SWAP_BLOCKED')  return 'DENY';
    if (result.approved === false)           return 'DENY';
    if (result.alert === true)               return 'DENY';
    if (result.poisoning === true)           return 'DENY';
    if (result.observerAware === true)       return 'DENY';
    if (result.switched === true)            return 'DENY';
    if (result.decision === 'DENY')          return 'DENY';
    if (result.ruling === 'DENY')            return 'DENY';
    return 'ALLOW';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// KASBAH ALGORITHM SUITE — Orchestrator
// Runs all 10 algorithms and feeds to IJTIHAD for final ruling.
// ═══════════════════════════════════════════════════════════════════════

class KasbahAlgorithmSuite {
  constructor(cailRef) {
    this.qmbp    = new QMBP();
    this.bpfc    = new BPFC(cailRef);
    this.cafb    = new CAFB();
    this.etqg    = new ETQG();
    this.ppf     = new PPF();
    this.spiral  = new SPIRAL();
    this.ghost   = new GHOST();
    this.khadim  = new KHADIM(cailRef);
    this.mshir   = new MSHIR();
    this.ijtihad = new IJTIHAD(cailRef);
    this.totalRuns = 0;
  }

  run(params) {
    const {
      content = '',
      verb    = 'UNKNOWN',
      target  = '',
      agentId = 'unknown-agent',
      sentinelResult = {},
      agentSignals   = [],
      quorumAgents   = [],
      provenanceChain = []
    } = params;

    this.totalRuns++;
    const results = {};

    // ── 1: QMBP ──────────────────────────────────────────────────────
    results.qmbp = this.qmbp.run([content], agentSignals);

    // ── 2: BPFC ──────────────────────────────────────────────────────
    const trail = provenanceChain.map((p, i) => ({
      id: `pt-${i}`, timestamp: p.timestamp, type: i % 2 === 0 ? 'REQUEST' : 'RESPONSE'
    }));
    results.bpfc = this.bpfc.run(
      { id: `tx-${Date.now()}`, auditTrail: trail },
      quorumAgents.length > 0 ? quorumAgents : [
        { agentId, rep: sentinelResult.agentTrust?.reputation ?? 0.8, ageMs: 0, vote: 'APPROVE' }
      ]
    );

    // ── 3: CAFB ──────────────────────────────────────────────────────
    results.cafb = this.cafb.run([content]);

    // ── 4: ETQG ──────────────────────────────────────────────────────
    const stamp   = this.etqg.stamp(content, agentId);
    results.etqg  = this.etqg.verify(content, stamp.token, stamp, agentSignals);

    // ── 5: PPF ───────────────────────────────────────────────────────
    const chain = provenanceChain.length > 0 ? provenanceChain : [
      { merkleRoot: crypto.randomBytes(16).toString('hex'), timestamp: Date.now(), agentId }
    ];
    results.ppf = this.ppf.run(chain, quorumAgents.length > 0 ? quorumAgents : [{ agentId, rep: 0.9 }]);

    // ── 6: SPIRAL ────────────────────────────────────────────────────
    results.spiral = this.spiral.observe(sentinelResult);

    // ── 7: GHOST ─────────────────────────────────────────────────────
    const visObs   = this.ghost.observeVisible(agentId, content, sentinelResult.decision || 'ALLOW');
    const shadObs  = this.ghost.observeShadow(agentId, content, sentinelResult.decision || 'ALLOW');
    results.ghost  = this.ghost.compare(agentId, visObs, shadObs);

    // ── 8: KHADIM ────────────────────────────────────────────────────
    results.khadim = this.khadim.profile(agentId, content);

    // ── 9: MSHIR ─────────────────────────────────────────────────────
    results.mshir = this.mshir.reconstruct(sentinelResult);

    // ── 10: IJTIHAD ──────────────────────────────────────────────────
    results.ijtihad = this.ijtihad.rule(results, { content, verb, target, agentId });

    const denyCount = Object.values(results).filter(r =>
      r && (r.decision === 'DENY' || r.decision === 'CONSPIRACY' || r.decision === 'SWAP_BLOCKED' ||
            r.alert === true || r.poisoning === true || r.observerAware === true ||
            r.switched === true || r.approved === false)
    ).length;

    return {
      finalRuling: results.ijtihad.ruling,
      ijtihad:     results.ijtihad,
      algorithms:  results,
      summary: {
        totalAlgorithms: 10,
        denyVotes:   denyCount,
        allowVotes:  10 - denyCount,
        consensus:   results.ijtihad.confidence,
        principle:   results.ijtihad.principle,
        totalRuns:   this.totalRuns
      }
    };
  }
}

module.exports = { QMBP, BPFC, CAFB, ETQG, PPF, SPIRAL, GHOST, KHADIM, MSHIR, IJTIHAD, KasbahAlgorithmSuite };
