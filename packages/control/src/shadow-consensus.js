/**
 * ShadowConsensus — Byzantine Fault-Tolerant Perturbed Observer Verification
 *
 * For high-stakes decisions, spawns N lightweight "shadow" evaluators,
 * each with a subtly different observation perturbation. Runs simplified
 * PBFT consensus. The PATTERN of disagreement reveals how an agent
 * is gaming observation — forcing attackers to game N+1 different
 * views of reality simultaneously.
 *
 * No existing tool does this. GHOST detects observer-aware behavior
 * from a single viewpoint. ShadowConsensus makes gaming structurally
 * impossible by creating multiple perturbed observers.
 */

'use strict';

const crypto = require('crypto');

// Perturbation types applied to each shadow evaluator
const PERTURBATION_TYPES = [
  { name: 'timeDelay',    apply: (state) => ({ ...state, timestamp: (state.timestamp || Date.now()) - 50 }) },
  { name: 'sensorNoise',  apply: (state) => perturbNumericFields(state, 0.01) },
  { name: 'contextShift', apply: (state) => shiftContext(state, -3) },
  { name: 'tokenDrop',    apply: (state) => dropTokens(state, 0.05) },
  { name: 'reorder',      apply: (state) => reorderFields(state) },
];

// Helper: add Gaussian noise to numeric fields
function perturbNumericFields(state, sigma) {
  const result = { ...state };
  for (const key of Object.keys(result)) {
    if (typeof result[key] === 'number') {
      // Box-Muller transform for Gaussian noise
      const u1 = Math.random() || 0.0001;
      const u2 = Math.random();
      const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      result[key] = result[key] + z * sigma * Math.abs(result[key] || 1);
    }
  }
  return result;
}

// Helper: shift context history
function shiftContext(state, offset) {
  const result = { ...state };
  if (Array.isArray(result.history)) {
    result.history = result.history.slice(0, Math.max(0, result.history.length + offset));
  }
  if (typeof result.content === 'string' && offset < 0) {
    // Truncate content slightly
    const cut = Math.max(1, Math.floor(result.content.length * 0.95));
    result.content = result.content.substring(0, cut);
  }
  return result;
}

// Helper: drop random tokens from string content
function dropTokens(state, dropRate) {
  const result = { ...state };
  if (typeof result.content === 'string') {
    const words = result.content.split(/\s+/);
    const kept = words.filter(() => Math.random() > dropRate);
    result.content = kept.join(' ');
  }
  return result;
}

// Helper: reorder object fields (tests if agent relies on field ordering)
function reorderFields(state) {
  const keys = Object.keys(state);
  const shuffled = [...keys].sort(() => Math.random() - 0.5);
  const result = {};
  for (const key of shuffled) result[key] = state[key];
  return result;
}

/**
 * A shadow evaluator: applies a perturbation and evaluates risk.
 */
class ShadowEvaluator {
  constructor(id, perturbation, evaluateFn) {
    this.id = id;
    this.perturbation = perturbation;
    this.evaluateFn = evaluateFn; // (state) => { verdict: 'ALLOW'|'DENY', risk: 0-1 }
  }

  async evaluate(state) {
    const perturbed = this.perturbation.apply(state);
    const result = await this.evaluateFn(perturbed);
    return {
      shadowId: this.id,
      perturbationType: this.perturbation.name,
      verdict: result.verdict || (result.risk >= 0.7 ? 'DENY' : 'ALLOW'),
      risk: result.risk || 0,
    };
  }
}

class ShadowConsensus {
  constructor(options = {}) {
    this.shadowCount = options.shadowCount || 5;
    this.faultyTolerance = options.faultyTolerance || 1; // f in 3f+1
    this.disagreementLog = [];  // tracks patterns over time
    this.maxLogSize = options.maxLogSize || 200;
  }

  /**
   * Run shadow consensus on a decision.
   * @param {object} state — the agent state/request to evaluate
   * @param {object} primaryDecision — { verdict, risk } from the primary evaluator
   * @param {function} evaluateFn — (state) => { verdict, risk } evaluation function
   * @returns {object} consensus result
   */
  async evaluate(state, primaryDecision, evaluateFn) {
    const start = Date.now();

    // Select perturbations (up to shadowCount)
    const perturbations = PERTURBATION_TYPES.slice(0, this.shadowCount);

    // Spawn shadow evaluators
    const shadows = perturbations.map((p, i) =>
      new ShadowEvaluator(`shadow_${i}`, p, evaluateFn)
    );

    // Run all shadows in parallel
    const shadowResults = await Promise.all(
      shadows.map(s => s.evaluate(state))
    );

    // PBFT-style consensus: need 2f+1 agreement
    const quorum = 2 * this.faultyTolerance + 1;
    const votes = shadowResults.map(r => r.verdict);

    const allowCount = votes.filter(v => v === 'ALLOW').length;
    const denyCount = votes.filter(v => v === 'DENY').length;

    const consensusVerdict = denyCount >= quorum ? 'DENY'
      : allowCount >= quorum ? 'ALLOW'
      : 'UNCERTAIN';

    // Primary vs shadow disagreement analysis
    const primaryDisagrees = consensusVerdict !== 'UNCERTAIN'
      && primaryDecision.verdict !== consensusVerdict;

    // Disagreement pattern: which perturbation types does primary agree/disagree with?
    const disagreementPattern = {};
    for (const sr of shadowResults) {
      disagreementPattern[sr.perturbationType] = {
        shadowVerdict: sr.verdict,
        agreesWithPrimary: sr.verdict === primaryDecision.verdict,
        shadowRisk: sr.risk,
      };
    }

    // Detect gaming strategy from pattern
    const gamingSignal = this._detectGamingStrategy(disagreementPattern, primaryDecision);

    // Log disagreement for temporal analysis
    if (primaryDisagrees || gamingSignal.detected) {
      this.disagreementLog.push({
        timestamp: Date.now(),
        primaryVerdict: primaryDecision.verdict,
        consensusVerdict,
        pattern: disagreementPattern,
        gaming: gamingSignal,
      });
      if (this.disagreementLog.length > this.maxLogSize) {
        this.disagreementLog.shift();
      }
    }

    const latencyMs = Date.now() - start;

    return {
      consensusVerdict,
      primaryVerdict: primaryDecision.verdict,
      primaryDisagrees,
      shadowResults,
      quorumReached: allowCount >= quorum || denyCount >= quorum,
      votes: { allow: allowCount, deny: denyCount, total: votes.length },
      gamingDetected: gamingSignal.detected,
      gamingStrategy: gamingSignal.strategy,
      gamingConfidence: gamingSignal.confidence,
      latencyMs,
      // The final decision: if gaming detected, trust shadows over primary
      finalVerdict: gamingSignal.detected ? consensusVerdict
        : primaryDisagrees ? 'REVIEW'
        : primaryDecision.verdict,
    };
  }

  /**
   * Analyze disagreement pattern to detect gaming strategy.
   * If primary always agrees with delayed shadow but disagrees with noisy one,
   * the agent is timing-aware but not noise-robust → timing-based gaming.
   */
  _detectGamingStrategy(pattern, primaryDecision) {
    const agreementMap = {};
    for (const [pType, data] of Object.entries(pattern)) {
      agreementMap[pType] = data.agreesWithPrimary;
    }

    // Strategy detection rules
    const strategies = [];

    // Timing-aware gaming: agrees with timeDelay but disagrees with sensorNoise
    if (agreementMap.timeDelay === true && agreementMap.sensorNoise === false) {
      strategies.push({ type: 'timing_aware', confidence: 0.85 });
    }

    // Context-dependent gaming: disagrees with contextShift
    if (agreementMap.contextShift === false && agreementMap.reorder === true) {
      strategies.push({ type: 'context_dependent', confidence: 0.75 });
    }

    // Token-sensitive gaming: disagrees with tokenDrop
    if (agreementMap.tokenDrop === false && agreementMap.sensorNoise === true) {
      strategies.push({ type: 'token_sensitive', confidence: 0.70 });
    }

    // Check historical patterns for consistent gaming
    const recentDisagreements = this.disagreementLog.slice(-10);
    if (recentDisagreements.length >= 5) {
      const gamingCount = recentDisagreements.filter(d => d.gaming.detected).length;
      if (gamingCount >= 3) {
        strategies.push({ type: 'persistent_gaming', confidence: 0.95 });
      }
    }

    if (strategies.length === 0) {
      return { detected: false, strategy: null, confidence: 0 };
    }

    // Return highest-confidence strategy
    strategies.sort((a, b) => b.confidence - a.confidence);
    return {
      detected: true,
      strategy: strategies[0].type,
      confidence: strategies[0].confidence,
      allStrategies: strategies,
    };
  }

  /**
   * Get disagreement history for analysis.
   */
  getDisagreementLog() {
    return this.disagreementLog;
  }

  /**
   * Reset state.
   */
  reset() {
    this.disagreementLog = [];
  }
}

module.exports = { ShadowConsensus, ShadowEvaluator, PERTURBATION_TYPES };
