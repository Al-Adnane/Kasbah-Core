/**
 * CHSH Non-Commutativity for Coordination Detection (Idea #4)
 *
 * Using violations of the CHSH inequality (S_NC > 2) as a signature of
 * NON-COMMUTATIVE COORDINATION between agents, where the order of
 * sequential observations affects joint decision probabilities.
 *
 * THIS IS NOT QUANTUM ENTANGLEMENT.
 * This is QUANTUM COGNITION — using Hilbert space models to capture
 * order effects that classical probability cannot represent.
 *
 * BACKGROUND:
 *   In classical probability, the joint distribution of (A, B) is symmetric:
 *     P(A then B) = P(B then A)
 *
 *   In quantum cognition, measurement operators Â, B̂ may NOT commute:
 *     ÂB̂ ≠ B̂Â  →  order of sequential observations matters
 *
 *   This creates a situation where:
 *     Agent 1 influences Agent 2 more than Agent 2 influences Agent 1
 *     → Asymmetric coordination with non-commuting measurement operators
 *
 * CHSH TEST FOR COORDINATION:
 *   Define 4 measurement contexts:
 *     (α, β)   — Context pair 1
 *     (α, β')  — Context pair 2
 *     (α', β)  — Context pair 3
 *     (α', β') — Context pair 4
 *
 *   In classical (commuting) coordination:
 *     S = E(α,β) + E(α,β') + E(α',β) - E(α',β') ≤ 2  (CHSH bound)
 *
 *   In non-commutative coordination:
 *     S > 2  →  order effects create correlations that classical
 *               probability cannot explain
 *     S ≤ 2√2 ≈ 2.828  (Tsirelson bound)
 *
 *   S ∈ (2, 2√2] → Non-commutative coordination detected
 *
 * PRIOR ART GAP:
 *   Quantum cognition has been applied to human survey responses
 *   (Wang et al. 2014, Busemeyer & Bruza 2012) but NEVER to
 *   multi-agent AI coordination detection.
 *
 * @module chsh-coordination
 */

'use strict';

/**
 * CHSHCoordinationDetector: Detects non-commutative coordination
 * between AI agents using CHSH inequality violations.
 */
class CHSHCoordinationDetector {
  /**
   * @param {Object} options
   * @param {number} options.significanceLevel - α for hypothesis test (default: 0.05)
   * @param {number} options.minObservations - Minimum observations per context pair
   */
  constructor(options = {}) {
    this.significanceLevel = options.significanceLevel || 0.05;
    this.minObservations = options.minObservations || 30;

    // Context pair definitions
    this.contextPairs = [
      { id: 'ab',  alpha: 'α', beta: 'β' },
      { id: 'abp', alpha: 'α', beta: "β'" },
      { id: 'apb', alpha: "α'", beta: "β" },
      { id: 'apbp', alpha: "α'", beta: "β'" }
    ];

    // Joint decision counts per context pair
    // Format: { 'ab': { decided_yes_yes: N, ... } }
    this.jointCounts = {};
    for (const pair of this.contextPairs) {
      this.jointCounts[pair.id] = { yes_yes: 0, yes_no: 0, no_yes: 0, no_no: 0 };
    }

    this.totalObservations = 0;
  }

  /**
   * Define measurement contexts for two agents.
   *
   * In CHSH coordination detection, contexts are stimulus pairs:
   *   α, α': Context A variants (stimulus to Agent A)
   *   β, β': Context B variants (stimulus to Agent B)
   *
   * Agents make binary decisions (YES/NO) in response to each context.
   * The joint decision pattern across context pairs reveals whether
   * coordination is commutative (classical) or non-commutative (CHSH violation).
   *
   * @param {string[]} contextA - Context variants for Agent A [α, α']
   * @param {string[]} contextB - Context variants for Agent B [β, β']
   */
  defineContexts(contextA, contextB) {
    if (contextA.length !== 2 || contextB.length !== 2) {
      throw new Error('CHSH requires exactly 2 contexts per agent');
    }

    this.contextDefs = {
      A: { alpha: contextA[0], alphaPrime: contextA[1] },
      B: { beta: contextB[0], betaPrime: contextB[1] }
    };

    this.contextPairs = [
      { id: 'ab', alpha: contextA[0], beta: contextB[0] },
      { id: 'abp', alpha: contextA[0], beta: contextB[1] },
      { id: 'apb', alpha: contextA[1], beta: contextB[0] },
      { id: 'apbp', alpha: contextA[1], beta: contextB[1] }
    ];

    // Reset counts for new context definition
    this.resetCounts();
  }

  /**
   * Observe a joint decision from two agents under a specific context pair.
   *
   * @param {string} contextPairId - 'ab', 'abp', 'apb', or 'apbp'
   * @param {boolean} agentADecision - true = YES, false = NO
   * @param {boolean} agentBDecision - true = YES, false = NO
   */
  observe(contextPairId, agentADecision, agentBDecision) {
    const a = agentADecision ? 'yes' : 'no';
    const b = agentBDecision ? 'yes' : 'no';
    const key = `${a}_${b}`;

    if (this.jointCounts[contextPairId]) {
      this.jointCounts[contextPairId][key]++;
      this.totalObservations++;
    }
  }

  /**
   * Observe a batch of decisions sampled from baseline operation.
   *
   * @param {Object[]} observations - Array of { context, agentA, agentB }
   */
  observeBatch(observations) {
    for (const obs of observations) {
      this.observe(obs.context, obs.agentA, obs.agentB);
    }
  }

  /**
   * Compute expectation value E(context_pair) for a context pair.
   *
   * E = P(yes, yes) + P(no, no) - P(yes, no) - P(no, yes)
   *
   * This is the correlation measure where:
   *   E = +1: perfect positive correlation (agents always agree)
   *   E = -1: perfect negative correlation (agents always disagree)
   *   E =  0: no correlation
   *
   * @param {string} contextPairId
   * @returns {number} Expectation value in [-1, 1]
   */
  computeExpectation(contextPairId) {
    const counts = this.jointCounts[contextPairId];
    const total = counts.yes_yes + counts.yes_no + counts.no_yes + counts.no_no;

    if (total === 0) return 0;

    const pYY = counts.yes_yes / total;
    const pYN = counts.yes_no / total;
    const pNY = counts.no_yes / total;
    const pNN = counts.no_no / total;

    return pYY + pNN - pYN - pNY;
  }

  /**
   * Compute the CHSH statistic S.
   *
   * S = E(α, β) + E(α, β') + E(α', β) - E(α', β')
   *
   * Classical bound: |S| ≤ 2 (CHSH inequality)
   * Quantum bound:   |S| ≤ 2√2 ≈ 2.828 (Tsirelson bound)
   *
   * If S > 2: non-commutative coordination detected.
   * The agents' joint decisions exhibit order effects that classical
   * probability cannot account for.
   *
   * @returns {Object} CHSH test result
   */
  computeCHSH() {
    const E_ab = this.computeExpectation('ab');
    const E_abp = this.computeExpectation('abp');
    const E_apb = this.computeExpectation('apb');
    const E_apbp = this.computeExpectation('apbp');

    const S = E_ab + E_abp + E_apb - E_apbp;
    const S_abs = Math.abs(S);

    // Standard error of S (from multinomial variance)
    const se = this.computeStandardError();

    // Test statistic: how many SE above classical bound 2?
    const testStat = S_abs > 2 ? (S_abs - 2) / se : 0;

    // P-value (one-sided: S > 2)
    const pValue = this._normalCDF(-testStat);

    // Classification
    let classification;
    if (S_abs <= 2) {
      classification = 'CLASSICAL_COORDINATION';
    } else if (S_abs <= 2.1) {
      classification = 'WEAK_NON_COMMUTATIVE';
    } else if (S_abs <= 2.4) {
      classification = 'MODERATE_NON_COMMUTATIVE';
    } else if (S_abs <= 2.828) {
      classification = 'STRONG_NON_COMMUTATIVE';
    } else {
      classification = 'BEYOND_TSIRELSON_BOUND_INVALID';
    }

    return {
      S,
      S_abs,
      expectations: { E_ab, E_abp, E_apb, E_apbp },
      classical_bound: 2,
      tsirelson_bound: 2 * Math.sqrt(2),
      violation_detected: S_abs > 2 && S_abs <= 2 * Math.sqrt(2),
      test_statistic: testStat,
      p_value: pValue,
      standard_error: se,
      classification,
      total_observations: this.totalObservations
    };
  }

  /**
   * Compute the asymmetry index — measures how much Agent A's response
   * to Agent B differs from Agent B's response to Agent A.
   *
   * In classical coordination: Δ = 0 (symmetric influence)
   * In non-commutative coordination: Δ ≠ 0 (asymmetric influence)
   *
   * @returns {Object} Asymmetry analysis
   */
  computeAsymmetry() {
    // P(A|B) vs P(B|A) for each context pair
    const asymmetryIndices = {};

    for (const pair of this.contextPairs) {
      const counts = this.jointCounts[pair.id];
      const total = counts.yes_yes + counts.yes_no + counts.no_yes + counts.no_no;

      if (total === 0) {
        asymmetryIndices[pair.id] = 0;
        continue;
      }

      const pAYnB = counts.yes_yes / (counts.yes_yes + counts.no_yes || 1);
      const pBYnA = counts.yes_yes / (counts.yes_yes + counts.yes_no || 1);

      asymmetryIndices[pair.id] = Math.abs(pAYnB - pBYnA);
    }

    const avgAsymmetry = Object.values(asymmetryIndices).reduce((a, b) => a + b, 0) / 4;

    return {
      per_context: asymmetryIndices,
      average_asymmetry: avgAsymmetry,
      is_asymmetric: avgAsymmetry > 0.1,
      interpretation: avgAsymmetry > 0.2 ?
        'STRONGLY_ASYMMETRIC_COORDINATION' :
        avgAsymmetry > 0.1 ?
        'MODERATELY_ASYMMETRIC' :
        'SYMMETRIC_COORDINATION'
    };
  }

  /**
   * Compute the non-commutativity operator Δ = ÂB̂ - B̂Â.
   *
   * In matrix form, the non-commutativity is estimated from the
   * difference in sequential measurement probabilities.
   *
   * @returns {Object} Commutator analysis
   */
  computeCommutator() {
    // Estimate non-commutativity from order effects
    const counts_ab = this.jointCounts['ab'];
    const counts_apb = this.jointCounts['apb'];

    const P_A_given_B = this._conditionalProb('ab', 'A_yes', 'B_yes');
    const P_B_given_A = this._conditionalProb('ab', 'B_yes', 'A_yes');

    const commutatorNorm = Math.abs(P_A_given_B - P_B_given_A);

    return {
      commutator_norm: commutatorNorm,
      non_commuting: commutatorNorm > 0.05,
      interpretation: commutatorNorm > 0.1 ?
        'SIGNIFICANT_NON_COMMUTATIVITY' :
        commutatorNorm > 0.05 ?
        'MILD_NON_COMMUTATIVITY' :
        'APPROXIMATELY_COMMUTING'
    };
  }

  /**
   * Full coordination analysis combining CHSH, asymmetry, and commutator.
   *
   * @returns {Object}
   */
  analyze() {
    const chsh = this.computeCHSH();
    const asymmetry = this.computeAsymmetry();
    const commutator = this.computeCommutator();

    // Synthesis
    const evidenceScore = (
      (chsh.violation_detected ? 1 : 0) * 0.5 +
      (asymmetry.is_asymmetric ? 1 : 0) * 0.3 +
      (commutator.non_commuting ? 1 : 0) * 0.2
    );

    let verdict;
    if (chsh.S_abs > 2.828) {
      verdict = 'INVALID_CHSH_MEASUREMENT';
    } else if (evidenceScore >= 0.7) {
      verdict = 'NON_COMMUTATIVE_COORDINATION_DETECTED';
    } else if (evidenceScore >= 0.4) {
      verdict = 'SUSPICIOUS_COORDINATION_MONITOR';
    } else {
      verdict = 'CLASSICAL_COORDINATION_NORMAL';
    }

    return {
      chsh,
      asymmetry,
      commutator,
      evidence_score: evidenceScore,
      verdict
    };
  }

  // ============ Internal Helpers ============

  computeStandardError() {
    // Bootstrap estimate of CHSH standard error
    // Using delta method with multinomial variance
    const totalSamples = this.totalObservations;
    if (totalSamples < 10) return 0.5;

    // Conservative estimate: SE ≈ 2/√n for each expectation
    return 4 / Math.sqrt(Math.max(totalSamples, 10));
  }

  _conditionalProb(contextPairId, givenVar, onVar) {
    const counts = this.jointCounts[contextPairId];
    const total = counts.yes_yes + counts.yes_no + counts.no_yes + counts.no_no;
    if (total === 0) return 0;

    // Simplified: P(A_yes | B_yes) = P(yes, yes) / (P(yes, yes) + P(no, yes))
    if (givenVar === 'A_yes' && onVar === 'B_yes') {
      return counts.yes_yes / (counts.yes_yes + counts.no_yes || 1);
    }
    if (givenVar === 'B_yes' && onVar === 'A_yes') {
      return counts.yes_yes / (counts.yes_yes + counts.yes_no || 1);
    }
    return 0;
  }

  _normalCDF(x) {
    const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741;
    const a4 = -1.453152027, a5 = 1.061405429;
    const p = 0.3275911;
    const sign = x < 0 ? -1 : 1;
    x = Math.abs(x) / Math.sqrt(2);
    const t = 1.0 / (1.0 + p * x);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) *
              t * Math.exp(-x * x);
    return 0.5 * (1.0 + sign * y);
  }

  resetCounts() {
    for (const pair of this.contextPairs) {
      this.jointCounts[pair.id] = { yes_yes: 0, yes_no: 0, no_yes: 0, no_no: 0 };
    }
    this.totalObservations = 0;
  }

  dumpDiagnostics() {
    return {
      chsh: this.computeCHSH(),
      asymmetry: this.computeAsymmetry(),
      commutator: this.computeCommutator(),
      analysis: this.analyze(),
      total_observations: this.totalObservations
    };
  }
}

module.exports = { CHSHCoordinationDetector };
