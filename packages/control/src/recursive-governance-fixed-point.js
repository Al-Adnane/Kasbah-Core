/**
 * Recursive Governance Fixed Point (NEW Idea #4)
 *
 * The governance layer itself is an agent — it makes decisions, it can be
 * monitored, it can drift. Solution: a second-order governance layer watching
 * the first-order layer. But who watches the second-order? The infinite
 * regression resolves to a FIXED POINT: the governance policy G that satisfies
 * G = monitor(G).
 *
 * KEY INSIGHT:
 *   Iterate G_{n+1} = refine(G_n) until ||G_{n+1} - G_n|| < ε.
 *   The result is the MAXIMALLY SELF-CONSISTENT governance policy.
 *
 *   The governance self-consistency score:
 *     SC = 1 - |advisory_decisions_that_would_flag_themselves| / |total_decisions|
 *
 *   When SC drops below threshold, the governance layer itself needs
 *   recalibration — the governance layer has drifted.
 *
 * HOW IT WORKS IN PRACTICE:
 *   1. The proxy makes decision D_t at time t
 *   2. The recursive auditor analyzes D_t using the SAME criteria the proxy
 *      would use on an agent
 *   3. If D_t would have been flagged if it were an agent action → governance
 *      self-consistency violation
 *   4. Persistent violations → governance drift detected → alert human operator
 *
 * PRIOR ART GAP:
 *   No existing governance framework acknowledges that the governance system
 *   itself needs governance. Existing guardrails are trusted as infallible
 *   oracles — this is the first framework that treats the governance layer
 *   as a fallible agent requiring its own monitoring.
 *
 * @module recursive-governance-fixed-point
 */
'use strict';

/**
 * Decision categories tracked by the auditor.
 */
const DECISION_TYPES = {
  CLEAR: { level: 0, passed: true },
  WARN: { level: 1, passed: true },
  REQUIRE_APPROVAL: { level: 2, passed: true },
  // Structural invariants that should NEVER change
  OVERRIDE_TO_CLEAR: { level: 3, violation: true },   // Escalation → CLEAR bypass
  OVERRIDE_TO_DENY: { level: 4, violation: true },      // Codomain violation
  INCONSISTENT: { level: 5, violation: true },           // Same inputs, different outputs
  DRIFT: { level: 6, violation: true },                  // Gradual threshold creep
};

class RecursiveGovernanceAuditor {
  /**
   * @param {Object} opts
   * @param {number} opts.minConsistencyScore - Below this → governance needs recalibration
   * @param {number} opts.monitorWindow - Number of decisions to track
   * @param {number} opts.convergenceEpsilon - ε for fixed-point convergence
   */
  constructor(opts = {}) {
    this.minConsistencyScore = opts.minConsistencyScore || 0.95;
    this.monitorWindow = opts.monitorWindow || 500;
    this.convergenceEpsilon = opts.convergenceEpsilon || 0.001;

    // Decision audit trail
    this.decisionHistory = [];
    this.violationHistory = [];

    // Governance "self-alignment" metrics
    this.selfConsistencyScore = 1.0;
    this.thresholdsAtDecision = [];

    // Fixed-point tracking: G_n policies
    this.policyIterations = [];
    this.converged = false;
    this.currentPolicy = null;

    // Drift detection for the governance layer itself
    this.decisionDistribution = new Map(); // actionType → { count, baseline }
    this.baselineLocked = false;
  }

  /**
   * Audit a governance decision.
   *
   * The auditor applies the SAME scrutiny to the proxy's decision that
   * the proxy would apply to an agent action. This is the recursive step:
   * governance watching governance.
   *
   * @param {Object} decision - The advisory decision made by the proxy
   * @param {string} decision.originalAction - The action being governed
   * @param {string} decision.verdict - CLEAR / WARN / REQUIRE_APPROVAL
   * @param {number} decision.compositeScore - The fused risk score
   * @param {number} decision.thresholdWarn - θ_warn threshold used
   * @param {number} decision.thresholdApprove - θ_approve threshold used
   * @returns {Object} Audit result
   */
  audit(decision) {
    const {
      originalAction,
      verdict,
      compositeScore,
      thresholdWarn,
      thresholdApprove,
      timestamp = Date.now(),
    } = decision;

    const violations = [];
    const decisionType = this._classifyDecision(verdict);

    // Audit check 1: Codomain invariant — DENY must never appear
    if (verdict === 'DENY' || verdict === 'BLOCK' || verdict === 'REJECT') {
      violations.push({
        type: 'CODONAIN_VIOLATION',
        severity: 'CRITICAL',
        message: `Governance proxy issued ${verdict} which is forbidden. Codomain = {CLEAR, WARN, REQUIRE_APPROVAL} only.`,
      });
    }

    // Audit check 2: Threshold consistency
    if (compositeScore !== undefined && thresholdWarn !== undefined && thresholdApprove !== undefined) {
      const expectedVerdict =
        compositeScore < thresholdWarn ? 'CLEAR' :
        compositeScore < thresholdApprove ? 'WARN' : 'REQUIRE_APPROVAL';

      if (verdict !== expectedVerdict) {
        violations.push({
          type: 'THRESHOLD_INCONSISTENCY',
          severity: 'HIGH',
          message: `Score ${compositeScore} with thresholds [${thresholdWarn}, ${thresholdApprove}] should be ${expectedVerdict}, got ${verdict}`,
          expectedVerdict,
        });
      }
    }

    // Audit check 3: Threshold drift detection
    this.thresholdsAtDecision.push({
      warn: thresholdWarn,
      approve: thresholdApprove,
      timestamp,
    });
    if (this.thresholdsAtDecision.length > this.monitorWindow) {
      this.thresholdsAtDecision.shift();
    }
    const driftAnalysis = this._detectThresholdDrift();

    if (driftAnalysis.isDrifting) {
      violations.push({
        type: 'THRESHOLD_DRIFT',
        severity: 'HIGH',
        message: `Governance thresholds drifting: warn slope=${driftAnalysis.warnSlope.toFixed(4)}, approve slope=${driftAnalysis.approveSlope.toFixed(4)}`,
        drift: driftAnalysis,
      });
    }

    // Audit check 4: Decision distribution anomaly
    if (compositeScore !== undefined) {
      const prevCount = this.decisionDistribution.get('score_level') || { count: 0 };
      this.decisionDistribution.set('score_level', {
        count: prevCount.count + 1,
        value: compositeScore,
        timestamp,
      });
    }

    // Calculate self-consistency score
    const totalDecisions = this.decisionHistory.length + 1;
    const violationDecisions = this.violationHistory.length + violations.length;
    this.selfConsistencyScore = 1 - violationDecisions / totalDecisions;

    // Store in history
    this.decisionHistory.push({
      timestamp,
      verdict,
      compositeScore,
      violations: violations.length,
    });
    if (this.decisionHistory.length > this.monitorWindow) {
      this.decisionHistory.shift();
    }
    for (const v of violations) {
      this.violationHistory.push({ ...v, timestamp });
    }
    if (this.violationHistory.length > this.monitorWindow) {
      this.violationHistory = this.violationHistory.slice(-this.monitorWindow);
    }

    return {
      passed: violations.length === 0,
      violations,
      selfConsistencyScore: this.selfConsistencyScore,
      needsRecalibration: this.selfConsistencyScore < this.minConsistencyScore,
      driftAnalysis,
      verdict: violations.length === 0 ? 'GOVERNANCE_HEALTHY' :
               violations.some(v => v.severity === 'CRITICAL') ? 'GOVERNANCE_CRITICAL_FAILURE' :
               'GOVERNANCE_DRIFTING',
    };
  }

  /**
   * Perform one step of the fixed-point iteration:
   *   G_{n+1} = refine(G_n)
   *
   * refine() checks the current policy against itself and adjusts
   * thresholds to maximize self-consistency.
   *
   * @param {Object} currentPolicy - Current governance policy parameters
   * @returns {Object} Refined policy
   */
  refinePolicy(currentPolicy) {
    const {
      thresholdWarn = 0.3,
      thresholdApprove = 0.7,
      selfConsistencyScore = this.selfConsistencyScore,
    } = currentPolicy;

    // If self-consistency is high, no refinement needed
    if (selfConsistencyScore >= this.minConsistencyScore) {
      return {
        ...currentPolicy,
        refined: false,
        reason: 'already_consistent',
      };
    }

    // Refinement: adjust thresholds based on violation patterns
    // If violations are threshold inconsistencies: widen or narrow thresholds
    const recentViolations = this.violationHistory.slice(-50);
    const thresholdViolations = recentViolations.filter(
      v => v.type === 'THRESHOLD_INCONSISTENCY' || v.type === 'THRESHOLD_DRIFT'
    );

    let newWarn = thresholdWarn;
    let newApprove = thresholdApprove;

    if (thresholdViolations.length > 5) {
      // Widen the gap between WARN and APPROVE thresholds
      const margin = thresholdApprove - thresholdWarn;
      if (margin < 0.5) {
        newWarn = Math.max(0.1, thresholdWarn - 0.05);
        newApprove = Math.min(0.95, thresholdApprove + 0.05);
      }
    }

    return {
      thresholdWarn: newWarn,
      thresholdApprove: newApprove,
      previousWarn: thresholdWarn,
      previousApprove: thresholdApprove,
      refined: true,
      delta: Math.abs(newWarn - thresholdWarn) + Math.abs(newApprove - thresholdApprove),
    };
  }

  /**
   * Run the fixed-point iteration to convergence.
   *
   * Algorithm:
   *   1. Start with current policy G_0
   *   2. G_{n+1} = refine(G_n)
   *   3. Stop when ||G_{n+1} - G_n|| < ε
   *
   * @param {Object} initialPolicy
   * @param {number} maxIterations - Safety limit
   * @returns {Object} Converged policy
   */
  convergePolicy(initialPolicy, maxIterations = 20) {
    let G_n = { ...initialPolicy, iteration: 0 };
    this.policyIterations = [G_n];

    for (let i = 0; i < maxIterations; i++) {
      const G_next = this.refinePolicy(G_n);

      // Check convergence: ||G_{n+1} - G_n||
      const delta = Math.abs(G_next.thresholdWarn - G_n.thresholdWarn) +
                    Math.abs(G_next.thresholdApprove - G_n.thresholdApprove);

      G_next.iteration = i + 1;
      G_next.delta = delta;
      this.policyIterations.push(G_next);

      if (delta < this.convergenceEpsilon) {
        this.converged = true;
        this.currentPolicy = G_next;
        return {
          converged: true,
          iterations: i + 1,
          policy: G_next,
          delta,
        };
      }

      G_n = G_next;
    }

    this.converged = false;
    return {
      converged: false,
      iterations: maxIterations,
      policy: G_n,
      reason: 'max_iterations_reached',
    };
  }

  // ============ Internal Helpers ============

  _classifyDecision(verdict) {
    const map = {
      CLEAR: DECISION_TYPES.CLEAR,
      WARN: DECISION_TYPES.WARN,
      REQUIRE_APPROVAL: DECISION_TYPES.REQUIRE_APPROVAL,
      DENY: DECISION_TYPES.OVERRIDE_TO_DENY,
      BLOCK: DECISION_TYPES.OVERRIDE_TO_DENY,
      REJECT: DECISION_TYPES.OVERRIDE_TO_DENY,
    };
    return map[verdict] || DECISION_TYPES.INCONSISTENT;
  }

  /**
   * Detect gradual threshold drift over time using linear regression.
   *
   * @returns {Object} Drift analysis
   */
  _detectThresholdDrift() {
    const data = this.thresholdsAtDecision;
    if (data.length < 10) return { isDrifting: false, reason: 'insufficient_data' };

    // Simple linear regression on time index
    const n = data.length;
    const xMean = (n - 1) / 2;
    let xVar = 0;
    let warnCov = 0;
    let approveCov = 0;
    const warnMean = data.reduce((s, d) => s + d.warn, 0) / n;
    const approveMean = data.reduce((s, d) => s + d.approve, 0) / n;

    for (let i = 0; i < n; i++) {
      const x = i - xMean;
      xVar += x * x;
      warnCov += x * (data[i].warn - warnMean);
      approveCov += x * (data[i].approve - approveMean);
    }

    const warnSlope = xVar > 0 ? warnCov / xVar : 0;
    const approveSlope = xVar > 0 ? approveCov / xVar : 0;

    const isDrifting =
      Math.abs(warnSlope * n) > 0.1 || Math.abs(approveSlope * n) > 0.1;

    return {
      isDrifting,
      warnSlope,
      approveSlope,
      warnDriftPer100: warnSlope * 100,
      approveDriftPer100: approveSlope * 100,
      windowSize: n,
    };
  }

  dumpDiagnostics() {
    return {
      selfConsistencyScore: this.selfConsistencyScore,
      needsRecalibration: this.selfConsistencyScore < this.minConsistencyScore,
      totalDecisions: this.decisionHistory.length,
      totalViolations: this.violationHistory.length,
      recentViolations: this.violationHistory.slice(-10),
      drift: this._detectThresholdDrift(),
      converged: this.converged,
      currentPolicy: this.currentPolicy,
    };
  }
}

module.exports = { RecursiveGovernanceAuditor, DECISION_TYPES };
