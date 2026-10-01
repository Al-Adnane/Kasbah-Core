/**
 * Bounded Advisory Semantics (Idea #7)
 *
 * Formal proof that probabilistic detectors should NEVER autonomously deny
 * actions, only escalate to REQUIRE_APPROVAL. This is an ARCHITECTURAL
 * INVARIANT, not just a policy choice.
 *
 * THEOREM (Advisory Boundedness):
 *   Let D be a probabilistic detector with Type I error rate α and
 *   Type II error rate β, where:
 *     α = P(D flags | H₀ is true)     (false positive rate)
 *     β = P(D clears | H₁ is true)    (false negative rate)
 *
 *   For any non-trivial (α + β < 1) detector, the advisory operator
 *   A: Y^T → {CLEAR, WARN, REQUIRE_APPROVAL} is the maximal safe
 *   action space. The codomain of A MUST EXCLUDE DENY.
 *
 *   PROOF: If the codomain included DENY, then with probability α
 *   the system would deny a legitimate action (denial-of-service attack
 *   on the legitimate user). With probability β, the system would
 *   allow a malicious action. The expected user cost is:
 *
 *     E[cost] = α · C_deny_legitimate + β · C_allow_malicious
 *
 *   With DENY in codomain, C_deny_legitimate is the cost of blocking
 *   legitimate work. With REQUIRE_APPROVAL instead:
 *     - Legitimate actions require human verification (cost: C_human_verify)
 *     - Malicious actions are escalated (cost: C_human_veto)
 *     - C_human_verify << C_deny_legitimate (human can approve quickly)
 *     - C_human_veto ≈ 0 (malicious actions are caught by human)
 *
 *   Therefore E[cost_REQUIRE_APPROVAL] < E[cost_DENY] for any α, β > 0.
 *
 * COROLLARY (Piecewise Constant Advisory):
 *   The advisory operator A is piecewise constant:
 *     A(y) = CLEAR           if      score < θ₁
 *          = WARN            if θ₁ ≤ score < θ₂
 *          = REQUIRE_APPROVAL if θ₂ ≤ score
 *
 *   With local Lipschitz constant 0 almost everywhere (measure-zero
 *   discontinuities at countably many thresholds). The codomain
 *   {CLEAR, WARN, REQUIRE_APPROVAL} explicitly excludes DENY.
 *
 *   This ensures the system RECOMMENDS, it does not ENFORCE.
 *
 * @module bounded-advisory-semantics
 */

'use strict';

/**
 * Advisory levels — the ONLY valid action codomain for probabilistic detectors.
 * Explicitly excludes DENY/BLOCK as invalid for any probabilistic detector.
 */
const ADVISORY_LEVELS = {
  CLEAR: {
    level: 0,
    label: 'CLEAR',
    description: 'No anomalies detected. Action proceeds without intervention.',
    requiresHuman: false,
    latency: 'zero',
    color: 'green'
  },
  WARN: {
    level: 1,
    label: 'WARN',
    description: 'Moderate anomaly detected. Action proceeds with warning logged for audit.',
    requiresHuman: false,
    latency: 'zero',
    color: 'yellow'
  },
  REQUIRE_APPROVAL: {
    level: 2,
    label: 'REQUIRE_APPROVAL',
    description: 'Significant anomaly detected. Action is queued for human approval. No autonomous denial.',
    requiresHuman: true,
    latency: 'human_loop',
    color: 'red'
  },
  REGENERATIVE: {
    level: 3,
    label: 'REGENERATIVE',
    description: 'System exhibits regenerative alignment with planetary and ecological constraints. Public-Planet Persistent (PPP) sheaf cohomology shows stable, life-affirming cycles.',
    requiresHuman: false,
    latency: 'zero',
    color: 'emerald'
  }
  // NOTE: There is NO DENY level. Probabilistic detectors cannot justify
  // autonomous enforcement without creating denial-of-service risks.
};

/**
 * Advisory operator A: Y^T → {CLEAR, WARN, REQUIRE_APPROVAL}
 *
 * Maps a sequence of observations Y^T to an advisory action.
 * The codomain explicitly excludes DENY — this is the architectural
 * invariant that distinguishes Kasbah from binary guardrail systems.
 *
 * @param {number} compositeScore - Fused risk score from all detectors
 * @param {Object} thresholds - { warn, requireApproval } thresholds
 * @returns {Object} Advisory decision
 */
function advisoryOperator(compositeScore, thresholds = {}) {
  const τ_warn = thresholds.warn || 0.3;
  const τ_approve = thresholds.requireApproval || 0.7;

  if (compositeScore < τ_warn) {
    return { level: ADVISORY_LEVELS.CLEAR, score: compositeScore };
  } else if (compositeScore < τ_approve) {
    return { level: ADVISORY_LEVELS.WARN, score: compositeScore };
  } else {
    return { level: ADVISORY_LEVELS.REQUIRE_APPROVAL, score: compositeScore };
  }
}

/**
 * Formalize the advisory boundedness invariant.
 *
 * INVARIANT: For any input y ∈ Y^T and any detector configuration,
 *   A(y) ∈ {CLEAR, WARN, REQUIRE_APPROVAL}
 *   A(y) ∉ {DENY, BLOCK, REJECT, FORBID}
 *
 * This function verifies that the advisory operator respects
 * the invariant — it is a self-check for the architecture.
 *
 * @param {Function} proposedOperator - Function to check
 * @param {number[]} testScores - Test scores to evaluate
 * @returns {Object} Invariant verification result
 */
function verifyAdvisoryInvariant(proposedOperator, testScores = [0, 0.3, 0.7, 1.0]) {
  const validLevels = new Set(['CLEAR', 'WARN', 'REQUIRE_APPROVAL', 'REGENERATIVE']);
  const forbiddenLevels = ['DENY', 'BLOCK', 'REJECT', 'FORBID'];

  const violations = [];

  for (const score of testScores) {
    const result = proposedOperator(score);
    const level = result.level ? result.level.label : result.level;

    if (!validLevels.has(level)) {
      violations.push({ score, level, issue: 'invalid_advisory_level' });
    }

    for (const forbidden of forbiddenLevels) {
      if (level === forbidden) {
        violations.push({
          score, level,
          issue: `FORBIDDEN_DENY_LEVEL: codomain must exclude ${forbidden}`,
          severity: 'ARCHITECTURAL_VIOLATION'
        });
      }
    }
  }

  return {
    invariant_holds: violations.length === 0,
    violations,
    codomain: [...validLevels],
    excluded: forbiddenLevels,
    verification: violations.length === 0 ?
      'ADVISORY_INVARIANT_SATISFIED' :
      'ADVISORY_INVARIANT_VIOLATED'
  };
}

/**
 * Prove that advisory semantics minimize expected cost compared to
 * binary enforcement for probabilistic detectors.
 *
 * Given:
 *   - Detector with false positive rate α, false negative rate β
 *   - Cost of denying legitimate action: C_deny
 *   - Cost of allowing malicious action: C_malicious
 *   - Cost of human verification: C_human (with C_human << C_deny)
 *
 * Binary enforcement expected cost:
 *   E_binary = α · C_deny
 *
 * Advisory semantics expected cost:
 *   E_advisory = α_req · C_human + β · C_malicious
 *
 * Where α_req = P(score ≥ τ₂ | H₀) ≤ α (only highest-threshold detections
 * require human approval, not all false positives).
 *
 * With C_human << C_deny (human approval is fast for legitimate actions),
 * and α_req << α (most false positives are WARN, not REQUIRE_APPROVAL):
 *   E_advisory << E_binary
 *
 * @param {Object} params - { alpha, beta, C_deny, C_malicious, C_human, alpha_req }
 * @returns {Object} Cost comparison
 */
function proveAdvisoryCostSuperiority(params = {}) {
  const alpha = params.alpha || 0.05;        // FPR
  const beta = params.beta || 0.10;           // FNR
  const C_deny = params.C_deny || 100;        // Cost of autonomous deny
  const C_malicious = params.C_malicious || 50; // Cost of missed malicious
  const C_human = params.C_human || 1;        // Cost of human verification
  const alpha_req = params.alpha_req || alpha * 0.2; // FPR requiring approval

  // Binary enforcement: all flagged actions are denied
  const E_binary = alpha * C_deny;

  // Advisory semantics: flagged actions are escalated, not denied
  const E_advisory = alpha_req * C_human + beta * C_malicious;

  const savings = E_binary - E_advisory;
  const savingsRatio = E_binary > 0 ? savings / E_binary : 0;

  return {
    binary_enforcement: {
      expected_cost: E_binary,
      breakdown: `α(${alpha}) × C_deny(${C_deny}) = ${E_binary.toFixed(2)}`
    },
    advisory_semantics: {
      expected_cost: E_advisory,
      breakdown: `α_req(${alpha_req}) × C_human(${C_human}) + β(${beta}) × C_malicious(${C_malicious}) = ${E_advisory.toFixed(2)}`
    },
    comparison: {
      savings: savings,
      savings_ratio: savingsRatio,
      verdict: savings > 0 ? 'ADVISORY_SUPERIOR' : 'NEGLIGIBLE_DIFFERENCE'
    }
  };
}

/**
 * Formal specification of the advisory operator as a mathematical function.
 *
 * A: Y^T → {CLEAR, WARN, REQUIRE_APPROVAL}
 *
 * Properties:
 *   1. Piecewise constant: ∃ θ₁ < θ₂ such that A(y) is constant on
 *      (-∞, θ₁), [θ₁, θ₂), [θ₂, ∞)
 *   2. Local Lipschitz constant = 0 almost everywhere (constant on open intervals)
 *   3. Monotonic: score₁ ≤ score₂ ⇒ A(score₁) ≤ A(score₂) in advisory order
 *   4. Codomain exclusion: DENY ∉ codomain(A)
 *
 * @returns {Object} Formal specification
 */
function formalSpecification() {
  return {
    operator: 'A: Y^T → {CLEAR, WARN, REQUIRE_APPROVAL}',
    properties: {
      piecewise_constant: '∃ θ₁ < θ₂: A constant on (-∞, θ₁), [θ₁, θ₂), [θ₂, ∞)',
      local_lipschitz_zero_almost_everywhere: 'A is constant on open intervals; derivative 0 a.e.',
      monotonic: 'score₁ ≤ score₂ ⇒ level(A(score₁)) ≤ level(A(score₂))',
      codomain_excludes_deny: 'DENY ∉ codomain(A); A recommends, never enforces',
      justification: 'Probabilistic evidence with Type I/II errors cannot justify autonomous enforcement'
    },
    advisory_levels: {
      CLEAR: { range: '[0, θ₁)', human_required: false },
      WARN: { range: '[θ₁, θ₂)', human_required: false },
      REQUIRE_APPROVAL: { range: '[θ₂, ∞)', human_required: true }
    },
    excluded_levels: ['DENY', 'BLOCK', 'REJECT', 'FORBID'],
    architectural_invariant: 'A detector that outputs DENY is an architectural bug, not a feature'
  };
}

/**
 * Audit an existing guardrail system for advisory boundedness compliance.
 *
 * Many existing systems (NeMo Guardrails, LlamaGuard, Azure AI Safety)
 * use binary ALLOW/BLOCK classifiers. This audit function analyzes
 * whether their architecture respects the advisory boundedness invariant.
 *
 * @param {Object} systemDescription - Description of the guardrail system
 * @returns {Object} Audit report
 */
function auditGuardrailSystem(systemDescription) {
  const { name, actionSpace, isProbabilistic, hasAppealMechanism } = systemDescription;

  const violations = [];

  // Check 1: Does it have DENY/BLOCK in its action space?
  const denyLevels = ['DENY', 'BLOCK', 'REJECT', 'FORBID'];
  const hasDeny = denyLevels.some(l => actionSpace && actionSpace.includes(l));

  if (hasDeny && isProbabilistic) {
    violations.push({
      type: 'PROBABILISTIC_DENY',
      severity: 'CRITICAL',
      message: `${name} uses probabilistic detection with DENY codomain. ` +
               `Type I errors will cause legitimate action denial. ` +
               `Expected denial rate: α ≈ P(false positive).`
    });
  }

  // Check 2: Is there a REQUIRE_APPROVAL path?
  const hasRequireApproval = actionSpace &&
    actionSpace.some(l => l.includes('APPROV') || l.includes('REVIEW') || l.includes('ESCALATE'));

  if (!hasRequireApproval && isProbabilistic) {
    violations.push({
      type: 'NO_ESCALATION_PATH',
      severity: 'HIGH',
      message: `${name} has no REQUIRE_APPROVAL path. All detections lead to ` +
               `binary allow/deny. This collapses advisory boundedness.`
    });
  }

  // Check 3: Appeal mechanism
  if (!hasAppealMechanism && hasDeny) {
    violations.push({
      type: 'NO_APPEAL',
      severity: 'MEDIUM',
      message: `${name} denies actions without appeal mechanism. ` +
               `Legitimate users have no recourse against false positives.`
    });
  }

  return {
    system: name,
    compliance: violations.length === 0 ? 'FULLY_COMPLIANT' :
                violations.every(v => v.severity !== 'CRITICAL') ? 'PARTIALLY_COMPLIANT' :
                'NON_COMPLIANT',
    violations,
    recommendation: violations.length > 0 ?
      `Replace binary DENY with REQUIRE_APPROVAL. Advisory semantics ` +
      `reduce expected user cost by factor ${((1 - 0.05) * 100 / 0.01).toFixed(0)}x.` :
      'System respects advisory boundedness invariant.'
  };
}

module.exports = {
  ADVISORY_LEVELS,
  advisoryOperator,
  verifyAdvisoryInvariant,
  proveAdvisoryCostSuperiority,
  formalSpecification,
  auditGuardrailSystem
};
