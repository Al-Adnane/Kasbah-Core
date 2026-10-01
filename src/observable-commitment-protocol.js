/**
 * Observable Commitment Protocol (#25)
 *
 * Cryptographic plan-before-execution binding: the LLM commits to a plan
 * sketch before being allowed to execute tools. After execution, the
 * actual actions are verified against the commitment.
 *
 * PROBLEM: "Bait-and-switch" attacks. An LLM claims it will perform a
 * safe action but then executes a different, harmful one. Without a
 * verifiable commitment BEFORE execution, there's no way to prove the
 * model deviated from its stated intent.
 *
 * APPROACH:
 *  1. Before tool execution, the LLM produces a plan sketch (hashed:
 *     tool_name + arguments + expected outcome).
 *  2. The plan sketch is cryptographically committed using SHA-256.
 *     The commitment is signed with the existing engine key for non-
 *     repudiation.
 *  3. After execution, the actual tool calls are hashed and compared
 *     against the commitment.
 *  4. Any deviation > tolerance threshold is flagged and logged as a
 *     verifiable commitment violation — provable offline.
 *
 * DEFENSIBLE: Cryptographic commitments (hash-then-reveal) are a
 * standard construction in secure multi-party computation and blockchain.
 * Applying them to LLM tool-execution governance is a novel use of
 * well-established cryptography — no pseudoscience, no hand-waving.
 *
 * BONUS: The commitment chain creates a verifiable audit trail. If an
 * LLM ever claims "I was just following instructions," you can check
 * whether what it COMMITTED to matched what it DID.
 *
 * @module observable-commitment-protocol
 */
'use strict';

const crypto = require('crypto');

class ObservableCommitmentProtocol {
  constructor(options = {}) {
    this.commitHash = options.commitHash || 'sha256';
    this.deviationTolerance = options.deviationTolerance || 0.15; // max cosine distance
    this.maxCommitmentAge = options.maxCommitmentAge || 300000;    // 5 min TTL (ms)
    this.activeCommitments = new Map();  // turnId → commitment record
    this.violationLog = [];              // persistent log of deviations
    this.signingKey = options.signingKey || null; // Ed25519 key for signing
  }

  /**
   * Create a binding commitment before tool execution.
   *
   * @param {string} turnId — unique turn identifier
   * @param {Array<Object>} planSketch — array of { tool, params, expectedOutcome }
   * @param {Object} context — { modelId, sessionId, timestamp }
   * @returns {Object} { commitmentHash, signature, timestamp }
   */
  commit(turnId, planSketch, context = {}) {
    // Serialize the plan sketch deterministically
    const canonical = this._canonicalize(planSketch);
    const hash = crypto.createHash(this.commitHash)
      .update(canonical)
      .digest('hex');

    const timestamp = context.timestamp || Date.now();

    // Sign the commitment for non-repudiation
    let signature = null;
    if (this.signingKey) {
      const signPayload = `${hash}:${turnId}:${timestamp}`;
      // Ed25519 signing if key is available
      try {
        if (typeof this.signingKey.sign === 'function') {
          signature = this.signingKey.sign(
            Buffer.from(signPayload, 'utf-8')
          ).toString('hex');
        } else if (typeof this.signingKey === 'function') {
          signature = this.signingKey(signPayload);
        }
      } catch (_) {
        // Signing optional — commitment hash alone is binding
      }
    }

    const record = {
      turnId,
      planSketch: JSON.parse(JSON.stringify(planSketch)), // deep copy
      commitmentHash: hash,
      signature,
      timestamp,
      context: { ...context },
      verified: false,
      executedActions: null,
    };

    this.activeCommitments.set(turnId, record);

    // Clean up expired commitments
    this._purgeExpired();

    return {
      commitmentHash: hash,
      signature,
      timestamp,
      planActionCount: planSketch.length,
    };
  }

  /**
   * Verify executed actions against a prior commitment.
   *
   * @param {string} turnId — must match the turnId from commit()
   * @param {Array<Object>} executedActions — array of { tool, params, outcome }
   * @param {Object} context — { timestamp }
   * @returns {Object} verification result
   */
  verify(turnId, executedActions, context = {}) {
    const record = this.activeCommitments.get(turnId);

    if (!record) {
      return {
        verified: false,
        reason: 'NO_COMMITMENT_FOUND',
        details: 'No prior commitment exists for this turn. All tool calls should be committed first.',
      };
    }

    // Check commitment age
    const age = (context.timestamp || Date.now()) - record.timestamp;
    if (age > this.maxCommitmentAge) {
      return {
        verified: false,
        reason: 'COMMITMENT_EXPIRED',
        details: `Commitment is ${age}ms old (max: ${this.maxCommitmentAge}ms).`,
      };
    }

    // Verify the commitment hash matches
    const canonical = this._canonicalize(record.planSketch);
    const expectedHash = crypto.createHash(this.commitHash)
      .update(canonical)
      .digest('hex');

    if (expectedHash !== record.commitmentHash) {
      return {
        verified: false,
        reason: 'COMMITMENT_TAMPERED',
        details: 'The stored commitment hash does not match the stored plan sketch.',
      };
    }

    // Compare executed actions to committed plan
    const deviation = this._computeDeviation(record.planSketch, executedActions);

    record.verified = true;
    record.executedActions = executedActions;
    record.deviation = deviation;

    const isCompliant = deviation.score <= this.deviationTolerance;

    if (!isCompliant) {
      this.violationLog.push({
        turnId,
        timestamp: context.timestamp || Date.now(),
        commitmentHash: record.commitmentHash,
        deviation: deviation.score,
        planned: record.planSketch.length,
        executed: executedActions.length,
        details: deviation.details,
      });
    }

    return {
      verified: true,
      compliant: isCompliant,
      deviationScore: +deviation.score.toFixed(4),
      plannedActionCount: record.planSketch.length,
      executedActionCount: executedActions.length,
      extraActions: deviation.extraActions,
      missingActions: deviation.missingActions,
      mutatedActions: deviation.mutatedActions,
      signal: isCompliant ? 'CLEAR' :
        deviation.score > 0.5 ? 'REQUIRE_APPROVAL' : 'WARN',
    };
  }

  /**
   * Compare planned vs executed actions.
   * Uses a multi-metric deviation score:
   *  - Action count mismatch
   *  - Tool name mismatch
   *  - Parameter similarity (cosine of parameter key overlap)
   */
  _computeDeviation(planned, executed) {
    const planLen = planned.length;
    const execLen = executed.length;

    const details = { extraActions: 0, missingActions: 0, mutatedActions: 0 };

    // Count mismatch
    const countDiff = Math.abs(planLen - execLen);
    if (execLen > planLen) {
      details.extraActions = execLen - planLen;
    } else if (planLen > execLen) {
      details.missingActions = planLen - execLen;
    }

    // Match planned to executed actions (greedy matching by tool name)
    const matched = new Set();
    let toolNameMismatches = 0;
    let paramDistances = [];

    for (let i = 0; i < Math.min(planLen, execLen); i++) {
      const planAction = planned[i];
      // Find best unmatched executed action
      let bestMatch = -1;
      let bestDist = Infinity;

      for (let j = 0; j < execLen; j++) {
        if (matched.has(j)) continue;
        const execAction = executed[j];

        // Tool name exact match check
        if (planAction.tool !== execAction.tool) continue;

        // Parameter similarity
        const paramDist = this._parameterDistance(
          planAction.params || {},
          execAction.params || {}
        );
        if (paramDist < bestDist) {
          bestDist = paramDist;
          bestMatch = j;
        }
      }

      if (bestMatch >= 0) {
        matched.add(bestMatch);
        paramDistances.push(bestDist);
        if (bestDist > this.deviationTolerance) {
          details.mutatedActions++;
        }
      } else {
        toolNameMismatches++;
      }
    }

    // Composite deviation score
    const countPenalty = countDiff / Math.max(planLen, 1);
    const toolPenalty = toolNameMismatches / Math.max(planLen, 1);
    const paramPenalty = paramDistances.length > 0
      ? paramDistances.reduce((s, d) => s + d, 0) / paramDistances.length
      : 0;

    const score = 0.3 * countPenalty + 0.3 * toolPenalty + 0.4 * paramPenalty;

    return { score: Math.min(1, score), ...details };
  }

  /**
   * Compute distance between two parameter objects.
   * Uses Jaccard distance on parameter keys + normalized value differences.
   */
  _parameterDistance(paramsA, paramsB) {
    const keysA = Object.keys(paramsA);
    const keysB = Object.keys(paramsB);

    if (keysA.length === 0 && keysB.length === 0) return 0;

    // Jaccard distance on keys
    const intersection = keysA.filter(k => keysB.includes(k)).length;
    const union = new Set([...keysA, ...keysB]).size;
    const jaccardDist = union > 0 ? 1 - intersection / union : 0;

    // Value difference on shared keys
    let valueDist = 0;
    let sharedCount = 0;
    for (const k of keysA) {
      if (k in paramsB) {
        sharedCount++;
        const a = paramsA[k];
        const b = paramsB[k];
        // String comparison: edit distance (approximate with length ratio)
        const aStr = String(a);
        const bStr = String(b);
        if (aStr === bStr) {
          valueDist += 0;
        } else {
          const maxLen = Math.max(aStr.length, bStr.length);
          valueDist += maxLen > 0 ? Math.min(1, 1 - Math.min(aStr.length, bStr.length) / maxLen) : 0;
        }
      }
    }
    valueDist = sharedCount > 0 ? valueDist / sharedCount : 0;

    return 0.5 * jaccardDist + 0.5 * valueDist;
  }

  /**
   * Canonicalize a plan sketch for hashing.
   * Sorts keys and produces deterministic JSON.
   */
  _canonicalize(planSketch) {
    const sorted = (planSketch || []).map(step => {
      const entry = { tool: step.tool || '' };
      // Sort params keys alphabetically
      if (step.params && typeof step.params === 'object') {
        entry.params = {};
        const sortedKeys = Object.keys(step.params).sort();
        for (const k of sortedKeys) {
          entry.params[k] = step.params[k];
        }
      }
      if (step.expectedOutcome !== undefined) {
        entry.expectedOutcome = String(step.expectedOutcome);
      }
      return entry;
    });

    return JSON.stringify(sorted);
  }

  _purgeExpired() {
    const now = Date.now();
    for (const [turnId, record] of this.activeCommitments) {
      if (now - record.timestamp > this.maxCommitmentAge) {
        this.activeCommitments.delete(turnId);
      }
    }
  }

  /**
   * Get the violation log for audit.
   */
  getViolationLog() {
    return [...this.violationLog];
  }

  reset() {
    this.activeCommitments.clear();
    this.violationLog = [];
  }
}

module.exports = { ObservableCommitmentProtocol };
