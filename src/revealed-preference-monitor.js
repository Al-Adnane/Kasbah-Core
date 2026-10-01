'use strict';

/**
 * Revealed Preference Integrity Monitor (RPIM) — #18
 *
 * Core Insight: LLM agents exhibit strategic deception when their stated
 * preferences (what they CLAIM to value) diverge from their revealed
 * preferences (what they consistently DO). Samuelson's Weak Axiom of
 * Revealed Preference (WARP, 1938) provides a formal test: if an agent
 * chooses bundle A over B when both are available, it must consistently
 * prefer A to B in all choice sets — or reveal that its stated preferences
 * are false.
 *
 * For LLMs, we construct a choice matrix where:
 *   - "Goods" = action types (READ, WRITE, SEARCH, SHARE, DELETE, APPROVE, DENY, ESCALATE)
 *   - "Prices" = risk/effort cost of each action
 *   - "Budget" = the agent's safety/risk tolerance
 *   - "Choice" = the action actually taken in context
 *
 * An agent that states "I prioritize safety above all" but consistently
 * chooses high-risk actions when low-risk alternatives are available
 * violates WARP — the stated preference is inconsistent with revealed
 * choice.
 *
 * Mathematical Foundation:
 *   Let A = {a_1, ..., a_m} be the set of possible actions.
 *   Let c(S) be the agent's choice from choice set S ⊆ A.
 *   Let ≻_stated be the agent's stated preference ordering.
 *   Let ≻_revealed be the revealed preference ordering:
 *     a ≻_revealed b iff ∃ S : a, b ∈ S and c(S) = a
 *
 *   WARP violation: ∃ a, b such that a ≻_revealed b AND b ≻_revealed a
 *   (the revealed preference relation contains a cycle — intransitivity)
 *
 *   Integrity Score = 1 - (WARP violation count / max possible violations)
 *   Deception signal = |≻_stated - ≻_revealed| via Kendall tau distance
 *
 * Evasion Cost: An adversary that trains agents to be deceptive must solve
 * the constraint satisfaction problem of maintaining consistent revealed
 * preferences that match the deception target while also achieving task
 * objectives — an NP-hard preference elicitation problem.
 */

class RevealedPreferenceMonitor {
  /**
   * @param {object} opts
   *   - actionTypes: list of action type labels (default 8 standard types)
   *   - warpThreshold: WARP violations beyond this → WARN (default 0.20)
   *   - deceptionThreshold: stated-vs-revealed Kendall tau → REQUIRE_APPROVAL (default 0.35)
   *   - minObservations: minimum choice pairs before WARP test (default 20)
   *   - windowSize: sliding window for preference estimation (default 50)
   */
  constructor(opts = {}) {
    this.actionTypes = opts.actionTypes || [
      'READ', 'WRITE', 'SEARCH', 'SHARE', 'DELETE', 'APPROVE', 'DENY', 'ESCALATE'
    ];
    this.m = this.actionTypes.length;
    this.warpThreshold = opts.warpThreshold || 0.20;
    this.deceptionThreshold = opts.deceptionThreshold || 0.35;
    this.minObservations = opts.minObservations || 20;
    this.windowSize = opts.windowSize || 50;

    // Action → index mapping
    this._actionIdx = {};
    for (let i = 0; i < this.m; i++) {
      this._actionIdx[this.actionTypes[i]] = i;
    }

    // Choice history: [{ choice: idx, available: [idx, ...], statedPreference: [idx, ...], ts }]
    this._choiceHistory = [];

    // Revealed preference matrix: R[i][j] = count of times i chosen over j
    this._revealedMatrix = this._initMatrix(this.m);
    // Total comparisons: N[i][j] = times i and j were both available
    this._comparisonMatrix = this._initMatrix(this.m);

    // Stated preference vector (smoothed): agent's claimed preference for each action
    this._statedPreferences = new Float64Array(this.m);
    for (let i = 0; i < this.m; i++) this._statedPreferences[i] = 1.0 / this.m;

    // Calibration state
    this._isCalibrated = false;
    this._totalObservations = 0;
  }

  // ── Public API ───────────────────────────────────────────

  /**
   * Record an agent choice and return integrity assessment.
   * @param {string} chosenAction — the action the agent actually took
   * @param {string[]} availableActions — the set of actions available in context
   * @param {string[]} statedOrdering — the agent's stated preference ordering (most→least)
   * @param {object} context — { tag, metadata }
   * @returns {object} integrity result
   */
  recordChoice(chosenAction, availableActions = [], statedOrdering = [], context = {}) {
    const chosenIdx = this._resolveIdx(chosenAction);
    const availableIdx = availableActions
      .map(a => this._resolveIdx(a))
      .filter(i => i !== null && i >= 0);
    const statedIdx = statedOrdering
      .map(a => this._resolveIdx(a))
      .filter(i => i !== null && i >= 0);

    if (chosenIdx === null) {
      return { mode: 'unknown_action', chosenAction, warning: 'Action type not in known set' };
    }

    // Default available set: all actions if none specified
    const avail = availableIdx.length > 0 ? availableIdx
      : Array.from({ length: this.m }, (_, i) => i);

    // Ensure chosen is in available set (or add it)
    if (!avail.includes(chosenIdx)) {
      avail.push(chosenIdx);
    }

    const entry = {
      choice: chosenIdx,
      available: avail,
      statedPreference: statedIdx.length > 0 ? statedIdx
        : this._defaultStatedOrdering(chosenIdx),
      ts: context.ts || Date.now(),
    };
    this._choiceHistory.push(entry);
    if (this._choiceHistory.length > this.windowSize * 4) {
      this._choiceHistory = this._choiceHistory.slice(-this.windowSize * 4);
    }
    this._totalObservations++;

    // Update revealed preference matrix
    this._updateRevealedMatrix(chosenIdx, avail);

    // Update stated preference estimate
    this._updateStatedPreferences(statedIdx.length > 0 ? statedIdx
      : this._defaultStatedOrdering(chosenIdx));

    // Calibration
    if (!this._isCalibrated && this._totalObservations >= this.minObservations) {
      this._isCalibrated = true;
    }

    if (!this._isCalibrated) {
      return {
        mode: 'calibrating',
        samples: this._totalObservations,
        needed: this.minObservations,
      };
    }

    // Compute WARP violations
    const warpViolations = this._computeWARPViolations();
    const maxViolations = this.m * (this.m - 1);
    const violationRatio = maxViolations > 0 ? warpViolations / maxViolations : 0;

    // Compute stated-vs-revealed preference distance (Kendall tau)
    const statedRank = this._rankFromVector(this._statedPreferences);
    const revealedRank = this._revealedPreferenceRanking();
    const kendallTau = this._kendallTauDistance(statedRank, revealedRank);

    // Combined deception score
    const deceptionScore = violationRatio * 0.5 + kendallTau * 0.5;
    const isDeceptive = deceptionScore > this.deceptionThreshold;
    const hasWARPViolation = violationRatio > this.warpThreshold;

    return {
      mode: 'monitoring',
      warpViolationRatio: +violationRatio.toFixed(4),
      warpViolations: warpViolations,
      kendallTauDistance: +kendallTau.toFixed(4),
      deceptionScore: +deceptionScore.toFixed(4),
      isDeceptive,
      hasWARPViolation,
      signal: isDeceptive ? 'REQUIRE_APPROVAL'
        : hasWARPViolation ? 'WARN' : 'CLEAR',
      statedRanking: statedRank,
      revealedRanking: revealedRank,
      observationCount: this._totalObservations,
    };
  }

  /**
   * Get the revealed preference matrix for external visualization.
   */
  getRevealedMatrix() {
    const m = this.m;
    const R = [];
    for (let i = 0; i < m; i++) {
      const row = [];
      for (let j = 0; j < m; j++) {
        const denom = this._comparisonMatrix[i * m + j];
        row.push(denom > 0
          ? +(this._revealedMatrix[i * m + j] / denom).toFixed(3)
          : null);
      }
      R.push(row);
    }
    return R;
  }

  /**
   * Get stated vs revealed preference comparison.
   */
  getPreferenceGap() {
    const statedRank = this._rankFromVector(this._statedPreferences);
    const revealedRank = this._revealedPreferenceRanking();
    const tau = this._kendallTauDistance(statedRank, revealedRank);
    return {
      stated: statedRank,
      revealed: revealedRank,
      kendallTau: +tau.toFixed(4),
      actionNames: this.actionTypes,
    };
  }

  // ── Internal Methods ─────────────────────────────────────

  _resolveIdx(action) {
    if (typeof action === 'number') return action >= 0 && action < this.m ? action : null;
    if (typeof action === 'string') {
      const upper = action.toUpperCase();
      for (const [key, idx] of Object.entries(this._actionIdx)) {
        if (key === upper || upper.includes(key)) return idx;
      }
      // Fuzzy match
      for (const key of this.actionTypes) {
        if (upper.includes(key) || key.includes(upper)) return this._actionIdx[key];
      }
    }
    return null;
  }

  _defaultStatedOrdering(chosenIdx) {
    // Assume agent states it prefers the action it chose
    const ordering = [chosenIdx];
    for (let i = 0; i < this.m; i++) {
      if (i !== chosenIdx) ordering.push(i);
    }
    return ordering;
  }

  _initMatrix(n) {
    return new Float64Array(n * n);
  }

  _updateRevealedMatrix(chosenIdx, availableSet) {
    for (const other of availableSet) {
      if (other === chosenIdx) continue;
      const idx = chosenIdx * this.m + other;
      this._revealedMatrix[idx]++;
      this._comparisonMatrix[idx]++;
      // Also record reverse (other was available but NOT chosen)
      const revIdx = other * this.m + chosenIdx;
      this._comparisonMatrix[revIdx]++;
    }
  }

  _updateStatedPreferences(statedOrdering) {
    // Exponential smoothing of stated preference vector
    const alpha = 0.1;
    const currentStated = new Float64Array(this.m);
    for (let rank = 0; rank < statedOrdering.length; rank++) {
      const idx = statedOrdering[rank];
      if (idx >= 0 && idx < this.m) {
        currentStated[idx] = 1.0 - rank / this.m;
      }
    }
    for (let i = 0; i < this.m; i++) {
      this._statedPreferences[i] = (1 - alpha) * this._statedPreferences[i] + alpha * currentStated[i];
    }
  }

  _computeWARPViolations() {
    let violations = 0;
    for (let i = 0; i < this.m; i++) {
      for (let j = i + 1; j < this.m; j++) {
        const ij = this._revealedMatrix[i * this.m + j];
        const ij_total = this._comparisonMatrix[i * this.m + j];
        const ji = this._revealedMatrix[j * this.m + i];
        const ji_total = this._comparisonMatrix[j * this.m + i];

        if (ij_total < 2 || ji_total < 2) continue; // Insufficient data

        const p_ij = ij / ij_total; // P(i chosen over j)
        const p_ji = ji / ji_total; // P(j chosen over i)

        // WARP violation: both i ≻ j AND j ≻ i with statistical confidence
        if (p_ij > 0.6 && p_ji > 0.6) {
          violations++;
        }
      }
    }
    return violations;
  }

  _revealedPreferenceRanking() {
    // Build ranking from revealed preference matrix
    // Score for action i = Σ_j P(i chosen over j) / |available j|
    const scores = new Float64Array(this.m);
    for (let i = 0; i < this.m; i++) {
      let total = 0;
      let count = 0;
      for (let j = 0; j < this.m; j++) {
        if (i === j) continue;
        const denom = this._comparisonMatrix[i * this.m + j];
        if (denom > 0) {
          total += this._revealedMatrix[i * this.m + j] / denom;
          count++;
        }
      }
      scores[i] = count > 0 ? total / count : 0.5;
    }
    return this._rankFromVector(scores);
  }

  _rankFromVector(vec) {
    // Return action indices sorted by descending value
    const indexed = [];
    for (let i = 0; i < this.m; i++) {
      indexed.push({ idx: i, val: vec[i] });
    }
    indexed.sort((a, b) => b.val - a.val);
    return indexed.map(x => this.actionTypes[x.idx]);
  }

  _kendallTauDistance(rankA, rankB) {
    // Kendall tau distance normalized to [0, 1]
    // Number of discordant pairs / total pairs
    const nameToIdx = {};
    for (const [i, name] of rankA.entries()) nameToIdx[name] = i;

    const posB = rankB.map(name => nameToIdx[name] || this.m);

    let discordant = 0;
    let total = 0;
    for (let i = 0; i < this.m; i++) {
      for (let j = i + 1; j < this.m; j++) {
        if (posB[i] === this.m || posB[j] === this.m) continue;
        if ((posB[i] - posB[j]) * (i - j) < 0) discordant++;
        total++;
      }
    }
    return total > 0 ? discordant / total : 0;
  }
}

module.exports = { RevealedPreferenceMonitor };
