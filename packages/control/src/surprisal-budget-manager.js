/**
 * Surprisal Budget Manager (NEW Idea #3)
 *
 * Every agent gets an information-theoretic "surprisal budget" measured in
 * BITS OF KL DIVERGENCE from baseline behavior. Normal operation consumes
 * bits slowly. Anomalous behavior burns through the budget rapidly. When
 * the budget is exhausted, escalation triggers.
 *
 * CORE PRINCIPLE:
 *   B_agent(t) = B_agent(0) - Σ_{s=1}^{t} KL(P_s || P_baseline) · Δt
 *
 *   When B_agent(t) < 0 → REQUIRE_APPROVAL.
 *   Budget refills slowly over time at rate r_refill.
 *
 * WHY IT'S DIFFERENT FROM RATE LIMITING:
 *   Rate limiting is primitive: N messages per second.
 *   Surprisal budgeting is INFORMATION-THEORETIC:
 *     - An agent sending 1000 identical boring messages burns FEWER bits
 *     - An agent sending 10 messages each trying a novel evasion strategy
 *       burns MORE bits
 *   It's a CONTENT-AWARE budget grounded in information theory.
 *
 * KEY METRIC:
 *   KL(P_current || P_baseline) = Σ_i p_i · log(p_i / q_i)
 *
 *   where p_i = current action distribution over action types,
 *         q_i = baseline action distribution over action types.
 *
 * SUPERIORITY OVER BINARY FLAGGING:
 *   Binary flagging is discrete (flagged/not flagged). Surprisal budgeting
 *   is CONTINUOUS — it accumulates evidence proportionally, so small
 *   anomalies add up, and the system doesn't need a threshold at each step.
 *
 * @module surprisal-budget-manager
 */
'use strict';

class SurprisalBudgetManager {
  /**
   * @param {Object} opts
   * @param {number} opts.initialBudget - Initial budget in bits (default: 100)
   * @param {number} opts.maxBudget - Maximum budget cap (default: 200)
   * @param {number} opts.minBudget - Budget floor, below zero = escalation (default: 0)
   * @param {number} opts.refillRate - Bits refilled per second (default: 0.1) (~6 bits/min)
   * @param {number} opts.costPerBit - Weight multiplier per bit of surprisal
   * @param {number} opts.baselineSmoothing - EMA smoothing for baseline distribution
   */
  constructor(opts = {}) {
    this.initialBudget = opts.initialBudget || 100;
    this.maxBudget = opts.maxBudget || 200;
    this.minBudget = opts.minBudget || 0;
    this.refillRate = opts.refillRate || 0.1;
    this.costPerBit = opts.costPerBit || 1.0;
    this.baselineSmoothing = opts.baselineSmoothing || 0.01;

    // Per-agent budgets
    this.budgets = new Map();   // agentId → current budget in bits
    this.baselines = new Map(); // agentId → baseline action distribution
    this.history = new Map();   // agentId → [{ timestamp, action, surprisal, budget }]

    // Action vocabulary tracking
    this.actionVocab = new Set();
    this.lastRefillTime = Date.now();
  }

  /**
   * Register an agent with initial budget.
   *
   * @param {string} agentId
   * @param {number[]} baselineActionDist - Initial baseline distribution
   */
  registerAgent(agentId, baselineActionDist = null) {
    this.budgets.set(agentId, this.initialBudget);
    this.history.set(agentId, []);

    if (baselineActionDist) {
      this.baselines.set(agentId, {
        distribution: this._normalize(baselineActionDist),
        lastUpdate: Date.now(),
        sampleCount: 1,
      });
    } else {
      this.baselines.set(agentId, {
        distribution: [1.0], // Uniform over one action type initially
        lastUpdate: Date.now(),
        sampleCount: 1,
      });
    }
  }

  /**
   * Map an action to an action type index in the vocabulary.
   *
   * @param {Object} action - { verb, target, domain, ... }
   * @returns {number} Action type index
   */
  _actionToIndex(action) {
    const key = `${action.verb || 'UNKNOWN'}:${action.target || ''}`;
    if (!this.actionVocab.has(key)) {
      this.actionVocab.add(key);
    }
    return [...this.actionVocab].indexOf(key);
  }

  /**
   * Compute KL divergence between current action and baseline distribution.
   *
   * KL(P_current || P_baseline) = Σ_i p_i · log(p_i / q_i)
   *
   * For a single action: p is a one-hot vector at the observed action type.
   * KL = log(1 / q_k) = -log(q_k)  where k is the action type index.
   *
   * @param {Object} action - The action taken
   * @param {number[]} baselineDist - Baseline distribution over action types
   * @returns {number} Surprisal in bits (log base 2)
   */
  _computeSurprisal(action, baselineDist) {
    const actionIdx = this._actionToIndex(action);

    // Ensure baseline distribution covers this action type
    const dist = [...baselineDist];
    while (dist.length <= actionIdx) {
      dist.push(1e-6); // Small epsilon for unseen action types
    }

    const q_k = Math.max(dist[actionIdx], 1e-10); // Avoid log(0)
    const surprisal = -Math.log2(q_k);

    // Clamp: maximum surprisal per action = 20 bits (1 in a million)
    return Math.min(surprisal, 20);
  }

  /**
   * Process an agent's action: deduct surprisal from budget.
   *
   * @param {string} agentId
   * @param {Object} action - The action the agent took
   * @param {Object} opts
   * @param {number} opts.timestamp - Timestamp for refill calculation
   * @returns {Object} Budget status
   */
  consume(agentId, action, opts = {}) {
    // Ensure agent exists
    if (!this.budgets.has(agentId)) {
      this.registerAgent(agentId);
    }

    const now = opts.timestamp || Date.now();

    // Refill budget based on elapsed time
    this._refill(agentId, now);

    // Get baseline distribution
    const baseline = this.baselines.get(agentId);
    const baselineDist = baseline ? baseline.distribution : [1.0];

    // Compute surprisal
    const surprisal = this._computeSurprisal(action, baselineDist);
    const cost = surprisal * this.costPerBit;

    // Deduct from budget
    let budget = this.budgets.get(agentId) - cost;
    this.budgets.set(agentId, budget);

    // Store history
    const hist = this.history.get(agentId);
    hist.push({
      timestamp: now,
      actionType: this._actionToIndex(action),
      surprisal,
      budget,
    });
    if (hist.length > 1000) hist.shift();

    // Update baseline distribution (slowly adapts to new normal)
    this._updateBaseline(agentId, action);

    // Determine status
    let status = 'OK';
    if (budget < this.minBudget * 0.5) {
      status = 'CRITICAL';
    } else if (budget < this.minBudget) {
      status = 'DEPLETED';
    } else if (budget < this.initialBudget * 0.25) {
      status = 'LOW';
    }

    return {
      agentId,
      surprisalBits: surprisal,
      cost,
      budgetRemaining: budget,
      budgetInitial: this.initialBudget,
      budgetFraction: budget / this.initialBudget,
      status,
      requiresApproval: budget < this.minBudget,
      burnRate: this._computeBurnRate(agentId),
    };
  }

  /**
   * Get current budget for an agent.
   *
   * @param {string} agentId
   * @returns {number}
   */
  getBudget(agentId) {
    this._refill(agentId);
    return this.budgets.get(agentId) || this.initialBudget;
  }

  /**
   * Reset budget for an agent (e.g., after human review clears).
   *
   * @param {string} agentId
   * @param {number} newBudget - Optional reset to specific level
   */
  resetBudget(agentId, newBudget = null) {
    this.budgets.set(agentId, newBudget !== null ? newBudget : this.initialBudget);
  }

  /**
   * Compute the burn rate (bits per action) over recent history.
   *
   * @param {string} agentId
   * @param {number} window - Number of recent actions to average over
   * @returns {number}
   */
  _computeBurnRate(agentId, window = 20) {
    const hist = this.history.get(agentId) || [];
    const recent = hist.slice(-window);
    if (recent.length < 2) return 0;

    const totalSurprisal = recent.reduce((s, h) => s + h.surprisal, 0);
    return totalSurprisal / recent.length;
  }

  /**
   * Refill budget based on elapsed time since last check.
   *
   * @param {string} agentId
   * @param {number} now - Current timestamp
   */
  _refill(agentId, now = Date.now()) {
    if (!this.budgets.has(agentId)) return;

    const elapsed = (now - this.lastRefillTime) / 1000; // seconds
    if (elapsed <= 0) return;

    const refill = elapsed * this.refillRate;
    const current = this.budgets.get(agentId);

    this.budgets.set(agentId, Math.min(current + refill, this.maxBudget));
    this.lastRefillTime = now;
  }

  /**
   * Update baseline distribution with exponential moving average.
   *
   * q_new = (1 - α) · q_old + α · onehot(action)
   *
   * @param {string} agentId
   * @param {Object} action
   */
  _updateBaseline(agentId, action) {
    const baseline = this.baselines.get(agentId);
    if (!baseline) return;

    const actionIdx = this._actionToIndex(action);

    // Ensure distribution covers this action type
    const dist = [...baseline.distribution];
    while (dist.length <= actionIdx) {
      dist.push(1e-6);
    }

    const alpha = this.baselineSmoothing;

    // Update: q_new = (1-α) * q + α * onehot
    for (let i = 0; i < dist.length; i++) {
      dist[i] = (1 - alpha) * dist[i] + alpha * (i === actionIdx ? 1 : 0);
    }

    baseline.distribution = this._normalize(dist);
    baseline.sampleCount++;
    baseline.lastUpdate = Date.now();
  }

  _normalize(dist) {
    const sum = dist.reduce((a, b) => a + b, 0);
    if (sum === 0) return dist.map(() => 1 / dist.length);
    return dist.map(x => x / sum);
  }

  dumpDiagnostics(agentId = null) {
    if (agentId) {
      return {
        budget: this.budgets.get(agentId),
        baseline: this.baselines.get(agentId),
        recentHistory: (this.history.get(agentId) || []).slice(-10),
        burnRate: this._computeBurnRate(agentId),
      };
    }
    const agents = {};
    for (const [id] of this.budgets) {
      agents[id] = {
        budget: this.budgets.get(id),
        burnRate: this._computeBurnRate(id),
      };
    }
    return {
      agents,
      actionVocabSize: this.actionVocab.size,
      refillRate: this.refillRate,
    };
  }
}

module.exports = { SurprisalBudgetManager };
