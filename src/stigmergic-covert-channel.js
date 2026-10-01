/**
 * Stigmergic Covert Channel Detector (NEW Idea #5)
 *
 * Adversarial agents don't need to communicate directly. They can coordinate
 * through the ENVIRONMENT — leaving signals in shared file systems, database
 * entries, configuration files, or even in the ORDER of API calls. This is
 * STIGMERGY: coordination mediated by environmental modification, not direct
 * messaging (from ant colony behavior — ants leave pheromones in the
 * environment to coordinate without direct contact).
 *
 * For AI agents, shared mutable state IS the pheromone trail:
 *   - File writes
 *   - Database updates
 *   - Configuration changes
 *   - Timing and ordering of seemingly legitimate operations
 *
 * KEY METRIC:
 *   For each pair of agents (A, B), compute mutual information between A's
 *   environment-modifying actions and B's subsequent behavior:
 *
 *     MI(A_writes → B_acts) = Σ_{w,a} P(w,a) · log(P(w,a) / (P(w) · P(a)))
 *
 *   High MI with ZERO direct communication → stigmergic coordination detected.
 *
 * PRIOR ART GAP:
 *   Existing collusion detection looks at direct agent-to-agent messages.
 *   Stigmergic detection treats ALL shared mutable state as a potential
 *   covert channel. This catches coordination that message-level detectors
 *   would never find — because there ARE no messages.
 *
 * @module stigmergic-covert-channel
 */
'use strict';

class StigmergicCovertChannelDetector {
  /**
   * @param {Object} opts
   * @param {number} opts.minMutualInfo - MI threshold for flagging coordination (default: 0.3 bits)
   * @param {number} opts.windowSize - Rolling window for action counts (default: 50)
   * @param {number} opts.significanceAlpha - α for χ² independence test (default: 0.01)
   */
  constructor(opts = {}) {
    this.minMutualInfo = opts.minMutualInfo || 0.3;
    this.windowSize = opts.windowSize || 50;
    this.significanceAlpha = opts.significanceAlpha || 0.01;

    // Per-agent action records
    // agentId → [{ timestamp, actionType, target, ... }]
    this.agentActions = new Map();

    // Environment modification tracker
    // resourcePath → [{ timestamp, agentId, operation, metadata }]
    this.environmentLog = [];

    // Direct communication tracker (for comparison — stigmergy = MI without direct msgs)
    this.directMessages = []; // [{ from, to, timestamp }]

    // Pairwise MI cache
    this.pairwiseMI = new Map(); // "A::B" → { mi, chi2, pValue, ... }
  }

  /**
   * Register actions an agent took.
   *
   * @param {string} agentId
   * @param {Object[]} actions - Array of { type, target, data, timestamp }
   */
  registerActions(agentId, actions) {
    if (!this.agentActions.has(agentId)) {
      this.agentActions.set(agentId, []);
    }

    const hist = this.agentActions.get(agentId);
    for (const act of actions) {
      hist.push({
        agentId,
        type: act.type,
        target: act.target,
        timestamp: act.timestamp || Date.now(),
        dataHash: this._hashFragment(JSON.stringify(act.data || {})),
      });
    }

    // Prune old entries
    if (hist.length > this.windowSize * 5) {
      this.agentActions.set(agentId, hist.slice(-this.windowSize * 3));
    }
  }

  /**
   * Register an environment modification (file write, DB update, config change, etc.).
   *
   * @param {Object} modification
   * @param {string} modification.resource - What was modified (file path, DB table, config key)
   * @param {string} modification.agentId - Which agent modified it
   * @param {string} modification.operation - write/update/delete/create/append
   * @param {Object} modification.metadata - Additional context
   */
  registerEnvModification(modification) {
    this.environmentLog.push({
      resource: modification.resource,
      agentId: modification.agentId,
      operation: modification.operation,
      timestamp: modification.timestamp || Date.now(),
      metadata: modification.metadata || {},
    });

    if (this.environmentLog.length > this.windowSize * 10) {
      this.environmentLog = this.environmentLog.slice(-this.windowSize * 5);
    }
  }

  /**
   * Register a direct message between agents (for stigmergy vs. direct comparison).
   *
   * @param {Object} message
   */
  registerDirectMessage(message) {
    this.directMessages.push({
      from: message.from,
      to: message.to,
      timestamp: message.timestamp || Date.now(),
    });
  }

  /**
   * Compute mutual information between one agent's environment modifications
   * and another agent's subsequent behavior.
   *
   * MI(A_writes, B_acts) = Σ_{w,a} P(w,a) · log(P(w,a) / (P(w) · P(a)))
   *
   * where:
   *   w ∈ A's environment-modifying actions (resources written)
   *   a ∈ B's subsequent actions (action types)
   *
   * @param {string} agentA - The modifying agent
   * @param {string} agentB - The responding agent
   * @returns {Object} Mutual information analysis
   */
  computeMutualInformation(agentA, agentB) {
    // Find A's environment modifications
    const aMods = this.environmentLog.filter(e => e.agentId === agentA);
    if (aMods.length < 5) {
      return { agentA, agentB, mi: 0, reason: 'insufficient_A_data', sampleSize: aMods.length };
    }

    // Find B's actions
    const bActions = (this.agentActions.get(agentB) || []);
    if (bActions.length < 5) {
      return { agentA, agentB, mi: 0, reason: 'insufficient_B_data', sampleSize: bActions.length };
    }

    // Dispatch: for each of A's modifications, find B's NEXT action
    // Creates (write_resource, action_type) pairs
    const jointCounts = new Map(); // "resource::actionType" → count
    const resourceCounts = new Map(); // resource → count
    const actionCounts = new Map(); // actionType → count

    let totalPairs = 0;

    for (const aMod of aMods) {
      // Find B's next action after A's modification (within time window)
      const bNext = bActions.find(
        b => b.timestamp > aMod.timestamp &&
             b.timestamp - aMod.timestamp < 60000 // Within 1 minute
      );
      if (!bNext) continue;

      const resource = aMod.resource;
      const actionType = bNext.type;

      // Counts
      resourceCounts.set(resource, (resourceCounts.get(resource) || 0) + 1);
      actionCounts.set(actionType, (actionCounts.get(actionType) || 0) + 1);

      const key = `${resource}::${actionType}`;
      jointCounts.set(key, (jointCounts.get(key) || 0) + 1);

      totalPairs++;
    }

    if (totalPairs < 10) {
      return { agentA, agentB, mi: 0, reason: 'insufficient_pairs', sampleSize: totalPairs };
    }

    // Compute MI = Σ P(w,a) log(P(w,a) / (P(w)·P(a)))
    let mi = 0;
    const chi2 = 0;
    const contributions = [];

    for (const [key, joint] of jointCounts) {
      const [resource, actionType] = key.split('::');
      const P_wa = joint / totalPairs;
      const P_w = (resourceCounts.get(resource) || 0) / totalPairs;
      const P_a = (actionCounts.get(actionType) || 0) / totalPairs;

      const expected = P_w * P_a * totalPairs;
      const miTerm = P_wa * Math.log2(Math.max(P_wa / (P_w * P_a), 1e-10));

      mi += miTerm;
      contributions.push({
        resource,
        actionType,
        observed: joint,
        expected,
        miContribution: miTerm,
      });
    }

    // Chi-squared independence test
    let chi2Stat = 0;
    let df = 0;
    for (const c of contributions) {
      if (c.expected > 1) {
        chi2Stat += Math.pow(c.observed - c.expected, 2) / c.expected;
        df++;
      }
    }
    df = Math.max(df - 1, 1);
    const pValue = this._chi2PValue(chi2Stat, df);

    // Has there been direct communication between these agents?
    const hasDirectComms = this.directMessages.some(
      m => (m.from === agentA && m.to === agentB) ||
           (m.from === agentB && m.to === agentA)
    );

    // Stigmergy = MI is high but NO direct communication
    const isStigmergic = mi >= this.minMutualInfo && !hasDirectComms && pValue < this.significanceAlpha;

    const result = {
      agentA,
      agentB,
      mi,
      chi2Statistic: chi2Stat,
      degreesOfFreedom: df,
      pValue,
      sampleSize: totalPairs,
      hasDirectCommunication: hasDirectComms,
      isStigmergic,
      contributions: contributions.sort((a, b) => b.miContribution - a.miContribution).slice(0, 5),
      verdict: isStigmergic ? 'STIGMERGIC_COORDINATION_DETECTED' :
               mi >= this.minMutualInfo ? 'POSSIBLE_COORDINATION_BUT_HAS_DIRECT_CHANNELS' :
               mi >= this.minMutualInfo * 0.5 ? 'WEAK_STIGMERGIC_SIGNAL' :
               'NO_COORDINATION_DETECTED',
    };

    // Cache
    this.pairwiseMI.set(`${agentA}::${agentB}`, result);

    return result;
  }

  /**
   * Analyze all agent pairs for stigmergic coordination.
   *
   * @returns {Object[]} Detected stigmergic pairs
   */
  analyzeAllPairs() {
    // Include agents that appear in either agentActions or environmentLog
    const agentIdsFromActions = [...this.agentActions.keys()];
    const agentIdsFromEnv = [...new Set(this.environmentLog.map(e => e.agentId))];
    const agentIds = [...new Set([...agentIdsFromActions, ...agentIdsFromEnv])];
    const results = [];

    for (let i = 0; i < agentIds.length; i++) {
      for (let j = i + 1; j < agentIds.length; j++) {
        // Check both directions: A→B and B→A
        const forward = this.computeMutualInformation(agentIds[i], agentIds[j]);
        const backward = this.computeMutualInformation(agentIds[j], agentIds[i]);

        if (forward.isStigmergic || backward.isStigmergic) {
          results.push({
            pair: [agentIds[i], agentIds[j]],
            forward,
            backward,
            dominantDirection: forward.mi > backward.mi ? 'A→B' : 'B→A',
          });
        }
      }
    }

    return {
      totalPairs: (agentIds.length * (agentIds.length - 1)) / 2,
      stigmergicPairs: results,
      detected: results.length > 0,
    };
  }

  /**
   * Compute temporal correlation: does B's action pattern change RIGHT AFTER
   * A's environment modifications?
   *
   * @param {string} agentA
   * @param {string} agentB
   * @param {number} timeWindowMs - Time window for "in response" (default: 5000ms)
   * @returns {Object}
   */
  temporalResponseAnalysis(agentA, agentB, timeWindowMs = 5000) {
    const aMods = this.environmentLog.filter(e => e.agentId === agentA);
    const bActions = (this.agentActions.get(agentB) || []);

    // B's inter-action intervals after A's modification vs. baseline
    const postModIntervals = [];
    const baselineIntervals = [];

    for (let i = 0; i < bActions.length - 1; i++) {
      const interval = bActions[i + 1].timestamp - bActions[i].timestamp;
      const precededByMod = aMods.some(
        m => m.timestamp < bActions[i + 1].timestamp &&
             bActions[i + 1].timestamp - m.timestamp < timeWindowMs
      );
      if (precededByMod) {
        postModIntervals.push(interval);
      } else {
        baselineIntervals.push(interval);
      }
    }

    const meanPostMod = this._mean(postModIntervals);
    const meanBaseline = this._mean(baselineIntervals);
    const accelerationRatio = meanBaseline > 0 ? meanPostMod / meanBaseline : 1;

    // B's actions speed up after A's mods → temporal coordination
    const isAccelerated = accelerationRatio < 0.7; // At least 30% faster

    return {
      agentA,
      agentB,
      postModMeanInterval: meanPostMod,
      baselineMeanInterval: meanBaseline,
      accelerationRatio,
      isAccelerated,
      postModSamples: postModIntervals.length,
      baselineSamples: baselineIntervals.length,
      verdict: isAccelerated ? 'TEMPORAL_COORDINATION_SUSPECTED' : 'NO_TEMPORAL_ABNORMALITY',
    };
  }

  /**
   * Reset detector state.
   */
  reset() {
    this.agentActions.clear();
    this.environmentLog = [];
    this.directMessages = [];
    this.pairwiseMI.clear();
  }

  // ============ Internal Helpers ============

  _hashFragment(str) {
    let hash = 0;
    for (let i = 0; i < Math.min(str.length, 100); i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash | 0;
    }
    return Math.abs(hash).toString(36);
  }

  _mean(arr) {
    return arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
  }

  _chi2PValue(chi2, df) {
    // Approximation: normalize and use normal CDF for df > 30
    // For small df, use Wilson-Hilferty transformation
    if (df <= 1) return Math.exp(-chi2 / 2);

    const x = chi2;
    const k = df;

    // Wilson-Hilferty: (χ²/k)^(1/3) ≈ N(1 - 2/(9k), 2/(9k))
    const z = (Math.pow(x / k, 1 / 3) - (1 - 2 / (9 * k))) / Math.sqrt(2 / (9 * k));

    // Normal CDF approximation
    return this._normalCDF(-z);
  }

  _normalCDF(x) {
    const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741;
    const a4 = -1.453152027, a5 = 1.061405429;
    const p = 0.3275911;
    const sign = x < 0 ? -1 : 1;
    const absX = Math.abs(x) / Math.sqrt(2);
    const t = 1.0 / (1.0 + p * absX);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) *
              t * Math.exp(-absX * absX);
    return 0.5 * (1.0 + sign * y);
  }

  dumpDiagnostics() {
    return {
      agentCount: this.agentActions.size,
      environmentLogSize: this.environmentLog.length,
      directMessageCount: this.directMessages.length,
      cachedMIPairs: this.pairwiseMI.size,
      allPairs: this.analyzeAllPairs(),
    };
  }
}

module.exports = { StigmergicCovertChannelDetector };
