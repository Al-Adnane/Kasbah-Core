'use strict';

/**
 * Brittleness-Aware Cost Governor — Kasbah Core.
 * Ported from ARCHIVE/kasbah-core/core/moats/brittleness_governor.py (515 lines).
 *
 * Novel features:
 * - Multi-dimensional brittleness scoring (usage + latency + error rate)
 * - Exponential moving average for trend detection
 * - Predictive throttling before threshold breach
 * - Resource affinity groups for intelligent diversification
 */

const FrequencyCategory = Object.freeze({
  QUANTUM: 'quantum',   // Sub-millisecond changes (cache, memory)
  FAST:     'fast',     // Sub-second changes (API calls)
  MID:      'mid',      // Minute-level changes (config, models)
  SLOW:     'slow',     // Day-level changes (contracts, subscriptions)
  CRYO:     'cryo',     // Month-level changes (infrastructure)
});

const ActionRecommendation = Object.freeze({
  ALLOW:         'allow',
  MONITOR:       'monitor',
  THROTTLE:      'throttle',
  DIVERSIFY:     'diversify',
  CIRCUIT_BREAK: 'circuit_break',
});

/**
 * Resource metrics tracker with EMA trend detection.
 */
class ResourceMetrics {
  constructor(resourceId, frequency = FrequencyCategory.FAST) {
    this.resourceId     = resourceId;
    this.usageCount     = 0;
    this.usageTokens    = 0;
    this.usageCostCents = 0.0;
    this.latencyP50     = 0.0;
    this.latencyP99     = 0.0;
    this.errorRate      = 0.0;
    this.capacityLimit  = 100000;
    this.frequency      = frequency;
    this.usageHistory   = []; // [{ timestamp: Date, tokens: number }]
  }

  /**
   * Record a usage event with EMA updates.
   */
  addUsage({ tokens = 0, costCents = 0.0, latencyMs = 0.0, success = true, timestamp = null }) {
    this.usageCount += 1;
    this.usageTokens += tokens;
    this.usageCostCents += costCents;

    // EMA for latency
    const alpha = 0.3;
    if (this.latencyP50 === 0) {
      this.latencyP50 = latencyMs;
    } else {
      this.latencyP50 = alpha * latencyMs + (1 - alpha) * this.latencyP50;
    }

    // EMA for error rate
    if (!success) {
      this.errorRate = alpha * 1.0 + (1 - alpha) * this.errorRate;
    }

    // Keep last 100 entries
    this.usageHistory.push({ timestamp: timestamp || new Date(), tokens });
    if (this.usageHistory.length > 100) {
      this.usageHistory = this.usageHistory.slice(-100);
    }
  }
}

/**
 * Brittleness analysis report.
 */
class BrittlenessReport {
  constructor(opts) {
    this.timestamp            = opts.timestamp || new Date();
    this.overallBrittleness   = opts.overallBrittleness;
    this.brittleResource      = opts.brittleResource || null;
    this.recommendedAction    = opts.recommendedAction;
    this.confidence           = opts.confidence;
    this.resourceScores       = opts.resourceScores;
    this.trendDirection       = opts.trendDirection;
    this.timeToThreshold      = opts.timeToThreshold;
    this.diversificationTargets = opts.diversificationTargets;
    this.cadenceMultiplier    = opts.cadenceMultiplier;
    this.analysisVersion      = '2.0.0';
    this.patentPending        = true;
  }
}

/**
 * Advanced brittleness detection with predictive capabilities.
 *
 * Usage:
 *   const governor = new BrittlenessGovernor({
 *     resourceAffinityGroups: { llm_api: ['openai_gpt4', 'anthropic_claude'] }
 *   });
 *   governor.recordUsage('openai_gpt4', { tokens: 1500, latencyMs: 45 });
 *   const report = governor.analyze();
 */
class BrittlenessGovernor {
  // Thresholds (tunable based on risk tolerance)
  static THRESHOLD_MONITOR        = 0.40;
  static THRESHOLD_THROTTLE       = 0.65;
  static THRESHOLD_DIVERSIFY      = 0.80;
  static THRESHOLD_CIRCUIT_BREAK  = 0.95;

  // Weights for multi-dimensional scoring
  static WEIGHT_USAGE   = 0.50;
  static WEIGHT_LATENCY = 0.25;
  static WEIGHT_ERRORS  = 0.25;

  // Trend analysis
  static TREND_WINDOW_SIZE = 10;
  static TREND_ALPHA       = 0.3;

  /**
   * @param {object} [opts]
   * @param {object} [opts.resourceAffinityGroups] — { groupName: [resourceId, ...] }
   */
  constructor(opts = {}) {
    this.resources           = {};  // { resourceId: ResourceMetrics }
    this.affinityGroups      = opts.resourceAffinityGroups || {};
    this.brittlenessHistory  = [];  // [{ timestamp: Date, score: number }]
    this.resourceToGroup     = {};
    this.enablePredictive    = true;
    this.enableAffinityAware  = true;

    // Build inverse mapping: resourceId → groupName
    for (const [groupName, resources] of Object.entries(this.affinityGroups)) {
      for (const resource of resources) {
        this.resourceToGroup[resource] = groupName;
      }
    }
  }

  /**
   * Record a resource usage event.
   * @param {string} resourceId
   * @param {object} opts — { tokens, costCents, latencyMs, success, frequency }
   */
  recordUsage(resourceId, opts = {}) {
    if (!this.resources[resourceId]) {
      this.resources[resourceId] = new ResourceMetrics(
        resourceId,
        opts.frequency || FrequencyCategory.FAST
      );
    }
    this.resources[resourceId].addUsage({
      tokens:     opts.tokens     || 0,
      costCents:  opts.costCents  || 0.0,
      latencyMs:  opts.latencyMs  || 0.0,
      success:    opts.success    !== undefined ? opts.success : true,
      timestamp:  opts.timestamp  || null,
    });
  }

  /** Usage dependency brittleness */
  _calculateUsageBrittleness(resource, totalUsage) {
    if (totalUsage === 0) return 0.0;

    const usageRatio = resource.usageTokens / totalUsage;
    const capacityPressure = resource.usageCount / resource.capacityLimit;
    const capacityModifier = 1.0 + Math.min(capacityPressure, 1.0) * 0.5;

    return Math.min(usageRatio * capacityModifier, 1.0);
  }

  /** Latency degradation brittleness */
  _calculateLatencyBrittleness(resource) {
    if (resource.latencyP50 === 0) return 0.0;

    const latencyScore = Math.min(resource.latencyP50 / 1000.0, 1.0);

    let instabilityModifier = 0.0;
    if (resource.latencyP50 > 0) {
      const instabilityRatio = resource.latencyP99 / resource.latencyP50;
      instabilityModifier = Math.min((instabilityRatio - 1) / 10, 1.0);
    }

    return latencyScore * (1 + instabilityModifier) / 2;
  }

  /** Error rate brittleness */
  _calculateErrorBrittleness(resource) {
    return resource.errorRate;
  }

  /** Composite multi-dimensional brittleness score */
  _calculateCompositeBrittleness(resource, totalUsage) {
    const usageBrittleness   = this._calculateUsageBrittleness(resource, totalUsage);
    const latencyBrittleness = this._calculateLatencyBrittleness(resource);
    const errorBrittleness   = this._calculateErrorBrittleness(resource);

    const composite =
      BrittlenessGovernor.WEIGHT_USAGE   * usageBrittleness +
      BrittlenessGovernor.WEIGHT_LATENCY * latencyBrittleness +
      BrittlenessGovernor.WEIGHT_ERRORS  * errorBrittleness;

    return Math.min(composite, 1.0);
  }

  /**
   * Linear regression trend analysis.
   * @returns {[string, number|null]} — [trendDirection, timeToThresholdSeconds]
   */
  _analyzeTrend() {
    if (this.brittlenessHistory.length < 2) return ['stable', null];

    const n = this.brittlenessHistory.length;
    const baseTime = this.brittlenessHistory[0].timestamp.getTime();
    const times = this.brittlenessHistory.map(h => (h.timestamp.getTime() - baseTime) / 1000);
    const scores = this.brittlenessHistory.map(h => h.score);

    const meanT = times.reduce((a, b) => a + b, 0) / n;
    const meanS = scores.reduce((a, b) => a + b, 0) / n;

    let numerator = 0, denominator = 0;
    for (let i = 0; i < n; i++) {
      const dt = times[i] - meanT;
      const ds = scores[i] - meanS;
      numerator   += dt * ds;
      denominator += dt * dt;
    }

    if (denominator === 0) return ['stable', null];

    const slope = numerator / denominator;

    let trend;
    if (slope > 0.001)      trend = 'increasing';
    else if (slope < -0.001) trend = 'decreasing';
    else                     trend = 'stable';

    // Predict time to diversify threshold
    const currentScore = scores[n - 1];
    let timeToThreshold = null;
    if (slope > 0 && currentScore < BrittlenessGovernor.THRESHOLD_DIVERSIFY) {
      const remaining = BrittlenessGovernor.THRESHOLD_DIVERSIFY - currentScore;
      timeToThreshold = remaining / slope;
    }

    return [trend, timeToThreshold];
  }

  /** Find alternative resources in same affinity group with lower brittleness */
  _findDiversificationTargets(brittleResource) {
    if (!this.enableAffinityAware) return [];

    const groupName = this.resourceToGroup[brittleResource];
    if (!groupName) return [];

    const totalUsage = Object.values(this.resources).reduce((sum, r) => sum + r.usageTokens, 0);
    const scores = {};
    for (const [resId, metrics] of Object.entries(this.resources)) {
      scores[resId] = this._calculateCompositeBrittleness(metrics, totalUsage);
    }

    const currentScore = scores[brittleResource] ?? 1.0;
    const alternatives = [];
    for (const resource of (this.affinityGroups[groupName] || [])) {
      if (resource !== brittleResource && (scores[resource] ?? 1.0) < currentScore) {
        alternatives.push(resource);
      }
    }

    return alternatives.sort((a, b) => (scores[a] ?? 1.0) - (scores[b] ?? 1.0));
  }

  /**
   * Perform comprehensive brittleness analysis.
   * @returns {BrittlenessReport}
   */
  analyze() {
    const timestamp = new Date();

    if (Object.keys(this.resources).length === 0) {
      return new BrittlenessReport({
        overallBrittleness:   0.0,
        brittleResource:      null,
        recommendedAction:    ActionRecommendation.ALLOW,
        confidence:           1.0,
        resourceScores:       {},
        trendDirection:       'stable',
        timeToThreshold:      null,
        diversificationTargets: [],
        cadenceMultiplier:    1.0,
        timestamp,
      });
    }

    const totalUsage = Object.values(this.resources).reduce((sum, r) => sum + r.usageTokens, 0);

    // Calculate per-resource brittleness
    const resourceScores = {};
    let maxBrittleness = 0.0;
    let brittleResource = null;

    for (const [resId, metrics] of Object.entries(this.resources)) {
      const score = this._calculateCompositeBrittleness(metrics, totalUsage);
      resourceScores[resId] = score;
      if (score > maxBrittleness) {
        maxBrittleness = score;
        brittleResource = resId;
      }
    }

    // Record for trend analysis
    this.brittlenessHistory.push({ timestamp, score: maxBrittleness });
    if (this.brittlenessHistory.length > BrittlenessGovernor.TREND_WINDOW_SIZE) {
      this.brittlenessHistory = this.brittlenessHistory.slice(-BrittlenessGovernor.TREND_WINDOW_SIZE);
    }

    const [trend, timeToThreshold] = this._analyzeTrend();
    const action = this._determineAction(maxBrittleness, trend);
    const cadenceMultiplier = this._calculateCadenceMultiplier(maxBrittleness);

    let diversificationTargets = [];
    if (brittleResource &&
        (action === ActionRecommendation.DIVERSIFY || action === ActionRecommendation.CIRCUIT_BREAK)) {
      diversificationTargets = this._findDiversificationTargets(brittleResource);
    }

    // Confidence based on sample size
    const totalSamples = Object.values(this.resources).reduce((sum, r) => sum + r.usageCount, 0);
    const confidence = Math.min(1.0, totalSamples / 100);

    return new BrittlenessReport({
      overallBrittleness:   maxBrittleness,
      brittleResource,
      recommendedAction:    action,
      confidence,
      resourceScores,
      trendDirection:       trend,
      timeToThreshold,
      diversificationTargets,
      cadenceMultiplier,
      timestamp,
    });
  }

  /** Determine action based on brittleness and trend */
  _determineAction(brittleness, trend) {
    // Predictive: act early if trend is increasing
    if (this.enablePredictive && trend === 'increasing') {
      if (brittleness > BrittlenessGovernor.THRESHOLD_DIVERSIFY * 0.9)
        return ActionRecommendation.DIVERSIFY;
      if (brittleness > BrittlenessGovernor.THRESHOLD_THROTTLE * 0.9)
        return ActionRecommendation.THROTTLE;
    }

    // Standard threshold-based
    if (brittleness >= BrittlenessGovernor.THRESHOLD_CIRCUIT_BREAK)
      return ActionRecommendation.CIRCUIT_BREAK;
    if (brittleness >= BrittlenessGovernor.THRESHOLD_DIVERSIFY)
      return ActionRecommendation.DIVERSIFY;
    if (brittleness >= BrittlenessGovernor.THRESHOLD_THROTTLE)
      return ActionRecommendation.THROTTLE;
    if (brittleness >= BrittlenessGovernor.THRESHOLD_MONITOR)
      return ActionRecommendation.MONITOR;
    return ActionRecommendation.ALLOW;
  }

  /**
   * Exponential decay cadence multiplier.
   * multiplier = exp(-k * brittleness^2) — gentle at moderate, aggressive at high.
   */
  _calculateCadenceMultiplier(brittleness) {
    if (brittleness < BrittlenessGovernor.THRESHOLD_THROTTLE) return 1.0;

    const k = 3.0;
    const multiplier = Math.exp(-k * brittleness * brittleness);
    return Math.max(multiplier, 0.01); // Ensure minimum 1% traffic
  }

  /** Get mapping of resources to their affinity groups */
  getResourceAffinityMap() {
    return { ...this.resourceToGroup };
  }

  /** Reset all metrics and history */
  reset() {
    this.resources = {};
    this.brittlenessHistory = [];
  }

  /** Export current metrics for monitoring/auditing */
  exportMetrics() {
    const resources = {};
    for (const [resId, m] of Object.entries(this.resources)) {
      resources[resId] = {
        usageCount:     m.usageCount,
        usageTokens:    m.usageTokens,
        usageCostCents: m.usageCostCents,
        latencyP50:     m.latencyP50,
        errorRate:      m.errorRate,
        frequency:      m.frequency,
      };
    }

    return {
      timestamp:    new Date().toISOString(),
      resourceCount: Object.keys(this.resources).length,
      resources,
      affinityGroups: this.affinityGroups,
      historyLength:  this.brittlenessHistory.length,
    };
  }
}

/** Singleton convenience */
let _governorInstance = null;

function getGovernor() {
  if (!_governorInstance) _governorInstance = new BrittlenessGovernor();
  return _governorInstance;
}

module.exports = {
  BrittlenessGovernor,
  BrittlenessReport,
  ResourceMetrics,
  FrequencyCategory,
  ActionRecommendation,
  getGovernor,
};
