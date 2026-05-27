'use strict';

/**
 * Kasbah AgentCostWatch — AI Agent Token Budget Governor
 *
 * Prevents surprise AI bills by:
 *   - Tracking token usage per request (FAST/MID/SLOW bands)
 *   - Computing brittleness score: error-rate × cadence composite
 *   - Auto-throttling when budget thresholds are approached
 *   - Hard-blocking when critical thresholds are hit
 *   - Detecting runaway loops (same action repeated N+ times)
 *
 * Based on the RTP Brittleness Governor concept (Patent Pending).
 *
 * Usage:
 *   const { AgentCostWatch } = require('@kasbah/agent-cost-watch');
 *   const acw = new AgentCostWatch({ maxCostPerHour: 10 });
 *   acw.record({ tokens: 500, costUsd: 0.01, model: 'gpt-4', action: 'search' });
 *   const decision = acw.check();  // { action: 'allow'|'warn'|'throttle'|'block', brittleness }
 */

const EventEmitter = require('events');

// ── FAST/MID/SLOW frequency bands (based on call cadence) ──────────────────
const BAND_THRESHOLDS = {
  fast: 10,    // >10 calls/min  = FAST band (highest risk of runaway)
  mid:  2,     // 2-10 calls/min = MID band
  slow: 0,     //  <2 calls/min  = SLOW band (normal operation)
};

// ── Default config ───────────────────────────────────────────────────────────
const DEFAULT_CONFIG = {
  warnThreshold:      0.55,   // Brittleness > 55% → WARN
  criticalThreshold:  0.80,   // Brittleness > 80% → BLOCK
  throttleFactor:     0.50,   // Throttle: 50% of requests rejected
  maxCostPerHour:     50.0,   // USD
  maxCostPerDay:      200.0,  // USD
  maxTokensPerMin:    100_000,
  maxTokensPerHour:   2_000_000,
  loopDetectWindow:   10,     // last N calls for loop detection
  loopRepeatLimit:    5,      // same action >5 times = loop
};

class AgentCostWatch extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
    this._records = [];           // [{ ts, tokens, costUsd, model, action, band }]
    this._errorCount = 0;
    this._totalCalls = 0;
    this._band = 'slow';
  }

  /**
   * Record a completed AI call.
   * @param {object} r — { tokens, costUsd, model, action, isError? }
   */
  record(r = {}) {
    const ts = Date.now();
    this._totalCalls++;
    if (r.isError) this._errorCount++;

    const band = this._computeBand();
    this._band = band;
    this._records.push({ ts, tokens: r.tokens || 0, costUsd: r.costUsd || 0, model: r.model || 'unknown', action: r.action || 'unknown', band, isError: !!r.isError });

    // Prune records older than 24h
    const cutoff = ts - 86_400_000;
    while (this._records.length > 0 && this._records[0].ts < cutoff) this._records.shift();

    this.emit('record', { ...r, band, brittleness: this.brittleness() });
  }

  /**
   * Compute current brittleness score (0–1).
   * Composite: 40% error rate + 35% cost velocity + 25% band penalty
   */
  brittleness() {
    const now = Date.now();
    const r1h = this._records.filter(r => r.ts > now - 3_600_000);

    const errorRate = this._totalCalls > 0 ? Math.min(1, this._errorCount / this._totalCalls) : 0;
    const costHour  = r1h.reduce((s, r) => s + r.costUsd, 0);
    const costVelocity = this.config.maxCostPerHour > 0 ? Math.min(1, costHour / this.config.maxCostPerHour) : 0;
    const bandPenalty = this._band === 'fast' ? 1.0 : this._band === 'mid' ? 0.5 : 0.1;

    return +(0.40 * errorRate + 0.35 * costVelocity + 0.25 * bandPenalty).toFixed(4);
  }

  /**
   * Check whether the next call should be allowed.
   * Returns { action: 'allow'|'warn'|'throttle'|'block', brittleness, reason }
   */
  check() {
    const b = this.brittleness();
    const now = Date.now();
    const r1h  = this._records.filter(r => r.ts > now - 3_600_000);
    const r1m  = this._records.filter(r => r.ts > now - 60_000);
    const r24h = this._records.filter(r => r.ts > now - 86_400_000);

    const tokensPerMin   = r1m.reduce((s, r)  => s + r.tokens, 0);
    const tokensPerHour  = r1h.reduce((s, r)  => s + r.tokens, 0);
    const costPerHour    = r1h.reduce((s, r)  => s + r.costUsd, 0);
    const costPerDay     = r24h.reduce((s, r) => s + r.costUsd, 0);

    // Hard limits
    if (tokensPerMin  >= this.config.maxTokensPerMin)   return { action: 'block',    brittleness: b, reason: 'tokens_per_min_exceeded' };
    if (tokensPerHour >= this.config.maxTokensPerHour)  return { action: 'block',    brittleness: b, reason: 'tokens_per_hour_exceeded' };
    if (costPerHour   >= this.config.maxCostPerHour)    return { action: 'block',    brittleness: b, reason: 'cost_per_hour_exceeded' };
    if (costPerDay    >= this.config.maxCostPerDay)     return { action: 'block',    brittleness: b, reason: 'cost_per_day_exceeded' };

    // Loop detection
    const loop = this._detectLoop();
    if (loop.isLoop) return { action: 'block', brittleness: b, reason: 'runaway_loop_detected', loop };

    // Brittleness gates
    if (b >= this.config.criticalThreshold) return { action: 'block',    brittleness: b, reason: 'critical_brittleness' };
    if (b >= this.config.warnThreshold)     return { action: 'throttle', brittleness: b, reason: 'high_brittleness' };

    if (costPerHour > this.config.maxCostPerHour * 0.70) return { action: 'warn', brittleness: b, reason: 'approaching_hourly_limit' };

    return {
      action: 'allow', brittleness: b,
      usage: { tokensPerMin, tokensPerHour, costPerHour: +costPerHour.toFixed(4), costPerDay: +costPerDay.toFixed(4) }
    };
  }

  /**
   * Detect runaway loops: same action repeated > loopRepeatLimit times
   */
  _detectLoop() {
    const window = this._records.slice(-this.config.loopDetectWindow);
    if (window.length < this.config.loopRepeatLimit) return { isLoop: false };
    const counts = {};
    for (const r of window) counts[r.action] = (counts[r.action] || 0) + 1;
    for (const [action, count] of Object.entries(counts)) {
      if (count >= this.config.loopRepeatLimit) return { isLoop: true, action, count };
    }
    return { isLoop: false };
  }

  /** Compute current call frequency band */
  _computeBand() {
    const now = Date.now();
    const callsPerMin = this._records.filter(r => r.ts > now - 60_000).length;
    if (callsPerMin > BAND_THRESHOLDS.fast) return 'fast';
    if (callsPerMin > BAND_THRESHOLDS.mid)  return 'mid';
    return 'slow';
  }

  /** Get full usage summary */
  usage() {
    const now = Date.now();
    const r1m  = this._records.filter(r => r.ts > now - 60_000);
    const r1h  = this._records.filter(r => r.ts > now - 3_600_000);
    const r24h = this._records.filter(r => r.ts > now - 86_400_000);
    return {
      band:          this._band,
      brittleness:   this.brittleness(),
      totalCalls:    this._totalCalls,
      errorRate:     this._totalCalls > 0 ? +(this._errorCount / this._totalCalls).toFixed(4) : 0,
      tokensPerMin:  r1m.reduce((s, r) => s + r.tokens, 0),
      tokensPerHour: r1h.reduce((s, r) => s + r.tokens, 0),
      costPerHour:   +r1h.reduce((s, r)  => s + r.costUsd, 0).toFixed(6),
      costPerDay:    +r24h.reduce((s, r) => s + r.costUsd, 0).toFixed(6),
    };
  }

  /** Reset all state */
  reset() {
    this._records = [];
    this._errorCount = 0;
    this._totalCalls = 0;
    this._band = 'slow';
  }
}

// ── Kasbah API middleware integration ───────────────────────────────────────
// Drop-in wrapper for fetch/axios calls to an LLM API.
// Usage: const govern = kasbahMiddleware(acw); govern(() => fetch(...), {tokens: 500, costUsd: 0.01})

function kasbahMiddleware(acw) {
  return async function govern(fn, meta = {}) {
    const decision = acw.check();
    if (decision.action === 'block') throw new Error(`AgentCostWatch: blocked — ${decision.reason}`);
    if (decision.action === 'throttle' && Math.random() < acw.config.throttleFactor) {
      throw new Error(`AgentCostWatch: throttled — brittleness=${decision.brittleness}`);
    }
    try {
      const result = await fn();
      acw.record({ ...meta, isError: false });
      return result;
    } catch (err) {
      acw.record({ ...meta, isError: true });
      throw err;
    }
  };
}

const {
  BrittlenessGovernor,
  BrittlenessReport,
  ResourceMetrics,
  FrequencyCategory,
  ActionRecommendation,
  getGovernor,
} = require('./brittleness-governor');

module.exports = {
  AgentCostWatch,
  kasbahMiddleware,
  DEFAULT_CONFIG,
  BAND_THRESHOLDS,
  BrittlenessGovernor,
  BrittlenessReport,
  ResourceMetrics,
  FrequencyCategory,
  ActionRecommendation,
  getGovernor,
};
