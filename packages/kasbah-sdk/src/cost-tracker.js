/**
 * Kasbah Cost Tracker
 *
 * Real-time cost tracking across all models:
 * - Anthropic (Claude Opus, Sonnet, Haiku)
 * - Alibaba (Qwen, GLM, Kimi)
 * - Tracks tokens, latency, cost/model
 * - Savings from intelligent routing
 * - Audit receipts for compliance
 */

const fs = require('fs');
const path = require('path');

const HOME = process.env.HOME || require('os').homedir();
const COST_DB = path.join(HOME, '.config/kasbah', 'cost-db.json');

const PRICING = {
  'claude-opus': {
    input: 0.015 / 1000000,    // $15 per 1M tokens
    output: 0.075 / 1000000,   // $75 per 1M tokens
    provider: 'anthropic'
  },
  'claude-sonnet': {
    input: 0.003 / 1000000,    // $3 per 1M
    output: 0.015 / 1000000,   // $15 per 1M
    provider: 'anthropic'
  },
  'claude-haiku': {
    input: 0.00080 / 1000000,  // $0.80 per 1M
    output: 0.004 / 1000000,   // $4 per 1M
    provider: 'anthropic'
  },
  'qwen3.5-plus': {
    input: 0.0008 / 1000000,   // Roughly $0.80 per 1M (Alibaba pricing varies)
    output: 0.002 / 1000000,
    provider: 'alibaba'
  },
  'qwen3-coder-plus': {
    input: 0.001 / 1000000,
    output: 0.0025 / 1000000,
    provider: 'alibaba'
  },
  'glm-5': {
    input: 0.0010 / 1000000,
    output: 0.0025 / 1000000,
    provider: 'alibaba'
  }
};

class CostTracker {
  constructor() {
    this.db = this.load();
    this.currentSession = {
      startTime: Date.now(),
      calls: [],
      totals: { tokens: 0, cost: 0, calls: 0 }
    };
  }

  load() {
    try {
      if (fs.existsSync(COST_DB)) {
        return JSON.parse(fs.readFileSync(COST_DB, 'utf8'));
      }
    } catch (e) {
      console.warn('[CostTracker] Failed to load DB:', e.message);
    }
    return { daily: {}, monthly: {}, allTime: { cost: 0, tokens: 0, calls: 0 } };
  }

  save() {
    try {
      const dir = path.dirname(COST_DB);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(COST_DB, JSON.stringify(this.db, null, 2));
    } catch (e) {
      console.warn('[CostTracker] Failed to save DB:', e.message);
    }
  }

  recordCall(model, inputTokens, outputTokens, latencyMs, metadata = {}) {
    const pricing = PRICING[model];
    if (!pricing) {
      console.warn(`[CostTracker] Unknown model: ${model}`);
      return null;
    }

    const cost = (inputTokens * pricing.input) + (outputTokens * pricing.output);
    const totalTokens = inputTokens + outputTokens;
    const timestamp = new Date().toISOString();
    const date = timestamp.split('T')[0];
    const month = date.slice(0, 7);

    // Initialize buckets
    if (!this.db.daily[date]) this.db.daily[date] = { cost: 0, tokens: 0, calls: 0, byModel: {} };
    if (!this.db.monthly[month]) this.db.monthly[month] = { cost: 0, tokens: 0, calls: 0, byModel: {} };
    if (!this.db.daily[date].byModel[model]) this.db.daily[date].byModel[model] = { cost: 0, tokens: 0, calls: 0 };
    if (!this.db.monthly[month].byModel[model]) this.db.monthly[month].byModel[model] = { cost: 0, tokens: 0, calls: 0 };

    // Record
    const call = {
      timestamp,
      model,
      inputTokens,
      outputTokens,
      cost,
      latencyMs,
      provider: pricing.provider,
      ...metadata
    };

    this.db.daily[date].cost += cost;
    this.db.daily[date].tokens += totalTokens;
    this.db.daily[date].calls++;
    this.db.daily[date].byModel[model].cost += cost;
    this.db.daily[date].byModel[model].tokens += totalTokens;
    this.db.daily[date].byModel[model].calls++;

    this.db.monthly[month].cost += cost;
    this.db.monthly[month].tokens += totalTokens;
    this.db.monthly[month].calls++;
    this.db.monthly[month].byModel[model].cost += cost;
    this.db.monthly[month].byModel[model].tokens += totalTokens;
    this.db.monthly[month].byModel[model].calls++;

    this.db.allTime.cost += cost;
    this.db.allTime.tokens += totalTokens;
    this.db.allTime.calls++;

    // Session tracking
    this.currentSession.calls.push(call);
    this.currentSession.totals.tokens += totalTokens;
    this.currentSession.totals.cost += cost;
    this.currentSession.totals.calls++;

    this.save();
    return call;
  }

  /**
   * Calculate savings from routing cheaper models instead of Opus
   */
  calculateRoutingSavings() {
    const opusPricing = PRICING['claude-opus'];
    const savings = {};

    for (const [model, pricing] of Object.entries(PRICING)) {
      if (model === 'claude-opus') continue;
      const avgInput = pricing.input;
      const avgOutput = pricing.output;
      const opusAvgOutput = opusPricing.output;

      savings[model] = {
        pctCheaper: Math.round(((opusAvgOutput - avgOutput) / opusAvgOutput) * 100),
        perMillionTokens: (avgOutput - opusAvgOutput) * 1_000_000
      };
    }

    return savings;
  }

  getDailyReport(date = null) {
    date = date || new Date().toISOString().split('T')[0];
    const daily = this.db.daily[date] || { cost: 0, tokens: 0, calls: 0, byModel: {} };

    return {
      date,
      totalCost: daily.cost,
      totalTokens: daily.tokens,
      totalCalls: daily.calls,
      byModel: daily.byModel,
      avgCostPerCall: daily.calls > 0 ? (daily.cost / daily.calls).toFixed(6) : '0',
      avgTokensPerCall: daily.calls > 0 ? Math.round(daily.tokens / daily.calls) : 0
    };
  }

  getMonthlyReport(month = null) {
    month = month || new Date().toISOString().slice(0, 7);
    const monthly = this.db.monthly[month] || { cost: 0, tokens: 0, calls: 0, byModel: {} };

    return {
      month,
      totalCost: monthly.cost,
      totalTokens: monthly.tokens,
      totalCalls: monthly.calls,
      byModel: monthly.byModel,
      avgCostPerDay: monthly.cost / 30,
      avgCostPerCall: monthly.calls > 0 ? (monthly.cost / monthly.calls).toFixed(6) : '0',
      projectedMonthly: (monthly.cost / Math.max(1, Math.floor((new Date() - new Date(month + '-01')) / (1000 * 60 * 60 * 24)))) * 30
    };
  }

  getSessionReport() {
    const duration = (Date.now() - this.currentSession.startTime) / 1000;
    return {
      duration: `${Math.round(duration)}s`,
      calls: this.currentSession.totals.calls,
      tokens: this.currentSession.totals.tokens,
      cost: this.currentSession.totals.cost.toFixed(6),
      avgCostPerCall: this.currentSession.totals.calls > 0
        ? (this.currentSession.totals.cost / this.currentSession.totals.calls).toFixed(6)
        : '0'
    };
  }

  getAllTimeStats() {
    return {
      totalCost: this.db.allTime.cost,
      totalTokens: this.db.allTime.tokens,
      totalCalls: this.db.allTime.calls,
      daysActive: Object.keys(this.db.daily).length,
      monthsActive: Object.keys(this.db.monthly).length,
      avgDailyCost: Object.keys(this.db.daily).length > 0
        ? (this.db.allTime.cost / Object.keys(this.db.daily).length).toFixed(6)
        : '0'
    };
  }
}

module.exports = { CostTracker, PRICING };
