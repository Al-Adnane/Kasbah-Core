'use strict';

/**
 * Usage Meter — production-grade tracking for Kasbah Guard commerce.
 *
 * Tracks per-API-key:
 *   • daily and monthly request counts
 *   • per-product cost (Legal Evidence = 5x, Compliance = 10x, default = 1x)
 *   • prepaid credits balance (for pay-as-you-go)
 *   • last reset timestamps
 *
 * Persists to .kasbah/usage.jsonl so quotas survive server restarts.
 * In-memory hot cache + write-through to JSONL append log.
 *
 * Public API:
 *   • recordRequest(keyId, opts)  → returns { allowed, remaining, limit, cost, used }
 *   • getUsage(keyId)             → returns full usage snapshot
 *   • addCredits(keyId, count)    → top up pay-as-you-go credits
 *   • TIER_LIMITS                 → exposed for /v1/billing/plans
 *   • PRODUCT_WEIGHTS             → exposed for transparency
 */

const fs   = require('fs');
const path = require('path');

const DATA_DIR  = path.resolve(__dirname, '..', '..', '..', '.kasbah');
const USAGE_LOG = path.join(DATA_DIR, 'usage.jsonl');

try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (_) {}

// ─── Tier definitions (the public price list) ────────────────────────────────
const TIER_LIMITS = {
  free:       { daily: 100,        monthly: 1_000,      label: 'Free' },
  starter:    { daily: 2_000,      monthly: 20_000,     label: 'Starter' },
  pro:        { daily: 10_000,     monthly: 100_000,    label: 'Pro' },
  business:   { daily: 50_000,     monthly: 1_000_000,  label: 'Business' },
  enterprise: { daily: Infinity,   monthly: Infinity,   label: 'Enterprise' },
  admin:      { daily: Infinity,   monthly: Infinity,   label: 'Admin' }
};

// Per-product cost multipliers — premium engines cost more quota
const PRODUCT_WEIGHTS = {
  // Court-admissible AI detection with ZK proof — most expensive
  'legal-evidence':     5,
  // Compliance reports involve PQ signatures + full audit chain
  'compliance':        10,
  // Frontier / coordinated detection
  'botnet-radar':       3,
  'quantum-sentinel':   2,
  'neural-witness':     2,
  'chronos-paradox':    2,
  'manifold-validator': 2,
  // Standard products
  'dating-guard':       1,
  'relationship-guard': 1,
  'resume-authentic':   1,
  'baseline-drift':     1,
  'dao-vote-guard':     1,
  // Default scan (govern endpoint)
  'general':            1,
  // Multi-model gateway: pre + post scan = 2 credits per call
  'gateway':            2
};

// ─── In-memory state ─────────────────────────────────────────────────────────
const _usage = new Map(); // keyId → { dayDate, dayCount, monthDate, monthCount, credits, lastUpdate }

// Boot: replay usage log
function _replay() {
  try {
    if (!fs.existsSync(USAGE_LOG)) return;
    const lines = fs.readFileSync(USAGE_LOG, 'utf8').trim().split('\n').filter(Boolean);
    for (const line of lines) {
      try {
        const e = JSON.parse(line);
        if (e.keyId) _usage.set(e.keyId, e);
      } catch (_) {}
    }
  } catch (e) { console.warn('[usage-meter] replay failed:', e.message); }
}
_replay();

// Persist a snapshot row — small enough to append on every state change
function _persist(keyId) {
  try {
    const snap = _usage.get(keyId);
    if (!snap) return;
    fs.appendFileSync(USAGE_LOG, JSON.stringify({ ...snap, keyId, ts: Date.now() }) + '\n');
  } catch (_) {}
}

// ─── Time helpers ────────────────────────────────────────────────────────────
function _today()  { return new Date().toISOString().slice(0, 10); } // YYYY-MM-DD
function _month()  { return new Date().toISOString().slice(0, 7);  } // YYYY-MM
function _resetTimes() {
  const now = new Date();
  const tomorrowUTC = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
  const nextMonthUTC = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
  return { dailyResetMs: tomorrowUTC.getTime(), monthlyResetMs: nextMonthUTC.getTime() };
}

function _initRecord(keyId) {
  const r = {
    keyId,
    dayDate:    _today(),
    dayCount:   0,
    monthDate:  _month(),
    monthCount: 0,
    credits:    0,
    lastUpdate: Date.now()
  };
  _usage.set(keyId, r);
  return r;
}

function _rollIfNeeded(rec) {
  const today = _today();
  const month = _month();
  if (rec.dayDate   !== today) { rec.dayDate   = today;   rec.dayCount   = 0; }
  if (rec.monthDate !== month) { rec.monthDate = month;   rec.monthCount = 0; }
  return rec;
}

// ─── Public API ──────────────────────────────────────────────────────────────

function recordRequest(keyId, { tier = 'free', product = 'general' } = {}) {
  const rec = _rollIfNeeded(_usage.get(keyId) || _initRecord(keyId));
  const limits = TIER_LIMITS[tier] || TIER_LIMITS.free;
  const cost   = PRODUCT_WEIGHTS[product] ?? 1;

  // Check credits first (pay-as-you-go bypasses tier caps)
  if (rec.credits > 0 && rec.credits >= cost) {
    rec.credits  -= cost;
    rec.lastUpdate = Date.now();
    _persist(keyId);
    return {
      allowed:        true,
      source:         'credits',
      cost,
      creditsAfter:   rec.credits,
      dayUsed:        rec.dayCount,
      monthUsed:      rec.monthCount,
      tier,
      ...(_resetTimes())
    };
  }

  // Tier-based quota check
  if (isFinite(limits.daily) && rec.dayCount + cost > limits.daily) {
    return {
      allowed:        false,
      reason:         'daily_quota_exceeded',
      cost,
      dayUsed:        rec.dayCount,
      dayLimit:       limits.daily,
      monthUsed:      rec.monthCount,
      monthLimit:     limits.monthly,
      tier,
      credits:        rec.credits,
      ...(_resetTimes())
    };
  }
  if (isFinite(limits.monthly) && rec.monthCount + cost > limits.monthly) {
    return {
      allowed:        false,
      reason:         'monthly_quota_exceeded',
      cost,
      dayUsed:        rec.dayCount,
      dayLimit:       limits.daily,
      monthUsed:      rec.monthCount,
      monthLimit:     limits.monthly,
      tier,
      credits:        rec.credits,
      ...(_resetTimes())
    };
  }

  // Allowed — increment
  rec.dayCount   += cost;
  rec.monthCount += cost;
  rec.lastUpdate  = Date.now();
  _persist(keyId);

  const dayRemaining = isFinite(limits.daily)
    ? Math.max(0, limits.daily - rec.dayCount)
    : Number.POSITIVE_INFINITY;
  const monthRemaining = isFinite(limits.monthly)
    ? Math.max(0, limits.monthly - rec.monthCount)
    : Number.POSITIVE_INFINITY;

  // Quota-warning flag at 80% of daily limit
  const warn = isFinite(limits.daily) && (rec.dayCount / limits.daily >= 0.8);

  return {
    allowed:        true,
    source:         'tier',
    cost,
    tier,
    dayUsed:        rec.dayCount,
    dayLimit:       limits.daily,
    dayRemaining:   isFinite(dayRemaining) ? dayRemaining : null,
    monthUsed:      rec.monthCount,
    monthLimit:     limits.monthly,
    monthRemaining: isFinite(monthRemaining) ? monthRemaining : null,
    credits:        rec.credits,
    warn,
    ...(_resetTimes())
  };
}

function getUsage(keyId, tier = 'free') {
  const rec = _rollIfNeeded(_usage.get(keyId) || _initRecord(keyId));
  const limits = TIER_LIMITS[tier] || TIER_LIMITS.free;
  return {
    keyId,
    tier,
    tierLabel:      limits.label,
    dayUsed:        rec.dayCount,
    dayLimit:       limits.daily,
    dayRemaining:   isFinite(limits.daily) ? Math.max(0, limits.daily - rec.dayCount) : null,
    dayPercentUsed: isFinite(limits.daily) ? Math.round((rec.dayCount / limits.daily) * 100) : 0,
    monthUsed:      rec.monthCount,
    monthLimit:     limits.monthly,
    monthRemaining: isFinite(limits.monthly) ? Math.max(0, limits.monthly - rec.monthCount) : null,
    credits:        rec.credits,
    ...(_resetTimes())
  };
}

function addCredits(keyId, count) {
  const rec = _rollIfNeeded(_usage.get(keyId) || _initRecord(keyId));
  rec.credits   += Math.max(0, Math.floor(count));
  rec.lastUpdate = Date.now();
  _persist(keyId);
  return { keyId, credits: rec.credits };
}

function getAllUsage() {
  const out = [];
  for (const [keyId, rec] of _usage.entries()) {
    _rollIfNeeded(rec);
    out.push({ keyId, ...rec });
  }
  return out;
}

module.exports = {
  TIER_LIMITS,
  PRODUCT_WEIGHTS,
  recordRequest,
  getUsage,
  addCredits,
  getAllUsage
};
