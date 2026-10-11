'use strict';

/**
 * Kasbah Overseer — the single control plane for ALL agent activity.
 *
 * One policy, set once, enforced across every interception surface (proxy,
 * gateway, CLI shim, MCP). Three pillars, end to end:
 *
 *   COSTS    — daily + per-call spend caps. Over cap → block (or warn).
 *   ACTIONS  — enforce | monitor; fail-closed; deny-on-threat.
 *   PRIVACY  — PII redaction on/off and strictness, before anything leaves.
 *
 * The policy lives at ~/.kasbah/overseer.json so it survives restarts and is
 * the same whether traffic arrives via the drop-in proxy, the gateway, or a
 * shimmed CLI. Every surface calls the same getPolicy()/checkCost()/etc.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const POLICY_PATH = path.join(os.homedir(), '.kasbah', 'overseer.json');

const DEFAULT_POLICY = {
  version: 1,
  costs: {
    dailyCapUSD:   0,      // 0 = no cap
    perCallCapUSD: 0,      // 0 = no cap
    onExceed:      'block' // 'block' | 'warn'
  },
  actions: {
    mode:        'enforce', // 'enforce' (can block) | 'monitor' (log only, never block)
    failClosed:  false,     // governance error → block the call
    denyOnThreat:true       // DENY verdict blocks the call
  },
  privacy: {
    redactPII: true,        // strip PII before it leaves the machine
    level:     'standard'   // 'off' | 'standard' | 'strict'
  }
};

let _policy = null;
// In-memory daily spend, keyed by YYYY-MM-DD so it auto-resets each day.
const _spend = { day: _today(), usd: 0, calls: 0, blocked: 0 };

function _today() { return new Date().toISOString().slice(0, 10); }
function _deepMerge(base, over) {
  const out = { ...base };
  for (const k of Object.keys(over || {})) {
    out[k] = (over[k] && typeof over[k] === 'object' && !Array.isArray(over[k]))
      ? _deepMerge(base[k] || {}, over[k]) : over[k];
  }
  return out;
}

function getPolicy() {
  if (_policy) return _policy;
  try {
    if (fs.existsSync(POLICY_PATH)) {
      _policy = _deepMerge(DEFAULT_POLICY, JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8')));
      return _policy;
    }
  } catch (_) {}
  _policy = { ...DEFAULT_POLICY };
  return _policy;
}

function setPolicy(patch) {
  _policy = _deepMerge(getPolicy(), patch || {});
  try {
    fs.mkdirSync(path.dirname(POLICY_PATH), { recursive: true });
    fs.writeFileSync(POLICY_PATH, JSON.stringify(_policy, null, 2));
  } catch (_) {}
  return _policy;
}

function _rollDay() { const t = _today(); if (_spend.day !== t) { _spend.day = t; _spend.usd = 0; _spend.calls = 0; _spend.blocked = 0; } }

// ── COSTS ───────────────────────────────────────────────────────────────────
// Decide BEFORE a call whether the projected spend is allowed.
function checkCost(estUSD = 0) {
  _rollDay();
  const p = getPolicy().costs || {};
  if (p.perCallCapUSD > 0 && estUSD > p.perCallCapUSD)
    return { allow: p.onExceed !== 'block', reason: 'per_call_cap', cap: p.perCallCapUSD, est: estUSD, enforce: p.onExceed === 'block' };
  if (p.dailyCapUSD > 0 && (_spend.usd + estUSD) > p.dailyCapUSD)
    return { allow: p.onExceed !== 'block', reason: 'daily_cap', cap: p.dailyCapUSD, spent: _spend.usd, enforce: p.onExceed === 'block' };
  return { allow: true };
}
function recordSpend(usd = 0, blocked = false) { _rollDay(); _spend.usd += (usd || 0); _spend.calls++; if (blocked) _spend.blocked++; }
function spendToday() { _rollDay(); return { ...(_spend) }; }

// ── ACTIONS ───────────────────────────────────────────────────────────────────
function actions()  { return getPolicy().actions || DEFAULT_POLICY.actions; }
function isMonitorOnly() { return actions().mode === 'monitor'; }       // never blocks
function isFailClosed()  { return actions().failClosed === true; }
function deniesOnThreat(){ return actions().denyOnThreat !== false; }

// ── PRIVACY ───────────────────────────────────────────────────────────────────
function privacy() { return getPolicy().privacy || DEFAULT_POLICY.privacy; }
function redactionOn() { return privacy().level !== 'off' && privacy().redactPII !== false; }

// ── HTTP control surface ───────────────────────────────────────────────────────
function mount(app) {
  app.get('/v1/overseer/policy', (_req, res) => res.json(getPolicy()));
  app.put('/v1/overseer/policy', (req, res) => {
    // N2: the overseer policy is a security control — same admin check as PUT /v1/policy.
    const k = req.apiKeyEntry;
    if (!k || k.tier !== 'admin' || (k.dev && process.env.KASBAH_ALLOW_LOCAL_POLICY !== '1')) {
      return res.status(403).json({ error: 'Admin key required to change the overseer policy', code: 'POLICY_AUTH_REQUIRED' });
    }
    res.json({ ok: true, policy: setPolicy(req.body || {}) });
  });
  app.get('/v1/overseer/status', (_req, res) => {
    const p = getPolicy();
    res.json({
      policy: p,
      today:  spendToday(),
      pillars: {
        costs:   { capped: (p.costs.dailyCapUSD > 0 || p.costs.perCallCapUSD > 0), dailyCapUSD: p.costs.dailyCapUSD, spentTodayUSD: +spendToday().usd.toFixed(6) },
        actions: { mode: p.actions.mode, failClosed: p.actions.failClosed, denyOnThreat: p.actions.denyOnThreat },
        privacy: { redacting: redactionOn(), level: p.privacy.level }
      },
      ts: new Date().toISOString()
    });
  });
  console.log('[overseer] mounted — unified control plane (costs · actions · privacy) at /v1/overseer/*');
}

module.exports = {
  mount, getPolicy, setPolicy,
  checkCost, recordSpend, spendToday,
  isMonitorOnly, isFailClosed, deniesOnThreat,
  redactionOn, privacy, actions,
  POLICY_PATH, DEFAULT_POLICY,
};
