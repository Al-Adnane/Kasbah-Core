// ─── Kasbah Kernel — execution-gating primitives ───────────────────────────
//
// Ported concepts from the earlier Python "Kasbah Kernel" design
// (docs/KASBAH_KERNEL_v1.md, docs/MOATS_REGISTRY.md on origin/main) that
// never made it into the current Node gateway:
//
//   1. Signed, tool+args-bound, single-use execution tickets with replay
//      protection — a receipt proves a decision was made; a ticket proves
//      that decision has not yet been *acted on*.
//   2. A kill switch — instant emergency halt, global or per-scope.
//   3. A minimal rate limiter for the decide/consume path.
//
// Domain-agnostic by design: this module knows nothing about prompts,
// models, or LLMs. It only issues/verifies/consumes tickets and gates on
// a kill-switch flag, exactly like the frozen kernel spec required.
//
// Multi-instance correctness: replay protection and the kill switch are
// backed by persistence.js (Redis when available, in-memory fallback
// otherwise), the same "shared state across replicas via Redis" property
// the original MOATS_REGISTRY.md required. A single process still works
// with zero setup — persistence.js degrades to an in-memory Map — but if
// Kasbah ever runs more than one replica behind a load balancer, ticket
// replay and the kill switch are now correct across all of them, not just
// the instance that happened to handle a given request.

const crypto = require('crypto');
const persistence = require('./persistence.js');
const carbonGate = require('./carbon-gate.js');

const TICKET_SECRET = process.env.KASBAH_TICKET_SECRET || crypto.randomBytes(32).toString('hex');
const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes
const NS = 'kasbah:kernel';

function _argsHash(args) {
  const canonical = JSON.stringify(args && typeof args === 'object' ? args : {}, Object.keys(args || {}).sort());
  return crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}

function _sign(payload) {
  return crypto.createHmac('sha256', TICKET_SECRET).update(payload).digest('base64url');
}

// ─── Tickets ────────────────────────────────────────────────────────────────

/**
 * Issue a signed, tool+args-bound ticket authorizing one execution.
 * @param {object} opts { actorId, action, toolName, args, ttlMs, carbonThreshold, carbonZone }
 *
 * When carbonThreshold (gCO2eq/kWh) is set, the current grid carbon intensity
 * is checked before issuing.  If CI > threshold the call throws with a
 * carbon-gate error and no ticket is produced.  The CI attestation is embedded
 * in the ticket body so verifiers can audit it offline.
 */
async function issueTicket({ actorId, action, toolName, args, ttlMs, carbonThreshold, carbonZone } = {}) {
  if (!actorId || !action || !toolName) {
    throw new Error('actorId, action, and toolName are required');
  }

  let carbonAttestation = null;
  if (carbonThreshold != null) {
    const cg = await carbonGate.check(carbonThreshold, carbonZone);
    if (!cg.allowed) throw Object.assign(new Error(cg.reason), { code: 'CARBON_GATE', ci: cg.ci, threshold: cg.threshold, zone: cg.zone });
    carbonAttestation = cg.attestation;
  }

  const jti = crypto.randomBytes(12).toString('hex');
  const now = Date.now();
  const exp = now + (ttlMs || DEFAULT_TTL_MS);
  const argsHash = _argsHash(args);

  const body = { jti, actorId, action, toolName, argsHash, iat: now, exp };
  if (carbonAttestation) body.carbonAttestation = carbonAttestation;

  const encoded = Buffer.from(JSON.stringify(body)).toString('base64url');
  const sig = _sign(encoded);

  return {
    ticket: `kasbah_ticket:v1:${encoded}:${sig}`,
    jti,
    expiresAt: new Date(exp).toISOString(),
    ...(carbonAttestation && { carbonAttestation }),
  };
}

function _parseTicket(ticket) {
  if (typeof ticket !== 'string') return { error: 'ticket must be a string' };
  const parts = ticket.split(':');
  if (parts.length !== 4 || parts[0] !== 'kasbah_ticket' || parts[1] !== 'v1') {
    return { error: 'malformed ticket' };
  }
  const [, , encoded, sig] = parts;
  const expected = _sign(encoded);
  let expectedBuf, sigBuf;
  try {
    expectedBuf = Buffer.from(expected);
    sigBuf = Buffer.from(sig);
  } catch (_) {
    return { error: 'bad signature' };
  }
  if (expectedBuf.length !== sigBuf.length || !crypto.timingSafeEqual(expectedBuf, sigBuf)) {
    return { error: 'bad signature' };
  }
  let body;
  try {
    body = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch (_) {
    return { error: 'malformed ticket body' };
  }
  return { body };
}

/**
 * Verify a ticket's signature, expiry, and (optionally) that it matches the
 * tool/args it's about to authorize — without consuming it. Checks the
 * shared replay store so an already-consumed ticket reads as invalid on
 * every replica, not just the one that consumed it.
 */
async function verifyTicket(ticket, { toolName, args } = {}) {
  const { body, error } = _parseTicket(ticket);
  if (error) return { valid: false, reason: error };
  if (Date.now() > body.exp) return { valid: false, reason: 'expired' };
  if (toolName && toolName !== body.toolName) return { valid: false, reason: 'tool mismatch' };
  if (args !== undefined && _argsHash(args) !== body.argsHash) return { valid: false, reason: 'args mismatch' };
  const consumed = await persistence.get(`${NS}:ticket:consumed:${body.jti}`);
  if (consumed) return { valid: false, reason: 'replay' };
  return { valid: true, ticket: body };
}

/**
 * Verify AND atomically consume a ticket. Only the first caller wins — across
 * every replica, via persistence.setnx — and every subsequent consume of the
 * same jti returns { ok: false, reason: 'replay' }.
 */
async function consumeTicket(ticket, { toolName, args } = {}) {
  const { body, error } = _parseTicket(ticket);
  if (error) return { ok: false, reason: error };
  if (Date.now() > body.exp) return { ok: false, reason: 'expired' };
  if (toolName && toolName !== body.toolName) return { ok: false, reason: 'tool mismatch' };
  if (args !== undefined && _argsHash(args) !== body.argsHash) return { ok: false, reason: 'args mismatch' };

  const ttlSec = Math.max(1, Math.ceil((body.exp - Date.now()) / 1000));
  const claimed = await persistence.setnx(`${NS}:ticket:consumed:${body.jti}`, body.iat, ttlSec);
  if (!claimed) return { ok: false, reason: 'replay' };
  return { ok: true, ticket: body };
}

// ─── Kill switch ────────────────────────────────────────────────────────────
// Global halt + per-scope halt (e.g. 'proxy', 'govern', a specific keyId).
// Backed by persistence so enabling it on one replica halts every replica,
// not just the one that received the toggle request — "Emergency disable
// all" only means "all" if every instance sees it. Falls back to a local
// in-memory flag if the persistence read itself errors, so a transient
// storage hiccup fails toward "gate stays whatever it locally last was"
// rather than throwing on every governed request.

const _localKillSwitch = { all: false, scopes: new Set() };
const KS_ALL_KEY = `${NS}:killswitch:all`;
const KS_SCOPE_PREFIX = `${NS}:killswitch:scope:`;

async function killSwitchEnable(scope) {
  if (!scope || scope === 'all') {
    _localKillSwitch.all = true;
    await persistence.set(KS_ALL_KEY, true);
  } else {
    _localKillSwitch.scopes.add(scope);
    await persistence.set(`${KS_SCOPE_PREFIX}${scope}`, true);
  }
  return killSwitchStatus();
}

async function killSwitchDisable(scope) {
  if (!scope || scope === 'all') {
    _localKillSwitch.all = false;
    await persistence.del(KS_ALL_KEY);
  } else {
    _localKillSwitch.scopes.delete(scope);
    await persistence.del(`${KS_SCOPE_PREFIX}${scope}`);
  }
  return killSwitchStatus();
}

function killSwitchStatus() {
  return { all: _localKillSwitch.all, scopes: [..._localKillSwitch.scopes] };
}

/**
 * Check whether the kill switch is active. Async — consults shared state so
 * it's correct across replicas — with the local flag as a same-process
 * fast path/fallback. Call sites that gate a request (e.g. /v1/govern) must
 * await this.
 */
async function killSwitchActive(scope) {
  try {
    const all = await persistence.get(KS_ALL_KEY);
    if (all) { _localKillSwitch.all = true; return true; }
    if (scope) {
      const s = await persistence.get(`${KS_SCOPE_PREFIX}${scope}`);
      if (s) { _localKillSwitch.scopes.add(scope); return true; }
    }
    return false;
  } catch (_) {
    // Persistence hiccup: fall back to whatever this process last knew.
    return _localKillSwitch.all || (!!scope && _localKillSwitch.scopes.has(scope));
  }
}

// ─── Rate limiter ───────────────────────────────────────────────────────────
// Fixed-window counter shared via persistence.get/set, so the limit applies
// across replicas rather than per-instance. This is a read-then-write, not
// a single atomic op (persistence.js has no INCR+EXPIRE-in-one primitive),
// so under heavy concurrent traffic on the same key it can undercount by a
// handful of requests right at the window edge — an acceptable trade-off
// for a rate limiter (unlike ticket replay, which uses the atomic setnx
// above and must never be approximate).

async function rateLimit(key, { limit = 60, windowMs = 60 * 1000 } = {}) {
  const windowSec = Math.max(1, Math.round(windowMs / 1000));
  const bucketKey = `${NS}:rl:${key}:${Math.floor(Date.now() / 1000 / windowSec)}`;
  const current = (await persistence.get(bucketKey)) || 0;
  if (current >= limit) {
    return { allowed: false, remaining: 0, retryAfterMs: windowMs };
  }
  await persistence.set(bucketKey, current + 1, windowSec);
  return { allowed: true, remaining: limit - (current + 1) };
}

function rateLimitMiddleware({ limit = 60, windowMs = 60 * 1000, keyFn } = {}) {
  return async (req, res, next) => {
    const key = (keyFn ? keyFn(req) : null) || req.apiKeyEntry?.keyId || req.ip || 'anonymous';
    const result = await rateLimit(`rl:${key}`, { limit, windowMs });
    if (!result.allowed) {
      return res.status(429).json({ error: 'rate limited', retryAfterMs: result.retryAfterMs });
    }
    next();
  };
}

module.exports = {
  issueTicket,
  verifyTicket,
  consumeTicket,
  killSwitchEnable,
  killSwitchDisable,
  killSwitchStatus,
  killSwitchActive,
  rateLimit,
  rateLimitMiddleware,
};
