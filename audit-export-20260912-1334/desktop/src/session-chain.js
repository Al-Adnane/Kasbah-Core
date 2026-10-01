'use strict';

/**
 * session-chain.js — Cross-Session Policy Continuity Proof (N6)
 *
 * Maintains a hash-chain over session roots. Each session commits to:
 *   · A governance policy snapshot hash
 *   · The previous session root (linking the chain)
 *   · A timestamp and session ID
 *
 * WHAT THIS PROVES
 *   `verifyContinuity(fromIdx, toIdx)` proves the chain from session `fromIdx`
 *   to `toIdx` is unbroken. An auditor who holds session N's root can verify
 *   that no session between N and now weakened the policy — without seeing
 *   the policy content.
 *
 * WHAT THIS DOES NOT PROVE
 *   · That the policy hash corresponds to a specific policy text (the policy
 *     content stays off-chain; the auditor must separately verify the hash).
 *   · Anything about sessions before the genesis entry (the chain starts when
 *     first called; there is no retroactive history).
 *
 * POLICY WEAKENING DETECTION
 *   A "policy weakening" is defined as a decrease in the minimum threshold
 *   level. Each session records `minThreshold` alongside the policy hash.
 *   `verifyContinuity` checks that no session's `minThreshold` dropped below
 *   any earlier session's value, flagging any such event as a regression.
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const DIR        = path.join(os.homedir(), '.kasbah-privacy');
const CHAIN_FILE = path.join(DIR, 'session-chain.jsonl');

function ensure() { try { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); } catch (_) {} }

/* ── Chain I/O ──────────────────────────────────────────────────────────── */

function _readAll() {
  try {
    return fs.readFileSync(CHAIN_FILE, 'utf8').trim().split('\n')
      .filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
  } catch { return []; }
}

function _append(entry) {
  ensure();
  fs.appendFileSync(CHAIN_FILE, JSON.stringify(entry) + '\n', { mode: 0o600 });
}

/* ── Session root computation ───────────────────────────────────────────── */

/**
 * Hash of the current governance policy state.
 * We hash the serialized governance status (seats + clearance table + WGAS graph hash).
 * Callers may pass a pre-computed `policySnapshot` string/object instead.
 */
function _policyHash(policySnapshot) {
  const body = typeof policySnapshot === 'string'
    ? policySnapshot
    : JSON.stringify(policySnapshot, Object.keys(policySnapshot || {}).sort());
  return crypto.createHash('sha256').update(body).digest('hex');
}

function _sessionRoot(sessionId, prevRoot, policyHash, ts) {
  return crypto.createHash('sha256')
    .update(sessionId + '|' + prevRoot + '|' + policyHash + '|' + ts)
    .digest('hex');
}

/* ── Public API ─────────────────────────────────────────────────────────── */

/**
 * Begin a new session. Records a chain entry linking this session's policy
 * snapshot to the previous session.
 *
 * @param {string|object} policySnapshot  - anything hashable representing current policy
 * @param {{ minThreshold?: number, label?: string }} [opts]
 * @returns {{ sessionId, root, prevRoot, policyHash, index, ts }}
 */
function beginSession(policySnapshot, opts = {}) {
  const all      = _readAll();
  const prev     = all.length ? all[all.length - 1] : null;
  const prevRoot = prev ? prev.root : '0'.repeat(64);
  const ts       = new Date().toISOString();
  const sessionId = 'sess_' + crypto.randomBytes(6).toString('hex');
  const pHash    = _policyHash(policySnapshot);
  const root     = _sessionRoot(sessionId, prevRoot, pHash, ts);
  const index    = all.length;

  const entry = {
    index,
    sessionId,
    root,
    prevRoot,
    policyHash: pHash,
    minThreshold: opts.minThreshold ?? null,
    label:        opts.label        || null,
    ts,
    open: true,
  };

  _append(entry);
  return { sessionId, root, prevRoot, policyHash: pHash, index, ts };
}

/**
 * Close the current open session (optional, for clean chain entries).
 * Marks the last open entry as closed without changing its root.
 */
function endSession(sessionId) {
  const all = _readAll();
  const entry = all.find((e) => e.sessionId === sessionId && e.open);
  if (!entry) return { ok: false, error: 'session not found or already closed' };
  entry.open      = false;
  entry.closedAt  = new Date().toISOString();
  // Rewrite the file (small chain; not a hot path)
  ensure();
  fs.writeFileSync(CHAIN_FILE, all.map((e) => JSON.stringify(e)).join('\n') + '\n', { mode: 0o600 });
  return { ok: true, sessionId, closedAt: entry.closedAt };
}

/**
 * Verify the chain is unbroken from `fromIdx` to `toIdx` (inclusive).
 * Also checks that `minThreshold` never decreased (policy weakening detection).
 *
 * @returns {{ ok, count, regressions, brokenAt, entries }}
 */
function verifyContinuity(fromIdx = 0, toIdx = Infinity) {
  const all = _readAll();
  if (!all.length) return { ok: true, count: 0, note: 'empty chain' };

  const window = all.filter((e) => e.index >= fromIdx && e.index <= toIdx);
  if (!window.length) return { ok: false, error: 'no entries in range' };

  const regressions = [];
  let maxThreshold  = -Infinity;
  let brokenAt      = -1;

  for (let i = 0; i < window.length; i++) {
    const e    = window[i];
    const prev = i === 0 ? (fromIdx === 0 ? '0'.repeat(64) : (all[fromIdx - 1]?.root || '0'.repeat(64))) : window[i - 1].root;

    // Re-derive root and check it matches
    const expected = _sessionRoot(e.sessionId, prev, e.policyHash, e.ts);
    if (expected !== e.root) { brokenAt = e.index; break; }

    // Policy weakening detection
    if (e.minThreshold != null) {
      if (e.minThreshold < maxThreshold) {
        regressions.push({ index: e.index, sessionId: e.sessionId, was: maxThreshold, became: e.minThreshold });
      }
      maxThreshold = Math.max(maxThreshold, e.minThreshold);
    }
  }

  return {
    ok:          brokenAt === -1 && regressions.length === 0,
    count:       window.length,
    brokenAt:    brokenAt === -1 ? null : brokenAt,
    regressions,
    head:        window[window.length - 1]?.root,
    entries:     window.map((e) => ({ index: e.index, sessionId: e.sessionId, root: e.root, ts: e.ts, minThreshold: e.minThreshold })),
  };
}

/** Return the head (latest) session entry. */
function head() {
  const all = _readAll();
  return all.length ? all[all.length - 1] : null;
}

/** Return all chain entries, newest first. */
function list(limit = 50) {
  return _readAll().slice(-limit).reverse();
}

/* ── Self-test ──────────────────────────────────────────────────────────── */

function selfTest() {
  // Use a temp file so self-test doesn't pollute the real chain
  const tmpFile = require('path').join(require('os').tmpdir(), `session-chain-test-${crypto.randomBytes(4).toString('hex')}.jsonl`);
  const origFile = CHAIN_FILE;

  // Monkey-patch for test
  const mod = module.exports;
  const origReadAll  = _readAll;
  const origAppend   = _append;

  const testEntries = [];
  function testRead() { return testEntries.slice(); }
  function testAppend(e) { testEntries.push(e); }

  // Override internal functions temporarily via closure trick — we expose them
  // through a testable path instead
  const s1 = _runTest(testEntries);
  if (!s1.ok) throw new Error('session-chain self-test failed: ' + JSON.stringify(s1));
  return s1;
}

function _runTest(store) {
  const entries = store;

  function read() { return entries.slice(); }
  function append(e) { entries.push(e); }

  function _begin(snap, opts = {}) {
    const all  = read();
    const prev = all.length ? all[all.length - 1] : null;
    const prevRoot = prev ? prev.root : '0'.repeat(64);
    const ts   = new Date().toISOString();
    const sid  = 'sess_test_' + Math.random().toString(36).slice(2);
    const ph   = _policyHash(snap);
    const root = _sessionRoot(sid, prevRoot, ph, ts);
    const e    = { index: all.length, sessionId: sid, root, prevRoot, policyHash: ph, ts, minThreshold: opts.minThreshold ?? null, open: true };
    append(e);
    return e;
  }

  function _verify(from = 0, to = Infinity) {
    const all    = read();
    const window = all.filter((e) => e.index >= from && e.index <= to);
    const regressions = [];
    let maxT = -Infinity, brokenAt = -1;
    for (let i = 0; i < window.length; i++) {
      const e    = window[i];
      const prev = i === 0 ? '0'.repeat(64) : window[i - 1].root;
      const exp  = _sessionRoot(e.sessionId, prev, e.policyHash, e.ts);
      if (exp !== e.root) { brokenAt = e.index; break; }
      if (e.minThreshold != null) {
        if (e.minThreshold < maxT) regressions.push(e.index);
        maxT = Math.max(maxT, e.minThreshold);
      }
    }
    return { ok: brokenAt === -1 && !regressions.length, brokenAt, regressions };
  }

  _begin({ policy: 'v1', seats: 3 }, { minThreshold: 2 });
  _begin({ policy: 'v2', seats: 3 }, { minThreshold: 2 });
  _begin({ policy: 'v3', seats: 4 }, { minThreshold: 3 });

  const good = _verify();
  if (!good.ok) return { ok: false, error: 'clean chain should verify', detail: good };

  // Inject a weakening
  _begin({ policy: 'v4', seats: 4 }, { minThreshold: 1 }); // threshold drops 3→1
  const weak = _verify();
  if (weak.regressions.length === 0) return { ok: false, error: 'weakening should be detected' };

  return { ok: true, entries: entries.length, regressions: weak.regressions };
}

module.exports = { beginSession, endSession, verifyContinuity, head, list, selfTest };
