'use strict';
/**
 * sensor-firewall.js — Purpose-registered, time-boxed sensor access.
 * Ported from workspace firewall.ts concept into Kasbah IPC reality:
 *   1. Apps REGISTER a purpose before raw mic/camera streams flow.
 *   2. Access is TIME-BOXED (grant opens N seconds, then closes).
 *   3. Every grant is RECEIPTED in a hash-chained log.
 * Fail-closed throughout. ZK purpose-proof plugs into voice-privacy
 * OR-Sigma where available; registry + time-box + receipts are live now.
 */
const crypto = require('crypto');

const _purposes = new Map(); // app -> Set(purpose)
const _grants = new Map(); // grantId -> { app, sensor, purpose, untilMs }
const _receipts = [];
let _head = crypto.createHash('sha256').update('sensor-fw-genesis').digest('hex');

function register(app = '', purposes = []) {
  const a = String(app || '');
  if (!a) return { ok: false, reason: 'app required' };
  const set = _purposes.get(a) || new Set();
  (Array.isArray(purposes) ? purposes : [purposes]).forEach((p) => { if (p) set.add(String(p)); });
  _purposes.set(a, set);
  return { ok: true, app: a, purposes: [...set] };
}
function request(app = '', sensor = '', purpose = '', seconds = 60) {
  const a = String(app || '');
  if (!['mic', 'camera'].includes(sensor)) return { ok: false, reason: 'sensor must be mic|camera' };
  const reg = _purposes.get(a);
  if (!reg || !reg.has(String(purpose))) {
    _receipt({ event: 'SENSOR_DENIED', app: a, sensor, purpose, reason: 'purpose not registered' });
    return { ok: false, reason: 'purpose not registered for app' };
  }
  const secs = Math.min(Math.max(Number(seconds) || 60, 5), 600);
  const grant = { grantId: 'sg_' + crypto.randomBytes(8).toString('hex'), app: a, sensor, purpose: String(purpose), untilMs: Date.now() + secs * 1000 };
  _grants.set(grant.grantId, grant);
  _receipt({ event: 'SENSOR_GRANTED', ...grant });
  return { ok: true, ...grant };
}
function check(app = '', sensor = '') {
  for (const g of _grants.values()) {
    if (g.app === String(app) && g.sensor === sensor && g.untilMs > Date.now()) return { ok: true, grant: g };
  }
  return { ok: false, reason: 'no live grant (register purpose + request access)' };
}
function revoke(app = '', sensor = '') {
  let n = 0;
  for (const [id, g] of _grants.entries()) {
    if ((!app || g.app === String(app)) && (!sensor || g.sensor === sensor)) { _grants.delete(id); n++; }
  }
  if (n) _receipt({ event: 'SENSOR_REVOKED', app, sensor, count: n });
  return { ok: true, revoked: n };
}
function _receipt(row) {
  const body = JSON.stringify({ ...row, ts: Date.now(), prev: _head });
  _head = crypto.createHash('sha256').update(body).digest('hex');
  _receipts.push({ ...row, head: _head });
  if (_receipts.length > 1000) _receipts.splice(0, _receipts.length - 1000);
  return _head;
}
function receipts(limit = 100) { return _receipts.slice(-limit).reverse(); }

module.exports = { register, request, check, revoke, receipts };
