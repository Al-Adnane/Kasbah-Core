'use strict';
/**
 * physical-products.js — Engine of the physical products family.
 *
 * One host-side engine drives every Kasbah device: Consent Stone (desk),
 * Ring, Band, USB token (v1-lite), and future variants. Devices differ
 * only in TRANSPORT + FORM; the trust model is identical:
 *   - keys live in the secure element, never exportable
 *   - tap/gesture requires physical liveness (touch ISR)
 *   - attestations verify against provisioned per-agent pubkeys
 *   - fail-closed on timeout, disconnect, or cross-agent use
 *
 * Products registry: each product declares { transport, form,
 * capabilities[] }. The engine fans aura/alerts/gestures out to every
 * device paired to an agent, and accepts attestations from any of them.
 */
const crypto = require('crypto');
const consentGate = require('./consent-gate.js');

const PRODUCTS = {
  'stone-desk':  { transport: ['ble'],       form: 'desk', capabilities: ['tap', 'aura-glow', 'haptic', 'presence'] },
  'stone-pendant': { transport: ['ble'], form: 'pendant', hero: true, weight: '12 g', capabilities: ['tap', 'double-tap', 'hold-to-deny', 'duress', 'aura-glow', 'haptic', 'presence', 'away-mode'] },
  'stone-ring':  { transport: ['ble'],       form: 'ring', weight: '6 g', capabilities: ['tap', 'double-tap', 'hold-to-deny', 'duress', 'aura-glow', 'haptic', 'presence', 'away-mode'] },
  'stone-clip':  { transport: ['ble'],       form: 'clip', weight: '9 g', capabilities: ['tap', 'aura-glow', 'haptic', 'presence'] },
  'stone-band':  { transport: ['ble'],       form: 'wristband', weight: '18 g', capabilities: ['tap', 'double-tap', 'hold-to-deny', 'duress', 'aura-glow', 'haptic', 'presence', 'away-mode', 'rppg-guard'] },
  'stone-usb':   { transport: ['usb-hid'],   form: 'token', capabilities: ['tap', 'presence'] },
  'stone-card':  { transport: ['nfc'],       form: 'card', capabilities: ['tap', 'presence'] },
};
// Monotonic counter: SE bumps a counter per signature; host rejects any
// attestation with counter <= cached (anti-replay beyond nonce binding).
const _counters = new Map(); // stoneId -> last counter
function checkCounter(stoneId, counter) {
  const last = _counters.get(String(stoneId)) ?? -1;
  if (typeof counter !== 'number' || counter <= last) return { ok: false, reason: 'STALE_COUNTER' };
  _counters.set(String(stoneId), counter);
  return { ok: true };
}

// Transport drivers. Soft (simulator) is live; ble/usb-hid/nfc register
// real drivers when their native modules are present. Missing driver =
// clean { available:false }, never a fake attestation.
const _drivers = new Map();
function registerTransport(name, driver) {
  _drivers.set(String(name), driver);
  return { ok: true, transport: String(name) };
}
function transportFor(productId) {
  const p = PRODUCTS[productId];
  if (!p) return { ok: false, reason: 'unknown product' };
  for (const t of p.transport) {
    if (_drivers.has(t)) return { ok: true, product: productId, transport: t, driver: _drivers.get(t), simulated: false };
  }
  // Soft fallback: simulator drives any product until its native driver
  // registers. Never claims to be hardware.
  if (_drivers.has('soft')) return { ok: true, product: productId, transport: p.transport[0] + '+soft-sim', driver: _drivers.get('soft'), simulated: true };
  return { ok: false, product: productId, reason: 'no driver for ' + p.transport.join('/') };
}
// Soft driver: in-process sign (dev/pilot). Never claims to be hardware.
registerTransport('soft', {
  available: true, hardware: false,
  async requestTap({ canonical, agentId }) {
    const att = consentGate.stoneSign(canonical, agentId);
    return { ok: true, attestation: att };
  },
});

// Device registry: agentId -> [{ productId, deviceId, pubkey, ... }]
const _devices = new Map();
function pairDevice(agentId = 'anonymous', body = {}) {
  const id = String(agentId || 'anonymous');
  if (!PRODUCTS[body.productId]) return { ok: false, reason: 'unknown product', known: Object.keys(PRODUCTS) };
  const list = _devices.get(id) || [];
  const rec = {
    deviceId: String(body.deviceId || 'dev-' + crypto.randomBytes(4).toString('hex')),
    productId: body.productId,
    pubkey: body.pubkey || null,
    transport: PRODUCTS[body.productId].transport[0],
    pairedAt: Date.now(), lastSeen: Date.now(),
  };
  // A device that presents a signing key becomes an approver for this agent.
  // First key is trust-on-first-use; later keys need a proof signed by a
  // registered approver (see consentGate.provisionApprover).
  let approver = null;
  if (rec.pubkey) {
    approver = consentGate.provisionApprover({ agentId: id, pubkey: String(rec.pubkey), kind: 'hw-stone', proof: body.proof });
    if (!approver.ok) return { ok: false, reason: approver.reason };
    rec.keyId = approver.keyId;
  }
  list.push(rec);
  _devices.set(id, list);
  // Wearable-class devices also register with the away-mode subsystem.
  if (['stone-ring', 'stone-band'].includes(body.productId)) {
    try { consentGate.pairWearable(id, { wearableId: rec.deviceId, kind: body.productId, pubkey: rec.pubkey }); } catch (_) {}
  }
  return { ok: true, agentId: id, stoneId: consentGate.stoneIdFor(id), device: rec, approver };
}
function devicesFor(agentId) { return _devices.get(String(agentId || 'anonymous')) || []; }
function heartbeat(agentId, deviceId, body = {}) {
  const list = devicesFor(agentId);
  const d = list.find((x) => x.deviceId === String(deviceId));
  if (!d) return { ok: false, reason: 'unknown device' };
  d.lastSeen = Date.now();
  if (body.rssi !== undefined) d.rssi = Number(body.rssi);
  let flushed = [];
  if (d.productId === 'stone-ring' || d.productId === 'stone-band') {
    try { const r = consentGate.wearableHeartbeat(agentId, body); flushed = r.boxes || []; } catch (_) {}
  }
  return { ok: true, device: d, away: consentGate.awayMode(agentId).away, flushed: flushed.length, boxes: flushed };
}
// Fan-out: one alert lights every paired device's aura at once.
function fanoutAlert(agentId, source, detail = {}) {
  const r = consentGate.sentinelAlert(agentId, source, detail);
  const devices = devicesFor(agentId).map((d) => ({ deviceId: d.deviceId, productId: d.productId, glow: r.aura.glow }));
  return { ...r, fannedOut: devices.length, devices };
}
// Attestation intake from any device: counter + agent checks, then bind.
// Hardware attestations carry { signature, counter, stoneId }; the SE bumps
// the counter per signature and the host rejects stale counters.
function acceptAttestation({ tapId, attestation, agentId } = {}) {
  if (!tapId || !attestation || typeof attestation !== 'object') return { ok: false, reason: 'tapId + attestation required' };
  const pend = consentGate.pending().find((p) => p.id === tapId);
  if (!pend) return { ok: false, reason: 'unknown or expired tap' };
  // The attestation is for the agent that owns the request. A caller naming a
  // different agent is refused; omitting agentId no longer slips through.
  const claimed = agentId != null ? String(agentId) : (attestation.agentId != null ? String(attestation.agentId) : null);
  if (claimed !== null && claimed !== String(pend.agentId)) {
    return { ok: false, reason: 'cross-agent attestation denied: remote kill-switch blocked' };
  }
  if (!consentGate.APPROVER_KINDS.has(attestation.signer)) {
    return { ok: false, reason: 'attestation must come from a registered approver (hw-stone or desktop)' };
  }
  if (!consentGate.approverRequired(pend.agentId)) {
    // No key is provisioned to check the signature against. Accepting it would
    // mean trusting an unverifiable claim of "hardware", so refuse.
    return { ok: false, reason: 'no approver key is provisioned for this agent; pair a device first' };
  }
  // The gate verifies the signature over the request's challenge and enforces
  // the monotonic counter. Nothing is approved on the strength of the
  // attestation's own fields.
  const r = consentGate.tap(tapId, { agentId: pend.agentId, approve: true, attestation });
  if (r.error) return { ok: false, reason: r.error };
  return { ok: r.A === 1, ...r };
}

module.exports = { PRODUCTS, registerTransport, transportFor, pairDevice, devicesFor, heartbeat, fanoutAlert, acceptAttestation, checkCounter };
