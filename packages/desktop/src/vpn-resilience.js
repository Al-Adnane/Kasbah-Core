'use strict';

/**
 * Auto-reconnect + DPI probe for WireGuard.
 * Unique: Myanmar-class networks drop UDP; we detect and offer WSS mode.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const dgram = require('dgram');
const { execFile } = require('child_process');

const STATE = {
  autoReconnect: false,
  lastLocationId: null,
  failStreak: 0,
  timer: null,
  onChange: null,
};

function setState(patch) {
  Object.assign(STATE, patch);
  if (STATE.onChange) STATE.onChange({ ...STATE });
}

/** Probe whether UDP to host:port looks filtered (no path vs path). */
function dpiProbe(host, port = 51820, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      try { s.close(); } catch (_) {}
      resolve(r);
    };
    s.on('error', (e) => finish({ host, port, udp: 'error', detail: e.message, dpiRisk: 'high' }));
    // Send a WG-sized datagram. No reply is normal; ICMP unreachable is a signal.
    s.send(Buffer.alloc(148, 1), port, host, (err) => {
      if (err) return finish({ host, port, udp: 'send-fail', detail: err.message, dpiRisk: 'high' });
    });
    setTimeout(() => finish({ host, port, udp: 'sent', detail: 'no icmp-unreachable', dpiRisk: 'unknown' }), timeoutMs);
  });
}

/** Start auto-reconnect loop. Calls `connectFn(locationId)` when tunnel dies. */
function startAutoReconnect({ connectFn, checkFn, locationId, intervalMs = 20000, onChange }) {
  stopAutoReconnect();
  STATE.autoReconnect = true;
  STATE.lastLocationId = locationId;
  STATE.onChange = onChange || null;
  STATE.timer = setInterval(async () => {
    if (!STATE.autoReconnect) return;
    let up = false;
    try { up = await checkFn(); } catch { up = false; }
    if (up) {
      STATE.failStreak = 0;
      if (STATE.onChange) STATE.onChange({ ...STATE, status: 'connected' });
      return;
    }
    STATE.failStreak++;
    if (STATE.onChange) STATE.onChange({ ...STATE, status: 'reconnecting', failStreak: STATE.failStreak });
    if (STATE.failStreak >= 1) {
      try {
        await connectFn(STATE.lastLocationId);
        STATE.failStreak = 0;
      } catch (_) { /* keep trying */ }
    }
  }, intervalMs);
  return { ok: true, autoReconnect: true, locationId };
}

function stopAutoReconnect() {
  STATE.autoReconnect = false;
  if (STATE.timer) clearInterval(STATE.timer);
  STATE.timer = null;
  STATE.failStreak = 0;
  return { ok: true, autoReconnect: false };
}

function autoReconnectStatus() {
  return {
    autoReconnect: STATE.autoReconnect,
    lastLocationId: STATE.lastLocationId,
    failStreak: STATE.failStreak,
  };
}

/** Persist preference */
const PREF = path.join(os.homedir(), '.kasbah-vpn', 'prefs.json');
function loadPrefs() {
  try { return JSON.parse(fs.readFileSync(PREF, 'utf8')); } catch { return {}; }
}
function savePrefs(p) {
  try {
    fs.mkdirSync(path.dirname(PREF), { recursive: true });
    fs.writeFileSync(PREF, JSON.stringify(p, null, 2), { mode: 0o600 });
  } catch (_) {}
  return p;
}

module.exports = { dpiProbe, startAutoReconnect, stopAutoReconnect, autoReconnectStatus, loadPrefs, savePrefs };
