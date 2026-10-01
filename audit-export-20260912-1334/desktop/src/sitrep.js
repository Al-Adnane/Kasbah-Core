'use strict';

/**
 * Situation / Crisis mode — from OCP sulfur supply-chain pattern.
 * Tracks VPN “inventory” (uptime budget), censorship spikes, and one-button crisis.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const SITREP = path.join(DIR, 'sitrep.jsonl');
const CRISIS = path.join(dirSafe(), 'crisis.json');

function dirSafe() {
  try { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); } catch (_) {}
  return DIR;
}

function appendSitrep(rec) {
  dirSafe();
  const line = { ts: new Date().toISOString(), ...rec };
  try { fs.appendFileSync(SITREP, JSON.stringify(line) + '\n'); } catch (_) {}
  return line;
}

function loadSitrep(n = 96) {
  try {
    return fs.readFileSync(SITREP, 'utf8').trim().split('\n').filter(Boolean)
      .map((l) => JSON.parse(l)).slice(-n);
  } catch { return []; }
}

/**
 * Censorship spike: compare recent handshake/ping success vs baseline.
 * @param {Array<{ok:boolean, avgMs:number|null, ts:number}>} samples
 */
function detectSpike(samples = []) {
  if (samples.length < 4) return { spike: false, reason: 'not enough samples' };
  const mid = Math.floor(samples.length / 2);
  const a = samples.slice(0, mid);
  const b = samples.slice(mid);
  const rate = (arr) => arr.filter((s) => s.ok).length / arr.length;
  const ra = rate(a);
  const rb = rate(b);
  const drop = ra - rb;
  return {
    spike: drop >= 0.4,
    baselineSuccess: +ra.toFixed(2),
    recentSuccess: +rb.toFixed(2),
    drop: +drop.toFixed(2),
    reason: drop >= 0.4
      ? `Success rate dropped ${Math.round(drop * 100)}% — possible DPI/block`
      : 'No spike',
  };
}

function inventory({ connectedMs = 0, monthMs = 30 * 24 * 3600 * 1000 } = {}) {
  const pct = monthMs > 0 ? Math.min(100, (connectedMs / monthMs) * 100) : 0;
  return {
    connectedMs,
    monthMs,
    protectedPct: +pct.toFixed(1),
    note: pct < 5 ? 'Low protected time this month' : 'Protection inventory OK',
  };
}

function crisisStatus() {
  try { return JSON.parse(fs.readFileSync(CRISIS, 'utf8')); }
  catch { return { on: false, since: null, steps: [] }; }
}

function setCrisis(on, steps = []) {
  const s = {
    on: !!on,
    since: on ? new Date().toISOString() : null,
    steps: on
      ? (steps.length ? steps : [
          'Force DPI/WSS if available on exit',
          'Lock vault',
          'Enable clipboard watch + honeytokens',
          'Require VPN for agents',
          'Alert trusted contact (dead-man)',
        ])
      : [],
  };
  dirSafe();
  fs.writeFileSync(CRISIS, JSON.stringify(s, null, 2), { mode: 0o600 });
  appendSitrep({ type: on ? 'crisis_on' : 'crisis_off' });
  return s;
}

/** Daily situation report for UI. */
function sitrep({ vpnOn = false, egress = null, lastPings = [] } = {}) {
  const hist = loadSitrep(24);
  const secretsBlocked = hist.filter((h) => h.type === 'secret_block').length;
  const spike = detectSpike(lastPings);
  return {
    ts: new Date().toISOString(),
    vpnOn,
    egressIp: egress?.ip || null,
    loc: egress?.loc || null,
    colo: egress?.colo || null,
    censorship: spike,
    inventory: inventory({ connectedMs: 0 }),
    last24h: {
      secretsBlocked,
      events: hist.length,
    },
    crisis: crisisStatus(),
  };
}

module.exports = {
  appendSitrep, loadSitrep, detectSpike, inventory,
  crisisStatus, setCrisis, sitrep, SITREP,
};
