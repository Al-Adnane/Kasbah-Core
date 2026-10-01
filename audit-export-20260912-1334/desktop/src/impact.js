'use strict';

/**
 * Impact card — outcomes (incidents prevented), not feature counts.
 * Pattern from ESS: outputs vs results.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const FILE = path.join(os.homedir(), '.kasbah-privacy', 'impact.json');

function load() {
  try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); }
  catch {
    return {
      secretsBlocked: 0,
      honeyHits: 0,
      agentBlocks: 0,
      vpnMinutes: 0,
      proofsMinted: 0,
      scans: 0,
      startedAt: new Date().toISOString(),
    };
  }
}

function save(s) {
  try {
    fs.mkdirSync(path.dirname(FILE), { recursive: true, mode: 0o700 });
    fs.writeFileSync(FILE, JSON.stringify(s, null, 2), { mode: 0o600 });
  } catch (_) {}
  return s;
}

function bump(key, n = 1) {
  const s = load();
  if (key in s && typeof s[key] === 'number') s[key] += n;
  return save(s);
}

function snapshot() {
  const s = load();
  // Rough “value avoided” narrative — not a bill, a story
  const estValue = s.secretsBlocked * 500 + s.agentBlocks * 200 + s.honeyHits * 1000;
  return {
    ...s,
    estValueUsd: estValue,
    headline: s.secretsBlocked || s.agentBlocks || s.honeyHits
      ? `${s.secretsBlocked + s.agentBlocks + s.honeyHits} risky events stopped`
      : 'No incidents yet — protection is on',
    note: 'Outcomes, not feature count',
  };
}

module.exports = { load, save, bump, snapshot, FILE };
