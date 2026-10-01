'use strict';

/**
 * Claim ledger — every product claim gets verdict + confidence + how to verify.
 * Pattern from academic fact-check reports on Desktop.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const FILE = path.join(os.homedir(), '.kasbah-privacy', 'claim-ledger.json');

const SEED = [
  {
    id: 'vpn-my-sg',
    claim: 'VPN works from Myanmar to Singapore',
    verdict: 'FIELD_TESTED',
    confidence: 'high',
    evidence: 'Yangon Frontiir → egress 138.199.24.239 colo SIN (2026-09-11)',
    reproduce: 'Connect Singapore → Verify IP; expect colo=SIN',
    lastChecked: null,
  },
  {
    id: 'pq-psk',
    claim: 'WireGuard PSK is post-quantum hybrid (ML-KEM-768)',
    verdict: 'UNIT_TESTED',
    confidence: 'high',
    evidence: 'kasbah-vpn test.js — both sides derive identical PSK',
    reproduce: 'node packages/kasbah-vpn/test.js',
    lastChecked: null,
  },
  {
    id: 'pop-signed',
    claim: 'Protection proofs are offline-verifiable',
    verdict: 'UNIT_TESTED',
    confidence: 'high',
    evidence: 'proof-protection mint + verifyEntry; Ed25519',
    reproduce: 'node test/run-tests.js (proof-of-protection)',
    lastChecked: null,
  },
  {
    id: 'agent-vpn-lock',
    claim: 'evaluate()/HTTP gate deny agent tool calls when VPN required and tunnel down',
    verdict: 'UNIT_TESTED',
    confidence: 'medium',
    evidence: 'agent-guard evaluate + setVpnState is unit-tested and does deny correctly, but enforcement is advisory: only a caller that actually consults evaluate() (IPC) or POSTs to the HTTP gate before acting is blocked — nothing intercepts a tool call that skips it.',
    reproduce: 'node test/run-tests.js (agent guard)',
    lastChecked: null,
  },
  {
    id: 'dpi-wss',
    claim: 'DPI / WSS:443 bypasses Myanmar UDP blocks',
    verdict: 'UNPROVEN',
    confidence: 'low',
    evidence: 'Client obfs + exit scripts exist; no field matrix yet',
    reproduce: 'Install wstunnel on exit; enable obfs on location; test from MM',
    lastChecked: null,
  },
  {
    id: 'no-logs-exit',
    claim: 'Exit nodes keep no logs',
    verdict: 'NOT_CLAIMED',
    confidence: 'n/a',
    evidence: 'Fly.io is not under our control — we never claim no-logs',
    reproduce: 'n/a',
    lastChecked: null,
  },
];

function load() {
  try {
    const j = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    if (Array.isArray(j.claims) && j.claims.length) return j.claims;
  } catch (_) {}
  return SEED.slice();
}

function save(claims) {
  try {
    fs.mkdirSync(path.dirname(FILE), { recursive: true, mode: 0o700 });
    fs.writeFileSync(FILE, JSON.stringify({ claims, updatedAt: new Date().toISOString() }, null, 2), { mode: 0o600 });
  } catch (_) {}
  return claims;
}

function list() {
  return load().map((c) => ({
    ...c,
    verified: c.verdict === 'FIELD_TESTED' || c.verdict === 'UNIT_TESTED',
  }));
}

function markChecked(id) {
  const claims = load();
  const c = claims.find((x) => x.id === id);
  if (c) { c.lastChecked = new Date().toISOString(); save(claims); }
  return c || null;
}

module.exports = { list, markChecked, FILE };
