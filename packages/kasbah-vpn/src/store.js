'use strict';

/**
 * On-disk profile state: ~/.kasbah-vpn (override with KASBAH_VPN_DIR).
 *
 *   profile.json    — WG keys, KEM keys, peers, server settings
 *   receipt-key.pem — Ed25519 receipt signing key (0600)
 *   receipts.jsonl  — chained signed session receipts, append-only
 *
 * Key files and the directory are private (0700/0600). Everything is local;
 * nothing here phones home.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

function stateDir() {
  return process.env.KASBAH_VPN_DIR || path.join(os.homedir(), '.kasbah-vpn');
}

function ensureDir() {
  const dir = stateDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function profilePath() {
  return path.join(stateDir(), 'profile.json');
}

function loadProfile() {
  try {
    const p = JSON.parse(fs.readFileSync(profilePath(), 'utf8'));
    const normalized = _normalizeProfile(p);
    if (normalized !== p) {
      // Persist the migrated shape so every later read is consistent.
      try { saveProfile(normalized); } catch {}
    }
    return normalized;
  } catch {
    return null;
  }
}

// (audit 2026-09): legacy profiles (pre-mesh format) stored a flat
// { privateKey, publicKey, psk, address, createdAt } — the current code
// expects { wg: { privateKey, publicKey }, kem?, peers: [], ... } and crashed
// on `profile.wg.publicKey` when reading an old profile. Normalize on load.
function _normalizeProfile(p) {
  if (!p || typeof p !== 'object') return null;
  if (p.wg) return p; // current format
  return {
    name: p.name || 'default',
    wg: { privateKey: p.privateKey, publicKey: p.publicKey },
    psk: p.psk,
    address: p.address,
    kem: p.kem || null,
    peers: p.peers || [],
    server: p.server || null,
    client: p.client || null,
    createdAt: p.createdAt,
    _migratedFrom: 'legacy-flat-format',
  };
}

function saveProfile(profile) {
  ensureDir();
  fs.writeFileSync(profilePath(), JSON.stringify(profile, null, 2) + '\n', { mode: 0o600 });
  return profile;
}

function writePrivate(name, content) {
  ensureDir();
  const p = path.join(stateDir(), name);
  fs.writeFileSync(p, content, { mode: 0o600 });
  return p;
}

function readFileIfExists(name) {
  try {
    return fs.readFileSync(path.join(stateDir(), name), 'utf8');
  } catch {
    return null;
  }
}

function appendLine(name, line) {
  ensureDir();
  const p = path.join(stateDir(), name);
  fs.appendFileSync(p, line + '\n', { mode: 0o600 });
  return p;
}

module.exports = { stateDir, ensureDir, profilePath, loadProfile, saveProfile, writePrivate, readFileIfExists, appendLine };
