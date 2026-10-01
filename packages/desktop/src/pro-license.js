'use strict';

/**
 * Kasbah Privacy Pro — offline-issued license bound to this machine.
 *
 * Code format: KASBAH-PRO-XXXX-YYYY
 *   XXXX = random body
 *   YYYY = first 4 hex of HMAC-SHA256(SECRET, body || machineId)
 *
 * machineId is derived from hostname + username (stable per Mac).
 * This is NOT a server round-trip: it stops casual code sharing, not a
 * determined cracker who reads this file. Real entitlement should call
 * the billing API the same way vpn:connect does — when you have one.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const LICENSE_PATH = path.join(os.homedir(), '.kasbah-pro.json');
// Public-ish app secret: fine for offline HMAC; rotate if you go commercial.
const SECRET = 'kasbah-privacy-pro-hmac-v1-2026';

const PRO_FEATURES = [
  'multi_exit',
  'dpi_priority',
  'receipt_export',
  'identity_watch',
  'encrypted_backup',
  'family_safety',
  'clipboard_watch',
  'priority_support',
  'vc_export',            // unlimited portable VC issue + file export
  'compliance_credential', // alias for marketing; same gate as vc_export
];

function machineId() {
  const raw = `${os.hostname()}|${os.userInfo().username || process.env.USER || 'user'}|kasbah`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

function expectedSuffix(body) {
  return crypto.createHmac('sha256', SECRET).update(body + '|' + machineId()).digest('hex').slice(0, 4).toUpperCase();
}

function load() {
  try {
    const lic = JSON.parse(fs.readFileSync(LICENSE_PATH, 'utf8'));
    // Re-verify binding on every load — copy-pasting the file to another Mac fails
    if (lic.tier === 'pro' && lic.body) {
      if (lic.machineId !== machineId()) {
        return { tier: 'free', features: [], activatedAt: null, code: null, reason: 'machine_mismatch' };
      }
      if (expectedSuffix(lic.body) !== lic.suffix) {
        return { tier: 'free', features: [], activatedAt: null, code: null, reason: 'bad_signature' };
      }
    }
    return lic;
  } catch {
    return { tier: 'free', features: [], activatedAt: null, code: null };
  }
}

function save(lic) {
  fs.writeFileSync(LICENSE_PATH, JSON.stringify(lic, null, 2), { mode: 0o600 });
  return lic;
}

function activate(code) {
  const c = String(code || '').trim().toUpperCase();
  // Demo: only valid on this machine via HMAC (same as real codes)
  if (!/^KASBAH-PRO-([A-Z0-9]{4})-([A-Z0-9]{4})$/.test(c)) {
    return { ok: false, error: 'Format: KASBAH-PRO-XXXX-XXXX' };
  }
  const body = RegExp.$1;
  const suffix = RegExp.$2;
  if (expectedSuffix(body) !== suffix) {
    return {
      ok: false,
      error: 'Invalid or not issued for this Mac. Use a code from Plans / support.',
    };
  }
  const lic = {
    tier: 'pro',
    code: c,
    body,
    suffix,
    machineId: machineId(),
    source: 'signed-offline',
    features: PRO_FEATURES,
    activatedAt: new Date().toISOString(),
  };
  save(lic);
  return { ok: true, license: redact(lic) };
}

function deactivate() {
  save({ tier: 'free', features: [], activatedAt: null, code: null });
  return { ok: true, license: status() };
}

function status() {
  return redact(load());
}

function redact(lic) {
  return {
    tier: lic.tier || 'free',
    isPro: lic.tier === 'pro',
    features: lic.features || [],
    activatedAt: lic.activatedAt || null,
    codeHint: lic.code ? lic.code.slice(0, 14) + '…' : null,
    machineId: machineId(),
  };
}

function has(feature) {
  const lic = load();
  return lic.tier === 'pro' && (lic.features || []).includes(feature);
}

/** Issue a valid code for THIS machine (support / founder use). */
function issueCode() {
  const body = crypto.randomBytes(2).toString('hex').toUpperCase();
  const suffix = expectedSuffix(body);
  return { code: `KASBAH-PRO-${body}-${suffix}`, machineId: machineId() };
}

/** Founder/demo shortcut: always a valid code for this Mac. */
function demoCode() {
  return issueCode();
}

module.exports = { activate, deactivate, status, has, issueCode, PRO_FEATURES, LICENSE_PATH, machineId };
