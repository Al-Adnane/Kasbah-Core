'use strict';

/**
 * Signed session receipts for VPN lifecycle events.
 *
 * Every up/down/peer-add/mesh-init gets an Ed25519 receipt via
 * @yobekasbah/receipts, chained to the previous one and appended to
 * receipts.jsonl. Anyone holding the public key can verify the whole session
 * history offline — same artifact, same verifier as gateway receipts.
 *
 * What this proves: that this tool recorded and signed these lifecycle events,
 * in this order, with this key. It is NOT a no-logs attestation about any
 * exit-node operator — the docs must never claim that.
 */

const path = require('path');
const receiptsLib = require(path.join(__dirname, '..', '..', 'kasbah-receipts', 'src', 'index.js'));
const store = require('./store');

const KEY_FILE = 'receipt-key.pem';
const PUB_FILE = 'receipt-key.pub.pem';
const LOG_FILE = 'receipts.jsonl';

/** Load (or mint on first use) the local Ed25519 receipt signing key. */
function signingKey() {
  let priv = store.readFileIfExists(KEY_FILE);
  if (!priv) {
    const kp = receiptsLib.generateKeyPair();
    store.writePrivate(KEY_FILE, kp.privateKeyPem);
    store.writePrivate(PUB_FILE, kp.publicKeyPem);
    priv = kp.privateKeyPem;
  }
  return { privateKey: priv, publicKeyPem: store.readFileIfExists(PUB_FILE) };
}

function lastEntry() {
  const raw = store.readFileIfExists(LOG_FILE);
  if (!raw) return null;
  const lines = raw.trim().split('\n').filter(Boolean);
  if (lines.length === 0) return null;
  try {
    return JSON.parse(lines[lines.length - 1]);
  } catch {
    return null;
  }
}

/**
 * Sign and append a session event receipt.
 * @param {string} event  e.g. 'vpn.up', 'vpn.down', 'peer.add', 'mesh.init', 'ai-lane.start'
 * @param {object} detail event fields (interface, peer pubkey, mode, …) — no key material
 */
function record(event, detail = {}) {
  const { privateKey } = signingKey();
  const prev = lastEntry();
  const signed = receiptsLib.sign(
    {
      attestationType: 'vpn-session',
      action: event,
      detail,
      host: require('os').hostname(),
    },
    { privateKey },
    {
      engine: '@yobekasbah/vpn@0.1.0',
      chainId: prev?.decoded?.chainId || 'vpnchain_' + Date.now().toString(36),
      parentReceipt: prev?.receipt || null,
    }
  );
  const entry = { receipt: signed.receipt, payload: signed.payload, decoded: signed.decoded };
  store.appendLine(LOG_FILE, JSON.stringify(entry));
  return entry;
}

/** All recorded receipts, oldest first. */
function list() {
  const raw = store.readFileIfExists(LOG_FILE);
  if (!raw) return [];
  return raw
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

/** Verify every receipt in the log against the local public key. */
function verifyAll() {
  const { publicKeyPem } = signingKey();
  const entries = list();
  const results = entries.map((e) => {
    const r = receiptsLib.verify(e.receipt, e.payload, publicKeyPem);
    return { id: e.decoded?.id, action: e.decoded?.action, ts: e.decoded?.ts, valid: r.valid, error: r.error };
  });
  return { total: entries.length, valid: results.filter((r) => r.valid).length, results };
}

module.exports = { record, list, verifyAll, signingKey, LOG_FILE };
