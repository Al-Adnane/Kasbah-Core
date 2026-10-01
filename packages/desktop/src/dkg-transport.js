'use strict';

/**
 * DKG transport — authenticated share delivery between local seats.
 * Honest: single-machine authenticated channel (Ed25519 + optional ML-KEM seal).
 * NOT libp2p/Noise. For multi-device, drop shares into a sealed file or
 * QR/USB and verify signatures.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const didKey = require('./did-key.js');
const pq = require('./pq-seal.js');

const DIR = path.join(os.homedir(), '.kasbah-privacy', 'dkg-mailbox');
function ensure() { try { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); } catch (_) {} }

/**
 * Create a signed envelope for a share destined to peerId.
 * @param opts.fromDid, fromPrivateKey, toDid, share, usePq, recipientPkB64
 */
function sendShare(opts = {}) {
  ensure();
  const body = {
    v: 1,
    type: 'dkg-share',
    from: opts.fromDid,
    to: opts.toDid,
    ts: Date.now(),
    share: opts.share,
  };
  const payload = JSON.stringify(body);
  const sig = didKey.signRaw(opts.fromPrivateKey, payload);
  let sealed = null;
  if (opts.usePq && opts.recipientPkB64 && pq.available()) {
    sealed = pq.seal(Buffer.from(payload), opts.recipientPkB64, 'dkg-share');
  }
  const env = {
    v: 1,
    from: opts.fromDid,
    to: opts.toDid,
    sig: sig.toString('base64url'),
    sealed,
    // plaintext only when not sealed
    body: sealed ? undefined : body,
  };
  const file = path.join(DIR, `${Date.now()}-${crypto.randomBytes(4).toString('hex')}.json`);
  fs.writeFileSync(file, JSON.stringify(env, null, 2), { mode: 0o600 });
  return { ok: true, file, sealed: !!sealed };
}

/** List envelopes for a recipient DID. */
function inbox(toDid) {
  ensure();
  const out = [];
  for (const f of fs.readdirSync(DIR).filter((x) => x.endsWith('.json'))) {
    try {
      const env = JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));
      if (env.to === toDid) out.push({ file: f, ...env });
    } catch (_) {}
  }
  return out;
}

/** Verify + open one envelope. */
function receive(env, { recipientSecretKeyB64, fromPublicKeyRaw } = {}) {
  let body = env.body;
  if (env.sealed) {
    if (!recipientSecretKeyB64) return { ok: false, error: 'sealed envelope requires recipient key' };
    const pt = pq.open(env.sealed, recipientSecretKeyB64);
    body = JSON.parse(pt.toString('utf8'));
  }
  if (!body) return { ok: false, error: 'no body' };
  // Signature: need sender public key — from DID if did:key
  let pk = fromPublicKeyRaw;
  if (!pk && body.from && String(body.from).startsWith('did:key:')) {
    pk = didKey.publicKeyFromDidKey(body.from);
  }
  if (!pk) return { ok: false, error: 'cannot resolve sender public key' };
  const ok = didKey.verifyRaw(pk, JSON.stringify(body), didKey.b64urlDecode(env.sig));
  if (!ok) return { ok: false, error: 'envelope signature invalid' };
  return { ok: true, body };
}

function selfTest() {
  const A = didKey.generateIssuer();
  const B = didKey.generateIssuer();
  const r1 = sendShare({
    fromDid: A.did, fromPrivateKey: A.privateKey, toDid: B.did,
    share: { x: '0x1', y: 'abc' },
  });
  const list = inbox(B.did);
  if (!list.length) throw new Error('inbox empty');
  const rec = receive(list[0], {});
  if (!rec.ok || rec.body.share.y !== 'abc') throw new Error(rec.error || 'receive failed');
  const cases = ['sign+receive'];
  if (pq.available()) {
    const r2 = sendShare({
      fromDid: A.did, fromPrivateKey: A.privateKey, toDid: B.did,
      share: { x: '0x2', y: 'sealed' },
      usePq: true,
      recipientPkB64: pq.keygen().publicKey,
    });
    if (!r2.sealed) throw new Error('pq seal missing');
    cases.push('pq envelope written');
  }
  return { ok: true, passed: cases.length, cases };
}

module.exports = { sendShare, inbox, receive, selfTest, DIR };
