'use strict';

/**
 * Capability tokens with delegation chains (Node Ed25519).
 * Root grant → delegate to subject → verify chain.
 * Honest: local keys; no status list / revocation.
 */

const crypto = require('crypto');
const didKey = require('./did-key.js');

function canonical(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort(), /* replacer */ undefined);
}
// stable stringify with sorted keys
function jcs(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(jcs).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(obj[k])).join(',') + '}';
}

function capCanonical(c) {
  return jcs({
    issuer: c.issuer,
    subject: c.subject,
    resource: c.resource,
    action: c.action,
    expires: c.expires,
    delegatable: c.delegatable,
    nonce: c.nonce,
  });
}

function issue({ issuerPrivateKey, issuerDid, subjectDid, resource, action, ttlSeconds = 3600, delegatable = true }) {
  const nonce = crypto.randomBytes(16).toString('base64url');
  const body = {
    type: 'KasbahCapability',
    issuer: issuerDid,
    subject: subjectDid,
    resource,
    action,
    expires: Date.now() / 1000 + Number(ttlSeconds),
    delegatable: !!delegatable,
    nonce,
  };
  const sig = didKey.signRaw(issuerPrivateKey, capCanonical(body));
  return { ...body, signature: sig.toString('base64url') };
}

function delegate({ parent, delegatorPrivateKey, delegatorDid, newSubjectDid, ttlSeconds }) {
  if (!parent || !parent.delegatable) throw new Error('capability is not delegatable');
  if (parent.subject !== delegatorDid) throw new Error('delegator is not the capability subject');
  let expires = parent.expires;
  if (ttlSeconds != null) expires = Math.min(expires, Date.now() / 1000 + Number(ttlSeconds));
  return issue({
    issuerPrivateKey: delegatorPrivateKey,
    issuerDid: delegatorDid,
    subjectDid: newSubjectDid,
    resource: parent.resource,
    action: parent.action,
    ttlSeconds: expires - Date.now() / 1000,
    delegatable: parent.delegatable,
  });
}

function verifyChain(chain, resource, action) {
  if (!Array.isArray(chain) || !chain.length) return { ok: false, reason: 'empty chain' };
  const now = Date.now() / 1000;
  let prevSubject = null;
  for (let i = 0; i < chain.length; i++) {
    const link = chain[i];
    if (!link || link.type !== 'KasbahCapability') return { ok: false, reason: `link ${i}: wrong type` };
    if (link.resource !== resource || link.action !== action) return { ok: false, reason: `link ${i}: resource/action mismatch` };
    if (Number(link.expires) < now) return { ok: false, reason: `link ${i}: expired` };
    let pk;
    try { pk = didKey.publicKeyFromDidKey(link.issuer); }
    catch (e) { return { ok: false, reason: `link ${i}: ${e.message}` }; }
    const sig = didKey.b64urlDecode(link.signature);
    if (!didKey.verifyRaw(pk, capCanonical(link), sig)) return { ok: false, reason: `link ${i}: signature invalid` };
    if (prevSubject !== null && link.issuer !== prevSubject) return { ok: false, reason: `link ${i}: issuer is not previous subject` };
    if (i < chain.length - 1 && !link.delegatable) return { ok: false, reason: `link ${i}: not delegatable but chain continues` };
    prevSubject = link.subject;
  }
  return { ok: true, reason: 'ok' };
}

function selfTest() {
  const A = didKey.generateIssuer();
  const B = didKey.generateIssuer();
  const C = didKey.generateIssuer();
  const root = issue({
    issuerPrivateKey: A.privateKey, issuerDid: A.did,
    subjectDid: B.did, resource: 'vault', action: 'read',
    ttlSeconds: 3600, delegatable: true,
  });
  const leaf = delegate({
    parent: root, delegatorPrivateKey: B.privateKey, delegatorDid: B.did,
    newSubjectDid: C.did,
  });
  const good = verifyChain([root, leaf], 'vault', 'read');
  const bad = verifyChain([root, issue({
    issuerPrivateKey: C.privateKey, issuerDid: C.did,
    subjectDid: C.did, resource: 'vault', action: 'read',
  })], 'vault', 'read');
  const nonDel = issue({
    issuerPrivateKey: A.privateKey, issuerDid: A.did,
    subjectDid: B.did, resource: 'vault', action: 'read',
    delegatable: false,
  });
  const escalated = verifyChain([root, issue({
    issuerPrivateKey: B.privateKey, issuerDid: B.did,
    subjectDid: C.did, resource: 'vault', action: 'write',
  })], 'vault', 'write');
  return {
    ok: good.ok === true && bad.ok === false && escalated.ok === false
      && verifyChain([nonDel, leaf], 'vault', 'read').ok === false,
    good, brokenLink: bad, escalate: escalated,
  };
}

module.exports = { issue, delegate, verifyChain, selfTest, jcs };
