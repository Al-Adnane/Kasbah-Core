'use strict';

/**
 * consent-attested.test.js — adversarial tests for human-bound approval.
 *
 * The property under test: once an approver key is provisioned, NOTHING
 * approves a request except a fresh signature from that key over the request's
 * own challenge. Every test below is an attempt to get an approval some other
 * way, or to weaken the gate, and must fail.
 *
 * Runs in a temp directory. No server, no hardware.
 * Run: node tests/consent-attested.test.js
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const GATE = path.join(__dirname, '..', 'packages', 'api-server', 'src', 'consent-gate.js');
const PHYS = path.join(__dirname, '..', 'packages', 'api-server', 'src', 'physical-products.js');
delete process.env.KASBAH_REQUIRE_ATTESTED_TAP;

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log('  ✓ ' + name); }
  catch (e) { fail++; console.log('  ✗ ' + name + '\n      ' + String(e.message).split('\n')[0]); }
}

// Fresh module instances + fresh data dir for each scenario.
function fresh() {
  for (const k of Object.keys(require.cache)) if (k === GATE || k === PHYS) delete require.cache[k];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kasbah-consent-'));
  const gate = require(GATE);
  gate.init({ dataDir: dir });
  return { gate, phys: require(PHYS), dir };
}
function reload(dir) {
  for (const k of Object.keys(require.cache)) if (k === GATE || k === PHYS) delete require.cache[k];
  const gate = require(GATE); gate.init({ dataDir: dir });
  return { gate, phys: require(PHYS) };
}
function approver() {
  const kp = crypto.generateKeyPairSync('ed25519');
  const pubkey = kp.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  let counter = 0;
  return {
    pubkey, kp,
    next: () => ++counter,
    sign: (gate, challenge, c, signer = 'desktop') => ({
      signer, counter: c,
      signature: crypto.sign(null, Buffer.from(gate.attestationMessage(challenge, c)), kp.privateKey).toString('base64url'),
    }),
    signRaw: (msg) => crypto.sign(null, Buffer.from(msg), kp.privateKey).toString('base64url'),
  };
}
const READY = { ignition: true, coherence: true, scalars: [{ value: 0.9 }], n: 4, agree: 4 };
const req = (gate, extra = {}) => gate.startTap({ action: 'write report', tool: 'file_write', agentId: 'agent-a', ...READY, ...extra }).gate;

// ─── Legacy mode ─────────────────────────────────────────────────────────────
console.log('\nNo approver provisioned (legacy)');
t('approval works but is labelled self-signed, not human-bound', () => {
  const { gate } = fresh();
  const g = req(gate);
  assert.strictEqual(g.approverRequired, false);
  const r = gate.tap(g.id, { agentId: 'agent-a' });
  assert.strictEqual(r.A, 1); assert.strictEqual(r.attestation.selfSigned, true); assert.strictEqual(r.humanBound, false);
  assert.strictEqual(r.tierElevation, null, 'a self-signed tap must not claim a human warrant');
});
t('KASBAH_REQUIRE_ATTESTED_TAP=1 with no approver fails closed', () => {
  const { gate } = fresh();
  process.env.KASBAH_REQUIRE_ATTESTED_TAP = '1';
  try {
    const g = req(gate);
    const r = gate.tap(g.id, { agentId: 'agent-a' });
    assert.strictEqual(r.A, 0); assert.ok(r.attestationRequired);
  } finally { delete process.env.KASBAH_REQUIRE_ATTESTED_TAP; }
});

// ─── Provisioning ────────────────────────────────────────────────────────────
console.log('\nProvisioning approver keys');
t('first key is accepted; the same key again is idempotent', () => {
  const { gate } = fresh(); const a = approver();
  const r = gate.provisionApprover({ agentId: '*', pubkey: a.pubkey, kind: 'desktop' });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.firstUse, true);
  assert.strictEqual(gate.provisionApprover({ agentId: '*', pubkey: a.pubkey, kind: 'desktop' }).alreadyRegistered, true);
});
t('a second key without proof is refused (an agent cannot add its own approver)', () => {
  const { gate } = fresh(); const a = approver(), evil = approver();
  gate.provisionApprover({ agentId: '*', pubkey: a.pubkey, kind: 'desktop' });
  assert.strictEqual(gate.provisionApprover({ agentId: '*', pubkey: evil.pubkey, kind: 'desktop' }).ok, false);
  assert.strictEqual(gate.provisionApprover({ agentId: 'agent-a', pubkey: evil.pubkey, kind: 'hw-stone' }).ok, false, 'per-agent scope is covered by the global key');
});
t('a global key cannot be slipped in over an existing per-agent key', () => {
  const { gate } = fresh(); const a = approver(), evil = approver();
  gate.provisionApprover({ agentId: 'agent-a', pubkey: a.pubkey, kind: 'hw-stone' });
  assert.strictEqual(gate.provisionApprover({ agentId: '*', pubkey: evil.pubkey, kind: 'desktop' }).ok, false);
});
t('a second key with a self-signed or stale proof is refused; a valid proof is accepted', () => {
  const { gate } = fresh(); const a = approver(), b = approver();
  const first = gate.provisionApprover({ agentId: '*', pubkey: a.pubkey, kind: 'desktop' });
  const ts = Date.now();
  const canon = gate.provisionCanonical({ scope: '*', pubkey: b.pubkey, kind: 'hw-stone', ts });
  assert.strictEqual(gate.provisionApprover({ agentId: '*', pubkey: b.pubkey, kind: 'hw-stone', proof: { keyId: first.keyId, ts, signature: b.signRaw(canon) } }).ok, false, 'signed by the new key itself');
  const old = ts - 10 * 60 * 1000;
  assert.strictEqual(gate.provisionApprover({ agentId: '*', pubkey: b.pubkey, kind: 'hw-stone', proof: { keyId: first.keyId, ts: old, signature: a.signRaw(gate.provisionCanonical({ scope: '*', pubkey: b.pubkey, kind: 'hw-stone', ts: old })) } }).ok, false, 'stale proof');
  assert.strictEqual(gate.provisionApprover({ agentId: '*', pubkey: b.pubkey, kind: 'hw-stone', proof: { keyId: first.keyId, ts, signature: a.signRaw(canon) } }).ok, true);
});
t('junk keys and unknown kinds are refused', () => {
  const { gate } = fresh();
  assert.strictEqual(gate.provisionApprover({ pubkey: 'not-a-key', kind: 'desktop' }).ok, false);
  assert.strictEqual(gate.provisionApprover({ pubkey: approver().pubkey, kind: 'soft-stone' }).ok, false);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  assert.strictEqual(gate.provisionApprover({ pubkey: rsa, kind: 'desktop' }).ok, false, 'non-Ed25519 key');
});

// ─── Approval requires the approver ──────────────────────────────────────────
console.log('\nApproval once an approver exists');
function armed() {
  const ctx = fresh(); const a = approver();
  ctx.gate.provisionApprover({ agentId: '*', pubkey: a.pubkey, kind: 'desktop' });
  return { ...ctx, a };
}
t('an unsigned tap is refused and the request stays pending', () => {
  const { gate } = armed(); const g = req(gate);
  const r = gate.tap(g.id, { agentId: 'agent-a' });
  assert.strictEqual(r.A, 0); assert.ok(r.attestationRequired);
  assert.ok(gate.pending().some((p) => p.id === g.id), 'still pending for the real approver');
});
t('a correctly signed tap is approved, human-bound, and yields a ticket', () => {
  const { gate, a } = armed(); const g = req(gate);
  const r = gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) });
  assert.strictEqual(r.A, 1); assert.strictEqual(r.humanBound, true); assert.ok(r.ticket);
  assert.strictEqual(r.attestation.selfSigned, undefined);
});
t('a signature from the wrong key is refused', () => {
  const { gate } = armed(); const evil = approver(); const g = req(gate);
  assert.strictEqual(gate.tap(g.id, { agentId: 'agent-a', attestation: evil.sign(gate, g.challenge, 1) }).A, 0);
});
t('a signature over a different request cannot approve this one', () => {
  const { gate, a } = armed(); const g1 = req(gate), g2 = req(gate);
  assert.notStrictEqual(g1.challenge, g2.challenge);
  assert.strictEqual(gate.tap(g2.id, { agentId: 'agent-a', attestation: a.sign(gate, g1.challenge, a.next()) }).A, 0);
});
t('identical actions get different challenges (fresh nonce each time)', () => {
  const { gate } = armed();
  assert.notStrictEqual(req(gate).challenge, req(gate).challenge);
});
t('the challenge binds the arguments: same action, different args, different challenge hash', () => {
  const { gate } = armed();
  const g1 = req(gate, { args: { path: '/tmp/a' } }), g2 = req(gate, { args: { path: '/etc/passwd' } });
  assert.notStrictEqual(g1.argsHash, g2.argsHash);
  assert.ok(g1.challenge.includes(g1.argsHash));
});
t('replaying a used attestation on a new request is refused', () => {
  const { gate, a } = armed(); const g1 = req(gate);
  const att = a.sign(gate, g1.challenge, a.next());
  assert.strictEqual(gate.tap(g1.id, { agentId: 'agent-a', attestation: att }).A, 1);
  const g2 = req(gate);
  assert.strictEqual(gate.tap(g2.id, { agentId: 'agent-a', attestation: att }).A, 0);
});
t('the counter must strictly increase: equal or lower is refused', () => {
  const { gate, a } = armed();
  const g1 = req(gate); assert.strictEqual(gate.tap(g1.id, { agentId: 'agent-a', attestation: a.sign(gate, g1.challenge, 10) }).A, 1);
  const g2 = req(gate); assert.match(gate.tap(g2.id, { agentId: 'agent-a', attestation: a.sign(gate, g2.challenge, 10) }).reason, /STALE_COUNTER/);
  assert.match(gate.tap(g2.id, { agentId: 'agent-a', attestation: a.sign(gate, g2.challenge, 3) }).reason, /STALE_COUNTER/);
  assert.strictEqual(gate.tap(g2.id, { agentId: 'agent-a', attestation: a.sign(gate, g2.challenge, 11) }).A, 1);
});
t('the counter is covered by the signature: changing it breaks the signature', () => {
  const { gate, a } = armed(); const g = req(gate);
  const att = a.sign(gate, g.challenge, 5); att.counter = 6;
  assert.match(gate.tap(g.id, { agentId: 'agent-a', attestation: att }).reason, /SIGNATURE_MISMATCH/);
});
t('malformed attestations are refused without throwing', () => {
  const { gate, a } = armed();
  const bads = [null, 'yes', 42, {}, { signer: 'desktop' }, { signer: 'desktop', signature: 'x', counter: 1 },
    { signer: 'soft-stone', signature: 'A'.repeat(86), counter: 1 }, { signer: 'desktop', signature: 'A'.repeat(86), counter: -1 },
    { signer: 'desktop', signature: 'A'.repeat(86), counter: 1.5 }, { signer: 'desktop', signature: 'A'.repeat(86), counter: '2' },
    { signer: 'desktop', signature: 'A'.repeat(5000), counter: 1 }, { signer: 'hw-stone', hardware: true, counter: 9 }];
  for (const b of bads) {
    const g = req(gate);
    const r = gate.tap(g.id, { agentId: 'agent-a', attestation: b });
    assert.strictEqual(r.A, 0, JSON.stringify(b));
  }
  const g = req(gate);
  assert.strictEqual(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) }).A, 1, 'a good one still works afterwards');
});
t('claiming the wrong signer kind for a real key is refused', () => {
  const { gate, a } = armed(); const g = req(gate);
  assert.strictEqual(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next(), 'hw-stone') }).A, 0);
});
t('five bad attestations burn the request; a good one after that is too late', () => {
  const { gate, a } = armed(); const evil = approver(); const g = req(gate);
  let last;
  for (let i = 1; i <= gate.MAX_BAD_ATTESTATIONS; i++) last = gate.tap(g.id, { agentId: 'agent-a', attestation: evil.sign(gate, g.challenge, i) });
  assert.match(last.reason, /too many invalid attestations/);
  assert.ok(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) }).error);
});
t('a valid signature cannot rescue a request the gate itself rejected', () => {
  const { gate, a } = armed();
  const g = gate.startTap({ action: 'write', tool: 'file_write', agentId: 'agent-a', ignition: false, coherence: true, scalars: [{ value: 0.9 }], n: 4, agree: 4 }).gate;
  const r = gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) });
  assert.strictEqual(r.A, 0); assert.strictEqual(r.ticket, null);
});
t('a hard veto (one scalar at zero) cannot be approved', () => {
  const { gate, a } = armed();
  const g = gate.startTap({ action: 'write', tool: 'file_write', agentId: 'agent-a', ignition: true, coherence: true, scalars: [{ value: 0.99 }, { value: 0 }], n: 4, agree: 4 }).gate;
  assert.strictEqual(g.veto, true);
  assert.strictEqual(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) }).A, 0);
});
t('cross-agent: a tap or attestation naming another agent is refused', () => {
  const { gate, a } = armed(); const g = req(gate);
  assert.match(gate.tap(g.id, { agentId: 'agent-b', attestation: a.sign(gate, g.challenge, a.next()) }).reason, /cross-agent/);
  const att = a.sign(gate, g.challenge, a.next()); att.agentId = 'agent-b';
  assert.match(gate.tap(g.id, { agentId: 'agent-a', attestation: att }).reason, /CROSS_AGENT/);
});
t('a per-agent approver cannot approve a different agent', () => {
  const { gate } = fresh(); const a = approver();
  gate.provisionApprover({ agentId: 'agent-a', pubkey: a.pubkey, kind: 'hw-stone' });
  const gb = gate.startTap({ action: 'write', tool: 'file_write', agentId: 'agent-b', ...READY }).gate;
  assert.strictEqual(gb.approverRequired, false, 'agent-b has no approver of its own');
  const ga = req(gate);
  assert.strictEqual(gate.tap(ga.id, { agentId: 'agent-a', attestation: a.sign(gate, ga.challenge, a.next(), 'hw-stone') }).A, 1);
});
t('denying needs no signature, and a denied request cannot then be approved', () => {
  const { gate, a } = armed(); const g = req(gate);
  assert.strictEqual(gate.deny(g.id, { agentId: 'agent-a' }).status, 'denied-human');
  assert.ok(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) }).error);
});
t('an approved request cannot be approved twice', () => {
  const { gate, a } = armed(); const g = req(gate);
  assert.strictEqual(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) }).A, 1);
  assert.ok(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) }).error);
});
t('an expired request is refused even with a valid signature', () => {
  const { gate, a } = armed(); const g = req(gate);
  const realNow = Date.now;
  try { Date.now = () => realNow() + gate.DESKTOP_GRACE_MS + 1000;
    assert.ok(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) }).error);
  } finally { Date.now = realNow; }
});
t('gestures cannot approve once a signed approval is required', () => {
  const { gate } = armed(); const g = req(gate);
  assert.strictEqual(gate.gesture('agent-a', 'double-tap').ok, false);
  assert.ok(gate.pending().some((p) => p.id === g.id), 'and the gesture did not burn the request');
  assert.strictEqual(gate.gesture('agent-a', 'hold-to-deny').denied, 1, 'gestures can still deny');
});
t('a desktop approver gets a human-length window; hardware-only keeps the short one', () => {
  const d = armed(); assert.strictEqual(req(d.gate).graceMs, d.gate.DESKTOP_GRACE_MS);
  const { gate } = fresh(); gate.provisionApprover({ agentId: '*', pubkey: approver().pubkey, kind: 'hw-stone' });
  assert.strictEqual(req(gate).graceMs, gate.GRACE_MS);
});

// ─── Human-decides requests ──────────────────────────────────────────────────
console.log('\nPlain "ask the person" requests (no machine evidence)');
const plain = (gate, extra = {}) => gate.startTap({ action: 'delete the build folder', tool: 'shell', agentId: 'agent-a', args: { command: 'rm -rf ./build' }, mode: 'human', ...extra }).gate;
t('with an approver, a plain request is approvable and a signed tap approves it', () => {
  const { gate, a } = armed(); const g = plain(gate);
  assert.strictEqual(g.mode, 'human'); assert.strictEqual(g.gateReady, true);
  const r = gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) });
  assert.strictEqual(r.A, 1); assert.strictEqual(r.humanBound, true);
});
t('without an approver, a plain request can never be approved (no self-signed fallback)', () => {
  const { gate } = fresh(); const g = plain(gate);
  assert.strictEqual(g.gateReady, false); assert.ok(/no approver/.test(g.notReadyReason));
  const r = gate.tap(g.id, { agentId: 'agent-a' });
  assert.strictEqual(r.A, 0); assert.strictEqual(r.ticket, null);
});
t('a plain request still needs the signature: unsigned and wrong-key taps are refused', () => {
  const { gate } = armed(); const g = plain(gate);
  assert.strictEqual(gate.tap(g.id, { agentId: 'agent-a' }).A, 0);
  assert.strictEqual(gate.tap(g.id, { agentId: 'agent-a', attestation: approver().sign(gate, g.challenge, 1) }).A, 0);
});
t('a plain kill request aimed at another agent stays unapprovable', () => {
  const { gate, a } = armed();
  const g = plain(gate, { action: 'pkill agent', targetAgent: 'agent-b' });
  assert.strictEqual(g.gateReady, false);
  assert.strictEqual(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) }).A, 0);
});
t('the advice shown to the person is part of what they sign', () => {
  const { gate } = armed();
  const g = plain(gate, { advice: "Kasbah's own check: DENY (risk 90%)" });
  assert.ok(JSON.parse(g.challenge).advice.includes('DENY'));
  assert.notStrictEqual(g.challenge, plain(gate, { advice: 'something else' }).challenge.replace(/"nonce":"[0-9a-f]+"/, ''));
});
t('the default mode is unchanged: no evidence means not ready', () => {
  const { gate } = armed();
  const g = gate.startTap({ action: 'x', tool: 'file_write', agentId: 'agent-a' }).gate;
  assert.strictEqual(g.mode, 'evidence'); assert.strictEqual(g.gateReady, false);
});

// ─── Device path ─────────────────────────────────────────────────────────────
console.log('\nDevice attestation intake');
t('a bare { signer: "hw-stone" } claim approves nothing', () => {
  const { gate, phys } = fresh(); const g = req(gate);
  const r = phys.acceptAttestation({ tapId: g.id, attestation: { signer: 'hw-stone', counter: 1, hardware: true } });
  assert.strictEqual(r.ok, false);
  assert.ok(gate.pending().some((p) => p.id === g.id));
});
t('pairing a device provisions its key, and its signed attestation approves', () => {
  const { gate, phys } = fresh(); const dev = approver();
  const pr = phys.pairDevice('agent-a', { productId: 'stone-pendant', pubkey: dev.pubkey });
  assert.strictEqual(pr.ok, true); assert.strictEqual(pr.approver.firstUse, true);
  const g = req(gate);
  assert.strictEqual(g.graceMs, gate.GRACE_MS);
  const r = phys.acceptAttestation({ tapId: g.id, agentId: 'agent-a', attestation: dev.sign(gate, g.challenge, dev.next(), 'hw-stone') });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.attestation.hardware, true);
});
t('a second device cannot pair its key without proof from the first', () => {
  const { phys } = fresh(); const dev = approver(), evil = approver();
  phys.pairDevice('agent-a', { productId: 'stone-pendant', pubkey: dev.pubkey });
  assert.strictEqual(phys.pairDevice('agent-a', { productId: 'stone-ring', pubkey: evil.pubkey }).ok, false);
});
t('device attestation for another agent, or with a forged signature, is refused', () => {
  const { gate, phys } = fresh(); const dev = approver(), evil = approver();
  phys.pairDevice('agent-a', { productId: 'stone-pendant', pubkey: dev.pubkey });
  const g = req(gate);
  assert.strictEqual(phys.acceptAttestation({ tapId: g.id, agentId: 'agent-b', attestation: dev.sign(gate, g.challenge, dev.next(), 'hw-stone') }).ok, false);
  assert.strictEqual(phys.acceptAttestation({ tapId: g.id, attestation: evil.sign(gate, g.challenge, 1, 'hw-stone') }).ok, false);
  assert.strictEqual(phys.acceptAttestation({ tapId: 'tap_nope', attestation: dev.sign(gate, g.challenge, dev.next(), 'hw-stone') }).ok, false);
  assert.strictEqual(phys.acceptAttestation({}).ok, false);
});

// ─── Persistence ─────────────────────────────────────────────────────────────
console.log('\nAcross restarts');
t('the approver registry and its counter survive a restart', () => {
  const { gate, a, dir } = armed();
  const g1 = req(gate); const used = a.sign(gate, g1.challenge, 7);
  assert.strictEqual(gate.tap(g1.id, { agentId: 'agent-a', attestation: used }).A, 1);
  const { gate: g2 } = reload(dir);
  assert.strictEqual(g2.approverRequired('agent-a'), true);
  const r = req(g2);
  assert.strictEqual(g2.tap(r.id, { agentId: 'agent-a' }).A, 0, 'unsigned still refused after restart');
  assert.match(g2.tap(r.id, { agentId: 'agent-a', attestation: a.sign(g2, r.challenge, 7) }).reason, /STALE_COUNTER/, 'old counter still refused after restart');
  assert.strictEqual(g2.tap(r.id, { agentId: 'agent-a', attestation: a.sign(g2, r.challenge, 8) }).A, 1);
});
t('a corrupted registry fails closed instead of reopening the self-signed path', () => {
  const { gate, dir } = armed();
  fs.writeFileSync(path.join(dir, 'consent-approvers.json'), '{ not json');
  const { gate: g2 } = reload(dir);
  assert.strictEqual(g2.approverRequired('agent-a'), true);
  const r = req(g2);
  assert.strictEqual(g2.tap(r.id, { agentId: 'agent-a' }).A, 0);
  assert.strictEqual(g2.provisionApprover({ pubkey: approver().pubkey, kind: 'desktop' }).ok, false, 'and cannot be re-seeded by whoever asks first');
  void gate;
});
t('registry and key files are private to the user (mode 0600)', () => {
  const { dir } = armed();
  assert.strictEqual(fs.statSync(path.join(dir, 'consent-approvers.json')).mode & 0o077, 0);
});
t('agent ids that sanitise to the same name do not share a key file', () => {
  const { gate } = fresh();
  const s1 = gate.stoneSign('m', 'a/b'), s2 = gate.stoneSign('m', 'a_b');
  assert.notStrictEqual(s1.signature, s2.signature);
  assert.strictEqual(gate.stoneVerify('m', s1, 'a/b'), true);
  assert.strictEqual(gate.stoneVerify('m', { ...s1, agentId: 'a_b' }, 'a_b'), false);
});

// ─── Lockdown ────────────────────────────────────────────────────────────────
console.log('\nLockdown');
t('anyone can turn lockdown on; lifting it needs the approver', () => {
  const { gate, a } = armed();
  assert.strictEqual(gate.setLockdown(true, 'x').lockdown, true);
  assert.strictEqual(gate.setLockdown(false, 'x').ok, false);
  assert.strictEqual(gate.setLockdown(false, 'x', { trusted: true }).ok, false, 'an admin flag is not enough once an approver exists');
  assert.strictEqual(gate.lockdown(), true);
  const ts = Date.now(), c = 500;
  const proof = { ts, counter: c, signature: a.signRaw(gate.opCanonical('lockdown-off', ts, c)) };
  assert.strictEqual(gate.setLockdown(false, 'x', { proof }).ok, true);
  assert.strictEqual(gate.lockdown(), false);
  gate.setLockdown(true, 'x');
  assert.strictEqual(gate.setLockdown(false, 'x', { proof }).ok, false, 'the same proof cannot be replayed');
});
t('a proof signed for another operation does not lift lockdown', () => {
  const { gate, a } = armed(); gate.setLockdown(true, 'x');
  const ts = Date.now();
  assert.strictEqual(gate.setLockdown(false, 'x', { proof: { ts, counter: 900, signature: a.signRaw(gate.opCanonical('something-else', ts, 900)) } }).ok, false);
});
t('without approvers, only a trusted caller can lift lockdown', () => {
  const { gate } = fresh(); gate.setLockdown(true, 'x');
  assert.strictEqual(gate.setLockdown(false, 'x').ok, false);
  assert.strictEqual(gate.setLockdown(false, 'x', { trusted: true }).ok, true);
});
t('lockdown survives a restart, and unreadable lockdown state means locked', () => {
  const { gate, dir } = fresh(); gate.setLockdown(true, 'x');
  assert.strictEqual(reload(dir).gate.lockdown(), true);
  fs.writeFileSync(path.join(dir, 'consent-lockdown.json'), 'garbage');
  assert.strictEqual(reload(dir).gate.lockdown(), true);
});

// ─── Tickets ─────────────────────────────────────────────────────────────────
console.log('\nExecution tickets');
t('a ticket works once, for its own tool and arguments only', () => {
  const { gate } = fresh();
  const tk = gate.issueTicket('agent-a', 'file_write', { path: 'a' });
  assert.strictEqual(gate.verifyTicket('agent-a', tk, 'file_write', { path: 'b' }).reason, 'TOOL_MISMATCH');
  assert.strictEqual(gate.verifyTicket('agent-a', tk, 'shell', { path: 'a' }).reason, 'TOOL_MISMATCH');
  assert.strictEqual(gate.verifyTicket('agent-a', tk, 'file_write', { path: 'a' }).ok, true);
  assert.strictEqual(gate.verifyTicket('agent-a', tk, 'file_write', { path: 'a' }).reason, 'REPLAY');
});
t('a ticket is refused when expired, forged, or used by another agent', () => {
  const { gate } = fresh();
  const tk = gate.issueTicket('agent-a', 't', {});
  assert.strictEqual(gate.verifyTicket('agent-a', { ...tk, mac: '0'.repeat(64) }, 't', {}).reason, 'MAC_FAIL');
  assert.strictEqual(gate.verifyTicket('agent-a', { ...tk, expiresMs: tk.expiresMs + 60000 }, 't', {}).reason, 'MAC_FAIL', 'extending the expiry breaks the MAC');
  assert.notStrictEqual(gate.verifyTicket('agent-b', tk, 't', {}).ok, true);
  assert.strictEqual(gate.verifyTicket('agent-a', {}, 't', {}).reason, 'TICKET_MISSING');
  const realNow = Date.now;
  try { Date.now = () => realNow() + gate.TICKET_TTL_MS + 50; assert.strictEqual(gate.verifyTicket('agent-a', tk, 't', {}).reason, 'EXPIRED'); }
  finally { Date.now = realNow; }
});

// ─── Kill switch ─────────────────────────────────────────────────────────────
console.log('\nKill switch');
t('a kill request aimed at another agent is never ready and cannot be approved', () => {
  const { gate, a } = armed();
  const g = gate.startTap({ action: 'pkill agent', tool: 'shell', agentId: 'agent-a', targetAgent: 'agent-b', ...READY }).gate;
  assert.strictEqual(g.gateReady, false); assert.strictEqual(g.status, 'denied-killswitch');
  assert.strictEqual(gate.tap(g.id, { agentId: 'agent-a', attestation: a.sign(gate, g.challenge, a.next()) }).A, 0);
});

console.log(`\n${pass} passed · ${fail} failed`);
process.exit(fail ? 1 : 0);
