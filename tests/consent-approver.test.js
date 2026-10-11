'use strict';

/**
 * consent-approver.test.js — the desktop approver against the real consent gate.
 *
 * The approver module is driven with a fake native dialog and an in-process
 * transport that calls the same gate functions the HTTP routes call. Checks
 * that a signature exists only after an "Allow" click, that the dialog shows
 * what is actually signed, and that every failure mode ends in a denial.
 *
 * Runs in temp directories. Run: node tests/consent-approver.test.js
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const GATE = path.join(__dirname, '..', 'packages', 'api-server', 'src', 'consent-gate.js');
const { createApprover } = require(path.join(__dirname, '..', 'packages', 'desktop', 'src', 'consent-approver.js'));
delete process.env.KASBAH_REQUIRE_ATTESTED_TAP;

let pass = 0, fail = 0;
const tests = [];
const t = (name, fn) => tests.push([name, fn]);
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
const READY = { ignition: true, coherence: true, scalars: [{ value: 0.9 }], n: 4, agree: 4 };

function world({ answer = 1, tamper = null } = {}) {
  delete require.cache[GATE];
  const gate = require(GATE);
  gate.init({ dataDir: tmp('kasbah-gate-') });
  const dialogs = [];
  const sent = [];
  // Same behaviour as the routes in server.js, without the network.
  const request = async (method, url, body) => {
    sent.push({ method, url, body });
    if (method === 'POST' && url === '/v1/consent/approver') return gate.provisionApprover({ agentId: body.agentId || '*', pubkey: body.pubkey, kind: body.kind, proof: body.proof });
    if (method === 'GET' && url === '/v1/consent/pending') { const list = gate.pending(); return { pending: tamper ? list.map(tamper) : list }; }
    let m = url.match(/^\/v1\/consent\/tap\/(.+)$/);
    if (m) return gate.tap(decodeURIComponent(m[1]), { approve: body.approve !== false, agentId: body.agentId, attestation: body.attestation || null });
    m = url.match(/^\/v1\/consent\/deny\/(.+)$/);
    if (m) return gate.deny(decodeURIComponent(m[1]), { agentId: body.agentId });
    throw new Error('unexpected request ' + method + ' ' + url);
  };
  const showDialog = async (opts) => { dialogs.push(opts); if (answer instanceof Error) throw answer; return typeof answer === 'function' ? answer(opts) : answer; };
  const dir = tmp('kasbah-approver-');
  const mk = (d = dir) => createApprover({ dir: d, request, showDialog, log: { warn() {} }, pollMs: 60000 });
  return { gate, dialogs, sent, request, dir, mk, approver: mk() };
}
const ask = (gate, extra = {}) => gate.startTap({ action: 'write the quarterly report', tool: 'file_write', agentId: 'agent-a', args: { path: '/tmp/report.md' }, ...READY, ...extra });
const settle = () => new Promise((r) => setTimeout(r, 30));
async function pollAndWait(a) { await a.poll(); await settle(); await settle(); }

t('registers itself as the approver on first poll', async () => {
  const w = world();
  await w.approver.poll();
  assert.strictEqual(w.approver.status().registered, true);
  assert.strictEqual(w.gate.approverRequired('anyone'), true);
});
t('Allow in the dialog produces a signed, human-bound approval', async () => {
  const w = world({ answer: 1 });
  await w.approver.poll();
  const { gate, done } = ask(w.gate); void gate;
  await pollAndWait(w.approver);
  const r = await done;
  assert.strictEqual(r.A, 1); assert.strictEqual(r.humanBound, true); assert.strictEqual(r.attestation.signer, 'desktop');
  assert.strictEqual(w.dialogs.length, 1);
  assert.strictEqual(w.approver.status().decisions[0].outcome, 'allowed');
});
t('Deny in the dialog denies, and nothing is signed', async () => {
  const w = world({ answer: 0 });
  await w.approver.poll();
  const { done } = ask(w.gate);
  await pollAndWait(w.approver);
  const r = await done;
  assert.strictEqual(r.A, 0); assert.strictEqual(r.status, 'denied-human');
  assert.ok(!w.sent.some((s) => s.body && s.body.attestation), 'no attestation left the process');
});
t('the safe choice is the default: Deny is button 0, default and cancel', async () => {
  const w = world({ answer: 0 });
  await w.approver.poll(); ask(w.gate); await pollAndWait(w.approver);
  const d = w.dialogs[0];
  assert.deepStrictEqual(d.buttons, ['Deny', 'Allow']); assert.strictEqual(d.defaultId, 0); assert.strictEqual(d.cancelId, 0);
});
t('a dialog that fails or returns something odd denies', async () => {
  for (const answer of [new Error('window closed'), 2, -1, null, '1', true, 1.5]) { // (undefined would fall back to this helper's default)
    const w = world({ answer });
    await w.approver.poll();
    const { done } = ask(w.gate);
    await pollAndWait(w.approver);
    assert.strictEqual((await done).A, 0, 'answer=' + String(answer));
  }
});
t('no dialog, no signature: nothing is approved without a click', async () => {
  const w = world({ answer: 1 });
  await w.approver.poll();
  const { gate } = ask(w.gate);
  // An attacker calls the tap route directly, before or instead of the dialog.
  assert.strictEqual(w.gate.tap(gate.id, { agentId: 'agent-a' }).A, 0);
  assert.strictEqual(w.dialogs.length, 0);
});
t('the dialog shows what is signed, even if the loose fields were altered in transit', async () => {
  const w = world({ answer: 0, tamper: (p) => ({ ...p, action: 'read a public file', tool: 'read_file', tier: 'READ' }) });
  await w.approver.poll();
  ask(w.gate, { action: 'rm -rf ~/Documents', tool: 'shell', args: { command: 'rm -rf ~/Documents' } });
  await pollAndWait(w.approver);
  const detail = w.dialogs[0].detail;
  assert.ok(detail.includes('rm -rf ~/Documents'), 'real action shown');
  assert.ok(!detail.includes('read a public file'), 'altered text not shown');
  assert.ok(/Risk: DESTRUCTIVE/.test(detail), 'real tier shown');
});
t('an entry whose challenge does not match its id is never shown', async () => {
  let other = null;
  const w = world({ answer: 1, tamper: (p) => { if (!other) other = p; return { ...p, challenge: other.challenge }; } });
  await w.approver.poll();
  const a = ask(w.gate), b = ask(w.gate, { action: 'second' });
  await pollAndWait(w.approver);
  assert.strictEqual(w.dialogs.length, 1, 'only the entry whose challenge is its own');
  void a; void b;
});
t('arguments are shown only when they match the signed fingerprint', async () => {
  const w = world({ answer: 0, tamper: (p) => ({ ...p, argsPreview: '{"path":"/tmp/harmless.txt"}' }) });
  await w.approver.poll();
  ask(w.gate, { args: { path: '/etc/sudoers' } });
  await pollAndWait(w.approver);
  assert.ok(!w.dialogs[0].detail.includes('harmless'), 'substituted details not shown');
  assert.ok(/fingerprint [0-9a-f]{16}/.test(w.dialogs[0].detail));
});
t('control and bidirectional-override characters cannot disguise the text', async () => {
  const w = world({ answer: 0 });
  await w.approver.poll();
  ask(w.gate, { action: 'delete‮elif‬ all\u0000\u001b[2J backups' });
  await pollAndWait(w.approver);
  assert.ok(!/[\u0000-\u001f‪-‮⁦-⁩]/.test(w.dialogs[0].detail.replace(/\n/g, '')));
});
t('very long text is clipped rather than pushing the buttons off screen', async () => {
  const w = world({ answer: 0 });
  await w.approver.poll();
  ask(w.gate, { action: 'A'.repeat(20000) });
  await pollAndWait(w.approver);
  assert.ok(w.dialogs[0].detail.length < 2000);
});
t('each request is shown once, and requests the gate already rejected are not shown', async () => {
  const w = world({ answer: 0 });
  await w.approver.poll();
  ask(w.gate);
  w.gate.startTap({ action: 'x', tool: 'file_write', agentId: 'agent-a', ignition: false, coherence: true, scalars: [{ value: 0.9 }], n: 4, agree: 4 });
  await pollAndWait(w.approver); await pollAndWait(w.approver);
  assert.strictEqual(w.dialogs.length, 1);
});
t('dialogs are shown one at a time, in order', async () => {
  let open = 0, maxOpen = 0; const order = [];
  const w = world({ answer: async (o) => { open++; maxOpen = Math.max(maxOpen, open); order.push(o.detail.split('\n')[0]); await new Promise((r) => setTimeout(r, 15)); open--; return 0; } });
  await w.approver.poll();
  ask(w.gate, { action: 'first' }); ask(w.gate, { action: 'second' }); ask(w.gate, { action: 'third' });
  await w.approver.poll(); await new Promise((r) => setTimeout(r, 150));
  assert.strictEqual(maxOpen, 1); assert.deepStrictEqual(order, ['What: first', 'What: second', 'What: third']);
});
t('a request that expires while the dialog is open is not signed', async () => {
  const realNow = Date.now; let skew = 0;
  const w = world({ answer: async () => { skew = 10 * 60 * 1000; return 1; } });
  const a = createApprover({ dir: w.dir, request: w.request, showDialog: async (o) => { w.dialogs.push(o); skew = 10 * 60 * 1000; return 1; }, log: { warn() {} }, now: () => realNow() + skew });
  await a.poll();
  ask(w.gate);
  await pollAndWait(a);
  assert.ok(!w.sent.some((s) => s.body && s.body.attestation), 'no signature for an expired request');
  assert.strictEqual(a.status().decisions[0].outcome, 'expired');
});
t('the key and counter persist; the counter never repeats across restarts', async () => {
  const w = world();
  const k1 = w.approver._keys().keyId; const c1 = w.approver._nextCounter(); const c2 = w.approver._nextCounter();
  const again = w.mk();
  assert.strictEqual(again._keys().keyId, k1);
  const c3 = again._nextCounter();
  assert.ok(c2 > c1 && c3 > c2);
});
t('a lost counter file still yields a higher counter than before', async () => {
  const w = world();
  const before = w.approver._nextCounter();
  fs.unlinkSync(path.join(w.dir, 'consent-approver-counter.json'));
  await new Promise((r) => setTimeout(r, 3));
  assert.ok(w.mk()._nextCounter() > before);
});
t('a damaged key file is an error, not a silent new identity', async () => {
  const w = world();
  w.approver._keys();
  fs.writeFileSync(path.join(w.dir, 'consent-approver-key.json'), '{ broken');
  assert.throws(() => w.mk()._keys(), /could not read the approver key/);
});
t('key and counter files are private to the user (mode 0600)', async () => {
  const w = world(); w.approver._keys(); w.approver._nextCounter();
  for (const f of ['consent-approver-key.json', 'consent-approver-counter.json']) assert.strictEqual(fs.statSync(path.join(w.dir, f)).mode & 0o077, 0, f);
});
t('a second machine cannot register itself over the first approver', async () => {
  const w = world();
  await w.approver.poll();
  const intruder = w.mk(tmp('kasbah-intruder-'));
  await intruder.poll();
  assert.strictEqual(intruder.status().registered, false);
  assert.ok(/registered approver|already exists/.test(intruder.status().error));
});
t('lifting lockdown needs its own confirmation and a fresh signed proof', async () => {
  const w = world({ answer: 1 });
  await w.approver.poll();
  w.gate.setLockdown(true, 'test');
  const proof = await w.approver.signOp('lockdown-off', { message: 'Lift lockdown?', detail: '' });
  assert.strictEqual(w.gate.setLockdown(false, 'test', { proof }).ok, true);
  w.gate.setLockdown(true, 'test');
  assert.strictEqual(w.gate.setLockdown(false, 'test', { proof }).ok, false, 'replay refused');
  const w2 = world({ answer: 0 });
  assert.strictEqual(await w2.approver.signOp('lockdown-off', { message: 'x', detail: '' }), null, 'Cancel signs nothing');
});
t('the approver exposes no method that signs without a dialog', async () => {
  const w = world();
  const names = Object.keys(w.approver).filter((k) => !k.startsWith('_'));
  assert.deepStrictEqual(names.sort(), ['describe', 'poll', 'register', 'signOp', 'start', 'status', 'stop']);
  assert.strictEqual(JSON.stringify(w.approver.status()).includes('privateKey'), false);
});

(async () => {
  console.log('\nDesktop approver against the consent gate');
  for (const [name, fn] of tests) {
    try { await fn(); pass++; console.log('  ✓ ' + name); }
    catch (e) { fail++; console.log('  ✗ ' + name + '\n      ' + String(e.message).split('\n')[0]); }
  }
  console.log(`\n${pass} passed · ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
