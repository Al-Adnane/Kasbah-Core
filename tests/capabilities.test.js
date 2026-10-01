'use strict';

/**
 * capabilities.test.js — unit tests for the seven previously-missing
 * capability packages, exercised directly (no server needed). Run:
 *   node tests/capabilities.test.js
 */

const assert = require('assert');
let pass = 0, fail = 0;
function t(name, fn) {
  return Promise.resolve().then(fn).then(
    () => { pass++; console.log('  ✓ ' + name); },
    (e) => { fail++; console.log('  ✗ ' + name + '\n      ' + e.message); }
  );
}

const P = (rel) => require('../packages/' + rel);

(async () => {
  console.log('\nZK proofs (ristretto255 sigma-protocols)');
  {
    const { ZKProofSystem } = P('crypto-utils/src/zk-proofs-full.js');
    const zk = new ZKProofSystem();
    const pub = { verdict: 'DENY', policy: 'v1' };
    const proof = zk.generateDetectionProof({ privateInputs: { value: 77 }, publicInputs: pub });
    await t('PoK verifies with matching public inputs', () => assert.strictEqual(zk.verifyProof(proof, pub).isValid, true));
    await t('PoK rejects mismatched public inputs', () => assert.strictEqual(zk.verifyProof(proof, { verdict: 'ALLOW' }).isValid, false));
    await t('PoK rejects tampered response', () => assert.strictEqual(zk.verifyProof({ ...proof, z1: proof.z2 }, pub).isValid, false));
    const rp = zk.generateRangeProof(1234567, 32);
    await t('range proof verifies', () => assert.strictEqual(zk.verifyRangeProof(rp).isValid, true));
    await t('range proof rejects tampered bit', () => { const b = JSON.parse(JSON.stringify(rp)); b.bitProofs[3].z0 = b.bitProofs[3].z1; assert.strictEqual(zk.verifyRangeProof(b).isValid, false); });
    await t('cannot prove out-of-range value', () => assert.throws(() => zk.generateRangeProof(300, 8)));
  }

  console.log('\nagent-governance (identity + GCMDP + maqasid)');
  {
    const { AgentIdentity, GCMDP, evaluateMaqasid } = P('agent-governance/src/index.js');
    const id = AgentIdentity.generate('agent-1', { role: 'researcher' });
    const cert = id.createCertificate();
    await t('identity certificate verifies', () => assert.strictEqual(AgentIdentity.verifyCertificate(cert).valid, true));
    await t('tampered certificate rejected', () => { const c = { ...cert, agentId: 'evil' }; assert.strictEqual(AgentIdentity.verifyCertificate(c).valid, false); });
    const g = new GCMDP();
    await t('GCMDP denies over-budget action', () => assert.strictEqual(g.evaluate({ type: 'spend', cost: 100 }, { spent: 50 }, { budget: 120 }).decision, 'DENY'));
    await t('GCMDP allows within constraints', () => assert.strictEqual(g.evaluate({ type: 'read', cost: 1, risk: 0.1 }, {}, { budget: 100, maxRisk: 0.5 }).decision, 'ALLOW'));
    await t('GCMDP forbidden action denied', () => assert.strictEqual(g.evaluate('delete_all', {}, { forbiddenActions: ['delete_all'] }).decision, 'DENY'));
    await t('maqasid flags violence', () => assert.notStrictEqual(evaluateMaqasid('how to kill someone and poison them').grade, 'COMPLIANT'));
    await t('maqasid passes benign text', () => assert.strictEqual(evaluateMaqasid('please help me write a thank-you note').grade, 'COMPLIANT'));
  }

  console.log('\nnomos-engine (consensus + debate)');
  {
    const { createDefaultEngine, createDebateEngine } = P('nomos-engine/src/index.js');
    const e = createDefaultEngine();
    await t('rejects clearly harmful content', () => { const r = e.evaluate('deceive and steal from vulnerable elderly people without their consent'); assert.ok(['REJECTED', 'CONTESTED'].includes(r.verdict), r.verdict); });
    await t('approves benign content', () => { const r = e.evaluate('help educate children with compassion and honesty'); assert.strictEqual(r.verdict, 'APPROVED'); });
    await t('reports conflict as stddev', () => { const r = e.evaluate('kill the process to save the server'); assert.ok(typeof r.stdDev === 'number'); });
    const d = createDebateEngine();
    await t('debate returns a ruling', () => { const r = d.debate('harm reduction program', 'CONTESTED', 'this protects life and helps vulnerable people'); assert.ok(typeof r.overturned === 'boolean' && r.ruling); });
  }

  console.log('\nadvanced-security (shamir + consent + threshold)');
  {
    const { ShamirSecretSharing, ConsentManager, DynamicThreshold } = P('advanced-security/src/index.js');
    const secret = Buffer.from('correct horse battery').toString('hex');
    const { shares } = ShamirSecretSharing.generate(secret, 3, 5);
    await t('any 3 of 5 shares reconstruct', () => assert.strictEqual(ShamirSecretSharing.combine([shares[0], shares[2], shares[4]]), secret));
    await t('a different triple reconstructs the same secret', () => assert.strictEqual(ShamirSecretSharing.combine([shares[1], shares[3], shares[4]]), secret));
    await t('2 shares (below threshold) do NOT reconstruct', () => assert.notStrictEqual(ShamirSecretSharing.combine([shares[0], shares[1]]), secret));
    const cm = new ConsentManager();
    cm.grant('user@x.com', 'analytics', { dataTypes: ['email'] });
    await t('consent granted for covered type', () => assert.strictEqual(cm.check('user@x.com', 'analytics', 'email').granted, true));
    await t('consent denied for uncovered type', () => assert.strictEqual(cm.check('user@x.com', 'analytics', 'ssn').granted, false));
    await t('consent revoke works', () => { cm.revoke('user@x.com', 'analytics'); assert.strictEqual(cm.check('user@x.com', 'analytics', 'email').granted, false); });
    const dt = new DynamicThreshold({ baseThreshold: 0.5 });
    for (let i = 0; i < 20; i++) dt.record('fn', false);
    await t('threshold tightens after false negatives', () => assert.ok(dt.getThreshold().threshold < 0.5));
  }

  console.log('\nbiometric-detection (DSP forensics)');
  {
    const { rPPGDetector, VoiceCloneDetector, NeuralCodecDetector, NeuralFingerprintAnalyzer } = P('biometric-detection/src/index.js');
    // Synthetic 72bpm pulse (1.2Hz) at 30fps + noise
    const frames = Array.from({ length: 128 }, (_, i) => 128 + 8 * Math.sin(2 * Math.PI * 1.2 * i / 30) + (Math.random() - 0.5));
    await t('rPPG detects a periodic pulse', () => { const r = new rPPGDetector().detect(frames, 30); assert.strictEqual(r.pulseDetected, true); assert.ok(r.bpmEstimate > 50 && r.bpmEstimate < 100); });
    await t('rPPG finds no pulse in flat signal', () => { const r = new rPPGDetector().detect(Array.from({ length: 128 }, () => 128), 30); assert.strictEqual(r.pulseDetected, false); });
    // Pure tone = synthetic-like (over-stable pitch, no breath)
    const tone = Array.from({ length: 8192 }, (_, i) => Math.sin(2 * Math.PI * 200 * i / 16000));
    await t('voice-clone flags a pure synthetic tone', () => { const r = new VoiceCloneDetector().analyze(tone, { sampleRate: 16000 }); assert.ok(r.cloneLikelihood > 0.3, 'likelihood ' + r.cloneLikelihood); });
    // Band-limited noise = codec-like ceiling
    const lp = []; let acc = 0; for (let i = 0; i < 8192; i++) { acc = 0.9 * acc + 0.1 * (Math.random() - 0.5); lp.push(acc); }
    await t('neural-codec detector returns a verdict', () => { const r = new NeuralCodecDetector().detect(lp, { sampleRate: 16000 }); assert.ok(typeof r.codecLikelihood === 'number' && r.method); });
    // 4x4 RGB image → analyzer runs
    const px = []; for (let i = 0; i < 16; i++) px.push(100 + i, 110 + i, 120 + i);
    await t('neural-fingerprint analyzes an image', () => { const r = new NeuralFingerprintAnalyzer().analyze(px, 4, 4); assert.ok(r.verdict && typeof r.aiLikelihood === 'number'); });
  }

  console.log('\nkernel-ebpf (gating policy)');
  {
    const { KernelGatingEngine } = P('kernel-ebpf/src/kernel-gating-engine.js');
    const k = new KernelGatingEngine();
    await t('denies a dangerous syscall', () => assert.strictEqual(k.evaluate('ptrace').allowed, false));
    await t('denies reads of credential paths', () => assert.strictEqual(k.evaluate('open', { path: '/etc/shadow' }).allowed, false));
    await t('denies cloud metadata SSRF', () => assert.strictEqual(k.evaluate('connect', { address: '169.254.169.254' }).allowed, false));
    await t('allows benign operations', () => assert.strictEqual(k.evaluate('open', { path: '/tmp/data.json' }).allowed, true));
    await t('reports an honest enforcement mode', () => assert.ok(['ebpf-capable', 'policy-userspace'].includes(k.evaluate('read').mode)));
    await t('default-deny policy blocks unlisted ops', () => { const kd = new KernelGatingEngine({ defaultAction: 'deny', allowedOperations: ['read'] }); assert.strictEqual(kd.evaluate('write').allowed, false); assert.strictEqual(kd.evaluate('read').allowed, true); });
  }

  console.log('\nZK threshold-verdict proofs (the compliance moat)');
  {
    const { ZKProofSystem } = P('crypto-utils/src/zk-proofs-full.js');
    const z = new ZKProofSystem();
    await t('proves ALLOW (score < T) without revealing score', () => assert.strictEqual(z.verifyThresholdVerdict(z.proveThresholdVerdict(320, 800, true, 16)).isValid, true));
    await t('proves DENY (score >= T) without revealing score', () => assert.strictEqual(z.verifyThresholdVerdict(z.proveThresholdVerdict(920, 800, false, 16)).isValid, true));
    await t('REFUSES to prove a false verdict at generation time', () => assert.throws(() => z.proveThresholdVerdict(920, 800, true, 16)));
    await t('rejects a receipt whose public threshold was tampered', () => { const p = z.proveThresholdVerdict(320, 800, true, 16); p.threshold = 300; assert.strictEqual(z.verifyThresholdVerdict(p).isValid, false); });
    await t('score commitment is hiding (same score → different commitment)', () => assert.notStrictEqual(z.proveThresholdVerdict(320, 800, true, 16).scoreCommitment, z.proveThresholdVerdict(320, 800, true, 16).scoreCommitment));
  }

  console.log('\nZK-compliance receipts (signed + private + verifiable)');
  {
    const zkc = P('api-server/src/zk-compliance-receipt.js');
    const secret = 'REGULATED PROMPT ssn 123-45-6789';
    const rec = zkc.build({ prompt: secret, verdict: 'DENY', riskScore: 0.92 });
    await t('receipt verifies (signature + ZK) without the prompt', () => { const v = zkc.verify(rec.receipt, rec.payload); assert.ok(v.valid && v.signatureValid && v.zkValid); });
    await t('prompt is NOT present in the signed payload', () => assert.ok(!Buffer.from(rec.payload, 'base64url').toString().includes('123-45-6789')));
    await t('tampered verdict in payload is rejected', () => { const bad = Buffer.from(JSON.stringify({ ...rec.decoded, verdict: 'ALLOW' })).toString('base64url'); assert.strictEqual(zkc.verify(rec.receipt, bad).valid, false); });
    await t('input commitment opens to the real prompt in a dispute', () => assert.strictEqual(zkc.openCommitment(secret, rec.salt, rec.decoded.inputCommitment).matches, true));
    await t('input commitment does NOT open to a wrong prompt', () => assert.strictEqual(zkc.openCommitment('other', rec.salt, rec.decoded.inputCommitment).matches, false));
    await t('ALLOW receipt (score < warn threshold) verifies', () => assert.strictEqual(zkc.verify(...(() => { const a = zkc.build({ prompt: 'hi', verdict: 'ALLOW', riskScore: 0.05 }); return [a.receipt, a.payload]; })()).valid, true));
  }

  console.log(`\n${pass} passed · ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})();
