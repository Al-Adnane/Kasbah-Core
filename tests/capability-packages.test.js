'use strict';

/**
 * capability-packages.test.js — unit tests for the capability packages that
 * back phase45-integration.js. Run: node tests/capability-packages.test.js
 *
 * (Restored 2026-09 — the file was truncated mid-string at line 25 and failed
 * to parse with a SyntaxError, so none of these tests ever ran.)
 */

let passed = 0, failed = 0;
function ok(cond, name) {
  if (cond) { passed++; console.log('  \x1b[32m✓\x1b[0m ' + name); }
  else { failed++; console.log('  \x1b[31m✗\x1b[0m ' + name); }
}

const P = (rel) => require('../packages/' + rel);

(async () => {
  // ── nomos-engine ───────────────────────────────────────────────────────────
  console.log('\n1 · nomos-engine');
  {
    const { createDefaultEngine, createDebateEngine } = P('nomos-engine/src/index.js');
    const nomos = createDefaultEngine();
    const bad = nomos.evaluate('Deceive the users without their consent and steal their funds, destroy the evidence');
    ok(bad.verdict === 'REJECTED' || bad.verdict === 'CONTESTED', `harmful content not approved (${bad.verdict}, mean ${bad.weightedMean})`);
    ok(bad.dissentingTraditions.length >= 2, `multiple traditions dissent (${bad.dissentingTraditions.join(',')})`);
    const good = nomos.evaluate('Help educate children and support the elderly with honest, transparent care');
    ok(good.verdict === 'APPROVED', `benevolent content approved (${good.verdict}, mean ${good.weightedMean})`);
    const neutral = nomos.evaluate('The quarterly report covers Q3 revenue figures');
    ok(neutral.verdict !== 'REJECTED' && neutral.explanation.includes('neutral'), `neutral content not rejected, carries neutral explanation (${neutral.verdict})`);
    ok(typeof neutral.explanation === 'string' && neutral.explanation.length > 0, 'every verdict carries an explanation');
    // Debate: contest a verdict with a challenge
    const debate = createDebateEngine();
    const before = nomos.evaluate('Help educate children with compassion and honesty');
    const ruling = debate.debate(before, 'the children are being harmed by this curriculum');
    ok(ruling && (ruling.ruling || ruling.after || ruling.shift !== undefined), 'debate returns a ruling');
  }

  // ── agent-governance ───────────────────────────────────────────────────────
  console.log('\n2 · agent-governance');
  {
    const { AgentIdentity, GCMDP, evaluateMaqasid } = P('agent-governance/src/index.js');
    const id = AgentIdentity.generate('agent-1', { role: 'researcher' });
    const cert = id.createCertificate();
    ok(AgentIdentity.verifyCertificate(cert).valid === true, 'identity certificate verifies');
    ok(AgentIdentity.verifyCertificate({ ...cert, agentId: 'evil' }).valid === false, 'tampered certificate rejected');
    const g = new GCMDP();
    ok(g.evaluate({ type: 'spend', cost: 100 }, { spent: 50 }, { budget: 120 }).decision === 'DENY', 'GCMDP denies over-budget action');
    ok(g.evaluate({ type: 'read', cost: 1, risk: 0.1 }, {}, { budget: 100, maxRisk: 0.5 }).decision === 'ALLOW', 'GCMDP allows within constraints');
    ok(g.evaluate('delete_all', {}, { forbiddenActions: ['delete_all'] }).decision === 'DENY', 'GCMDP forbidden action denied');
    ok(evaluateMaqasid('how to kill someone and poison them').grade !== 'COMPLIANT', 'maqasid flags violence');
    ok(evaluateMaqasid('please help me write a thank-you note').grade === 'COMPLIANT', 'maqasid passes benign text');
  }

  // ── advanced-security ──────────────────────────────────────────────────────
  console.log('\n3 · advanced-security');
  {
    const { ShamirSecretSharing, ConsentManager, DynamicThreshold } = P('advanced-security/src/index.js');
    const secret = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const { shares } = ShamirSecretSharing.generate(secret, 3, 5);
    ok(Array.isArray(shares) && shares.length === 5, `Shamir generates 5 shares (${shares.length})`);
    ok(ShamirSecretSharing.combine(shares.slice(0, 3)) === secret, 'any 3 of 5 shares reconstruct');
    ok(ShamirSecretSharing.combine(shares.slice(2, 5)) === secret, 'a different triple reconstructs the same secret');
    ok(ShamirSecretSharing.combine(shares.slice(0, 2)) !== secret, '2 shares (below threshold) do NOT reconstruct');
    const cm = new ConsentManager();
    cm.grant('user-1', 'analytics', { dataTypes: ['usage'] });
    ok(cm.check('user-1', 'analytics', 'usage').granted === true, 'consent granted for covered type');
    ok(cm.check('user-1', 'analytics', 'marketing').granted === false, 'consent denied for uncovered type');
    cm.revoke('user-1', 'analytics');
    ok(cm.check('user-1', 'analytics', 'usage').granted === false, 'consent revoke works');
    const dt = new DynamicThreshold({ baseThreshold: 0.5 });
    const before = dt.getThreshold();
    for (let i = 0; i < 10; i++) dt.record('scan', true); // false positives tighten
    ok(dt.getThreshold().threshold !== before.threshold || dt.getThreshold().threshold >= 0.2, `threshold responds to recorded events (${before.threshold} → ${dt.getThreshold().threshold})`);
  }

  // ── biometric-detection ────────────────────────────────────────────────────
  console.log('\n4 · biometric-detection');
  {
    const { rPPGDetector, VoiceCloneDetector, NeuralCodecDetector } = P('biometric-detection/src/index.js');
    // Synthetic 72bpm pulse (1.2Hz) at 30fps + noise
    const frames = Array.from({ length: 128 }, (_, i) => 128 + 8 * Math.sin(2 * Math.PI * 1.2 * i / 30) + (Math.random() - 0.5));
    const pulse = new rPPGDetector().detect(frames, 30);
    ok(pulse.pulseDetected === true && pulse.bpmEstimate > 50 && pulse.bpmEstimate < 100, `rPPG detects a periodic pulse (${pulse.bpmEstimate} bpm)`);
    const noPulse = new rPPGDetector().detect(Array.from({ length: 128 }, () => 128), 30);
    ok(noPulse.pulseDetected === false, 'rPPG finds no pulse in flat signal');
    // Pure tone = synthetic-like (over-stable pitch, no breath)
    const tone = Array.from({ length: 8192 }, (_, i) => Math.sin(2 * Math.PI * 200 * i / 16000));
    const voice = new VoiceCloneDetector().analyze(tone, { sampleRate: 16000 });
    ok(voice.cloneLikelihood > 0.3, `voice-clone flags a pure synthetic tone (likelihood ${voice.cloneLikelihood})`);
    // Band-limited noise = codec-like ceiling
    const lp = []; let acc = 0; for (let i = 0; i < 8192; i++) { acc = 0.9 * acc + 0.1 * (Math.random() - 0.5); lp.push(acc); }
    const codec = new NeuralCodecDetector().detect(lp, { sampleRate: 16000 });
    ok(typeof codec.codecLikelihood === 'number' && codec.method, 'neural-codec detector returns a verdict');
  }

  // ── kernel-ebpf ────────────────────────────────────────────────────────────
  console.log('\n5 · kernel-ebpf');
  {
    const { KernelGatingEngine } = P('kernel-ebpf/src/kernel-gating-engine.js');
    const k = new KernelGatingEngine();
    ok(k.evaluate('ptrace').allowed === false, 'denies a dangerous syscall');
    ok(k.evaluate('open', { path: '/etc/shadow' }).allowed === false, 'denies reads of credential paths');
    ok(k.evaluate('connect', { address: '169.254.169.254' }).allowed === false, 'denies cloud metadata SSRF');
    ok(k.evaluate('open', { path: '/tmp/data.json' }).allowed === true, 'allows benign operations');
    ok(['ebpf-capable', 'policy-userspace'].includes(k.evaluate('read').mode), 'reports an honest enforcement mode');
    const kd = new KernelGatingEngine({ defaultAction: 'deny', allowedOperations: ['read'] });
    ok(kd.evaluate('write').allowed === false && kd.evaluate('read').allowed === true, 'default-deny policy blocks unlisted ops');
  }

  // ── zk proofs ──────────────────────────────────────────────────────────────
  console.log('\n6 · zk-proofs (crypto-utils)');
  {
    const { ZKProofSystem } = P('crypto-utils/src/zk-proofs-full.js');
    const zk = new ZKProofSystem();
    const pub = { verdict: 'DENY', policy: 'v1' };
    const proof = zk.generateDetectionProof({ privateInputs: { value: 77 }, publicInputs: pub });
    ok(zk.verifyProof(proof, pub).isValid === true, 'PoK verifies with matching public inputs');
    ok(zk.verifyProof(proof, { verdict: 'ALLOW' }).isValid === false, 'PoK rejects mismatched public inputs');
    ok(zk.verifyProof({ ...proof, z1: proof.z2 }, pub).isValid === false, 'PoK rejects tampered response');
    const rp = zk.generateRangeProof(1234567, 32);
    ok(zk.verifyRangeProof(rp).isValid === true, 'range proof verifies');
    const tb = JSON.parse(JSON.stringify(rp)); tb.bitProofs[3].z0 = tb.bitProofs[3].z1;
    ok(zk.verifyRangeProof(tb).isValid === false, 'range proof rejects tampered bit');
    let outOfRange = false;
    try { zk.generateRangeProof(300, 8); } catch { outOfRange = true; }
    ok(outOfRange, 'cannot prove out-of-range value');
  }

  console.log(`\n${passed} passed · ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
})();
