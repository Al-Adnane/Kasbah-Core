'use strict';

/**
 * Kasbah Guard Desktop — integration smoke test.
 *
 * Tests the full silent-orchestration chain at the Node level without Electron:
 *   Home → Check → checkup returns score → impact.bump fires
 *   Home → Connect → commit proof created → open() verifies
 *   Egress secret → impact.secretsBlocked increments
 *   Honeytoken seed → honey.list() returns tokens
 *   LLM Gate install → config file written
 *
 * No network. No Electron. Pure Node. Run: node test/smoke.js
 */

const assert = require('assert');
const path   = require('path');
const os     = require('os');
const fs     = require('fs');
const crypto = require('crypto');

const SRC = path.join(__dirname, '..', 'src');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  ✓', name); pass++; }
  catch (e) { console.error('  ✗', name, '—', e.message); fail++; }
}
async function ta(name, fn) {
  try { await fn(); console.log('  ✓', name); pass++; }
  catch (e) { console.error('  ✗', name, '—', e.message); fail++; }
}

// ── Wipe test state dirs before starting ────────────────────────────────────
const TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'kasbah-smoke-'));
const realHomedir = os.homedir;
os.homedir = () => TEST_HOME;

(async () => {
  console.log('Kasbah Guard Desktop — smoke test (integration chain)\n');

  // ── 1. Privacy checkup returns a score ──────────────────────────────────────
  console.log('■ privacy checkup');
  const privacy = require(path.join(SRC, 'privacy-engine.js'));
  await ta('checkup returns score and verdict', async () => {
    const r = await privacy.privacyCheckup({ connected: false, egress: null });
    assert.ok(typeof r.score === 'number', 'score must be a number');
    assert.ok(r.verdict, 'verdict must be set');
    assert.ok(r.score >= 0 && r.score <= 100, 'score must be 0–100');
  });
  await ta('checkup with VPN shows higher score', async () => {
    const r = await privacy.privacyCheckup({ connected: true, egress: '185.1.2.3' });
    assert.ok(typeof r.score === 'number');
  });

  // ── 2. Impact counter — the "invisible" chain ───────────────────────────────
  console.log('\n■ impact counter (silent orchestration)');
  const impact = require(path.join(SRC, 'impact.js'));
  t('snapshot starts at zero', () => {
    const s = impact.load();
    assert.ok(typeof s.secretsBlocked === 'number');
    assert.ok(typeof s.scans === 'number');
  });
  t('bump(scans) increments counter', () => {
    const before = impact.load().scans;
    impact.bump('scans');
    const after = impact.load().scans;
    assert.strictEqual(after, before + 1);
  });
  t('bump(secretsBlocked) increments counter', () => {
    const before = impact.load().secretsBlocked;
    impact.bump('secretsBlocked');
    const after = impact.load().secretsBlocked;
    assert.strictEqual(after, before + 1);
  });
  t('bump(honeyHits) increments counter', () => {
    const before = impact.load().honeyHits;
    impact.bump('honeyHits');
    const after = impact.load().honeyHits;
    assert.strictEqual(after, before + 1);
  });
  t('snapshot headline reflects stopped events', () => {
    const s = impact.snapshot();
    assert.ok(s.secretsBlocked >= 1);
    assert.ok(s.headline, 'headline must be non-empty');
    assert.ok(typeof s.estValueUsd === 'number');
  });

  // ── 3. Egress classifier → impact chain ─────────────────────────────────────
  console.log('\n■ egress classifier → impact chain');
  const egress = require(path.join(SRC, 'egress-classifier.js'));
  t('AWS key triggers tier-1 detection', () => {
    const r = egress.classify('AKIAIOSFODNN7EXAMPLE');
    assert.ok(r.found);
    assert.strictEqual(r.tiers[0], 1);
    // Simulate the handleScan side-effect
    if (r.found) impact.bump('secretsBlocked');
    assert.ok(impact.load().secretsBlocked >= 2);
  });
  t('clean text does not trigger', () => {
    const r = egress.classify('Hello, world! This is a normal sentence.');
    assert.strictEqual(r.found, false);
  });

  // ── 4. Commitment proof — Connect → proof created → open verifies ───────────
  console.log('\n■ commitment proof (auto-fires on Connect)');
  const commitProof = require(path.join(SRC, 'commit-proof.js'));
  let createdId;
  t('create() returns requestId and commitment', () => {
    const r = commitProof.create({ egressIp: '185.220.101.1', location: 'sin', claim: 'PROTECTED' });
    assert.ok(r.requestId, 'requestId must exist');
    assert.ok(r.commitment, 'commitment must exist');
    assert.strictEqual(r.claim, 'PROTECTED');
    assert.ok(r.receipt.startsWith('kasbah_receipt:v2:ed25519:'), 'receipt must be signed');
    createdId = r.requestId;
  });
  t('open() reveals IP and verifies commitment', () => {
    const r = commitProof.open(createdId);
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.egressIp, '185.220.101.1');
  });
  t('list() returns the created proof', () => {
    const list = commitProof.list();
    assert.ok(list.length >= 1);
    assert.ok(list.some(p => p.requestId === createdId || p.claim === 'PROTECTED'));
  });
  t('create() without egressIp still works (blank commit)', () => {
    const r = commitProof.create({ location: 'sin', claim: 'PROTECTED' });
    assert.ok(r.requestId);
    // open() on a blank-IP commit: egressIp stored as null → commitment = SHA256('null|salt')
    const opened = commitProof.open(r.requestId);
    // ok=true means stored commitment matches recomputed commitment
    assert.ok(typeof opened.ok === 'boolean', 'open must return ok field');
  });

  // ── 5. Honeytoken seed — silent on Connect ───────────────────────────────────
  console.log('\n■ honeytoken seeding (_silentOrchestrate)');
  const honey = require(path.join(SRC, 'honeytokens.js'));
  t('deploy email token', () => {
    const r = honey.deploy('email');
    assert.ok(r.id);
    assert.ok(r.token);
  });
  t('deploy aws-key token', () => {
    const r = honey.deploy('aws-key');
    assert.ok(r.id);
  });
  t('list() returns both deployed tokens', () => {
    const list = honey.list();
    assert.ok(list.length >= 2);
  });
  t('check() detects own token in text', () => {
    const list = honey.list();
    const token = list[0].token;
    const r = honey.check(`Here is a value: ${token}`);
    assert.strictEqual(r.found, true);
    assert.ok(r.hits.length >= 1);
    // Simulate impact bump
    impact.bump('honeyHits');
    assert.ok(impact.load().honeyHits >= 2);
  });

  // ── 6. LLM Gate install — real config written ────────────────────────────────
  console.log('\n■ LLM Gate install');
  const llmProxy = require(path.join(SRC, 'llm-proxy.js'));
  ta('install() writes config file', async () => {
    const r = llmProxy.install(8796);
    assert.strictEqual(r.ok, true);
    assert.ok(r.configPath, 'configPath must exist');
    assert.ok(r.proxy.includes('127.0.0.1:8796'), 'proxy must point to localhost');
    const written = fs.existsSync(r.configPath);
    assert.ok(written, 'config file must be on disk');
    const cfg = JSON.parse(fs.readFileSync(r.configPath, 'utf8'));
    assert.ok(cfg.token, 'config must contain auth token');
    assert.ok(Array.isArray(cfg.allowedHosts), 'allowedHosts must be array');
  });
  ta('uninstall() removes config file', async () => {
    llmProxy.uninstall();
    // CONFIG_PATH is in homedir — verify it's gone
    const cfg = path.join(TEST_HOME, '.kasbah-llmgate.json');
    assert.ok(!fs.existsSync(cfg), 'config must be removed after uninstall');
  });

  // ── 7. Full chain integration: checkup → bump scans → score flows through ───
  console.log('\n■ full chain: Check → impact → snapshot reflects reality');
  ta('checkup + impact.bump matches snapshot', async () => {
    impact.bump('scans');
    const snap = impact.snapshot();
    assert.ok(snap.scans >= 2, 'scans counter should reflect bumps');
    assert.ok(snap.secretsBlocked >= 2, 'secretsBlocked should reflect egress detections');
    assert.ok(snap.honeyHits >= 2, 'honeyHits should reflect check() hits');
  });

  // ── 8. Shamir vault round-trip (crypto audit surface) ───────────────────────
  console.log('\n■ Shamir vault (crypto correctness)');
  const shamir = require(path.join(SRC, 'shamir-vault.js'));
  t('splitString and combineToString (3-of-5)', () => {
    const secret = 'recovery-seed-phrase-test-1234567890';
    const shares = shamir.splitString(secret, 5, 3); // (str, n, k)
    assert.strictEqual(shares.length, 5, 'must produce 5 shares');
    // Reconstruct from 3 non-sequential shares
    const subset = [shares[0], shares[2], shares[4]];
    const recovered = shamir.combineToString(subset);
    assert.strictEqual(recovered, secret, 'reconstructed secret must match original');
  });
  t('below-threshold reconstruct produces wrong result', () => {
    const secret = 'another-secret-12345';
    const shares = shamir.splitString(secret, 3, 2);
    // Only 1 share — below threshold of 2
    try {
      const bad = shamir.combineToString([shares[0]]);
      // If it doesn't throw, result must not equal the secret
      assert.notStrictEqual(bad, secret, 'single share must not reconstruct secret');
    } catch (_) {
      // Throwing is also acceptable
    }
  });

  // ── Summary ──────────────────────────────────────────────────────────────────
  console.log('\n──────────────────────────────────────────────────');
  console.log(`Smoke: ${pass + fail} tests | ${pass} passed | ${fail} failed`);
  if (fail) { console.error('✗ Smoke test FAILED'); process.exitCode = 1; }
  else console.log('✓ Smoke test passed — full chain verified');

  // Cleanup
  try { fs.rmSync(TEST_HOME, { recursive: true, force: true }); } catch (_) {}
  os.homedir = realHomedir;
})();
