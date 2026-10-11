'use strict';

/**
 * enforcer.test.js — Tier-3 enforcement + camera sentinel + data lineage.
 *
 * Verifies:
 *   1. Enforcer: enforce mode off → never acts (alert-only)
 *   2. Enforcer: protected processes are NEVER acted on (safety rail)
 *   3. Enforcer: terminate action attempts + audit-logs on unapproved apps
 *   4. Enforcer: tcc-reset action path constructs correctly
 *   5. Camera sentinel: check() returns the expected shape (active/alerts/tcc)
 *   6. Data lineage: record → chain → provenance round-trip
 *
 * Run: node tests/enforcer.test.js
 */

const path = require('path');
const fs   = require('fs');
const os   = require('os');
// T1: never touch the real ~/.kasbah-privacy and never run real kill/tccutil.
process.env.KASBAH_PRIVACY_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'kasbah-enf-test-'));
process.env.KASBAH_ENFORCE_DRYRUN = '1';
process.on('exit', () => { try { fs.rmSync(process.env.KASBAH_PRIVACY_DIR, { recursive: true, force: true }); } catch (_) {} });
const enforcer = require(path.join(__dirname, '..', 'src', 'kasbah-enforcer.js'));
const cameraSentinel = require(path.join(__dirname, '..', 'packages', 'desktop', 'src', 'camera-sentinel.js'));
const dataLineage = require(path.join(__dirname, '..', 'packages', 'api-server', 'src', 'data-lineage.js'));

let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { passed++; console.log(`  ✓ ${name}`); }
  else { failed++; console.log(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); }
}

console.log('\n═══ Enforcer + Camera Sentinel + Data Lineage ═══\n');

// ── 1. Enforce off → never acts
{
  const st = enforcer.setEnforce(false);
  check('enforce off status', st.enforce === false && st.tier === 1, JSON.stringify(st));
}

(async () => {
  // 2. Protected processes are never acted on even with enforce ON
  enforcer.setEnforce(true);
  const r1 = await enforcer.actOnAlert({ device: 'mic', name: 'coreaudiod', pid: 42 });
  check('protected process never acted on', r1.acted === false && /protected/.test(r1.reason), JSON.stringify(r1));
  const r2 = await enforcer.actOnAlert({ device: 'camera', name: 'Electron', pid: 43 });
  check('Kasbah/Electron never acted on', r2.acted === false && /protected/.test(r2.reason), JSON.stringify(r2));

  // 3. Terminate action on an unapproved app (pid won't exist — action attempts + logs)
  enforcer.setAction('terminate');
  const before = enforcer.recentActions(50).length;
  const beforeLatest = enforcer.recentActions(1)[0]?.ts || '';
  const r3 = await enforcer.actOnAlert({ device: 'camera', name: 'DefinitelyNotRealApp', pid: 3999999 });
  const after = enforcer.recentActions(50);
  check('terminate attempted (result logged)', typeof r3.reason === 'string', JSON.stringify(r3));
  check('action audit-logged', after.some(e => e.action === 'terminate' && (e.ts || '') >= beforeLatest), JSON.stringify(after[0] || {}));

  // 4. tcc-reset path
  enforcer.setAction('tcc-reset');
  const r4 = await enforcer.actOnAlert({ device: 'mic', name: 'SomeApp', pid: 1 });
  check('tcc-reset attempted', typeof r4.reason === 'string', JSON.stringify(r4));

  // Invalid action rejected
  const bad = enforcer.setAction('rm-rf');
  check('invalid action rejected', !!bad.error, JSON.stringify(bad));

  // Cleanup: enforce off
  enforcer.setEnforce(false);

  // ── 5. Camera sentinel shape
  const cam = await cameraSentinel.check();
  check('camera sentinel shape', Array.isArray(cam.active) && Array.isArray(cam.alerts) && typeof cam.tccAvailable === 'boolean', JSON.stringify({ active: cam.active.length, alerts: cam.alerts.length, tcc: cam.tccAvailable }));
  const camApproved = cameraSentinel.listApproved();
  check('camera approved list is an array', Array.isArray(camApproved));

  // ── 6. Data lineage round-trip
  {
    dataLineage.record({ keyId: 'test-key-123', surface: 'paste', verdict: 'DENY', risk: 0.9, intervention: 'hard_block', receiptUrl: 'http://x/verify/abc' });
    dataLineage.record({ keyId: 'test-key-123', surface: 'browser', verdict: 'ALLOW', risk: 0.1 });
    const chain = dataLineage.chain('test-key-123');
    check('lineage chain has both edges', chain.length >= 2, JSON.stringify(chain.length));
    check('lineage newest first', chain[0].surface === 'browser');
    const prov = dataLineage.provenance('test-key-123');
    check('provenance totals', prov.totalTracked >= 2 && prov.receipts >= 1, JSON.stringify(prov));
    check('provenance surfaces include paste', prov.surfaces.some(s => s.surface === 'paste'));
    check('provenance lastDeny present', prov.lastDeny && prov.lastDeny.verdict === 'DENY');
    const st = dataLineage.stats();
    check('lineage stats aggregate', st.edges > 0 && st.surfaces.includes('paste'), JSON.stringify(st));
  }

  console.log(`\n═══ ${passed} passed, ${failed} failed ═══\n`);
  process.exit(failed ? 1 : 0);
})();