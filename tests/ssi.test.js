'use strict';

/**
 * ssi.test.js — every SSI (sovereign admission) module, end to end.
 *
 *   1. JS mirror            src/ssi-admission.js
 *   2. Python core suite    kasbah-os/ssi_universal_core.py   (18 checks)
 *   3. Engine Max suite     kasbah-os/sovereign_engine_max.py
 *   4. CLI bridge           kasbah-os/ssi_cli.py              (every command)
 *   5. JS ↔ Python parity   KSG-1 mutual-information estimator
 *   6. Tool-risk gate       packages/api-server/src/ssi-gate.js
 *
 * No server needed. Python sections are skipped (not failed) when python3 is
 * missing, unless KASBAH_REQUIRE_PYTHON=1.
 *
 * Run: node tests/ssi.test.js
 */

const assert = require('assert');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const OS_DIR = path.join(ROOT, 'kasbah-os');
let pass = 0, fail = 0, skipped = 0;
function t(name, fn) {
  try { fn(); pass++; console.log('  ✓ ' + name); }
  catch (e) { fail++; console.log('  ✗ ' + name + '\n      ' + String(e.message).split('\n')[0]); }
}
function skip(name, why) { skipped++; console.log('  - ' + name + ' (skipped: ' + why + ')'); }

const hasPython = spawnSync('python3', ['-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)']).status === 0;
if (!hasPython && process.env.KASBAH_REQUIRE_PYTHON === '1') {
  console.error('KASBAH_REQUIRE_PYTHON=1 but python3 >= 3.10 is not available'); process.exit(1);
}
const cli = (payload) => JSON.parse(execFileSync('python3', ['-B', path.join(OS_DIR, 'ssi_cli.py')],
  { input: typeof payload === 'string' ? payload : JSON.stringify(payload), timeout: 90000 }).toString());

const COUPLED_X = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8];
const COUPLED_Y = [0.11, 0.19, 0.31, 0.39, 0.51, 0.59, 0.71, 0.79];
const FLAT = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5];
const GOOD_RIGHTS = [1, 0.8, 0.5, 1];
const BAD_RIGHTS = [0, 0.8, 0.5, 1];

// ─── 1. JS mirror ────────────────────────────────────────────────────────────
console.log('\nSSI JS mirror (src/ssi-admission.js)');
const ssi = require(path.join(ROOT, 'src', 'ssi-admission.js'));
t('built-in self-test passes every check', () => {
  const r = ssi.selfTest(); assert.strictEqual(r.passed, r.total, 'failed: ' + r.failed.join(','));
});
t('hard rights are non-compensable: one pillar below its floor fails', () => {
  assert.strictEqual(ssi.rightsGate(GOOD_RIGHTS).ok, true);
  const r = ssi.rightsGate([0.99, 1, 1, 1]); // everything else maxed cannot buy pillar 0 back
  assert.strictEqual(r.ok, false); assert.strictEqual(r.failedIndex, 0);
});
t('rights exactly at the floor pass; a missing pillar fails', () => {
  assert.strictEqual(ssi.rightsGate(ssi.RIGHTS_BASE.slice()).ok, true);
  assert.strictEqual(ssi.rightsGate([1, 0.8, 0.5]).ok, false);
});
t('KSG-1: coupled signals leak, flat signals do not', () => {
  assert.ok(ssi.ksg1(COUPLED_X, COUPLED_Y) > ssi.EPSILON_LEAK);
  assert.ok(ssi.ksg1(FLAT, FLAT) < ssi.EPSILON_LEAK);
});
t('KSG-1 is deterministic and rejects mismatched lengths', () => {
  assert.strictEqual(ssi.ksg1(COUPLED_X, COUPLED_Y), ssi.ksg1(COUPLED_X, COUPLED_Y));
  assert.strictEqual(ssi.ksg1([1, 2, 3], [1, 2]), 0);
});
t('permit is single-use: second consume is refused', () => {
  const ta = new ssi.MicroTicketAuthority();
  const tk = ta.issue('state', 1, 500);
  assert.strictEqual(ta.consume(tk), true); assert.strictEqual(ta.consume(tk), false);
});
t('permit expires, and a forged or cross-authority permit is refused', () => {
  const ta = new ssi.MicroTicketAuthority();
  assert.strictEqual(ta.consume(ta.issue('state', 1, -10)), false);
  const forged = ta.issue('state', 1, 500); forged.mac = '0'.repeat(64);
  assert.strictEqual(ta.consume(forged), false);
  const other = new ssi.MicroTicketAuthority();
  assert.strictEqual(other.consume(ta.issue('state', 1, 500)), false);
  assert.strictEqual(ta.consume(null), false);
});
t('a permit whose scope was edited after issue is refused', () => {
  const ta = new ssi.MicroTicketAuthority();
  const tk = ta.issue('state', 1, 500);
  tk._payload = tk._payload.replace(/\|1$/, '|9');
  assert.strictEqual(ta.consume(tk), false);
});
t('screen is advisory: flags a rights failure and a leak, never throws on empty input', () => {
  assert.deepStrictEqual(ssi.ssiScreen({}).flags, []);
  assert.strictEqual(ssi.ssiScreen({ rights: BAD_RIGHTS }).advisory, 'WARN');
  const s = ssi.ssiScreen({ subSignal: COUPLED_X, telSignal: COUPLED_Y });
  assert.ok(s.flags.includes('ksg1_leakage_above_epsilon'));
  assert.strictEqual(ssi.ssiScreen({ rights: GOOD_RIGHTS, subSignal: FLAT, telSignal: FLAT }).advisory, 'CLEAR');
});

// ─── 2–5. Python cores ───────────────────────────────────────────────────────
console.log('\nSSI Python cores (kasbah-os)');
if (!hasPython) {
  skip('core suite, Engine Max suite, CLI bridge, parity', 'python3 >= 3.10 not found');
} else {
  t('ssi_universal_core.py: all 18 self-test checks pass', () => {
    const r = spawnSync('python3', ['-B', path.join(OS_DIR, 'ssi_universal_core.py')], { timeout: 120000 });
    const out = String(r.stdout);
    assert.strictEqual(r.status, 0, String(r.stderr).split('\n')[0]);
    assert.ok(/All 18 Self-Test Verification Checks Completed Successfully/.test(out));
    assert.ok(!/: FAIL/.test(out), 'a check reported FAIL');
  });
  t('sovereign_engine_max.py: all max-hardness checks pass', () => {
    const r = spawnSync('python3', ['-B', path.join(OS_DIR, 'sovereign_engine_max.py')], { timeout: 180000 });
    const out = String(r.stdout);
    assert.strictEqual(r.status, 0, String(r.stderr).split('\n')[0]);
    assert.ok(/all max-hardness checks passed/.test(out));
    assert.ok(!/\[FAIL\]/.test(out), 'a check reported FAIL');
  });
  t('cli selftest is ok and the leak threshold separates resting from coupled', () => {
    const r = cli({ cmd: 'selftest' });
    assert.strictEqual(r.ok, true);
    assert.ok(r.calibration.resting_p99 < r.calibration.current_epsilon);
    assert.ok(r.calibration.current_epsilon < r.calibration.coupled_min);
  });
  t('cli screen reports the failed rights pillar and a leak', () => {
    assert.deepStrictEqual(cli({ cmd: 'screen', rights: BAD_RIGHTS }).rights_failed, [0]);
    assert.strictEqual(cli({ cmd: 'screen', rights: GOOD_RIGHTS }).rights_ok, true);
    assert.strictEqual(cli({ cmd: 'screen', sub: COUPLED_X, tel: COUPLED_Y }).leak, true);
  });
  t('cli admit: a normal action is admitted', () => {
    const r = cli({ cmd: 'admit' }); assert.strictEqual(r.admitted, true); assert.strictEqual(r.deny, 'ADMIT');
  });
  t('cli admit: a rights violation is refused as DENY_RIGHTS', () => {
    const r = cli({ cmd: 'admit', rights: BAD_RIGHTS }); assert.strictEqual(r.admitted, false); assert.strictEqual(r.deny, 'DENY_RIGHTS');
  });
  t('cli admit: an expired permit is refused', () => {
    assert.strictEqual(cli({ cmd: 'admit', ttl_ms: -50 }).deny, 'DENY_TICKET_EXPIRED');
  });
  t('cli admit: signal leakage is refused', () => {
    const r = cli({ cmd: 'admit', sub: COUPLED_X, tel: COUPLED_Y }); assert.strictEqual(r.admitted, false); assert.strictEqual(r.deny, 'DENY_THERMO');
  });
  t('cli admit: the consent passphrase gate admits the right phrase only', () => {
    assert.strictEqual(cli({ cmd: 'admit', inner: 'execute' }).admitted, true);
    assert.strictEqual(cli({ cmd: 'admit', inner: 'wrong' }).deny, 'DENY_INNER_SPEECH');
  });
  t('cli engine_admit: consent admits and yields a working capability; no consent is refused', () => {
    const yes = cli({ cmd: 'engine_admit' }); assert.strictEqual(yes.admitted, true); assert.strictEqual(yes.cap_ok, true);
    const no = cli({ cmd: 'engine_admit', consent: false }); assert.strictEqual(no.admitted, false);
  });
  t('cli fails safely on an unknown command and on bad JSON', () => {
    assert.strictEqual(cli({ cmd: 'bogus' }).ok, false);
    assert.strictEqual(cli('not json').ok, false);
  });
  t('JS mirror and Python core agree on KSG-1 to 3 decimal places', () => {
    const cases = [[COUPLED_X, COUPLED_Y], [FLAT, FLAT], [[0.9, 0.1, 0.4, 0.7, 0.2, 0.8, 0.3, 0.6], [0.2, 0.6, 0.9, 0.1, 0.5, 0.3, 0.8, 0.4]]];
    for (const [x, y] of cases) {
      const js = ssi.ksg1(x, y); const py = cli({ cmd: 'screen', sub: x, tel: y }).mi;
      assert.ok(Math.abs(js - py) < 1e-3, `js ${js} vs python ${py}`);
    }
  });
  t('JS mirror and Python core use the same rights floors and leak threshold', () => {
    const out = execFileSync('python3', ['-B', '-c',
      'import sys,json; sys.path.insert(0, sys.argv[1]); from ssi_universal_core import Config; print(json.dumps({"b": list(Config.RIGHTS_BASE), "e": Config.EPSILON_LEAK}))', OS_DIR]).toString();
    const py = JSON.parse(out);
    assert.deepStrictEqual(py.b, ssi.RIGHTS_BASE); assert.strictEqual(py.e, ssi.EPSILON_LEAK);
  });
}

// ─── 6. Tool-risk gate ───────────────────────────────────────────────────────
console.log('\nSSI tool-risk gate (packages/api-server/src/ssi-gate.js)');
const gate = require(path.join(ROOT, 'packages', 'api-server', 'src', 'ssi-gate.js'));
t('read-only tools need no tap; logged writes are soft-gated', () => {
  assert.strictEqual(gate.classifyRisk('read_file', { path: 'README.md' }).tier, 'ZERO_TOUCH');
  assert.strictEqual(gate.classifyRisk('write_file', { path: 'notes.txt' }).tier, 'SOFT_GATE');
});
t('a sensitive path forces a physical tap even for a read-only tool', () => {
  for (const p of ['~/.ssh/id_rsa', '.env', '~/.aws/credentials']) {
    const r = gate.classifyRisk('read_file', { path: p });
    assert.strictEqual(r.tier, 'PHYSICAL_TOUCH', p); assert.strictEqual(r.tapRequired, true);
  }
});
t('unknown tools fail safe to a physical tap', () => {
  assert.strictEqual(gate.classifyRisk('some_new_tool', {}).tier, 'PHYSICAL_TOUCH');
  assert.strictEqual(gate.classifyRisk('', {}).tier, 'PHYSICAL_TOUCH');
});
t('kill-switch commands are flagged', () => {
  for (const c of ['pkill node', 'kill -9 123', 'terraform destroy', 'kubectl delete ns prod']) {
    assert.strictEqual(gate.classifyRisk('bash', { command: c }).killSwitch, true, c);
  }
});
t('one agent cannot trigger another agent\'s kill switch', () => {
  const tier = gate.classifyRisk('bash', { command: 'pkill node' });
  assert.strictEqual(gate.killSwitchGuard({ requestingAgent: 'a', targetAgent: 'b', tier }).ok, false);
  const own = gate.killSwitchGuard({ requestingAgent: 'a', targetAgent: 'a', tier });
  assert.strictEqual(own.ok, true); assert.strictEqual(own.needsLocalTap, true);
});
t('each agent gets its own stable stone identity', () => {
  assert.notStrictEqual(gate.stoneFor('a').stoneId, gate.stoneFor('b').stoneId);
  assert.strictEqual(gate.stoneFor('a').stoneId, gate.stoneFor('a').stoneId);
});
t('action hash is stable and changes with the arguments', () => {
  assert.strictEqual(gate.actionHash('t', { a: 1 }), gate.actionHash('t', { a: 1 }));
  assert.notStrictEqual(gate.actionHash('t', { a: 1 }), gate.actionHash('t', { a: 2 }));
});

console.log(`\n${pass} passed · ${fail} failed${skipped ? ' · ' + skipped + ' skipped' : ''}`);
process.exit(fail ? 1 : 0);
