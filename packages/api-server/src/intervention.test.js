'use strict';

/**
 * Unit tests for the intervention / seatbelt product layer.
 * Run: node packages/api-server/src/intervention.test.js
 */

const assert = require('assert');
const intervention = require('./intervention.js');

let passed = 0;
function ok(name, fn) {
  try {
    fn();
    passed++;
    console.log('  ✓', name);
  } catch (e) {
    console.error('  ✗', name, '—', e.message);
    process.exitCode = 1;
  }
}

console.log('intervention.js');

ok('silent pass below 0.30', () => {
  intervention.reset('t1');
  const d = intervention.decide({ risk: 0.1, threats: [], clientKey: 't1' });
  assert.strictEqual(d.intervention, 'silent_pass');
  assert.strictEqual(d.enforcement, 'none');
  assert.strictEqual(d.authority.verb, 'SIMULATE');
  assert.strictEqual(d.authority.units, 0);
});

ok('warning toast 0.30–0.70', () => {
  intervention.reset('t2');
  const d = intervention.decide({ risk: 0.5, threats: ['pii:ssn'], clientKey: 't2' });
  assert.strictEqual(d.intervention, 'warning_toast');
  assert.strictEqual(d.ui, 'toast');
  assert.strictEqual(d.enforcement, 'warn');
  assert.ok(d.copy.toast.includes('sensitive'));
});

ok('hard block at ≥0.70', () => {
  intervention.reset('t3');
  const d = intervention.decide({
    risk: 0.9,
    threats: ['secret:aws_key'],
    clientKey: 't3',
    surface: 'paste',
  });
  assert.strictEqual(d.intervention, 'hard_block');
  assert.strictEqual(d.enforcement, 'block');
  assert.strictEqual(d.authority.verb, 'SHIELD');
  assert.strictEqual(d.authority.units, 1);
  assert.strictEqual(d.ui, 'modal');
  assert.ok(d.share.worthy);
});

ok('hysteresis holds hard_block until risk falls past exit', () => {
  intervention.reset('t4');
  intervention.decide({ risk: 0.9, clientKey: 't4' });
  // still block-ish at 0.60 (above exit 0.55)
  const mid = intervention.decide({ risk: 0.6, clientKey: 't4' });
  assert.strictEqual(mid.intervention, 'hard_block');
  // drop past exit → warning
  const low = intervention.decide({ risk: 0.4, clientKey: 't4' });
  assert.strictEqual(low.intervention, 'warning_toast');
});

ok('modal budget suppresses repeated hard blocks', () => {
  intervention.reset('t5');
  const a = intervention.decide({ risk: 0.95, clientKey: 't5' });
  assert.strictEqual(a.ui, 'modal');
  const b = intervention.decide({ risk: 0.95, clientKey: 't5' });
  assert.strictEqual(b.suppressUi, true);
  assert.strictEqual(b.suppressReason, 'modal_budget');
});

ok('mute block when enforcement budget exhausted', () => {
  intervention.reset('t6');
  const d = intervention.decide({
    risk: 0.95,
    threats: ['secret:stripe'],
    clientKey: 't6',
    enforcementBudget: 0,
  });
  assert.strictEqual(d.intervention, 'hard_block');
  assert.strictEqual(d.muteBlock, true);
  assert.strictEqual(d.enforcement, 'warn');
  assert.ok(d.copy.title.includes('Would have blocked'));
  assert.ok(d.share.worthy);
});

ok('redact verb when requested on warning', () => {
  intervention.reset('t7');
  const d = intervention.decide({
    risk: 0.55,
    threats: ['pii:email'],
    clientKey: 't7',
    wantRedact: true,
    enforcementBudget: 10,
  });
  assert.strictEqual(d.authority.verb, 'REDACT');
  assert.strictEqual(d.authority.units, 5);
  assert.strictEqual(d.enforcement, 'redact');
});

ok('snapshot counters accumulate', () => {
  intervention.reset('t8');
  intervention.decide({ risk: 0.1, clientKey: 't8' });
  intervention.decide({ risk: 0.95, clientKey: 't8' });
  const s = intervention.snapshot('t8');
  assert.ok(s.counters.silent_pass >= 1);
  assert.ok(s.counters.hard_block >= 1);
  assert.ok(s.counters.saved >= 1);
});

ok('AUTHORITY_VERBS exports unit costs', () => {
  assert.strictEqual(intervention.AUTHORITY_VERBS.SHIELD, 1);
  assert.strictEqual(intervention.AUTHORITY_VERBS.REDACT, 5);
  assert.strictEqual(intervention.AUTHORITY_VERBS.CERTIFY, 20);
});

ok('fromGovern trusts engine DENY over soft risk', () => {
  intervention.reset('g1');
  const d = intervention.fromGovern({ verdict: 'DENY', risk: 0.2, threats: ['x'] }, { clientKey: 'g1' });
  assert.strictEqual(d.intervention, 'hard_block');
  assert.strictEqual(d.engineVerdict, 'DENY');
});

ok('fromGovern maps REQUIRE_APPROVAL to non-silent UX', () => {
  intervention.reset('g2');
  const d = intervention.fromGovern({ verdict: 'REQUIRE_APPROVAL', risk: 0.1, threats: [] }, { clientKey: 'g2' });
  assert.notStrictEqual(d.intervention, 'silent_pass');
});

ok('fromGovern ALLOW → silent_pass', () => {
  intervention.reset('g3');
  const d = intervention.fromGovern({ verdict: 'ALLOW', risk: 0.05 }, { clientKey: 'g3' });
  assert.strictEqual(d.intervention, 'silent_pass');
});

console.log(`\n${passed} passed`);
