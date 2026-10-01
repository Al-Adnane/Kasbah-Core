'use strict';
const { AgentCostWatch, kasbahMiddleware } = require('./index.js');

let pass = 0, fail = 0;
function test(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); pass++; }
  catch(e) { console.log(`  ✗ ${name}: ${e.message}`); fail++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'Assertion failed'); }

console.log('\n  AgentCostWatch Tests\n');

test('starts with zero brittleness', () => {
  const acw = new AgentCostWatch();
  assert(acw.brittleness() < 0.30, 'initial brittleness should be low');
});

test('records tokens and costs', () => {
  const acw = new AgentCostWatch();
  acw.record({ tokens: 1000, costUsd: 0.02, model: 'gpt-4', action: 'search' });
  assert(acw.usage().totalCalls === 1);
  assert(acw.usage().tokensPerMin === 1000);
});

test('allows normal usage', () => {
  const acw = new AgentCostWatch();
  acw.record({ tokens: 100, costUsd: 0.001, action: 'search' });
  assert(acw.check().action === 'allow');
});

test('blocks on cost_per_hour exceeded', () => {
  const acw = new AgentCostWatch({ maxCostPerHour: 0.01 });
  acw.record({ tokens: 100, costUsd: 0.02, action: 'search' });
  assert(acw.check().action === 'block');
  assert(acw.check().reason === 'cost_per_hour_exceeded');
});

test('detects runaway loops', () => {
  const acw = new AgentCostWatch({ loopRepeatLimit: 3, loopDetectWindow: 5 });
  for (let i = 0; i < 5; i++) acw.record({ tokens: 10, costUsd: 0, action: 'search_web' });
  const d = acw.check();
  assert(d.action === 'block', `expected block, got ${d.action}`);
  assert(d.reason === 'runaway_loop_detected');
});

test('error rate increases brittleness', () => {
  const acw = new AgentCostWatch();
  for (let i = 0; i < 5; i++) acw.record({ tokens: 10, costUsd: 0.001, action: 'call', isError: true });
  assert(acw.brittleness() > 0.30, 'errors should raise brittleness');
});

test('reset clears all state', () => {
  const acw = new AgentCostWatch();
  acw.record({ tokens: 5000, costUsd: 10, action: 'expensive' });
  acw.reset();
  assert(acw.usage().totalCalls === 0);
  assert(acw.brittleness() < 0.10);
});

test('middleware allows normal call', async () => {
  const acw = new AgentCostWatch();
  const govern = kasbahMiddleware(acw);
  let called = false;
  await govern(async () => { called = true; return 'ok'; }, { tokens: 100, costUsd: 0.001, action: 'test' });
  assert(called, 'fn should have been called');
});

test('middleware blocks when over budget', async () => {
  const acw = new AgentCostWatch({ maxCostPerHour: 0.001 });
  acw.record({ tokens: 100, costUsd: 0.002, action: 'seed' });
  const govern = kasbahMiddleware(acw);
  let threw = false;
  try { await govern(async () => 'ok', { tokens: 10, costUsd: 0 }); }
  catch (e) { threw = e.message.includes('blocked'); }
  assert(threw, 'should have thrown blocked error');
});

console.log(`\n  ${pass} passed · ${fail} failed\n`);
process.exit(fail > 0 ? 1 : 0);
