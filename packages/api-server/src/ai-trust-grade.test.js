'use strict';

/**
 * AI Trust Grade unit tests.
 * Run: node packages/api-server/src/ai-trust-grade.test.js
 */

const assert = require('assert');
const { grade, chip, WEIGHTS } = require('./ai-trust-grade.js');

let n = 0;
function ok(name, fn) {
  try { fn(); n++; console.log('  ✓', name); }
  catch (e) { console.error('  ✗', name, e.message); process.exitCode = 1; }
}

console.log('ai-trust-grade.js');

ok('weights sum to 100', () => {
  const sum = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);
  assert.strictEqual(sum, 100);
});

ok('disabled protection → F', () => {
  const g = grade({ enabled: false, scanned: 10, secretsBlocked: 5 });
  assert.strictEqual(g.grade, 'F');
  assert.strictEqual(g.score, 0);
});

ok('strong protection → A/B', () => {
  const g = grade({
    scanned: 20, secretsBlocked: 4, injectionBlocked: 3, blocked: 7,
    receiptsIssued: 7, trackersBlocked: 12, offlineScans: 0,
  });
  assert.ok(['A', 'B'].includes(g.grade), g.grade + ' score=' + g.score);
  assert.ok(g.score >= 80);
});

ok('offline penalty lowers grade', () => {
  const good = grade({ scanned: 10, secretsBlocked: 2, receiptsIssued: 2, offlineScans: 0 });
  const bad = grade({ scanned: 10, secretsBlocked: 2, receiptsIssued: 2, offlineScans: 4 });
  assert.ok(bad.score < good.score, `${bad.score} !< ${good.score}`);
});

ok('chip maps grades to colors', () => {
  const c = chip({ grade: 'A', score: 95 });
  assert.strictEqual(c.letter, 'A');
  assert.strictEqual(c.title, 'Fortress');
});

ok('explainable factors present when threats exist', () => {
  const g = grade({ scanned: 5, secretsBlocked: 2, injectionBlocked: 1, offlineScans: 1 });
  assert.ok(Array.isArray(g.factors) && g.factors.length >= 2);
  assert.ok(g.formula.includes('weight'));
});

console.log(`\n${n} passed`);
