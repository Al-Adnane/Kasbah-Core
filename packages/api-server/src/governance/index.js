'use strict';

/**
 * Kasbah governance aggregator.
 *
 * Runs all 4 detectors in parallel-style aggregation, combines risk scores
 * using probabilistic union, and emits a single { verdict, risk, threats,
 * details } envelope. Used by /v1/govern + the LLM proxy pre-check.
 *
 *   risk < 0.35  → ALLOW
 *   0.35 ≤ r < 0.70 → WARN
 *   risk ≥ 0.70  → DENY
 */

const promptInjection   = require('./prompt-injection.js');
const secretLeak        = require('./secret-leak.js');
const pii               = require('./pii.js');
const destructiveIntent = require('./destructive-intent.js');

const DETECTORS = [
  { name: 'prompt-injection',   weight: 1.0, fn: promptInjection.detect },
  { name: 'secret-leak',        weight: 1.0, fn: secretLeak.detect },
  { name: 'pii',                weight: 0.55, fn: (t) => { const r = pii.detect(t, { redact: false }); return { risk: r.risk, threats: r.threats, details: r.details }; } },
  { name: 'destructive-intent', weight: 1.0, fn: destructiveIntent.detect }
];

/**
 * Run the full pipeline.
 * @param {string} text
 * @param {object} ctx — optional context (currently unused, future: agent, surface, …)
 * @returns {{ verdict: 'ALLOW'|'WARN'|'DENY', risk: number, threats: string[], detectors: {name, risk, threats, details}[] }}
 */
function evaluate(text, ctx = {}) {
  const results = [];
  let combined = 0;
  for (const d of DETECTORS) {
    const r = d.fn(text);
    const effective = r.risk * d.weight;
    combined = 1 - (1 - combined) * (1 - effective);
    results.push({ name: d.name, risk: +r.risk.toFixed(3), threats: r.threats, details: r.details });
  }
  const risk = +combined.toFixed(3);
  const verdict = risk >= 0.70 ? 'DENY' : risk >= 0.35 ? 'WARN' : 'ALLOW';
  const allThreats = [].concat(...results.map(r => r.threats));
  return { verdict, risk, threats: allThreats, detectors: results };
}

// Convenience PII redaction (used by the proxy)
function redactPII(text) {
  return pii.detect(text || '', { redact: true });
}

module.exports = {
  evaluate,
  redactPII,
  detectors: { promptInjection, secretLeak, pii, destructiveIntent }
};
