#!/usr/bin/env node
'use strict';
const mc = require('./src/model-catalog.js');
const mo = require('./src/model-optimizer.js');
const ACW = require('../agent-cost-watch/src/index.js').AgentCostWatch;

console.log('═══════════════════════════════════════════════════');
console.log('  KASBAH GUARD v3 — TOKEN OPTIMIZATION REPORT');
console.log('═══════════════════════════════════════════════════\n');

// ── 1. MODEL CATALOG ──────────────────────────────────────────────────
console.log('📊 MODEL CATALOG');
console.log('  Models:', mc.CATALOG.length, '| Providers:', mc.PROVIDERS?.length || 'N/A', '| Regions:', mc.REGIONS?.length || 'N/A');
console.log('');

// Top 10 most expensive models
const byPrice = [...mc.CATALOG].sort((a,b) => ((b.in||0)+(b.out||0)) - ((a.in||0)+(a.out||0)));
console.log('  Top models by price/1M tokens:');
byPrice.slice(0,8).forEach(m => {
  const p = (m.in||0)+(m.out||0);
  console.log(`    ${m.id.padEnd(28)} ${m.provider.padEnd(12)} $${(m.in||0).toFixed(1)}/${(m.out||0).toFixed(1)}  = $${p.toFixed(1)}/1M`);
});
console.log('');

// Cheapest models
const cheapest = [...mc.CATALOG].sort((a,b) => ((a.in||0)+(a.out||0)) - ((b.in||0)+(b.out||0)));
console.log('  Cheapest models:');
cheapest.slice(0,5).forEach(m => {
  const p = (m.in||0)+(m.out||0);
  console.log(`    ${m.id.padEnd(28)} ${m.provider.padEnd(12)} $${p.toFixed(2)}/1M`);
});
console.log('');

// ── 2. COST SIMULATION ─────────────────────────────────────────────────
console.log('💰 COST SIMULATION — 3 real scenarios\n');

const scenarios = [
  { name: 'Trivial: "hello"', prompt: 'hello', tokens: 5 },
  { name: 'Simple QA', prompt: 'What is the capital of France and why was it chosen?', tokens: 150 },
  { name: 'Code review', prompt: 'Review this function for SQL injection: function login(u,p) { return db.query("SELECT * FROM users WHERE user=\'"+u+"\'"); }', tokens: 500 },
  { name: 'Architecture design', prompt: 'Design a distributed real-time messaging system for 10M concurrent users with pub/sub, presence, and message persistence', tokens: 2000 },
];

for (const s of scenarios) {
  const route = mo.autoRoute(s.prompt, null, 'gpt-4o');
  const gpt4oPrice = mc.priceFor(mc.byId.get('gpt-4o'), s.tokens, s.tokens * 0.5);
  const optedPrice = route.model?.id ? mc.priceFor(mc.byId.get(route.model.id) || mc.detect({model: route.model.id}), s.tokens, s.tokens * 0.5) : { total: 0 };

  console.log(`  ${s.name}`);
  console.log(`    Tokens:       ${s.tokens} in / ${Math.floor(s.tokens*0.5)} out`);
  console.log(`    GPT-4o cost:  $${gpt4oPrice.total.toFixed(6)}`);
  console.log(`    Tier:         ${route.tier}`);
  console.log(`    Routed to:    ${route.model?.id || 'N/A'} (${route.model?.provider || 'N/A'})`);
  console.log(`    Optimized:    $${optedPrice.total.toFixed(6)}`);
  const savings = gpt4oPrice.total - optedPrice.total;
  if (savings > 0) console.log(`    SAVED:        $${savings.toFixed(6)} (${((savings/gpt4oPrice.total)*100).toFixed(0)}%)`);
  console.log('');
}

// ── 3. AGENT COST WATCH ────────────────────────────────────────────────
console.log('🛡️  AGENT COST WATCH — loop detection + throttling\n');

const acw = new ACW({ maxCostPerHour: 1.0, maxCostPerDay: 5.0 });

// Simulate normal usage
for (let i = 0; i < 3; i++) {
  acw.record({ tokens: 1000, costUsd: 0.002, model: 'gpt-4o', action: 'search' });
}
const d1 = acw.check();
console.log('  After 3 normal calls:', d1.action, '| brittleness:', d1.brittleness?.toFixed(2));

// Simulate a loop (same action 6 times)
for (let i = 0; i < 6; i++) {
  acw.record({ tokens: 500, costUsd: 0.001, model: 'gpt-4o', action: 'shell_exec' });
}
const d2 = acw.check();
console.log('  After 6x loop:', d2.action, '| brittleness:', d2.brittleness?.toFixed(2), '| loop:', d2.isLoop || false);

// Run up costs to trigger budget
for (let i = 0; i < 200; i++) {
  acw.record({ tokens: 1000, costUsd: 0.01, model: 'gpt-4o', action: 'api_call' });
}
const d3 = acw.check();
console.log('  After $2+ spent:', d3.action, '| brittleness:', d3.brittleness?.toFixed(2));
console.log('  Hourly cost:', acw.stats().costPerHour, '| Daily:', acw.stats().costPerDay);
console.log('');

// ── 4. SAVINGS SUMMARY ─────────────────────────────────────────────────
console.log('📈 CUMULATIVE SAVINGS');
const sv = mo.getSavings();
console.log('  Total routes optimized:', sv.totalRoutes);
console.log('  Total saved:', '$' + sv.totalSaved.toFixed(2));
console.log('');

console.log('═══════════════════════════════════════════════════');
console.log('  System ready — restart API server for live endpoints');
console.log('═══════════════════════════════════════════════════');
