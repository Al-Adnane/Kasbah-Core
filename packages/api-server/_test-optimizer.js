const mo = require('./src/model-optimizer.js');

// Test 1: Trivial prompt
const r1 = mo.suggestCheaper('hello', 'gpt-4o');
console.log('=== Trivial: "hello" ===');
console.log('Tier:', r1.tier, '| Current:', r1.current.id, '$' + r1.current.pricePer1M + '/1M');
r1.alternatives.slice(0, 3).forEach(a => console.log('  →', a.model.id, 'save', a.savingsPct + '%'));

// Test 2: Complex
const r2 = mo.suggestCheaper('Design a distributed system architecture for 10M users with real-time messaging', 'claude-opus');
console.log('\n=== Complex: architecture ===');
console.log('Tier:', r2.tier);
r2.alternatives.slice(0, 3).forEach(a => console.log('  →', a.model.id, 'save', a.savingsPct + '%'));

// Test 3: Auto-route
const r3 = mo.autoRoute('Review this code for SQL injection: SELECT * FROM users WHERE name=\'" + user + "\'', null, 'gpt-4o');
console.log('\n=== Auto-route: code review ===');
console.log('Tier:', r3.tier, '→', r3.model.id, '(' + r3.model.provider + ')');
if (r3.savings) console.log('Savings: $' + r3.savings.savedPer1M + '/1M vs ' + r3.savings.originalId);

// Test 4: Savings
console.log('\n=== Cumulative savings ===');
console.log(JSON.stringify(mo.getSavings(), null, 2));
