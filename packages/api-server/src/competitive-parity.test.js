'use strict';
const assert = require('assert');
const bom = require('./ai-bom.js');
const nl = require('./nl-policy.js');

let n = 0;
function ok(name, fn) {
  try { fn(); n++; console.log('  ✓', name); }
  catch (e) { console.error('  ✗', name, e.message); process.exitCode = 1; }
}

console.log('ai-bom.js');
ok('always includes host endpoint', () => {
  const b = bom.build({ discovery: {}, policy: null });
  assert.ok(b.items.some((i) => i.kind === 'endpoint'));
  assert.strictEqual(b.spec, 'kasbah-ai-bom/v1');
});
ok('maps discovery models + mcp + keys', () => {
  const b = bom.build({
    discovery: {
      models: [{ name: 'gpt-4o', vendor: 'openai' }],
      mcpHosts: [{ name: 'claude-desktop' }],
      apiKeys: [{ label: 'OPENAI_API_KEY', provider: 'openai', source: 'env' }],
    },
    policy: { governance: { forbidden_verbs: ['EXEC'] }, metadata: { compliance_packs: ['SOC2'] } },
  });
  assert.ok(b.items.some((i) => i.kind === 'model'));
  assert.ok(b.items.some((i) => i.kind === 'mcp_host'));
  assert.ok(b.items.some((i) => i.kind === 'credential' && i.note === 'value redacted'));
  assert.ok(b.items.some((i) => i.kind === 'policy'));
  assert.ok(b.summary.total >= 4);
});

console.log('nl-policy.js');
ok('destructive text → forbidden verbs', () => {
  const r = nl.author('Never let the agent delete files or drop tables in production');
  assert.ok(r.policy.governance.forbidden_verbs.includes('DELETE_FILE'));
  assert.ok(r.policy.governance.require_approval.includes('DEPLOY'));
  assert.ok(r.reviewRequired === true);
});
ok('secrets + compliance packs', () => {
  const r = nl.author('Block access to secrets and API keys. Tag SOC2 and GDPR compliance.');
  assert.ok(r.policy.governance.forbidden_verbs.includes('ACCESS_SECRETS'));
  assert.ok((r.policy.metadata.compliance_packs || []).includes('SOC2'));
});
ok('unknown text stays reviewable draft', () => {
  const r = nl.author('hello world');
  assert.strictEqual(r.matches.length, 0);
  assert.ok(r.reviewRequired);
});

console.log(`\n${n} passed`);
