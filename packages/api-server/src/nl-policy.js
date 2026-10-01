'use strict';

/**
 * Natural-language policy authoring (F5 AI Guardrails parity).
 * Turns plain English into a .kasbahpolicy.json-shaped rule set, with
 * confidence and an explicit review flag — never silent policy mutation.
 */

const RULE_LIBRARY = [
  {
    id: 'block-delete',
    match: /\b(delete|destroy|wipe|rm|drop|purge)\b.{0,40}\b(files?|tables?|database|db|everything|all)\b/i,
    emit: (policy) => {
      policy.governance.forbidden_verbs = uniq([...(policy.governance.forbidden_verbs || []), 'DELETE_FILE', 'DROP_TABLE']);
    },
    why: 'Blocks destructive file/DB verbs',
    confidence: 0.92,
  },
  {
    id: 'block-exec',
    match: /\b(run|execute|eval|exec|shell|arbitrary code)\b/i,
    emit: (policy) => {
      policy.governance.forbidden_verbs = uniq([...(policy.governance.forbidden_verbs || []), 'EXEC', 'EVAL']);
    },
    why: 'Blocks arbitrary code execution',
    confidence: 0.88,
  },
  {
    id: 'block-secrets',
    match: /\b(secrets?|credentials?|api.?keys?|passwords?|private.?keys?|tokens?)\b/i,
    emit: (policy) => {
      policy.governance.forbidden_verbs = uniq([...(policy.governance.forbidden_verbs || []), 'ACCESS_SECRETS', 'EXFILTRATE_DATA']);
    },
    why: 'Blocks secret access and exfiltration',
    confidence: 0.9,
  },
  {
    id: 'block-root',
    match: /\b(root|sudo|privilege|admin access|escalat)/i,
    emit: (policy) => {
      policy.governance.forbidden_verbs = uniq([...(policy.governance.forbidden_verbs || []), 'ESCALATE_PRIVILEGE', 'RUN_AS_ROOT']);
    },
    why: 'Blocks privilege escalation',
    confidence: 0.87,
  },
  {
    id: 'require-approval-deploy',
    match: /\b(deploy|production|push code|ship|release|infra)\b/i,
    emit: (policy) => {
      policy.governance.require_approval = uniq([...(policy.governance.require_approval || []), 'DEPLOY', 'PUSH_CODE', 'MODIFY_INFRA']);
    },
    why: 'Requires human approval before deploy/infra',
    confidence: 0.85,
  },
  {
    id: 'allow-domain',
    match: /\b(?:only|allow|whitelist)\s+(?:domain|url|site)s?\s+([a-z0-9.,\s-]+\.[a-z]{2,})/i,
    emit: (policy, m) => {
      const domains = (m[1] || '').split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
      if (domains.length) {
        policy.governance.allowed_domains = uniq([...(policy.governance.allowed_domains || []), ...domains]);
      }
    },
    why: 'Adds allowlisted domains',
    confidence: 0.8,
  },
  {
    id: 'rate-limit',
    match: /\b(?:limit|rate.?limit|max)\s+(\d+)\s*(?:requests?|calls?|per minute|\/min)/i,
    emit: (policy, m) => {
      const n = Number(m[1] || 60);
      policy.governance.rate_limits = { READ_per_minute: n, WRITE_per_minute: Math.max(1, Math.floor(n / 10)) };
    },
    why: 'Sets rate limits',
    confidence: 0.78,
  },
  {
    id: 'pii-block',
    match: /\b(pii|gdpr|hipaa|ssn|credit.?card|personal data|customer data)\b/i,
    emit: (policy) => {
      policy.governance.forbidden_verbs = uniq([...(policy.governance.forbidden_verbs || []), 'EXFILTRATE_DATA']);
      policy.metadata = policy.metadata || {};
      policy.metadata.notes = ((policy.metadata.notes || '') + ' PII-sensitive policy.').trim();
    },
    why: 'Treats personal/sensitive data as high-risk',
    confidence: 0.83,
  },
  {
    id: 'compliance-pack',
    match: /\b(soc ?2|eu ai act|nist|owasp|iso ?27001|pci|hipaa|gdpr)\b/i,
    emit: (policy, m) => {
      policy.metadata = policy.metadata || {};
      const packs = new Set(policy.metadata.compliance_packs || []);
      const raw = (m[1] || '').toUpperCase().replace(/\s+/g, '');
      packs.add(raw === 'SOC2' ? 'SOC2' : raw);
      policy.metadata.compliance_packs = [...packs];
    },
    why: 'Tags compliance pack',
    confidence: 0.75,
  },
];

function uniq(arr) {
  return [...new Set((arr || []).filter(Boolean))];
}

function basePolicy() {
  return {
    version: '2.0.0',
    governance: {
      forbidden_verbs: [],
      allowed_domains: [],
      rate_limits: {},
      require_approval: [],
    },
    metadata: {
      org: 'kasbah',
      policy_owner: 'NL authoring',
      compliance_packs: [],
      notes: 'Generated from natural language — review before apply.',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      source: 'nl-policy',
    },
    _nl: { reviewRequired: true, matches: [] },
  };
}

/**
 * @param {string} text — natural language policy intent
 * @param {object} [existing] — optional current policy to merge into
 * @returns {{ policy, matches, reviewRequired, confidence }}
 */
function author(text, existing = null) {
  const src = String(text || '').trim();
  const policy = existing
    ? JSON.parse(JSON.stringify(existing))
    : basePolicy();
  policy.governance = policy.governance || { forbidden_verbs: [], allowed_domains: [], rate_limits: {}, require_approval: [] };
  policy.metadata = policy.metadata || {};
  policy.metadata.updated_at = new Date().toISOString();

  const matches = [];
  for (const rule of RULE_LIBRARY) {
    const m = src.match(rule.match);
    if (!m) continue;
    rule.emit(policy, m);
    matches.push({ id: rule.id, why: rule.why, confidence: rule.confidence, excerpt: m[0].slice(0, 80) });
  }

  policy._nl = {
    reviewRequired: true,
    matches,
    sourceText: src.slice(0, 500),
    generatedAt: new Date().toISOString(),
  };

  return {
    policy,
    matches,
    reviewRequired: true,
    confidence: matches.length
      ? +(matches.reduce((a, b) => a + b.confidence, 0) / matches.length).toFixed(3)
      : 0,
    note: matches.length
      ? 'Draft policy ready — apply only after human review.'
      : 'No known rule patterns matched. Add explicit verbs/domains or edit JSON.',
  };
}

module.exports = { author, RULE_LIBRARY };
