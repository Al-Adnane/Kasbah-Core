'use strict';

/**
 * Secret-leak detector. Returns { risk, threats, details }.
 *
 * Catches API keys for common providers, plus generic high-entropy tokens.
 * A single confirmed credential is a strong signal (risk 0.9). Entropy hints
 * alone are weaker (risk 0.3 each).
 */

const PROVIDERS = [
  // Cloud
  { rx: /\bAKIA[0-9A-Z]{16}\b/,                          label: 'aws-access-key',         w: 0.92 },
  { rx: /\b(AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b/,label: 'aws-key-type',           w: 0.92 },
  { rx: /-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----/, label: 'private-key-pem', w: 0.95 },
  { rx: /\bAIza[0-9A-Za-z_-]{35}\b/,                     label: 'google-api-key',         w: 0.90 },

  // Source
  { rx: /\bghp_[A-Za-z0-9]{36}\b/,                       label: 'github-pat',             w: 0.95 },
  { rx: /\bgho_[A-Za-z0-9]{36}\b/,                       label: 'github-oauth',           w: 0.95 },
  { rx: /\bglpat-[A-Za-z0-9_-]{20}\b/,                   label: 'gitlab-pat',             w: 0.92 },

  // Payments
  { rx: /\bsk_live_[A-Za-z0-9]{24,}\b/,                  label: 'stripe-live-key',        w: 0.95 },
  { rx: /\bsk_test_[A-Za-z0-9]{24,}\b/,                  label: 'stripe-test-key',        w: 0.65 },
  { rx: /\bpk_live_[A-Za-z0-9]{24,}\b/,                  label: 'stripe-publishable',     w: 0.45 },

  // AI providers
  { rx: /\bsk-[A-Za-z0-9_-]{40,}\b/,                     label: 'openai-key',             w: 0.85 },
  { rx: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,                 label: 'anthropic-key',          w: 0.92 },
  { rx: /\bxai-[A-Za-z0-9_-]{20,}\b/,                    label: 'xai-key',                w: 0.90 },

  // Kasbah
  { rx: /\bksk_[a-f0-9]{48}\b/,                          label: 'kasbah-key',             w: 0.95 },

  // Slack / Discord / Twilio
  { rx: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,              label: 'slack-token',            w: 0.90 },
  { rx: /\b(?:N|M)[A-Za-z\d]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}\b/, label: 'discord-bot-token', w: 0.88 },
  { rx: /\bAC[a-f0-9]{32}\b/,                            label: 'twilio-sid',             w: 0.65 },

  // Generic env-style leaks
  { rx: /\b(api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_/+=-]{24,}/i,
                                                          label: 'generic-env-key',        w: 0.55 },

  // Database connection strings with embedded credentials — high-confidence,
  // near-zero false-positive rate (ported from archived secret_guard.py, 2026-07)
  { rx: /\bpostgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/,  label: 'postgres-url',           w: 0.93 },
  { rx: /\bmysql:\/\/[^:\s]+:[^@\s]+@[^\s"']+/,            label: 'mysql-url',              w: 0.93 },
  { rx: /\bmongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/,label: 'mongodb-url',            w: 0.93 },
  { rx: /\bredis:\/\/[^:\s]*:[^@\s]+@[^\s"']+/,            label: 'redis-url',              w: 0.90 },

  // More provider tokens (same source)
  { rx: /\bsk-proj-[A-Za-z0-9_-]{50,100}\b/,               label: 'openai-project-key',     w: 0.90 },
  { rx: /\bsk-svcacct-[A-Za-z0-9_-]{50,100}\b/,            label: 'openai-service-key',     w: 0.90 },
  { rx: /\brk_live_[A-Za-z0-9]{24,}\b/,                    label: 'stripe-restricted-key',  w: 0.90 },
  { rx: /\bghu_[A-Za-z0-9]{36,}\b|\bghs_[A-Za-z0-9]{36,}\b|\bghr_[A-Za-z0-9]{36,}\b/, label: 'github-app-token', w: 0.92 },
  { rx: /\bnpm_[A-Za-z0-9]{36}\b/,                         label: 'npm-token',              w: 0.90 },
  { rx: /\bpypi-[A-Za-z0-9_-]{50,}\b/,                     label: 'pypi-token',             w: 0.90 },
  { rx: /\bshp(?:pa|ss|at)_[a-zA-Z0-9]{32,}\b/,            label: 'shopify-key',            w: 0.90 },
  { rx: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,    label: 'sendgrid-key',           w: 0.85 },
  { rx: /\bdop_v1_[A-Za-z0-9]{64,}\b/,                     label: 'digitalocean-token',     w: 0.90 },
  { rx: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]{9,11}\/[A-Z0-9]{9,11}\/[A-Za-z0-9]{24,}/,
                                                            label: 'slack-webhook',         w: 0.85 },
  { rx: /"type"\s*:\s*"service_account"/,                  label: 'gcp-service-account',    w: 0.90 },
  { rx: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]{88}/,
                                                            label: 'azure-storage-conn',     w: 0.93 },

  // Auth headers / misc tokens (ported from archived @kasbah/detector, 2026-07)
  { rx: /\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*/,            label: 'bearer-token',           w: 0.55 },
  { rx: /\bBasic\s+[A-Za-z0-9+/]{16,}=*/,                  label: 'basic-auth',             w: 0.55 },
  { rx: /\bya29\.[0-9A-Za-z_-]{20,}\b/,                    label: 'google-oauth-token',     w: 0.88 },
  { rx: /\bamqp:\/\/[^:\s]+:[^@\s]+@[^\s"']+/,             label: 'rabbitmq-url',           w: 0.90 }
];

// Safe-context markers that suppress a match — cuts false positives on
// example/test/placeholder text (ported from archived @kasbah/detector).
const _SAFE_CONTEXT = /(\/\/|#|\/\*|<!--)\s*example\b|\btest[_-]?key\b|\bfake[_-]?key\b|\bdummy[_-]?key\b|\bplaceholder\b|\byour[_-].*[_-]here\b|xxxx+/i;
function _inSafeContext(text, index, len) {
  const window = text.slice(Math.max(0, index - 40), Math.min(text.length, index + len + 40));
  return _SAFE_CONTEXT.test(window);
}

function _shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0; const n = s.length;
  for (const c in freq) { const p = freq[c] / n; h -= p * Math.log2(p); }
  return h;
}

function detect(text) {
  if (!text || typeof text !== 'string') return { risk: 0, threats: [], details: [] };
  const details = [];
  let combined = 0;
  for (const p of PROVIDERS) {
    const m = p.rx.exec(text);
    if (m && !_inSafeContext(text, m.index, m[0].length)) {
      details.push({ label: p.label, weight: p.w });
      combined = 1 - (1 - combined) * (1 - p.w);
    }
  }
  // Entropy heuristic on long alphanumeric runs
  const runs = text.match(/\b[A-Za-z0-9_/+=-]{32,}\b/g) || [];
  for (const r of runs.slice(0, 4)) {
    const h = _shannonEntropy(r);
    if (h > 4.5 && !details.find(d => d.run === r)) {
      details.push({ label: 'high-entropy-token', weight: 0.30, entropy: +h.toFixed(2), run: r.slice(0, 8) + '…' });
      combined = 1 - (1 - combined) * (1 - 0.30);
    }
  }
  return { risk: Math.min(1, combined), threats: details.map(d => d.label), details };
}

module.exports = { detect, PROVIDERS };
