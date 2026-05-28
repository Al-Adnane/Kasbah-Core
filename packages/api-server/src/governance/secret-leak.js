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
                                                          label: 'generic-env-key',        w: 0.55 }
];

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
    if (p.rx.test(text)) {
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
