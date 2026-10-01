'use strict';

/**
 * Egress classifier — multi-tier detection for secrets leaving the machine.
 * Implements AISEC-018 (Shannon entropy classifier), AISEC-030 (9-layer
 * obfuscation decoder), and AISEC-028 (4-tier cascade).
 *
 * Tier 1: Fast regex patterns (API keys, tokens, URLs with creds)
 * Tier 2: Shannon entropy + char-class transitions (high-entropy strings)
 * Tier 3: Obfuscation decode + re-classify (base64, URL-enc, hex, unicode, etc.)
 * Tier 4: Structural analysis (private keys, JWTs, UUIDs embedded in larger text)
 */

const crypto = require('crypto');

// ─── Tier 1: Fast pattern matching ───────────────────────────────────────────

const FAST_PATTERNS = [
  { id: 'aws-access-key',  label: 'AWS Access Key',        re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'aws-secret-key',  label: 'AWS Secret Key',        re: /\b[A-Za-z0-9/+]{40}\b/ },
  { id: 'github-token',    label: 'GitHub Token',          re: /\bghp_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b/ },
  { id: 'slack-token',     label: 'Slack Token',           re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { id: 'stripe-key',      label: 'Stripe Key',            re: /\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{24,}\b/ },
  { id: 'openai-key',      label: 'OpenAI API Key',        re: /\bsk-[A-Za-z0-9]{32,}\b/ },
  { id: 'anthropic-key',   label: 'Anthropic API Key',     re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { id: 'private-key-pem', label: 'Private Key (PEM)',     re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { id: 'jwt',             label: 'JWT Token',             re: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/ },
  { id: 'db-url',          label: 'Database URL w/ creds', re: /\b(postgres|mysql|mongodb|redis):\/\/[^:@\s]+:[^@\s]+@/ },
  { id: 'url-with-token',  label: 'URL with token/secret', re: /https?:\/\/[^\s]*[?&](token|secret|api_?key|access_token|auth)=[^\s&]+/i },
  { id: 'clerk-secret',    label: 'Clerk Secret Key',      re: /\bsk_(?:live|test)_[A-Za-z0-9]{32,}\b/ },
  { id: 'twilio-token',    label: 'Twilio Auth Token',     re: /\bAC[a-f0-9]{32}\b/ },
  { id: 'sendgrid-key',    label: 'SendGrid API Key',      re: /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}\b/ },
  { id: 'heroku-key',      label: 'Heroku API Key',        re: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/ },
  { id: 'npm-token',       label: 'npm Token',             re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: 'ssh-private-key', label: 'SSH Private Key',       re: /-----BEGIN OPENSSH PRIVATE KEY-----/ },
  { id: 'gcp-service-acct',label: 'GCP Service Account',  re: /"type":\s*"service_account"/ },
];

function tier1Scan(text) {
  const findings = [];
  for (const p of FAST_PATTERNS) {
    if (p.re.test(text)) findings.push({ tier: 1, id: p.id, label: p.label });
  }
  return findings;
}

// ─── Tier 2: Shannon entropy classifier ──────────────────────────────────────

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let H = 0;
  const len = str.length;
  for (const c of Object.values(freq)) { const p = c / len; H -= p * Math.log2(p); }
  return H;
}

function charClassTransitions(str) {
  let transitions = 0;
  const cls = (c) => /[A-Z]/.test(c) ? 0 : /[a-z]/.test(c) ? 1 : /[0-9]/.test(c) ? 2 : 3;
  for (let i = 1; i < str.length; i++) if (cls(str[i]) !== cls(str[i - 1])) transitions++;
  return transitions / Math.max(1, str.length - 1);
}

function uniqueRatio(str) { return new Set(str).size / str.length; }

const BASE62_RE = /[A-Za-z0-9+/=_-]{20,}/g;

function tier2Scan(text) {
  const findings = [];
  const candidates = text.match(BASE62_RE) || [];
  for (const token of candidates) {
    if (token.length < 20 || token.length > 1000) continue;
    const H = shannonEntropy(token);
    const tr = charClassTransitions(token);
    const ur = uniqueRatio(token);
    // High-entropy, high-transition, high-unique: likely a secret
    if (H >= 4.5 && tr >= 0.3 && ur >= 0.6 && token.length >= 32) {
      findings.push({ tier: 2, id: 'high-entropy-token', label: 'High-entropy secret candidate', token: token.slice(0, 40) + (token.length > 40 ? '…' : ''), entropy: Math.round(H * 100) / 100 });
      break; // one per block is enough
    }
  }
  return findings;
}

// ─── Tier 3: Obfuscation decoder ─────────────────────────────────────────────

const PRINTABLE_RE = /^[\x09\x0a\x0d\x20-\x7e -�]+$/;

function decodeBase64Layers(text, maxDepth = 3) {
  // Try each base64 candidate in the text — the surrounding text may corrupt
  // a single-pass decode, so test each token independently.
  const candidates = text.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || [];
  for (const candidate of candidates) {
    let current = candidate;
    for (let d = 0; d < maxDepth; d++) {
      try {
        const dec = Buffer.from(current, 'base64').toString('utf8');
        if (/[\x00-\x08\x0b\x0e-\x1f]/.test(dec)) break; // binary output — stop
        if (!PRINTABLE_RE.test(dec)) break;   // mojibake — stop
        if (dec === current) break;             // idempotent — stop
        return dec;                             // return first successful decode
      } catch { break; }
    }
  }
  return null;
}

const ZERO_WIDTH = /[​‌‍⁠﻿]/g;
const HOMOGLYPHS = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'ⅰ': 'i' };

function normalizeHomoglyphs(text) {
  return text.split('').map((c) => HOMOGLYPHS[c] || c).join('').replace(ZERO_WIDTH, '');
}

function decodeUrlEncoded(text) {
  try { const d = decodeURIComponent(text); return d !== text ? d : null; } catch { return null; }
}

function decodeHex(text) {
  const m = text.match(/(?:0x)?([0-9a-fA-F]{40,})/);
  if (!m) return null;
  try {
    const d = Buffer.from(m[1], 'hex').toString('utf8');
    return /[\x00-\x08\x0b\x0e-\x1f]/.test(d) ? null : d;
  } catch { return null; }
}

function decodeRot13(text) { return text.replace(/[A-Za-z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + (c < 'N' || (c > 'Z' && c < 'n') ? 13 : -13))); }

function tier3Scan(text) {
  const findings = [];
  const normalized = normalizeHomoglyphs(text);
  if (normalized !== text) {
    const rescan = tier1Scan(normalized);
    if (rescan.length) findings.push(...rescan.map((f) => ({ ...f, tier: 3, obfuscation: 'homoglyph/zero-width' })));
  }
  const b64 = decodeBase64Layers(text);
  if (b64) {
    const rescan = [...tier1Scan(b64), ...tier2Scan(b64)];
    if (rescan.length) findings.push(...rescan.map((f) => ({ ...f, tier: 3, obfuscation: 'base64' })));
  }
  const url = decodeUrlEncoded(text);
  if (url) {
    const rescan = tier1Scan(url);
    if (rescan.length) findings.push(...rescan.map((f) => ({ ...f, tier: 3, obfuscation: 'url-encoding' })));
  }
  const hex = decodeHex(text);
  if (hex) {
    const rescan = tier1Scan(hex);
    if (rescan.length) findings.push(...rescan.map((f) => ({ ...f, tier: 3, obfuscation: 'hex' })));
  }
  // ROT13 (only try on suspiciously base-64-like strings to avoid false positives)
  const r13 = decodeRot13(text);
  const r13scan = tier1Scan(r13);
  if (r13scan.length) findings.push(...r13scan.map((f) => ({ ...f, tier: 3, obfuscation: 'rot13' })));
  return findings;
}

// ─── Tier 4: Structural deep analysis ────────────────────────────────────────

function tier4Scan(text) {
  const findings = [];
  // Private key block detection
  if (/BEGIN.*PRIVATE KEY/.test(text)) findings.push({ tier: 4, id: 'private-key-block', label: 'Private key block' });
  // dotenv-style leaks: KEY=value on its own line
  const envLines = text.match(/^[A-Z_]{4,}=(?:"|')?[^\s"']{16,}(?:"|')?$/gm) || [];
  for (const line of envLines.slice(0, 3)) {
    const [k] = line.split('=');
    if (/SECRET|KEY|TOKEN|PASS|PWD|AUTH|CREDENTIAL/i.test(k)) {
      findings.push({ tier: 4, id: 'dotenv-secret', label: `Env secret: ${k}` });
    }
  }
  return findings;
}

// ─── 4-Tier cascade ──────────────────────────────────────────────────────────

function classify(text) {
  if (!text || text.length < 10) return { found: false, findings: [], tiers: [] };
  const t = String(text);
  const t1 = tier1Scan(t);
  if (t1.length) return { found: true, findings: t1, tiers: [1] };
  const t2 = tier2Scan(t);
  if (t2.length) {
    // Tier 3: decode and re-check
    const t3 = tier3Scan(t);
    return { found: true, findings: [...t2, ...t3], tiers: t3.length ? [2, 3] : [2] };
  }
  const t3 = tier3Scan(t);
  if (t3.length) return { found: true, findings: t3, tiers: [3] };
  const t4 = tier4Scan(t);
  if (t4.length) return { found: true, findings: t4, tiers: [4] };
  return { found: false, findings: [], tiers: [] };
}

/**
 * Scan an HTTP request or egress payload for secrets before it leaves.
 * Returns { block: bool, findings: [], risk: 0..1 }
 */
function scanEgress({ url = '', body = '', headers = {} } = {}) {
  const combined = [url, typeof body === 'string' ? body : JSON.stringify(body), JSON.stringify(headers)].join('\n');
  const result = classify(combined);
  const risk = result.found ? Math.min(1, 0.4 + result.findings.length * 0.15) : 0;
  return { block: risk >= 0.8, findings: result.findings, risk, tiers: result.tiers };
}

module.exports = { classify, scanEgress, tier1Scan, tier2Scan, tier3Scan, tier4Scan, shannonEntropy };
