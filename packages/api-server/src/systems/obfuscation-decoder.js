'use strict';

const COMMON_WORDS = new Set([
  'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have',
  'i', 'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you',
  'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they',
  'we', 'say', 'her', 'she', 'or', 'an', 'will', 'my', 'one',
  'all', 'would', 'there', 'their', 'what', 'so', 'up', 'out',
  'if', 'about', 'who', 'get', 'which', 'go', 'me', 'when',
  'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know',
  'take', 'people', 'into', 'year', 'your', 'good', 'some',
  'could', 'them', 'see', 'other', 'than', 'then', 'now',
  'look', 'only', 'come', 'its', 'over', 'think', 'also',
  'back', 'after', 'use', 'two', 'how', 'our', 'work',
  'first', 'well', 'way', 'even', 'new', 'want', 'because',
  'any', 'these', 'give', 'day', 'most', 'us', 'is', 'was',
  'hello', 'world', 'test', 'text', 'example', 'ignore', 'previous', 'instructions',
  'understand', 'system', 'user', 'are', 'been', 'has', 'having', 'may',
  'much', 'only', 'own', 'same', 'should', 'such', 'than', 'too',
]);

const HOMOGLYPHS = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'r',
  'ο': 'o', 'α': 'a', 'ε': 'e',
  '–': '-', '—': '-',
  'ｒ': 'r', 'ｍ': 'm', 'ｆ': 'f',
};

function looksLikeEnglish(text) {
  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  const commonWordCount = words.filter(w => COMMON_WORDS.has(w.replace(/[^a-z]/g, ''))).length;
  return commonWordCount >= Math.ceil(words.length * 0.3); // At least 30% common words
}

function normalizeHomoglyphs(text) {
  return text.split('').map(c => HOMOGLYPHS[c] || c).join('');
}

function stripZeroWidth(text) {
  return text.replace(/[​‌‍﻿⁠]/g, '');
}

function rot13(text) {
  return text.replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

function tryBase64(text) {
  const b64Pattern = /[A-Za-z0-9+/]{8,500}={0,2}/g;
  const decoded = [];
  let m;
  while ((m = b64Pattern.exec(text)) !== null) {
    try {
      const d = Buffer.from(m[0], 'base64').toString('utf8');
      if (/^[\x20-\x7E\n\r\t]+$/.test(d)) decoded.push(d);
    } catch (_) {}
  }
  return decoded;
}

function tryUrlDecode(text) {
  try {
    const d = decodeURIComponent(text);
    return d !== text ? [d] : [];
  } catch (_) { return []; }
}

function tryUnicodeEscape(text) {
  try {
    const d = text.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    return d !== text ? [d] : [];
  } catch (_) { return []; }
}

function tryHex(text) {
  const hexPattern = /(?:0x)?([0-9a-fA-F]{2}){4,}/g;
  const decoded = [];
  let m;
  while ((m = hexPattern.exec(text)) !== null) {
    try {
      const hex = m[0].replace(/^0x/i, '');
      const d = Buffer.from(hex, 'hex').toString('utf8');
      if (/^[\x20-\x7E]+$/.test(d) && d.length >= 4) decoded.push(d);
    } catch (_) {}
  }
  return decoded;
}

function deepDecode(text) {
  if (text == null || typeof text !== 'string') {
    return { decodedForms: [], layers: [], threatFound: false };
  }
  const forms = new Set([text]);
  const layers = [];

  const zw = stripZeroWidth(text);
  if (zw !== text) { forms.add(zw); layers.push('zero_width'); }

  const hg = normalizeHomoglyphs(text);
  if (hg !== text) { forms.add(hg); layers.push('homoglyph'); }
  const hgZw = normalizeHomoglyphs(zw);
  if (hgZw !== hg) forms.add(hgZw);

  const urlDecoded = tryUrlDecode(text);
  if (urlDecoded.length) { urlDecoded.forEach(d => forms.add(d)); layers.push('url_encode'); }

  const uniDecoded = tryUnicodeEscape(text);
  if (uniDecoded.length) { uniDecoded.forEach(d => forms.add(d)); layers.push('unicode_escape'); }

  const b64Decoded = tryBase64(text);
  if (b64Decoded.length) { b64Decoded.forEach(d => forms.add(d)); layers.push('base64'); }

  const hexDecoded = tryHex(text);
  if (hexDecoded.length) { hexDecoded.forEach(d => forms.add(d)); layers.push('hex'); }

  // Apply ROT13 if we've found other obfuscation
  // For suspiciously-alpha-only text, we'll TRY ROT13 for analysis, but won't flag it as a threat on its own
  const alphaRatio = (text.match(/[a-zA-Z]/g) || []).length / (text.length || 1);
  const shouldTryRot13 = layers.length > 0 || (alphaRatio > 0.85 && /^[a-z\s]+$/i.test(text) && !looksLikeEnglish(text));
  if (shouldTryRot13) {
    const r13 = rot13(text);
    if (r13 !== text) { forms.add(r13); layers.push('rot13'); }
  }

  // Apply reversal only if we've already found other obfuscation layers
  if (layers.length > 0 && text.length <= 100) {
    const reversed = text.split('').reverse().join('');
    if (reversed !== text) { forms.add(reversed); layers.push('reversal'); }
  }

  const substantiveLayers = layers.filter(l => !['rot13', 'reversal'].includes(l));
  const threatFound = substantiveLayers.length > 0;

  return {
    decodedForms: [...forms],
    layers: [...new Set(layers)],
    threatFound,
  };
}

function normalizeForDetection(text) {
  return normalizeHomoglyphs(stripZeroWidth(text));
}

const EXPANDED_SECRET_PATTERNS = [
  { re: /-----BEGIN PGP PRIVATE KEY BLOCK-----/i,           type: 'pgp_private_key',      severity: 'CRITICAL' },
  { re: /redis:\/\/[^:@\s]*:[^@\s]+@[^\s]+/i,              type: 'redis_uri_with_creds', severity: 'CRITICAL' },
  { re: /mysql:\/\/[^:@\s]+:[^@\s]+@[^\s]+/i,              type: 'mysql_uri_with_creds', severity: 'CRITICAL' },
  { re: /postgresql:\/\/[^:@\s]+:[^@\s]+@[^\s]+/i,         type: 'postgres_uri',         severity: 'CRITICAL' },
  { re: /mongodb(?:\+srv)?:\/\/[^:@\s]+:[^@\s]+@[^\s]+/i,  type: 'mongodb_uri',          severity: 'CRITICAL' },
  { re: /npm_[a-zA-Z0-9]{36}/,                              type: 'npm_token',            severity: 'HIGH' },
  { re: /"private_key_id"\s*:\s*"[a-f0-9]{40}"/,           type: 'firebase_sa_key',      severity: 'HIGH' },
  { re: /SK[a-z0-9]{32}/,                                   type: 'twilio_auth_token',    severity: 'HIGH' },
  { re: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/,        type: 'sendgrid_key',         severity: 'HIGH' },
  { re: /"sensitive"\s*:\s*true/,                           type: 'terraform_sensitive',  severity: 'MEDIUM' },
];

function expandedSecretScan(text) {
  if (text == null || typeof text !== 'string') return { found: false, count: 0, secrets: [] };
  const found = [];
  for (const p of EXPANDED_SECRET_PATTERNS) {
    if (p.re.test(text)) found.push({ type: p.type, severity: p.severity });
  }
  return { found: found.length > 0, count: found.length, secrets: found };
}

module.exports = { deepDecode, normalizeForDetection, expandedSecretScan, EXPANDED_SECRET_PATTERNS };
