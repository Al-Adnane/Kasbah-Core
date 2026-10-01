'use strict';

/**
 * PII detector. Returns { risk, threats, details, redacted }.
 *
 * Detects + counts: SSN, credit card (Luhn-validated), email, phone, IBAN,
 * SWIFT/BIC, IPv4. Optionally returns a redacted copy of the text.
 *
 * PII presence alone doesn't justify DENY (user may legitimately need to
 * paste an email). Risk scales with COUNT + TYPE: one email = 0.15,
 * SSN + card + phone = 0.65.
 */

const PATTERNS = [
  { rx: /\b\d{3}-?\d{2}-?\d{4}\b/g,                                        label: 'ssn',        replace: '[SSN_REDACTED]',   wEach: 0.45 },
  { rx: /\b(?:\d[ -]?){13,19}\b/g,                                         label: 'card',       replace: '[CARD_REDACTED]',  wEach: 0.40, luhn: true },
  { rx: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g,                                   label: 'email',      replace: '[EMAIL_REDACTED]', wEach: 0.15 },
  { rx: /\b(?:\+?\d{1,3}[ -]?)?(?:\(\d{3}\)|\d{3})[ -]?\d{3}[ -]?\d{4}\b/g,label: 'phone',      replace: '[PHONE_REDACTED]', wEach: 0.20 },
  { rx: /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/g,                                 label: 'iban',       replace: '[IBAN_REDACTED]',  wEach: 0.30 },
  { rx: /\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b/g,                          label: 'swift-bic',  replace: '[BIC_REDACTED]',   wEach: 0.20 },
  { rx: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,                                    label: 'ipv4',       replace: '[IP_REDACTED]',    wEach: 0.10 }
];

function _luhn(num) {
  const d = (num || '').replace(/[^\d]/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let s = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = +d[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    s += n; alt = !alt;
  }
  return s % 10 === 0;
}

function detect(text, opts = {}) {
  if (!text || typeof text !== 'string') return { risk: 0, threats: [], details: [], redacted: text };
  const details = [];
  let combined = 0;
  let redacted = text;
  for (const p of PATTERNS) {
    const matches = text.match(p.rx) || [];
    let valid = matches;
    if (p.luhn) valid = matches.filter(_luhn);
    if (valid.length) {
      details.push({ label: p.label, count: valid.length, weight: p.wEach });
      // each instance contributes diminishing-returns risk
      const layerW = 1 - Math.pow(1 - p.wEach, valid.length);
      combined = 1 - (1 - combined) * (1 - layerW);
      if (opts.redact !== false) redacted = redacted.replace(p.rx, (m) => (p.luhn && !_luhn(m)) ? m : p.replace);
    }
  }
  return {
    risk: Math.min(1, combined),
    threats: details.map(d => d.label),
    details,
    redacted
  };
}

module.exports = { detect, PATTERNS };
