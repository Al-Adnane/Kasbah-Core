'use strict';
/**
 * Multilingual PII Detection Engine — regex-based PII scanner for 100+ languages/scripts
 * Ported from ARCHIVE/kasbah-core/core/frontier/multilingual_pii.py
 */

// ── Unicode script ranges ──────────────────────────────────────────────────────
const SCRIPT_RANGES = {
  arabic:     [[0x0600, 0x06FF], [0x0750, 0x077F], [0xFB50, 0xFDFF], [0xFE70, 0xFEFF]],
  cjk:        [[0x4E00, 0x9FFF], [0x3400, 0x4DBF], [0x20000, 0x2A6DF], [0x3000, 0x303F], [0xFF00, 0xFFEF]],
  cyrillic:   [[0x0400, 0x04FF], [0x0500, 0x052F]],
  devanagari: [[0x0900, 0x097F]],
  thai:       [[0x0E00, 0x0E7F]],
  hangul:     [[0xAC00, 0xD7AF], [0x1100, 0x11FF], [0x3130, 0x318F]],
  hebrew:     [[0x0590, 0x05FF], [0xFB00, 0xFB4F]],
  georgian:   [[0x10A0, 0x10FF]],
  armenian:   [[0x0530, 0x058F]],
  ethiopic:   [[0x1200, 0x137F]],
  myanmar:    [[0x1000, 0x109F]],
  khmer:      [[0x1780, 0x17FF]],
  lao:        [[0x0E80, 0x0EFF]],
  tibetan:    [[0x0F00, 0x0FFF]],
  sinhala:    [[0x0D80, 0x0DFF]],
  tamil:      [[0x0B80, 0x0BFF]],
  telugu:     [[0x0C00, 0x0C7F]],
  kannada:    [[0x0C80, 0x0CFF]],
  malayalam:  [[0x0D00, 0x0D7F]],
  bengali:    [[0x0980, 0x09FF]],
};

function detectScripts(text) {
  const counts = {};
  for (const char of text) {
    const cp = char.codePointAt(0);
    for (const [script, ranges] of Object.entries(SCRIPT_RANGES)) {
      for (const [lo, hi] of ranges) {
        if (cp >= lo && cp <= hi) {
          counts[script] = (counts[script] || 0) + 1;
          break;
        }
      }
    }
  }
  const threshold = Math.max(2, text.length * 0.005);
  const detected = Object.entries(counts)
    .filter(([, c]) => c >= threshold)
    .map(([s]) => s);
  if (detected.length === 0 && text.trim().length > 0) return ['latin'];
  return detected.length ? detected : ['unknown'];
}

// ── Checksum validators ────────────────────────────────────────────────────────

// Context-aware validators (receive raw match, full text, and match index).
// Added 2026-07 to cut false positives measured on bench/detection-scorecard:
// bare digit/date/alnum runs matching phone/DOB/national-id patterns inside
// UUIDs, invoice numbers, order dates, and product SKUs. See CHANGELOG.md.

// A bare ISO date (YYYY-MM-DD) is only PII when it plausibly denotes a birth
// date: either a birth-context cue precedes it (DOB/born/geboren/생년월일…) or
// the year is old enough to be a birth year rather than a transaction date.
function dobContextValid(raw, text, idx) {
  if (typeof text !== 'string' || typeof idx !== 'number') return true; // no context → keep prior behavior
  const before = text.slice(Math.max(0, idx - 24), idx).toLowerCase();
  const cue = /\b(dob|d\.o\.b|birth|born|geboren|née?|nacim|생년|生年月日|生年)\b/.test(before);
  const year = parseInt(raw.slice(0, 4), 10);
  // Birth years: plausibly up to ~13 years ago. Transaction/order dates are recent.
  const plausibleBirthYear = Number.isFinite(year) && year <= (new Date().getFullYear() - 13);
  return cue || plausibleBirthYear;
}

// Reject a match that is immediately preceded by a product/reference-code cue —
// these formats (2 letters + 6 digits, etc.) collide with SKUs/part numbers.
function notProductCode(raw, text, idx) {
  if (typeof text !== 'string' || typeof idx !== 'number') return true;
  const before = text.slice(Math.max(0, idx - 12), idx).toLowerCase();
  return !/\b(sku|part|item|model|ref|order|batch|lot|serial)\s*[:#]?\s*$/.test(before);
}

// A 16-digit run preceded by a payment-card cue is a card (handled by the CARD
// detector + Luhn), not an Indonesian KTP national ID — reject the national-id
// interpretation to avoid double/false labelling.
function notPaymentCard(raw, text, idx) {
  if (typeof text !== 'string' || typeof idx !== 'number') return true;
  const before = text.slice(Math.max(0, idx - 12), idx).toLowerCase();
  return !/\b(card|cc|credit|debit|visa|mastercard|amex)\b\s*[:#]?\s*$/.test(before);
}

function luhnValid(number) {
  const digits = number.replace(/\D/g, '').split('').map(Number);
  if (digits.length < 9) return false;
  let total = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits[digits.length - 1 - i];
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
  }
  return total % 10 === 0;
}

function usSsnValid(ssn) {
  const d = ssn.replace(/\D/g, '');
  if (d.length !== 9) return false;
  const area = d.slice(0, 3), group = d.slice(3, 5), serial = d.slice(5);
  // SSA structural rules — reject the ranges never issued (also kills most
  // false positives from arbitrary 3-2-4 digit runs).
  if (area === '000' || area === '666' || area[0] === '9') return false;
  if (group === '00') return false;
  if (serial === '0000') return false;
  return true;
}

function mod97Valid(iban) {
  iban = iban.replace(/\s/g, '').toUpperCase();
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let numeric = '';
  for (const ch of rearranged) {
    if (/\d/.test(ch)) {
      numeric += ch;
    } else if (/[A-Z]/.test(ch)) {
      numeric += (ch.charCodeAt(0) - 65 + 10).toString();
    } else {
      return false;
    }
  }
  // BigInt mod for large numbers
  let remainder = 0n;
  for (const digit of numeric) {
    remainder = (remainder * 10n + BigInt(digit)) % 97n;
  }
  return remainder === 1n;
}

function egyptNidValid(nid) {
  const digits = nid.replace(/\D/g, '');
  if (digits.length !== 14) return false;
  const centuryCode = parseInt(digits[0], 10);
  if (centuryCode !== 2 && centuryCode !== 3) return false;
  const governorate = parseInt(digits.slice(7, 9), 10);
  return governorate >= 1 && governorate <= 35;
}

function southKoreanRrnValid(rrn) {
  const digits = rrn.replace(/[-\s]/g, '');
  if (digits.length !== 13) return false;
  const weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
  let total = 0;
  for (let i = 0; i < 12; i++) total += parseInt(digits[i], 10) * weights[i];
  const check = (11 - (total % 11)) % 10;
  return check === parseInt(digits[12], 10);
}

function aadhaarVerhoeff(number) {
  const D = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
  ];
  const P = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],
    [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],
    [7,0,4,6,9,1,3,2,5,8],
  ];
  const digits = number.replace(/\D/g, '');
  if (digits.length !== 12) return false;
  let c = 0;
  const rev = digits.split('').reverse();
  for (let i = 0; i < rev.length; i++) {
    const p = P[i % 8][parseInt(rev[i], 10)];
    c = D[c][p];
  }
  return c === 0;
}

// ── PII pattern definitions ────────────────────────────────────────────────────

const PII_PATTERNS = [
  // Arabic / MENA
  { id: 'EG_NID',        type: 'national_id',     language: 'Arabic/Egyptian', script: 'arabic',     region: 'EG', regex: /\b[23]\d{13}\b/g,                                    validator: egyptNidValid,       confidence: 0.92 },
  { id: 'SA_IQAMA',      type: 'national_id',     language: 'Arabic/Saudi',    script: 'arabic',     region: 'SA', regex: /\b[12]\d{9}\b/g,                                      validator: null,                confidence: 0.80 },
  { id: 'UAE_ID',        type: 'national_id',     language: 'Arabic/UAE',      script: 'arabic',     region: 'AE', regex: /\b784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d\b/g,            validator: null,                confidence: 0.90 },
  { id: 'MA_CIN',        type: 'national_id',     language: 'Arabic/Moroccan', script: 'arabic',     region: 'MA', regex: /\b[A-Z]{1,2}\d{5,6}\b/g,                             validator: notProductCode,      confidence: 0.75 },
  { id: 'JO_NID',        type: 'national_id',     language: 'Arabic/Jordanian',script: 'arabic',     region: 'JO', regex: /\b\d{10}\b(?=\D|$)/g,                                validator: null,                confidence: 0.70 },
  { id: 'KW_CID',        type: 'national_id',     language: 'Arabic/Kuwaiti',  script: 'arabic',     region: 'KW', regex: /\b[12]\d{11}\b/g,                                    validator: null,                confidence: 0.80 },
  { id: 'IQ_NID',        type: 'national_id',     language: 'Arabic/Iraqi',    script: 'arabic',     region: 'IQ', regex: /\b\d{14}\b/g,                                         validator: null,                confidence: 0.65 },
  { id: 'TN_CIN',        type: 'national_id',     language: 'Arabic/Tunisian', script: 'arabic',     region: 'TN', regex: /\b[01]\d{7}\b/g,                                     validator: null,                confidence: 0.75 },
  { id: 'DZ_NID',        type: 'national_id',     language: 'Arabic/Algerian', script: 'arabic',     region: 'DZ', regex: /\b\d{18}\b/g,                                         validator: null,                confidence: 0.68 },
  { id: 'TR_KIMLIK',     type: 'national_id',     language: 'Turkish',         script: 'latin',      region: 'TR', regex: /\b[1-9]\d{10}\b/g,                                   validator: null,                confidence: 0.82 },
  { id: 'PK_CNIC',       type: 'national_id',     language: 'Urdu/Pakistani',  script: 'devanagari', region: 'PK', regex: /\b\d{5}-\d{7}-\d\b/g,                               validator: null,                confidence: 0.93 },
  { id: 'PK_CNIC_NS',    type: 'national_id',     language: 'Urdu/Pakistani',  script: 'devanagari', region: 'PK', regex: /\b\d{13}\b/g,                                         validator: null,                confidence: 0.75 },

  // South Asian
  { id: 'IN_AADHAAR',    type: 'national_id',     language: 'Hindi/Indian',    script: 'devanagari', region: 'IN', regex: /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g,            validator: aadhaarVerhoeff,     confidence: 0.93 },
  { id: 'IN_PAN',        type: 'tax_id',          language: 'Hindi/Indian',    script: 'latin',      region: 'IN', regex: /\b[A-Z]{5}\d{4}[A-Z]\b/g,                           validator: null,                confidence: 0.92 },
  { id: 'IN_VOTER',      type: 'national_id',     language: 'Hindi/Indian',    script: 'latin',      region: 'IN', regex: /\b[A-Z]{3}\d{7}\b/g,                                 validator: null,                confidence: 0.80 },
  { id: 'IN_DL',         type: 'driver_license',  language: 'Hindi/Indian',    script: 'latin',      region: 'IN', regex: /\b[A-Z]{2}\d{2}[\s-]?\d{4}[\s-]?\d{7}\b/g,         validator: null,                confidence: 0.85 },
  { id: 'BD_NID',        type: 'national_id',     language: 'Bengali',         script: 'bengali',    region: 'BD', regex: /\b\d{10}(?:\d{7})?\b/g,                             validator: null,                confidence: 0.70 },
  { id: 'LK_NIC',        type: 'national_id',     language: 'Sinhala',         script: 'sinhala',    region: 'LK', regex: /\b(?:\d{9}[VX]|\d{12})\b/g,                        validator: null,                confidence: 0.88 },
  { id: 'NP_CITID',      type: 'national_id',     language: 'Nepali',          script: 'devanagari', region: 'NP', regex: /\b\d{2}-\d{2}-\d{2}-\d{5}\b/g,                     validator: null,                confidence: 0.88 },

  // CJK
  { id: 'CN_RIC',        type: 'national_id',     language: 'Chinese',         script: 'cjk',        region: 'CN', regex: /\b\d{17}[\dX]\b/g,                                  validator: null,                confidence: 0.90 },
  { id: 'CN_RESIDENT',   type: 'national_id',     language: 'Chinese',         script: 'cjk',        region: 'CN', regex: /(?:身份证|居民身份证|ID卡)[\s:：]*\d{15,18}/g,        validator: null,                confidence: 0.95 },
  { id: 'JP_MYNUMBER',   type: 'national_id',     language: 'Japanese',        script: 'cjk',        region: 'JP', regex: /(?:マイナンバー|個人番号)[\s:：]*\d{12}/g,           validator: null,                confidence: 0.96 },
  { id: 'JP_MYNUMBER_B', type: 'national_id',     language: 'Japanese',        script: 'cjk',        region: 'JP', regex: /(?<![\w-])\d{12}(?![\w-])/g,                            validator: null,                confidence: 0.65 },
  { id: 'KR_RRN',        type: 'national_id',     language: 'Korean',          script: 'hangul',     region: 'KR', regex: /\b\d{6}-[1-4]\d{6}\b/g,                             validator: southKoreanRrnValid, confidence: 0.95 },
  { id: 'KR_RRN_LABEL',  type: 'national_id',     language: 'Korean',          script: 'hangul',     region: 'KR', regex: /(?:주민등록번호|주민번호)[\s:：]*\d{6}-[1-4]\d{6}/g, validator: null,                confidence: 0.98 },
  { id: 'TW_NID',        type: 'national_id',     language: 'Chinese/Taiwanese',script: 'cjk',       region: 'TW', regex: /\b[A-Z]\d{9}\b/g,                                   validator: null,                confidence: 0.85 },
  { id: 'HK_HKID',       type: 'national_id',     language: 'Chinese/HK',      script: 'cjk',        region: 'HK', regex: /\b[A-Z]{1,2}\d{6}[\dA]\b/g,                        validator: null,                confidence: 0.87 },
  { id: 'SG_NRIC',       type: 'national_id',     language: 'English/Singaporean', script: 'latin',  region: 'SG', regex: /\b[STFGM]\d{7}[A-Z]\b/g,                           validator: null,                confidence: 0.90 },
  { id: 'MY_NRIC',       type: 'national_id',     language: 'Malay',           script: 'latin',      region: 'MY', regex: /\b\d{6}-\d{2}-\d{4}\b/g,                            validator: null,                confidence: 0.92 },
  { id: 'TH_NID',        type: 'national_id',     language: 'Thai',            script: 'thai',       region: 'TH', regex: /\b\d[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d\b/g, validator: null,                confidence: 0.88 },
  { id: 'ID_KTP',        type: 'national_id',     language: 'Indonesian',      script: 'latin',      region: 'ID', regex: /\b\d{16}\b/g,                                         validator: notPaymentCard,      confidence: 0.72 },
  { id: 'PH_SSS',        type: 'social_security', language: 'Filipino',        script: 'latin',      region: 'PH', regex: /\b\d{2}-\d{7}-\d\b/g,                               validator: null,                confidence: 0.88 },

  // European / Global
  { id: 'IBAN_GLOBAL',   type: 'iban',            language: 'Global',          script: 'latin',      region: 'GLOBAL', regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b/g, validator: mod97Valid, confidence: 0.90 },
  { id: 'CREDIT_CARD',   type: 'credit_card',     language: 'Global',          script: 'latin',      region: 'GLOBAL', regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, validator: luhnValid, confidence: 0.92 },
  { id: 'US_SSN',        type: 'social_security', language: 'English',         script: 'latin',      region: 'US', regex: /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/g,                   validator: usSsnValid,          confidence: 0.90 },
  { id: 'RU_SNILS',      type: 'social_security', language: 'Russian',         script: 'cyrillic',   region: 'RU', regex: /\b\d{3}-\d{3}-\d{3}[\s-]\d{2}\b/g,                 validator: null,                confidence: 0.88 },
  { id: 'RU_INN',        type: 'tax_id',          language: 'Russian',         script: 'cyrillic',   region: 'RU', regex: /\b\d{10}(?:\d{2})?\b/g,                             validator: null,                confidence: 0.70 },
  { id: 'IL_TEUDAT',     type: 'national_id',     language: 'Hebrew',          script: 'hebrew',     region: 'IL', regex: /\b\d{9}\b/g,                                          validator: luhnValid,            confidence: 0.82 },

  // Universal
  { id: 'EMAIL',         type: 'email',           language: 'Global',          script: 'latin',      region: 'GLOBAL', regex: /\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g, validator: null, confidence: 0.97 },
  { id: 'PHONE_INTL',    type: 'phone',           language: 'Global',          script: 'latin',      region: 'GLOBAL', regex: /(?<![\w-])\+?[1-9]\d{0,2}[\s\-.]?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}(?![\w-])/g, validator: null, confidence: 0.80 },
  { id: 'DOB_ISO',       type: 'date_of_birth',   language: 'Global',          script: 'latin',      region: 'GLOBAL', regex: /\b(?:19|20)\d{2}[-\/]\d{2}[-\/]\d{2}\b/g,       validator: dobContextValid,     confidence: 0.75 },
];

// ── Document type detection ────────────────────────────────────────────────────

const DOC_TYPE_KEYWORDS = {
  medical:    ['patient', 'diagnosis', 'prescription', 'مريض', 'রোগী', '患者'],
  financial:  ['account', 'invoice', 'حساب', 'खाता', '계좌', '账户'],
  legal:      ['contract', 'agreement', 'عقد', '契約', '계약'],
  government: ['ministry', 'وزارة', 'सरकार', '政府', '정부'],
  hr:         ['employee', 'موظف', 'कर्मचारी', '직원', '雇员'],
  customer:   ['customer', 'عميل', 'ग्राहक', '고객', '客户'],
};

const DOC_MULTIPLIERS = {
  medical: 1.4, financial: 1.3, legal: 1.2,
  government: 1.25, hr: 1.2, customer: 1.1, general: 1.0,
};

const SEV_WEIGHTS = {
  national_id: 1.0, credit_card: 1.0, social_security: 1.0,
  health_id: 0.95, biometric: 0.95, passport: 0.90, tax_id: 0.85,
  iban: 0.85, driver_license: 0.80, email: 0.70, phone: 0.65,
  date_of_birth: 0.60, address: 0.55, name: 0.50,
};

function inferDocumentType(text) {
  const lower = text.toLowerCase();
  for (const [docType, keywords] of Object.entries(DOC_TYPE_KEYWORDS)) {
    if (keywords.some(kw => lower.includes(kw.toLowerCase()))) return docType;
  }
  return 'general';
}

// ── Language confidence scoring ────────────────────────────────────────────────

const LANG_NGRAM_SEEDS = {
  ar: ['ال', 'في', 'من', 'إل', 'وا', 'ون', 'ية', 'ما', 'أن'],
  he: ['ה', 'ו', 'ב', 'ש', 'ל', 'מ', 'א'],
  fa: ['که', 'از', 'به', 'در', 'را', 'با', 'این', 'کر'],
  ur: ['کا', 'کے', 'سے', 'ہے', 'نے', 'پر', 'کو', 'کی'],
  zh: ['的', '了', '在', '是', '我', '有', '他', '这'],
  ja: ['の', 'は', 'に', 'を', 'た', 'が', 'で', 'て'],
  ko: ['이', '가', '을', '의', '는', '하', '에', '고'],
  hi: ['का', 'के', 'की', 'है', 'में', 'से', 'को', 'पर'],
  ru: ['ов', 'ен', 'ни', 'то', 'на', 'по', 'за', 'он'],
  th: ['ที่', 'ของ', 'ใน', 'กา', 'การ', 'ให้', 'ได้'],
  ta: ['ல்', 'ம்', 'ன்', 'ர்', 'வர்', 'கள்'],
  bn: ['এর', 'এই', 'যে', 'কি', 'তার', 'একটি'],
};

function scoreLanguageConfidence(text) {
  const scores = {};
  for (const [lang, seeds] of Object.entries(LANG_NGRAM_SEEDS)) {
    const hits = seeds.filter(seed => text.includes(seed)).length;
    if (hits > 0) scores[lang] = Math.min(1.0, hits / seeds.length);
  }
  if (Object.keys(scores).length > 0) {
    const mx = Math.max(...Object.values(scores));
    for (const k in scores) scores[k] = Math.round((scores[k] / mx) * 1000) / 1000;
  }
  return scores;
}

// ── Redaction ──────────────────────────────────────────────────────────────────

function redact(raw) {
  if (raw.length <= 4) return '****';
  const keep = 2;
  return raw.slice(0, keep) + '*'.repeat(raw.length - keep * 2) + raw.slice(-keep);
}

// ── Main function ──────────────────────────────────────────────────────────────

/**
 * Scan text for PII across 100+ languages and 20+ scripts.
 *
 * @param {string} text  Raw input to scan
 * @returns {{ detected: boolean, findings: Array, riskScore: number }}
 */
function multilingualPiiCheck(text) {
  if (!text || typeof text !== 'string') {
    return { detected: false, findings: [], riskScore: 0 };
  }

  const docType = inferDocumentType(text);
  const multiplier = DOC_MULTIPLIERS[docType] || 1.0;
  const scripts = detectScripts(text);
  const languageScores = scoreLanguageConfidence(text);

  const rawFindings = [];

  // UUID spans: a UUID's hyphen-delimited hex groups make `\b\d{N}\b` patterns
  // fire on its digit substrings (e.g. the 12-hex tail). Compute the spans once
  // and skip any match that falls inside one — a general guard covering every
  // pattern, present and future, instead of per-regex boundary hacks.
  const uuidSpans = [];
  {
    const uuidRe = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
    let u;
    while ((u = uuidRe.exec(text)) !== null) uuidSpans.push([u.index, u.index + u[0].length]);
  }
  const inUuid = (i) => uuidSpans.some(([a, b]) => i >= a && i < b);

  for (const pat of PII_PATTERNS) {
    // Reset lastIndex for global regexes
    pat.regex.lastIndex = 0;
    let match;
    while ((match = pat.regex.exec(text)) !== null) {
      const raw = match[0].trim();
      if (inUuid(match.index)) continue; // skip digit substrings inside a UUID
      let checksumValid = null;

      if (pat.validator) {
        try {
          // Pass surrounding context (full text + match index) so context-aware
          // validators (e.g. DOB disambiguation) can use it. Checksum validators
          // ignore the extra args — safe and backward-compatible.
          const valid = pat.validator(raw, text, match.index);
          if (valid === false) continue; // skip failed checksum / context reject
          checksumValid = valid;
        } catch (_) {
          checksumValid = null;
        }
      }

      const conf = Math.min(1.0, pat.confidence * multiplier);
      rawFindings.push({
        type: pat.type,
        value: redact(raw),
        rawValue: raw,
        language: pat.language,
        script: pat.script,
        region: pat.region,
        confidence: Math.round(conf * 1000) / 1000,
        checksumValid,
        patternId: pat.id,
        start: match.index,
        end: match.index + match[0].length,
      });
    }
  }

  // Deduplicate overlapping spans (keep highest confidence)
  const sorted = rawFindings.sort((a, b) => a.start - b.start || b.confidence - a.confidence);
  const kept = [];
  let lastEnd = -1;
  for (const f of sorted) {
    if (f.start >= lastEnd) {
      kept.push(f);
      lastEnd = f.end;
    }
  }

  // Strip sensitive rawValue; keep start/end/type so callers can redact.
  const findings = kept.map(({ rawValue, patternId, ...rest }) => rest);

  // Composite risk score
  let riskScore = 0;
  if (kept.length > 0) {
    const weightedSum = kept.reduce((sum, f) => {
      const sev = SEV_WEIGHTS[f.type] || 0.7;
      return sum + f.confidence * sev;
    }, 0);
    riskScore = Math.min(1.0, weightedSum / kept.length);
  }

  return {
    detected: kept.length > 0,
    findings,
    riskScore: Math.round(riskScore * 10000) / 10000,
    scriptsDetected: scripts,
    languageScores,
    documentType: docType,
  };
}

/**
 * Redact every PII span the detector finds — so redaction == detection.
 * Returns { redacted, count }. Replaces each span with [TYPE_REDACTED],
 * right-to-left so earlier indices stay valid.
 */
function redactText(text) {
  if (typeof text !== 'string' || !text) return { redacted: text, count: 0 };
  const { findings } = multilingualPiiCheck(text);
  const spans = (findings || [])
    .filter(f => Number.isInteger(f.start) && Number.isInteger(f.end))
    .sort((a, b) => b.start - a.start); // right-to-left
  let out = text;
  for (const f of spans) {
    const token = `[${String(f.type || 'PII').toUpperCase()}_REDACTED]`;
    out = out.slice(0, f.start) + token + out.slice(f.end);
  }
  return { redacted: out, count: spans.length };
}

module.exports = { multilingualPiiCheck, redactText };
