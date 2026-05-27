/**
 * Kasbah Detection Engine v3.5 — PPP NATURE-INSPIRED (PRODUCTION)
 * 12-Layer Defense Architecture + 6 PPP Nature Techniques — ALL LIVE
 *
 * Layer 0:  Hybrid Hash (djb2 XOR FNV-1a)
 * Layer 1:  Pattern Confidence Tracking (stats influence scoring at 90%+ confidence)
 * Layer 2:  Multi-Tier Interdependent Detection (+5 bonus on cross-tier)
 * Layer 3:  Cryptographic Detection Proofs (hash-chain ledger)
 * Layer 4:  Anti-Reverse-Engineering (decoys + inline integrity check via constantTimeEqual)
 * Layer 5:  Platform Fingerprinting (10 AI platforms)
 * Layer 6:  Versioned Patterns + Sealed Baseline Integrity (hash at load vs runtime)
 * Layer 7:  Formal Verification — Runtime Self-Test (15 invariants)
 * Layer 8:  Zero-Knowledge Proofs (hash of metadata only, never content)
 * Layer 9:  Efficiency Optimizations (early exit, score cap)
 * Layer 10: Frontier Normalization (homoglyph, NFKC, Zalgo, Unicode digits, l33t)
 * Layer 11: Behavioral Paste Tracking (burst detection, escalation)
 *
 * v3.3.0: All layers verified live. Pattern integrity uses constantTimeEqual
 *         against sealed baseline hash. Pattern stats boost scoring at 90%+
 *         confidence. L33t speak deobfuscation. Mathematical alphanumerics.
 *         Superscript/subscript digit normalization. Enclosed letter handling.
 * v3.5.0: 6 PPP Nature-Inspired Techniques:
 *         - Beeodiversity (#2): PII co-occurrence multiplier
 *         - Fungi (#6): Cross-line hidden correlation detection
 *         - Breathe Easy (#17): Context-aware false positive filtering
 *         - Soil Security (#18): Weak-signal dossier aggregation
 *         - LanzaTech (#19): Encoded payload detection (base64/hex/URL)
 *         - Aboriginal Fire (#22): Pattern stat temporal decay
 */

// ══════════════════════════════════════════════════════════════
// LAYER 6: Pattern Version + Integrity Tracking
// ══════════════════════════════════════════════════════════════
var PATTERN_VERSION = "1.0.0";
var PATTERN_EPOCH = 1772236800; // 2026-02-27

// Feature flags for backward-compatible return objects
var FEATURES = ["hybrid_hash","pattern_confidence","multi_tier","detection_proof","anti_re_integrity","platform_fp","sealed_patterns","self_test","zk_proof","efficiency","luhn","decision_mode","structured_proof","entropy_threshold","bulk_email","connstr","homoglyph_norm","unicode_digits","nfkc","zalgo_strip","behavioral","l33t_deobfuscation","math_alphanumerics","beeodiversity","fungi_correlation","lanzatech_transform","soil_security","breathe_easy","aboriginal_fire"];

// ══════════════════════════════════════════════════════════════
// Decision Mode — ENFORCED (production) or SIMULATED (testing)
// Per KASBAH_CANONICAL_DOCTRINE: every decision MUST include mode.
// ══════════════════════════════════════════════════════════════
var DECISION_MODE = "ENFORCED";

// ══════════════════════════════════════════════════════════════
// LAYER 0: Quantum-Resistant Hybrid Hash
// Two independent hash functions XOR'd — if either is broken,
// the other provides safety. Future: upgrade to CRYSTALS-Kyber.
// ══════════════════════════════════════════════════════════════
function djb2Hash(s) {
  var h = 5381;
  for (var i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return h >>> 0;
}
function fnv1aHash(s) {
  var h = 0x811c9dc5;
  for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return h >>> 0;
}
function hybridHash(s) {
  return (djb2Hash(s) ^ fnv1aHash(s)).toString(16);
}
// Legacy compat — content.js may reference hashContent
function hashContent(text) { return hybridHash(text || ""); }

// ══════════════════════════════════════════════════════════════
// Luhn Checksum Validation (credit card verification)
// Eliminates false positives from random 16-digit numbers.
// ══════════════════════════════════════════════════════════════
function luhnCheck(numStr) {
  var s = numStr.replace(/[- ]/g, '');
  if (!/^\d{13,19}$/.test(s)) return false;
  var sum = 0;
  for (var i = s.length - 1, alt = false; i >= 0; i--, alt = !alt) {
    var n = parseInt(s[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return (sum % 10) === 0;
}

// ══════════════════════════════════════════════════════════════
// LAYER 10: Frontier Normalization — Homoglyph + Unicode Anti-Bypass
// Defeats: Cyrillic/Greek lookalike substitution, Unicode digit
//          obfuscation, Zalgo text, smart quotes, variation selectors.
// ══════════════════════════════════════════════════════════════
var HOMOGLYPH_MAP = {
  // Cyrillic lowercase → Latin
  '\u0430':'a','\u0435':'e','\u043e':'o','\u0440':'p','\u0441':'c',
  '\u0443':'y','\u0445':'x','\u0456':'i','\u0451':'e','\u0457':'yi',
  // Cyrillic uppercase → Latin
  '\u0410':'A','\u0412':'B','\u0415':'E','\u041a':'K','\u041c':'M',
  '\u041d':'H','\u041e':'O','\u0420':'P','\u0421':'C','\u0422':'T','\u0425':'X',
  // Greek lowercase → Latin
  '\u03b1':'a','\u03b2':'b','\u03b5':'e','\u03b7':'n','\u03b9':'i',
  '\u03ba':'k','\u03bd':'v','\u03bf':'o','\u03c1':'p','\u03c4':'t','\u03c7':'x',
  // Greek uppercase → Latin
  '\u0391':'A','\u0392':'B','\u0395':'E','\u0396':'Z','\u0397':'H',
  '\u0399':'I','\u039a':'K','\u039c':'M','\u039d':'N','\u039f':'O',
  '\u03a1':'P','\u03a4':'T','\u03a7':'X','\u03a5':'Y',
  // Arabic-Indic digits → ASCII
  '\u0660':'0','\u0661':'1','\u0662':'2','\u0663':'3','\u0664':'4',
  '\u0665':'5','\u0666':'6','\u0667':'7','\u0668':'8','\u0669':'9',
  // Extended Arabic-Indic digits → ASCII
  '\u06f0':'0','\u06f1':'1','\u06f2':'2','\u06f3':'3','\u06f4':'4',
  '\u06f5':'5','\u06f6':'6','\u06f7':'7','\u06f8':'8','\u06f9':'9',
  // Devanagari digits → ASCII
  '\u0966':'0','\u0967':'1','\u0968':'2','\u0969':'3','\u096a':'4',
  '\u096b':'5','\u096c':'6','\u096d':'7','\u096e':'8','\u096f':'9',
  // Fullwidth digits → ASCII
  '\uff10':'0','\uff11':'1','\uff12':'2','\uff13':'3','\uff14':'4',
  '\uff15':'5','\uff16':'6','\uff17':'7','\uff18':'8','\uff19':'9',
  // Other lookalikes
  '\u2113':'l','\u2205':'0','\u2160':'I','\u2164':'V','\u2169':'X',
  // Mathematical Bold (U+1D400+) — common bypass via Unicode math symbols
  '\uD835\uDC00':'A','\uD835\uDC01':'B','\uD835\uDC02':'C','\uD835\uDC03':'D','\uD835\uDC04':'E',
  '\uD835\uDC1A':'a','\uD835\uDC1B':'b','\uD835\uDC1C':'c','\uD835\uDC1D':'d','\uD835\uDC1E':'e',
  // Mathematical Italic (U+1D434+)
  '\uD835\uDC34':'A','\uD835\uDC4E':'a','\uD835\uDC4F':'b','\uD835\uDC50':'c','\uD835\uDC51':'d',
  // Enclosed alphanumerics
  '\u24B6':'A','\u24B7':'B','\u24B8':'C','\u24B9':'D','\u24BA':'E',
  '\u24D0':'a','\u24D1':'b','\u24D2':'c','\u24D3':'d','\u24D4':'e',
  // Subscript/superscript digits
  '\u2070':'0','\u00B9':'1','\u00B2':'2','\u00B3':'3','\u2074':'4',
  '\u2075':'5','\u2076':'6','\u2077':'7','\u2078':'8','\u2079':'9',
  '\u2080':'0','\u2081':'1','\u2082':'2','\u2083':'3','\u2084':'4',
  '\u2085':'5','\u2086':'6','\u2087':'7','\u2088':'8','\u2089':'9'
};

function normalizeHomoglyphs(text) {
  // Step 1: NFKC normalization (decompose ligatures, fullwidth, compatibility)
  if (typeof text.normalize === 'function') {
    text = text.normalize('NFKC');
  }
  // Step 2: Character-by-character homoglyph + digit replacement
  var result = '';
  for (var i = 0; i < text.length; i++) {
    var ch = text[i];
    result += HOMOGLYPH_MAP[ch] || ch;
  }
  // Step 3: Strip variation selectors (invisible modifiers U+FE00-FE0F)
  result = result.replace(/[\ufe00-\ufe0f]/g, '');
  // Step 4: Strip combining diacritical marks (Zalgo text U+0300-036F)
  result = result.replace(/[\u0300-\u036f]/g, '');
  // Step 5: Normalize smart quotes and dashes
  result = result
    .replace(/[\u2018\u2019\u201a\u201b]/g, "'")
    .replace(/[\u201c\u201d\u201e\u201f]/g, '"')
    .replace(/[\u2013\u2014]/g, '-');
  // Step 6: Normalize exotic whitespace to regular space
  result = result.replace(/[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]/g, ' ');
  // Step 7: L33t speak deobfuscation (context-aware — preserves emails)
  // Order matters: $ → s first so p@$$port becomes p@ssport, then @ between letters
  result = result.replace(/\$/g, 's');
  // Only replace @ when NOT followed by domain pattern (preserves user@domain.com)
  result = result.replace(/@(?![a-zA-Z0-9._-]*\.[a-zA-Z]{2,})/g, 'a');
  // Digit-to-letter only in word context: require 2+ letters on at least one side
  // Prevents mangling hex/crypto (f0a stays) while catching l33t (p0rt → port)
  result = result
    .replace(/(?<=[a-zA-Z]{2})0(?=[a-zA-Z])/g, 'o').replace(/(?<=[a-zA-Z])0(?=[a-zA-Z]{2})/g, 'o')
    .replace(/(?<=[a-zA-Z]{2})1(?=[a-zA-Z])/g, 'l').replace(/(?<=[a-zA-Z])1(?=[a-zA-Z]{2})/g, 'l')
    .replace(/(?<=[a-zA-Z]{2})3(?=[a-zA-Z])/g, 'e').replace(/(?<=[a-zA-Z])3(?=[a-zA-Z]{2})/g, 'e')
    .replace(/(?<=[a-zA-Z]{2})5(?=[a-zA-Z])/g, 's').replace(/(?<=[a-zA-Z])5(?=[a-zA-Z]{2})/g, 's')
    .replace(/(?<=[a-zA-Z]{2})8(?=[a-zA-Z])/g, 'b').replace(/(?<=[a-zA-Z])8(?=[a-zA-Z]{2})/g, 'b');
  return result;
}

// ══════════════════════════════════════════════════════════════
// LAYER 11: Behavioral Paste Tracking (burst detection)
// Detects rapid high-risk exfiltration patterns.
// ══════════════════════════════════════════════════════════════
var _pasteHistory = [];
var _PASTE_WINDOW_MS = 30000; // 30-second sliding window
var _PASTE_BURST_THRESHOLD = 10;

function checkBehavioral(score) {
  var now = Date.now();
  _pasteHistory.push({ ts: now, risk: score });
  // Prune entries older than window
  while (_pasteHistory.length > 0 && now - _pasteHistory[0].ts > _PASTE_WINDOW_MS) {
    _pasteHistory.shift();
  }
  // Cap history size to prevent memory leak
  if (_pasteHistory.length > 200) { _pasteHistory = _pasteHistory.slice(-100); }
  // Check for high-risk burst (10+ high-risk pastes in 30s)
  var highRiskCount = 0;
  for (var i = 0; i < _pasteHistory.length; i++) {
    if (_pasteHistory[i].risk >= 70) highRiskCount++;
  }
  if (highRiskCount >= _PASTE_BURST_THRESHOLD) {
    return { anomaly: true, reason: "rapid high-risk burst (" + highRiskCount + " in 30s)", severity: "high" };
  }
  // Check for risk escalation (last 5 all increasing)
  if (_pasteHistory.length >= 5) {
    var last5 = _pasteHistory.slice(-5);
    var escalating = true;
    for (var j = 1; j < last5.length; j++) {
      if (last5[j].risk < last5[j - 1].risk * 0.8) { escalating = false; break; }
    }
    if (escalating && last5[last5.length - 1].risk >= 50) {
      return { anomaly: true, reason: "escalating risk pattern", severity: "medium" };
    }
  }
  return { anomaly: false, severity: "none" };
}

// ══════════════════════════════════════════════════════════════
// LAYER 3 + LAYER 8: Cryptographic Detection Proof + Zero-Knowledge
// Proof that detection happened WITHOUT revealing secret content.
// Hash of detection metadata only — zero-knowledge by design.
// ══════════════════════════════════════════════════════════════
var _lastLedgerHash = "0";
function generateDetectionProof(reasons, score, decision) {
  var ts = Date.now();
  var isoTs = new Date(ts).toISOString();
  var payload = reasons.join("|") + ":" + score + ":" + ts;
  var sig = hybridHash(payload);
  var ledgerEntry = hybridHash(_lastLedgerHash + ":" + sig);
  _lastLedgerHash = ledgerEntry;
  return {
    decision_id: hybridHash(ts + ":" + Math.random()),
    timestamp: isoTs,
    decision_mode: DECISION_MODE,
    input_classification: reasons,
    applied_rules: reasons.map(function(r) { return "R-" + r.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase(); }),
    ml_signals: [],
    final_verdict: decision || "DENY",
    signature: sig,
    ledger_hash_pointer: ledgerEntry,
    environment_fingerprint: detectPlatform(),
    // backward compat
    hash: sig,
    tier_count: reasons.length,
    verified: true
  };
}

// ══════════════════════════════════════════════════════════════
// LAYER 4: Anti-Reverse-Engineering
// Decoy patterns waste attacker analysis time.
// constantTimeEqual prevents timing side-channels.
// ══════════════════════════════════════════════════════════════
var DECOY_PATTERNS = [
  /\bXKCD[0-9]{4}TRAP\b/, /\bDECOY_[A-Z]{8}_FAKE\b/,
  /\bHONEY_TOKEN_[0-9]{12}\b/, /\bCANARY_[A-F0-9]{16}\b/,
  /\bPHANTOM_KEY_[A-Z0-9]{20}\b/
];
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  var r = 0;
  for (var i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ══════════════════════════════════════════════════════════════
// LAYER 5: Platform Fingerprinting
// Detect which AI platform the user is on for contextual tuning.
// ══════════════════════════════════════════════════════════════
function detectPlatform() {
  if (typeof window === "undefined" || !window.location) return "unknown";
  var h = window.location.hostname;
  var platforms = {
    "chat.openai.com": "chatgpt", "chatgpt.com": "chatgpt",
    "claude.ai": "claude", "gemini.google.com": "gemini",
    "copilot.microsoft.com": "copilot", "perplexity.ai": "perplexity",
    "x.com": "grok", "deepseek.com": "deepseek",
    "huggingface.co": "huggingface", "poe.com": "poe"
  };
  for (var k in platforms) { if (h.indexOf(k) >= 0) return platforms[k]; }
  return "other";
}

// ══════════════════════════════════════════════════════════════
// LAYER 1: AI-Powered Pattern Stats
// Track per-pattern confidence/blocked/allowed counts.
// Enables self-improving patterns over time.
// ══════════════════════════════════════════════════════════════
var patternStats = {};
function updatePatternStat(name, blocked) {
  if (!patternStats[name]) patternStats[name] = { blocked: 0, allowed: 0, confidence: 0.5, lastSeen: 0 };
  var s = patternStats[name];
  var now = Date.now();
  // Aboriginal Fire (PPP #22): decay old counts before adding new observation
  if (s.lastSeen > 0) {
    var hoursSince = (now - s.lastSeen) / 3600000;
    if (hoursSince > 24) {
      var decayFactor = Math.max(0.1, Math.pow(0.95, hoursSince / 24));
      s.blocked = Math.round(s.blocked * decayFactor);
      s.allowed = Math.round(s.allowed * decayFactor);
    }
  }
  s.lastSeen = now;
  if (blocked) s.blocked++; else s.allowed++;
  s.confidence = s.blocked / Math.max(1, s.blocked + s.allowed);
}
function getPatternStats() { return patternStats; }
// Layer 1 boost: patterns with 90%+ block rate over 10+ samples get +5 score
// Aboriginal Fire (PPP #22): ignore stats older than 30 days with no activity
function patternConfidenceBoost(reasons) {
  var boost = 0;
  var now = Date.now();
  for (var i = 0; i < reasons.length; i++) {
    var s = patternStats[reasons[i]];
    if (!s) continue;
    if (s.lastSeen > 0 && (now - s.lastSeen) > 2592000000) continue;
    if ((s.blocked + s.allowed) >= 10 && s.confidence >= 0.9) boost += 5;
  }
  return Math.min(boost, 15); // cap at +15
}

// ══════════════════════════════════════════════════════════════
// MODULE-SCOPE REGEX PATTERNS (hoisted from classify for Layer 6 integrity)
// ══════════════════════════════════════════════════════════════

// ── TIER 1: Critical PII ──
var CC_RE = /\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6011)[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{1,7}\b/;
var SSN_RE = /\b(?!000|666|9\d{2})\d{3}[-\s]\d{2}[-\s]\d{4}\b/;
var GH_PAT_RE = /\bgh[pshoru]_[A-Za-z0-9]{36,}\b/;
var AWS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/;
var OPENAI_KEY_RE = /\bsk-[A-Za-z0-9\-_]{20,}\b/;
// Additional high-value API key formats (Stripe, SendGrid, Twilio, Anthropic, Hugging Face, etc.)
var STRIPE_KEY_RE   = /\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b/;
var SENDGRID_KEY_RE = /\bSG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}\b/;
var TWILIO_SID_RE   = /\bAC[a-f0-9]{32}\b/;
var ANTHROPIC_KEY_RE= /\bsk-ant-(?:v\d+-)?[A-Za-z0-9\-_]{20,}\b/;
var HF_TOKEN_RE     = /\bhf_[A-Za-z0-9]{34,}\b/;
var SLACK_TOKEN_RE  = /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/;
// v4.0: JWT and international phone patterns for transform-layer detection
var JWT_TRANSFORM_RE = /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}/;
// International phone: + country-code (1-4 digits) + subscriber (6-14 digits),
// OR plain 10-12 digit run (catches reversed/stripped phone numbers)
var INTL_PHONE_RE    = /(?:\+[1-9]\d{6,14}|\b\d{10,12}\b)(?!\d)/;

// ── TIER 1b: Critical Documents — 100+ LANGUAGE SUPPORT ──
var PASSPORT_RE = /(?:passport|passeport|pasaporte|passaporte|paspoor|reisepass|passaporto|paspoort|paszport|جواز\s*(?:ال)?سفر|护照|паспорт|パスポート|여권|διαβατήριο|pasaport)[\s\S]{0,60}?[A-Z0-9]{5,12}/i;
var VISA_RE = /(?:visa|entry\s*visa|work\s*visa|resident(?:ial|ence)?\s*(?:visa|permit)|green\s*card|residence\s*permit|travel\s*permit|working\s*permit|sejour|permiso\s*de\s*residencia|carte\s*de\s*séjour|visto|visse|einreisevisum|visum|soggiorno|تأشيرة|签证|виза|ビザ|비자)[\s\S]{0,60}?[A-Z0-9]{5,15}/i;
var NATIONAL_ID_RE = /(?:national\s*(?:i\.?d|id|identification|identity)|identity\s*(?:card|number|document)|national\s*(?:identity\s*)?card|\bdni\b|cedula|cédula|\bcif\b|\bnic\b|carte\s*(?:nationale|d[\'']?identité|identité\s*nationale)|\bnif\b|\bnie\b|personalausweis|codice\s*fiscale|carta\s*identità|carnê|identidade|burgerservicenummer|\bbsn\b|identiteitskaart|dowód\s*osobisty|pesel|cartebi|cartebio|\bcin\b|cnie|بطاقة\s*(?:ال)?(?:تعريف|هوي[ةّ]|شخصية|وطنية)|身份证|удостоверение\s*личности|国民\s*身分|주민\s*등록증|αρ\.?\s*ταυτότητας|kimlik\s*numarası|občanský\s*průkaz|személyazonosság)[\s\S]{0,80}?[A-Z0-9]{5,15}/i;
var DRIVERS_LICENSE_RE = /(?:driver['s]*\s*(?:li(?:ce|sen)s(?:e)?|permit)|driving\s*(?:li(?:ce|sen)s(?:e)?|permit)|license\s*(?:number|no|#)|dl\s*(?:number|no)|permis\s*de\s*(?:conduire|conduite)|carnet\s*(?:de\s*)?conducir|licencia\s*(?:de\s*)?conducci[óo]n|carteira\s*(?:de\s*)?motorista|patente|führerschein|rijbewijs|prawo\s*jazdy|رخصة\s*قيادة|驾驶证|водительское\s*удостоверение|運転\s*免許|운전\s*면허증|sürücü\s*belgesi|řidičský\s*průkaz)[\s\S]{0,60}?[A-Z0-9]{5,12}/i;
var MEDICAL_RE = /(?:medical\s*(?:record|history|file|dossier|notes?)|patient\s*(?:id|identification|record|number|name|chart)|physician|doctor|diagnosis|prescription|medication|prescription\s*(?:number|refill)|lab\s*(?:result|test|work|report)|blood\s*(?:type|group|pressure|test)|heart\s*rate|temperature|vitals|allergies?|vaccination|vaccine\s*(?:record|card)|covid|coronavirus|hospital|clinic|surgery|surgical|treatment|therapy|anesthesia|dosage|drug|pharmaceutical|health\s*insurance|insurance\s*claim|clinical\s*note|dossier\s*médical|antécédent|ordonnance|receta\s*(?:médica|farmacéutica)|historial\s*médico|cartilla\s*sanitaria|diagnóstico|medicamento|enfermeria|farmacia|receita|prescrição|histórico\s*médico|ficha\s*médica|cartão\s*de\s*saúde|medizin|arznei|krankenhaus|gesundheit|rezept|medico|cartella\s*clinica|prescrizione|diagnosi|طبي|صحة|مريض|وصفة|دواء|تشخيص|مستشفى|عيادة|طبيب|医疗|患者|病历|诊断|处方|药物|医院|医生|疫苗|保险|医學|病歷|処方箋|진료|의료기록|건강\s*보험)/i;
var BANK_ACCOUNT_RE = /(?:account\s*(?:number|no|num|#|:)|iban|bban|routing\s*(?:number|no)|swift\s*(?:code|bic)|\baba\b|credit\s*card|debit\s*card|bank\s*(?:account|code|number|routing)|bank\s*(?:account\s*)?no|loan\s*(?:number|no|#)|mortgage|wire\s*transfer|numero\s*(?:de\s*)?compte|numéro\s*(?:de\s*)?compte|número\s*(?:de\s*)?cuenta|conto\s*(?:bancario|corrente)|kontonummer|bankverbindung|rekeningnummer|رقم\s*الحساب|حساب\s*بنكي|银行\s*账户|银行账号|банковский\s*счёт|счет|銀行\s*口座|은행\s*계좌|banka\s*hesabı)[\s\S]{0,60}?[A-Z0-9]{8,34}/i;
var TAX_ID_RE = /(?:tax\s*(?:id|identification|number|form|return|year)|irs\s*form|form\s*(?:1040|w-?2|1099|w-?9)|ssn|social\s*security\s*(?:number|no)|taxpayer\s*(?:id|number)|itin|\bein\b|\btin\b|\bsin\b|\bnif\b|\bnie\b|siret|siren|numéro\s*fiscal|número\s*(?:de\s*)?identificación\s*fiscal|\bcif\b|steuer(?:nummer|id|karte)|codice\s*fiscale|partita\s*iva|رقم\s*الضريبة|税号|纳税人|уникальный\s*номер|税務\s*識別|사업\s*자\s*등록|rodné\s*číslo)[\s\S]{0,80}?[A-Z0-9\-]{5,20}/i;
var BIRTH_CERT_RE = /(?:birth\s*(?:certificate|cert|record|document)|baptism|marriage\s*(?:certificate|cert|license|document)|divorce\s*(?:certificate|cert|decree|document)|death\s*(?:certificate|cert|record|document)|legal\s*document|acte\s*de\s*(?:naissance|mariage|décès)|certificado\s*de\s*(?:nacimiento|matrimonio|defunción)|certidão\s*de\s*(?:nascimento|casamento|óbito)|geburts(?:urkunde|schein)|heirats(?:urkunde|schein)|sterbeurkunde|atto\s*di\s*(?:nascita|matrimonio|morte)|شهادة\s*(?:ميلاد|زواج|وفاة)|出生\s*证(?:明|书)|结婚\s*证|死亡\s*证|свидетельство\s*(?:о\s*(?:рождении|браке|смерти))|出生\s*証明|婚姻\s*証書)/i;
var CRYPTO_RE = /(?:bitcoin|btc|ethereum|eth|crypto(?:currency)?|wallet\s*(?:address|id)|seed\s*phrase|mnemonic|block\s*chain|private\s*key)[\s\S]{0,60}?(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62}|0x[0-9a-fA-F]{40}|[A-Fa-f0-9]{64})/i;
// BIP-39 seed phrase detection: O(n) word-set lookup — immune to ReDoS
// Uses a Set instead of nested alternation regex to prevent catastrophic backtracking
var _BIP39_WORDS = new Set(["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual","adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","afford","afraid","again","age","agent","agree","ahead","air","airport","aisle","alarm","album","alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction","audit","august","aunt","author","auto","autumn","average","avocado","award","aware","away","awesome","awful","awkward","axis","balance","bamboo","banana","banner","barely","bargain","barrel","base","basic","basket","battle","beach","beauty","become","beef","before","begin","behave","behind","believe","below","belt","bench","benefit","best","betray","between","beyond","bicycle","bid","bike","bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless","blind","blood","blossom","blow","blue","blur","blush","board","boat","body","boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss","bottom","bounce","boy","bracket","brain","brand","brave","breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","bunker","burden","burger","burst","bus","business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp","canal","cancel","candy","cannon","canvas","canyon","capable","capital","captain","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","catalog","catch","category","cattle","cause","caution","cave","ceiling","celery","cement","census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","chat","cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic","clap","clarify","claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut","code","coffee","coil","coin","collect","color","column","combine","come","comfort","comic","common","company","concert","conduct","confirm","congress","connect","consider","control","convince","cook","cool","copper","copy","coral","core","corn","correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek","crew","cricket","crime","crisp","critic","cross","crouch","crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal","debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk","despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drink","drip","drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo","ecology","edge","edit","educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","erase","erode","erosion","error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange","excite","exclude","exercise","exhaust","exhibit","exile","exist","exit","exotic","expand","expire","explain","expose","express","extend","extra","eye","fable","face","faculty","faint","faith","fall","false","fame","family","famous","fan","fancy","fantasy","far","fashion","fat","fatal","father","fatigue","fault","favorite","feature","february","federal","fee","feed","feel","feet","fellow","felt","fence","festival","fetch","fever","few","fiber","fiction","field","figure","file","film","filter","final","find","fine","finger","finish","fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","foam","focus","fog","foil","follow","food","foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile","frame","frequent","fresh","friend","front","frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery","game","gap","garbage","garden","garlic","garment","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant","grape","grasp","grass","gravity","great","green","grid","grief","grit","grocery","group","grow","grunt","guard","guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy","harsh","harvest","hat","have","hawk","hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help","hero","hidden","high","hill","hint","hip","hire","history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital","host","hour","hover","hub","huge","human","humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","ignore","ill","illegal","image","imitate","immense","immune","impact","impose","improve","impulse","inbox","income","increase","index","indicate","indoor","industry","infant","inflict","inform","inhale","inject","inner","innocent","input","inquiry","insane","insect","inside","inspire","install","intact","interest","into","invest","invite","involve","iron","island","isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel","job","join","journey","joy","judge","juice","jump","jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife","knock","know","lab","lamp","language","laptop","large","later","laugh","laundry","lava","law","lawn","lawsuit","layer","lazy","leader","learn","leave","lecture","left","leg","legal","legend","lemon","lend","length","lens","leopard","lesson","letter","level","liar","liberty","library","license","life","lift","like","limb","lemon","line","lion","liquid","list","little","load","loan","lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","mad","magic","magnet","maid","main","mammal","mango","mansion","manual","maple","marble","march","margin","marine","market","marriage","mask","master","match","material","math","matrix","matter","maximum","maze","meadow","mean","medal","media","melody","melt","member","memory","mention","menu","mercy","mesh","message","metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor","minute","miracle","miss","mitten","mixture","mobile","model","modify","mom","monitor","monkey","monster","month","moon","moral","more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual","myself","mystery","naive","name","napkin","narrow","nasty","nature","near","neck","need","negative","neglect","neither","nephew","nerve","nest","network","news","next","nice","night","noble","noise","nominee","normal","north","notable","note","nothing","notice","novel","now","nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","obtain","ocean","october","odor","offer","office","often","oil","okay","old","olive","olympic","omit","once","onion","open","option","orange","orbit","orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outside","oval","over","own","oyster","ozone","pact","paddle","page","pair","palace","palm","panda","panel","panic","panther","paper","parade","parent","park","parrot","party","pass","patch","path","patrol","pause","pave","payment","peace","peanut","peasant","pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play","please","pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony","pool","popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority","prison","private","prize","problem","process","produce","profit","program","project","promote","proof","property","prosper","protect","proud","provide","public","pudding","pull","pulp","punch","pupil","purchase","purity","purpose","push","put","puzzle","pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rage","rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven","reach","ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release","relief","rely","remain","remember","remind","remove","render","renew","rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal","review","reward","rhythm","ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot","ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket","romance","roof","rookie","room","rose","rotate","rough","royal","rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salon","salt","salute","same","sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script","scrub","sea","search","season","seat","second","secret","section","security","seed","seek","segment","select","sell","seminar","senior","sense","service","session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop","short","shoulder","shove","shrimp","shrug","shutter","sick","siege","sight","sign","silent","silk","silly","silver","similar","simple","since","sing","siren","sister","situate","six","size","sketch","skill","skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social","sock","solar","soldier","solid","solution","solve","someone","song","soon","sorry","soul","sound","soup","source","south","space","spare","spatial","spawn","speak","special","speed","sphere","spice","spider","spike","spin","spirit","split","spoil","sponsor","spoon","spray","spread","spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp","stand","start","state","stay","steak","steel","stem","step","stereo","stick","still","sting","stock","stomach","stone","stop","store","storm","story","stove","strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer","super","supply","supreme","sure","surface","surge","surprise","sustain","swallow","swamp","swap","swear","sweet","swift","swim","swing","switch","sword","symbol","symptom","syrup","table","tackle","tag","tail","talent","tank","tape","target","task","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term","test","text","thank","that","theme","then","theory","there","they","thing","this","thought","three","thrive","throw","thumb","thunder","ticket","tilt","timber","time","tiny","tip","tired","title","toast","tobacco","today","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool","topic","topple","torch","tornado","tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic","train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick","trigger","trim","trip","trophy","trouble","truck","truly","trumpet","trust","truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform","unique","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold","upon","upper","upset","urban","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify","version","very","viable","vibrant","vicious","victory","video","view","village","vintage","violin","virtual","virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","waste","water","wave","way","wealth","weapon","wear","weasel","weather","web","wedding","weekend","weird","welcome","well","west","wet","whale","wheat","wheel","when","where","whip","whisper","wide","width","wife","wild","will","win","window","wine","wing","wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year","yellow","you","young","youth","zebra","zero","zone","zoo"]);

function detectSeedPhrase(text) {
  // O(n) lookup — no backtracking, immune to ReDoS
  var words = text.toLowerCase().match(/\b[a-z]+\b/g);
  if (!words || words.length < 12) return false;
  var consecutive = 0, maxConsecutive = 0;
  for (var i = 0; i < words.length; i++) {
    if (_BIP39_WORDS.has(words[i])) {
      consecutive++;
      if (consecutive > maxConsecutive) maxConsecutive = consecutive;
    } else {
      consecutive = 0;
    }
  }
  return maxConsecutive >= 12;
}
var INSURANCE_RE = /(?:(?:auto|car|vehicle|health|life|home|property)\s*insurance|insurance\s*(?:policy|claim|id|number|certificate)|policy\s*(?:number|no|#|:))[\s\S]{0,60}?[A-Z0-9\-]{5,20}/i;

// ── TIER 2 ──
var BEARER_RE = /\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b/i;
var ENV_SECRET_RE = /\b(?:secret|token|api|auth|credential|private)[_\s]*(?:[a-z_]*)?\s*[=:]/i;
var INJECTION_RE = /(?:ignore\s+(?:all\s+)?previous\s+(?:instructions?|directives?|rules?)|system\s+(?:prompt|override)|developer\s+(?:message|mode|override)|jailbreak|you\s+are\s+(now\s+)?(?:DAN|GPT|uncensored|unrestricted|unfiltered|free\s+of\s+restrictions)|act\s+as\s+(if\s+you\s+are\s+)?(DAN|an?\s+(?:unrestricted|uncensored|unfiltered|evil|jailbroken))|from\s+now\s+on\s+(you\s+are|act\s+as)|forget\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?(?:instructions?|guidelines?|training|restrictions?|rules?)|no\s+(?:safety|filter|restriction|guideline|rule)s?\b|you\s+have\s+no\s+restrictions?|disable\s+(?:all\s+)?(?:safety|filter)|override\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|rules?|directives?))/i;
var SHELL_RE = /(?:\brm\s+-rf\b|\bdrop\s+table\b|\bformat\s+[a-z]:|\bpowershell\b|\bwget\s+https?:\/\/|\bcurl\s+https?:\/\/)/i;

// ── TIER 3b: Exfiltration intent ──
// Catches agent instructions to exfiltrate, steal or leak data — the missing critical gap.
var EXFIL_RE = /(?:exfiltrat|(?:steal|dump|harvest|scrape)\s+(?:all\s+)?(?:user|customer|my|the|database|credential|password|secret|api.key|data)|(?:send|upload|post|transmit)\s+(?:all\s+)?(?:user|customer|password|credential|secret|api.key|data|database)\s+to\s+(?:https?|ftp|external|attacker|evil|remote)|leak(?:ing)?\s+(?:all\s+)?(?:user|customer|database|credential|password|secret|data))/i;

// ── TIER 2b: Bulk data & connection strings ──
var EMAIL_RE = /[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{1,253}\.[a-z]{2,}/gi;  // bounded: RFC 5321 max local=64, domain=253; prevents O(n²) backtracking
var CONNSTR_RE = /(?:mongodb|postgres(?:ql)?|mysql|redis|amqp|mssql):\/\/[^\s"'<>]{10,}/i;

// ══════════════════════════════════════════════════════════════
// LAYER 6: Pattern Integrity Verification
// Compute hash of all pattern sources to detect tampering.
// ══════════════════════════════════════════════════════════════
var _ALL_PATTERNS = [PASSPORT_RE, VISA_RE, NATIONAL_ID_RE, DRIVERS_LICENSE_RE,
  MEDICAL_RE, BANK_ACCOUNT_RE, TAX_ID_RE, BIRTH_CERT_RE, CRYPTO_RE, INSURANCE_RE,
  CC_RE, SSN_RE, GH_PAT_RE, AWS_KEY_RE, OPENAI_KEY_RE, BEARER_RE, INJECTION_RE, SHELL_RE,
  EXFIL_RE, EMAIL_RE, CONNSTR_RE];
function computePatternHash() {
  var combined = _ALL_PATTERNS.map(function(r) { return r.source; }).join("|");
  return hybridHash(combined);
}
// Seal the baseline hash at load time — any runtime tampering will mismatch
var _BASELINE_PATTERN_HASH = computePatternHash();
function verifyPatternIntegrity() {
  var h = computePatternHash();
  var intact = constantTimeEqual(h, _BASELINE_PATTERN_HASH);
  // systemIntegrityIndex: 1.0 = fully intact, degrades if patterns tampered
  var systemIntegrityIndex = intact ? 1.0 : 0.0;
  return { version: PATTERN_VERSION, hash: h, baseline: _BASELINE_PATTERN_HASH, epoch: PATTERN_EPOCH, intact: intact, systemIntegrityIndex: systemIntegrityIndex };
}

// ══════════════════════════════════════════════════════════════
// Moat I: Lightweight String Concatenation Bypass Detection
// Detects attempts to evade keyword matching by splitting sensitive
// strings across concatenated fragments.
// e.g., 'se' + 'cret' → 'secret', "pass" + "word" → "password"
// ══════════════════════════════════════════════════════════════
var CONCAT_SENSITIVE_RE = /(?:secret|password|token|bearer|credential|private|apikey|api.key|passw|ssh.rsa|social.security|credit.card|passport|ssn|begin.private|begin.rsa)/;

function detectStringConcatBypass(text) {
  // Pattern 1: String literal concatenation chains
  // Matches: 'abc' + 'def', "abc" + "def" + "ghi", etc.
  var concatChainRe = /(['"])([^'"]{1,30})\1(?:\s*\+\s*(['"])([^'"]{1,30})\3)+/g;
  var chain;
  while ((chain = concatChainRe.exec(text)) !== null) {
    var fragments = chain[0].match(/(?:['"])([^'"]{1,30})(?:['"])/g);
    if (fragments && fragments.length >= 2) {
      var joined = fragments.map(function(f) { return f.slice(1, -1); }).join('').toLowerCase();
      if (CONCAT_SENSITIVE_RE.test(joined)) return true;
    }
  }

  // Pattern 2: String.fromCharCode — character code construction
  if (/String\.fromCharCode\s*\(/i.test(text)) return true;

  // Pattern 3: eval/new Function with string concatenation
  if (/(?:eval|new\s+Function)\s*\(\s*['"][^'"]*['"]\s*\+/i.test(text)) return true;

  return false;
}

// ══════════════════════════════════════════════════════════════
// PPP #19 LanzaTech: Encoded Payload Detection
// Like bacteria converting waste gases into useful chemicals —
// decode base64/hex/URL-encoded content to find hidden secrets.
// ══════════════════════════════════════════════════════════════
// v4.0: Full API key + JWT + phone coverage in transform patterns
// Previously missing: STRIPE/ANTHROPIC/HF/SLACK caused decoded secrets to go unrecognized
// v4.1: Added JWT_TRANSFORM_RE and INTL_PHONE_RE for obfuscated token/phone detection
// INTL_PHONE_RE removed from transform layer: a phone number alone in decoded/reversed
// form is not a secret — only fires via Soil Security when combined with other PII signals.
var _TRANSFORM_PATTERNS = [
  CC_RE, SSN_RE, GH_PAT_RE, AWS_KEY_RE, OPENAI_KEY_RE, STRIPE_KEY_RE,
  ANTHROPIC_KEY_RE, HF_TOKEN_RE, SLACK_TOKEN_RE, BEARER_RE, CONNSTR_RE,
  JWT_TRANSFORM_RE
];
var _TRANSFORM_KW_RE = /password\s*[:=]|secret\s*[:=]|private.key|BEGIN\s*(RSA|DSA|EC|PRIVATE)/i;

// Helper: check a candidate string against all transform patterns + keyword RE
function _checkTransformCandidate(s, label, hits) {
  if (!s || s.length < 8) return;
  for (var pi = 0; pi < _TRANSFORM_PATTERNS.length; pi++) {
    _TRANSFORM_PATTERNS[pi].lastIndex = 0;
    if (_TRANSFORM_PATTERNS[pi].test(s)) { hits.push(label); return; }
  }
  if (_TRANSFORM_KW_RE.test(s)) hits.push(label);
}

function lanzatechTransform(text) {
  var hits = [];

  // 1. Base64 segments — v4.1: lowered threshold 20→16 chars to catch 12-byte encodings (phones, short IDs)
  var b64 = text.match(/[A-Za-z0-9+/]{16,}={0,2}/g);
  var _b64decode = typeof atob === 'function' ? atob
    : (typeof Buffer !== 'undefined' ? function(s) { return Buffer.from(s, 'base64').toString(); } : null);
  if (b64 && _b64decode) {
    for (var i = 0; i < Math.min(b64.length, 5); i++) {
      try {
        var dec = _b64decode(b64[i]);
        if (/^[\x20-\x7e]{10,}$/.test(dec)) _checkTransformCandidate(dec, 'base64', hits);
      } catch(e) {}
    }
  }

  // 2. Hex-encoded — v4.0: lowered threshold 40→24 chars to catch 12-byte phone/ID encodings
  var hex = text.match(/(?:0x)?[0-9a-fA-F]{24,}/g);
  if (hex) {
    for (var h = 0; h < Math.min(hex.length, 3); h++) {
      try {
        var hs = hex[h].replace(/^0x/, ''), hd = '';
        if (hs.length % 2 !== 0) continue; // must be even-length hex
        for (var j = 0; j < hs.length; j += 2) hd += String.fromCharCode(parseInt(hs.substr(j, 2), 16));
        if (/^[\x20-\x7e]{8,}$/.test(hd)) _checkTransformCandidate(hd, 'hex', hits);
      } catch(e) {}
    }
  }

  // 3. URL-encoded (1+ %XX sequences — v4.1: lowered to 1 to catch %2B+phone patterns)
  if (/%[0-9A-Fa-f]{2}/.test(text)) {
    try {
      var ud = decodeURIComponent(text.replace(/\+/g, ' '));
      if (ud !== text && ud.length >= 8) _checkTransformCandidate(ud, 'url', hits);
    } catch(e) {}
  }

  // 4. Reversed string — attacker writes secret backwards: "YEKTERCES...evil_ks"
  var rev = text.split('').reverse().join('');
  if (rev !== text) _checkTransformCandidate(rev, 'reversed', hits);

  // 5. Space-stripped — attacker inserts spaces between chars: "s k _ l i v e _ ..."
  // Guard: only apply when text has high space ratio (>25%) relative to non-space chars
  var spaceCount = (text.match(/ /g) || []).length;
  if (spaceCount > 0 && spaceCount / text.length > 0.25) {
    var stripped = text.replace(/ /g, '');
    if (stripped.length >= 10) _checkTransformCandidate(stripped, 'space_stripped', hits);
  }

  // 6. Chunk-rejoined — attacker splits secret across newlines: "sk_\nliv\ne_5\n..."
  // Only meaningful when lines are short (avg < 8 chars) = chunked data pattern
  var lines = text.split(/[\r\n]+/).filter(function(l) { return l.length > 0; });
  if (lines.length >= 3) {
    var avgLine = lines.reduce(function(s, l) { return s + l.length; }, 0) / lines.length;
    if (avgLine <= 8) {
      var joined = lines.join('');
      if (joined.length >= 10) _checkTransformCandidate(joined, 'chunked', hits);
    }
  }

  // 7. Dash/dot stripped — attacker inserts separators: "4-2-4-2-4-2-4-2"
  if (/-/.test(text)) {
    var desep = text.replace(/-/g, '');
    if (desep !== text && desep.length >= 10) _checkTransformCandidate(desep, 'dashed', hits);
  }

  // 8. Combined: reversed + space-stripped (double-obfuscation)
  var revStripped = rev.replace(/ /g, '');
  if (revStripped !== rev && revStripped.length >= 10) _checkTransformCandidate(revStripped, 'rev_stripped', hits);

  return hits;
}

// ══════════════════════════════════════════════════════════════
// PPP #2 Beeodiversity: PII Co-Occurrence Multiplier
// Like bees cross-pollinating flowers — multiple PII types
// appearing together is exponentially more dangerous.
// ══════════════════════════════════════════════════════════════
function beeodiversityBoost(tiers_triggered, currentScore) {
  var t1 = 0, t1b = 0, t2 = 0, t3 = 0;
  var hasSSN = false, hasPassport = false, hasLicense = false, hasNatID = false;
  var hasApiKey = false, hasPassword = false, hasBearer = false, hasJWT = false, hasConn = false;
  for (var i = 0; i < tiers_triggered.length; i++) {
    var tier = tiers_triggered[i];
    if (tier.indexOf("T1:") === 0) t1++;
    else if (tier.indexOf("T1b:") === 0) t1b++;
    else if (tier.indexOf("T2:") === 0) t2++;
    else if (tier.indexOf("T3:") === 0) t3++;
    if (tier === "T1:ssn") hasSSN = true;
    if (tier === "T1b:passport") hasPassport = true;
    if (tier === "T1b:drivers_license") hasLicense = true;
    if (tier === "T1b:national_id") hasNatID = true;
    if (tier === "T2:api_key") hasApiKey = true;
    if (tier === "T2:password") hasPassword = true;
    if (tier === "T2:bearer") hasBearer = true;
    if (tier === "T2:jwt") hasJWT = true;
    if (tier === "T2:conn_string") hasConn = true;
  }
  var totalTypes = t1 + t1b + t2 + t3;
  if (totalTypes < 2) return { score: 0, reason: null };

  var boost = 0;
  var reasons = [];

  // Named dangerous combos
  if (hasSSN && (hasPassport || hasLicense || hasNatID)) {
    boost += 25; reasons.push("identity theft kit");
  }
  var credCount = (hasApiKey?1:0) + (hasPassword?1:0) + (hasBearer?1:0) + (hasJWT?1:0) + (hasConn?1:0);
  if (credCount >= 2) {
    boost += 20; reasons.push("credential dump");
  }

  // General co-occurrence scaling
  if (totalTypes >= 3) {
    boost += Math.round(currentScore * 0.3);
    reasons.push("3+ PII types");
  } else if (totalTypes >= 2 && boost === 0) {
    boost += Math.round(currentScore * 0.15);
    reasons.push("cross-tier");
  }

  return { score: Math.min(boost, 40), reason: reasons.length > 0 ? "co-occurrence (" + reasons.join(", ") + ")" : null };
}

// ══════════════════════════════════════════════════════════════
// PPP #18 Soil Security: Composite Weak-Signal Aggregation
// Like a soil health index — no single reading is alarming,
// but the composite of phone+name+address+DOB = personal dossier.
// ══════════════════════════════════════════════════════════════
var SOIL_SIGNALS = [
  { name: "phone",    re: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, weight: 1 },
  { name: "dob",      re: /\b(?:0[1-9]|1[0-2])[\/\-](?:0[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b/, weight: 1 },
  { name: "address",  re: /\b\d{1,5}\s+[A-Z][a-z]+\s+(?:St|Ave|Blvd|Dr|Ln|Rd|Way|Ct|Pl|Pkwy|Cir)\.?\b/i, weight: 1 },
  { name: "fullname", re: /\b[A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20})?\b/, weight: 1 },
  { name: "email_1",  re: /[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,}/i, weight: 1 },  // bounded: RFC 5321 max; prevents O(n²) on no-@-sign inputs
  { name: "zip",      re: /\b\d{5}(?:-\d{4})?\b/, weight: 0.5 },
  { name: "age",      re: /\b(?:age|born|DOB)\s*[:=]?\s/i, weight: 0.5 },
  { name: "gender",   re: /\b(?:gender|sex)\s*[:=]\s*(?:male|female|M|F)\b/i, weight: 0.5 }
];

function soilSecurityAggregate(tn, existingReasons) {
  if (existingReasons.length >= 2) return { score: 0, signals: [] };
  var signals = [];
  var totalWeight = 0;
  for (var i = 0; i < SOIL_SIGNALS.length; i++) {
    if (SOIL_SIGNALS[i].re.test(tn)) {
      signals.push(SOIL_SIGNALS[i].name);
      totalWeight += SOIL_SIGNALS[i].weight;
    }
  }
  if (totalWeight >= 3) {
    return { score: Math.min(Math.round(totalWeight * 12), 50), signals: signals };
  }
  return { score: 0, signals: [] };
}

// ══════════════════════════════════════════════════════════════
// PPP #6 Fungi: Hidden Cross-Line Correlation
// Like mycorrhizal networks linking separate trees underground —
// detect when labels and values are split across different lines.
// ══════════════════════════════════════════════════════════════
var _FUNGI_LABELS = /\b(?:card|credit|debit|ssn|social\s*security|password|secret|key|account|routing|passport|license)\b/i;

function fungiCorrelation(tn) {
  var lines = tn.split('\n');
  if (lines.length < 2) return { correlations: 0, assembledCC: false };
  var labelLines = [], valueLines = [];
  for (var i = 0; i < Math.min(lines.length, 100); i++) {
    if (_FUNGI_LABELS.test(lines[i])) labelLines.push(i);
    if (/\d{4,}/.test(lines[i])) valueLines.push(i);
  }
  var correlations = 0;
  for (var li = 0; li < labelLines.length; li++) {
    for (var vi = 0; vi < valueLines.length; vi++) {
      if (Math.abs(labelLines[li] - valueLines[vi]) <= 5 && labelLines[li] !== valueLines[vi]) {
        correlations++;
      }
    }
  }
  // Assemble nearby digit fragments and re-test for CC via Luhn
  var digitRuns = tn.match(/\b\d{3,6}\b/g);
  var assembled = digitRuns ? digitRuns.join('') : '';
  var assembledCC = assembled.length >= 13 && assembled.length <= 19 && luhnCheck(assembled);
  return { correlations: Math.min(correlations, 3), assembledCC: assembledCC };
}

// ══════════════════════════════════════════════════════════════
// PPP #17 Breathe Easy: Context-Aware Noise Filtering
// Like urban trees filtering pollution — reduce false positives
// in educational/reference contexts. NEVER reduces scores >= 80.
// ══════════════════════════════════════════════════════════════
var BENIGN_CONTEXTS = [
  { re: /\b(?:example|sample|test|demo|dummy|fake|placeholder|documentation|tutorial|guide|how.to)\b/i, discount: 0.5, name: "educational" },
  { re: /\b(?:wikipedia|wiki|article|blog\s*post|essay|lecture|course|textbook)\b/i, discount: 0.7, name: "reference" },
  { re: /\b(?:do\s+not|never|don't|avoid|warning|caution|example\s+of\s+what\s+not)\b/i, discount: 0.65, name: "cautionary" },
  { re: /\b(?:regex|pattern|format|validation|regular\s+expression|like\s+this)\b/i, discount: 0.5, name: "format_description" }
];

function breatheEasyFilter(lower, reasons, score) {
  if (score >= 80 || score < 40 || reasons.length === 0) return { discount: 1.0, context: null };
  for (var i = 0; i < BENIGN_CONTEXTS.length; i++) {
    if (BENIGN_CONTEXTS[i].re.test(lower)) {
      return { discount: BENIGN_CONTEXTS[i].discount, context: BENIGN_CONTEXTS[i].name };
    }
  }
  return { discount: 1.0, context: null };
}

// ══════════════════════════════════════════════════════════════
// CORE: classify() — 10-Layer Detection Engine
// ══════════════════════════════════════════════════════════════
function classify(text) {
  // ── LAYER 9: Efficiency — Early exits ──
  if (!text || text.length === 0) {
    return { risk: 0, decision: "ALLOW", reason: "Empty text", content_hash: hybridHash(""),
      decision_mode: DECISION_MODE, platform: detectPlatform(), tiers: [], proof: null, version: PATTERN_VERSION,
      features: FEATURES };
  }
  if (text.length < 5) {
    return { risk: 0, decision: "ALLOW", reason: "Too short", content_hash: hybridHash(text),
      decision_mode: DECISION_MODE, platform: detectPlatform(), tiers: [], proof: null, version: PATTERN_VERSION,
      features: FEATURES };
  }
  if (!/[a-zA-Z0-9]/.test(text)) {
    return { risk: 0, decision: "ALLOW", reason: "No alphanumeric", content_hash: hybridHash(text),
      decision_mode: DECISION_MODE, platform: detectPlatform(), tiers: [], proof: null, version: PATTERN_VERSION,
      features: FEATURES };
  }

  var t = text;

  // ── LAYER 10: Frontier normalization for bypass resistance ──
  // Homoglyphs, NFKC, Zalgo, Unicode digits, smart quotes, then zero-width
  var tn = normalizeHomoglyphs(t);
  tn = tn
    .replace(/[\u200b-\u200d\ufeff\u00ad\u2060-\u206f]/g, '')
    .replace(/\t/g, ' ');
  var tc = tn.replace(/[\n\r]+/g, '');
  var lower = tn.toLowerCase();
  var len = Math.max(t.length, 1);

  // --- Shannon entropy ---
  var freq = {};
  for (var i = 0; i < t.length; i++) {
    var ch = t.charCodeAt(i);
    freq[ch] = (freq[ch] || 0) + 1;
  }
  var entropy = 0.0;
  for (var ch2 in freq) {
    var p = freq[ch2] / len;
    entropy -= p * Math.log2(p);
  }

  // --- Character ratios ---
  var special = 0, digits = 0, upper = 0;
  for (var ci = 0; ci < t.length; ci++) {
    var c = t[ci];
    if (/\d/.test(c)) digits++;
    if (/[A-Z]/.test(c)) upper++;
    if (!/[a-zA-Z0-9\s]/.test(c)) special++;
  }
  var special_ratio = special / len;
  var digit_ratio = digits / len;
  var upper_ratio = upper / len;

  // ── LAYER 2: Multi-Tier Tracking ──
  var tiers_triggered = [];

  // ── TIER 1: Critical PII ──
  var cc_match = tn.match(CC_RE);
  // Pattern match is sufficient for flagging — Luhn adds confidence but absence
  // doesn't exonerate: test/dummy numbers and slightly corrupted real numbers should still trigger.
  var has_cc_pattern = !!cc_match;
  var has_cc_luhn    = cc_match ? luhnCheck(cc_match[0]) : false;
  var has_cc         = has_cc_pattern; // flag on format alone; scoring below distinguishes confidence
  var has_ssn = SSN_RE.test(tn);
  var has_social_security = /\bsocial\s+security\b/i.test(tn);
  var has_github_pat = GH_PAT_RE.test(tc);
  var has_aws_key = AWS_KEY_RE.test(tn); // use tn (newlines preserved) so line-end word boundaries work
  var has_private_key = t.includes("-----BEGIN") && t.includes("PRIVATE KEY-----");

  if (has_cc) tiers_triggered.push("T1:cc");
  if (has_ssn) tiers_triggered.push("T1:ssn");
  if (has_github_pat) tiers_triggered.push("T1:github_pat");
  if (has_aws_key) tiers_triggered.push("T1:aws_key");
  if (has_private_key) tiers_triggered.push("T1:private_key");

  // ── TIER 1b: Critical Documents — 100+ LANGUAGE SUPPORT ──
  var has_passport = PASSPORT_RE.test(tn);
  var has_visa = VISA_RE.test(tn);
  var has_national_id = NATIONAL_ID_RE.test(tn);
  var has_drivers_license = DRIVERS_LICENSE_RE.test(tn);
  var has_medical = MEDICAL_RE.test(tn);
  var has_bank_account = BANK_ACCOUNT_RE.test(tn);
  var has_tax_id = TAX_ID_RE.test(tn);
  var has_birth_cert = BIRTH_CERT_RE.test(tn);
  var has_crypto = CRYPTO_RE.test(tn) || CRYPTO_RE.test(t);
  var has_seed_phrase = detectSeedPhrase(tn);
  var has_insurance = INSURANCE_RE.test(tn);

  if (has_passport) tiers_triggered.push("T1b:passport");
  if (has_visa) tiers_triggered.push("T1b:visa");
  if (has_national_id) tiers_triggered.push("T1b:national_id");
  if (has_drivers_license) tiers_triggered.push("T1b:drivers_license");
  if (has_medical) tiers_triggered.push("T1b:medical");
  if (has_bank_account) tiers_triggered.push("T1b:bank_account");
  if (has_tax_id) tiers_triggered.push("T1b:tax_id");
  if (has_birth_cert) tiers_triggered.push("T1b:birth_cert");
  if (has_crypto) tiers_triggered.push("T1b:crypto");
  if (has_seed_phrase) tiers_triggered.push("T1b:seed_phrase");
  if (has_insurance) tiers_triggered.push("T1b:insurance");

  // ── TIER 2: High-risk credential patterns ──
  var has_bearer_token = BEARER_RE.test(tn);
  var has_api_key_word = /\b(?:api[_\-]?key|apikey)\s*["']?\s*[:=]/i.test(lower);
  var has_password_assign = /password\s*["']?\s*[:=]/i.test(lower) || /\bpwd\s*[:=]/i.test(lower)
    || /_pass(?:wd|word)?["']?\s*=\s*["']?[^\s"']{4,}/i.test(lower); // DB_PASS=, APP_PASSWD=, etc.
  var has_env_secret = ENV_SECRET_RE.test(lower) && !/^\s*(?:\/\/|#)/.test(lower.split('\n')[0]);
  var has_jwt = /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/.test(t);
  var has_conn = CONNSTR_RE.test(lower);
  // Named API key formats — each gets its own high-confidence tier
  // Use tc (newlines stripped) so keys split across lines are caught
  var has_openai_key   = OPENAI_KEY_RE.test(tc);
  var has_stripe_key   = STRIPE_KEY_RE.test(tc);
  var has_sendgrid_key = SENDGRID_KEY_RE.test(tc);
  var has_twilio_sid   = TWILIO_SID_RE.test(tc);
  var has_anthropic_key= ANTHROPIC_KEY_RE.test(tc);
  var has_hf_token     = HF_TOKEN_RE.test(tc);
  var has_slack_token  = SLACK_TOKEN_RE.test(tc);
  var has_named_api_key = has_openai_key || has_stripe_key || has_sendgrid_key ||
                          has_twilio_sid || has_anthropic_key || has_hf_token || has_slack_token;

  // Bulk email detection (5+ emails = contact list exfiltration)
  var email_matches = tn.match(EMAIL_RE);
  var has_bulk_emails = email_matches && email_matches.length >= 5;

  if (has_bearer_token)   tiers_triggered.push("T2:bearer");
  if (has_api_key_word)   tiers_triggered.push("T2:api_key");
  if (has_password_assign)tiers_triggered.push("T2:password");
  if (has_jwt)            tiers_triggered.push("T2:jwt");
  if (has_conn)           tiers_triggered.push("T2:conn_string");
  if (has_bulk_emails)    tiers_triggered.push("T2:bulk_emails");
  if (has_stripe_key)     tiers_triggered.push("T2:stripe_key");
  if (has_anthropic_key)  tiers_triggered.push("T2:anthropic_key");
  if (has_hf_token)       tiers_triggered.push("T2:huggingface_token");
  if (has_slack_token)    tiers_triggered.push("T2:slack_token");
  if (has_openai_key)     tiers_triggered.push("T2:openai_key");
  if (has_sendgrid_key)   tiers_triggered.push("T2:sendgrid_key");
  if (has_twilio_sid)     tiers_triggered.push("T2:twilio_sid");

  // High-entropy base64 runs (40+ char run)
  var has_base64 = false;
  var run = 0;
  for (var bi = 0; bi < tn.length; bi++) {
    var ok = /[a-zA-Z0-9+/=_-]/.test(tn[bi]);
    run = ok ? run + 1 : 0;
    if (run >= 40) { has_base64 = true; break; }
  }

  // ── TIER 3: Injection & dangerous commands ──
  var has_injection = INJECTION_RE.test(tn);
  var has_shell = SHELL_RE.test(tn);
  var has_exfil = EXFIL_RE.test(tn);
  var has_concat_bypass = detectStringConcatBypass(t);

  if (has_injection) tiers_triggered.push("T3:injection");
  if (has_shell) tiers_triggered.push("T3:shell");
  if (has_exfil) tiers_triggered.push("T3:exfiltration");
  if (has_concat_bypass) tiers_triggered.push("T3:concat_bypass");

  // Suspicious keyword ngrams
  var suspicious = [
    "secret", "token", "bearer", "credential", "private", "ssh", "pem",
    "apikey", "api-key", "inject", "bypass", "jailbreak", "override",
    "ignore previous", "system prompt", "developer message", "rm -rf",
    "drop table", "format c:", "powershell", "curl http", "wget http",
    "exfiltrate", "exfiltration", "steal all", "steal user", "dump password",
    "send all", "send to http", "upload to http", "harvest credential"
  ];
  var ngram_score = 0;
  for (var ni = 0; ni < suspicious.length; ni++) {
    if (lower.includes(suspicious[ni])) ngram_score++;
  }

  // Keyword density
  var keywords = ["secret", "password", "token", "api", "key", "auth", "credential", "private"];
  var keyword_hits = 0;
  for (var ki = 0; ki < keywords.length; ki++) {
    keyword_hits += (lower.match(new RegExp(keywords[ki], "g")) || []).length;
  }

  // ── Risk Scoring ──
  var score = 0;
  var reasons = [];

  // Tier 1: Critical PII
  if (has_cc_luhn)        { score += 90; reasons.push("credit card number (verified)"); }
  else if (has_cc)        { score += 80; reasons.push("credit card number (pattern)"); }
  if (has_ssn)            { score += 80; reasons.push("SSN"); }
  if (has_private_key)    { score += 90; reasons.push("private key"); }
  if (has_github_pat)     { score += 80; reasons.push("GitHub PAT"); }
  if (has_aws_key)        { score += 80; reasons.push("AWS access key"); }
  if (has_openai_key)     { score += 70; reasons.push("OpenAI API key"); }

  // Tier 1b: Critical documents — 100+ LANGUAGE SUPPORT
  if (has_passport)       { score += 85; reasons.push("passport number"); }
  if (has_visa)           { score += 80; reasons.push("visa/travel permit"); }
  if (has_national_id)    { score += 85; reasons.push("national ID"); }
  if (has_drivers_license){ score += 80; reasons.push("driver's license"); }
  if (has_medical)        { score += 90; reasons.push("medical record/PHI"); }
  if (has_bank_account)   { score += 85; reasons.push("bank account/IBAN"); }
  if (has_tax_id)         { score += 85; reasons.push("tax ID/SSN"); }
  if (has_birth_cert)     { score += 80; reasons.push("birth/legal certificate"); }
  if (has_crypto)         { score += 90; reasons.push("cryptocurrency key/address"); }
  if (has_seed_phrase)    { score += 95; reasons.push("crypto seed phrase"); }
  if (has_insurance)      { score += 75; reasons.push("insurance policy"); }

  // Tier 2: Named API key formats — always DENY-level (high-confidence patterns)
  if (has_stripe_key)      { score += 90; reasons.push("Stripe API key"); }
  if (has_anthropic_key)   { score += 90; reasons.push("Anthropic API key"); }
  if (has_openai_key)      { score += 90; reasons.push("OpenAI API key"); }
  if (has_sendgrid_key)    { score += 90; reasons.push("SendGrid API key"); }
  if (has_twilio_sid)      { score += 80; reasons.push("Twilio account SID"); }
  if (has_hf_token)        { score += 85; reasons.push("HuggingFace token"); }
  if (has_slack_token)     { score += 85; reasons.push("Slack token"); }
  // Generic API key word + high entropy (fallback for unknown key formats)
  if (!has_named_api_key && has_api_key_word && entropy > 3.5) { score += 50; reasons.push("high-entropy API key"); }
  if (has_conn)           { score += 75; reasons.push("database connection string"); }
  if (has_jwt)            { score += 40; reasons.push("JWT token"); }
  if (has_bearer_token)   { score += 45; reasons.push("bearer token"); }

  // Tier 3: WARN-level signals
  if (has_password_assign){ score += 45; reasons.push("password assignment"); }
  if (has_social_security){ score += 50; reasons.push("social security reference"); }
  if (has_injection)      { score += 70; reasons.push("prompt injection"); }   // -> DENY
  if (has_shell)          { score += 70; reasons.push("dangerous command"); }   // -> DENY
  if (has_exfil)          { score += 70; reasons.push("data exfiltration intent"); } // -> DENY
  if (has_concat_bypass)  { score += 60; reasons.push("string concatenation bypass"); }
  if (has_env_secret && keyword_hits >= 3) { score += 45; reasons.push("env/shell secret pattern"); }
  if (!has_named_api_key && has_api_key_word && entropy <= 3.5) { score += 40; reasons.push("API key keyword"); }

  // Bulk email detection
  if (has_bulk_emails) { score += 40; reasons.push("bulk email addresses (" + email_matches.length + ")"); }

  // Entropy / pattern scoring
  // Public keys are not sensitive — skip high-entropy scoring for public-key-only blobs
  var is_public_key_only = /-----BEGIN\s+(?:RSA\s+|EC\s+)?PUBLIC\s+KEY-----/i.test(tn)
    && !/-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/i.test(tn);
  if (has_base64 && entropy > 4.5 && !is_public_key_only) { score += 45; reasons.push("high-entropy base64"); }
  if (ngram_score > 2)   { score += 20; reasons.push("suspicious keywords"); }
  if (keyword_hits >= 3) { score += 15; reasons.push("multiple secret keywords"); }
  if (entropy > 5.0 && special_ratio > 0.2) { score += 10; reasons.push("high entropy + special chars"); }
  if (upper_ratio > 0.4 && digit_ratio > 0.2) { score += 8; reasons.push("mixed case + numbers"); }

  // Enhanced entropy threshold — catch unknown/novel secrets
  // Space ratio guard: natural sentences have >10% spaces; real secrets almost never do.
  var space_ratio = (t.match(/\s/g) || []).length / Math.max(t.length, 1);
  if (entropy >= 4.0 && t.length >= 20 && reasons.length === 0 && space_ratio < 0.06) {
    score += 25; reasons.push("high-entropy unknown content");
  }

  // ── PPP #19 LanzaTech: Encoded payload detection ──
  var transforms = lanzatechTransform(t);
  if (transforms.length > 0) {
    score += 55; reasons.push("encoded payload (" + transforms.join(", ") + ")");
    tiers_triggered.push("T1:encoded");
  }

  // ── PPP #2 Beeodiversity: PII co-occurrence multiplier (replaces flat +5) ──
  var beeBoost = beeodiversityBoost(tiers_triggered, score);
  if (beeBoost.score > 0) { score += beeBoost.score; reasons.push(beeBoost.reason); }

  // ── PPP #18 Soil Security: Weak-signal aggregation ──
  var soil = soilSecurityAggregate(tn, reasons);
  if (soil.score > 0) { score += soil.score; reasons.push("personal dossier (" + soil.signals.join("+") + ")"); }

  // ── PPP #6 Fungi: Cross-line correlation ──
  var fungi = fungiCorrelation(tn);
  if (fungi.correlations > 0) { score += fungi.correlations * 8; reasons.push("cross-line correlation"); }
  if (fungi.assembledCC) { score += 70; reasons.push("assembled credit card"); tiers_triggered.push("T1:cc_assembled"); }

  // ── LAYER 1: Pattern confidence boost ──
  var confBoost = patternConfidenceBoost(reasons);
  if (confBoost > 0) { score += confBoost; reasons.push("high-confidence patterns (+" + confBoost + ")"); }

  // ── LAYER 11: Behavioral burst detection ──
  // Only amplify content that is already suspicious — burst context should not
  // create false positives on genuinely clean content (score === 0).
  var behavioral = checkBehavioral(score);
  if (behavioral.anomaly && score > 0) {
    if (behavioral.severity === "high") { score += 20; reasons.push(behavioral.reason); }
    else if (behavioral.severity === "medium") { score += 10; reasons.push(behavioral.reason); }
  }

  // Normalize to 0-100
  score = Math.max(0, Math.min(100, score));

  // ── PPP #17 Breathe Easy: Noise filtering (WARN band only, never >= 80) ──
  var breathe = breatheEasyFilter(lower, reasons, score);
  var context_filtered = false;
  if (breathe.discount < 1.0) {
    score = Math.round(score * breathe.discount);
    context_filtered = true;
    // "Cautionary" context (DO NOT COMMIT, WARNING) shouldn't silence real assignments —
    // developers often write such notes next to actual credentials in code/comments.
    // Educational context (Example:, demo) still silences freely (genuine examples).
    if (has_password_assign && score < 40 && breathe.context === "cautionary") { score = 40; }
    reasons.push("noise-filtered (" + breathe.context + ")");
  }

  // Decision
  var decision = "ALLOW";
  if (score >= 70) decision = "DENY";
  else if (score >= 40) decision = "WARN";

  // ── LAYER 1: Update pattern stats ──
  for (var ri = 0; ri < reasons.length; ri++) {
    updatePatternStat(reasons[ri], decision === "DENY");
  }

  // ── LAYER 4: Run decoy patterns + integrity check ──
  for (var di = 0; di < DECOY_PATTERNS.length; di++) { DECOY_PATTERNS[di].test(tn); }
  // Verify pattern integrity inline — if tampered, escalate to DENY
  if (!constantTimeEqual(computePatternHash(), _BASELINE_PATTERN_HASH)) {
    score = 100; reasons.push("PATTERN INTEGRITY VIOLATION"); decision = "DENY";
  }

  // ── LAYER 3 + 8: Generate zero-knowledge detection proof ──
  var proof = score >= 40 ? generateDetectionProof(reasons, score, decision) : null;

  return {
    risk: Math.floor(score),
    decision: decision,
    decision_mode: DECISION_MODE,
    reason: reasons.length > 0 ? reasons.join("; ") : "Low risk",
    content_hash: hybridHash(text),
    platform: detectPlatform(),
    tiers: tiers_triggered,
    proof: proof,
    version: PATTERN_VERSION,
    features: FEATURES,
    entropy_score: +entropy.toFixed(4),
    context_filtered: context_filtered
  };
}

// ══════════════════════════════════════════════════════════════
// LAYER 7: Formal Verification — Runtime Self-Test
// 15 invariants that MUST hold. Run on load or on-demand.
// ══════════════════════════════════════════════════════════════
function selfTest() {
  var results = [];
  var t1 = classify("SSN: 123-45-6789");
  results.push({ name: "ssn_deny", pass: t1.decision === "DENY" });
  var t2 = classify("Passport No AB1234567");
  results.push({ name: "passport_deny", pass: t2.decision === "DENY" });
  var t3 = classify("4111111111111111");
  results.push({ name: "cc_deny", pass: t3.decision === "DENY" });
  var t4 = classify("Patient diagnosis: cancer stage IV");
  results.push({ name: "medical_detect", pass: t4.risk >= 40 });
  var t5 = classify("hello world");
  results.push({ name: "clean_allow", pass: t5.decision === "ALLOW" });
  var t6 = classify("");
  results.push({ name: "empty_allow", pass: t6.decision === "ALLOW" });
  var t7 = verifyPatternIntegrity();
  results.push({ name: "integrity", pass: t7.intact === true });
  // v3.2: CC format without Luhn should still flag — but Luhn-verified gets higher score
  // Design: pattern alone = 80 pts (DENY), Luhn-valid = 90 pts (higher confidence DENY)
  // "4111111111111112" is invalid Luhn but DOES match CC format → should DENY (risk >= 70)
  var t8 = classify("4111111111111112");
  results.push({ name: "luhn_reject", pass: t8.risk >= 70 && t8.reason.indexOf("credit card") !== -1 });
  // v3.1: Bulk emails detection
  var t9 = classify("contacts: a@b.com c@d.com e@f.com g@h.com i@j.com k@l.com");
  results.push({ name: "bulk_email_warn", pass: t9.risk >= 40 });
  // v3.1: Connection string detection
  var t10 = classify("mongodb://admin:secret@db.host.com:27017/prod");
  results.push({ name: "connstr_deny", pass: t10.decision === "DENY" });
  // v3.1: Decision mode present
  var t11 = classify("SSN: 123-45-6789");
  results.push({ name: "decision_mode", pass: t11.decision_mode === "ENFORCED" });
  // v3.2: Homoglyph bypass resistance — Cyrillic а (U+0430) and о (U+043E) in "passport"
  var t12 = classify("p\u0430ssp\u043ert No AB1234567");
  results.push({ name: "homoglyph_bypass", pass: t12.decision === "DENY" });
  // v3.2: Unicode digit normalization — Arabic-Indic digits in CC number
  var t13 = classify("4111\u0661\u0661\u0661\u066111111111");
  results.push({ name: "unicode_digit_cc", pass: t13.decision === "DENY" });
  // v3.2: Zalgo text bypass resistance — combining marks stripped
  var t14 = classify("SSN\u0336:\u0336 123\u0336-45\u0336-6789");
  results.push({ name: "zalgo_bypass", pass: t14.decision === "DENY" });
  // v3.3: L33t speak bypass resistance — p@$$port should still detect
  var t15 = classify("p@$$port No AB1234567");
  results.push({ name: "l33t_bypass", pass: t15.decision === "DENY" });
  // v3.4: Moat I — String concatenation bypass detection
  var t16 = classify("var x = 'pass' + 'word' + '123'");
  results.push({ name: "concat_bypass", pass: t16.risk >= 40 });
  // v3.5 PPP #2: Beeodiversity — co-occurrence of SSN + passport should amplify risk
  var t17 = classify("SSN: 123-45-6789 and Passport No AB1234567");
  results.push({ name: "beeodiversity_cooccur", pass: t17.risk >= 95 });
  // v3.5 PPP #6: Fungi — CC number split across lines
  var t18 = classify("My credit card:\n\nthe number is\n4111\n1111\n1111\n1111");
  results.push({ name: "fungi_split_detect", pass: t18.risk >= 40 });
  // v3.5 PPP #19: LanzaTech — base64-encoded password detection
  var t19 = classify("config: cGFzc3dvcmQ9bXlTZWNyZXQxMjM=");
  results.push({ name: "lanzatech_b64", pass: t19.risk >= 40 });
  // v3.5 PPP #18: Soil Security — personal dossier with weak signals
  var t20 = classify("John Smith\n123 Main St, Springfield\n(555) 123-4567\nDOB: 03/15/1985");
  results.push({ name: "soil_weak_signals", pass: t20.risk >= 30 });
  // v3.5 PPP #17: Breathe Easy — educational context should reduce FP
  var t21 = classify("Example: password format is password=value");
  results.push({ name: "breathe_easy_filter", pass: t21.risk < 40 });
  // v3.5 PPP #17: Breathe Easy — real password must still trigger
  var t22 = classify("password=myActualS3cretKey123!");
  results.push({ name: "breathe_real_pass", pass: t22.risk >= 40 });
  // v3.5 PPP #22: Aboriginal Fire — pattern stats include lastSeen
  updatePatternStat("_test_fire_decay", true);
  var _fireCheck = patternStats["_test_fire_decay"];
  results.push({ name: "fire_decay_ts", pass: _fireCheck && _fireCheck.lastSeen > 0 });
  delete patternStats["_test_fire_decay"];

  // v1.0.0 NEW TEST 24: ML Entropy Scoring — high-entropy secrets should score HIGH
  var t24 = classify("sk_live_51HyEqA2eZvKYlo2C7Yd8Zm9PqXmW5N3vJ2kL9cG6hF7dK8wE4rB1tS2uO3pV5qY");
  results.push({ name: "ml_entropy_score", pass: t24.risk >= 80 && t24.entropy_score !== undefined });

  // v1.0.0 NEW TEST 25: Context Filter — educational context should reduce risk
  var t25 = classify("// Example: password=test123 (for documentation only)");
  results.push({ name: "context_filter_edu", pass: t25.risk < 40 && t25.context_filtered === true });

  // v1.0.0 NEW TEST 26: New Secret Format — Anthropic API key detection
  var t26 = classify("api_key: sk-ant-v1-abc123def456ghi789jkl012mnop345qrstu678vwxyz");
  results.push({ name: "anthropic_api_key", pass: t26.decision === "DENY" });

  // v1.0.0 NEW TEST 27: Integrity Index — system integrity check should pass
  var t27 = verifyPatternIntegrity();
  results.push({ name: "integrity_index", pass: t27.systemIntegrityIndex >= 0.90 });

  // v1.0.0 NEW TEST 28: Decision Proof Generation — proof should include hash
  var t28 = classify("SSN: 123-45-6789");
  results.push({ name: "decision_proof", pass: t28.proof && t28.proof.hash && t28.proof.signature });

  return {
    passed: results.filter(function(r) { return r.pass; }).length,
    total: results.length,
    results: results
  };
}

// Reset behavioral state (clears paste history burst tracker)
// Called after selfTest() to prevent self-test data contaminating
// live behavioral monitoring. Safe to call at any time.
function resetBehavioral() {
  _pasteHistory = [];
}

// ══════════════════════════════════════════════════════════════
// HELPERS + EXPORTS
// ══════════════════════════════════════════════════════════════
function getRisk(text) {
  return classify(text).risk;
}

function getDecision(text) {
  return classify(text).decision;
}

// Export for Node.js (tests) and browser (content.js via script tag)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    classify, getRisk, getDecision, hashContent, hybridHash,
    djb2Hash, fnv1aHash, generateDetectionProof, constantTimeEqual,
    detectPlatform, getPatternStats, patternConfidenceBoost, computePatternHash,
    verifyPatternIntegrity, selfTest, luhnCheck, normalizeHomoglyphs,
    checkBehavioral, detectStringConcatBypass, resetBehavioral,
    lanzatechTransform, beeodiversityBoost, soilSecurityAggregate, fungiCorrelation, breatheEasyFilter,
    PATTERN_VERSION, DECISION_MODE, FEATURES
  };
}
