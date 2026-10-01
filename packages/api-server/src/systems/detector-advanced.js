'use strict';
// detector-advanced.js — secretScan (57 patterns) | detectGPT (6 signals) | ahoCorasick | pHashSimilarity
// Pure CommonJS, no external deps. Adapted from @kasbah/detector TypeScript sources.

// ── SECTION 1: SECRET SCAN ────────────────────────────────────────────────────

/** Confidence values per severity tier */
const SEVERITY_CONFIDENCE = { CRITICAL: 0.98, HIGH: 0.90, MEDIUM: 0.75, LOW: 0.60 };

/**
 * All 57 secret detection patterns.
 * Each entry: { regex, type, severity, id }
 */
const SECRET_PATTERNS = [
  // TIER 1: CRITICAL (15)
  { id: 'AWS-001',      severity: 'CRITICAL', type: 'AWS Access Key ID',              regex: /AKIA[0-9A-Z]{16}/g },
  { id: 'AWS-002',      severity: 'CRITICAL', type: 'AWS Secret Access Key',          regex: /(?<![A-Za-z0-9_])[A-Za-z0-9_]{40}(?![A-Za-z0-9_])/g },
  { id: 'GITHUB-001',   severity: 'CRITICAL', type: 'GitHub Personal Access Token',   regex: /ghp_[a-zA-Z0-9]{36}/g },
  { id: 'GITHUB-002',   severity: 'CRITICAL', type: 'GitHub OAuth Token',             regex: /gho_[a-zA-Z0-9]{36}/g },
  { id: 'GITHUB-003',   severity: 'CRITICAL', type: 'GitHub User-to-Server Token',    regex: /ghu_[a-zA-Z0-9]{36}/g },
  { id: 'GITHUB-004',   severity: 'CRITICAL', type: 'GitHub Server-to-Server Token',  regex: /ghs_[a-zA-Z0-9]{36}/g },
  { id: 'GITHUB-005',   severity: 'CRITICAL', type: 'GitHub Refresh Token',           regex: /ghr_[a-zA-Z0-9]{36}/g },
  { id: 'OPENAI-001',   severity: 'CRITICAL', type: 'OpenAI API Key',                 regex: /sk-[a-zA-Z0-9]{48}/g },
  { id: 'SLACK-001',    severity: 'CRITICAL', type: 'Slack Token',                    regex: /xox[baprs]-[0-9a-zA-Z-]+/g },
  { id: 'KEY-001',      severity: 'CRITICAL', type: 'Private Key',                    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { id: 'KEY-002',      severity: 'CRITICAL', type: 'PGP Private Key',                regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },
  { id: 'STRIPE-001',   severity: 'CRITICAL', type: 'Stripe Secret Key',              regex: /sk_live_[0-9a-zA-Z]{24}/g },
  { id: 'STRIPE-002',   severity: 'CRITICAL', type: 'Stripe Restricted Key',          regex: /rk_live_[0-9a-zA-Z]{24}/g },
  { id: 'SQUARE-001',   severity: 'CRITICAL', type: 'Square Access Token',            regex: /sq0atp-[0-9A-Za-z\-_]{22}/g },
  { id: 'SQUARE-002',   severity: 'CRITICAL', type: 'Square Client Secret',           regex: /sq0csp-[0-9A-Za-z\-_]{43}/g },

  // TIER 2: HIGH (20)
  { id: 'GOOGLE-001',   severity: 'HIGH', type: 'Google API Key',                     regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { id: 'GOOGLE-002',   severity: 'HIGH', type: 'Google OAuth Client ID',             regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g },
  { id: 'GOOGLE-003',   severity: 'HIGH', type: 'Google OAuth Token',                 regex: /ya29\.[0-9A-Za-z\-_]+/g },
  { id: 'MONGO-001',    severity: 'HIGH', type: 'MongoDB Connection String',          regex: /mongodb(\+srv)?:\/\/[^\s'"]+/g },
  { id: 'POSTGRES-001', severity: 'HIGH', type: 'PostgreSQL Connection String',       regex: /postgres(?:ql)?:\/\/[^\s'"]+/g },
  { id: 'MYSQL-001',    severity: 'HIGH', type: 'MySQL Connection String',            regex: /mysql:\/\/[^\s'"]+/g },
  { id: 'REDIS-001',    severity: 'HIGH', type: 'Redis Connection String',            regex: /redis:\/\/[^\s'"]+/g },
  { id: 'RABBITMQ-001', severity: 'HIGH', type: 'RabbitMQ Connection String',         regex: /amqp:\/\/[^\s'"]+/g },
  { id: 'BEARER-001',   severity: 'HIGH', type: 'Bearer Token',                       regex: /Bearer\s+[a-zA-Z0-9\-._~+/]+=*/g },
  { id: 'BASIC-001',    severity: 'HIGH', type: 'Basic Auth Credentials',             regex: /Basic\s+[a-zA-Z0-9+/]+=*/g },
  { id: 'TWILIO-001',   severity: 'HIGH', type: 'Twilio Credential',                  regex: /TWILIO_AUTH_TOKEN|TWILIO_API_KEY|twilio.*key/gi },
  { id: 'SENDGRID-001', severity: 'HIGH', type: 'SendGrid API Key',                   regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g },
  { id: 'HEROKU-001',   severity: 'HIGH', type: 'Heroku API Key',                     regex: /heroku.*key|heroku_api_key|HEROKU_API_KEY/gi },
  { id: 'DO-001',       severity: 'HIGH', type: 'DigitalOcean Token',                 regex: /DIGITALOCEAN_TOKEN|do_token|digitalocean.*key/gi },
  { id: 'AZURE-001',    severity: 'HIGH', type: 'Azure Credential',                   regex: /azure.*key|AZURE_CLIENT_SECRET|azure.*secret/gi },
  { id: 'CF-001',       severity: 'HIGH', type: 'Cloud Foundry Password',             regex: /CF_PASSWORD|cf.*password|cloudfoundry.*password/gi },
  { id: 'FACEBOOK-001', severity: 'HIGH', type: 'Facebook Access Token',              regex: /FB[0-9A-F]{8}\-[0-9A-F]{4}\-[0-9A-F]{4}\-[0-9A-F]{4}\-[0-9A-F]{12}/gi },
  { id: 'FACEBOOK-002', severity: 'HIGH', type: 'Facebook Page Token',                regex: /EAACEdEose0cBA[0-9A-Za-z]+/g },
  { id: 'DROPBOX-001',  severity: 'HIGH', type: 'Dropbox Access Token',               regex: /1\/[0-9A-Za-z\-_]{43}/g },
  { id: 'SLACK-002',    severity: 'HIGH', type: 'Slack Webhook URL',                  regex: /sl\.[0-9A-Za-z\-_]{43}/g },

  // TIER 3: MEDIUM (15)
  { id: 'PII-001',      severity: 'MEDIUM', type: 'Social Security Number',           regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { id: 'PII-002',      severity: 'MEDIUM', type: 'Credit Card Number',               regex: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g },
  { id: 'PII-003',      severity: 'MEDIUM', type: 'Email Address',                    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g },
  { id: 'PII-004',      severity: 'MEDIUM', type: 'Phone Number',                     regex: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g },
  { id: 'PII-005',      severity: 'MEDIUM', type: 'IP Address',                       regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g },
  { id: 'PII-006',      severity: 'MEDIUM', type: 'UK Postcode',                      regex: /\b[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2}\b/gi },
  { id: 'PII-007',      severity: 'MEDIUM', type: 'US ZIP Code',                      regex: /\b\d{5}(?:-\d{4})?\b/g },
  { id: 'PII-008',      severity: 'MEDIUM', type: 'Passport Number',                  regex: /passport.*number|passport_no|passportnumber/gi },
  { id: 'PII-009',      severity: 'MEDIUM', type: 'Driver License Number',            regex: /driver.*license|dl_number|license.*number/gi },
  { id: 'PII-010',      severity: 'MEDIUM', type: 'National ID Pattern',              regex: /\b[A-Z]{2}\d{6}[A-Z]?\b/g },
  { id: 'AI-001',       severity: 'MEDIUM', type: 'ChatGPT Credential Reference',     regex: /CHATGPT.*PASSWORD|CHATGPT.*KEY|chatgpt.*credential/gi },
  { id: 'AI-002',       severity: 'MEDIUM', type: 'Claude Credential Reference',      regex: /CLAUDE.*PASSWORD|CLAUDE.*KEY|claude.*credential/gi },
  { id: 'AI-003',       severity: 'MEDIUM', type: 'AI Data Send Intent',              regex: /SEND.*TO.*CHATGPT|SEND.*TO.*CLAUDE|send.*to.*AI/gi },
  { id: 'AI-004',       severity: 'MEDIUM', type: 'Prompt with Secret',               regex: /PROMPT.*CONTAINS.*SECRET|PROMPT.*CONTAINS.*KEY/gi },
  { id: 'AI-005',       severity: 'MEDIUM', type: 'Direct Credential Share',          regex: /HERE.*MY.*API.*KEY|HERE.*MY.*PASSWORD|HERE.*MY.*SECRET/gi },

  // TIER 4: LOW (7)
  { id: 'CREDS-001',    severity: 'LOW', type: 'Password Assignment',                 regex: /PASSWORD\s*=\s*['"][^'"]+['"]/gi },
  { id: 'CREDS-002',    severity: 'LOW', type: 'Secret Assignment',                   regex: /SECRET\s*=\s*['"][^'"]+['"]/gi },
  { id: 'CREDS-003',    severity: 'LOW', type: 'API Key Assignment',                  regex: /API_KEY\s*=\s*['"][^'"]+['"]/gi },
  { id: 'CREDS-004',    severity: 'LOW', type: 'Token Assignment',                    regex: /TOKEN\s*=\s*['"][^'"]+['"]/gi },
  { id: 'CREDS-005',    severity: 'LOW', type: 'Private Key Assignment',              regex: /PRIVATE\s*=\s*['"][^'"]+['"]/gi },
  { id: 'LEGAL-001',    severity: 'LOW', type: 'Confidentiality Marker',              regex: /CONFIDENTIAL|PROPRIETARY|TRADE SECRET/gi },
  { id: 'LEGAL-002',    severity: 'LOW', type: 'Distribution Restriction',            regex: /DO NOT SHARE|DO NOT DISTRIBUTE|INTERNAL ONLY/gi },
];

/** Context patterns that indicate a match is likely a safe (example/test) value */
const SAFE_CONTEXT_PATTERNS = [
  /\/\/\s*example/gi,
  /\/\*\s*example/gi,
  /#\s*example/gi,
  /<!--\s*example/gi,
  /test.*key/gi,
  /fake.*key/gi,
  /dummy.*key/gi,
  /placeholder/gi,
  /your_.*_here/gi,
  /xxx.*xxx/gi,
];

/**
 * Mask a secret value for safe display: show first 4 and last 4 chars.
 * @param {string} s
 * @returns {string}
 */
function maskSecret(s) {
  if (s.length <= 8) return '***';
  return s.slice(0, 4) + '...' + s.slice(-4);
}

/**
 * Get the line number (1-based) of a character index within a string.
 * @param {string} text
 * @param {number} index
 * @returns {number}
 */
function lineAt(text, index) {
  return text.slice(0, index).split('\n').length;
}

/**
 * Scan text for secrets across all 57 patterns.
 *
 * @param {string} text
 * @returns {{ found: boolean, secrets: Array<{type: string, value: string, line: number}>, count: number }}
 */
function secretScan(text) {
  const secrets = [];

  for (const pattern of SECRET_PATTERNS) {
    // Clone regex to safely reset lastIndex
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;

    while ((match = re.exec(text)) !== null) {
      // Extract context window (±50 chars) to check for safe markers
      const ctxStart = Math.max(0, match.index - 50);
      const ctxEnd   = Math.min(text.length, match.index + match[0].length + 50);
      const context  = text.slice(ctxStart, ctxEnd);

      let isSafe = false;
      for (const safeRe of SAFE_CONTEXT_PATTERNS) {
        // Reset stateful regexes
        safeRe.lastIndex = 0;
        if (safeRe.test(context)) { isSafe = true; break; }
      }
      if (isSafe) continue;

      secrets.push({
        type:  pattern.type,
        value: maskSecret(match[0]),
        line:  lineAt(text, match.index),
      });
    }
  }

  return { found: secrets.length > 0, secrets, count: secrets.length };
}

// ── SECTION 2: DETECT GPT ────────────────────────────────────────────────────

const AI_THRESHOLD  = 0.65;
const MIN_TOKENS    = 20;
const GPT_WEIGHTS   = { entropy: 0.20, burstiness: 0.15, repetitionScore: 0.20,
                         vocabularyRichness: 0.15, sentenceLengthVariance: 0.15,
                         punctuationDensity: 0.15 };

/** Clamp x to [lo, hi] */
function clamp(x, lo, hi) { return Math.max(lo, Math.min(hi, x)); }

/** Logistic sigmoid centred at `centre` with steepness `k` */
function sigmoid(x, centre, k) { return 1 / (1 + Math.exp(-k * (x - centre))); }

/** Tokenise text into lowercase word tokens (letters + apostrophes, ≥2 chars) */
function tokenise(text) {
  return (text.toLowerCase().match(/\b[a-z']{2,}\b/g) || []);
}

/** Split text into sentences on common terminators */
function splitSentences(text) {
  return text.split(/(?<=[.!?])\s+/).map(s => s.trim()).filter(s => s.length > 0);
}

/** Signal 1: Shannon entropy mapped to AI-likelihood */
function computeEntropySignal(tokens) {
  const freq = new Map();
  for (const t of tokens) freq.set(t, (freq.get(t) || 0) + 1);

  const n = tokens.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / n;
    entropy -= p * Math.log2(p);
  }

  const V = freq.size;
  const maxEntropy = V > 1 ? Math.log2(V) : 1;
  const normalised = maxEntropy > 0 ? entropy / maxEntropy : 0;

  // AI-likeness peaks around 0.80 normalised entropy
  const aiPeak = 0.80, spread = 0.18;
  return clamp(Math.exp(-Math.pow(normalised - aiPeak, 2) / (2 * spread * spread)), 0, 1);
}

/** Signal 2: Burstiness — low coefficient of variation of word inter-arrivals */
function computeBurstinessSignal(tokens) {
  const freq = new Map();
  for (const t of tokens) freq.set(t, (freq.get(t) || 0) + 1);

  const top = [...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20).map(([w]) => w);
  const cvs = [];

  for (const word of top) {
    const positions = [];
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i] === word) positions.push(i);
    }
    if (positions.length < 2) continue;

    const gaps = [];
    for (let i = 1; i < positions.length; i++) gaps.push(positions[i] - positions[i - 1]);

    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    if (mean === 0) continue;
    const variance = gaps.reduce((s, g) => s + (g - mean) ** 2, 0) / gaps.length;
    cvs.push(Math.sqrt(variance) / mean);
  }

  if (cvs.length === 0) return 0.5;
  const meanCV = cvs.reduce((a, b) => a + b, 0) / cvs.length;
  return clamp(1 - (meanCV - 0.2) / 1.5, 0, 1);
}

/** Signal 3: Repeated n-gram ratio (2-, 3-, 4-grams) */
function computeRepetitionSignal(tokens) {
  let totalNgrams = 0, repeatedNgrams = 0;

  for (const n of [2, 3, 4]) {
    const seen = new Map();
    for (let i = 0; i <= tokens.length - n; i++) {
      const gram = tokens.slice(i, i + n).join(' ');
      seen.set(gram, (seen.get(gram) || 0) + 1);
      totalNgrams++;
    }
    for (const count of seen.values()) {
      if (count > 1) repeatedNgrams += count - 1;
    }
  }

  if (totalNgrams === 0) return 0;
  return clamp(sigmoid(repeatedNgrams / totalNgrams, 0.06, 60), 0, 1);
}

/** Signal 4: Vocabulary richness (hapax legomena + corrected TTR), inverted */
function computeVocabularyRichnessSignal(tokens) {
  const freq = new Map();
  for (const t of tokens) freq.set(t, (freq.get(t) || 0) + 1);

  const n = tokens.length;
  if (n === 0) return 0.5;

  const types   = freq.size;
  const hapax   = [...freq.values()].filter(c => c === 1).length;
  const hapaxRatio = hapax / types;
  const cttrNorm   = clamp((types / Math.sqrt(2 * n)) / 3, 0, 1);
  const richness   = hapaxRatio * 0.6 + cttrNorm * 0.4;

  return clamp(1 - richness, 0, 1);
}

/** Signal 5: Sentence length variance (low CV → AI-like) */
function computeSentenceLengthVarianceSignal(text) {
  const sentences = splitSentences(text);
  if (sentences.length < 3) return 0.5;

  const lengths = sentences.map(s => tokenise(s).length).filter(l => l > 0);
  if (lengths.length < 2) return 0.5;

  const mean = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  if (mean === 0) return 0.5;

  const variance = lengths.reduce((s, l) => s + (l - mean) ** 2, 0) / lengths.length;
  const cv = Math.sqrt(variance) / mean;

  return clamp(1 - (cv - 0.10) / 0.70, 0, 1);
}

/** Signal 6: Punctuation density uniformity (low CV → AI-like) */
function computePunctuationDensitySignal(text) {
  const sentences = splitSentences(text);
  if (sentences.length < 3) return 0.5;

  const densities = sentences.map(s => {
    const punctCount = (s.match(/[,;:—\-]/g) || []).length;
    const wordCount  = tokenise(s).length || 1;
    return punctCount / wordCount;
  });

  const mean = densities.reduce((a, b) => a + b, 0) / densities.length;
  if (mean === 0) return 0.3;

  const variance = densities.reduce((s, d) => s + (d - mean) ** 2, 0) / densities.length;
  const cv = Math.sqrt(variance) / mean;

  return clamp(1 - cv / 1.2, 0, 1);
}

/**
 * Detect whether text is likely AI-generated using six local statistical signals.
 *
 * @param {string} text
 * @returns {{ isAI: boolean, confidence: number, signals: string[] }}
 */
function detectGPT(text) {
  const tokens = tokenise(text);

  if (tokens.length < MIN_TOKENS) {
    return { isAI: false, confidence: 0, signals: ['insufficient_data'] };
  }

  const entropy               = computeEntropySignal(tokens);
  const burstiness            = computeBurstinessSignal(tokens);
  const repetitionScore       = computeRepetitionSignal(tokens);
  const vocabularyRichness    = computeVocabularyRichnessSignal(tokens);
  const sentenceLengthVariance = computeSentenceLengthVarianceSignal(text);
  const punctuationDensity    = computePunctuationDensitySignal(text);

  const score =
    entropy               * GPT_WEIGHTS.entropy               +
    burstiness            * GPT_WEIGHTS.burstiness            +
    repetitionScore       * GPT_WEIGHTS.repetitionScore       +
    vocabularyRichness    * GPT_WEIGHTS.vocabularyRichness    +
    sentenceLengthVariance * GPT_WEIGHTS.sentenceLengthVariance +
    punctuationDensity    * GPT_WEIGHTS.punctuationDensity;

  const isAI = score > AI_THRESHOLD;
  const maxDist  = Math.max(AI_THRESHOLD, 1 - AI_THRESHOLD);
  const confidence = clamp(Math.abs(score - AI_THRESHOLD) / maxDist, 0, 1);

  // Build human-readable signal list
  const signalMap = { entropy, burstiness, repetitionScore, vocabularyRichness,
                       sentenceLengthVariance, punctuationDensity };
  const signals = Object.entries(signalMap)
    .filter(([, v]) => v > 0.5)
    .map(([k, v]) => `${k}=${v.toFixed(2)}`);

  return { isAI, confidence: parseFloat(confidence.toFixed(4)), signals };
}

// ── SECTION 3: AHO-CORASICK ──────────────────────────────────────────────────

/**
 * Build an Aho-Corasick automaton from an array of pattern strings.
 *
 * Returns an object with a search(text) method.
 *
 * @param {string[]} patterns
 */
function buildAC(patterns) {
  // Each state: { goto: Map<number,number>, fail: number, output: string[] }
  const states = [{ goto: new Map(), fail: 0, output: [] }];

  // Phase 1 — Build goto trie
  for (const pattern of patterns) {
    let cur = 0;
    for (let i = 0; i < pattern.length; i++) {
      const code = pattern.charCodeAt(i);
      const node = states[cur];
      if (!node.goto.has(code)) {
        node.goto.set(code, states.length);
        states.push({ goto: new Map(), fail: 0, output: [] });
      }
      cur = node.goto.get(code);
    }
    states[cur].output.push(pattern);
  }

  // Phase 2 — Compute failure links via BFS
  const queue = [];
  for (const [, child] of states[0].goto) {
    states[child].fail = 0;
    queue.push(child);
  }

  while (queue.length > 0) {
    const s = queue.shift();
    for (const [code, t] of states[s].goto) {
      queue.push(t);

      let f = states[s].fail;
      while (f !== 0 && !states[f].goto.has(code)) {
        f = states[f].fail;
      }
      const failTarget = states[f].goto.get(code) || 0;
      states[t].fail = (failTarget === t) ? 0 : failTarget;

      // Propagate output from failure link
      const failOut = states[states[t].fail].output;
      if (failOut.length > 0) {
        states[t].output = states[t].output.concat(failOut);
      }
    }
  }

  return {
    /**
     * Search text for all pattern occurrences.
     * @param {string} text
     * @returns {Array<{pattern: string, position: number, context: string}>}
     */
    search(text) {
      const matches = [];
      let state = 0;

      for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);

        while (state !== 0 && !states[state].goto.has(code)) {
          state = states[state].fail;
        }
        state = states[state].goto.get(code) || 0;

        for (const pat of states[state].output) {
          const start = i - pat.length + 1;
          const ctxStart = Math.max(0, start - 10);
          const ctxEnd   = Math.min(text.length, i + 11);
          matches.push({
            pattern:  pat,
            position: start,
            context:  text.slice(ctxStart, ctxEnd),
          });
        }
      }

      return matches;
    }
  };
}

/**
 * Efficient multi-pattern substring search using the Aho-Corasick algorithm.
 *
 * @param {string} text
 * @param {string[]} patterns
 * @returns {{ matches: Array<{pattern: string, position: number, context: string}> }}
 */
function ahoCorasick(text, patterns) {
  if (!patterns || patterns.length === 0) return { matches: [] };
  const ac = buildAC(patterns);
  return { matches: ac.search(text) };
}

// ── SECTION 4: PHASH SIMILARITY ──────────────────────────────────────────────

/** Default max Hamming distance to classify images as similar */
const DEFAULT_PHASH_THRESHOLD = 10;

/** Population count (number of set bits) for a single byte */
const POPCOUNT_TABLE = new Uint8Array(256);
for (let i = 1; i < 256; i++) {
  POPCOUNT_TABLE[i] = POPCOUNT_TABLE[i >> 1] + (i & 1);
}

/**
 * Compute Hamming distance between two hex perceptual-hash strings.
 *
 * The hex strings represent 64-bit hashes; each hex character encodes 4 bits.
 * Strings must be equal in length.
 *
 * @param {string} hash1 - Hex string (e.g. "f8e0a0c0b0d0e0f0")
 * @param {string} hash2 - Hex string
 * @returns {{ distance: number, similar: boolean }}
 */
function pHashSimilarity(hash1, hash2) {
  if (typeof hash1 !== 'string' || typeof hash2 !== 'string') {
    throw new TypeError('pHashSimilarity: both arguments must be hex strings');
  }

  // Pad to equal length
  const maxLen = Math.max(hash1.length, hash2.length);
  const h1 = hash1.toLowerCase().padStart(maxLen, '0');
  const h2 = hash2.toLowerCase().padStart(maxLen, '0');

  let distance = 0;
  for (let i = 0; i < h1.length; i++) {
    const b1 = parseInt(h1[i], 16);
    const b2 = parseInt(h2[i], 16);
    if (isNaN(b1) || isNaN(b2)) continue;
    distance += POPCOUNT_TABLE[b1 ^ b2];
  }

  return { distance, similar: distance <= DEFAULT_PHASH_THRESHOLD };
}

// ── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  secretScan,
  detectGPT,
  ahoCorasick,
  pHashSimilarity,
};
