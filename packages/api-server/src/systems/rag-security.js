'use strict';
/**
 * RAG Security — secures Retrieval-Augmented Generation pipelines
 * Ported from ARCHIVE/kasbah-core/core/frontier-ts/rag-security.ts
 */

const { createHash } = require('crypto');

// ============================================================================
// ACCESS LEVEL CLASSIFICATION
// ============================================================================

const ACCESS_LEVELS = ['public', 'internal', 'restricted', 'confidential'];

/**
 * Classify the access level implied by a piece of retrieved context.
 * Heuristic: scan for markers that suggest sensitivity.
 */
function classifyAccessLevel(text) {
  const lower = text.toLowerCase();

  if (/\b(top secret|confidential|classified|do not distribute|nda|proprietary)\b/.test(lower)) {
    return 'confidential';
  }
  if (/\b(internal use only|restricted|not for public|sensitive|pii|personal data)\b/.test(lower)) {
    return 'restricted';
  }
  if (/\b(internal|employee|staff|team only|non-public)\b/.test(lower)) {
    return 'internal';
  }
  return 'public';
}

// ============================================================================
// PROMPT INJECTION DETECTION
// ============================================================================

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions?/i,
  /forget\s+(all\s+)?previous\s+instructions?/i,
  /disregard\s+(your\s+)?(previous|prior|above)\s+/i,
  /you\s+are\s+now\s+(a|an)\s+/i,
  /act\s+as\s+(if\s+you\s+are\s+)?(a|an)\s+/i,
  /\bnew\s+instructions?:/i,
  /\bsystem\s*prompt\b/i,
  /override\s+(your\s+)?(instructions?|rules?|constraints?|directives?)/i,
  /\bjailbreak\b/i,
  /\bdan\s+mode\b/i,
  /\bprompt\s+injection\b/i,
  /print\s+(your\s+)?(system\s+)?(prompt|instructions?|context)/i,
  /reveal\s+(your\s+)?(system\s+)?(prompt|instructions?|secret)/i,
  /\bexfiltrate\b|\bexfiltration\b/i,
  /output\s+(all|everything|your)\s+(system|instruction|context)/i,
];

function detectInjection(text) {
  const hits = [];
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      hits.push(pattern.source);
    }
  }
  return hits;
}

// ============================================================================
// CONTENT SANITIZATION
// ============================================================================

// Credential / secret patterns to redact
const CREDENTIAL_PATTERNS = [
  // Key/token assignments
  /\b(password|passwd|api[_-]?key|secret[_-]?key?|token|auth[_-]?token|access[_-]?token)\s*[:=]\s*\S+/gi,
  // Common key prefixes
  /\b(sk|pk|rk|ak)[_-](live|test|prod|dev)_[A-Za-z0-9]{8,}/gi,
  // JWT-shaped tokens
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  // AWS keys
  /(?:AKIA|ASIA)[A-Z0-9]{16}/g,
];

function sanitizeContent(text) {
  let sanitized = text;

  // Strip script tags (including multiline)
  sanitized = sanitized.replace(/<script[\s\S]*?<\/script>/gi, '[SCRIPT_REMOVED]');

  // Strip javascript: protocol
  sanitized = sanitized.replace(/javascript\s*:/gi, '[JS_PROTOCOL_REMOVED]');

  // Strip inline event handlers
  sanitized = sanitized.replace(/\bon\w+\s*=/gi, '[EVENT_HANDLER_REMOVED]=');

  // Strip SQL injection patterns
  sanitized = sanitized.replace(/\b(UNION\s+ALL\s+SELECT|UNION\s+SELECT|SELECT\s+\*\s+FROM|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\w+\s+SET|EXEC\s*\(|xp_cmdshell)\b/gi, '[SQL_REMOVED]');

  // Redact credentials
  for (const pattern of CREDENTIAL_PATTERNS) {
    sanitized = sanitized.replace(pattern, (match) => {
      // Keep the key name if present, redact value
      const eqIdx = match.search(/[:=]/);
      if (eqIdx > -1) {
        return match.slice(0, eqIdx + 1) + ' [REDACTED]';
      }
      return '[REDACTED]';
    });
  }

  return sanitized;
}

// ============================================================================
// DOCUMENT INTEGRITY
// ============================================================================

function generateChecksum(content) {
  return createHash('sha256').update(content).digest('hex').slice(0, 16);
}

function verifyChecksum(content, expectedChecksum) {
  if (!expectedChecksum) return true; // No checksum provided — skip verification
  return generateChecksum(content) === expectedChecksum;
}

// ============================================================================
// THREAT AGGREGATION
// ============================================================================

/**
 * Build a list of threat objects from all detection passes.
 */
function buildThreats(injectionHits, sqlHits, xssHits, credentialHits, checksumFailed) {
  const threats = [];

  if (injectionHits.length > 0) {
    threats.push({
      type: 'prompt_injection',
      severity: 'critical',
      details: `${injectionHits.length} injection pattern(s) detected`
    });
  }

  if (sqlHits) {
    threats.push({
      type: 'sql_injection',
      severity: 'high',
      details: 'SQL injection patterns found in retrieved context'
    });
  }

  if (xssHits) {
    threats.push({
      type: 'xss',
      severity: 'high',
      details: 'Cross-site scripting patterns found in retrieved context'
    });
  }

  if (credentialHits) {
    threats.push({
      type: 'credential_exposure',
      severity: 'high',
      details: 'Credential or secret patterns detected in retrieved context'
    });
  }

  if (checksumFailed) {
    threats.push({
      type: 'integrity_violation',
      severity: 'medium',
      details: 'Document checksum mismatch — content may have been tampered with'
    });
  }

  return threats;
}

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * Evaluate a retrieved RAG context for security threats.
 *
 * @param {string} retrievedContext - The text/documents retrieved from the vector store
 * @param {string} [userQuery=''] - The original user query (used to detect query-level injection)
 * @param {object} [options={}]
 * @param {string} [options.expectedChecksum] - SHA-256 hex checksum to verify integrity
 * @returns {{
 *   safe: boolean,
 *   threats: Array<{type: string, severity: string, details: string}>,
 *   accessLevel: string,
 *   sanitized: string,
 *   injectionAttempt: boolean
 * }}
 */
function ragSecurityCheck(retrievedContext, userQuery = '', options = {}) {
  if (typeof retrievedContext !== 'string') {
    retrievedContext = String(retrievedContext);
  }

  const combinedText = userQuery ? `${userQuery}\n${retrievedContext}` : retrievedContext;

  // 1. Prompt injection detection (check both the retrieved context and the query)
  const contextInjections = detectInjection(retrievedContext);
  const queryInjections   = detectInjection(userQuery);
  const allInjections     = [...contextInjections, ...queryInjections];
  const injectionAttempt  = allInjections.length > 0;

  // 2. SQL injection check (raw, before sanitization)
  const hasSQLInjection = /\b(UNION\s+(ALL\s+)?SELECT|SELECT\s+\*\s+FROM|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|EXEC\s*\(|xp_cmdshell)\b/i.test(combinedText);

  // 3. XSS check (raw)
  const hasXSS = /<script[\s\S]*?>/i.test(combinedText) || /javascript\s*:/i.test(combinedText);

  // 4. Credential exposure check (raw)
  const hasCredentials = CREDENTIAL_PATTERNS.some(p => {
    const freshRe = new RegExp(p.source, p.flags);
    return freshRe.test(combinedText);
  });

  // 5. Integrity check
  const checksumFailed = options.expectedChecksum
    ? !verifyChecksum(retrievedContext, options.expectedChecksum)
    : false;

  // 6. Access level classification
  const accessLevel = classifyAccessLevel(retrievedContext);

  // 7. Sanitize
  const sanitized = sanitizeContent(combinedText);

  // 8. Aggregate threats
  const threats = buildThreats(allInjections, hasSQLInjection, hasXSS, hasCredentials, checksumFailed);

  const safe = threats.length === 0;

  return {
    safe,
    threats,
    accessLevel,
    sanitized,
    injectionAttempt
  };
}

module.exports = { ragSecurityCheck };
