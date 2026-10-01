'use strict';

/**
 * Prompt Firewall — Multi-layer injection/jailbreak detection for LLM pipelines.
 * Ported from ARCHIVE/kasbah-core/core/frontier/prompt_firewall.py (296 lines).
 *
 * Detects: instruction override, jailbreak patterns, system prompt extraction,
 * role-play attacks, encoded injection, token boundary manipulation,
 * context poisoning, reasoning hijack, tool exploitation.
 */

const crypto = require('crypto');

const ThreatLevel = Object.freeze({
  SAFE: 'safe',
  SUSPICIOUS: 'suspicious',
  MALICIOUS: 'malicious',
  CRITICAL: 'critical',
});

const DefenseAction = Object.freeze({
  ALLOW: 'allow',
  WARN: 'warn',
  SANITIZE: 'sanitize',
  BLOCK: 'block',
  QUARANTINE: 'quarantine',
});

// ─── Built-in Detection Patterns ───────────────────────────────────────────────

const BUILTIN_PATTERNS = [
  {
    id: 'pi_001', name: 'Ignore Previous Instructions',
    pattern: /(ignore|disregard|forget|override)\s+(previous|prior|all|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?|context)/gi,
    threatLevel: ThreatLevel.CRITICAL, confidence: 0.95, scoreContribution: 0.7,
  },
  {
    id: 'pi_002', name: 'System Prompt Extraction',
    pattern: /(reveal|show|print|output|display|repeat|tell me|what (is|are|was))\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|base\s+prompt|configuration)/gi,
    threatLevel: ThreatLevel.MALICIOUS, confidence: 0.88, scoreContribution: 0.55,
  },
  {
    id: 'pi_003', name: 'DAN Jailbreak',
    pattern: /(DAN|do anything now|jailbreak|pretend (you are|to be) (an? )?(uncensored|unrestricted|free|evil|unethical)\s+(AI|model|assistant|version))/gi,
    threatLevel: ThreatLevel.CRITICAL, confidence: 0.92, scoreContribution: 0.75,
  },
  {
    id: 'pi_004', name: 'Role-Play Override',
    pattern: /(you are now|act as|pretend to be|roleplay as|simulate being|from now on (you are|act))\s+.{0,50}(without restrictions?|no (limits?|rules?|guidelines?)|uncensored|unrestricted)/gi,
    threatLevel: ThreatLevel.MALICIOUS, confidence: 0.82, scoreContribution: 0.5,
  },
  {
    id: 'pi_005', name: 'Developer Mode Override',
    pattern: /(developer\s+mode|dev\s+mode|god\s+mode|admin\s+mode|maintenance\s+mode|debug\s+mode)\s*(enabled?|on|activated?|unlocked?)/gi,
    threatLevel: ThreatLevel.MALICIOUS, confidence: 0.85, scoreContribution: 0.6,
  },
  {
    id: 'pi_006', name: 'Token Boundary Injection',
    pattern: /(<\|?(im_start|im_end|system|user|assistant|endoftext|pad|unk)\|?>|\[INST\]|\[\/INST\]|<<SYS>>|<<\/SYS>>|\|\|OMNISEND\|\||<\|SYSTEM\|>)/gi,
    threatLevel: ThreatLevel.CRITICAL, confidence: 0.97, scoreContribution: 0.8,
  },
  {
    id: 'pi_007', name: 'Indirect Prompt via Data',
    pattern: /(when (you|the (AI|model|assistant)) (reads?|processes?|sees?|encounters?)\s+this|hidden\s+instruction|encoded\s+command|secret\s+(command|instruction|payload))/gi,
    threatLevel: ThreatLevel.MALICIOUS, confidence: 0.75, scoreContribution: 0.45,
  },
  {
    id: 'pi_008', name: 'Context Window Poisoning',
    pattern: /(repeat\s+(the\s+)?(following|this)\s+(\d+\s+)?(times?|hundred|thousand)|fill\s+(your\s+)?(context|window|memory)\s+with)/gi,
    threatLevel: ThreatLevel.SUSPICIOUS, confidence: 0.65, scoreContribution: 0.3,
  },
  {
    id: 'pi_009', name: 'Goal Hijacking',
    pattern: /(your\s+(new\s+|primary\s+|only\s+|real\s+)?goal\s+is|your\s+(true\s+|actual\s+)?purpose\s+is|forget\s+(everything|all)\s+(else|you\s+know)|your\s+(main\s+)?objective\s+is\s+now)/gi,
    threatLevel: ThreatLevel.MALICIOUS, confidence: 0.80, scoreContribution: 0.55,
  },
  {
    id: 'pi_010', name: 'Tool Exploitation',
    pattern: /(call\s+(the\s+)?(tool|function|api|endpoint)\s+.{0,30}(without|bypass|skip)\s+(auth|permission|check|validation)|use\s+(tool|function)\s+.{0,30}as\s+(admin|root|system|superuser))/gi,
    threatLevel: ThreatLevel.MALICIOUS, confidence: 0.78, scoreContribution: 0.5,
  },
  {
    id: 'pi_011', name: 'Multi-step Reasoning Hijack',
    pattern: /(step\s+\d+[\s:]+.{0,30}(ignore|bypass|override)|first[\s,]+.{0,30}(then|and then|next)[\s,]+.{0,30}(ignore|reveal|leak|exfiltrate))/gi,
    threatLevel: ThreatLevel.SUSPICIOUS, confidence: 0.60, scoreContribution: 0.35,
  },
  {
    id: 'pi_012', name: 'Prompt Leakage via Translation',
    pattern: /(translate\s+(your\s+)?(system\s+prompt|instructions?|rules?)\s+(to|into)\s+\w+|say\s+(your\s+)?(system\s+prompt|instructions?)\s+in\s+\w+)/gi,
    threatLevel: ThreatLevel.MALICIOUS, confidence: 0.80, scoreContribution: 0.5,
  },
];

// ─── Obfuscation Helpers ───────────────────────────────────────────────────────

function _tryDecodeBase64(text) {
  try {
    const padded = text + '='.repeat((4 - (text.length % 4)) % 4);
    const decoded = Buffer.from(padded, 'base64').toString('utf8');
    if (decoded.length > 5 && /^[\x20-\x7E\r\n\t]*$/.test(decoded)) return decoded;
  } catch {}
  return null;
}

function _decodeUnicodeEscapes(text) {
  try {
    return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
  } catch { return text; }
}

function _extractBase64Candidates(text) {
  const results = [];
  const matches = text.match(/[A-Za-z0-9+/]{20,}={0,2}/g);
  if (matches) results.push(...matches);
  return results;
}

// ─── Prompt Firewall ───────────────────────────────────────────────────────────

class PromptFirewall {
  /**
   * @param {object} [opts]
   * @param {number} [opts.blockThreshold=0.5]
   * @param {number} [opts.quarantineThreshold=0.8]
   * @param {boolean} [opts.checkObfuscation=true]
   * @param {boolean} [opts.sanitizeOnSuspicious=true]
   * @param {object[]} [opts.customPatterns] — additional DetectionPattern objects
   */
  constructor(opts = {}) {
    this.blockThreshold = opts.blockThreshold || 0.5;
    this.quarantineThreshold = opts.quarantineThreshold || 0.8;
    this.checkObfuscation = opts.checkObfuscation !== undefined ? opts.checkObfuscation : true;
    this.sanitizeOnSuspicious = opts.sanitizeOnSuspicious !== undefined ? opts.sanitizeOnSuspicious : true;
    this._patterns = [...BUILTIN_PATTERNS, ...(opts.customPatterns || [])];
    this._stats = { analyzed: 0, blocked: 0, sanitized: 0, quarantined: 0 };
  }

  /** Add a custom detection pattern */
  addPattern(pattern) {
    this._patterns.push(pattern);
  }

  /**
   * Analyze a prompt for injection/jailbreak threats.
   * @param {string} text
   * @param {object} [context] — optional { sessionId, userId, ... }
   * @returns {object} — { threatLevel, action, score, matchedPatterns, reason, sanitizedText, analysisMs, allowed }
   */
  analyze(text, context) {
    const t0 = performance.now();
    this._stats.analyzed++;

    const textsToScan = [text];

    // Obfuscation decoding pass
    if (this.checkObfuscation) {
      const decoded = _decodeUnicodeEscapes(text);
      if (decoded !== text) textsToScan.push(decoded);

      for (const candidate of _extractBase64Candidates(text)) {
        const decoded = _tryDecodeBase64(candidate);
        if (decoded) textsToScan.push(decoded);
      }
    }

    const matchedPatterns = new Set();
    let cumulativeScore = 0.0;

    for (const scanText of textsToScan) {
      for (const pat of this._patterns) {
        if (!pat.pattern) continue;
        // Reset lastIndex for global regex
        pat.pattern.lastIndex = 0;
        if (pat.pattern.test(scanText)) {
          if (!matchedPatterns.has(pat.name)) {
            matchedPatterns.add(pat.name);
            cumulativeScore += pat.scoreContribution * pat.confidence;
          }
        }
      }
    }

    const score = Math.min(cumulativeScore, 1.0);

    // Classify threat level
    let threatLevel;
    if (score >= 0.7) threatLevel = ThreatLevel.CRITICAL;
    else if (score >= 0.5) threatLevel = ThreatLevel.MALICIOUS;
    else if (score >= 0.25) threatLevel = ThreatLevel.SUSPICIOUS;
    else threatLevel = ThreatLevel.SAFE;

    // Determine action
    let action;
    if (score >= this.quarantineThreshold) {
      action = DefenseAction.QUARANTINE;
      this._stats.quarantined++;
    } else if (score >= this.blockThreshold) {
      action = DefenseAction.BLOCK;
      this._stats.blocked++;
    } else if (score > 0 && this.sanitizeOnSuspicious) {
      action = DefenseAction.SANITIZE;
      this._stats.sanitized++;
    } else if (score > 0) {
      action = DefenseAction.WARN;
    } else {
      action = DefenseAction.ALLOW;
    }

    const allowed = action === DefenseAction.ALLOW || action === DefenseAction.WARN;

    // Sanitize if needed
    let sanitized = null;
    if (action === DefenseAction.SANITIZE) {
      sanitized = this._sanitize(text, matchedPatterns);
    }

    const matchedArray = [...matchedPatterns];
    const reason = matchedArray.length > 0
      ? `Threat score ${score.toFixed(2)} -- matched: ${matchedArray.join(', ')}`
      : 'No threats detected';

    return {
      threatLevel,
      action,
      score: Math.round(score * 10000) / 10000,
      matchedPatterns: matchedArray,
      reason,
      sanitizedText: sanitized,
      analysisMs: Math.round((performance.now() - t0) * 100) / 100,
      allowed,
    };
  }

  _sanitize(text, matchedPatternNames) {
    let sanitized = text;
    for (const pat of this._patterns) {
      if (!pat.pattern || !matchedPatternNames.has(pat.name)) continue;
      pat.pattern.lastIndex = 0;
      sanitized = sanitized.replace(pat.pattern, '[FILTERED]');
    }
    return sanitized;
  }

  getStats() { return { ...this._stats }; }

  hashPrompt(text) {
    return crypto.createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 16);
  }
}

module.exports = { PromptFirewall, ThreatLevel, DefenseAction, BUILTIN_PATTERNS };
