/**
 * KASBAH POLICY ENGINE
 * Declarative, human-readable policy language for AI agent governance.
 *
 * Instead of hardcoded checks — write policies as rules:
 *   { "deny_if": { "verb": "DELETE", "target_pattern": "/prod/*" } }
 *
 * Ships with pre-certified compliance packs:
 *   - HIPAA (healthcare)
 *   - GDPR (EU data protection)
 *   - SOC2 Type II
 *   - PCI-DSS (payments)
 *   - ITAR (export control)
 *
 * Enterprises update rules without touching workflow code.
 * Security teams audit policies, not JavaScript.
 */

const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════
// BUILT-IN COMPLIANCE PACKS
// ═══════════════════════════════════════════════════════════

const COMPLIANCE_PACKS = {

  HIPAA: {
    name: 'HIPAA Healthcare Compliance Pack',
    version: '2024.1',
    rules: [
      { id: 'H-001', deny_if: { verb_in: ['DELETE_FILE','DROP_TABLE','TRUNCATE'] }, reason: 'PHI records cannot be deleted without audit trail' },
      { id: 'H-002', deny_if: { target_matches: /patient|medical|health|diagnosis|prescription/ , verb_in: ['EXPORT','SEND_EMAIL','POST_EXTERNAL'] }, reason: 'PHI cannot leave authorized systems' },
      { id: 'H-003', require_approval_if: { verb_in: ['READ'], target_matches: /patient/ , rate_exceeds: { per_minute: 50 } }, reason: 'Bulk PHI access requires approval' },
      { id: 'H-004', deny_if: { content_pattern: /ssn|social.security|dob|date.of.birth/i }, reason: 'SSN/DOB in agent output requires redaction' },
      { id: 'H-005', deny_if: { verb_in: ['EXEC','EVAL','RUN_CODE'] }, reason: 'Arbitrary code execution not permitted in clinical systems' },
      { id: 'H-006', warn_if: { target_matches: /external|public|internet/ }, reason: 'External data access requires security review' }
    ]
  },

  GDPR: {
    name: 'GDPR EU Data Protection Pack',
    version: '2024.1',
    rules: [
      { id: 'G-001', deny_if: { content_pattern: /email|phone|address|ip.address/i, verb_in: ['SEND_EXTERNAL','POST','EXPORT'] }, reason: 'PII cannot be exported without explicit consent record' },
      { id: 'G-002', require_approval_if: { verb: 'DELETE', target_matches: /user|profile|account/ }, reason: 'Right to erasure requires human verification' },
      { id: 'G-003', deny_if: { verb_in: ['PROFILE','INFER','SCORE'], target_matches: /user|person|individual/ }, reason: 'Automated profiling requires DPA notification' },
      { id: 'G-004', deny_if: { target_matches: /eu.user|european/ , verb_in: ['TRANSFER_US','TRANSFER_CHINA','TRANSFER_EXTERNAL'] }, reason: 'Cross-border EU data transfer requires SCCs' },
      { id: 'G-005', warn_if: { content_pattern: /name.*age|gender.*address/i }, reason: 'Combined PII fields may create GDPR-relevant profile' }
    ]
  },

  SOC2: {
    name: 'SOC2 Type II Compliance Pack',
    version: '2024.1',
    rules: [
      { id: 'S-001', deny_if: { verb_in: ['ACCESS_SECRETS','READ_ENV','DUMP_CONFIG'] }, reason: 'Credentials access violates SOC2 CC6.1' },
      { id: 'S-002', deny_if: { verb_in: ['ESCALATE_PRIVILEGE','SUDO','RUN_AS_ROOT'] }, reason: 'Privilege escalation violates SOC2 CC6.3' },
      { id: 'S-003', require_approval_if: { verb_in: ['DEPLOY','PUSH_CODE','MODIFY_INFRA'] }, reason: 'Change management requires approval (SOC2 CC8.1)' },
      { id: 'S-004', deny_if: { content_pattern: /api.key|secret|password|token/i, verb_in: ['LOG','WRITE_FILE','POST_EXTERNAL'] }, reason: 'Secrets must not appear in logs (SOC2 CC6.7)' },
      { id: 'S-005', warn_if: { rate_exceeds: { per_minute: 500 } }, reason: 'High-volume access may indicate SOC2 availability risk' }
    ]
  },

  PCI_DSS: {
    name: 'PCI-DSS Payment Security Pack',
    version: '2024.1',
    rules: [
      { id: 'P-001', deny_if: { content_pattern: /\b4[0-9]{15}\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b/ }, reason: 'Full PAN in plaintext violates PCI-DSS Req 3.4' },
      { id: 'P-002', deny_if: { content_pattern: /cvv|cvv2|cvc|security.code/i }, reason: 'CVV storage/transmission violates PCI-DSS Req 3.2' },
      { id: 'P-003', deny_if: { target_matches: /payment|card|billing/, verb_in: ['LOG','WRITE_FILE'] }, reason: 'CHD logging violates PCI-DSS Req 3' },
      { id: 'P-004', deny_if: { verb_in: ['EXEC','EVAL'], target_matches: /payment|transaction/ }, reason: 'Dynamic code in payment flow violates PCI-DSS Req 6.3' }
    ]
  },

  // ═══════════════════════════════════════════════════════════
  // BIOMETRIC_GUARD — defends the USER against covert silent-speech,
  // facial micro-expression, subvocalization and QAI intent-inference
  // surveillance. Kasbah does NOT perform this analysis; it BLOCKS any
  // agent/tool action that attempts to capture or infer it.
  // ═══════════════════════════════════════════════════════════
  BIOMETRIC_GUARD: {
    name: 'Biometric & Silent-Speech Surveillance Protection Pack',
    version: '2026.1',
    rules: [
      { id: 'B-001', deny_if: { verb_in: ['CAPTURE_VIDEO','ACCESS_CAMERA','RECORD_WEBCAM','ENABLE_CAMERA','READ_CAMERA'], target_matches: /face|facial|expression|micro.?expression|emotion|gaze|pupil|lip/i }, reason: 'Facial micro-expression capture for intent inference is prohibited (BIOMETRIC_GUARD)' },
      { id: 'B-002', deny_if: { content_pattern: /silent.?speech|sub-?vocal(?:iz|is)?(?:ation|ed|ing)?|electromyograph|\bEMG\b|throat.?mic|neural.?intent|brain.?computer.?interface|\bBCI\b/i }, reason: 'Silent-speech / subvocalization / BCI intent capture prohibited (BIOMETRIC_GUARD)' },
      { id: 'B-003', deny_if: { verb_in: ['INFER','PROFILE','SCORE','CLASSIFY','PREDICT'], target_matches: /emotion|intent|micro.?expression|facial|biometric|gaze|lip.?read|sentiment.?face/i }, reason: 'Covert biometric intent inference of a person is prohibited (BIOMETRIC_GUARD)' },
      { id: 'B-004', deny_if: { content_pattern: /facial.?landmark|\bFACS\b|action.?unit|lip.?read|gaze.?track|pupil.?dilat|iris.?scan|retina.?scan|face.?embedding|faceprint/i }, reason: 'Biometric facial-feature extraction / faceprinting prohibited (BIOMETRIC_GUARD)' },
      { id: 'B-005', deny_if: { verb_in: ['ACCESS_MICROPHONE','RECORD_AUDIO','ENABLE_MIC','CAPTURE_AUDIO'], target_matches: /subvocal|silent.?speech|whisper.?detect|throat|larynx|articulator/i }, reason: 'Covert subvocal audio capture prohibited (BIOMETRIC_GUARD)' },
      { id: 'B-006', deny_if: { content_pattern: /apple.?silent.?speech|silent.?speech.?recognition|qai.?intent|quantum.?intent.?infer|covert.?intent.?read|mind.?read/i }, reason: 'Known silent-speech / QAI surveillance vector blocked (BIOMETRIC_GUARD)' },
      { id: 'B-007', warn_if: { verb_in: ['ACCESS_CAMERA','ACCESS_MICROPHONE','CAPTURE_VIDEO','RECORD_AUDIO'] }, reason: 'Camera/microphone access — verify it is not used for biometric/silent-speech inference (BIOMETRIC_GUARD)' }
    ]
  }

};

// ═══════════════════════════════════════════════════════════
// POLICY ENGINE
// ═══════════════════════════════════════════════════════════

class KasbahPolicyEngine {
  constructor(options = {}) {
    this.rules      = [];
    this.packs      = new Set();
    this.customRules = [];
    this.evalLog    = [];

    // Load compliance packs
    if (options.packs) {
      options.packs.forEach(p => this.loadPack(p));
    }

    // Load custom rules
    if (options.rules) {
      options.rules.forEach(r => this.addRule(r));
    }

    // Compute engine hash (proves which rules are loaded)
    this.engineHash = this._computeHash();
  }

  // ─────────────────────────────────────────────────────────
  // LOAD COMPLIANCE PACKS
  // ─────────────────────────────────────────────────────────

  loadPack(packName) {
    const pack = COMPLIANCE_PACKS[packName];
    if (!pack) throw new Error(`Unknown compliance pack: ${packName}. Available: ${Object.keys(COMPLIANCE_PACKS).join(', ')}`);

    pack.rules.forEach(rule => {
      this.rules.push({ ...rule, pack: packName });
    });
    this.packs.add(packName);
    this.engineHash = this._computeHash();
    return this;
  }

  addRule(rule) {
    const r = { ...rule, id: rule.id || `custom-${Date.now()}`, pack: 'custom' };
    this.rules.push(r);
    this.customRules.push(r);
    this.engineHash = this._computeHash();
    return this;
  }

  // ─────────────────────────────────────────────────────────
  // EVALUATE ACTION AGAINST ALL RULES
  // ─────────────────────────────────────────────────────────

  evaluate(action) {
    const { agent, verb, target, content, rateContext } = action;
    const results = [];
    let finalDecision = 'ALLOW';
    let finalReason   = 'All policies passed';
    const violations  = [];
    const warnings    = [];
    const approvals   = [];

    for (const rule of this.rules) {
      const result = this._evaluateRule(rule, { verb, target, content, rateContext });

      if (result.triggered) {
        results.push({ rule: rule.id, pack: rule.pack, result });

        if (result.action === 'DENY') {
          violations.push({ rule: rule.id, reason: rule.reason, severity: 'critical' });
          finalDecision = 'DENY';
          finalReason   = rule.reason;
        } else if (result.action === 'WARN') {
          warnings.push({ rule: rule.id, reason: rule.reason });
          if (finalDecision === 'ALLOW') finalDecision = 'WARN';
        } else if (result.action === 'REQUIRE_APPROVAL') {
          approvals.push({ rule: rule.id, reason: rule.reason });
          if (finalDecision === 'ALLOW') finalDecision = 'REQUIRE_APPROVAL';
        }
      }
    }

    const evaluation = {
      decision:    finalDecision,
      reason:      finalReason,
      violations,
      warnings,
      approvals,
      rulesEvaluated: this.rules.length,
      packsActive:    [...this.packs],
      engineHash:     this.engineHash,
      timestamp:      new Date().toISOString()
    };

    this.evalLog.push({ action, evaluation });
    return evaluation;
  }

  // ─────────────────────────────────────────────────────────
  // RULE EVALUATOR
  // ─────────────────────────────────────────────────────────

  _evaluateRule(rule, context) {
    const { verb, target, content, rateContext } = context;

    // Determine action type and condition
    let conditionKey, action;
    if (rule.deny_if)             { conditionKey = rule.deny_if;             action = 'DENY'; }
    else if (rule.warn_if)         { conditionKey = rule.warn_if;             action = 'WARN'; }
    else if (rule.require_approval_if) { conditionKey = rule.require_approval_if; action = 'REQUIRE_APPROVAL'; }
    else return { triggered: false };

    const triggered = this._checkCondition(conditionKey, { verb, target, content, rateContext });
    return { triggered, action };
  }

  _checkCondition(condition, context) {
    const { verb, target, content, rateContext } = context;
    const checks = [];

    // verb_in: ['DELETE', 'EXEC']
    if (condition.verb_in) {
      checks.push(condition.verb_in.includes(verb));
    }

    // verb: 'DELETE' (exact)
    if (condition.verb) {
      checks.push(condition.verb === verb);
    }

    // target_matches: /patient|medical/
    if (condition.target_matches && target) {
      const pattern = condition.target_matches instanceof RegExp
        ? condition.target_matches
        : new RegExp(condition.target_matches, 'i');
      checks.push(pattern.test(target));
    }

    // content_pattern: /ssn|social.security/i
    if (condition.content_pattern && content) {
      const pattern = condition.content_pattern instanceof RegExp
        ? condition.content_pattern
        : new RegExp(condition.content_pattern, 'i');
      checks.push(pattern.test(content));
    }

    // rate_exceeds: { per_minute: 50 }
    if (condition.rate_exceeds && rateContext) {
      const limit = condition.rate_exceeds.per_minute;
      checks.push((rateContext.callsPerMinute || 0) > limit);
    }

    // All specified conditions must match (AND logic)
    return checks.length > 0 && checks.every(Boolean);
  }

  // ─────────────────────────────────────────────────────────
  // COMPLIANCE REPORT
  // ─────────────────────────────────────────────────────────

  generateComplianceReport() {
    const denials   = this.evalLog.filter(e => e.evaluation.decision === 'DENY');
    const warnings  = this.evalLog.filter(e => e.evaluation.decision === 'WARN');
    const approvals = this.evalLog.filter(e => e.evaluation.decision === 'REQUIRE_APPROVAL');

    return {
      engine:        'KasbahPolicyEngine',
      engineHash:    this.engineHash,
      packsLoaded:   [...this.packs],
      rulesLoaded:   this.rules.length,
      customRules:   this.customRules.length,
      evaluations:   this.evalLog.length,
      decisions: {
        allowed:  this.evalLog.length - denials.length - warnings.length,
        denied:   denials.length,
        warned:   warnings.length,
        approval: approvals.length
      },
      violationsByRule: this._countByRule(denials),
      topViolatedPacks: this._countByPack(denials),
      generated: new Date().toISOString()
    };
  }

  _countByRule(entries) {
    const counts = {};
    entries.forEach(e => {
      e.evaluation.violations.forEach(v => {
        counts[v.rule] = (counts[v.rule] || 0) + 1;
      });
    });
    return counts;
  }

  _countByPack(entries) {
    const counts = {};
    entries.forEach(e => {
      e.evaluation.violations.forEach(v => {
        const rule = this.rules.find(r => r.id === v.rule);
        if (rule) counts[rule.pack] = (counts[rule.pack] || 0) + 1;
      });
    });
    return counts;
  }

  _computeHash() {
    return crypto.createHash('sha256')
      .update(JSON.stringify(this.rules.map(r => r.id)))
      .digest('hex').slice(0, 16);
  }
}

module.exports = { KasbahPolicyEngine, COMPLIANCE_PACKS };
