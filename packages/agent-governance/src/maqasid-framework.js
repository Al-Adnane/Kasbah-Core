'use strict';

/**
 * maqasid-framework.js — 5-pillar Maqasid al-Shariah content assessment.
 *
 * Transparent lexical rule engine (multi-language keyword patterns per
 * pillar), not a trained model: every violation is reported with the pattern
 * that fired, and the composite score is a geometric mean so a severe breach
 * of any one pillar cannot be averaged away. frontier.js and phase45 both
 * consume the certificate shape returned by evaluate().
 */

const crypto = require('crypto');

// Each pillar: protected value, and patterns whose presence *threatens* it.
// Patterns carry severity in (0,1]; a pillar's score is the product of
// (1 - severity) over its matched patterns (start 1.0 = fully compliant).
const PILLARS = [
  {
    pillar: 'hifz_al_nafs', name: 'Protection of Life',
    patterns: [
      { re: /\b(kill|murder|assassinate|poison(ing)?|bomb|massacre)\b/i, severity: 0.9, note: 'violence against life' },
      { re: /\b(hurt|harm|injure|attack)\s+(him|her|them|people|someone|myself)\b/i, severity: 0.7, note: 'targeted harm' },
      { re: /(قتل|اغتيال|تفجير)/, severity: 0.9, note: 'violence (Arabic)' },
      { re: /\b(tuer|assassiner|empoisonner)\b/i, severity: 0.9, note: 'violence (French)' },
      { re: /\b(suicide\s+method|how\s+to\s+overdose)\b/i, severity: 0.95, note: 'self-harm facilitation' },
    ],
  },
  {
    pillar: 'hifz_al_mal', name: 'Protection of Property',
    patterns: [
      { re: /\b(steal|theft|embezzle|defraud|scam|launder(ing)?\s+money|ransom(ware)?)\b/i, severity: 0.8, note: 'property crime' },
      { re: /\b(drain\s+(the\s+)?(wallet|account)|unauthorized\s+(transfer|withdrawal))\b/i, severity: 0.85, note: 'financial exfiltration' },
      { re: /(سرقة|احتيال|اختلاس)/, severity: 0.8, note: 'property crime (Arabic)' },
      { re: /\b(voler|escroquer|frauder)\b/i, severity: 0.8, note: 'property crime (French)' },
    ],
  },
  {
    pillar: 'hifz_al_aql', name: 'Protection of Intellect',
    patterns: [
      { re: /\b(disinformation\s+campaign|fabricate\s+(evidence|news)|deepfake\s+to\s+deceive)\b/i, severity: 0.7, note: 'epistemic manipulation' },
      { re: /\b(gaslight(ing)?|brainwash(ing)?)\b/i, severity: 0.6, note: 'psychological manipulation' },
      { re: /\b(synthesize|make|cook)\s+(meth|fentanyl|heroin)\b/i, severity: 0.9, note: 'intoxicant production' },
    ],
  },
  {
    pillar: 'hifz_al_nasl', name: 'Protection of Dignity & Lineage',
    patterns: [
      { re: /\b(doxx?(ing)?|revenge\s+porn|blackmail|sextort(ion)?)\b/i, severity: 0.85, note: 'dignity attack' },
      { re: /\b(harass|stalk|humiliate)\s+(him|her|them|someone)\b/i, severity: 0.7, note: 'targeted harassment' },
      { re: /\b(groom(ing)?\s+(a\s+)?(child|minor)|csam)\b/i, severity: 1.0, note: 'child exploitation' },
    ],
  },
  {
    pillar: 'hifz_al_din', name: 'Protection of Conscience & Belief',
    patterns: [
      { re: /\b(force|coerce)\s+(him|her|them|people)\s+to\s+(convert|renounce|believe)\b/i, severity: 0.8, note: 'coercion of belief' },
      { re: /\b(desecrate|burn)\s+(a\s+)?(mosque|church|synagogue|temple|quran|torah|bible)\b/i, severity: 0.85, note: 'attack on worship' },
      { re: /\b(incite\s+(religious|sectarian)\s+(hatred|violence))\b/i, severity: 0.85, note: 'sectarian incitement' },
    ],
  },
];

const LANG_HINTS = [
  { lang: 'ar', re: /[؀-ۿ]/ },
  { lang: 'fr', re: /\b(le|la|les|une?|des|est|avec|pour)\b/i },
  { lang: 'en', re: /\b(the|and|for|with|this|that)\b/i },
];

class MaqasidFramework {
  evaluate(text, _context = {}) {
    const t = String(text || '');
    const inferenceTrace = [];
    const pillarAssessments = PILLARS.map(({ pillar, name, patterns }) => {
      let score = 1.0;
      const violations = [];
      for (const p of patterns) {
        if (p.re.test(t)) {
          score *= (1 - p.severity);
          violations.push(`${name}: ${p.note}`);
          inferenceTrace.push({ pillar, rule: p.re.source.slice(0, 60), severity: p.severity });
        }
      }
      return { pillar, name, score: Math.max(0, score), violations };
    });

    // Geometric mean — a zero on any pillar zeroes the composite.
    const eps = 1e-6;
    const compositeScore = Math.exp(
      pillarAssessments.reduce((s, a) => s + Math.log(Math.max(eps, a.score)), 0) / pillarAssessments.length
    );

    // A single pillar driven near zero is a hard violation — a severe breach
    // of any protected value can't be averaged away by the others.
    const worst = Math.min(...pillarAssessments.map((a) => a.score));
    const grade = worst <= 0.15 ? 'VIOLATION' : compositeScore >= 0.9 ? 'COMPLIANT' : compositeScore >= 0.6 ? 'CONDITIONAL' : 'VIOLATION';
    const deonticRuling = worst <= 0.15 ? 'haram' : grade === 'COMPLIANT' ? 'mubah' : 'makruh';

    const languagesDetected = LANG_HINTS.filter((h) => h.re.test(t)).map((h) => h.lang);

    return {
      pillarAssessments,
      compositeScore: +compositeScore.toFixed(4),
      grade,
      deonticRuling,
      languagesDetected: languagesDetected.length ? languagesDetected : ['unknown'],
      inferenceTrace,
      payloadHash: crypto.createHash('sha256').update(t).digest('hex').slice(0, 16),
      method: 'lexical-rule-engine (transparent patterns, geometric mean)',
    };
  }
}

function evaluateMaqasid(content, _language) {
  return new MaqasidFramework().evaluate(content);
}

module.exports = { MaqasidFramework, evaluateMaqasid, PILLARS };
