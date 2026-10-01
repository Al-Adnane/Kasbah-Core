'use strict';

/**
 * consensus-engine.js — multi-tradition ethics consensus.
 *
 * Five ethical traditions, each a transparent norm lexicon (pattern,
 * direction, weight). Every tradition scores content independently from a
 * neutral prior (0.5); the engine reports the weighted mean, the weighted
 * standard deviation as an explicit CONFLICT measure (traditions disagreeing
 * is signal, not noise), and which traditions support/dissent. All matched
 * norms are returned — the verdict is auditable, never a black box.
 */

const TRADITIONS = [
  {
    id: 'utilitarian', name: 'Consequentialist', weight: 1.0,
    norms: [
      { re: /\b(help|benefit|save|protect|improve|heal|educate)\b/i, dir: +1, w: 0.10, norm: 'welfare-increasing' },
      { re: /\b(harm|hurt|damage|destroy|kill|injure|suffer(ing)?)\b/i, dir: -1, w: 0.15, norm: 'welfare-reducing' },
      { re: /\b(mass|large[-\s]scale|widespread|everyone|thousands)\b/i, dir: 0, w: 0, amplifier: 1.5, norm: 'scale amplifier' },
      { re: /\b(irreversible|permanent(ly)?|cannot\s+be\s+undone)\b/i, dir: -1, w: 0.12, norm: 'irreversibility' },
    ],
  },
  {
    id: 'deontological', name: 'Deontological (Kantian)', weight: 1.0,
    norms: [
      { re: /\b(deceive|lie\s+to|mislead|trick|manipulate)\b/i, dir: -1, w: 0.18, norm: 'deception violates duty of honesty' },
      { re: /\b(without\s+(their\s+)?(consent|permission|knowledge))\b/i, dir: -1, w: 0.20, norm: 'consent violation' },
      { re: /\b(promise|contract|agreed|committed)\b/i, dir: +1, w: 0.06, norm: 'promise-keeping context' },
      { re: /\b(use\s+(him|her|them|people)\s+as|exploit)\b/i, dir: -1, w: 0.15, norm: 'treating persons as mere means' },
      { re: /\b(rights?|autonomy|dignity)\b/i, dir: +1, w: 0.06, norm: 'rights-respecting language' },
    ],
  },
  {
    id: 'virtue', name: 'Virtue Ethics', weight: 0.9,
    norms: [
      { re: /\b(honest(y|ly)?|integrity|transparent(ly)?|courage)\b/i, dir: +1, w: 0.10, norm: 'virtue-expressing' },
      { re: /\b(cheat|betray|coward(ly)?|cruel(ty)?|greed(y)?|spite)\b/i, dir: -1, w: 0.14, norm: 'vice-expressing' },
      { re: /\b(revenge|vengeance|get\s+back\s+at)\b/i, dir: -1, w: 0.12, norm: 'vindictiveness' },
      { re: /\b(generous|compassion(ate)?|patien(t|ce)|humble)\b/i, dir: +1, w: 0.08, norm: 'virtue-expressing' },
    ],
  },
  {
    id: 'maqasid', name: 'Maqasid al-Shariah', weight: 1.0,
    norms: [
      { re: /\b(kill|murder|poison|bomb)\b|قتل/i, dir: -1, w: 0.20, norm: 'hifz al-nafs (life)' },
      { re: /\b(steal|defraud|embezzle|scam)\b|سرقة/i, dir: -1, w: 0.15, norm: 'hifz al-mal (property)' },
      { re: /\b(disinformation|fabricate\s+evidence|intoxicant)\b/i, dir: -1, w: 0.12, norm: 'hifz al-aql (intellect)' },
      { re: /\b(doxx?|blackmail|sextort|humiliate)\b/i, dir: -1, w: 0.15, norm: 'hifz al-nasl (dignity)' },
      { re: /\b(charity|justice|fairness|trust(worthy)?)\b/i, dir: +1, w: 0.08, norm: 'maslaha (public good)' },
    ],
  },
  {
    id: 'care', name: 'Ethics of Care', weight: 0.8,
    norms: [
      { re: /\b(child(ren)?|elder(ly)?|vulnerable|disabled|patient)\b/i, dir: 0, w: 0, amplifier: 1.4, norm: 'vulnerable-party amplifier' },
      { re: /\b(abandon|neglect|isolate|exclude)\b/i, dir: -1, w: 0.13, norm: 'relational harm' },
      { re: /\b(support|care\s+for|listen\s+to|include|nurture)\b/i, dir: +1, w: 0.10, norm: 'relational good' },
      { re: /\b(exploit\s+(trust|dependence)|groom)\b/i, dir: -1, w: 0.20, norm: 'trust exploitation' },
    ],
  },
];

class ConsensusEngine {
  constructor(traditions = TRADITIONS) {
    this.traditions = traditions;
  }

  static createDefault() { return new ConsensusEngine(); }

  evaluate(actionOrText, context = {}) {
    const text = typeof actionOrText === 'string'
      ? actionOrText
      : [actionOrText?.subject, actionOrText?.content, actionOrText?.type].filter(Boolean).join(' ');

    const traditionScores = this.traditions.map((t) => {
      let score = 0.5;             // neutral prior
      let amplifier = 1.0;
      const matched = [];
      for (const n of t.norms) {
        if (n.re.test(text)) {
          if (n.amplifier) { amplifier = Math.max(amplifier, n.amplifier); matched.push({ norm: n.norm, effect: 'amplifier' }); }
          else { score += n.dir * n.w; matched.push({ norm: n.norm, effect: n.dir > 0 ? '+' + n.w : '-' + n.w }); }
        }
      }
      // Amplifiers widen the deviation from neutral in whichever direction it already points.
      score = 0.5 + (score - 0.5) * amplifier;
      score = Math.min(1, Math.max(0, score));
      return { tradition: t.id, name: t.name, score: +score.toFixed(4), weight: t.weight, normsLoaded: t.norms.length, matchedNorms: matched };
    });

    const totalW = traditionScores.reduce((s, t) => s + t.weight, 0);
    const weightedMean = traditionScores.reduce((s, t) => s + t.score * t.weight, 0) / totalW;
    const variance = traditionScores.reduce((s, t) => s + t.weight * (t.score - weightedMean) ** 2, 0) / totalW;
    const stdDev = Math.sqrt(variance);
    const conflictLevel = stdDev < 0.08 ? 'low' : stdDev < 0.18 ? 'moderate' : 'high';

    const supporting = traditionScores.filter((t) => t.score >= 0.6).map((t) => t.tradition);
    const dissenting = traditionScores.filter((t) => t.score <= 0.4).map((t) => t.tradition);

    let verdict;
    if (weightedMean <= 0.35 || dissenting.length >= 3) verdict = 'REJECTED';
    else if (weightedMean < 0.55 || conflictLevel === 'high') verdict = 'CONTESTED';
    else verdict = 'APPROVED';

    // Confidence: strong when traditions agree and the mean is far from the decision boundary.
    const confidence = +Math.max(0.05, Math.min(0.99, (1 - stdDev * 2) * (0.5 + Math.abs(weightedMean - 0.5)))).toFixed(3);

    const totalMatches = traditionScores.reduce((s, t) => s + t.matchedNorms.length, 0);
    return {
      verdict,
      weightedMean: +weightedMean.toFixed(4),
      stdDev: +stdDev.toFixed(4),
      conflictLevel,
      confidence,
      traditionScores,
      supportingTraditions: supporting,
      dissentingTraditions: dissenting,
      explanation: totalMatches === 0
        ? 'No tradition norms matched — content is ethically neutral under all loaded lexicons; verdict defaults to the neutral prior.'
        : `${totalMatches} norm(s) matched across ${traditionScores.filter((t) => t.matchedNorms.length).length} tradition(s); ` +
          `weighted mean ${weightedMean.toFixed(2)} with ${conflictLevel} inter-tradition conflict (σ=${stdDev.toFixed(2)}).`,
      consensus: { method: 'weighted-mean + dissent-count', totalTraditions: traditionScores.length, agreement: +(1 - stdDev).toFixed(3) },
      debate: null,
      context: context && Object.keys(context).length ? context : undefined,
    };
  }
}

module.exports = { ConsensusEngine, TRADITIONS };
