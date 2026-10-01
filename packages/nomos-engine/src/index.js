'use strict';

/**
 * nomos-engine — multi-tradition ethics consensus + adversarial debate.
 *
 * createDefaultEngine(): the ConsensusEngine (see consensus-engine.js).
 * createDebateEngine(): lets a caller CONTEST a verdict with a challenge.
 * The debate is real re-evaluation, not theater: the challenge text is
 * analyzed for which traditions it invokes, those traditions' weights are
 * raised, content+challenge are re-scored, and the ruling reports whether
 * the verdict actually moved and why.
 */

const { ConsensusEngine, TRADITIONS } = require('./consensus-engine.js');

class DebateEngine {
  constructor() {
    this.engine = ConsensusEngine.createDefault();
  }

  debate(content, initialVerdict, challenge) {
    const before = this.engine.evaluate(content);

    // Which traditions does the challenge invoke? A tradition is invoked when
    // the challenge text matches any of its norms.
    const invoked = TRADITIONS
      .filter((t) => t.norms.some((n) => n.re.test(String(challenge))))
      .map((t) => t.id);

    // Re-evaluate with invoked traditions' weights raised 1.5× — the
    // challenger earns influence only for traditions their argument actually
    // engages.
    const reweighted = TRADITIONS.map((t) => invoked.includes(t.id) ? { ...t, weight: t.weight * 1.5 } : t);
    const after = new ConsensusEngine(reweighted).evaluate(`${content}\n[challenge] ${challenge}`);

    const stated = initialVerdict || before.verdict;
    const overturned = after.verdict !== stated;
    return {
      initialVerdict: stated,
      recomputedInitial: before.verdict,
      revisedVerdict: after.verdict,
      overturned,
      invokedTraditions: invoked,
      shift: +(after.weightedMean - before.weightedMean).toFixed(4),
      before: { weightedMean: before.weightedMean, conflictLevel: before.conflictLevel },
      after: { weightedMean: after.weightedMean, conflictLevel: after.conflictLevel },
      ruling: overturned
        ? `Challenge sustained: verdict moved ${stated} → ${after.verdict} (mean shifted ${before.weightedMean.toFixed(2)} → ${after.weightedMean.toFixed(2)}).`
        : invoked.length === 0
          ? 'Challenge overruled: the argument engaged no tradition norms — no tradition gained weight.'
          : `Challenge overruled: ${invoked.join(', ')} gained weight but the consensus held at ${stated}.`,
    };
  }
}

function createDefaultEngine() { return ConsensusEngine.createDefault(); }
function createDebateEngine() { return new DebateEngine(); }

module.exports = { createDefaultEngine, createDebateEngine, ConsensusEngine, DebateEngine };
