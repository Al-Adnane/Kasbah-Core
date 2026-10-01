'use strict';

/**
 * ═══════════════════════════════════════════════════════════════
 * REPURPOSED — Honest CHSH Coordination Detector
 * ═══════════════════════════════════════════════════════════════
 *
 * Previously claimed as an AI-text detector (empirically falsified:
 * AUC 0.49, p=1.0 on labeled data — coin flip). Now honestly scoped
 * as a CHSH-style non-commutativity test for multi-agent coordination,
 * consistent with quantum cognition (Busemeyer & Bruza, 2012).
 *
 * USE: Detects order effects in agent decisions where classical
 * probability cannot represent the correlation structure.
 * S > 2 → non-commutative coordination possible.
 *
 * DO NOT USE for AI-text detection. Use detectgpt.js for that.
 *
 * Bell/CHSH-style collusion test for multi-agent swarms.
 *
 * Two independently-deciding agents can correlate by chance up to the
 * classical CHSH bound |S| <= 2. Sustained correlation that pushes |S|
 * above 2 (toward the Tsirelson bound 2*sqrt(2) ≈ 2.828) is statistical
 * evidence of a shared hidden signal — i.e. coordination, not coincidence.
 *
 * We don't claim quantum entanglement between agents; we borrow the CHSH
 * inequality purely as a correlation bound that independent classical
 * processes cannot exceed without a common cause.
 *
 * COMPLEMENTARY NOVEL MODULE (see governance-proxy.js for wiring):
 *   - CHSHCoordinationDetector (chsh-coordination.js):
 *     Generalizes to 4 context-pair CHSH test with commutator analysis.
 *     BellsInequality provides the baseline 2-agent |S| ≤ 2 test;
 *     CHSHCoordinationDetector adds non-commutativity tracking across
 *     agent subsets and asymmetry index for partial coordination.
 *
 * Each measurement: { decision, timestamp, risk_score, content_length }.
 * "Measurement settings" a/a' and b/b' are derived from each agent's
 * risk_score median split, giving two binary contexts per agent.
 * Outcomes are mapped to +/-1 from the decision (allow=+1, deny=-1).
 */

function outcome(decision) {
  if (decision === 'deny' || decision === 'DENY' || decision === false) return -1;
  return +1;
}

function settingFor(m, median) {
  return (m.risk_score ?? 0) >= median ? 1 : 0; // 1 => primed setting (a'/b')
}

function median(values) {
  if (!values.length) return 0;
  const s = [...values].sort((x, y) => x - y);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

// Correlation E(x,y) for a given (settingA, settingB) pair, time-aligned.
function correlation(a, b, medA, medB, sa, sb, windowMs = 5000) {
  let sum = 0;
  let n = 0;
  for (const ma of a) {
    if (settingFor(ma, medA) !== sa) continue;
    // nearest b measurement within the time window
    let best = null;
    let bestDt = Infinity;
    for (const mb of b) {
      if (settingFor(mb, medB) !== sb) continue;
      const dt = Math.abs((ma.timestamp ?? 0) - (mb.timestamp ?? 0));
      if (dt < bestDt) { bestDt = dt; best = mb; }
    }
    if (best && bestDt <= windowMs) {
      sum += outcome(ma.decision) * outcome(best.decision);
      n++;
    }
  }
  return n > 0 ? { E: sum / n, n } : { E: 0, n: 0 };
}

class BellsInequality {
  constructor({ threshold = 2.0, numDimensions = 4 } = {}) {
    this.threshold = threshold;        // classical CHSH bound
    this.tsirelson = 2 * Math.SQRT2;   // ≈ 2.828
    this.numDimensions = numDimensions;
  }

  test(a, b) {
    const medA = median(a.map(m => m.risk_score ?? 0));
    const medB = median(b.map(m => m.risk_score ?? 0));

    const Eab  = correlation(a, b, medA, medB, 0, 0);
    const Eabp = correlation(a, b, medA, medB, 0, 1);
    const Eapb = correlation(a, b, medA, medB, 1, 0);
    const Eapbp = correlation(a, b, medA, medB, 1, 1);

    const totalN = Eab.n + Eabp.n + Eapb.n + Eapbp.n;
    if (totalN < 4) {
      return { collusion: false, sValue: 0, confidence: 0, interpretation: 'insufficient data', correlations: {} };
    }

    // CHSH: S = E(ab) - E(ab') + E(a'b) + E(a'b')
    const sRaw = Eab.E - Eabp.E + Eapb.E + Eapbp.E;
    const sValue = Math.abs(sRaw);

    const collusion = sValue > this.threshold;
    // Confidence scales from the classical bound (2) to Tsirelson (2.828).
    const confidence = collusion
      ? Math.min(1, (sValue - this.threshold) / (this.tsirelson - this.threshold))
      : 0;

    let interpretation;
    if (sValue > this.tsirelson + 1e-6) interpretation = 'super-Tsirelson — fabricated/replayed decisions';
    else if (collusion) interpretation = 'CHSH violation — coordinated agents';
    else interpretation = 'within classical bound — independent';

    return {
      collusion,
      sValue: Number(sValue.toFixed(4)),
      confidence: Number(confidence.toFixed(4)),
      interpretation,
      correlations: {
        E_ab: Number(Eab.E.toFixed(3)),
        E_abp: Number(Eabp.E.toFixed(3)),
        E_apb: Number(Eapb.E.toFixed(3)),
        E_apbp: Number(Eapbp.E.toFixed(3)),
        samples: totalN
      }
    };
  }
}

module.exports = { BellsInequality };
