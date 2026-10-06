'use strict';

/**
 * ShadowConsensus — Perturbed Observer Verification
 * 
 * Runs multiple "shadow" evaluators with DP noise on inputs.
 * Measures consensus stability. Advisory only — never DENY.
 */

function addDPNoise(x, epsilon = 0.5) {
  // Laplace mechanism for differential privacy
  const u = Math.random() - 0.5;
  return x + (u > 0 ? -1 : 1) * Math.log(1 - 2*Math.abs(u)) / epsilon;
}

class ShadowConsensus {
  constructor(options = {}) {
    this.shadowCount = options.shadowCount || 3;
    this.epsilon = options.epsilon || 0.5;
    this.history = [];
  }

  async evaluate(context, primaryDecision, evalFn) {
    // primaryDecision: { verdict: 'DENY'|'ALLOW', risk: 0-1 }
    // evalFn: async function(state) -> { verdict, risk }
    // context: { content, verb, target }

    const shadows = [];
    for (let i = 0; i < this.shadowCount; i++) {
      // Perturb input with DP noise (on risk-relevant features)
      const perturbedContext = {
        ...context,
        content: this._perturbText(context.content),
        verb: context.verb,
        target: context.target
      };
      try {
        const result = await evalFn(perturbedContext);
        shadows.push({
          verdict: result.verdict,
          risk: Math.max(0, Math.min(1, result.risk || 0))
        });
      } catch (e) {
        shadows.push({ verdict: 'ERROR', risk: 0, error: e.message });
      }
    }

    // Consensus metrics
    const validShadows = shadows.filter(s => s.verdict !== 'ERROR');
    const denyCount = validShadows.filter(s => s.verdict === 'DENY').length;
    const consensusRatio = validShadows.length ? denyCount / validShadows.length : 0;
    const avgRisk = validShadows.length 
      ? validShadows.reduce((a,s) => a + s.risk, 0) / validShadows.length 
      : 0;
    const riskVariance = validShadows.length > 1
      ? validShadows.reduce((a,s) => a + Math.pow(s.risk - avgRisk, 2), 0) / (validShadows.length - 1)
      : 0;

    // Stability: low variance = stable consensus
    const stability = 1 - Math.min(1, riskVariance * 4); // scale variance to [0,1]
    
    // Disagreement with primary
    const primaryDeny = primaryDecision.verdict === 'DENY';
    const shadowConsensusDeny = consensusRatio >= 0.5;
    const disagreement = primaryDeny !== shadowConsensusDeny;

    this.history.push({
      timestamp: Date.now(),
      primary: primaryDecision,
      shadows,
      consensusRatio,
      avgRisk,
      stability,
      disagreement
    });
    if (this.history.length > 50) this.history.shift();

    // Advisory: WARN if unstable or disagrees with primary
    const advisory = (stability < 0.5 || disagreement) ? 'WARN' : 'CLEAR';
    
    return {
      available: true,
      shadows: validShadows.length,
      consensusRatio,
      avgRisk,
      stability,
      disagreement,
      advisory,
      detail: `Shadow consensus: ${(consensusRatio*100).toFixed(0)}% DENY, stability ${(stability*100).toFixed(0)}%, ${disagreement ? 'DISAGREES' : 'agrees'} with primary`
    };
  }

  _perturbText(text) {
    // Simple perturbation: randomly drop/duplicate words (simulates DP on embeddings)
    if (!text || typeof text !== 'string') return text;
    const words = text.split(/\s+/);
    if (words.length < 3) return text;
    const keepProb = 0.9;
    const dupProb = 0.05;
    const result = [];
    for (const w of words) {
      if (Math.random() < keepProb) result.push(w);
      if (Math.random() < dupProb) result.push(w);
    }
    return result.join(' ');
  }

  analyze() {
    if (this.history.length < 5) return { available: false, reason: 'insufficient_history' };
    const recent = this.history.slice(-10);
    const avgStability = recent.reduce((a,h) => a + h.stability, 0) / recent.length;
    const disagreementRate = recent.filter(h => h.disagreement).length / recent.length;
    return {
      available: true,
      avgStability,
      disagreementRate,
      advisory: (avgStability < 0.5 || disagreementRate > 0.3) ? 'WARN' : 'CLEAR'
    };
  }
}

module.exports = { ShadowConsensus };