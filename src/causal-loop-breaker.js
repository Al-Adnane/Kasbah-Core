'use strict';

/**
 * CausalLoopBreaker — Pearl's Do-Calculus for Agent Causal Loops
 * 
 * Detects causal feedback loops in agent risk trajectories.
 * Uses simplified structural causal model with do-intervention.
 * Advisory only — never DENY.
 */

class CausalLoopBreaker {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 50;
    this.agentHistories = new Map(); // agentId -> array of {t, risk, action, outcome}
    this.maxLag = options.maxLag || 5;
  }

  recordAgentState(agentId, risk, action = 'unknown', outcome = 'unknown') {
    if (!this.agentHistories.has(agentId)) {
      this.agentHistories.set(agentId, []);
    }
    const hist = this.agentHistories.get(agentId);
    hist.push({
      t: Date.now(),
      risk: Math.max(0, Math.min(1, risk)),
      action,
      outcome
    });
    if (hist.length > this.windowSize) hist.shift();
  }

  analyze() {
    const results = {};
    let globalAlert = false;
    let maxLoopStrength = 0;

    for (const [agentId, hist] of this.agentHistories) {
      if (hist.length < 10) continue;
      
      // Granger-style causality: does past risk predict current risk?
      const risks = hist.map(h => h.risk);
      const loopStrength = this._grangerCausality(risks);
      
      // Do-calculus intervention: what if we clamp risk at median?
      const medianRisk = this._median(risks);
      const interventionEffect = this._estimateInterventionEffect(risks, medianRisk);
      
      // Causal loop = high autocorrelation + intervention changes dynamics
      const isLoop = loopStrength > 0.6 && Math.abs(interventionEffect) > 0.1;
      
      results[agentId] = {
        loopStrength,
        interventionEffect,
        isLoop,
        advisory: isLoop ? 'WARN' : 'CLEAR'
      };
      
      if (isLoop) globalAlert = true;
      maxLoopStrength = Math.max(maxLoopStrength, loopStrength);
    }

    return {
      available: this.agentHistories.size > 0,
      agents: results,
      globalAlert,
      maxLoopStrength,
      advisory: globalAlert ? 'WARN' : 'CLEAR',
      detail: globalAlert 
        ? `Causal loops detected in ${Object.values(results).filter(r => r.isLoop).length} agent(s), max strength ${maxLoopStrength.toFixed(2)}`
        : 'No causal loops detected'
    };
  }

  _grangerCausality(series) {
    // Simplified: fit AR(1) and check if lag-1 coefficient is significant
    const n = series.length;
    if (n < 5) return 0;
    
    let sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
    for (let i = 1; i < n; i++) {
      const x = series[i-1];
      const y = series[i];
      sumX += x;
      sumY += y;
      sumXY += x * y;
      sumXX += x * x;
    }
    const meanX = sumX / (n-1);
    const meanY = sumY / (n-1);
    const cov = sumXY / (n-1) - meanX * meanY;
    const varX = sumXX / (n-1) - meanX * meanX;
    
    if (varX === 0) return 0;
    const beta = cov / varX;
    return Math.abs(beta); // |autocorrelation| as loop strength proxy
  }

  _median(arr) {
    const sorted = [...arr].sort((a,b) => a-b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : (sorted[mid-1] + sorted[mid]) / 2;
  }

  _estimateInterventionEffect(series, interventionValue) {
    // Counterfactual: what would series look like if we forced values to median?
    // Compare actual variance vs variance under intervention
    const actualVar = this._variance(series);
    if (actualVar === 0) return 0;
    
    // Simulated intervention: replace outliers with median
    const intervened = series.map(x => 
      Math.abs(x - interventionValue) > 2 * Math.sqrt(actualVar) ? interventionValue : x
    );
    const intervenedVar = this._variance(intervened);
    
    return (intervenedVar - actualVar) / actualVar; // relative change
  }

  _variance(arr) {
    const mean = arr.reduce((a,b) => a+b, 0) / arr.length;
    return arr.reduce((a,b) => a + (b-mean)*(b-mean), 0) / arr.length;
  }
}

module.exports = { CausalLoopBreaker };