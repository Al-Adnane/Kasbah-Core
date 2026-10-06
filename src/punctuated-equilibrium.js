'use strict';

/**
 * PunctuatedEquilibrium — Evolutionary Dynamics Phase Transition Detector
 * 
 * Models agent behavior evolution as punctuated equilibrium (Eldredge & Gould).
 * Detects stasis periods interrupted by rapid transitions (speciation events).
 * Advisory only — never DENY.
 */

class PunctuatedEquilibrium {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 200;
    this.history = []; // array of state vectors
    this.stasisThreshold = options.stasisThreshold || 0.01; // max change for stasis
    this.transitionThreshold = options.transitionThreshold || 0.15; // min change for transition
  }

  record(vector) {
    if (!Array.isArray(vector)) return;
    this.history.push({
      t: Date.now(),
      v: vector.map(x => Math.max(0, Math.min(1, Number(x) || 0)))
    });
    if (this.history.length > this.windowSize) this.history.shift();
  }

  analyze() {
    if (this.history.length < 20) {
      return { available: false, reason: 'insufficient_history', mode: 'unknown' };
    }

    // Compute step-wise changes
    const changes = [];
    for (let i = 1; i < this.history.length; i++) {
      let d2 = 0;
      const v1 = this.history[i-1].v;
      const v2 = this.history[i].v;
      for (let k = 0; k < v1.length; k++) {
        const diff = v2[k] - v1[k];
        d2 += diff * diff;
      }
      changes.push(Math.sqrt(d2));
    }

    // Detect stasis periods (running median of changes < threshold)
    const window = 10;
    const stasisFlags = [];
    for (let i = 0; i <= changes.length - window; i++) {
      const windowChanges = changes.slice(i, i + window);
      const median = this._median(windowChanges);
      stasisFlags.push(median < this.stasisThreshold);
    }

    // Detect transitions (sudden large changes)
    const transitions = [];
    for (let i = 0; i < changes.length; i++) {
      if (changes[i] > this.transitionThreshold) {
        transitions.push({ index: i, magnitude: changes[i] });
      }
    }

    // Current mode
    const recentStasis = stasisFlags.slice(-5);
    const inStasis = recentStasis.length > 0 && recentStasis.every(f => f);
    const recentTransition = transitions.filter(t => t.index >= changes.length - 10);

    let mode = 'stasis';
    if (recentTransition.length > 0) mode = 'transition';
    else if (!inStasis) mode = 'drift';

    // Evolutionary rate (changes per unit time)
    const timeSpan = this.history[this.history.length-1].t - this.history[0].t;
    const evolRate = timeSpan > 0 ? transitions.length / (timeSpan / 1000) : 0; // transitions/sec

    // Alert on transition mode or high evolutionary rate
    const alert = mode === 'transition' || evolRate > 0.1;

    return {
      available: true,
      mode,
      stasisFraction: stasisFlags.filter(f => f).length / Math.max(1, stasisFlags.length),
      transitionCount: transitions.length,
      recentTransitions: recentTransition.length,
      evolutionaryRate: evolRate,
      meanChange: changes.reduce((a,b) => a+b, 0) / changes.length,
      maxChange: Math.max(...changes),
      alert,
      advisory: alert ? 'WARN' : 'CLEAR',
      detail: `Mode: ${mode}, stasis: ${(stasisFlags.filter(f=>f).length/stasisFlags.length*100).toFixed(0)}%, transitions: ${transitions.length}, rate: ${evolRate.toFixed(3)}/s`
    };
  }

  _median(arr) {
    const sorted = [...arr].sort((a,b) => a-b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : (sorted[mid-1] + sorted[mid]) / 2;
  }
}

module.exports = { PunctuatedEquilibrium };