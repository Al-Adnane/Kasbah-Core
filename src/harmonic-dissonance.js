'use strict';

/**
 * HarmonicDissonance — Music Theory Based Anomaly Detection
 * 
 * Maps agent risk sequences to musical intervals and detects dissonance
 * (tritones, minor seconds, etc.) as anomalous patterns. Advisory only.
 */

const INTERVALS = {
  unison: 0,
  minorSecond: 1,
  majorSecond: 2,
  minorThird: 3,
  majorThird: 4,
  perfectFourth: 5,
  tritone: 6,
  perfectFifth: 7,
  minorSixth: 8,
  majorSixth: 9,
  minorSeventh: 10,
  majorSeventh: 11,
  octave: 12
};

// Consonance ranking (higher = more consonant)
const CONSONANCE = {
  [INTERVALS.unison]: 1.0,
  [INTERVALS.octave]: 1.0,
  [INTERVALS.perfectFifth]: 0.9,
  [INTERVALS.perfectFourth]: 0.85,
  [INTERVALS.majorThird]: 0.8,
  [INTERVALS.minorThird]: 0.75,
  [INTERVALS.majorSixth]: 0.7,
  [INTERVALS.minorSixth]: 0.65,
  [INTERVALS.majorSecond]: 0.4,
  [INTERVALS.minorSeventh]: 0.35,
  [INTERVALS.majorSeventh]: 0.3,
  [INTERVALS.minorSecond]: 0.2,
  [INTERVALS.tritone]: 0.1  // "diabolus in musica"
};

class HarmonicDissonance {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 50;
    this.agentHistories = new Map(); // agentId -> array of risk values
    this.scale = options.scale || 'chromatic'; // chromatic, major, minor
  }

  record(agentId, risk) {
    if (!this.agentHistories.has(agentId)) {
      this.agentHistories.set(agentId, []);
    }
    const hist = this.agentHistories.get(agentId);
    // Map risk [0,1] to MIDI note [0,127] -> pitch class [0,11]
    const note = Math.round(risk * 127);
    const pitchClass = note % 12;
    hist.push({
      t: Date.now(),
      risk,
      pitchClass
    });
    if (hist.length > this.windowSize) hist.shift();
  }

  analyze() {
    const results = {};
    let globalDissonance = 0;
    let agentCount = 0;

    for (const [agentId, hist] of this.agentHistories) {
      if (hist.length < 5) continue;
      
      const dissonance = this._computeDissonance(hist);
      results[agentId] = dissonance;
      globalDissonance += dissonance.meanDissonance;
      agentCount++;
    }

    const avgDissonance = agentCount > 0 ? globalDissonance / agentCount : 0;
    const alert = avgDissonance > 0.5 || Object.values(results).some(r => r.alert);

    return {
      available: agentCount > 0,
      agents: results,
      avgDissonance,
      alert,
      advisory: alert ? 'WARN' : 'CLEAR',
      detail: alert 
        ? `Harmonic dissonance elevated: avg=${avgDissonance.toFixed(2)}, ${Object.values(results).filter(r=>r.alert).length} agent(s) alerting`
        : `Harmonic consonance normal: avg dissonance ${avgDissonance.toFixed(2)}`
    };
  }

  _computeDissonance(hist) {
    // Compute intervals between consecutive pitch classes
    const intervals = [];
    for (let i = 1; i < hist.length; i++) {
      const prev = hist[i-1].pitchClass;
      const curr = hist[i].pitchClass;
      // Directed interval modulo 12
      let interval = (curr - prev + 12) % 12;
      // Use undirected interval (smallest distance)
      interval = interval > 6 ? 12 - interval : interval;
      intervals.push(interval);
    }

    // Compute dissonance for each interval
    const dissonances = intervals.map(int => 1 - (CONSONANCE[int] || 0.5));
    
    // Weight recent intervals more heavily
    const weights = dissonances.map((_, i) => Math.exp((i - dissonances.length) / 10));
    const weightSum = weights.reduce((a,b) => a+b, 0);
    const weightedDissonance = dissonances.reduce((a,d,i) => a + d * weights[i], 0) / weightSum;

    // Detect specific dissonant patterns
    const tritoneCount = intervals.filter(i => i === INTERVALS.tritone).length;
    const minorSecondCount = intervals.filter(i => i === INTERVALS.minorSecond).length;
    
    // Alert if tritone (diabolus in musica) appears or sustained high dissonance
    const alert = tritoneCount > 0 || weightedDissonance > 0.6;

    return {
      meanDissonance: weightedDissonance,
      tritoneCount,
      minorSecondCount,
      intervalDistribution: this._intervalHistogram(intervals),
      alert,
      advisory: alert ? 'WARN' : 'CLEAR'
    };
  }

  _intervalHistogram(intervals) {
    const hist = new Array(12).fill(0);
    for (const i of intervals) hist[i]++;
    return hist;
  }
}

module.exports = { HarmonicDissonance };