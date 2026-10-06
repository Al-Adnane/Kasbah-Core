'use strict';

/**
 * ReynoldsFlow — Navier-Stokes Turbulence Monitor for Agent Dynamics
 * 
 * Models agent risk trajectories as fluid flow. Computes Reynolds number
 * analog to detect turbulent (chaotic/coordinated) vs laminar (stable) regimes.
 * Advisory only — never DENY.
 */

class ReynoldsFlow {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 100;
    this.history = []; // array of agent vectors
    this.viscosity = options.viscosity || 0.01; // diffusion coefficient
  }

  record(vector) {
    // vector: [risk, ethicalScore, consciousness, fingerprintConfidence, ...]
    if (!Array.isArray(vector)) return;
    this.history.push({
      t: Date.now(),
      v: vector.map(x => Math.max(0, Math.min(1, Number(x) || 0)))
    });
    if (this.history.length > this.windowSize) this.history.shift();
  }

  analyze() {
    if (this.history.length < 10) {
      return { available: false, reason: 'insufficient_history', reynolds: 0 };
    }

    const n = this.history.length;
    const dim = this.history[0].v.length;
    
    // Velocity field: difference between consecutive states
    const velocities = [];
    for (let i = 1; i < n; i++) {
      const vel = new Array(dim);
      for (let k = 0; k < dim; k++) {
        vel[k] = this.history[i].v[k] - this.history[i-1].v[k];
      }
      velocities.push(vel);
    }

    // Characteristic velocity U = RMS velocity
    let U2 = 0;
    for (const v of velocities) {
      for (let k = 0; k < dim; k++) U2 += v[k] * v[k];
    }
    const U = Math.sqrt(U2 / (velocities.length * dim));

    // Characteristic length L = average pairwise distance
    let L = 0;
    let pairs = 0;
    const recent = this.history.slice(-10); // last 10 states
    for (let i = 0; i < recent.length; i++) {
      for (let j = i+1; j < recent.length; j++) {
        let d2 = 0;
        for (let k = 0; k < dim; k++) {
          const diff = recent[i].v[k] - recent[j].v[k];
          d2 += diff * diff;
        }
        L += Math.sqrt(d2);
        pairs++;
      }
    }
    L = pairs > 0 ? L / pairs : 1;

    // Reynolds number Re = U * L / nu
    const Re = (U * L) / this.viscosity;

    // Turbulence indicators
    // 1. Velocity divergence (expansion/contraction)
    let div = 0;
    for (const v of velocities) {
      for (let k = 0; k < dim; k++) div += Math.abs(v[k]);
    }
    div /= (velocities.length * dim);

    // 2. Vorticity proxy (curl in higher dims) - use velocity gradient asymmetry
    let vorticity = 0;
    if (velocities.length >= 2) {
      for (let k = 0; k < dim; k++) {
        vorticity += Math.abs(velocities[velocities.length-1][k] - velocities[velocities.length-2][k]);
      }
      vorticity /= dim;
    }

    // Regime classification
    let regime = 'laminar';
    if (Re > 2000) regime = 'turbulent';
    else if (Re > 500) regime = 'transitional';

    // Alert on turbulent regime or high vorticity
    const alert = regime === 'turbulent' || vorticity > 0.1;

    return {
      available: true,
      reynolds: Re,
      regime,
      velocity: U,
      lengthScale: L,
      divergence: div,
      vorticity,
      alert,
      advisory: alert ? 'WARN' : 'CLEAR',
      detail: `Re=${Re.toFixed(1)} (${regime}), U=${U.toFixed(4)}, L=${L.toFixed(4)}, vorticity=${vorticity.toFixed(4)}`
    };
  }
}

module.exports = { ReynoldsFlow };