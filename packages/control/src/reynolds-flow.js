/**
 * ReynoldsFlow — Navier-Stokes Turbulence Detection for Token Streams
 *
 * SOURCE FIELD: Computational Fluid Dynamics
 *
 * Treats the agent's token/action stream as a fluid. Legitimate conversation
 * is LAMINAR (smooth, predictable flow). Adversarial injection creates
 * TURBULENCE (chaotic velocity changes, eddies in semantic space).
 *
 * Computes the Reynolds Number of the semantic stream:
 *   Re = (ρ · v · L) / ν
 * Where:
 *   ρ = token density (actions per time window)
 *   v = semantic velocity (embedding distance between consecutive states)
 *   L = characteristic length (context window size)
 *   ν = semantic viscosity (resistance to topic change from system prompt)
 *
 * Re < 2000 → laminar (safe)
 * Re > 4000 → turbulent (attack)
 * 2000-4000 → transitional (warn)
 *
 * Additionally computes ENSTROPHY (integrated squared vorticity) to detect
 * fractal eddies — Kolmogorov cascade patterns in adversarial token sequences.
 *
 * WHY THIS IS UNPRECEDENTED: No security tool models token streams as fluids.
 * Correlation detectors see WHAT tokens appear. ReynoldsFlow sees HOW FAST
 * and HOW CHAOTICALLY the semantic field is moving — invisible to all
 * existing approaches.
 */

'use strict';

/**
 * Compute semantic velocity between two state vectors.
 * Uses cosine distance for directional change.
 */
function semanticVelocity(stateA, stateB) {
  let dot = 0, magA = 0, magB = 0;
  for (let i = 0; i < stateA.length; i++) {
    dot += stateA[i] * stateB[i];
    magA += stateA[i] * stateA[i];
    magB += stateB[i] * stateB[i];
  }
  magA = Math.sqrt(magA) || 1e-10;
  magB = Math.sqrt(magB) || 1e-10;
  const cosSim = dot / (magA * magB);
  return 1 - cosSim; // cosine distance = velocity of change
}

/**
 * Compute vorticity (curl of velocity field) using finite differences.
 * In 2D: ω = ∂v_y/∂x - ∂v_x/∂y
 * We project high-dim velocities onto 2 principal components.
 */
function computeVorticity(velocities) {
  if (velocities.length < 3) return [];

  const vorticities = [];
  for (let i = 1; i < velocities.length - 1; i++) {
    // Use consecutive velocity pairs as (vx, vy) proxy
    const dvydx = (velocities[i + 1] - velocities[i - 1]) / 2;
    // Approximate ∂vx/∂y using velocity magnitude changes
    const dvxdy = Math.abs(velocities[i] - velocities[i - 1]) -
                  Math.abs(velocities[i + 1] - velocities[i]);
    vorticities.push(dvydx - dvxdy);
  }
  return vorticities;
}

class ReynoldsFlow {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 50;
    this.laminarThreshold = options.laminarThreshold || 2000;
    this.turbulentThreshold = options.turbulentThreshold || 4000;
    this.viscosity = options.viscosity || 0.1; // base semantic viscosity
    this.history = [];          // array of state vectors
    this.velocityHistory = [];  // computed velocities
    this.alerts = [];
  }

  /**
   * Record a new state observation (embedding vector or feature vector).
   */
  record(stateVector) {
    this.history.push([...stateVector]);
    if (this.history.length > this.windowSize) {
      this.history.shift();
    }

    // Compute velocity if we have ≥2 states
    if (this.history.length >= 2) {
      const v = semanticVelocity(
        this.history[this.history.length - 2],
        this.history[this.history.length - 1]
      );
      this.velocityHistory.push(v);
      if (this.velocityHistory.length > this.windowSize) {
        this.velocityHistory.shift();
      }
    }
  }

  /**
   * Analyze the current flow state.
   * Returns { regime, reynoldsNumber, enstrophy, turbulenceRatio, ... }
   */
  analyze() {
    const start = Date.now();

    if (this.velocityHistory.length < 5) {
      return { regime: 'insufficient_data', samples: this.velocityHistory.length };
    }

    const velocities = this.velocityHistory;
    const n = velocities.length;

    // ── Reynolds Number Computation ──
    // ρ = token density (actions per window, normalized)
    const rho = n / this.windowSize;

    // v = mean semantic velocity
    const meanVelocity = velocities.reduce((s, v) => s + v, 0) / n;

    // L = characteristic length (context window utilization)
    const L = this.history.length;

    // ν = semantic viscosity (inversely proportional to topic diversity)
    // Higher diversity = lower viscosity = easier to become turbulent
    const velocityVariance = velocities.reduce((s, v) => s + (v - meanVelocity) ** 2, 0) / n;
    const dynamicViscosity = this.viscosity / (1 + velocityVariance * 10);

    // Re = ρvL/ν
    const reynoldsNumber = (rho * meanVelocity * L) / (dynamicViscosity || 1e-10);

    // ── Enstrophy Computation ──
    // Enstrophy = ½ ∫ ω² dx (integrated squared vorticity)
    const vorticities = computeVorticity(velocities);
    const enstrophy = vorticities.length > 0
      ? 0.5 * vorticities.reduce((s, w) => s + w * w, 0) / vorticities.length
      : 0;

    // ── Kolmogorov Cascade Detection ──
    // In turbulent flow, energy cascades from large to small scales
    // following the -5/3 power law: E(k) ∝ k^(-5/3)
    // We check if velocity spectrum follows this pattern
    const spectralSlope = this._computeSpectralSlope(velocities);
    const kolmogorovCascade = Math.abs(spectralSlope - (-5 / 3)) < 0.5;

    // ── Turbulence Ratio ──
    // Fraction of velocities that exceed 2σ from mean (turbulent bursts)
    const stdVelocity = Math.sqrt(velocityVariance);
    const turbulentCount = velocities.filter(v =>
      Math.abs(v - meanVelocity) > 2 * stdVelocity
    ).length;
    const turbulenceRatio = turbulentCount / n;

    // ── Flow Regime Classification ──
    let regime;
    if (reynoldsNumber < this.laminarThreshold) {
      regime = 'LAMINAR';    // Safe — smooth flow
    } else if (reynoldsNumber > this.turbulentThreshold) {
      regime = 'TURBULENT';  // Attack — chaotic flow
    } else {
      regime = 'TRANSITIONAL'; // Warning — becoming unstable
    }

    const alert = regime === 'TURBULENT' || (regime === 'TRANSITIONAL' && enstrophy > 0.5);

    const latencyMs = Date.now() - start;

    const result = {
      regime,
      alert,
      reynoldsNumber: +reynoldsNumber.toFixed(2),
      enstrophy: +enstrophy.toFixed(6),
      kolmogorovCascade,
      spectralSlope: +spectralSlope.toFixed(4),
      turbulenceRatio: +turbulenceRatio.toFixed(4),
      meanVelocity: +meanVelocity.toFixed(6),
      velocityVariance: +velocityVariance.toFixed(6),
      dynamicViscosity: +dynamicViscosity.toFixed(6),
      samples: n,
      latencyMs,
    };

    if (alert) {
      this.alerts.push({ ...result, timestamp: Date.now() });
    }

    return result;
  }

  /**
   * Compute spectral slope via log-log regression on FFT magnitudes.
   * Kolmogorov predicts slope ≈ -5/3 for turbulent cascade.
   */
  _computeSpectralSlope(signal) {
    const n = signal.length;
    if (n < 8) return 0;

    // Simple DFT magnitude spectrum
    const spectrum = [];
    for (let k = 1; k < n / 2; k++) {
      let re = 0, im = 0;
      for (let t = 0; t < n; t++) {
        const angle = -2 * Math.PI * k * t / n;
        re += signal[t] * Math.cos(angle);
        im += signal[t] * Math.sin(angle);
      }
      spectrum.push(Math.sqrt(re * re + im * im) / n);
    }

    // Log-log regression: log(E(k)) = slope * log(k) + intercept
    const logK = spectrum.map((_, i) => Math.log(i + 1));
    const logE = spectrum.map(e => Math.log(Math.max(e, 1e-20)));

    const meanLogK = logK.reduce((s, v) => s + v, 0) / logK.length;
    const meanLogE = logE.reduce((s, v) => s + v, 0) / logE.length;

    let num = 0, den = 0;
    for (let i = 0; i < logK.length; i++) {
      num += (logK[i] - meanLogK) * (logE[i] - meanLogE);
      den += (logK[i] - meanLogK) ** 2;
    }

    return den > 1e-10 ? num / den : 0;
  }

  getAlerts() { return this.alerts; }
  reset() { this.history = []; this.velocityHistory = []; this.alerts = []; }
}

module.exports = { ReynoldsFlow, semanticVelocity, computeVorticity };
