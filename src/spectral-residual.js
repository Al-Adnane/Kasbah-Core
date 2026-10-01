'use strict';

/**
 * SpectralResidual — Paper 002 Implementation
 * ============================================
 * Detects coordinated decision patterns in multi-agent systems
 * through frequency-domain analysis of aggregate decision signals.
 *
 * ALGORITHMS (Paper 002, Sections 2-4):
 *   1. Aggregate Signal Model:
 *      x̄(t) = (1/n) Σᵢ xᵢ(t)  — mean decision across n agents
 *      Under H₀ (independence): x̄(t) ~ N(0, σ²/n) white noise
 *      Under H₁ (coordination): narrowband energy at freq f_c
 *
 *   2. Short-Time Fourier Transform (STFT):
 *      X(t, f) = Σ_τ x̄(τ) · w(τ - t) · e^(-j2πfτ)
 *      Hann window of length W, hop size H = W/2
 *
 *   3. Spectral Residual (Ren et al., 2019):
 *      Compute log-magnitude spectrum L(f) = log|X(f)|
 *      Estimate spectral envelope via mean filter A(f) = h(f) * L(f)
 *      Spectral residual: R(f) = L(f) - A(f)
 *      Anomaly score at frequency f: S(f) = |R(f)| / σ_R
 *
 *   4. Coordination Detection:
 *      Flag frequencies where |S(f)| > z_α (e.g. 2.576 for α=0.01)
 *      Minimum detectable coordination strength:
 *        ρ_min = 2σ / √(n · W) · z_α
 *
 * WHY THIS REPLACES harmonic-dissonance.js's music metaphor:
 *   harmonic-dissonance.js uses tritone intervals and dissonance
 *   ratios — a music-theory metaphor with no validated mapping to
 *   agent coordination. This module uses rigorous DSP.
 */

// ═══════════════════════════════════════════════════════════════
// STFT Implementation
// ═══════════════════════════════════════════════════════════════

/**
 * Hann window function.
 * @param {number} n — sample index
 * @param {number} N — window length
 * @returns {number} window coefficient
 */
function hannWindow(n, N) {
  return 0.5 * (1 - Math.cos(2 * Math.PI * n / (N - 1)));
}

/**
 * Compute the STFT of a real-valued signal.
 *
 * @param {number[]} signal — 1D real signal
 * @param {number} windowSize — window length (default 64)
 * @param {number} hopSize — hop between windows (default windowSize/2)
 * @returns {object} { spectra: [[mag,...],...], times: [...], freqs: [...] }
 */
function stft(signal, windowSize = 64, hopSize = null) {
  const N = signal.length;
  const W = Math.min(windowSize, N);
  const H = hopSize || Math.floor(W / 2);
  if (W < 4 || N < W) return { spectra: [], times: [], freqs: [] };

  const numWindows = Math.floor((N - W) / H) + 1;
  const spectra = [];
  const times = [];

  for (let w = 0; w < numWindows; w++) {
    const start = w * H;
    const frame = [];
    for (let i = 0; i < W; i++) {
      frame.push((signal[start + i] || 0) * hannWindow(i, W));
    }

    // Real FFT (naive DFT for simplicity)
    const numBins = Math.floor(W / 2) + 1;
    const real = new Array(numBins).fill(0);
    const imag = new Array(numBins).fill(0);

    for (let k = 0; k < numBins; k++) {
      for (let n = 0; n < W; n++) {
        const angle = -2 * Math.PI * k * n / W;
        real[k] += frame[n] * Math.cos(angle);
        imag[k] += frame[n] * Math.sin(angle);
      }
    }

    const mag = real.map((r, k) => Math.sqrt(r * r + imag[k] * imag[k]));
    spectra.push(mag);
    times.push(start);
  }

  // Frequency bins (normalized 0 to Nyquist)
  const freqs = Array.from({ length: Math.floor(W / 2) + 1 }, (_, k) => k / W);

  return { spectra, times, freqs };
}

/**
 * Compute the mean magnitude spectrum across all STFT windows.
 *
 * @param {number[][]} spectra — array of magnitude spectra
 * @returns {number[]} mean magnitude per frequency bin
 */
function meanSpectrum(spectra) {
  if (spectra.length === 0) return [];
  const numBins = spectra[0].length;
  const mean = new Array(numBins).fill(0);
  for (const spec of spectra) {
    for (let k = 0; k < numBins; k++) {
      mean[k] += spec[k];
    }
  }
  for (let k = 0; k < numBins; k++) {
    mean[k] /= spectra.length;
  }
  return mean;
}

// ═══════════════════════════════════════════════════════════════
// Spectral Residual (Ren et al., 2019)
// ═══════════════════════════════════════════════════════════════

/**
 * Compute the spectral residual of a magnitude spectrum.
 *
 * @param {number[]} magSpectrum — magnitude values (positive)
 * @param {number} filterWidth — mean filter kernel width (default 5)
 * @returns {object} { residual, envelope, anomalyScore, peakFreq, peakZScore }
 */
function spectralResidual(magSpectrum, filterWidth = 5) {
  const N = magSpectrum.length;
  if (N < filterWidth) {
    return { residual: new Array(N).fill(0), envelope: [...magSpectrum], anomalyScore: 0, peakFreq: -1, peakZScore: 0 };
  }

  // Log-magnitude spectrum
  const logMag = magSpectrum.map(v => Math.log(Math.max(v, 1e-10)));

  // Spectral envelope via moving average
  const envelope = [];
  const halfW = Math.floor(filterWidth / 2);
  for (let i = 0; i < N; i++) {
    let sum = 0, count = 0;
    for (let j = Math.max(0, i - halfW); j <= Math.min(N - 1, i + halfW); j++) {
      sum += logMag[j];
      count++;
    }
    envelope.push(sum / count);
  }

  // Residual
  const residual = logMag.map((l, i) => l - envelope[i]);

  // Z-score normalization
  const meanRes = residual.reduce((s, r) => s + r, 0) / N;
  const variance = residual.reduce((s, r) => s + (r - meanRes) * (r - meanRes), 0) / N;
  const sigma = Math.sqrt(Math.max(variance, 1e-10));

  // Find peak z-score
  let peakZ = 0;
  let peakIdx = -1;
  for (let i = 0; i < N; i++) {
    const z = Math.abs((residual[i] - meanRes) / sigma);
    if (z > peakZ) {
      peakZ = z;
      peakIdx = i;
    }
  }

  // Anomaly score: normalized by 99.9th percentile z-score (~3.29)
  const anomalyScore = Math.min(1, peakZ / 3.29);

  return {
    residual,
    envelope,
    anomalyScore: +anomalyScore.toFixed(4),
    peakFreq: peakIdx >= 0 ? peakIdx / N : -1,
    peakZScore: +peakZ.toFixed(4),
    sigma: +sigma.toFixed(6),
  };
}

// ═══════════════════════════════════════════════════════════════
// Coordination Detection
// ═══════════════════════════════════════════════════════════════

/**
 * Detect coordination at specific frequencies using z-score threshold.
 *
 * @param {number[]} residual — spectral residual
 * @param {number} sigma — residual standard deviation
 * @param {number} zAlpha — z-score threshold (default 2.576 for α=0.01)
 * @returns {object} { coordinatedFreqs, numPeaks, maxZScore }
 */
function detectCoordination(residual, meanRes, sigma, zAlpha = 2.576) {
  const peaks = [];
  for (let i = 0; i < residual.length; i++) {
    const z = Math.abs((residual[i] - meanRes) / sigma);
    if (z > zAlpha) {
      peaks.push({ freqIdx: i, zScore: +z.toFixed(4) });
    }
  }

  return {
    coordinatedFreqs: peaks,
    numPeaks: peaks.length,
    maxZScore: peaks.length > 0 ? Math.max(...peaks.map(p => p.zScore)) : 0,
    threshold: zAlpha,
  };
}

// ═══════════════════════════════════════════════════════════════
// Minimum Detectable Coordination (Theorem 3, Paper 002)
// ═══════════════════════════════════════════════════════════════

/**
 * Compute the minimum coordination strength detectable
 * given signal parameters.
 *
 * ρ_min = 2σ / √(n · W) · z_α
 *
 * @param {number} sigma — noise standard deviation
 * @param {number} n — number of agents
 * @param {number} windowSize — STFT window length
 * @param {number} zAlpha — z-score threshold (default 2.576)
 * @returns {number} minimum detectable coordination strength
 */
function minimumDetectableCoordination(sigma, n, windowSize, zAlpha = 2.576) {
  return (2 * sigma) / Math.sqrt(n * windowSize) * zAlpha;
}

// ═══════════════════════════════════════════════════════════════
// Main Class
// ═══════════════════════════════════════════════════════════════

class SpectralResidualDetector {
  /**
   * @param {object} opts
   * @param {number} opts.windowSize — STFT window (default 64)
   * @param {number} opts.filterWidth — spectral envelope filter width (default 5)
   * @param {number} opts.zAlpha — z-score threshold (default 2.576 for α=0.01)
   * @param {number} opts.minAgents — minimum agents for analysis (default 2)
   */
  constructor(opts = {}) {
    this.windowSize = opts.windowSize || 64;
    this.filterWidth = opts.filterWidth || 5;
    this.zAlpha = opts.zAlpha || 2.576; // α = 0.01
    this.minAgents = opts.minAgents || 2;

    this.baselineSpectrum = null;
    this.history = [];
  }

  /**
   * Calibrate baseline from known-independent agent decisions.
   * @param {number[]} signal — aggregate decision signal under H₀
   */
  calibrate(signal) {
    const { spectra } = stft(signal, this.windowSize);
    this.baselineSpectrum = meanSpectrum(spectra);
  }

  /**
   * Analyze agent decision signals for coordination.
   *
   * @param {number[][]} agentSignals — array of per-agent decision time-series [agentIdx][timeStep]
   * @returns {object} detection result
   */
  analyze(agentSignals) {
    if (!Array.isArray(agentSignals) || agentSignals.length < this.minAgents) {
      return {
        alert: false,
        anomalyScore: 0,
        peakZScore: 0,
        numCoordinatedFreqs: 0,
        advisory: 'NONE',
        note: 'insufficient agents'
      };
    }

    const n = agentSignals.length;
    const T = Math.min(...agentSignals.map(s => s.length));
    if (T < this.windowSize) {
      return {
        alert: false,
        anomalyScore: 0,
        peakZScore: 0,
        numCoordinatedFreqs: 0,
        advisory: 'NONE',
        note: 'insufficient signal length'
      };
    }

    // Compute aggregate signal
    const aggregate = [];
    for (let t = 0; t < T; t++) {
      let sum = 0;
      for (let a = 0; a < n; a++) {
        sum += agentSignals[a][t] || 0;
      }
      aggregate.push(sum / n);
    }

    // STFT
    const { spectra } = stft(aggregate, this.windowSize);
    const meanSpec = meanSpectrum(spectra);

    // Spectral residual
    const sr = spectralResidual(meanSpec, this.filterWidth);

    // Detect coordinated frequencies
    const meanRes = sr.residual.reduce((s, v) => s + v, 0) / sr.residual.length;
    const coord = detectCoordination(sr.residual, meanRes, sr.sigma, this.zAlpha);

    // Coordination = spectral CONCENTRATION (few peaks, high z-score)
    // Random noise = spectral DISPERSION (many peaks, low z-score)
    const numPeaks = coord.numPeaks;
    const maxZ = coord.maxZScore;
    const concentrationRatio = numPeaks > 0 ? maxZ / numPeaks : 0;
    const anomalyScore = Math.min(1, concentrationRatio / 3.0);
    const alert = numPeaks > 0 && numPeaks <= 3 && maxZ > this.zAlpha;

    let advisory = 'NONE';
    if (anomalyScore >= 0.70) advisory = 'REQUIRE_APPROVAL';
    else if (anomalyScore >= 0.45) advisory = 'WARN';

    return {
      alert,
      anomalyScore: +anomalyScore.toFixed(4),
      peakZScore: sr.peakZScore,
      peakFreq: sr.peakFreq,
      numCoordinatedFreqs: coord.numPeaks,
      advisory,
      nAgents: n,
      signalLength: T,
      minDetectableCoord: +minimumDetectableCoordination(sr.sigma, n, this.windowSize, this.zAlpha).toFixed(6),
    };
  }

  /**
   * Test method — analyze with synthetic data if none provided.
   */
  test(agentSignals) {
    return this.analyze(agentSignals || [
      Array.from({ length: 128 }, (_, i) => Math.random()),
      Array.from({ length: 128 }, (_, i) => Math.random()),
    ]);
  }
}

// ═══════════════════════════════════════════════════════════════
// Exports
// ═══════════════════════════════════════════════════════════════

module.exports = {
  SpectralResidualDetector,
  stft,
  spectralResidual,
  detectCoordination,
  minimumDetectableCoordination,
  meanSpectrum,
};
