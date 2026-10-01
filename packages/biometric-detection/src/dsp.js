'use strict';

/**
 * dsp.js — small, real signal-processing kernel shared by the biometric
 * detectors: radix-2 FFT, magnitude spectrum, autocorrelation, statistics.
 * No approximations pretending to be spectra — this is an actual FFT.
 */

// In-place iterative radix-2 Cooley–Tukey. Input length must be a power of 2.
function fft(re, im) {
  const n = re.length;
  if (n !== im.length || (n & (n - 1)) !== 0) throw new Error('fft: length must be a power of 2');
  // bit-reversal permutation
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) { [re[i], re[j]] = [re[j], re[i]]; [im[i], im[j]] = [im[j], im[i]]; }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const ang = -2 * Math.PI / len;
    const wr = Math.cos(ang), wi = Math.sin(ang);
    for (let i = 0; i < n; i += len) {
      let cwr = 1, cwi = 0;
      for (let j = 0; j < len / 2; j++) {
        const ur = re[i + j], ui = im[i + j];
        const vr = re[i + j + len / 2] * cwr - im[i + j + len / 2] * cwi;
        const vi = re[i + j + len / 2] * cwi + im[i + j + len / 2] * cwr;
        re[i + j] = ur + vr; im[i + j] = ui + vi;
        re[i + j + len / 2] = ur - vr; im[i + j + len / 2] = ui - vi;
        const nwr = cwr * wr - cwi * wi;
        cwi = cwr * wi + cwi * wr; cwr = nwr;
      }
    }
  }
}

/** Magnitude spectrum of a real signal (Hann-windowed, zero-padded to pow2). */
function magnitudeSpectrum(signal) {
  const n = signal.length;
  let size = 1; while (size < n) size <<= 1;
  const re = new Float64Array(size), im = new Float64Array(size);
  for (let i = 0; i < n; i++) {
    const w = 0.5 - 0.5 * Math.cos((2 * Math.PI * i) / (n - 1 || 1)); // Hann
    re[i] = signal[i] * w;
  }
  fft(re, im);
  const mags = new Float64Array(size / 2);
  for (let i = 0; i < size / 2; i++) mags[i] = Math.hypot(re[i], im[i]);
  return { mags, fftSize: size };
}

function mean(a) { let s = 0; for (const v of a) s += v; return s / (a.length || 1); }
function variance(a, m = mean(a)) { let s = 0; for (const v of a) s += (v - m) ** 2; return s / (a.length || 1); }

/** Normalized autocorrelation at each lag in [minLag, maxLag]. */
function autocorr(signal, minLag, maxLag) {
  const m = mean(signal);
  const x = signal.map((v) => v - m);
  const denom = x.reduce((s, v) => s + v * v, 0) || 1e-12;
  const out = [];
  for (let lag = minLag; lag <= maxLag; lag++) {
    let s = 0;
    for (let i = 0; i + lag < x.length; i++) s += x[i] * x[i + lag];
    out.push({ lag, r: s / denom });
  }
  return out;
}

/** Spectral flatness (geometric mean / arithmetic mean of power) in a bin range. */
function spectralFlatness(mags, from = 0, to = mags.length) {
  let logSum = 0, sum = 0, n = 0;
  for (let i = from; i < to; i++) {
    const p = mags[i] * mags[i] + 1e-12;
    logSum += Math.log(p); sum += p; n++;
  }
  if (!n) return 0;
  return Math.exp(logSum / n) / (sum / n);
}

module.exports = { fft, magnitudeSpectrum, autocorr, spectralFlatness, mean, variance };
