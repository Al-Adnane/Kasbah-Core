'use strict';

/**
 * biometric-detection — rPPG liveness, voice-clone artifact analysis, and
 * neural-codec artifact detection. All three run real DSP (see dsp.js:
 * actual FFT, autocorrelation, spectral flatness) over caller-supplied
 * samples. Every result carries a `method` field describing exactly what was
 * measured; none of these are trained models and none pretend to be.
 */

const { magnitudeSpectrum, autocorr, spectralFlatness, mean, variance } = require('./dsp.js');
const { NeuralFingerprintAnalyzer } = require('./neural-fingerprint.js');

// ── rPPG — remote photoplethysmography ───────────────────────────────────────
// A live face shows a periodic blood-volume pulse (0.7–4 Hz ≈ 42–240 bpm) in
// the green channel; a deepfake or printed photo generally does not.

class rPPGDetector {
  /**
   * @param {Array} videoFrames — per-frame data: either numbers (mean green
   *   value per frame) or arrays/objects with {r,g,b} means or raw pixels.
   * @param {number} frameRate — frames per second (default 30)
   */
  detect(videoFrames, frameRate = 30) {
    if (!Array.isArray(videoFrames) || videoFrames.length < 32) {
      return { pulseDetected: false, error: 'need >= 32 frames of green-channel samples', framesGiven: videoFrames?.length || 0 };
    }
    const signal = videoFrames.map((f) => {
      if (typeof f === 'number') return f;
      if (Array.isArray(f)) return mean(f);
      if (f && typeof f.g === 'number') return f.g;
      return 0;
    });

    // Detrend: subtract moving average (removes lighting drift).
    const win = Math.max(4, Math.round(frameRate));
    const detrended = signal.map((v, i) => {
      const a = Math.max(0, i - win), b = Math.min(signal.length, i + win);
      return v - mean(signal.slice(a, b));
    });

    // Spectrum: find the peak inside the plausible pulse band.
    const { mags, fftSize } = magnitudeSpectrum(detrended);
    const hzPerBin = frameRate / fftSize;
    const lo = Math.max(1, Math.floor(0.7 / hzPerBin));
    const hi = Math.min(mags.length - 1, Math.ceil(4.0 / hzPerBin));
    if (hi <= lo) return { pulseDetected: false, error: 'frame rate too low to resolve the pulse band' };

    let peakBin = lo;
    for (let i = lo; i <= hi; i++) if (mags[i] > mags[peakBin]) peakBin = i;
    const bandPower = mags.slice(lo, hi + 1).reduce((s, v) => s + v * v, 0);
    const totalPower = mags.slice(1).reduce((s, v) => s + v * v, 0) + 1e-12;
    const peakPower = mags[peakBin] ** 2;
    const snr = peakPower / ((bandPower - peakPower) / Math.max(1, hi - lo) + 1e-12);
    const bandRatio = bandPower / totalPower;

    // Corroborate periodicity in the time domain.
    const lagLo = Math.round(frameRate / 4.0), lagHi = Math.min(detrended.length - 2, Math.round(frameRate / 0.7));
    const ac = autocorr(detrended, Math.max(1, lagLo), Math.max(lagLo + 1, lagHi));
    const acPeak = ac.reduce((best, p) => (p.r > best.r ? p : best), { lag: 0, r: -1 });

    const bpm = +(peakBin * hzPerBin * 60).toFixed(1);
    const pulseDetected = snr > 4 && bandRatio > 0.25 && acPeak.r > 0.3;
    return {
      pulseDetected,
      bpmEstimate: pulseDetected ? bpm : null,
      snr: +snr.toFixed(2),
      bandPowerRatio: +bandRatio.toFixed(3),
      autocorrPeak: { lag: acPeak.lag, r: +acPeak.r.toFixed(3) },
      verdict: pulseDetected ? 'periodic-pulse-present' : 'no-pulse-signal',
      framesAnalyzed: signal.length,
      frameRate,
      method: 'FFT peak in 0.7–4Hz band + autocorrelation corroboration on detrended green-channel means',
    };
  }
}

// ── VoiceCloneDetector ───────────────────────────────────────────────────────
// TTS/clone artifacts measurable without a model: abnormally low spectral
// flux variance (over-regular prosody), high harmonicity with too-stable
// pitch, absence of natural breath/silence structure, sample-run repetition.

class VoiceCloneDetector {
  analyze(audioData, { sampleRate = 16000 } = {}) {
    if (!Array.isArray(audioData) && !ArrayBuffer.isView(audioData)) {
      return { error: 'audioData must be an array of PCM samples' };
    }
    if (audioData.length < 2048) return { error: 'need >= 2048 samples', samplesGiven: audioData.length };

    const frameLen = 512, hop = 256;
    const flatnesses = [], energies = [], pitches = [];
    let prevMags = null, fluxes = [];
    for (let start = 0; start + frameLen <= audioData.length && flatnesses.length < 400; start += hop) {
      const frame = Array.from({ length: frameLen }, (_, i) => Number(audioData[start + i]) || 0);
      const { mags } = magnitudeSpectrum(frame);
      flatnesses.push(spectralFlatness(mags, 1, mags.length));
      energies.push(frame.reduce((s, v) => s + v * v, 0) / frameLen);
      if (prevMags) {
        let flux = 0;
        for (let i = 0; i < mags.length; i++) flux += (mags[i] - prevMags[i]) ** 2;
        fluxes.push(Math.sqrt(flux));
      }
      prevMags = mags;
      // crude pitch via autocorrelation peak (60–400 Hz)
      const ac = autocorr(frame, Math.round(sampleRate / 400), Math.min(frameLen - 2, Math.round(sampleRate / 60)));
      const best = ac.reduce((b, p) => (p.r > b.r ? p : b), { lag: 0, r: -1 });
      if (best.r > 0.4) pitches.push(sampleRate / best.lag);
    }

    const eMean = mean(energies);
    const silenceRatio = energies.filter((e) => e < eMean * 0.05).length / energies.length;
    const fluxCv = fluxes.length ? Math.sqrt(variance(fluxes)) / (mean(fluxes) + 1e-9) : 0;
    const pitchCv = pitches.length > 4 ? Math.sqrt(variance(pitches)) / (mean(pitches) + 1e-9) : null;

    // Longest run of exactly-repeated samples (vocoder/looping artifact).
    let maxRun = 1, run = 1;
    for (let i = 1; i < Math.min(audioData.length, 200000); i++) {
      run = audioData[i] === audioData[i - 1] ? run + 1 : 1;
      if (run > maxRun) maxRun = run;
    }

    const indicators = [];
    let score = 0;
    if (fluxCv > 0 && fluxCv < 0.35) { score += 0.3; indicators.push({ indicator: 'over-regular-spectral-flux', value: +fluxCv.toFixed(3), note: 'frame-to-frame spectral change is unnaturally uniform' }); }
    if (pitchCv !== null && pitchCv < 0.02) { score += 0.3; indicators.push({ indicator: 'over-stable-pitch', value: +pitchCv.toFixed(4), note: 'pitch variation below natural human jitter' }); }
    if (silenceRatio < 0.02) { score += 0.2; indicators.push({ indicator: 'no-breath-pauses', value: +silenceRatio.toFixed(3), note: 'continuous energy with no natural silence structure' }); }
    if (maxRun > 64) { score += 0.2; indicators.push({ indicator: 'repeated-sample-runs', value: maxRun, note: 'long identical-sample runs — synthesis/looping artifact' }); }

    const cloneLikelihood = Math.min(1, score);
    return {
      cloneLikelihood: +cloneLikelihood.toFixed(3),
      verdict: cloneLikelihood >= 0.6 ? 'synthetic-artifacts-present' : cloneLikelihood >= 0.3 ? 'inconclusive' : 'no-synthesis-artifacts-found',
      features: {
        spectralFluxCv: +fluxCv.toFixed(4),
        pitchCv: pitchCv === null ? null : +pitchCv.toFixed(4),
        silenceRatio: +silenceRatio.toFixed(4),
        maxIdenticalRun: maxRun,
        framesAnalyzed: flatnesses.length,
        meanSpectralFlatness: +mean(flatnesses).toFixed(4),
      },
      indicators,
      method: 'frame-level DSP (spectral flux CV, pitch stability, silence structure, sample runs) — transparent heuristics, NOT a trained model',
    };
  }
}

// ── NeuralCodecDetector ──────────────────────────────────────────────────────
// Neural codecs (Encodec/SoundStream-class) leave a hard bandwidth ceiling
// and unnaturally flat/noisy content above it, plus strong frame-rate
// periodicity from the quantizer hop.

class NeuralCodecDetector {
  detect(audioData, { sampleRate = 16000 } = {}) {
    if (!Array.isArray(audioData) && !ArrayBuffer.isView(audioData)) {
      return { error: 'audioData must be an array of PCM samples' };
    }
    if (audioData.length < 4096) return { error: 'need >= 4096 samples', samplesGiven: audioData.length };

    const frame = Array.from({ length: 4096 }, (_, i) => Number(audioData[i]) || 0);
    const { mags, fftSize } = magnitudeSpectrum(frame);
    const hzPerBin = sampleRate / fftSize;

    // Bandwidth ceiling: highest bin whose power exceeds 1% of the peak.
    const peak = Math.max(...mags);
    let cutoffBin = mags.length - 1;
    for (let i = mags.length - 1; i > 0; i--) {
      if (mags[i] > peak * 0.01) { cutoffBin = i; break; }
    }
    const cutoffHz = cutoffBin * hzPerBin;
    const cutoffRatio = cutoffHz / (sampleRate / 2);

    // Sharpness of the rolloff around the cutoff (codecs cut hard; natural
    // audio and classical codecs roll off gradually).
    const before = mags.slice(Math.max(1, cutoffBin - 20), cutoffBin).reduce((s, v) => s + v, 0) / 20;
    const after = mags.slice(cutoffBin, Math.min(mags.length, cutoffBin + 20)).reduce((s, v) => s + v, 0) / 20;
    const rolloffSharpness = before / (after + 1e-9);

    // High-band flatness above the cutoff (quantization noise is flat).
    const highFlatness = cutoffBin < mags.length - 8 ? spectralFlatness(mags, cutoffBin, mags.length) : null;

    const indicators = [];
    let score = 0;
    if (cutoffRatio < 0.7) { score += 0.35; indicators.push({ indicator: 'bandwidth-ceiling', value: +cutoffHz.toFixed(0), note: `energy ends at ${cutoffHz.toFixed(0)}Hz of ${(sampleRate / 2).toFixed(0)}Hz available` }); }
    if (rolloffSharpness > 50) { score += 0.35; indicators.push({ indicator: 'hard-rolloff', value: +rolloffSharpness.toFixed(1), note: 'cliff-edge spectrum cut — codec resampling signature' }); }
    if (highFlatness !== null && highFlatness > 0.5) { score += 0.3; indicators.push({ indicator: 'flat-high-band', value: +highFlatness.toFixed(3), note: 'noise-like content above the ceiling — quantizer residue' }); }

    const codecLikelihood = Math.min(1, score);
    return {
      codecLikelihood: +codecLikelihood.toFixed(3),
      verdict: codecLikelihood >= 0.6 ? 'codec-artifacts-present' : codecLikelihood >= 0.3 ? 'inconclusive' : 'no-codec-artifacts-found',
      features: {
        cutoffHz: +cutoffHz.toFixed(1),
        cutoffRatio: +cutoffRatio.toFixed(3),
        rolloffSharpness: +rolloffSharpness.toFixed(2),
        highBandFlatness: highFlatness === null ? null : +highFlatness.toFixed(4),
      },
      indicators,
      method: 'FFT bandwidth-ceiling + rolloff sharpness + high-band flatness — transparent heuristics, NOT a trained model',
    };
  }
}

module.exports = { rPPGDetector, VoiceCloneDetector, NeuralCodecDetector, NeuralFingerprintAnalyzer };
