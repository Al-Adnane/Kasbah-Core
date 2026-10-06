'use strict';

/**
 * Local biometric forensics — loads packages/biometric-detection when present
 * (rPPG, voice-clone, neural-codec DSP). Honest unavailable if not packaged.
 */

const fs = require('fs');
const path = require('path');

function resolveBiometricDir() {
  const { app } = (() => { try { return require('electron'); } catch (_) { return {}; } })();
  const candidates = [
    process.resourcesPath ? path.join(process.resourcesPath, 'packages', 'biometric-detection') : null,
    path.join(__dirname, '..', '..', 'biometric-detection'),
    path.join(__dirname, '../../../packages/biometric-detection'),
    app && app.getAppPath ? path.join(app.getAppPath(), '../packages/biometric-detection') : null,
  ].filter(Boolean);
  for (const dir of candidates) {
    try { if (fs.existsSync(path.join(dir, 'src', 'index.js'))) return dir; } catch (_) {}
  }
  return null;
}

let _mod;
function load() {
  if (_mod !== undefined) return _mod;
  const dir = resolveBiometricDir();
  if (!dir) { _mod = null; return _mod; }
  try { _mod = { dir, ...require(path.join(dir, 'src', 'index.js')) }; }
  catch (e) { _mod = { dir, error: e.message }; }
  return _mod;
}

function status() {
  const m = load();
  return {
    available: !!(m && !m.error && (m.rPPGDetector || m.detectRPPG || m.NeuralFingerprintAnalyzer || typeof m === 'object')),
    dir: m?.dir || null,
    error: m?.error || null,
    exports: m ? Object.keys(m).filter((k) => k !== 'dir' && k !== 'error').slice(0, 12) : [],
  };
}

function rppg(videoFrames, frameRate = 30) {
  const m = load();
  if (!m || m.error) return { ok: false, available: false, error: m?.error || 'biometric-detection package not installed' };
  try {
    if (typeof m.rPPGDetector === 'function') {
      const d = new m.rPPGDetector();
      return { ok: true, available: true, ...d.detect(videoFrames, frameRate), method: 'rPPG-FFT-autocorr' };
    }
    if (typeof m.detectRPPG === 'function') {
      return { ok: true, available: true, ...m.detectRPPG(videoFrames, frameRate) };
    }
    // Fallback: package exports a detector object
    if (m.default && typeof m.default.detect === 'function') {
      return { ok: true, available: true, ...m.default.detect(videoFrames, frameRate) };
    }
    return { ok: false, available: true, error: 'no rPPG export in package', exports: Object.keys(m).slice(0, 16) };
  } catch (e) {
    return { ok: false, available: true, error: e.message };
  }
}

function neuralFingerprint(samples, opts = {}) {
  const m = load();
  if (!m || m.error) return { ok: false, available: false, error: m?.error || 'biometric-detection package not installed' };
  try {
    if (m.NeuralFingerprintAnalyzer) {
      const a = new m.NeuralFingerprintAnalyzer();
      return { ok: true, available: true, ...a.analyze(samples, opts) };
    }
    return { ok: false, available: true, error: 'NeuralFingerprintAnalyzer not exported' };
  } catch (e) { return { ok: false, available: true, error: e.message }; }
}

function voiceClone(samples, opts = {}) {
  const m = load();
  if (!m || m.error) return { ok: false, available: false, error: m?.error || 'biometric-detection package not installed' };
  try {
    if (m.VoiceCloneDetector) {
      const d = new m.VoiceCloneDetector();
      return { ok: true, available: true, ...d.detect(samples, opts) };
    }
    return { ok: false, available: true, error: 'VoiceCloneDetector not exported' };
  } catch (e) { return { ok: false, available: true, error: e.message }; }
}

function neuralCodec(samples, opts = {}) {
  const m = load();
  if (!m || m.error) return { ok: false, available: false, error: m?.error || 'biometric-detection package not installed' };
  try {
    if (m.NeuralCodecDetector) {
      const d = new m.NeuralCodecDetector();
      return { ok: true, available: true, ...d.detect(samples, opts) };
    }
    return { ok: false, available: true, error: 'NeuralCodecDetector not exported' };
  } catch (e) { return { ok: false, available: true, error: e.message }; }
}

module.exports = { status, rppg, neuralFingerprint, voiceClone, neuralCodec, resolveBiometricDir };
