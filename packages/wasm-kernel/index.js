'use strict';
let _detector = null;
let _available = false;

async function init() {
  try {
    const { WasmDetector } = require('./pkg/kasbah_wasm_kernel.js');
    _detector = new WasmDetector();
    _available = true;
    return true;
  } catch (e) {
    _available = false;
    return false;
  }
}

function isAvailable() { return _available; }

function detect(text) {
  if (!_available || !_detector) return null;
  try {
    return _detector.detect(text);
  } catch (e) {
    return null;
  }
}

function detectSecrets(text) {
  if (!_available || !_detector) return null;
  try {
    return _detector.detect_secrets(text);
  } catch (e) {
    return null;
  }
}

module.exports = { init, isAvailable, detect, detectSecrets };
