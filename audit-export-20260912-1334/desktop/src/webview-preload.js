'use strict';

/**
 * webview-preload.js — runs inside every page in the Kasbah Browser.
 *
 * Jobs:
 *   1. Fingerprint resistance (cheap): per-origin noise on canvas/audio/WebGL
 *      without reading/rewriting entire large canvases (that was the old
 *      multi-second lag on image-heavy sites).
 *   2. Password-field k-anonymity check (SHA-1 prefix only).
 */

const { ipcRenderer } = require('electron');

const FP_PROTECTION_ENABLED = process.argv.some((a) => a === '--kasbah-fp-protection=1');
const FP_MAX_PIXELS = 250000; // skip full-canvas work above ~0.25MP

function seedFor(origin) {
  let h = 2166136261 >>> 0;
  const s = origin + '|' + (globalThis.__kasbahSessionSalt || (globalThis.__kasbahSessionSalt = Math.random().toString(36)));
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function mulberry32(seed) {
  let a = seed;
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

(function protectFingerprinting() {
  if (!FP_PROTECTION_ENABLED) return;
  try {
    const origin = location.origin;
    const rng = mulberry32(seedFor(origin));

    // Only touch small buffers (typical fingerprint canvases). Large photos
    // skip noise — they were the source of multi-second getImageData lag.
    function noisyImageData(imageData) {
      const d = imageData.data;
      if (d.length > FP_MAX_PIXELS) return imageData;
      for (let i = 0; i < d.length; i += 16) {
        if (rng() < 0.15) {
          d[i] = Math.min(255, Math.max(0, d[i] + (rng() < 0.5 ? -1 : 1)));
        }
      }
      return imageData;
    }

    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (...args) {
      const result = origGetImageData.apply(this, args);
      return noisyImageData(result);
    };

    // Do NOT rewrite the live canvas on toDataURL (full read+write was the
    // hot path). toDataURL still benefits if the page used getImageData first.
    // Audio: very light sample
    if (window.AudioBuffer) {
      const origGetChannelData = AudioBuffer.prototype.getChannelData;
      AudioBuffer.prototype.getChannelData = function (...args) {
        const data = origGetChannelData.apply(this, args);
        if (data && data.length > 0 && data.length < 1e7) {
          data[0] += (rng() - 0.5) * 0.0001;
        }
        return data;
      };
    }

    // WebGL vendor spoof (cheap string returns)
    const spoofedVendor = ['Google Inc.', 'Intel Inc.', 'ATI Technologies Inc.', 'NVIDIA Corporation'][Math.floor(rng() * 4)];
    const spoofedRenderer = 'ANGLE (' + spoofedVendor + ', Generic Renderer, OpenGL 4.1)';
    for (const proto of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {
      if (!proto) continue;
      const origGetParameter = proto.prototype.getParameter;
      proto.prototype.getParameter = function (param) {
        if (param === 37445) return spoofedVendor;
        if (param === 37446) return spoofedRenderer;
        return origGetParameter.call(this, param);
      };
    }

    try {
      Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { get: () => 8, configurable: true });
      Object.defineProperty(Navigator.prototype, 'deviceMemory', { get: () => 8, configurable: true });
    } catch (_) {}
  } catch (_) {}
})();

async function sha1Hex(text) {
  const enc = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-1', enc);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

document.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('blur', async (e) => {
    const el = e.target;
    if (!el || el.tagName !== 'INPUT' || el.type !== 'password' || !el.value || el.value.length < 4) return;
    try {
      const hash = await sha1Hex(el.value);
      ipcRenderer.sendToHost('kasbah:password-check', { hash5: hash.slice(0, 5), hashSuffix: hash.slice(5) });
    } catch (_) {}
  }, true);
}, { once: true });

ipcRenderer.sendToHost('kasbah:webview-ready', { fingerprintProtection: FP_PROTECTION_ENABLED, origin: location.origin });
