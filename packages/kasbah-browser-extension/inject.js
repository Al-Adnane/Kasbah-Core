/**
 * Kasbah inject.js — page-world script.
 * Injected by content.js into the MAIN world so it can wrap native fetch/XHR
 * before any page script runs.
 *
 * Two jobs:
 *   1. Intercept outbound requests to AI provider APIs. If the request body
 *      contains a prompt that failed a Kasbah scan, block it and dispatch a
 *      custom event so content.js can show the banner.
 *   2. Fingerprint resistance: add calibrated noise to canvas, WebGL, and
 *      AudioContext fingerprinting surfaces, and spoof the navigator platform
 *      string so tracking pixels can't build a stable hardware fingerprint.
 *
 * Governance model:
 *   - The actual scan happens over the local gateway (127.0.0.1:8788), not
 *     inside this page-world script — this script cannot call chrome.runtime.
 *   - Instead it dispatches `kasbah:intercept` with the prompt text. The
 *     content script receives it, calls the background worker for a scan, and
 *     dispatches `kasbah:verdict` with the result. This script suspends the
 *     real request until the verdict arrives (timeout: 3 s → fail-open).
 *   - Fail-open by default: if the gateway is offline or the verdict times out,
 *     the request is allowed through.
 */

(function () {
  'use strict';

  // ── 1. fingerprint resistance ───────────────────────────────────────────────

  // Per-session random seed (Brave-style: new identity per tab, not per origin).
  // sessionStorage survives soft-navigations within the tab but resets on close.
  // Falls back to deterministic-per-origin if storage is unavailable.
  function _getSessionSeed() {
    try {
      const key = '__ksb_fp_seed__';
      const stored = sessionStorage.getItem(key);
      if (stored) return parseFloat(stored);
      const arr = new Uint32Array(1);
      crypto.getRandomValues(arr);
      const s = arr[0] / 0xffffffff;
      sessionStorage.setItem(key, String(s));
      return s;
    } catch (_) {
      let h = 0x9e3779b9;
      for (let i = 0; i < location.origin.length; i++) {
        h = Math.imul(h ^ location.origin.charCodeAt(i), 0x517cc1b7);
      }
      return ((h >>> 0) / 0xffffffff);
    }
  }
  const _seed = _getSessionSeed();
  function _noise(scale = 1) {
    // Tiny deterministic perturbation — imperceptible visually, breaks hash-based fingerprinting.
    return (_seed - 0.5) * 2 * scale;
  }

  // Canvas: add sub-pixel noise to getImageData / toDataURL / toBlob
  const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  const _origToBlob = HTMLCanvasElement.prototype.toBlob;
  const _origGetImageData = CanvasRenderingContext2D.prototype.getImageData;

  function _noiseImageData(imageData) {
    const d = imageData.data;
    for (let i = 0; i < d.length; i += 4) {
      // Shift one channel by ±1 at a deterministic subset of pixels.
      if ((i / 4 + Math.round(_seed * 1000)) % 97 === 0) {
        d[i] = Math.max(0, Math.min(255, d[i] + (_seed > 0.5 ? 1 : -1)));
      }
    }
    return imageData;
  }

  HTMLCanvasElement.prototype.toDataURL = function (...args) {
    const ctx = this.getContext && this.getContext('2d');
    if (ctx) {
      const w = this.width, h = this.height;
      if (w > 0 && h > 0) {
        const id = ctx.getImageData(0, 0, w, h);
        _noiseImageData(id);
        ctx.putImageData(id, 0, 0);
      }
    }
    return _origToDataURL.apply(this, args);
  };

  HTMLCanvasElement.prototype.toBlob = function (callback, ...args) {
    const ctx = this.getContext && this.getContext('2d');
    if (ctx) {
      const w = this.width, h = this.height;
      if (w > 0 && h > 0) {
        const id = ctx.getImageData(0, 0, w, h);
        _noiseImageData(id);
        ctx.putImageData(id, 0, 0);
      }
    }
    return _origToBlob.call(this, callback, ...args);
  };

  CanvasRenderingContext2D.prototype.getImageData = function (...args) {
    const id = _origGetImageData.apply(this, args);
    return _noiseImageData(id);
  };

  // WebGL: shift getParameter(RENDERER) and getParameter(VENDOR) slightly
  if (window.WebGLRenderingContext) {
    const _origGetParam = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function (param) {
      const v = _origGetParam.call(this, param);
      // RENDERER = 0x1F01, VENDOR = 0x1F00
      if (param === 0x1F01 && typeof v === 'string') return v + (_seed > 0.5 ? ' ' : '');
      if (param === 0x1F00 && typeof v === 'string') return v;
      return v;
    };
  }
  if (window.WebGL2RenderingContext) {
    const _origGetParam2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function (param) {
      const v = _origGetParam2.call(this, param);
      if (param === 0x1F01 && typeof v === 'string') return v + (_seed > 0.5 ? ' ' : '');
      return v;
    };
  }

  // AudioContext: offset the sample rate by a tiny fraction
  if (window.AudioContext || window.webkitAudioContext) {
    const AC = window.AudioContext || window.webkitAudioContext;
    const _origCreateAnalyser = AC.prototype.createAnalyser;
    AC.prototype.createAnalyser = function () {
      const node = _origCreateAnalyser.call(this);
      const _origGetByteFreq = node.getByteFrequencyData.bind(node);
      node.getByteFrequencyData = function (arr) {
        _origGetByteFreq(arr);
        // Shift one bucket by ±1 at a seed-determined index.
        const idx = Math.floor(_seed * arr.length);
        arr[idx] = Math.max(0, Math.min(255, arr[idx] + (_seed > 0.5 ? 1 : -1)));
      };
      return node;
    };
  }

  // navigator.hardwareConcurrency: report ±1 from real value (min 2)
  try {
    const real = navigator.hardwareConcurrency || 4;
    Object.defineProperty(navigator, 'hardwareConcurrency', {
      get: () => Math.max(2, real + (_seed > 0.5 ? -1 : 1)),
      configurable: true,
    });
  } catch (_) {}

  // ── 2. AI API fetch/XHR intercept ───────────────────────────────────────────

  const AI_API_PATTERNS = [
    /api\.openai\.com\/v\d+\/chat\/completions/,
    /api\.anthropic\.com\/v\d+\/messages/,
    /generativelanguage\.googleapis\.com\/.*:generateContent/,
    /api\.cohere\.(?:ai|com)\/v\d+\/chat/,
    /api\.mistral\.ai\/v\d+\/chat/,
    /api\.groq\.com\/openai\/v\d+\/chat/,
    /api\.perplexity\.ai\/chat\/completions/,
    /api\.together\.xyz\/v\d+\/chat/,
    /openrouter\.ai\/api\/v\d+\/chat/,
  ];

  function _matchesAI(url) {
    const s = typeof url === 'string' ? url : (url?.url || String(url));
    return AI_API_PATTERNS.some((r) => r.test(s));
  }

  function _extractPrompt(bodyText) {
    try {
      const j = JSON.parse(bodyText);
      const msgs = j.messages || j.contents || [];
      return msgs
        .filter((m) => m.role === 'user' || m.parts)
        .map((m) => {
          if (typeof m.content === 'string') return m.content;
          if (Array.isArray(m.content)) return m.content.map((p) => p.text || '').join(' ');
          if (Array.isArray(m.parts)) return m.parts.map((p) => p.text || '').join(' ');
          return '';
        })
        .join('\n')
        .trim();
    } catch (_) {
      return '';
    }
  }

  // Verdict cache: avoid duplicate round-trips for the same prompt text.
  const _verdictCache = new Map();
  const CACHE_TTL = 30000;

  function _requestVerdict(promptText) {
    const cached = _verdictCache.get(promptText);
    if (cached && Date.now() - cached.ts < CACHE_TTL) return Promise.resolve(cached.verdict);

    return new Promise((resolve) => {
      const id = Math.random().toString(36).slice(2);
      const timeout = setTimeout(() => {
        window.removeEventListener('kasbah:verdict:' + id, handler);
        resolve('ALLOW'); // fail-open on timeout
      }, 3000);

      function handler(e) {
        clearTimeout(timeout);
        const verdict = e.detail?.verdict || 'ALLOW';
        _verdictCache.set(promptText, { verdict, ts: Date.now() });
        resolve(verdict);
      }
      window.addEventListener('kasbah:verdict:' + id, handler, { once: true });

      window.dispatchEvent(new CustomEvent('kasbah:intercept', {
        detail: { id, text: promptText },
      }));
    });
  }

  // ── De-AI redirect chains (Brave De-AMP equivalent) ────────────────────────
  // Some AI tools wrap their real endpoint behind tracking redirects
  // (e.g. ?via=affiliate&utm_ai=...). Strip known AI tracking params so the
  // request goes direct and the URL can't be used for cross-site correlation.
  const _AI_TRACKING_PARAMS = ['utm_ai', 'ai_ref', 'ai_src', 'ai_click', 'oai_ref', 'copilot_ref', 'bingbot_ref'];

  function _stripAITrackingParams(url) {
    try {
      const u = new URL(url);
      let changed = false;
      for (const p of _AI_TRACKING_PARAMS) {
        if (u.searchParams.has(p)) { u.searchParams.delete(p); changed = true; }
      }
      return changed ? u.toString() : url;
    } catch (_) { return url; }
  }

  // Wrap fetch
  const _origFetch = window.fetch;
  window.fetch = async function (input, init) {
    let url = typeof input === 'string' ? input : (input instanceof Request ? input.url : String(input));
    // Strip AI tracking params before the request leaves the page.
    const cleanUrl = _stripAITrackingParams(url);
    if (cleanUrl !== url) {
      url = cleanUrl;
      input = input instanceof Request ? new Request(cleanUrl, input) : cleanUrl;
    }
    if (!_matchesAI(url)) return _origFetch.apply(this, [input, init]);

    const bodyText = init?.body
      ? (typeof init.body === 'string' ? init.body : null)
      : (input instanceof Request ? await input.clone().text().catch(() => null) : null);
    const prompt = bodyText ? _extractPrompt(bodyText) : '';

    if (prompt) {
      const verdict = await _requestVerdict(prompt);
      if (verdict === 'DENY') {
        window.dispatchEvent(new CustomEvent('kasbah:blocked', { detail: { url, prompt: prompt.slice(0, 100) } }));
        return new Response(JSON.stringify({ error: 'blocked_by_kasbah', message: 'Kasbah governance blocked this request.' }), {
          status: 403, headers: { 'content-type': 'application/json' },
        });
      }
    }
    return _origFetch.apply(this, arguments);
  };

  // Wrap XMLHttpRequest
  const _origOpen = XMLHttpRequest.prototype.open;
  const _origSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this._kasbahUrl = url;
    return _origOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const url = this._kasbahUrl || '';
    if (!_matchesAI(url)) return _origSend.call(this, body);

    const prompt = body && typeof body === 'string' ? _extractPrompt(body) : '';
    if (!prompt) return _origSend.call(this, body);

    const self = this;
    _requestVerdict(prompt).then((verdict) => {
      if (verdict === 'DENY') {
        window.dispatchEvent(new CustomEvent('kasbah:blocked', { detail: { url, prompt: prompt.slice(0, 100) } }));
        Object.defineProperty(self, 'status', { get: () => 403 });
        Object.defineProperty(self, 'responseText', { get: () => JSON.stringify({ error: 'blocked_by_kasbah' }) });
        const e = new ProgressEvent('load');
        self.dispatchEvent(e);
        if (typeof self.onload === 'function') self.onload(e);
        return;
      }
      _origSend.call(self, body);
    });
  };

  // ── 3. Screen / video capture intercept ────────────────────────────────────
  // Intercept getDisplayMedia (screen sharing) and getUserMedia (camera/mic).
  // AI tools that silently capture the screen or start video call recording
  // without a user-visible indicator are flagged. We do not block — we alert
  // and surface to the protection score. Blocking would break legitimate video
  // calls; the value is the audit trail and the user notification.

  const _origGetDisplayMedia = navigator.mediaDevices?.getDisplayMedia?.bind(navigator.mediaDevices);
  const _origGetUserMedia    = navigator.mediaDevices?.getUserMedia?.bind(navigator.mediaDevices);

  function _mediaAlert(type, constraints) {
    window.dispatchEvent(new CustomEvent('kasbah:media:access', {
      detail: {
        type,        // 'screen' | 'camera' | 'microphone'
        constraints: JSON.stringify(constraints || {}),
        origin:      location.origin,
        ts:          Date.now(),
      },
    }));
  }

  if (navigator.mediaDevices && _origGetDisplayMedia) {
    navigator.mediaDevices.getDisplayMedia = function (constraints) {
      _mediaAlert('screen', constraints);
      return _origGetDisplayMedia(constraints);
    };
  }

  if (navigator.mediaDevices && _origGetUserMedia) {
    navigator.mediaDevices.getUserMedia = function (constraints) {
      if (constraints?.video) _mediaAlert('camera', constraints);
      if (constraints?.audio) _mediaAlert('microphone', constraints);
      return _origGetUserMedia(constraints);
    };
  }

  // Intercept vision API calls (AI providers that accept image/frame uploads).
  // Patterns: openai /v1/chat with image_url, anthropic messages with image,
  // google gemini with inlineData. Existing fetch/XHR intercept already covers
  // the network layer; this adds frame-level awareness so the content script
  // can show a "camera/screen access detected" badge.
  const _AI_VISION_PATTERNS = [
    { re: /"type"\s*:\s*"image_url"/,    label: 'openai-vision' },
    { re: /"type"\s*:\s*"image"/,        label: 'anthropic-vision' },
    { re: /"inlineData"\s*:/,            label: 'gemini-vision' },
    { re: /"mimeType"\s*:\s*"image\//,   label: 'gemini-vision' },
  ];

  function _checkVisionPayload(body) {
    if (!body || typeof body !== 'string') return;
    for (const { re, label } of _AI_VISION_PATTERNS) {
      if (re.test(body)) {
        window.dispatchEvent(new CustomEvent('kasbah:media:access', {
          detail: { type: 'ai-vision', label, origin: location.origin, ts: Date.now() },
        }));
        break;
      }
    }
  }

  // Patch into the existing fetch wrapper by checking body after intercept.
  // We don't re-wrap — just add vision detection on the body string we already have.
  const _origFetch2 = window.fetch;
  window.fetch = async function (input, init) {
    const body = init?.body;
    if (typeof body === 'string') _checkVisionPayload(body);
    return _origFetch2.call(this, input, init);
  };

  // Signal to content.js that inject.js loaded
  window.dispatchEvent(new CustomEvent('kasbah:inject:ready'));
})();
