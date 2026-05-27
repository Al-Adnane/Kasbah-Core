'use strict';

/**
 * KasbahOS Zero-Config Auto-Instrumentation
 *
 * Patches the Node.js module loader to intercept OpenAI and Anthropic SDK
 * calls BEFORE the application code runs. Governance is applied automatically
 * without any code changes to the host application.
 *
 * Usage (zero code changes required):
 *   node --require @kasbah/sdk/src/auto-instrument app.js
 *   # or via environment:
 *   NODE_OPTIONS="--require @kasbah/sdk/src/auto-instrument" node app.js
 *
 * Environment variables:
 *   KASBAH_API_KEY     — required
 *   KASBAH_API_URL     — optional, defaults to https://api.bekasbah.com
 *   KASBAH_PASSPORT_ID — optional, passport for this process
 *   KASBAH_AUTO_BLOCK  — 'true' to throw on DENY (default: warn only)
 *   KASBAH_SILENT      — 'true' to suppress instrumentation logs
 */

const Module  = require('module');
const crypto  = require('crypto');

const API_KEY    = process.env.KASBAH_API_KEY;
const API_URL    = (process.env.KASBAH_API_URL || 'https://api.bekasbah.com').replace(/\/$/, '');
const PASSPORT   = process.env.KASBAH_PASSPORT_ID || null;
const AUTO_BLOCK = process.env.KASBAH_AUTO_BLOCK === 'true';
const SILENT     = process.env.KASBAH_SILENT === 'true';

if (!API_KEY) {
  if (!SILENT) process.stderr.write('[kasbah] KASBAH_API_KEY not set — auto-instrumentation disabled\n');
  module.exports = {};
  return;
}

if (!SILENT) process.stderr.write('[kasbah] Auto-instrumentation active — all AI calls governed\n');

// ── Govern helper (sync-style via native http — no deps) ────────────────────

const http  = require('http');
const https = require('https');

function govern(prompt, meta = {}) {
  return new Promise((resolve) => {
    const body = JSON.stringify({
      prompt:     String(prompt).slice(0, 4000),
      passportId: PASSPORT,
      agent:      meta.model || 'auto-instrumented',
      ...meta,
    });

    const url    = new URL(`${API_URL}/v1/govern`);
    const lib    = url.protocol === 'https:' ? https : http;
    const req    = lib.request({
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     '/v1/govern',
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        'x-api-key':      API_KEY,
        'x-kasbah-sdk':   'auto-instrument/1.0',
      },
      timeout: 5000,
    }, res => {
      let raw = '';
      res.on('data', d => { raw += d; });
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { resolve({ verdict: 'ALLOW', riskScore: 0 }); }
      });
    });

    req.on('error', () => resolve({ verdict: 'ALLOW', riskScore: 0 }));
    req.on('timeout', () => { req.destroy(); resolve({ verdict: 'ALLOW', riskScore: 0 }); });
    req.write(body);
    req.end();
  });
}

// ── Module loader patch ──────────────────────────────────────────────────────

const _originalLoad = Module._load;
const _patched      = new WeakSet(); // prevent double-patching

Module._load = function kasbahLoad(request, parent, isMain) {
  const mod = _originalLoad.apply(this, arguments);

  // Patch OpenAI SDK
  if ((request === 'openai' || request.endsWith('/openai')) && mod && !_patched.has(mod)) {
    _patched.add(mod);
    _patchOpenAI(mod);
  }

  // Patch Anthropic SDK
  if ((request === '@anthropic-ai/sdk' || request.endsWith('/@anthropic-ai/sdk')) && mod && !_patched.has(mod)) {
    _patched.add(mod);
    _patchAnthropic(mod);
  }

  return mod;
};

// ── OpenAI patcher ───────────────────────────────────────────────────────────

function _patchOpenAI(openaiModule) {
  const OrigClass = openaiModule.default || openaiModule.OpenAI || openaiModule;
  if (!OrigClass || typeof OrigClass !== 'function') return;

  const OrigProto = OrigClass.prototype;
  if (!OrigProto || _patched.has(OrigProto)) return;
  _patched.add(OrigProto);

  // Intercept chat.completions.create
  function patchChatCompletions(client) {
    if (!client?.chat?.completions?.create) return;
    const orig = client.chat.completions.create.bind(client.chat.completions);
    client.chat.completions.create = async function(params, options) {
      const userMsg = (params?.messages || []).filter(m => m.role === 'user').map(m =>
        typeof m.content === 'string' ? m.content : JSON.stringify(m.content)
      ).join('\n');

      if (userMsg) {
        const result = await govern(userMsg, { model: params?.model || 'openai' });
        if (!SILENT) process.stderr.write(`[kasbah] OpenAI call governed: ${result.verdict} (risk: ${result.riskScore})\n`);
        if (result.verdict === 'DENY' && AUTO_BLOCK) {
          throw new Error(`[KasbahOS] Request blocked: ${(result.threats || []).join(', ') || 'policy violation'}`);
        }
        // Attach receipt to the request for traceability
        if (options) options.headers = { ...(options.headers || {}), 'x-kasbah-receipt': result.receipt || '' };
      }

      return orig(params, options);
    };
  }

  // Patch constructor to intercept after instance creation
  const WrappedClass = new Proxy(OrigClass, {
    construct(Target, args) {
      const instance = new Target(...args);
      patchChatCompletions(instance);
      return instance;
    }
  });

  if (openaiModule.default) openaiModule.default = WrappedClass;
  if (openaiModule.OpenAI) openaiModule.OpenAI = WrappedClass;

  if (!SILENT) process.stderr.write('[kasbah] OpenAI SDK patched — chat.completions.create governed\n');
}

// ── Anthropic patcher ────────────────────────────────────────────────────────

function _patchAnthropic(anthropicModule) {
  const OrigClass = anthropicModule.default || anthropicModule.Anthropic || anthropicModule;
  if (!OrigClass || typeof OrigClass !== 'function') return;

  const OrigProto = OrigClass.prototype;
  if (!OrigProto || _patched.has(OrigProto)) return;
  _patched.add(OrigProto);

  function patchMessages(client) {
    if (!client?.messages?.create) return;
    const orig = client.messages.create.bind(client.messages);
    client.messages.create = async function(params, options) {
      const userMsg = (params?.messages || []).filter(m => m.role === 'user').map(m =>
        typeof m.content === 'string' ? m.content : JSON.stringify(m.content)
      ).join('\n');

      if (userMsg) {
        const result = await govern(userMsg, { model: params?.model || 'anthropic' });
        if (!SILENT) process.stderr.write(`[kasbah] Anthropic call governed: ${result.verdict} (risk: ${result.riskScore})\n`);
        if (result.verdict === 'DENY' && AUTO_BLOCK) {
          throw new Error(`[KasbahOS] Request blocked: ${(result.threats || []).join(', ') || 'policy violation'}`);
        }
      }
      return orig(params, options);
    };
  }

  const WrappedClass = new Proxy(OrigClass, {
    construct(Target, args) {
      const instance = new Target(...args);
      patchMessages(instance);
      return instance;
    }
  });

  if (anthropicModule.default) anthropicModule.default = WrappedClass;
  if (anthropicModule.Anthropic) anthropicModule.Anthropic = WrappedClass;

  if (!SILENT) process.stderr.write('[kasbah] Anthropic SDK patched — messages.create governed\n');
}

module.exports = { govern };
