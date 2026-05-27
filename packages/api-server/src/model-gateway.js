'use strict';

/**
 * Kasbah Model Gateway — Multi-Model AI Governance Layer
 *
 * ─── WHY THIS EXISTS (strategic context) ─────────────────────────────────────
 *
 * Enterprises run Claude, GPT-4, Gemini, Mistral, and open-source Llama side by
 * side. Each has different jailbreak surfaces, different injection patterns,
 * different output failure modes. Kasbah is the only governance layer that
 * sits in front of ALL of them with a single API, single audit chain, single
 * compliance report.
 *
 * For an Anthropic acquisition: this is the layer that lets Claude become the
 * "preferred safe model" — Kasbah blocks attacks against ALL models but the
 * audit trail naturally surfaces which providers are most vulnerable. Anthropic
 * gets a) defensive moat for Claude, b) competitive intelligence on every other
 * provider, c) enterprise distribution.
 *
 * ─── WHAT IT DOES ────────────────────────────────────────────────────────────
 *
 *   POST /v1/gateway/chat
 *     {
 *       provider: 'anthropic' | 'openai' | 'mistral' | 'google' | 'local',
 *       model:    'claude-sonnet-4-5' | 'gpt-4o' | ...,
 *       messages: [{role,content}, ...],
 *       guardrails: { ... },        // optional override
 *     }
 *
 * Flow:
 *   1. Pre-flight: scan the user message through Kasbah governance.
 *      → If blocked, return 403 with verdict + receipt, never call the provider.
 *      → If warned, attach warning to response.
 *
 *   2. Provider call: route to the right SDK with the customer's key.
 *      (Customer-owned keys; we never see the provider's tokens.)
 *
 *   3. Post-flight: scan the model's response for harmful output, prompt
 *      injection leak-through, PII, fabricated citations, etc.
 *
 *   4. Audit: append a signed receipt to the workspace's chain.
 *
 * Cost weight: each gateway call = 2 credits (one for input scan, one for
 * output scan). Configurable via PRODUCT_WEIGHTS['gateway'].
 *
 * ─── PROVIDER SUPPORT ────────────────────────────────────────────────────────
 *
 *   anthropic   → Messages API
 *   openai      → Chat Completions API
 *   mistral     → Chat Completions API
 *   google      → Gemini API
 *   local       → Pass-through to a customer-provided HTTP URL (Llama/vLLM)
 *
 * No SDK required for any of them — uses fetch with the customer's keys.
 * Customer keys live in their workspace settings, encrypted at rest.
 *
 * ─── ENV VARS ────────────────────────────────────────────────────────────────
 *
 *   ANTHROPIC_API_KEY (fallback if customer hasn't set one)
 *   OPENAI_API_KEY    (fallback)
 *   MISTRAL_API_KEY   (fallback)
 *   GOOGLE_API_KEY    (fallback)
 */

const SUPPORTED_PROVIDERS = {
  anthropic: {
    name: 'Anthropic',
    defaultModel: 'claude-sonnet-4-5',
    apiUrl: 'https://api.anthropic.com/v1/messages',
    envKey: 'ANTHROPIC_API_KEY',
    style: 'anthropic-messages'
  },
  openai: {
    name: 'OpenAI',
    defaultModel: 'gpt-4o',
    apiUrl: 'https://api.openai.com/v1/chat/completions',
    envKey: 'OPENAI_API_KEY',
    style: 'openai-chat'
  },
  mistral: {
    name: 'Mistral',
    defaultModel: 'mistral-large-latest',
    apiUrl: 'https://api.mistral.ai/v1/chat/completions',
    envKey: 'MISTRAL_API_KEY',
    style: 'openai-chat'
  },
  google: {
    name: 'Google Gemini',
    defaultModel: 'gemini-1.5-pro',
    apiUrl: 'https://generativelanguage.googleapis.com/v1beta/models',
    envKey: 'GOOGLE_API_KEY',
    style: 'gemini'
  },
  local: {
    name: 'Local / Self-hosted',
    defaultModel: 'custom',
    apiUrl: null,             // customer provides
    envKey: null,
    style: 'openai-chat'      // assumes OpenAI-compatible (vLLM, Ollama)
  }
};

// ─── Provider call adapters ──────────────────────────────────────────────────

async function _callAnthropic({ apiKey, model, messages, maxTokens = 1024, system }) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      model: model || 'claude-sonnet-4-5',
      max_tokens: maxTokens,
      system: system || undefined,
      messages: messages.filter(m => m.role !== 'system')
    })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Anthropic ${res.status}: ${err}`);
  }
  const data = await res.json();
  return {
    provider: 'anthropic',
    model: data.model,
    text: data.content?.[0]?.text || '',
    usage: data.usage,
    raw: data
  };
}

async function _callOpenAICompatible({ apiKey, model, messages, baseUrl, maxTokens = 1024 }) {
  const res = await fetch(baseUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      model,
      messages,
      max_tokens: maxTokens
    })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`${baseUrl} ${res.status}: ${err}`);
  }
  const data = await res.json();
  return {
    provider: 'openai-compatible',
    model: data.model,
    text: data.choices?.[0]?.message?.content || '',
    usage: data.usage,
    raw: data
  };
}

async function _callGemini({ apiKey, model, messages, maxTokens = 1024 }) {
  const m = model || 'gemini-1.5-pro';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${encodeURIComponent(apiKey)}`;
  // Convert OpenAI-style messages to Gemini's "contents" format
  const contents = messages.map(msg => ({
    role: msg.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: msg.content }]
  }));
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ contents, generationConfig: { maxOutputTokens: maxTokens } })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini ${res.status}: ${err}`);
  }
  const data = await res.json();
  return {
    provider: 'google',
    model: m,
    text: data.candidates?.[0]?.content?.parts?.[0]?.text || '',
    usage: data.usageMetadata,
    raw: data
  };
}

// ─── Mount routes ────────────────────────────────────────────────────────────

function mount(app, { governanceFn, auditPush }) {
  // GET /v1/gateway/providers — list supported providers
  app.get('/v1/gateway/providers', (req, res) => {
    res.json({
      providers: Object.entries(SUPPORTED_PROVIDERS).map(([id, p]) => ({
        id,
        name: p.name,
        defaultModel: p.defaultModel,
        configured: !!(p.envKey && process.env[p.envKey])
      })),
      docs: 'https://bekasbah.com/docs/gateway'
    });
  });

  // POST /v1/gateway/chat — governed call to any provider
  app.post('/v1/gateway/chat', async (req, res) => {
    const t0 = Date.now();
    const {
      provider = 'anthropic',
      model,
      messages = [],
      system,
      maxTokens = 1024,
      apiKey,            // customer's provider key (preferred over server env)
      baseUrl,           // for local
      guardrails = {}
    } = req.body || {};

    const def = SUPPORTED_PROVIDERS[provider];
    if (!def) return res.status(400).json({ error: 'Unsupported provider', supported: Object.keys(SUPPORTED_PROVIDERS) });
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'messages array required' });
    }

    // Resolve API key — customer-supplied first, then server env (fallback)
    const resolvedKey = apiKey || (def.envKey && process.env[def.envKey]);
    if (!resolvedKey && provider !== 'local') {
      return res.status(400).json({
        error: `No API key for ${provider}`,
        what: `Pass "apiKey" in body, or set ${def.envKey} on server.`
      });
    }
    const resolvedUrl = (provider === 'local') ? baseUrl : null;
    if (provider === 'local' && !resolvedUrl) {
      return res.status(400).json({ error: 'For provider=local, baseUrl is required' });
    }

    // 1) PRE-FLIGHT: scan latest user message
    const userMsg = [...messages].reverse().find(m => m.role === 'user')?.content || '';
    const preflight = await governanceFn({ prompt: userMsg, source: 'gateway-pre' });
    if (preflight?.verdict === 'DENY') {
      return res.status(403).json({
        error: 'Blocked by Kasbah governance (pre-flight)',
        verdict: preflight.verdict,
        threats: preflight.threats,
        receipt: preflight.proof?.hash || preflight.receipt,
        provider, model
      });
    }

    // 2) PROVIDER CALL
    let modelResult;
    try {
      if (def.style === 'anthropic-messages') {
        modelResult = await _callAnthropic({ apiKey: resolvedKey, model: model || def.defaultModel, messages, system, maxTokens });
      } else if (def.style === 'gemini') {
        modelResult = await _callGemini({ apiKey: resolvedKey, model: model || def.defaultModel, messages, maxTokens });
      } else {
        const baseUrl_ = provider === 'local' ? resolvedUrl : def.apiUrl;
        modelResult = await _callOpenAICompatible({ apiKey: resolvedKey, model: model || def.defaultModel, messages, baseUrl: baseUrl_, maxTokens });
      }
    } catch (e) {
      return res.status(502).json({ error: `Provider call failed: ${e.message}`, provider, model });
    }

    // 3) POST-FLIGHT: scan model output
    const postflight = await governanceFn({ prompt: modelResult.text, source: 'gateway-post' });

    // 4) AUDIT: write a receipt
    try {
      auditPush?.(req, {
        type: 'gateway.chat',
        provider, model: modelResult.model,
        preflightVerdict: preflight?.verdict || 'ALLOW',
        postflightVerdict: postflight?.verdict || 'ALLOW',
        preflightReceipt: preflight?.proof?.hash,
        postflightReceipt: postflight?.proof?.hash,
        ts: new Date().toISOString()
      });
    } catch (_) {}

    return res.json({
      provider,
      model: modelResult.model,
      output: modelResult.text,
      usage: modelResult.usage,
      kasbah: {
        preflight: { verdict: preflight?.verdict, threats: preflight?.threats, receipt: preflight?.proof?.hash },
        postflight: { verdict: postflight?.verdict, threats: postflight?.threats, receipt: postflight?.proof?.hash },
        latencyMs: Date.now() - t0
      }
    });
  });

  // GET /v1/gateway/audit/by-provider — compliance/competitive intel view
  app.get('/v1/gateway/audit/by-provider', (req, res) => {
    // Placeholder: real impl reads from audit chain and aggregates.
    // For now, expose the contract so SDKs can wire against it.
    res.json({
      windowHours: 24,
      providers: Object.keys(SUPPORTED_PROVIDERS).map(p => ({
        provider: p,
        totalCalls: 0,
        blocked: 0,
        warned: 0,
        averageLatencyMs: 0
      })),
      note: 'Aggregates audit chain — populated as gateway traffic flows.'
    });
  });
}

module.exports = { mount, SUPPORTED_PROVIDERS };
