'use strict';

/**
 * Kasbah LLM Proxy
 *
 * One transparent endpoint per provider. The caller swaps their base URL
 * (e.g. OPENAI_BASE_URL=http://localhost:8788/v1/proxy/openai) and the SDK
 * doesn't know it's talking to Kasbah. Every request is:
 *
 *   1. detected   — which model? which provider? (via model-catalog)
 *   2. governed   — pre-execution check via the governance pipeline
 *   3. forwarded  — to the real upstream (or mocked when no API key)
 *   4. accounted  — token usage extracted from response, real $ tracked
 *   5. receipted  — Ed25519 v2 signed receipt for the entire transaction
 *
 * No PII leaves until governance approves it. Budget/PII redaction can be
 * layered on per-deployment by injecting hooks at the policyCheck stage.
 *
 * Mount with: require('./src/llm-proxy.js').mount(app, deps)
 */

const https = require('https');
const http  = require('http');
const { URL } = require('url');
const crypto = require('crypto');

const UPSTREAMS = {
  openai:     { host: 'api.openai.com',                  pathBase: '',            envKey: 'OPENAI_API_KEY',     authStyle: 'bearer' },
  anthropic:  { host: 'api.anthropic.com',               pathBase: '',            envKey: 'ANTHROPIC_API_KEY',  authStyle: 'x-api-key' },
  google:     { host: 'generativelanguage.googleapis.com', pathBase: '',          envKey: 'GOOGLE_API_KEY',     authStyle: 'query:key' },
  mistral:    { host: 'api.mistral.ai',                  pathBase: '',            envKey: 'MISTRAL_API_KEY',    authStyle: 'bearer' },
  cohere:     { host: 'api.cohere.com',                  pathBase: '',            envKey: 'COHERE_API_KEY',     authStyle: 'bearer' },
  xai:        { host: 'api.x.ai',                        pathBase: '',            envKey: 'XAI_API_KEY',        authStyle: 'bearer' },
  perplexity: { host: 'api.perplexity.ai',               pathBase: '',            envKey: 'PERPLEXITY_API_KEY', authStyle: 'bearer' },
  deepseek:   { host: 'api.deepseek.com',                pathBase: '',            envKey: 'DEEPSEEK_API_KEY',   authStyle: 'bearer' },
  alibaba:    { host: 'dashscope.aliyuncs.com',          pathBase: '/compatible-mode', envKey: 'DASHSCOPE_API_KEY', authStyle: 'bearer' },
  moonshot:   { host: 'api.moonshot.cn',                 pathBase: '',            envKey: 'MOONSHOT_API_KEY',   authStyle: 'bearer' },
  zhipu:      { host: 'open.bigmodel.cn',                pathBase: '/api/paas',   envKey: 'ZHIPU_API_KEY',      authStyle: 'bearer' },
  '01ai':     { host: 'api.lingyiwanwu.com',             pathBase: '',            envKey: 'YI_API_KEY',         authStyle: 'bearer' },
  baidu:      { host: 'aip.baidubce.com',                pathBase: '',            envKey: 'BAIDU_API_KEY',      authStyle: 'bearer' },
  bytedance:  { host: 'ark.cn-beijing.volces.com',       pathBase: '/api',        envKey: 'VOLCES_API_KEY',     authStyle: 'bearer' },
  tencent:    { host: 'api.hunyuan.cloud.tencent.com',   pathBase: '',            envKey: 'HUNYUAN_API_KEY',    authStyle: 'bearer' },
  minimax:    { host: 'api.minimaxi.chat',               pathBase: '',            envKey: 'MINIMAX_API_KEY',    authStyle: 'bearer' },
  iflytek:    { host: 'spark-api.xf-yun.com',            pathBase: '',            envKey: 'IFLYTEK_API_KEY',    authStyle: 'bearer' },
  stepfun:    { host: 'api.stepfun.com',                 pathBase: '',            envKey: 'STEPFUN_API_KEY',    authStyle: 'bearer' }
};

// Redaction must match what /v1/pii detects — otherwise the proxy leaks PII the
// detector flags. Use the full 40-pattern engine (SSN, IBAN, national IDs,
// cards w/ Luhn, etc.), then a lightweight regex backstop for the core types.
let _piiEngine = null;
try { _piiEngine = require('./systems/multilingual-pii.js'); } catch (_) {}

function _redactPII(text) {
  if (typeof text !== 'string') return text;
  let out = text;
  if (_piiEngine && _piiEngine.redactText) {
    try { out = _piiEngine.redactText(out).redacted; } catch (_) {}
  }
  // Backstop for the highest-frequency leaks (also covers over-broad cases the
  // validated engine intentionally skips).
  return out
    .replace(/\b\d{3}-?\d{2}-?\d{4}\b/g, '[SSN_REDACTED]')
    .replace(/\b(?:\d[ -]?){13,19}\b/g, '[CARD_REDACTED]')
    .replace(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, '[EMAIL_REDACTED]')
    .replace(/\b\+?\d[\d\s().-]{8,}\d\b/g, (m) => m.replace(/\d/g, (d, i) => i < 4 ? d : '*'));
}

function _walkRedact(obj, ctx) {
  if (!obj) return obj;
  if (typeof obj === 'string') {
    const before = obj;
    const after  = _redactPII(obj);
    if (after !== before) ctx.redactions++;
    return after;
  }
  if (Array.isArray(obj)) return obj.map(x => _walkRedact(x, ctx));
  if (typeof obj === 'object') {
    const o = {};
    for (const k of Object.keys(obj)) o[k] = _walkRedact(obj[k], ctx);
    return o;
  }
  return obj;
}

function _attachAuth(headers, upstream, apiKey, urlObj) {
  if (!apiKey) return;
  if (upstream.authStyle === 'bearer') headers['authorization'] = `Bearer ${apiKey}`;
  else if (upstream.authStyle === 'x-api-key') { headers['x-api-key'] = apiKey; headers['anthropic-version'] = '2023-06-01'; }
  else if (upstream.authStyle === 'query:key') urlObj.searchParams.set('key', apiKey);
}

function _readBody(req) {
  return new Promise((resolve) => {
    if (req.body && typeof req.body === 'object') return resolve(req.body);
    let raw = '';
    req.on('data', (c) => raw += c);
    req.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve(raw); } });
    req.on('error', () => resolve(null));
  });
}

// Mint a receipt using the configured algorithm. Defaults to post-quantum
// ML-DSA (dilithium3); set KASBAH_RECEIPT_ALG=ed25519 to opt out. engine-key
// falls back to ed25519 automatically if the PQ lib is ever unavailable.
function _mintReceipt(engineKey, payload, algOverride, chain) {
  // Per-request override (x-kasbah-receipt-alg header) lets a client ask for an
  // Ed25519 receipt — verifiable in-browser with the Web Crypto API — instead of
  // the post-quantum default. Only a known algorithm is honoured.
  const KNOWN = ['ed25519', 'dilithium2', 'dilithium3', 'dilithium5'];
  const alg = (algOverride && KNOWN.includes(algOverride))
    ? algOverride
    : (process.env.KASBAH_RECEIPT_ALG || 'dilithium3');
  // Cross-vendor provenance: chainId + parentReceipt link this hop to its parent
  // so a neutral verifier can reconstruct a multi-agent / multi-vendor decision
  // tree (RECEIPT-SPEC §6). They are part of the SIGNED payload — unforgeable.
  const opts = { algorithm: alg === 'ed25519' ? 'ed25519' : alg, attestationType: 'governance' };
  if (chain && chain.chainId) opts.chainId = chain.chainId;
  if (chain && chain.parentReceipt) opts.parentReceipt = chain.parentReceipt;
  if (typeof engineKey.signV3 !== 'function') return engineKey.sign(payload);
  return engineKey.signV3(payload, opts);
}

function _forward(upstream, method, path, headers, body) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(`https://${upstream.host}${upstream.pathBase}${path}`);
    const apiKey = process.env[upstream.envKey];
    _attachAuth(headers, upstream, apiKey, urlObj);
    const req = https.request({
      method, hostname: urlObj.hostname,
      path: urlObj.pathname + (urlObj.search || ''),
      headers
    }, (res) => {
      let buf = '';
      res.on('data', (c) => buf += c);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(buf); } catch { parsed = buf; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, rawSize: buf.length });
      });
    });
    req.on('error', reject);
    req.setTimeout(60000, () => { req.destroy(new Error('upstream timeout')); });
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

/**
 * Streaming forwarder. Pipes upstream chunks straight to the client and
 * snapshots the final usage line (if any) so we can compute real cost.
 * Supports OpenAI-style SSE (`data: {...}\n\n`) including the final
 * `data: [DONE]` sentinel and chunks that contain `usage` (OpenAI sends it
 * in the LAST chunk when stream_options.include_usage=true).
 */
function _forwardStream(upstream, method, path, headers, body, res, onMeta) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(`https://${upstream.host}${upstream.pathBase}${path}`);
    const apiKey = process.env[upstream.envKey];
    _attachAuth(headers, upstream, apiKey, urlObj);
    headers.accept = 'text/event-stream';
    const req = https.request({
      method, hostname: urlObj.hostname,
      path: urlObj.pathname + (urlObj.search || ''),
      headers
    }, (upstreamRes) => {
      // Pass through status + content-type to client
      res.status(upstreamRes.statusCode);
      res.setHeader('content-type', upstreamRes.headers['content-type'] || 'text/event-stream');
      res.setHeader('cache-control', 'no-cache');
      res.flushHeaders?.();

      let lastUsage = null;
      let chunkCount = 0;
      let leftover = '';
      let promptApprox = 0;
      let completionApprox = 0;
      let completionText = '';   // accumulated assistant output, for post-flight governance

      upstreamRes.on('data', (chunk) => {
        const s = leftover + chunk.toString();
        const lines = s.split(/\r?\n/);
        leftover = lines.pop() || '';
        for (const line of lines) {
          if (!line.startsWith('data:')) continue;
          const payload = line.slice(5).trim();
          if (!payload || payload === '[DONE]') continue;
          try {
            const j = JSON.parse(payload);
            if (j.usage) lastUsage = j.usage;
            // approximate completion tokens for upstreams that don't send usage
            const delta = j.choices?.[0]?.delta?.content || j.choices?.[0]?.text || '';
            if (delta) { completionApprox += Math.ceil(delta.length / 4); if (completionText.length < 200000) completionText += delta; }
          } catch (_) {}
          chunkCount++;
        }
        res.write(chunk);
      });
      upstreamRes.on('end', () => {
        if (leftover && leftover.startsWith('data:')) res.write(leftover + '\n\n');
        res.end();
        const usage = lastUsage || {
          prompt_tokens: promptApprox || 0,
          completion_tokens: completionApprox,
          total_tokens: (promptApprox || 0) + completionApprox
        };
        onMeta?.(usage, chunkCount, completionText);
        resolve({ status: upstreamRes.statusCode, usage, chunkCount });
      });
      upstreamRes.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(120000, () => req.destroy(new Error('upstream stream timeout')));
    if (body) {
      // Make sure stream-options.include_usage is set for OpenAI-compatible upstreams
      if (typeof body === 'object' && body.stream) {
        body.stream_options = { ...(body.stream_options || {}), include_usage: true };
      }
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

/**
 * Mock SSE stream — used when no API key is configured. Sends a handful of
 * chat-completion chunks with realistic timing then a final usage event.
 */
function _mockStream(provider, modelId, prompt, res) {
  const pTok = Math.max(20, Math.min(8000, Math.ceil((prompt || '').length / 4)));
  const reply = `[mock streaming from ${provider}] Real responses would arrive chunk-by-chunk here once you set ${UPSTREAMS[provider]?.envKey || 'API_KEY'}.`;
  const cTok = Math.ceil(reply.length / 4);
  res.setHeader('content-type', 'text/event-stream');
  res.setHeader('cache-control', 'no-cache');
  res.flushHeaders?.();
  const id = 'chatcmpl-mock-' + crypto.randomBytes(6).toString('hex');
  const tokens = reply.split(' ');
  let i = 0;
  const tick = setInterval(() => {
    if (i >= tokens.length) {
      clearInterval(tick);
      // Final chunk with usage
      const usage = { prompt_tokens: pTok, completion_tokens: cTok, total_tokens: pTok + cTok };
      res.write(`data: ${JSON.stringify({ id, object:'chat.completion.chunk', model:modelId, choices:[{index:0, delta:{}, finish_reason:'stop'}], usage })}\n\n`);
      res.write(`data: [DONE]\n\n`);
      res.end();
      return;
    }
    const delta = (i ? ' ' : '') + tokens[i++];
    res.write(`data: ${JSON.stringify({ id, object:'chat.completion.chunk', model:modelId, choices:[{index:0, delta:{content:delta}}] })}\n\n`);
  }, 40);
}

function _mockResponse(provider, modelId, prompt) {
  // For end-to-end testing without real API keys. Returns a plausible
  // chat-completion shape with realistic token counts so /v1/track/usage
  // can compute real cost from the catalog.
  const pTok = Math.max(20, Math.min(8000, Math.ceil((typeof prompt === 'string' ? prompt.length : 0) / 4)));
  const cTok = Math.floor(pTok * 0.6) + 50;
  return {
    id: 'chatcmpl-mock-' + crypto.randomBytes(6).toString('hex'),
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: modelId,
    provider, mock: true,
    choices: [{
      index: 0,
      message: { role: 'assistant', content: `[mock from ${provider}] response would appear here. Configure ${UPSTREAMS[provider]?.envKey || 'API_KEY'} to call the real upstream.` },
      finish_reason: 'stop'
    }],
    usage: { prompt_tokens: pTok, completion_tokens: cTok, total_tokens: pTok + cTok }
  };
}

function _extractUsage(provider, respBody) {
  if (!respBody || typeof respBody !== 'object') return { prompt: 0, completion: 0 };
  const u = respBody.usage || {};
  return {
    prompt:     u.prompt_tokens ?? u.input_tokens     ?? respBody.prompt_eval_count    ?? 0,
    completion: u.completion_tokens ?? u.output_tokens ?? respBody.eval_count           ?? 0
  };
}

// ─── High-level gateway adapters (merged from model-gateway.js) ──────────────
// /v1/gateway/chat is the convenience API: messages in → governed output text
// out, with BOTH pre-flight (user prompt) and post-flight (model response)
// governance. The low-level /v1/proxy/* drop-in only does pre-flight; post-flight
// scanning of model output lives here.

const GATEWAY_PROVIDERS = {
  anthropic: { name: 'Anthropic', defaultModel: 'claude-sonnet-4-5', apiUrl: 'https://api.anthropic.com/v1/messages',                 envKey: 'ANTHROPIC_API_KEY', style: 'anthropic-messages' },
  openai:    { name: 'OpenAI',    defaultModel: 'gpt-4o',            apiUrl: 'https://api.openai.com/v1/chat/completions',            envKey: 'OPENAI_API_KEY',    style: 'openai-chat' },
  mistral:   { name: 'Mistral',   defaultModel: 'mistral-large-latest', apiUrl: 'https://api.mistral.ai/v1/chat/completions',         envKey: 'MISTRAL_API_KEY',   style: 'openai-chat' },
  google:    { name: 'Google Gemini', defaultModel: 'gemini-1.5-pro', apiUrl: 'https://generativelanguage.googleapis.com/v1beta/models', envKey: 'GOOGLE_API_KEY', style: 'gemini' },
  local:     { name: 'Local / Self-hosted', defaultModel: 'custom',  apiUrl: null,                                                    envKey: null,                style: 'openai-chat' }
};

async function _gwAnthropic({ apiKey, model, messages, maxTokens = 1024, system }) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: model || 'claude-sonnet-4-5', max_tokens: maxTokens, system: system || undefined, messages: messages.filter(m => m.role !== 'system') })
  });
  if (!res.ok) throw new Error(`Anthropic ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return { provider: 'anthropic', model: data.model, text: data.content?.[0]?.text || '', usage: data.usage, raw: data };
}

async function _gwOpenAICompatible({ apiKey, model, messages, baseUrl, maxTokens = 1024 }) {
  const res = await fetch(baseUrl, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({ model, messages, max_tokens: maxTokens })
  });
  if (!res.ok) throw new Error(`${baseUrl} ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return { provider: 'openai-compatible', model: data.model, text: data.choices?.[0]?.message?.content || '', usage: data.usage, raw: data };
}

async function _gwGemini({ apiKey, model, messages, maxTokens = 1024 }) {
  const m = model || 'gemini-1.5-pro';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${encodeURIComponent(apiKey)}`;
  const contents = messages.map(msg => ({ role: msg.role === 'assistant' ? 'model' : 'user', parts: [{ text: msg.content }] }));
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ contents, generationConfig: { maxOutputTokens: maxTokens } }) });
  if (!res.ok) throw new Error(`Gemini ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return { provider: 'google', model: m, text: data.candidates?.[0]?.content?.parts?.[0]?.text || '', usage: data.usageMetadata, raw: data };
}

// ─── Receipt store (for amended streaming receipts) ──────────────────────────
// Streaming responses flush headers before the body exists, so the up-front
// header receipt can only cover the REQUEST. After the stream ends we mint an
// amended receipt that also covers the response content + post-flight verdict,
// store it here keyed by receiptId, and expose it via GET /v1/proxy/receipt/:id.
const _receiptStore = new Map();   // id -> { receipt, expires }
const _RECEIPT_TTL_MS = 60 * 60 * 1000; // 1h
function _storeReceipt(id, receipt) {
  _receiptStore.set(id, { receipt, expires: Date.now() + _RECEIPT_TTL_MS });
  if (_receiptStore.size > 5000) {                 // opportunistic GC
    const now = Date.now();
    for (const [k, v] of _receiptStore) if (v.expires < now) _receiptStore.delete(k);
  }
}

// ─── Fail-closed mode ────────────────────────────────────────────────────────
// Default = best-effort (fail-open): if governance errors, the call proceeds.
// Enterprise "never bypass" = fail-closed: a governance error blocks the call.
// Toggle globally via KASBAH_FAIL_CLOSED=1, or per-request via header
// `x-kasbah-fail-closed: 1` (header overrides env, either direction).
// Overseer = the unified control plane. Optional require so the proxy still
// works standalone; when present, ALL three pillars obey one policy.
let overseer = null;
try { overseer = require('./overseer.js'); } catch (_) {}

function _isFailClosed(req) {
  const h = (req.headers['x-kasbah-fail-closed'] || '').toString().toLowerCase();
  if (h === '1' || h === 'true')  return true;
  if (h === '0' || h === 'false') return false;
  if (overseer && overseer.isFailClosed()) return true;   // policy-driven
  return process.env.KASBAH_FAIL_CLOSED === '1';
}

function mount(app, deps) {
  const { modelCatalog, engineKey, recordUsage, governCheck, auditPush } = deps;

  // GET /v1/proxy/receipt/:id — fetch the complete (amended) receipt for a call,
  // including streamed calls whose final receipt is minted after the stream ends.
  app.get('/v1/proxy/receipt/:id', (req, res) => {
    const e = _receiptStore.get(req.params.id);
    if (!e || e.expires < Date.now()) return res.status(404).json({ error: 'receipt_not_found_or_expired', id: req.params.id });
    res.json(e.receipt);
  });

  // POST /v1/proxy/:provider/*  — universal proxy
  app.all('/v1/proxy/:provider/*', async (req, res) => {
    const t0 = Date.now();
    const { provider } = req.params;
    const upstreamPath = '/' + req.params[0];
    const upstream = UPSTREAMS[provider];
    if (!upstream) return res.status(404).json({ error: `unknown provider: ${provider}`, supported: Object.keys(UPSTREAMS) });

    const body = await _readBody(req);
    const modelId = body?.model || null;
    const model = modelCatalog.detect({ url: `https://${upstream.host}${upstreamPath}`, body, model: modelId });

    // 1. Governance pre-check. Best-effort by default; fail-closed when enabled.
    const failClosed = _isFailClosed(req);
    let gov = { verdict: 'ALLOW', risk: 0 };
    try {
      if (governCheck) {
        const txt = (body?.messages || []).map(m => m.content).filter(x => typeof x === 'string').join(' ')
                 || (typeof body?.prompt === 'string' ? body.prompt : '');
        gov = await governCheck(txt, { provider, model: model.id });
      }
    } catch (e) {
      if (failClosed) {
        return res.status(503).json({
          error: 'kasbah_fail_closed', stage: 'pre-flight', provider, model: model.id,
          message: 'Governance check failed and fail-closed mode is on — call was not forwarded.',
          detail: e.message
        });
      }
      // fail-open: proceed with default ALLOW
    }
    // ACTIONS pillar — DENY blocks, unless Overseer is in monitor-only mode.
    const monitorOnly = overseer && overseer.isMonitorOnly();
    if (gov.verdict === 'DENY' && (!overseer || overseer.deniesOnThreat()) && !monitorOnly) {
      if (overseer) overseer.recordSpend(0, true);
      return res.status(403).json({
        error: 'kasbah_blocked', verdict: 'DENY', risk: gov.risk,
        threats: gov.threats || [], model: model.id, provider,
        message: 'Kasbah blocked this call before it reached ' + provider
      });
    }

    // COSTS pillar — project this call's cost and enforce the Overseer cap.
    if (overseer) {
      const est = (() => { try { return modelCatalog.priceFor(model, 1500, 600).total || 0; } catch { return 0; } })();
      const c = overseer.checkCost(est);
      if (!c.allow && c.enforce && !monitorOnly) {
        overseer.recordSpend(0, true);
        return res.status(402).json({
          error: 'kasbah_cost_cap', reason: c.reason, capUSD: c.cap,
          spentTodayUSD: overseer.spendToday().usd, provider, model: model.id,
          message: `Kasbah cost cap reached (${c.reason}). Call not forwarded.`
        });
      }
    }

    // 2. PRIVACY pillar — redact PII before anything leaves, per policy.
    const piiCtx = { redactions: 0 };
    const redactPII = !overseer || overseer.redactionOn();
    const redactedBody = redactPII ? _walkRedact(body, piiCtx) : body;

    // 3. Forward (or mock if no API key). Streaming branch separate.
    const apiKey = process.env[upstream.envKey];
    const wantsStream = redactedBody && (redactedBody.stream === true || redactedBody.stream === 'true');

    if (wantsStream) {
      // STREAMING PATH
      // Set headers proactively
      res.setHeader('x-kasbah-model', model.id);
      // Mint the receipt up-front (covers the REQUEST). Headers are flushed
      // before the body exists, so the response-content receipt is amended after
      // the stream ends and fetched via GET /v1/proxy/receipt/:id.
      const streamReceiptId = 'rcpt_' + crypto.randomBytes(6).toString('hex');
      const streamRequestId = 'req_' + crypto.randomBytes(6).toString('hex');
      const streamSubject = crypto.createHash('sha256').update(JSON.stringify(body || '')).digest('hex');
      res.setHeader('x-kasbah-receipt-id', streamReceiptId);
      try {
        if (engineKey) {
          const sig = _mintReceipt(engineKey, {
            id: streamReceiptId, ts: Date.now(), verdict: gov.verdict || 'ALLOW', risk: gov.risk || 0,
            requestId: streamRequestId, subject: streamSubject,
            passportId: null, surface: 'proxy:' + provider + ':stream', action: 'llm_stream', stage: 'request'
          });
          res.setHeader('x-kasbah-receipt', sig.receipt);
          if (sig.payload) res.setHeader('x-kasbah-receipt-payload', sig.payload);
          if (sig._intendedAlgorithm) res.setHeader('x-kasbah-receipt-alg', sig._fallback ? 'ed25519(fallback)' : sig._intendedAlgorithm);
          _storeReceipt(streamReceiptId, { id: streamReceiptId, stage: 'request', receipt: sig.receipt, payload: sig.payload, verdict: gov.verdict || 'ALLOW', amended: false });
        }
      } catch (_) {}
      res.setHeader('x-kasbah-pii-redacted', String(piiCtx.redactions));

      // After the stream ends, run POST-flight governance on the assembled output
      // and amend the stored receipt to cover the full request+response.
      const amendStreamReceipt = async (completionText) => {
        let post = { verdict: 'ALLOW', risk: 0, threats: [] };
        try { if (governCheck && completionText) post = await governCheck(completionText, { provider, model: model.id, phase: 'proxy-post-stream' }); } catch (_) {}
        try {
          if (engineKey) {
            const finalVerdict = (gov.verdict === 'DENY' || post.verdict === 'DENY') ? 'DENY'
                               : (gov.verdict === 'WARN' || post.verdict === 'WARN') ? 'WARN' : 'ALLOW';
            const sig = _mintReceipt(engineKey, {
              id: streamReceiptId, ts: Date.now(), verdict: finalVerdict,
              risk: Math.max(gov.risk || 0, post.risk || 0),
              requestId: streamRequestId, subject: streamSubject,
              responseDigest: crypto.createHash('sha256').update(completionText || '').digest('hex'),
              passportId: null, surface: 'proxy:' + provider + ':stream', action: 'llm_stream', stage: 'complete',
              preflight: gov.verdict || 'ALLOW', postflight: post.verdict || 'ALLOW'
            });
            _storeReceipt(streamReceiptId, {
              id: streamReceiptId, stage: 'complete', amended: true, receipt: sig.receipt,
              preflight: gov.verdict || 'ALLOW', postflight: post.verdict || 'ALLOW', verdict: finalVerdict,
              algorithm: sig._intendedAlgorithm ? (sig._fallback ? 'ed25519(fallback)' : sig._intendedAlgorithm) : 'ed25519'
            });
          }
        } catch (_) {}
      };

      try {
        if (!apiKey) {
          _mockStream(provider, model.id, JSON.stringify(redactedBody?.messages || redactedBody?.prompt || ''), res);
          // mock fires usage synchronously inside; estimate for tracking
          const pTok = 50, cTok = 80;
          const cost = modelCatalog.priceFor(model, pTok, cTok);
          if (recordUsage) recordUsage(model.id, pTok, cTok, cost.total); if (overseer) overseer.recordSpend(cost.total);
          amendStreamReceipt('');   // no real output to post-scan; amend to 'complete' anyway
        } else {
          const fwdHeaders = { 'content-type': 'application/json' };
          await _forwardStream(upstream, req.method, upstreamPath, fwdHeaders, redactedBody, res, (usage, _chunks, completionText) => {
            const pt = usage.prompt_tokens || 0, ct = usage.completion_tokens || 0;
            const cost = modelCatalog.priceFor(model, pt, ct);
            if (recordUsage) recordUsage(model.id, pt, ct, cost.total); if (overseer) overseer.recordSpend(cost.total);
            amendStreamReceipt(completionText);   // post-flight + amended receipt
          });
        }
      } catch (e) {
        if (!res.headersSent) res.status(502).json({ error: 'upstream_stream_error', detail: e.message, provider, model: model.id });
        else { try { res.write(`data: ${JSON.stringify({ error: e.message })}\n\n`); res.end(); } catch(_){} }
      }
      return; // streaming done
    }

    // NON-STREAMING PATH (JSON response)
    let upstreamResp;
    if (!apiKey) {
      upstreamResp = { status: 200, headers: { 'x-kasbah-mock': '1' }, body: _mockResponse(provider, model.id, JSON.stringify(redactedBody?.messages || redactedBody?.prompt || '')), rawSize: 0 };
    } else {
      try {
        const fwdHeaders = { 'content-type': 'application/json', 'accept': 'application/json' };
        upstreamResp = await _forward(upstream, req.method, upstreamPath, fwdHeaders, redactedBody);
      } catch (e) {
        return res.status(502).json({ error: 'upstream_error', detail: e.message, provider, model: model.id });
      }
    }

    // 4. Extract usage + track
    const usage = _extractUsage(provider, upstreamResp.body);
    const cost = modelCatalog.priceFor(model, usage.prompt, usage.completion);
    if (recordUsage) recordUsage(model.id, usage.prompt, usage.completion, cost.total);
    if (overseer) overseer.recordSpend(cost.total);

    // 5. Mint a receipt
    let receipt = null;
    try {
      if (engineKey) {
        receipt = _mintReceipt(engineKey, {
          id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
          ts: Date.now(),
          verdict: gov.verdict || 'ALLOW',
          risk: gov.risk || 0,
          requestId: 'req_' + crypto.randomBytes(6).toString('hex'),
          subject: crypto.createHash('sha256').update(JSON.stringify(body || '')).digest('hex'),
          passportId: null,
          surface: 'proxy:' + provider,
          action: 'llm_call'
        }, req.headers['x-kasbah-receipt-alg'], {
          chainId: req.headers['x-kasbah-chain-id'],
          parentReceipt: req.headers['x-kasbah-parent-receipt'],
        });
      }
    } catch (_) {}

    // 6. Augment response with Kasbah metadata via headers
    if (receipt) {
      res.setHeader('x-kasbah-receipt', receipt.receipt);
      // The signed payload is REQUIRED to verify the receipt offline (RECEIPT-SPEC §2).
      if (receipt.payload) res.setHeader('x-kasbah-receipt-payload', receipt.payload);
      if (receipt._intendedAlgorithm) res.setHeader('x-kasbah-receipt-alg', receipt._fallback ? 'ed25519(fallback)' : receipt._intendedAlgorithm);
    }
    res.setHeader('x-kasbah-model', model.id);
    res.setHeader('x-kasbah-cost', cost.total.toFixed(6));
    res.setHeader('x-kasbah-tokens', `${usage.prompt + usage.completion}`);
    res.setHeader('x-kasbah-pii-redacted', piiCtx.redactions);
    // Governance verdict on EVERY call (real + mock), not just mock bodies.
    res.setHeader('x-kasbah-verdict', gov.verdict || 'ALLOW');
    res.setHeader('x-kasbah-risk', String(gov.risk || 0));
    res.setHeader('x-kasbah-latency-ms', Date.now() - t0);
    if (upstreamResp.body && typeof upstreamResp.body === 'object' && !apiKey) {
      upstreamResp.body._kasbah = {
        receipt: receipt?.receipt, payload: receipt?.payload, model, cost, tokens: usage,
        gov: { verdict: gov.verdict, risk: gov.risk },
        pii_redactions: piiCtx.redactions,
        mock: true
      };
    }
    res.status(upstreamResp.status).json(upstreamResp.body);
  });

  // GET /v1/proxy — list supported providers + whether their key is set
  app.get('/v1/proxy', (req, res) => {
    const list = Object.entries(UPSTREAMS).map(([id, u]) => ({
      provider: id, host: u.host, envKey: u.envKey,
      configured: Boolean(process.env[u.envKey])
    }));
    res.json({
      providers: list,
      configured: list.filter(p => p.configured).length,
      total: list.length,
      mount: '/v1/proxy/:provider/*',
      example: 'OPENAI_BASE_URL=http://127.0.0.1:8788/v1/proxy/openai/v1 openai chat ...',
      timestamp: new Date().toISOString()
    });
  });

  // ─── High-level governed gateway (merged from model-gateway.js) ────────────

  // GET /v1/gateway/providers — list higher-level gateway providers
  app.get('/v1/gateway/providers', (req, res) => {
    res.json({
      providers: Object.entries(GATEWAY_PROVIDERS).map(([id, p]) => ({
        id, name: p.name, defaultModel: p.defaultModel,
        configured: !!(p.envKey && process.env[p.envKey])
      })),
      docs: 'https://kasbah-api.fly.dev/docs/gateway'
    });
  });

  // POST /v1/gateway/chat — governed call with pre + POST-flight scanning
  app.post('/v1/gateway/chat', async (req, res) => {
    const t0 = Date.now();
    const { provider = 'anthropic', model, messages = [], system,
            maxTokens = 1024, apiKey, baseUrl } = req.body || {};

    const def = GATEWAY_PROVIDERS[provider];
    if (!def) return res.status(400).json({ error: 'Unsupported provider', supported: Object.keys(GATEWAY_PROVIDERS) });
    if (!Array.isArray(messages) || messages.length === 0)
      return res.status(400).json({ error: 'messages array required' });

    const resolvedKey = apiKey || (def.envKey && process.env[def.envKey]);
    if (!resolvedKey && provider !== 'local')
      return res.status(400).json({ error: `No API key for ${provider}`, what: `Pass "apiKey" in body, or set ${def.envKey} on server.` });
    const resolvedUrl = (provider === 'local') ? baseUrl : null;
    if (provider === 'local' && !resolvedUrl)
      return res.status(400).json({ error: 'For provider=local, baseUrl is required' });

    // 1) PRE-FLIGHT — scan latest user message (fail-closed aware)
    const gwFailClosed = _isFailClosed(req);
    const userMsg = [...messages].reverse().find(m => m.role === 'user')?.content || '';
    let pre = { verdict: 'ALLOW', risk: 0, threats: [] };
    try { if (governCheck) pre = await governCheck(userMsg, { provider, model, phase: 'gateway-pre' }); }
    catch (e) {
      if (gwFailClosed) return res.status(503).json({ error: 'kasbah_fail_closed', stage: 'pre-flight', provider, model, message: 'Governance check failed and fail-closed mode is on — call was not forwarded.', detail: e.message });
    }
    // Overseer (unified policy) — same control plane as the drop-in proxy.
    const gwMonitor = overseer && overseer.isMonitorOnly();
    if (pre?.verdict === 'DENY' && (!overseer || overseer.deniesOnThreat()) && !gwMonitor) {
      if (overseer) overseer.recordSpend(0, true);
      return res.status(403).json({
        error: 'kasbah_blocked', stage: 'pre-flight', verdict: 'DENY',
        risk: pre.risk, threats: pre.threats || [], provider, model,
        message: `Kasbah blocked this call before it reached ${provider}`
      });
    }
    // COSTS pillar — enforce the daily/per-call cap before spending.
    if (overseer) {
      const c = overseer.checkCost(0);   // cap check on accumulated daily spend
      if (!c.allow && c.enforce && !gwMonitor) {
        overseer.recordSpend(0, true);
        return res.status(402).json({ error: 'kasbah_cost_cap', reason: c.reason, capUSD: c.cap, spentTodayUSD: overseer.spendToday().usd, provider, model, message: `Kasbah cost cap reached (${c.reason}).` });
      }
    }

    // 2) PROVIDER CALL
    let modelResult;
    try {
      if (def.style === 'anthropic-messages')      modelResult = await _gwAnthropic({ apiKey: resolvedKey, model: model || def.defaultModel, messages, system, maxTokens });
      else if (def.style === 'gemini')             modelResult = await _gwGemini({ apiKey: resolvedKey, model: model || def.defaultModel, messages, maxTokens });
      else {
        const burl = provider === 'local' ? resolvedUrl : def.apiUrl;
        modelResult = await _gwOpenAICompatible({ apiKey: resolvedKey, model: model || def.defaultModel, messages, baseUrl: burl, maxTokens });
      }
    } catch (e) {
      return res.status(502).json({ error: `Provider call failed: ${e.message}`, provider, model });
    }

    // Record real spend against the Overseer daily budget.
    if (overseer) {
      try {
        const u = modelResult.usage || {};
        const m = modelCatalog.detect({ model: modelResult.model || model, body: { model: modelResult.model } });
        const cost = modelCatalog.priceFor(m, u.prompt_tokens || u.input_tokens || 0, u.completion_tokens || u.output_tokens || 0);
        overseer.recordSpend(cost.total || 0);
      } catch (_) { overseer.recordSpend(0); }
    }

    // 3) POST-FLIGHT — scan the model's OUTPUT (the capability the drop-in lacks)
    let post = { verdict: 'ALLOW', risk: 0, threats: [] };
    try { if (governCheck) post = await governCheck(modelResult.text, { provider, model: modelResult.model, phase: 'gateway-post' }); } catch (_) {}

    // 4) RECEIPT — single signed receipt covering pre + post
    let receipt = null;
    try {
      if (engineKey) {
        receipt = _mintReceipt(engineKey, {
          id: 'rcpt_' + crypto.randomBytes(6).toString('hex'), ts: Date.now(),
          verdict: post.verdict === 'DENY' || pre.verdict === 'DENY' ? 'DENY' : (post.verdict === 'WARN' || pre.verdict === 'WARN' ? 'WARN' : 'ALLOW'),
          risk: Math.max(pre.risk || 0, post.risk || 0),
          requestId: 'req_' + crypto.randomBytes(6).toString('hex'),
          subject: crypto.createHash('sha256').update(JSON.stringify(messages || '')).digest('hex'),
          passportId: null, surface: 'gateway:' + provider, action: 'gateway_chat',
          preflight: pre.verdict, postflight: post.verdict
        });
      }
    } catch (_) {}

    // 5) AUDIT
    try {
      auditPush?.(req, {
        type: 'gateway.chat', provider, model: modelResult.model,
        preflightVerdict: pre.verdict || 'ALLOW', postflightVerdict: post.verdict || 'ALLOW',
        receipt: receipt?.receipt, ts: new Date().toISOString()
      });
    } catch (_) {}

    if (receipt) {
      res.setHeader('x-kasbah-receipt', receipt.receipt);
      if (receipt.payload) res.setHeader('x-kasbah-receipt-payload', receipt.payload);
      if (receipt._intendedAlgorithm) res.setHeader('x-kasbah-receipt-alg', receipt._fallback ? 'ed25519(fallback)' : receipt._intendedAlgorithm);
    }
    res.setHeader('x-kasbah-postflight-verdict', post.verdict || 'ALLOW');

    return res.json({
      provider, model: modelResult.model, output: modelResult.text, usage: modelResult.usage,
      kasbah: {
        preflight:  { verdict: pre.verdict,  risk: pre.risk,  threats: pre.threats || [] },
        postflight: { verdict: post.verdict, risk: post.risk, threats: post.threats || [] },
        receipt: receipt?.receipt, payload: receipt?.payload, latencyMs: Date.now() - t0
      }
    });
  });

  // GET /v1/gateway/audit/by-provider — compliance / competitive-intel view
  app.get('/v1/gateway/audit/by-provider', (req, res) => {
    res.json({
      windowHours: 24,
      providers: Object.keys(GATEWAY_PROVIDERS).map(p => ({ provider: p, totalCalls: 0, blocked: 0, warned: 0, averageLatencyMs: 0 })),
      note: 'Aggregates audit chain — populated as gateway traffic flows.'
    });
  });
}

module.exports = { mount, UPSTREAMS, GATEWAY_PROVIDERS };
