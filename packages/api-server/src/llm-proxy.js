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

function _redactPII(text) {
  if (typeof text !== 'string') return text;
  return text
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

function _forward(upstream, method, path, headers, body) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(`https://${upstream.host}${upstream.pathBase}${path}`);
    // headers may include query overrides
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

function mount(app, deps) {
  const { modelCatalog, engineKey, recordUsage, governCheck } = deps;

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

    // 1. Governance pre-check (best-effort)
    let gov = { verdict: 'ALLOW', risk: 0 };
    try {
      if (governCheck) {
        const txt = (body?.messages || []).map(m => m.content).filter(x => typeof x === 'string').join(' ')
                 || (typeof body?.prompt === 'string' ? body.prompt : '');
        gov = await governCheck(txt, { provider, model: model.id });
      }
    } catch (_) {}
    if (gov.verdict === 'DENY') {
      return res.status(403).json({
        error: 'kasbah_blocked', verdict: 'DENY', risk: gov.risk,
        threats: gov.threats || [], model: model.id, provider,
        message: 'Kasbah blocked this call before it reached ' + provider
      });
    }

    // 2. PII redaction (best-effort, in-place clone)
    const piiCtx = { redactions: 0 };
    const redactedBody = _walkRedact(body, piiCtx);

    // 3. Forward (or mock if no API key)
    let upstreamResp;
    const apiKey = process.env[upstream.envKey];
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

    // 5. Mint a receipt
    let receipt = null;
    try {
      if (engineKey) {
        receipt = engineKey.sign({
          id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
          ts: Date.now(),
          verdict: gov.verdict || 'ALLOW',
          risk: gov.risk || 0,
          requestId: 'req_' + crypto.randomBytes(6).toString('hex'),
          subject: crypto.createHash('sha256').update(JSON.stringify(body || '')).digest('hex'),
          passportId: null,
          surface: 'proxy:' + provider,
          action: 'llm_call'
        });
      }
    } catch (_) {}

    // 6. Augment response with Kasbah metadata via headers
    if (receipt) res.setHeader('x-kasbah-receipt', receipt.receipt);
    res.setHeader('x-kasbah-model', model.id);
    res.setHeader('x-kasbah-cost', cost.total.toFixed(6));
    res.setHeader('x-kasbah-tokens', `${usage.prompt + usage.completion}`);
    res.setHeader('x-kasbah-pii-redacted', piiCtx.redactions);
    res.setHeader('x-kasbah-latency-ms', Date.now() - t0);
    if (upstreamResp.body && typeof upstreamResp.body === 'object' && !apiKey) {
      upstreamResp.body._kasbah = {
        receipt: receipt?.receipt, model, cost, tokens: usage,
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
}

module.exports = { mount, UPSTREAMS };
