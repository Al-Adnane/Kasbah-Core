'use strict';

/**
 * Kasbah Model Catalog · 2026 Q2
 *
 * Every LLM provider Kasbah recognizes. Western, Chinese, open-source — all
 * in one table. Prices are per 1M tokens (USD), separated by input/output.
 * Context windows in tokens. Updated 2026-05; treat as floor — real prices
 * drop over time, real catalog grows.
 *
 * Usage:
 *   const { CATALOG, byProvider, byRegion, detect, priceFor } = require('./model-catalog');
 *   const m = detect({ url: 'https://api.deepseek.com/v1/chat/completions', body: { model: 'deepseek-v3' } });
 *   priceFor(m, 1500, 800)  // { input, output, total }
 */

const CATALOG = [
  // ─────────────────────────── WESTERN ───────────────────────────
  // OpenAI
  { id: 'gpt-4o',             provider: 'openai',      region: 'us', flag: '🇺🇸', country: 'United States', ctx: 128000, in:  2.50, out: 10.00, tier: 'flagship', class: 'general' },
  { id: 'gpt-4o-mini',        provider: 'openai',      region: 'us', flag: '🇺🇸', country: 'United States', ctx: 128000, in:  0.15, out:  0.60, tier: 'fast',     class: 'general' },
  { id: 'gpt-4.5-preview',    provider: 'openai',      region: 'us', flag: '🇺🇸', country: 'United States', ctx: 128000, in: 75.00, out:150.00, tier: 'flagship', class: 'general' },
  { id: 'gpt-4-turbo',        provider: 'openai',      region: 'us', flag: '🇺🇸', country: 'United States', ctx: 128000, in: 10.00, out: 30.00, tier: 'flagship', class: 'general' },
  { id: 'gpt-3.5-turbo',      provider: 'openai',      region: 'us', flag: '🇺🇸', country: 'United States', ctx:  16000, in:  0.50, out:  1.50, tier: 'fast',     class: 'general' },
  { id: 'o1',                 provider: 'openai',      region: 'us', flag: '🇺🇸', country: 'United States', ctx: 200000, in: 15.00, out: 60.00, tier: 'reasoning', class: 'reasoning' },
  { id: 'o1-mini',            provider: 'openai',      region: 'us', flag: '🇺🇸', country: 'United States', ctx: 128000, in:  3.00, out: 12.00, tier: 'reasoning', class: 'reasoning' },
  { id: 'o3-mini',            provider: 'openai',      region: 'us', flag: '🇺🇸', country: 'United States', ctx: 200000, in:  1.10, out:  4.40, tier: 'reasoning', class: 'reasoning' },

  // Anthropic
  { id: 'claude-opus-4.5',    provider: 'anthropic',   region: 'us', flag: '🇺🇸', country: 'United States', ctx: 200000, in: 15.00, out: 75.00, tier: 'flagship', class: 'general' },
  { id: 'claude-sonnet-4.5',  provider: 'anthropic',   region: 'us', flag: '🇺🇸', country: 'United States', ctx: 200000, in:  3.00, out: 15.00, tier: 'balanced', class: 'general' },
  { id: 'claude-haiku-4.5',   provider: 'anthropic',   region: 'us', flag: '🇺🇸', country: 'United States', ctx: 200000, in:  0.80, out:  4.00, tier: 'fast',     class: 'general' },
  { id: 'claude-3-5-sonnet',  provider: 'anthropic',   region: 'us', flag: '🇺🇸', country: 'United States', ctx: 200000, in:  3.00, out: 15.00, tier: 'balanced', class: 'general' },
  { id: 'claude-3-5-haiku',   provider: 'anthropic',   region: 'us', flag: '🇺🇸', country: 'United States', ctx: 200000, in:  0.80, out:  4.00, tier: 'fast',     class: 'general' },
  { id: 'claude-3-opus',      provider: 'anthropic',   region: 'us', flag: '🇺🇸', country: 'United States', ctx: 200000, in: 15.00, out: 75.00, tier: 'flagship', class: 'general' },

  // Google
  { id: 'gemini-2.0-flash',   provider: 'google',      region: 'us', flag: '🇺🇸', country: 'United States', ctx:1000000, in:  0.10, out:  0.40, tier: 'fast',     class: 'multimodal' },
  { id: 'gemini-1.5-pro',     provider: 'google',      region: 'us', flag: '🇺🇸', country: 'United States', ctx:2000000, in:  1.25, out:  5.00, tier: 'flagship', class: 'multimodal' },
  { id: 'gemini-1.5-flash',   provider: 'google',      region: 'us', flag: '🇺🇸', country: 'United States', ctx:1000000, in:  0.075,out:  0.30, tier: 'fast',     class: 'multimodal' },

  // Mistral (EU)
  { id: 'mistral-large',      provider: 'mistral',     region: 'eu', flag: '🇫🇷', country: 'France',        ctx: 128000, in:  2.00, out:  6.00, tier: 'flagship', class: 'general' },
  { id: 'mistral-medium',     provider: 'mistral',     region: 'eu', flag: '🇫🇷', country: 'France',        ctx:  32000, in:  0.40, out:  2.00, tier: 'balanced', class: 'general' },
  { id: 'codestral',          provider: 'mistral',     region: 'eu', flag: '🇫🇷', country: 'France',        ctx:  32000, in:  0.20, out:  0.60, tier: 'balanced', class: 'code' },

  // Cohere
  { id: 'command-r-plus',     provider: 'cohere',      region: 'ca', flag: '🇨🇦', country: 'Canada',        ctx: 128000, in:  2.50, out: 10.00, tier: 'flagship', class: 'general' },
  { id: 'command-r',          provider: 'cohere',      region: 'ca', flag: '🇨🇦', country: 'Canada',        ctx: 128000, in:  0.15, out:  0.60, tier: 'fast',     class: 'general' },

  // xAI
  { id: 'grok-2',             provider: 'xai',         region: 'us', flag: '🇺🇸', country: 'United States', ctx: 131000, in:  2.00, out: 10.00, tier: 'flagship', class: 'general' },
  { id: 'grok-3',             provider: 'xai',         region: 'us', flag: '🇺🇸', country: 'United States', ctx: 131000, in:  3.00, out: 15.00, tier: 'flagship', class: 'general' },

  // Perplexity
  { id: 'sonar',              provider: 'perplexity',  region: 'us', flag: '🇺🇸', country: 'United States', ctx: 127000, in:  1.00, out:  1.00, tier: 'balanced', class: 'search' },

  // ─────────────────────────── CHINESE ───────────────────────────
  // DeepSeek
  { id: 'deepseek-v3',        provider: 'deepseek',    region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  64000, in:  0.27, out:  1.10, tier: 'flagship', class: 'general',   note: 'open weights, 671B MoE' },
  { id: 'deepseek-r1',        provider: 'deepseek',    region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  64000, in:  0.55, out:  2.19, tier: 'reasoning',class: 'reasoning', note: 'o1-class, MIT license' },
  { id: 'deepseek-chat',      provider: 'deepseek',    region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  0.14, out:  0.28, tier: 'fast',     class: 'general' },
  { id: 'deepseek-coder',     provider: 'deepseek',    region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  16000, in:  0.14, out:  0.28, tier: 'fast',     class: 'code' },

  // Alibaba (Qwen)
  { id: 'qwen-max',           provider: 'alibaba',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  1.60, out:  6.40, tier: 'flagship', class: 'general' },
  { id: 'qwen-plus',          provider: 'alibaba',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 131000, in:  0.40, out:  1.20, tier: 'balanced', class: 'general' },
  { id: 'qwen-turbo',         provider: 'alibaba',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:1000000, in:  0.05, out:  0.20, tier: 'fast',     class: 'general' },
  { id: 'qwen3-max',          provider: 'alibaba',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 256000, in:  2.40, out:  9.60, tier: 'flagship', class: 'general' },
  { id: 'qwen3.5-plus',       provider: 'alibaba',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 131000, in:  0.80, out:  2.40, tier: 'balanced', class: 'general' },
  { id: 'qwen3-coder-plus',   provider: 'alibaba',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 131000, in:  0.30, out:  0.90, tier: 'balanced', class: 'code' },
  { id: 'qwen2.5-72b',        provider: 'alibaba',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 131000, in:  0.40, out:  1.20, tier: 'balanced', class: 'general',  note: 'open weights' },
  { id: 'qwen2.5-coder',      provider: 'alibaba',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  0.20, out:  0.60, tier: 'fast',     class: 'code',     note: 'open weights' },
  { id: 'qwen-vl-max',        provider: 'alibaba',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  3.00, out:  9.00, tier: 'flagship', class: 'multimodal' },

  // Moonshot (Kimi)
  { id: 'kimi-k2.5',          provider: 'moonshot',    region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 200000, in:  0.60, out:  2.50, tier: 'flagship', class: 'general' },
  { id: 'moonshot-v1-128k',   provider: 'moonshot',    region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 128000, in:  8.40, out:  8.40, tier: 'flagship', class: 'general' },
  { id: 'moonshot-v1-32k',    provider: 'moonshot',    region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  3.36, out:  3.36, tier: 'balanced', class: 'general' },
  { id: 'moonshot-v1-8k',     provider: 'moonshot',    region: 'cn', flag: '🇨🇳', country: 'China',         ctx:   8000, in:  1.68, out:  1.68, tier: 'fast',     class: 'general' },

  // Zhipu (GLM)
  { id: 'glm-5',              provider: 'zhipu',       region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 128000, in:  0.70, out:  2.00, tier: 'flagship', class: 'general' },
  { id: 'glm-4-plus',         provider: 'zhipu',       region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 128000, in:  7.00, out:  7.00, tier: 'flagship', class: 'general' },
  { id: 'glm-4-air',          provider: 'zhipu',       region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 128000, in:  0.14, out:  0.14, tier: 'balanced', class: 'general' },
  { id: 'glm-4-flash',        provider: 'zhipu',       region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 128000, in:  0.00, out:  0.00, tier: 'fast',     class: 'general', note: 'free tier' },
  { id: 'glm-4v',             provider: 'zhipu',       region: 'cn', flag: '🇨🇳', country: 'China',         ctx:   8000, in:  7.00, out:  7.00, tier: 'flagship', class: 'multimodal' },

  // 01.AI (Yi)
  { id: 'yi-large',           provider: '01ai',        region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  3.00, out:  3.00, tier: 'flagship', class: 'general' },
  { id: 'yi-medium',          provider: '01ai',        region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  16000, in:  0.42, out:  0.42, tier: 'balanced', class: 'general' },
  { id: 'yi-vision',          provider: '01ai',        region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  16000, in:  0.84, out:  0.84, tier: 'balanced', class: 'multimodal' },

  // Baidu (Ernie)
  { id: 'ernie-4.0',          provider: 'baidu',       region: 'cn', flag: '🇨🇳', country: 'China',         ctx:   8000, in: 17.00, out: 17.00, tier: 'flagship', class: 'general' },
  { id: 'ernie-3.5',          provider: 'baidu',       region: 'cn', flag: '🇨🇳', country: 'China',         ctx:   8000, in:  1.70, out:  1.70, tier: 'balanced', class: 'general' },
  { id: 'ernie-speed',        provider: 'baidu',       region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 128000, in:  0.00, out:  0.00, tier: 'fast',     class: 'general', note: 'free tier' },

  // ByteDance (Doubao)
  { id: 'doubao-pro-128k',    provider: 'bytedance',   region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 128000, in:  0.70, out:  1.40, tier: 'flagship', class: 'general' },
  { id: 'doubao-pro-32k',     provider: 'bytedance',   region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  0.11, out:  0.28, tier: 'balanced', class: 'general' },
  { id: 'doubao-lite',        provider: 'bytedance',   region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  0.04, out:  0.08, tier: 'fast',     class: 'general' },

  // Tencent (Hunyuan)
  { id: 'hunyuan-pro',        provider: 'tencent',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  4.20, out: 14.00, tier: 'flagship', class: 'general' },
  { id: 'hunyuan-standard',   provider: 'tencent',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 256000, in:  0.65, out:  2.00, tier: 'balanced', class: 'general' },
  { id: 'hunyuan-lite',       provider: 'tencent',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 256000, in:  0.00, out:  0.00, tier: 'fast',     class: 'general', note: 'free tier' },

  // MiniMax
  { id: 'minimax-m2.5',       provider: 'minimax',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 245000, in:  0.30, out:  1.20, tier: 'flagship', class: 'general' },
  { id: 'abab6.5',            provider: 'minimax',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 245000, in:  4.20, out:  4.20, tier: 'flagship', class: 'general' },
  { id: 'abab6.5s',           provider: 'minimax',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx: 245000, in:  1.40, out:  1.40, tier: 'balanced', class: 'general' },

  // iFlytek (Spark)
  { id: 'spark-3.5',          provider: 'iflytek',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:   8000, in:  4.50, out:  4.50, tier: 'flagship', class: 'general' },
  { id: 'spark-pro',          provider: 'iflytek',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:   8000, in:  2.10, out:  2.10, tier: 'balanced', class: 'general' },
  { id: 'spark-lite',         provider: 'iflytek',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:   4000, in:  0.00, out:  0.00, tier: 'fast',     class: 'general', note: 'free tier' },

  // StepFun
  { id: 'step-2',             provider: 'stepfun',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  5.60, out: 11.20, tier: 'flagship', class: 'general' },
  { id: 'step-1v',            provider: 'stepfun',     region: 'cn', flag: '🇨🇳', country: 'China',         ctx:  32000, in:  3.50, out:  7.00, tier: 'balanced', class: 'multimodal' },

  // ─────────────────────────── OPEN-SOURCE (free if self-hosted) ─────
  { id: 'llama-3.1-405b',     provider: 'meta',        region: 'us', flag: '🇺🇸', country: 'United States', ctx: 131000, in:  0.00, out:  0.00, tier: 'flagship', class: 'general', note: 'open weights' },
  { id: 'llama-3.1-70b',      provider: 'meta',        region: 'us', flag: '🇺🇸', country: 'United States', ctx: 131000, in:  0.00, out:  0.00, tier: 'balanced', class: 'general', note: 'open weights' },
  { id: 'llama-3.1-8b',       provider: 'meta',        region: 'us', flag: '🇺🇸', country: 'United States', ctx: 131000, in:  0.00, out:  0.00, tier: 'fast',     class: 'general', note: 'open weights' },
  { id: 'mixtral-8x22b',      provider: 'mistral',     region: 'eu', flag: '🇫🇷', country: 'France',        ctx:  65000, in:  0.00, out:  0.00, tier: 'flagship', class: 'general', note: 'open weights' },
  { id: 'phi-3-medium',       provider: 'microsoft',   region: 'us', flag: '🇺🇸', country: 'United States', ctx: 128000, in:  0.00, out:  0.00, tier: 'fast',     class: 'general', note: 'open weights' }
];

// ─── Indexes ────────────────────────────────────────────────────────────────
const byId       = new Map(CATALOG.map(m => [m.id, m]));
const byProvider = (() => { const m = {}; for (const x of CATALOG) (m[x.provider] = m[x.provider] || []).push(x); return m; })();
const byRegion   = (() => { const m = {}; for (const x of CATALOG) (m[x.region]   = m[x.region]   || []).push(x); return m; })();
const PROVIDERS  = Object.keys(byProvider).sort();
const REGIONS    = Object.keys(byRegion).sort();

// ─── Provider detection · URL + body hints ──────────────────────────────────
const URL_HINTS = [
  { rx: /api\.openai\.com/i,         provider: 'openai' },
  { rx: /api\.anthropic\.com/i,      provider: 'anthropic' },
  { rx: /generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com/i, provider: 'google' },
  { rx: /api\.mistral\.ai|codestral\.mistral\.ai/i, provider: 'mistral' },
  { rx: /api\.cohere\.com/i,         provider: 'cohere' },
  { rx: /api\.x\.ai/i,               provider: 'xai' },
  { rx: /api\.perplexity\.ai/i,      provider: 'perplexity' },
  { rx: /api\.deepseek\.com/i,       provider: 'deepseek' },
  { rx: /dashscope\.aliyuncs\.com|dashscope-intl\.aliyuncs\.com/i, provider: 'alibaba' },
  { rx: /api\.moonshot\.cn|api\.moonshot\.ai/i, provider: 'moonshot' },
  { rx: /open\.bigmodel\.cn/i,       provider: 'zhipu' },
  { rx: /api\.lingyiwanwu\.com|api\.01\.ai/i, provider: '01ai' },
  { rx: /aip\.baidubce\.com/i,       provider: 'baidu' },
  { rx: /ark\.cn-beijing\.volces\.com|ark\.volces\.com/i, provider: 'bytedance' },
  { rx: /hunyuan\.tencentcloudapi\.com|api\.hunyuan\.cloud\.tencent\.com/i, provider: 'tencent' },
  { rx: /api\.minimaxi\.chat|api\.minimax\.chat/i, provider: 'minimax' },
  { rx: /spark-api\.xf-yun\.com/i,   provider: 'iflytek' },
  { rx: /api\.stepfun\.com/i,        provider: 'stepfun' }
];
const MODEL_PREFIX_HINTS = [
  { rx: /^gpt|^o\d/i,                provider: 'openai' },
  { rx: /^claude/i,                  provider: 'anthropic' },
  { rx: /^gemini|^gemma/i,           provider: 'google' },
  { rx: /^mistral|^codestral|^mixtral|^pixtral/i, provider: 'mistral' },
  { rx: /^command/i,                 provider: 'cohere' },
  { rx: /^grok/i,                    provider: 'xai' },
  { rx: /^sonar|^pplx/i,             provider: 'perplexity' },
  { rx: /^deepseek/i,                provider: 'deepseek' },
  { rx: /^qwen/i,                    provider: 'alibaba' },
  { rx: /^kimi|^moonshot/i,          provider: 'moonshot' },
  { rx: /^glm/i,                     provider: 'zhipu' },
  { rx: /^yi-/i,                     provider: '01ai' },
  { rx: /^ernie/i,                   provider: 'baidu' },
  { rx: /^doubao/i,                  provider: 'bytedance' },
  { rx: /^hunyuan/i,                 provider: 'tencent' },
  { rx: /^abab|^minimax/i,           provider: 'minimax' },
  { rx: /^spark/i,                   provider: 'iflytek' },
  { rx: /^step-/i,                   provider: 'stepfun' },
  { rx: /^llama/i,                   provider: 'meta' },
  { rx: /^phi-/i,                    provider: 'microsoft' }
];

/**
 * Detect the model entry from a request (url, headers, body, or just a model id).
 * Returns the catalog entry, or a synthetic entry with provider=unknown if no match.
 */
function detect({ url, headers, body, model } = {}) {
  let id = model || body?.model || body?.model_name || headers?.['x-model'];
  if (typeof body === 'string') { try { const j = JSON.parse(body); id = id || j.model; } catch (_) {} }
  if (id && byId.has(id)) return byId.get(id);
  // Try by URL
  if (url) {
    for (const h of URL_HINTS) if (h.rx.test(url)) {
      const prov = byProvider[h.provider] || [];
      const cand = id ? prov.find(m => m.id === id || id.includes(m.id) || m.id.includes(id)) : prov[0];
      if (cand) return cand;
      if (id) return { id, provider: h.provider, region: prov[0]?.region || 'unknown', flag: prov[0]?.flag || '🌐', country: prov[0]?.country || 'Unknown', ctx: 0, in: 0, out: 0, tier: 'unknown', class: 'general', synthetic: true };
    }
  }
  // Try by model prefix
  if (id) for (const h of MODEL_PREFIX_HINTS) if (h.rx.test(id)) {
    const prov = byProvider[h.provider] || [];
    return prov.find(m => m.id === id) || { id, provider: h.provider, region: prov[0]?.region || 'unknown', flag: prov[0]?.flag || '🌐', country: prov[0]?.country || 'Unknown', ctx: 0, in: 0, out: 0, tier: 'unknown', class: 'general', synthetic: true };
  }
  return { id: id || 'unknown', provider: 'unknown', region: 'unknown', flag: '🌐', country: 'Unknown', ctx: 0, in: 0, out: 0, tier: 'unknown', class: 'general', synthetic: true };
}

/** Price for a request given token counts. Returns { input, output, total } in USD. */
function priceFor(model, promptTokens = 0, completionTokens = 0) {
  if (!model) return { input: 0, output: 0, total: 0 };
  const i = (promptTokens     / 1e6) * (model.in  || 0);
  const o = (completionTokens / 1e6) * (model.out || 0);
  return { input: i, output: o, total: i + o };
}

module.exports = { CATALOG, byId, byProvider, byRegion, PROVIDERS, REGIONS, detect, priceFor };
