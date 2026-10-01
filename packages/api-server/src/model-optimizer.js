'use strict';

/**
 * model-optimizer.js — Smart Model Routing + Cost Optimization
 *
 * Analyzes incoming prompts and routes them to the cheapest model that can
 * handle the task, with tiered fallback. Plugs into the LLM proxy.
 *
 * Strategy:
 *   Tier 0 (trivial):    "hello", "thanks"                    → flash / haiku
 *   Tier 1 (simple):     factual QA, translation               → mini / haiku
 *   Tier 2 (moderate):   code gen, analysis                    → standard
 *   Tier 3 (complex):    multi-step reasoning, long context    → pro / opus
 *   Tier 4 (vision):     image inputs                          → vision-capable
 *
 * Also provides:
 *   - suggestCheaper(prompt, currentModel) → cheaper alternatives with savings
 *   - autoRoute(prompt, preferredProvider) → best model for the task
 *   - Savings tracker: total saved via routing decisions
 */

const modelCatalog = require('./model-catalog.js');

// ─── Tier classification ────────────────────────────────────────────────────

const TIER_PATTERNS = {
  trivial: [
    { pattern: /^(hi|hello|hey|thanks|thank you|ok|okay|yes|no|bye|goodbye)[.!]*$/i, weight: 1.0 },
    { pattern: /^what('s| is) your name\??$/i, weight: 0.9 },
    { pattern: /^.{1,15}$/, weight: 0.7 },
  ],
  vision: [
    { pattern: /image|picture|photo|screenshot|diagram|chart|graph|visual/i, weight: 0.7 },
    { pattern: /describe (this|the) (image|picture|photo)/i, weight: 0.9 },
  ],
  complex: [
    { pattern: /.{2000,}/, weight: 0.8 },  // long prompts
    { pattern: /step by step|reason|analyze|evaluate|compare|contrast|critique|review|assess/i, weight: 0.6 },
    { pattern: /code review|refactor|optimize|debug|trace|explain why/i, weight: 0.5 },
    { pattern: /\b(implement|design|architecture|system|pipeline|workflow|orchestrat)\b/i, weight: 0.5 },
  ],
  moderate: [
    { pattern: /\b(code|function|class|method|api|endpoint|route|query|sql)\b/i, weight: 0.7 },
    { pattern: /\b(calculate|compute|convert|format|parse|extract|filter|sort|group)\b/i, weight: 0.6 },
    { pattern: /.{500,1999}/, weight: 0.4 },
  ],
};

function classifyTier(prompt) {
  if (!prompt) return 'simple';
  const scores = { trivial: 0, vision: 0, complex: 0, moderate: 0 };
  for (const [tier, patterns] of Object.entries(TIER_PATTERNS)) {
    for (const { pattern, weight } of patterns) {
      if (pattern.test(prompt)) scores[tier] = Math.max(scores[tier], weight);
    }
  }
  if (scores.vision > 0.5) return 'vision';
  if (scores.trivial > 0.6) return 'trivial';
  if (scores.complex > 0.4) return 'complex';
  if (scores.moderate > 0.4) return 'moderate';
  return 'simple';
}

// ─── Model tier mapping ─────────────────────────────────────────────────────

const TIER_MODELS = {
  trivial:  ['gpt-4o-mini', 'claude-haiku', 'gemini-flash', 'deepseek-chat', 'qwen-turbo'],
  simple:   ['gpt-4o-mini', 'claude-haiku', 'gemini-flash', 'deepseek-chat', 'qwen-plus'],
  moderate: ['gpt-4o', 'claude-sonnet', 'gemini-pro', 'deepseek-chat', 'qwen-max'],
  complex:  ['gpt-4o', 'claude-sonnet', 'claude-opus', 'gemini-pro', 'deepseek-reasoner'],
  vision:   ['gpt-4o', 'claude-sonnet', 'gemini-pro-vision'],
};

// ─── Savings tracker ─────────────────────────────────────────────────────────

const _savings = {
  totalRoutes: 0,
  totalSaved: 0,       // USD
  byProvider: {},      // provider → { routes, saved }
  history: [],         // last 100 decisions
};

// Record ONLY realized savings from actual traffic. savedPerMillion is the
// (in+out) price delta per 1M tokens; realized dollars = delta * tokens / 1e6.
// A routing *suggestion* (tokens=0) saved no real money and must not inflate
// the ledger — "we saved you $Z" has to be money that actually moved.
function recordSavings(originalModel, chosenModel, tokens, savedPerMillion) {
  _savings.totalRoutes++;
  const realizedUsd = tokens > 0 ? (savedPerMillion / 1e6) * tokens : 0;
  _savings.totalSaved += realizedUsd;
  const prov = chosenModel?.provider || 'unknown';
  if (!_savings.byProvider[prov]) _savings.byProvider[prov] = { routes: 0, saved: 0 };
  _savings.byProvider[prov].routes++;
  _savings.byProvider[prov].saved += realizedUsd;
  _savings.history.unshift({
    ts: Date.now(),
    original: originalModel?.id,
    chosen: chosenModel?.id,
    tokens,
    saved: +realizedUsd.toFixed(6),
  });
  if (_savings.history.length > 100) _savings.history.length = 100;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Suggest cheaper alternatives for a given model + prompt.
 * @returns {{ current, alternatives: [{ model, savingsPer1K, savingsPct }] }}
 */
function suggestCheaper(prompt, currentModelId) {
  const tier = classifyTier(prompt);
  const candidates = TIER_MODELS[tier] || TIER_MODELS.simple;
  const current = modelCatalog.byId.get(currentModelId) || modelCatalog.detect({ model: currentModelId });
  if (!current) return { tier, current: { id: currentModelId }, alternatives: [] };

  const currentPrice = (current.in || 0) + (current.out || 0);
  const alternatives = [];

  for (const candidateId of candidates) {
    if (candidateId === current.id) continue;
    const cand = modelCatalog.byId.get(candidateId) || modelCatalog.detect({ model: candidateId });
    if (!cand) continue;
    const candPrice = (cand.in || 0) + (cand.out || 0);
    if (candPrice < currentPrice) {
      alternatives.push({
        model: { id: cand.id, provider: cand.provider, region: cand.region },
        pricePer1M: candPrice,
        savingsPer1M: +(currentPrice - candPrice).toFixed(4),
        savingsPct: currentPrice > 0 ? +(((currentPrice - candPrice) / currentPrice) * 100).toFixed(1) : 0,
      });
    }
  }

  alternatives.sort((a, b) => b.savingsPer1M - a.savingsPer1M);
  return { tier, current: { id: current.id, provider: current.provider, pricePer1M: currentPrice }, alternatives };
}

/**
 * Auto-route a prompt to the best available model for the task.
 * @returns {{ model, tier, wasRouted, savings?: { originalId, savedUsd } }}
 */
function autoRoute(prompt, preferredProvider, currentModelId) {
  const tier = classifyTier(prompt);
  const candidates = TIER_MODELS[tier] || TIER_MODELS.simple;

  // Find cheapest candidate that exists in catalog
  let best = null;
  let bestPrice = Infinity;
  for (const id of candidates) {
    const m = modelCatalog.byId.get(id) || modelCatalog.detect({ model: id });
    if (!m) continue;
    // Filter by preferred provider if specified
    if (preferredProvider && m.provider !== preferredProvider) continue;
    const price = (m.in || 0) + (m.out || 0);
    if (price < bestPrice) { best = m; bestPrice = price; }
  }

  // If no candidate found in preferred provider, try without filter
  if (!best && preferredProvider) {
    return autoRoute(prompt, null, currentModelId);
  }

  if (!best) {
    // Fall back to current model
    const current = modelCatalog.byId.get(currentModelId) || modelCatalog.detect({ model: currentModelId });
    return { model: current, tier, wasRouted: false };
  }

  // Calculate savings vs. current model
  let savings = null;
  if (currentModelId) {
    const current = modelCatalog.byId.get(currentModelId) || modelCatalog.detect({ model: currentModelId });
    if (current) {
      const currentPrice = (current.in || 0) + (current.out || 0);
      const saved = currentPrice - bestPrice;
      if (saved > 0) {
        savings = { originalId: current.id, savedPer1M: +saved.toFixed(4) };
        recordSavings(current, best, 0, saved); // approximate — real savings computed per-request
      }
    }
  }

  return {
    model: { id: best.id, provider: best.provider, region: best.region, flag: best.flag },
    tier,
    wasRouted: savings !== null,
    savings,
  };
}

function getSavings() {
  const topProviders = Object.entries(_savings.byProvider)
    .sort((a, b) => b[1].saved - a[1].saved)
    .slice(0, 5)
    .map(([p, d]) => ({ provider: p, routes: d.routes, saved: +d.saved.toFixed(4) }));
  return {
    totalRoutes: _savings.totalRoutes,
    totalSaved: +_savings.totalSaved.toFixed(4),
    topProviders,
    recent: _savings.history.slice(0, 10),
  };
}

module.exports = {
  classifyTier,
  suggestCheaper,
  autoRoute,
  getSavings,
  recordSavings,
  TIER_MODELS,
};
