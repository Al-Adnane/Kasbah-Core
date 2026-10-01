'use strict';

/**
 * AI provider endpoints the split tunnel and AI lane know about.
 *
 * Slugs match the api-server's /v1/proxy/:provider mounts so the AI lane can
 * forward straight through. Hostnames are the public API endpoints; the
 * split-AI tunnel resolves them to AllowedIPs at config-generation time.
 * Provider IPs sit behind CDNs and rotate — split-AI is best-effort by
 * design and the docs say so. Full tunnel is the robust mode.
 */

const AI_PROVIDERS = [
  { slug: 'openai', host: 'api.openai.com' },
  { slug: 'anthropic', host: 'api.anthropic.com' },
  { slug: 'mistral', host: 'api.mistral.ai' },
  { slug: 'groq', host: 'api.groq.com' },
  { slug: 'deepseek', host: 'api.deepseek.com' },
  { slug: 'openrouter', host: 'openrouter.ai' },
  { slug: 'together', host: 'api.together.xyz' },
  { slug: 'xai', host: 'api.x.ai' },
  { slug: 'cohere', host: 'api.cohere.com' },
  { slug: 'google', host: 'generativelanguage.googleapis.com' },
];

function providerBySlug(slug) {
  return AI_PROVIDERS.find((p) => p.slug === slug) || null;
}

module.exports = { AI_PROVIDERS, providerBySlug };
