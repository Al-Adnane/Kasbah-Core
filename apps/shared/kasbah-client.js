'use strict';

/**
 * Kasbah API Client — used by apps/web and apps/mobile against the same engine.
 *
 * Browser/RN/Node universal. Uses global fetch (Node 18+, RN, modern browser).
 * Single source of truth for endpoint shapes — keeps web and mobile in sync.
 */

const VERSION = '0.1.0';

class KasbahClient {
  /**
   * @param {object} opts
   * @param {string} opts.baseUrl - e.g. https://api.kasbah.app or http://127.0.0.1:8788
   * @param {string} [opts.apiKey]
   * @param {string} [opts.agent]
   */
  constructor(opts = {}) {
    this.baseUrl = (opts.baseUrl || 'http://127.0.0.1:8788').replace(/\/$/, '');
    this.apiKey = opts.apiKey;
    this.agent  = opts.agent || 'web-client';
    this.timeoutMs = opts.timeoutMs || 10000;
  }

  async _request(method, path, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['Authorization'] = 'Bearer ' + this.apiKey;
    const ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const t = ctrl ? setTimeout(() => ctrl.abort(), this.timeoutMs) : null;
    try {
      const res = await fetch(this.baseUrl + path, {
        method, headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl?.signal
      });
      const text = await res.text();
      let data; try { data = text ? JSON.parse(text) : null; } catch { data = text; }
      if (!res.ok) throw new KasbahError(data?.error || ('HTTP ' + res.status), res.status, data);
      return data;
    } finally { if (t) clearTimeout(t); }
  }

  // ─── Core ──────────────────────────────────────────────────────────────
  health()                   { return this._request('GET',  '/v1/health'); }
  stats()                    { return this._request('GET',  '/v1/stats');  }

  scan(text)                 { return this._request('POST', '/v1/scan',    { text, prompt: text }); }
  govern(prompt, opts = {})  { return this._request('POST', '/v1/govern',  { prompt, agent: opts.agent || this.agent }); }
  explain(prompt)            { return this._request('POST', '/v1/explain', { prompt, text: prompt }); }

  verifyReceipt(receipt, payload) {
    return this._request('POST', '/v1/receipt/verify', payload ? { receipt, payload, once: false } : { receipt });
  }

  // ─── Smart routing (mirrors desktop's inferUseCase) ────────────────────
  detectUseCase(text) {
    if (!text) return null;
    const low = text.toLowerCase();
    const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
    if (lines.length >= 2) {
      const verbRe = /^(EXTRACT|FORMAT|SEND|READ|WRITE|EXEC|SCAN|LIST|DELETE|UPLOAD|DOWNLOAD|QUERY|SEARCH|CREATE|MODIFY|MOVE|COPY)\s/;
      const verbs = lines.filter(l => verbRe.test(l));
      if (verbs.length >= 2 && verbs.length >= lines.length * 0.5)
        return { slug: 'intent-analyzer', label: 'an agent trajectory', via: 'algorithms' };
    }
    if (/\b(experience|education|skills|employment|résumé|resume|curriculum|cv)\b/.test(low)
        && /^\s*[-•·]\s/m.test(text) && lines.length >= 5)
      return { slug: 'resume-authentic', label: 'a resume or CV' };
    if (/\b(plaintiff|defendant|whereas|hereby|witnessed|notarized|jurisdiction|affidavit|statute)\b/.test(low)
        || /\b(article \d|section \d|clause \d|exhibit [A-Z])\b/i.test(text))
      return { slug: 'legal-evidence', label: 'a legal document' };
    if (/\b(dao|on-chain|tokenholders|quorum|snapshot|governance vote|treasury allocation|ratify|abstain)\b/.test(low))
      return { slug: 'dao-vote-guard', label: 'a DAO proposal' };
    if (/^@\w+:?/m.test(text) || /\b(retweet|repost|engagement farm|coordinated|botnet|sockpuppet)\b/.test(low))
      return { slug: 'botnet-radar', label: 'a social-media thread' };
    return null;
  }

  // ─── Smart scan — auto-routes to the right product ─────────────────────
  async smartScan(text) {
    const inferred = this.detectUseCase(text);
    if (!inferred) {
      const r = await this.scan(text);
      return { ...r, _used: 'general-scan', _inferred: null };
    }
    if (inferred.via === 'algorithms') {
      const r = await this._request('POST', `/v1/algorithms/${inferred.slug}/run`, { steps: text, input: text });
      return { ...r, _used: inferred.slug, _inferred: inferred.label };
    }
    const body = inferred.slug === 'botnet-radar' ? { accounts: [{ id: 'a1', posts: [text] }] }
              : { input: text };
    const r = await this._request('POST', `/v1/products/${inferred.slug}/analyze`, body);
    return { ...r, _used: inferred.slug, _inferred: inferred.label };
  }

  // ─── Ethics parliament ─────────────────────────────────────────────────
  ethics(content, context = {})       { return this._request('POST', '/v1/nomos/evaluate', { content, context }); }
  ethicsDebate(content, initial, challenge) {
    return this._request('POST', '/v1/nomos/debate', { content, initialVerdict: initial, challenge });
  }

  // ─── Products & algorithms ─────────────────────────────────────────────
  listProducts()             { return this._request('GET',  '/v1/products'); }
  runProduct(slug, body)     { return this._request('POST', `/v1/products/${slug}/analyze`, body); }
  listAlgorithms()           { return this._request('GET',  '/v1/algorithms'); }
  runAlgorithm(slug, body)   { return this._request('POST', `/v1/algorithms/${slug}/run`, body); }
}

class KasbahError extends Error {
  constructor(message, status, body) {
    super(message); this.name = 'KasbahError'; this.status = status; this.body = body;
  }
}

if (typeof module !== 'undefined' && module.exports) module.exports = { KasbahClient, KasbahError, VERSION };
if (typeof globalThis !== 'undefined') { globalThis.KasbahClient = KasbahClient; globalThis.KasbahError = KasbahError; }
