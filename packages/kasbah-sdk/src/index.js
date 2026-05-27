'use strict';

/**
 * Kasbah Guard SDK — Official Node.js Client
 *
 * Govern AI agents from any Node.js app. Wraps the Kasbah API
 * with automatic passport management, retry logic, and streaming.
 *
 * Usage:
 *   const Kasbah = require('@kasbah/sdk');
 *   const k = new Kasbah({ apiKey: 'kg_...', baseUrl: 'https://api.bekasbah.com' });
 *
 *   // Govern a prompt
 *   const result = await k.govern({ prompt: 'User message here' });
 *   if (result.verdict === 'DENY') throw new Error('Blocked: ' + result.threats.join(', '));
 *
 *   // Issue a passport for an agent
 *   const passport = await k.passport.issue({ agentId: 'my-agent', capabilities: ['search'] });
 *
 *   // Check system health
 *   const health = await k.health();
 */

const http  = require('http');
const https = require('https');
const url   = require('url');

const SDK_VERSION = '6.0.0';

class KasbahError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'KasbahError';
    this.status = status;
    this.body = body;
  }
}

class Kasbah {
  /**
   * @param {object} opts
   * @param {string} opts.apiKey     — API key (default: 'kg_desktop_builtin')
   * @param {string} opts.baseUrl    — API base URL (default: 'https://api.bekasbah.com')
   * @param {number} opts.timeout    — Request timeout ms (default: 10000)
   * @param {boolean} opts.autoRetry — Retry on 5xx with backoff (default: true)
   */
  constructor(opts = {}) {
    this.apiKey    = opts.apiKey   || 'kg_desktop_builtin';
    this.baseUrl   = (opts.baseUrl || 'https://api.bekasbah.com').replace(/\/$/, '');
    this.timeout   = opts.timeout  || 10_000;
    this.autoRetry = opts.autoRetry !== false;
    this._passportId = opts.passportId || null;

    // Sub-clients
    this.passport   = new PassportClient(this);
    this.delegation = new DelegationClient(this);
    this.honeytoken = new HoneytokenClient(this);
    this.spend      = new SpendClient(this);
  }

  // ── Core govern ─────────────────────────────────────────────────────────

  /**
   * Govern a prompt/response through all 17 frontier systems.
   * @param {object} body — { prompt?, response?, passportId?, delegationTokenId?, agent? }
   * @returns {Promise<GovernResult>}
   */
  async govern(body = {}) {
    if (this._passportId && !body.passportId) body.passportId = this._passportId;
    return this._post('/v1/govern', body);
  }

  /**
   * Scan text for threats (lightweight — no passport/delegation processing).
   * @param {string} text
   * @returns {Promise<ScanResult>}
   */
  async scan(text) {
    const raw = await this._post('/v1/scan', { text });
    // /v1/scan returns {threats, risk, risk_score, safe, latency_ms} — normalize
    // to {decision, verdict, blocked, risk, threats, ...raw} so callers can rely on it.
    const threats = raw.threats || raw.violations || [];
    const risk    = raw.risk_score ?? raw.riskScore ?? raw.risk ?? 0;
    const safe    = raw.safe !== false;
    const verdict = raw.verdict || raw.decision || (safe ? 'ALLOW' : (risk < 0.7 ? 'WARN' : 'DENY'));
    return Object.assign({}, raw, {
      verdict,
      decision: verdict,
      blocked:  verdict === 'DENY',
      risk,
      threats
    });
  }

  /**
   * Explain why a prompt would be blocked/warned.
   * @param {string} prompt
   * @returns {Promise<ExplainResult>}
   */
  async explain(prompt) {
    return this._post('/v1/explain', { prompt });
  }

  // ── New v4.0 endpoints ──────────────────────────────────────────────────

  /**
   * Run Bell's Inequality AI text detection (CHSH S-value).
   * S > 2.0 = AI-generated text with non-local semantic correlations.
   */
  async bells(text) {
    return this._post('/v1/bells', { text });
  }

  /**
   * Run Maqasid Ethics Framework (5-pillar Islamic ethics scoring).
   */
  async maqasid(text) {
    return this._post('/v1/maqasid', { text });
  }

  /**
   * Run RTP pipeline (f0–f5 governance stages, no side-effects).
   */
  async rtp(text, passportId = null) {
    return this._post('/v1/rtp', { text, passportId });
  }

  /**
   * Run Witt-Crystalline Cohomology Analysis.
   * Novel mathematical framework: de Rham + crystalline + Witt vectors.
   * Computes [ω] ∈ H^k → W(ω) = η → lim σ_n (perfect governance state).
   */
  async witt(data) {
    return this._post('/v1/witt/analyze', { data });
  }

  /**
   * Run Nexus unified engine (RTP + Kernel + Bell's + Detector in one call).
   */
  async nexus(text) {
    return this._post('/v1/nexus', { text });
  }

  /**
   * Verify and consume an execution ticket.
   */
  async verifyTicket(ticketId, hmac) {
    return this._post('/v1/ticket/verify', { ticketId, hmac });
  }

  // ── System ──────────────────────────────────────────────────────────────

  async health()     { return this._get('/v1/health'); }
  async stats()      { return this._get('/v1/stats'); }
  async audit(n=50)  { return this._get(`/v1/audit?limit=${n}`); }
  async integrity()  { return this._get('/v1/integrity'); }
  async forecast()   { return this._get('/v1/forecast'); }
  async swarm()      { return this._get('/v1/swarm/status'); }
  async auditChain() { return this._get('/v1/audit/chain'); }
  async policy()     { return this._get('/v1/policy/active'); }

  async setPolicy(policy) { return this._request('PUT', '/v1/policy/active', policy); }

  // ── Proxy helpers ───────────────────────────────────────────────────────

  /**
   * Proxy an OpenAI chat completion through Kasbah governance.
   * Drop-in replacement for OpenAI's /v1/chat/completions
   * @param {object} body - OpenAI chat completion request body
   * @param {string} upstreamKey - Your OpenAI API key
   * @param {object} [options]
   * @returns OpenAI-compatible response with _kasbahReceipt captured
   */
  async proxyOpenAI(body, upstreamKey, options = {}) {
    const extraHeaders = { 'Authorization': `Bearer ${upstreamKey}` };
    const { body: json, headers } = await this._requestRaw(
      'POST', '/v1/proxy/openai/v1/chat/completions', body, extraHeaders
    );
    return { ...json, _kasbahReceipt: headers['x-kasbah-receipt'] || null };
  }

  /**
   * Proxy an Anthropic messages call through Kasbah governance.
   * Drop-in replacement for Anthropic's /v1/messages
   * @param {object} body - Anthropic messages request body
   * @param {string} upstreamKey - Your Anthropic API key
   * @param {object} [options]
   * @returns Anthropic-compatible response with _kasbahReceipt captured
   */
  async proxyAnthropic(body, upstreamKey, options = {}) {
    const extraHeaders = { 'x-api-key': upstreamKey };
    const { body: json, headers } = await this._requestRaw(
      'POST', '/v1/proxy/anthropic/v1/messages', body, extraHeaders
    );
    return { ...json, _kasbahReceipt: headers['x-kasbah-receipt'] || null };
  }

  // ── Budget management ───────────────────────────────────────────────────

  /**
   * Get token/cost usage for a passport.
   * @param {string} passportId
   */
  async getUsage(passportId) {
    return this._request('GET', `/v1/usage/${passportId}`);
  }

  /**
   * Set token/cost budget policy for a passport.
   * @param {string} passportId
   * @param {object} policy - { maxTokensPerMin?, maxTokensPerDay?, maxCostCentsPerDay? }
   */
  async setBudget(passportId, policy) {
    return this._request('POST', `/v1/budgets/${passportId}`, policy);
  }

  /**
   * Get current budget policy for a passport.
   * @param {string} passportId
   */
  async getBudget(passportId) {
    return this._request('GET', `/v1/budgets/${passportId}`);
  }

  // ── Agentic Layer ───────────────────────────────────────────────────────

  /**
   * Create a governed agent session.
   * Returns { sessionId, agentId, status, manifest, ... }
   * @param {object} opts
   * @param {string} opts.agentId      - human-readable agent name
   * @param {string} opts.passportId   - Kasbah passport for this agent
   * @param {string} opts.goal         - agent objective (logged)
   * @param {object} opts.manifest     - { allowedTools, maxTokens, maxCostCents, ... }
   */
  async createAgent(opts = {}) {
    return this._request('POST', '/v1/agents', opts);
  }

  /**
   * Govern a tool call for an active session.
   * Call this BEFORE executing any tool.
   * Returns { ok, verdict, reason?, receipt?, riskScore }
   * @param {string} sessionId
   * @param {string} tool        - tool name, e.g. 'bash', 'write_file'
   * @param {object} args        - raw args object
   * @param {string} argsText    - flattened text for content scanning
   */
  async governTool(sessionId, tool, args = {}, argsText = '') {
    return this._request('POST', `/v1/agents/${sessionId}/tool`, { tool, args, argsText });
  }

  /**
   * Scan a tool result for injected instructions.
   * Call this AFTER receiving a tool result, before feeding it back to the agent.
   * Returns { ok, verdict?, reason?, riskScore }
   * @param {string} sessionId
   * @param {string} tool
   * @param {string} result  - raw tool output text
   */
  async scanToolResult(sessionId, tool, result) {
    return this._request('POST', `/v1/agents/${sessionId}/tool-result`, { tool, result });
  }

  /**
   * Record a conversation turn for budget and chain tracking.
   * @param {string} sessionId
   * @param {string} role        - 'user' | 'assistant' | 'system' | 'tool'
   * @param {string} content
   * @param {number} tokens      - token count for this turn
   * @param {number} costCents   - cost in cents for this turn
   */
  async recordTurn(sessionId, role, content, tokens = 0, costCents = 0) {
    return this._request('POST', `/v1/agents/${sessionId}/turn`, { role, content, tokens, costCents });
  }

  /**
   * Get the current state of a governed session.
   * @param {string} sessionId
   */
  async getAgent(sessionId) {
    return this._request('GET', `/v1/agents/${sessionId}`);
  }

  /**
   * List all active governed sessions.
   */
  async listAgents() {
    return this._request('GET', '/v1/agents');
  }

  /**
   * Emergency kill: immediately stop a governed agent session.
   * @param {string} sessionId
   * @param {string} reason
   */
  async killAgent(sessionId, reason = 'manual') {
    return this._request('DELETE', `/v1/agents/${sessionId}`, { reason });
  }

  /**
   * Mark a session as completed normally.
   * @param {string} sessionId
   */
  async completeAgent(sessionId) {
    return this._request('POST', `/v1/agents/${sessionId}/complete`);
  }

  /**
   * Wrap an OpenAI client so every API call is auto-governed.
   *
   * The wrapped client is a Proxy — it has the exact same interface as the
   * original. All method calls transparently go through governTool() first.
   *
   * Usage:
   *   const session = await kasbah.createAgent({ agentId: 'my-bot', ... });
   *   const governed = kasbah.wrapOpenAI(openai, session.sessionId);
   *   // now governed.chat.completions.create(...) is auto-governed
   *
   * @param {object} openaiClient  - OpenAI SDK client instance
   * @param {string} sessionId
   */
  wrapOpenAI(openaiClient, sessionId) {
    return this._wrapClient(openaiClient, sessionId, 'openai');
  }

  /**
   * Wrap an Anthropic client so every API call is auto-governed.
   * @param {object} anthropicClient - Anthropic SDK client instance
   * @param {string} sessionId
   */
  wrapAnthropic(anthropicClient, sessionId) {
    return this._wrapClient(anthropicClient, sessionId, 'anthropic');
  }

  _wrapClient(client, sessionId, type) {
    const self = this;
    const intercept = async (methodPath, originalFn, args) => {
      // Extract text for governance
      const firstArg = args[0] || {};
      const messages = firstArg.messages || firstArg.prompt || '';
      const argsText = typeof messages === 'string'
        ? messages
        : Array.isArray(messages)
          ? messages.map(m => (typeof m.content === 'string' ? m.content : JSON.stringify(m.content))).join('\n')
          : JSON.stringify(firstArg).slice(0, 800);

      const decision = await self.governTool(sessionId, methodPath, firstArg, argsText);
      if (!decision.ok) {
        const err    = new Error(`KasbahOS blocked: ${decision.reason}`);
        err.kasbah   = decision;
        err.verdict  = decision.verdict;
        throw err;
      }

      // Execute the real call
      const result = await originalFn.apply(client, args);

      // Scan response for injection
      const responseText = type === 'openai'
        ? result?.choices?.[0]?.message?.content || ''
        : result?.content?.[0]?.text || '';
      if (responseText) {
        await self.scanToolResult(sessionId, methodPath, responseText);
      }

      // Record token usage
      const usage  = result?.usage;
      const tokens = usage
        ? (usage.total_tokens || (usage.input_tokens || 0) + (usage.output_tokens || 0))
        : 0;
      if (tokens > 0) {
        await self.recordTurn(sessionId, 'assistant', responseText.slice(0, 400), tokens, 0);
      }

      return result;
    };

    // Build a recursive proxy
    const makeProxy = (target, pathPrefix) => new Proxy(target, {
      get(inner, prop) {
        const val = inner[prop];
        if (typeof val === 'function') {
          return (...args) => intercept(`${pathPrefix}.${String(prop)}`, val, args);
        }
        if (val && typeof val === 'object') {
          return makeProxy(val, `${pathPrefix}.${String(prop)}`);
        }
        return val;
      },
    });

    return makeProxy(client, type);
  }

  // ── HTTP internals ──────────────────────────────────────────────────────

  async _get(path)         { return this._request('GET', path); }
  async _post(path, body)  { return this._request('POST', path, body); }

  async _request(method, path, body = null, attempt = 1) {
    const parsed  = new url.URL(this.baseUrl + path);
    const isHttps = parsed.protocol === 'https:';
    const lib     = isHttps ? https : http;

    const bodyStr = body ? JSON.stringify(body) : null;
    const headers = {
      'Content-Type':  'application/json',
      'x-api-key':     this.apiKey,
      'x-kasbah-sdk':  `node/${SDK_VERSION}`,
    };
    if (bodyStr) headers['Content-Length'] = Buffer.byteLength(bodyStr);

    return new Promise((resolve, reject) => {
      const req = lib.request({
        hostname: parsed.hostname,
        port:     parsed.port || (isHttps ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method,
        headers,
        timeout:  this.timeout,
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end',  () => {
          try {
            const json = JSON.parse(data);
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve(json);
            } else if (res.statusCode >= 500 && this.autoRetry && attempt < 3) {
              setTimeout(() => this._request(method, path, body, attempt + 1).then(resolve).catch(reject),
                Math.pow(2, attempt) * 200);
            } else {
              reject(new KasbahError(json.error || `HTTP ${res.statusCode}`, res.statusCode, json));
            }
          } catch (e) {
            reject(new KasbahError('Invalid JSON response', res.statusCode, data));
          }
        });
      });

      req.on('error',   reject);
      req.on('timeout', () => { req.destroy(); reject(new KasbahError('Request timeout', 408)); });
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  }

  /**
   * Like _request but returns { body, headers } so callers can inspect
   * response headers (e.g. x-kasbah-receipt for proxy endpoints).
   * @param {string} method
   * @param {string} path
   * @param {object|null} body
   * @param {object} [extraHeaders] - Additional headers to merge in (e.g. Authorization)
   * @param {number} [attempt]
   * @returns {Promise<{ body: object, headers: object }>}
   */
  async _requestRaw(method, path, body = null, extraHeaders = {}, attempt = 1) {
    const parsed  = new url.URL(this.baseUrl + path);
    const isHttps = parsed.protocol === 'https:';
    const lib     = isHttps ? https : http;

    const bodyStr = body ? JSON.stringify(body) : null;
    const headers = {
      'Content-Type':  'application/json',
      'x-api-key':     this.apiKey,
      'x-kasbah-sdk':  `node/${SDK_VERSION}`,
      ...extraHeaders,
    };
    if (bodyStr) headers['Content-Length'] = Buffer.byteLength(bodyStr);

    return new Promise((resolve, reject) => {
      const req = lib.request({
        hostname: parsed.hostname,
        port:     parsed.port || (isHttps ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method,
        headers,
        timeout:  this.timeout,
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end',  () => {
          try {
            const json = JSON.parse(data);
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve({ body: json, headers: res.headers });
            } else if (res.statusCode >= 500 && this.autoRetry && attempt < 3) {
              setTimeout(() => this._requestRaw(method, path, body, extraHeaders, attempt + 1).then(resolve).catch(reject),
                Math.pow(2, attempt) * 200);
            } else {
              reject(new KasbahError(json.error || `HTTP ${res.statusCode}`, res.statusCode, json));
            }
          } catch (e) {
            reject(new KasbahError('Invalid JSON response', res.statusCode, data));
          }
        });
      });

      req.on('error',   reject);
      req.on('timeout', () => { req.destroy(); reject(new KasbahError('Request timeout', 408)); });
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  }
}

// ── Sub-clients ──────────────────────────────────────────────────────────────

class PassportClient {
  constructor(k) { this._k = k; }
  async issue(opts = {})    { return this._k._post('/v1/passport/issue', opts); }
  async list()              { return this._k._get('/v1/passport/list'); }
  async get(id)             { return this._k._get(`/v1/passport/${id}`); }
  async revoke(id)          { return this._k._request('DELETE', `/v1/passport/${id}`); }
  async spend(id)           { return this._k._get(`/v1/passport/${id}/spend`); }
  async setSpendPolicy(id, policy) { return this._k._post(`/v1/passport/${id}/spend/policy`, policy); }
}

class DelegationClient {
  constructor(k) { this._k = k; }
  async issue(opts = {})    { return this._k._post('/v1/delegation/issue', opts); }
  async verify(tokenId)     { return this._k._post('/v1/delegation/verify', { tokenId }); }
}

class HoneytokenClient {
  constructor(k) { this._k = k; }
  async list()              { return this._k._get('/v1/honeytokens'); }
  async deploy(service)     { return this._k._post('/v1/honeytokens/deploy', { service }); }
  async check(text)         { return this._k._post('/v1/honeytokens/check', { text }); }
}

class SpendClient {
  constructor(k) { this._k = k; }
  async get(passportId)     { return this._k._get(`/v1/passport/${passportId}/spend`); }
  async setPolicy(passportId, policy) { return this._k._post(`/v1/passport/${passportId}/spend/policy`, policy); }
}

module.exports = Kasbah;
module.exports.Kasbah    = Kasbah;
module.exports.KasbahError = KasbahError;
// Public-key receipt v2 — world-proof Ed25519 verification.
module.exports.receipt   = require('./receipt');
