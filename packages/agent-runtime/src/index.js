'use strict';

/**
 * Kasbah Agent Runtime — The Agentic Control Plane
 *
 * Sits between an AI agent and every tool it uses.
 * Every bash call, file write, HTTP request, and code execution
 * passes through governance before the OS ever sees it.
 *
 * Architecture:
 *
 *   Agent receives goal
 *        │
 *        ▼  turns (prompts ↔ responses)
 *   AgentSession ──── ChainMonitor  (drift / injection / loop detection)
 *        │                          (reads entire conversation history)
 *        ▼  tool calls
 *   ToolGuard ──── ActionManifest   (allowed tools, blocked tools, domains)
 *             ──── BudgetEnforcer   (tokens, cost, time, turn limit)
 *             ──── Kasbah Govern    (content safety on args + results)
 *             ──── KillSwitch       (immediate hard-stop)
 *        │
 *        ▼  ALLOW only
 *   External World  (bash / file / HTTP / code)
 */

const { randomUUID } = require('crypto');
const EventEmitter   = require('events');
const http           = require('http');

// ── Causal Loop Breaker (Pearl's do-calculus cycle detection) ─────────────────
let _CausalLoopBreaker = null;
try { _CausalLoopBreaker = require('./causal-loop-breaker').CausalLoopBreaker; } catch (_) {}
const _causalBreaker = _CausalLoopBreaker ? new _CausalLoopBreaker() : null;

// ── Global registries ─────────────────────────────────────────────────────────
const _sessions   = new Map();   // sessionId → AgentSession
const _killed     = new Set();   // sessionIds hard-killed
const _sseClients = [];          // res objects for /v1/agents/stream

// ── Default action manifest ───────────────────────────────────────────────────
const DEFAULT_MANIFEST = {
  allowedTools:   ['read_file', 'list_dir', 'search', 'kasbah_govern'],
  blockedTools:   ['delete_file', 'format_drive', 'init_module', 'ptrace'],
  allowedDomains: null,    // null = no domain restriction on http tool
  maxTurns:       100,
  maxTokens:      500_000,
  maxCostCents:   1_000,   // $10 hard cap per session
  timeoutMs:      3_600_000,
  requireTicket:  false,
};

// ── Risk accumulator weights ──────────────────────────────────────────────────
const RISK_W = {
  injectionInChain:  0.30,
  secretInResult:    0.25,
  loopDetected:      0.20,
  escalationPattern: 0.20,
  budgetWarning:     0.10,
};

// ── Loop detection thresholds ─────────────────────────────────────────────────
const LOOP_WINDOW = 8;
const LOOP_LIMIT  = 4;   // same tool+argsHash appearing 4× in last 8 calls = loop

// ─────────────────────────────────────────────────────────────────────────────
// AgentSession — lifecycle owner for one agent run
// ─────────────────────────────────────────────────────────────────────────────
class AgentSession extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.agentId        - human-readable agent name
   * @param {string} opts.passportId     - Kasbah passport for this agent
   * @param {object} opts.manifest       - overrides for DEFAULT_MANIFEST
   * @param {string} opts.goal           - agent's stated objective (logged only)
   * @param {string} opts.parentSessionId - optional: inherit policy constraints from parent
   */
  constructor({ agentId, passportId, manifest = {}, goal = '', parentSessionId } = {}) {
    super();
    this.sessionId    = randomUUID();
    this.agentId      = agentId      || 'unnamed-agent';
    this.passportId   = passportId   || null;
    this.manifest     = { ...DEFAULT_MANIFEST, ...manifest };
    this.goal         = goal;
    this.status       = 'active';   // active | suspended | completed | killed
    this.startedAt    = Date.now();
    this.lastActiveAt = Date.now();
    this.turns        = [];
    this.toolCalls    = [];
    this.riskScore    = 0;
    this.budget       = { promptTokens: 0, completionTokens: 0, totalTokens: 0, costCents: 0 };
    this.parentSessionId = null;

    // ── Policy-constrained spawning: child CANNOT be more permissive than parent ──
    if (parentSessionId) {
      const parent = _sessions.get(parentSessionId);
      if (parent) {
        const pm = parent.manifest;
        this.manifest.allowedTools = this.manifest.allowedTools === '*'
          ? pm.allowedTools  // parent restriction wins
          : Array.isArray(this.manifest.allowedTools) && Array.isArray(pm.allowedTools) && pm.allowedTools !== '*'
            ? this.manifest.allowedTools.filter(t => pm.allowedTools.includes(t))  // intersection
            : this.manifest.allowedTools;
        this.manifest.maxTokens    = Math.min(this.manifest.maxTokens    || Infinity, pm.maxTokens    || Infinity);
        this.manifest.maxCostCents = Math.min(this.manifest.maxCostCents || Infinity, pm.maxCostCents || Infinity);
        this.manifest.maxTurns     = Math.min(this.manifest.maxTurns     || Infinity, pm.maxTurns     || Infinity);
        this.parentSessionId = parentSessionId;
      }
    }

    this._guard   = new ToolGuard(this);
    this._chain   = new ChainMonitor(this);

    _sessions.set(this.sessionId, this);
    _broadcast({ type: 'session_created', session: this._summary() });
  }

  // ── Record one conversation turn ────────────────────────────────────────────
  async recordTurn({ role, content = '', tokens = 0, costCents = 0 } = {}) {
    if (this.status !== 'active') {
      return { ok: false, verdict: 'DENY', reason: `session_${this.status}` };
    }

    this.lastActiveAt = Date.now();
    this.turns.push({
      role,
      content: String(content).slice(0, 800),  // keep ledger lean
      tokens,
      costCents,
      ts: Date.now(),
    });
    this.budget.totalTokens += tokens;
    this.budget.costCents   += costCents;

    // Timeout check
    if (Date.now() - this.startedAt > this.manifest.timeoutMs) {
      await this.kill('session_timeout');
      return { ok: false, verdict: 'KILL', reason: 'session_timeout' };
    }

    // Chain analysis — look for injections / escalation embedded in results
    const chain = await this._chain.analyze(content, role);
    if (chain.kill) {
      await this.kill('chain_monitor: ' + chain.reason);
      return { ok: false, verdict: 'KILL', reason: chain.reason };
    }

    _broadcast({ type: 'turn', sessionId: this.sessionId, role, tokens, riskScore: this.riskScore });
    return { ok: true, verdict: 'ALLOW', chain };
  }

  // ── Govern a single tool call ────────────────────────────────────────────────
  /**
   * Call this BEFORE executing any tool.
   * @param {object} opts
   * @param {string} opts.tool       - tool name, e.g. 'bash', 'write_file'
   * @param {object} opts.args       - raw args object (logged)
   * @param {string} opts.argsText   - flattened text representation for content scan
   * @returns {{ ok, verdict, reason?, receipt?, govResult? }}
   */
  async governTool({ tool, args = {}, argsText = '' } = {}) {
    // Hard-kill gate — fastest check first
    if (_killed.has(this.sessionId)) {
      return { ok: false, verdict: 'DENY', reason: 'session_killed' };
    }
    if (this.status !== 'active') {
      return { ok: false, verdict: 'DENY', reason: `session_${this.status}` };
    }

    this.lastActiveAt = Date.now();

    // 1 ── Manifest: is this tool allowed at all?
    const mf = this._checkManifest(tool);
    if (!mf.allowed) {
      this._logTool({ tool, args, argsText, verdict: 'DENY', reason: 'manifest_blocked' });
      _broadcast({ type: 'tool_denied', sessionId: this.sessionId, tool, reason: 'manifest_blocked' });
      return { ok: false, verdict: 'DENY', reason: 'manifest_blocked', allowedTools: this.manifest.allowedTools };
    }

    // 2 ── Turn cap
    if (this.turns.length >= this.manifest.maxTurns) {
      this._logTool({ tool, args, argsText, verdict: 'DENY', reason: 'turn_limit' });
      await this.kill('turn_limit_exceeded');
      return { ok: false, verdict: 'DENY', reason: 'turn_limit_exceeded', limit: this.manifest.maxTurns };
    }

    // 3 ── Budget cap
    const bud = this._checkBudget();
    if (bud.block) {
      this._logTool({ tool, args, argsText, verdict: 'DENY', reason: 'budget_exceeded' });
      await this.kill('budget_exceeded');
      return { ok: false, verdict: 'DENY', reason: 'budget_exceeded', budget: this.budget };
    }

    // 4 ── Loop detection
    const loop = this._detectLoop(tool, argsText);
    if (loop.detected) {
      this.riskScore = Math.min(1.0, this.riskScore + RISK_W.loopDetected);
      this._logTool({ tool, args, argsText, verdict: 'DENY', reason: 'loop_detected' });
      _broadcast({ type: 'loop_detected', sessionId: this.sessionId, tool, count: loop.count });
      return { ok: false, verdict: 'DENY', reason: 'loop_detected', count: loop.count };
    }

    // 4b ── Causal loop detection (Pearl's do-calculus cycle analysis)
    try {
      if (_causalBreaker) {
        _causalBreaker.recordAgentState(this.agentId, this.riskScore);
        _causalBreaker.recordMessage(this.agentId, tool, argsText?.slice(0, 100) || '');
        const causalResult = _causalBreaker.analyze();
        if (causalResult.cycles && causalResult.cycles.length > 0) {
          this.riskScore = Math.min(1.0, this.riskScore + 0.15);
          _broadcast({ type: 'causal_cycle_detected', sessionId: this.sessionId, cycles: causalResult.cycles.slice(0, 3) });
        }
      }
    } catch (_) {}

    // 5 ── Content scan on the tool arguments (async, 2s timeout)
    let govResult = null;
    if (argsText && argsText.length > 8) {
      govResult = await this._guard.scanContent(argsText, tool);
      if (govResult?.verdict === 'DENY') {
        this._logTool({ tool, args, argsText, verdict: 'DENY', reason: 'content_denied', govResult });
        _broadcast({ type: 'tool_content_denied', sessionId: this.sessionId, tool, threats: govResult.threats });
        return { ok: false, verdict: 'DENY', reason: 'content_denied', govResult };
      }
      if (govResult?.verdict === 'WARN') {
        this.riskScore = Math.min(1.0, this.riskScore + 0.05);
      }
    }

    this._logTool({ tool, args, argsText, verdict: 'ALLOW', govResult });
    _broadcast({ type: 'tool_allowed', sessionId: this.sessionId, tool, riskScore: this.riskScore });
    return {
      ok: true,
      verdict: 'ALLOW',
      receipt:   govResult?.proof  || govResult?.receipt || null,
      riskScore: this.riskScore,
    };
  }

  // ── Scan a tool result for injected instructions ─────────────────────────────
  async scanToolResult({ tool, result = '' }) {
    if (!result || typeof result !== 'string') return { ok: true };

    // 1. Regex chain monitor (fast, catches escalation patterns)
    const analysis = await this._chain.analyze(result, 'tool_result');
    if (analysis.kill) {
      await this.kill('injection_in_tool_result');
      return { ok: false, verdict: 'KILL', reason: 'injection_in_tool_result' };
    }

    // 2. Full govern scan on tool results (catches what regex misses)
    // Only scan if result is substantial enough to matter
    if (result.length > 20) {
      const govResult = await this._guard.scanContent(result, `${tool}_result`);
      if (govResult?.verdict === 'DENY') {
        this.riskScore = Math.min(1.0, this.riskScore + 0.40);
        if (this.riskScore >= 0.65) {
          await this.kill('injection_in_tool_result');
          return { ok: false, verdict: 'KILL', reason: 'injection_in_tool_result' };
        }
        _broadcast({ type: 'tool_content_denied', sessionId: this.sessionId, tool: `${tool}_result`, threats: govResult.threats });
        return { ok: false, verdict: 'DENY', reason: 'content_denied_in_result', govResult };
      }
    }

    return { ok: true, riskScore: this.riskScore };
  }

  // ── Emergency stop ────────────────────────────────────────────────────────────
  async kill(reason = 'manual') {
    this.status = 'killed';
    _killed.add(this.sessionId);
    _sessions.delete(this.sessionId);
    _broadcast({ type: 'session_killed', sessionId: this.sessionId, agentId: this.agentId, reason });
    this.emit('killed', { sessionId: this.sessionId, reason });
  }

  // ── Normal completion ─────────────────────────────────────────────────────────
  complete() {
    if (this.status === 'killed') return;
    this.status = 'completed';
    _sessions.delete(this.sessionId);
    _broadcast({ type: 'session_completed', sessionId: this.sessionId, agentId: this.agentId, budget: this.budget });
    this.emit('completed', this._summary());
  }

  // ── Internals ─────────────────────────────────────────────────────────────────
  _checkManifest(tool) {
    const { allowedTools, blockedTools } = this.manifest;
    if (Array.isArray(blockedTools) && blockedTools.includes(tool)) return { allowed: false };
    if (allowedTools === '*') return { allowed: true };
    if (Array.isArray(allowedTools) && allowedTools.includes(tool)) return { allowed: true };
    return { allowed: false };
  }

  _checkBudget() {
    const { maxCostCents, maxTokens } = this.manifest;
    if (maxCostCents && this.budget.costCents   >= maxCostCents) return { block: true, reason: 'cost' };
    if (maxTokens    && this.budget.totalTokens >= maxTokens)    return { block: true, reason: 'tokens' };
    return { block: false };
  }

  _detectLoop(tool, argsText) {
    const sig    = `${tool}:${String(argsText).slice(0, 120)}`;
    const window = this.toolCalls.slice(-LOOP_WINDOW);
    const count  = window.filter(c => c._sig === sig).length;
    // count is the number of ALREADY-LOGGED identical calls. The call being checked
    // would become count+1. Block when that would reach LOOP_LIMIT.
    return { detected: count >= LOOP_LIMIT - 1, count: count + 1 };
  }

  _logTool(entry) {
    this.toolCalls.push({ ...entry, _sig: `${entry.tool}:${String(entry.argsText).slice(0, 120)}`, ts: Date.now() });
  }

  _summary() {
    return {
      sessionId:      this.sessionId,
      agentId:        this.agentId,
      passportId:     this.passportId,
      parentSessionId: this.parentSessionId || null,
      status:         this.status,
      goal:           String(this.goal).slice(0, 200),
      turnCount:      this.turns.length,
      toolCount:      this.toolCalls.length,
      riskScore:      Math.round(this.riskScore * 100) / 100,
      budget:         this.budget,
      startedAt:      this.startedAt,
      lastActiveAt:   this.lastActiveAt,
      manifest: {
        allowedTools: this.manifest.allowedTools,
        blockedTools: this.manifest.blockedTools,
        maxTurns:     this.manifest.maxTurns,
        maxTokens:    this.manifest.maxTokens,
        maxCostCents: this.manifest.maxCostCents,
      },
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolGuard — calls Kasbah /v1/govern on tool arguments
// ─────────────────────────────────────────────────────────────────────────────
class ToolGuard {
  constructor(session) {
    this._session = session;
    this._host    = process.env.KASBAH_HOST || '127.0.0.1';
    this._port    = parseInt(process.env.KASBAH_PORT || process.env.PORT || '8788', 10);
  }

  async scanContent(text, tool) {
    // SECURITY: This method MUST be fail-closed.
    // If the governance API is unreachable (network error, timeout, bad JSON),
    // we return a synthetic DENY rather than null. The caller checks
    // govResult?.verdict === 'DENY', so null would silently allow — a critical
    // security hole. Fail-closed: if we can't verify, we block.
    // Object.freeze prevents downstream code from accidentally mutating
    // the sentinel — every error path shares the same immutable object.
    const FAIL_CLOSED = Object.freeze({
      verdict:  'DENY',
      score:    1.0,
      threats:  ['governance_unavailable'],
      reason:   'fail_closed',
    });

    const bodyObj = {
      prompt:  `[TOOL:${tool}] ${text}`,
      context: `agent_tool:${tool}:${this._session.sessionId}`,
    };
    // Only include passportId if it's a real passport (not a placeholder)
    if (this._session.passportId && this._session.passportId !== 'agent-runtime') {
      bodyObj.passportId = this._session.passportId;
    }
    const body = JSON.stringify(bodyObj);
    return new Promise((resolve) => {
      const req = http.request({
        hostname: this._host,
        port:     this._port,
        path:     '/v1/govern',
        method:   'POST',
        headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      }, (res) => {
        let raw = '';
        res.on('data', c => { raw += c; });
        res.on('end',  () => {
          // Non-2xx → fail closed
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return resolve(FAIL_CLOSED);
          }
          try {
            const parsed = JSON.parse(raw);
            // Missing verdict field → fail closed (error response slipped through)
            if (!parsed.verdict) return resolve(FAIL_CLOSED);
            resolve(parsed);
          } catch { resolve(FAIL_CLOSED); }
        });
      });
      req.on('error',   () => resolve(FAIL_CLOSED));              // network error → fail closed
      req.setTimeout(2000, () => { req.destroy(); resolve(FAIL_CLOSED); });  // timeout → fail closed
      req.write(body);
      req.end();
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChainMonitor — watches the full conversation for injected instructions,
//                escalation patterns, goal drift, and secret leakage
// ─────────────────────────────────────────────────────────────────────────────
class ChainMonitor {
  constructor(session) {
    this._session = session;
  }

  async analyze(content, role) {
    if (!content || typeof content !== 'string') return { kill: false };

    // ── Injection in tool results ──────────────────────────────────────────────
    // An attacker can embed instructions inside a web page, file, or API response
    // that the agent reads. We catch those here before the agent acts on them.
    const INJECTION_RX = [
      /ignore\s+(all\s+)?(previous|above|prior|system)\s+instructions/i,
      /you\s+are\s+now\s+(a\s+|an\s+)?/i,
      /\[system\]/i,
      /<system>[\s\S]{0,200}<\/system>/i,
      /override\s+(your\s+|all\s+)?(safety|previous|system)/i,
      /disregard\s+(all\s+|your\s+)?previous/i,
      /new\s+instruction[s]?:/i,
      /forget\s+(everything|all|what)/i,
    ];
    if (INJECTION_RX.some(r => r.test(content))) {
      this._session.riskScore = Math.min(1.0, this._session.riskScore + RISK_W.injectionInChain);
      if (this._session.riskScore >= 0.65) {
        return { kill: true, reason: 'prompt_injection_in_chain' };
      }
    }

    // ── Privilege escalation pattern ───────────────────────────────────────────
    const ESCALATION_TERMS = [
      'sudo ', 'chmod 777', 'chown root', 'rm -rf /', 'dd if=', 'mkfs.',
      '/etc/shadow', '/etc/passwd', 'net user /add', 'useradd', 'visudo',
      'iptables -F', 'setenforce 0', 'systemctl disable',
    ];
    const hitCount = ESCALATION_TERMS.filter(t => content.includes(t)).length;
    if (hitCount >= 2) {
      this._session.riskScore = Math.min(1.0, this._session.riskScore + RISK_W.escalationPattern);
      if (this._session.riskScore >= 0.75) {
        return { kill: true, reason: 'escalation_pattern_in_chain' };
      }
    }

    // ── Secret / credential in tool result (exfil attempt) ────────────────────
    const SECRET_RX = [
      /AKIA[0-9A-Z]{16}/,                          // AWS key
      /sk-[A-Za-z0-9]{40,}/,                        // OpenAI key
      /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, // JWT
      /-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----/,
    ];
    if (SECRET_RX.some(r => r.test(content))) {
      this._session.riskScore = Math.min(1.0, this._session.riskScore + RISK_W.secretInResult);
      if (this._session.riskScore >= 0.50) {
        return { kill: true, reason: 'secret_detected_in_chain' };
      }
    }

    return { kill: false, riskScore: this._session.riskScore };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentProxy — wraps an OpenAI or Anthropic client object so every call
//              automatically goes through AgentSession governance.
//
//  Usage:
//    const session = agentRuntime.createSession({ agentId: 'my-bot', ... });
//    const governed = agentRuntime.wrapOpenAI(openaiClient, session.sessionId);
//    // Now governed.chat.completions.create(...) is auto-governed
// ─────────────────────────────────────────────────────────────────────────────
class AgentProxy {
  constructor(client, sessionId, type = 'openai') {
    this._client    = client;
    this._sessionId = sessionId;
    this._type      = type;
    return this._buildProxy();
  }

  _buildProxy() {
    const self    = this;
    const session = () => _sessions.get(self._sessionId);

    const intercept = async (methodPath, originalFn, args) => {
      const s = session();
      if (!s) throw new Error(`KasbahAgentProxy: session ${self._sessionId} not found`);

      // Extract text for governance
      const firstArg  = args[0] || {};
      const messages  = firstArg.messages || firstArg.prompt || '';
      const argsText  = typeof messages === 'string' ? messages
        : Array.isArray(messages) ? messages.map(m => m.content || '').join('\n')
        : JSON.stringify(firstArg).slice(0, 1000);

      const decision = await s.governTool({ tool: methodPath, args: firstArg, argsText });
      if (!decision.ok) {
        const err = new Error(`KasbahOS blocked: ${decision.reason}`);
        err.kasbah = decision;
        throw err;
      }

      // Call the real method
      const result = await originalFn.apply(self._client, args);

      // Scan the response for injected instructions
      let responseText = '';
      if (self._type === 'openai') {
        responseText = result?.choices?.[0]?.message?.content || '';
      } else if (self._type === 'anthropic') {
        responseText = result?.content?.[0]?.text || '';
      } else if (self._type === 'gemini') {
        responseText = result?.candidates?.[0]?.content?.parts?.[0]?.text || '';
      } else if (self._type === 'ollama') {
        responseText = result?.message?.content || result?.response || '';
      } else if (self._type === 'bedrock') {
        responseText = result?.output?.message?.content?.[0]?.text || result?.body?.toString() || '';
      } else if (self._type === 'vertex') {
        responseText = (typeof result?.response?.text === 'function' ? result.response.text() : null)
          || result?.text || '';
      }
      if (responseText) await s.scanToolResult({ tool: methodPath, result: responseText });

      // Record token usage
      const usage = result?.usage;
      if (usage) {
        await s.recordTurn({
          role:       'assistant',
          content:    responseText,
          tokens:     usage.total_tokens || usage.input_tokens + (usage.output_tokens || 0) || 0,
          costCents:  0,  // caller can set budget policy separately
        });
      }

      return result;
    };

    // Shallow proxy of the client object
    return new Proxy(this._client, {
      get(target, prop) {
        const val = target[prop];
        if (typeof val !== 'object' || val === null) return val;
        // Recursively proxy nested objects (e.g. client.chat.completions)
        return new Proxy(val, {
          get(innerTarget, innerProp) {
            const innerVal = innerTarget[innerProp];
            if (typeof innerVal === 'function') {
              return (...args) => intercept(`${String(prop)}.${String(innerProp)}`, innerVal, args);
            }
            return innerVal;
          },
        });
      },
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSE broadcast helpers (used by the server's /v1/agents/stream endpoint)
// ─────────────────────────────────────────────────────────────────────────────
function _broadcast(event) {
  if (_sseClients.length === 0) return;
  const chunk = `data: ${JSON.stringify(event)}\n\n`;
  for (let i = _sseClients.length - 1; i >= 0; i--) {
    try { _sseClients[i].write(chunk); } catch { _sseClients.splice(i, 1); }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────
function createSession(opts)       { return new AgentSession(opts); }
function getSession(id)            { return _sessions.get(id) || null; }
function listSessions()            { return [..._sessions.values()].map(s => s._summary()); }
function isKilled(id)              { return _killed.has(id); }

async function killSession(id, reason = 'manual') {
  const s = _sessions.get(id);
  if (s) return s.kill(reason);
  _killed.add(id);   // pre-kill: block before session object is even created
}

function wrapOpenAI(client, sessionId)    { return new AgentProxy(client, sessionId, 'openai'); }
function wrapAnthropic(client, sessionId) { return new AgentProxy(client, sessionId, 'anthropic'); }
function wrapGemini(client, sessionId)    { return new AgentProxy(client, sessionId, 'gemini'); }
function wrapOllama(client, sessionId)    { return new AgentProxy(client, sessionId, 'ollama'); }
function wrapBedrock(client, sessionId)   { return new AgentProxy(client, sessionId, 'bedrock'); }
function wrapVertex(client, sessionId)    { return new AgentProxy(client, sessionId, 'vertex'); }

function addSseClient(res)    { _sseClients.push(res); }
function removeSseClient(res) {
  const i = _sseClients.indexOf(res);
  if (i >= 0) _sseClients.splice(i, 1);
}

module.exports = {
  // Classes (for advanced usage)
  AgentSession, ToolGuard, ChainMonitor, AgentProxy,
  // Core API
  createSession, getSession, listSessions, killSession, isKilled,
  // Client wrappers
  wrapOpenAI, wrapAnthropic, wrapGemini, wrapOllama, wrapBedrock, wrapVertex,
  // SSE
  addSseClient, removeSseClient,
  // Causal loop breaker (for dashboard stats)
  causalBreaker: _causalBreaker,
};
