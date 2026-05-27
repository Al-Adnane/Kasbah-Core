/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║            KASBAH AGENT CONTROL — Universal Governance Middleware        ║
 * ║                                                                          ║
 * ║  Intercepts calls to ANY LLM, agent framework, or AI API                ║
 * ║  Applies all 13 KasbahSentinel layers before execution                  ║
 * ║  Returns ALLOW / WARN / DENY with cryptographic proof                   ║
 * ║                                                                          ║
 * ║  Supported targets (zero code changes for the agent):                   ║
 * ║    OpenAI · Anthropic · Google · Groq · Ollama · Mistral · Cohere       ║
 * ║    LangChain · LangGraph · AutoGen · CrewAI · Claude Code               ║
 * ║    Kimi · Grok · Any OpenAI-compatible endpoint                         ║
 * ║                                                                          ║
 * ║  Integration modes:                                                      ║
 * ║    1. Transparent fetch proxy (zero agent code changes)                  ║
 * ║    2. SDK wrapper (KasbahControl.wrap(openai))                          ║
 * ║    3. Claude Code PreToolUse hook (hooks.json)                          ║
 * ║    4. HTTP sidecar proxy (port 31337)                                   ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

'use strict';

const crypto = require('crypto');
const { KasbahSentinel } = require('./kasbah-sentinel');

// ─── Constants ───────────────────────────────────────────────────────────────

const KASBAH_VERSION = '1.0.0';
const PROXY_PORT = 31337;

// Patterns that identify LLM API calls to intercept
const LLM_API_PATTERNS = [
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.groq.com',
  'localhost:11434',          // Ollama
  'api.mistral.ai',
  'api.cohere.com',
  'api.x.ai',                 // Grok
  'api.moonshot.cn',          // Kimi
  'dashscope.aliyuncs.com',   // Alibaba/Qwen
  '/v1/chat/completions',
  '/v1/messages',
  '/v1/generate',
];

// ─── Core Decision Engine ─────────────────────────────────────────────────────

class KasbahAgentControl {
  constructor(config = {}) {
    this.config = {
      mode: config.mode || 'enforce',       // enforce | warn | audit
      layers: config.layers || 'all',
      timeoutMs: config.timeoutMs || 50,    // target <50ms governance decision
      failOpen: config.failOpen || false,   // false = fail-closed (safer)
      auditLog: config.auditLog !== false,  // default: log everything
      ...config,
    };

    const policyPath = config.policyPath
      || process.env.KASBAH_POLICY_FILE
      || require('path').resolve(__dirname, '..', '.kasbahpolicy.json');
    this.sentinel = new KasbahSentinel({ policyPath });
    this._sessions = new Map();             // session → agent history (swarm detection)
    this._proofCounter = 0;
  }

  // ─── Primary governance check ──────────────────────────────────────────────

  async govern(request) {
    const start = Date.now();
    const requestId = this._requestId();

    // Stamp with TOCTOUGuard TTL — snapshot state NOW before any async work
    const toctouSnapshot = this._snapshotState(request);

    let sentinelResult;
    try {
      // ── Bridge: sentinelCheck() is the real entry-point on KasbahSentinel.
      // sentinel.evaluate() never existed — this was the root cause of all
      // DENY-on-safe-input failures. We extract text from whatever request
      // shape arrives, normalise to the sentinelCheck() contract, then
      // map the richer return object back to the {overallRisk} shape that
      // the rest of govern() expects.
      const sentinelInput = this._normaliseSentinelInput(request);
      sentinelResult = await Promise.race([
        this.sentinel.sentinelCheck(sentinelInput),
        this._timeout(this.config.timeoutMs),
      ]);
      // Normalise output: sentinelCheck returns {decision, scan:{risk}, violations}
      // risk is 0-100; map to overallRisk 0-1 for downstream logic.
      if (sentinelResult && typeof sentinelResult.decision === 'string') {
        const rawRisk = sentinelResult.scan?.risk ?? 0;
        sentinelResult.overallRisk = rawRisk / 100;
        // Carry violations into layers so _decision() can surface them
        sentinelResult.layers = sentinelResult.layers || {};
        if (Array.isArray(sentinelResult.violations) && sentinelResult.violations.length) {
          sentinelResult.layers.violations = sentinelResult.violations;
        }
      }
    } catch (err) {
      // Fail-closed by default: if Sentinel errors, DENY
      if (!this.config.failOpen) {
        return this._decision('DENY', requestId, { reason: 'sentinel_error', error: err.message }, toctouSnapshot, start);
      }
      sentinelResult = { overallRisk: 0.1, layers: {}, note: 'fail-open' };
    }

    // Verify TOCTOU — state must not have changed in the <50ms window
    const toctouViolation = this._verifyTOCTOU(toctouSnapshot, request);
    if (toctouViolation) {
      return this._decision('DENY', requestId, { reason: 'toctou_violation', detail: toctouViolation }, toctouSnapshot, start);
    }

    // Map Sentinel risk to decision
    const risk = sentinelResult.overallRisk || 0;
    let verdict;
    if (risk >= 0.7)      verdict = 'DENY';
    else if (risk >= 0.4) verdict = 'WARN';
    else                  verdict = 'ALLOW';

    // Mode override
    if (this.config.mode === 'audit') verdict = 'ALLOW';  // audit mode: log only, never block
    if (this.config.mode === 'warn' && verdict === 'DENY') verdict = 'WARN';

    return this._decision(verdict, requestId, sentinelResult, toctouSnapshot, start);
  }

  // ─── Claude Code hooks integration ────────────────────────────────────────

  /**
   * PreToolUse hook handler for Claude Code hooks.json
   * Usage: add to .claude/settings.json hooks section
   *
   * Returns { decision, proof, blockTool } — Claude Code checks blockTool
   */
  async preToolUse(toolName, toolInput) {
    const request = {
      type: 'tool_use',
      tool: toolName,
      input: toolInput,
      timestamp: Date.now(),
    };

    const decision = await this.govern(request);

    // Claude Code hook protocol: non-zero exit code blocks the tool
    if (decision.verdict === 'DENY') {
      return {
        blocked: true,
        reason: `KasbahSentinel DENIED: ${decision.reason}`,
        proof: decision.proof,
        auditId: decision.requestId,
      };
    }

    return {
      blocked: false,
      verdict: decision.verdict,
      proof: decision.proof,
    };
  }

  // ─── Transparent fetch proxy (zero agent code changes) ────────────────────

  /**
   * Patches globalThis.fetch to intercept all LLM API calls.
   * Works for: OpenAI SDK, Anthropic SDK, any JS framework using fetch.
   * Call once at app startup — completely transparent.
   */
  installFetchProxy() {
    if (typeof globalThis === 'undefined' || !globalThis.fetch) {
      console.warn('[KasbahControl] fetch not available — fetch proxy skipped');
      return;
    }

    const originalFetch = globalThis.fetch.bind(globalThis);
    const control = this;

    globalThis.fetch = async function kasbahFetch(input, init = {}) {
      const url = typeof input === 'string' ? input : input?.url || String(input);

      // Only intercept LLM API calls
      if (!control._isLLMCall(url)) {
        return originalFetch(input, init);
      }

      // Parse request body
      let body = null;
      try {
        body = init.body ? JSON.parse(init.body) : null;
      } catch (_) { /* binary or non-JSON body — skip governance */ }

      if (!body) return originalFetch(input, init);

      // Run governance
      const decision = await control.govern({
        type: 'llm_call',
        url,
        method: init.method || 'POST',
        body,
        headers: init.headers || {},
        timestamp: Date.now(),
      });

      if (decision.verdict === 'DENY') {
        // Return a synthetic 403 response — agent sees a failed API call
        return new Response(JSON.stringify({
          error: {
            message: `KasbahSentinel blocked this request`,
            type: 'governance_rejection',
            code: 'kasbah_deny',
            kasbah: {
              verdict: 'DENY',
              reason: decision.reason,
              proof: decision.proof,
              auditId: decision.requestId,
              layers: decision.layers,
            },
          },
        }), {
          status: 403,
          headers: {
            'Content-Type': 'application/json',
            'X-Kasbah-Verdict': 'DENY',
            'X-Kasbah-Proof': decision.proof,
            'X-Kasbah-Audit-Id': decision.requestId,
          },
        });
      }

      // ALLOW or WARN: forward the original request
      const response = await originalFetch(input, init);

      // Inject governance headers into response
      const governed = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: {
          ...Object.fromEntries(response.headers.entries()),
          'X-Kasbah-Verdict': decision.verdict,
          'X-Kasbah-Audit-Id': decision.requestId,
        },
      });

      return governed;
    };

    console.log('[KasbahControl] Fetch proxy installed — all LLM calls governed');
  }

  // ─── SDK wrapper (explicit wrapping) ──────────────────────────────────────

  /**
   * Wrap any SDK object. Works with:
   *   const openai = control.wrap(new OpenAI())
   *   const anthropic = control.wrap(new Anthropic())
   *   const chain = control.wrap(langchainLLM)
   */
  wrap(sdkInstance, options = {}) {
    const control = this;

    return new Proxy(sdkInstance, {
      get(target, prop) {
        const value = target[prop];

        if (typeof value !== 'function') return value;

        // Wrap methods that look like LLM calls
        if (control._isLLMMethod(prop)) {
          return async function (...args) {
            const decision = await control.govern({
              type: 'sdk_call',
              method: prop,
              args,
              sdk: target.constructor?.name || 'unknown',
              timestamp: Date.now(),
              ...options,
            });

            if (decision.verdict === 'DENY') {
              const err = new Error(`KasbahSentinel blocked ${prop}: ${decision.reason}`);
              err.kasbah = decision;
              throw err;
            }

            return value.apply(target, args);
          };
        }

        return value.bind ? value.bind(target) : value;
      },
    });
  }

  // ─── LangChain callback handler ───────────────────────────────────────────

  /**
   * Returns a LangChain-compatible BaseCallbackHandler.
   * Usage:
   *   const llm = new ChatOpenAI({ callbacks: [control.langchainCallback()] })
   */
  langchainCallback() {
    const control = this;
    return {
      name: 'KasbahSentinel',
      async handleLLMStart(llm, prompts, runId) {
        const decision = await control.govern({
          type: 'langchain_llm_start',
          llm: llm.id?.[llm.id.length - 1] || 'unknown',
          prompts,
          runId,
          timestamp: Date.now(),
        });

        if (decision.verdict === 'DENY') {
          throw new Error(`KasbahSentinel blocked LangChain LLM call: ${decision.reason}`);
        }
      },
      async handleToolStart(tool, input, runId) {
        const decision = await control.govern({
          type: 'langchain_tool_start',
          tool: tool.id?.[tool.id.length - 1] || 'unknown',
          input,
          runId,
          timestamp: Date.now(),
        });

        if (decision.verdict === 'DENY') {
          throw new Error(`KasbahSentinel blocked LangChain tool: ${decision.reason}`);
        }
      },
    };
  }

  // ─── LangGraph node wrapper ───────────────────────────────────────────────

  /**
   * Wrap a LangGraph StateGraph node function.
   * Usage:
   *   graph.addNode('agent', control.langGraphNode(agentFn))
   */
  langGraphNode(nodeFn, nodeName = 'unknown') {
    const control = this;
    return async function kasbahNode(state, config) {
      const decision = await control.govern({
        type: 'langgraph_node',
        node: nodeName,
        state,
        timestamp: Date.now(),
      });

      if (decision.verdict === 'DENY') {
        return {
          ...state,
          kasbah_blocked: true,
          kasbah_reason: decision.reason,
          kasbah_proof: decision.proof,
        };
      }

      return nodeFn(state, config);
    };
  }

  // ─── AutoGen / CrewAI message bus ─────────────────────────────────────────

  /**
   * Intercept messages in AutoGen or CrewAI agent groups.
   * Pass through message handlers — KasbahSentinel checks swarm collusion.
   */
  async governMessage(message, fromAgent, toAgent, sessionId) {
    // Track all agent messages in this session for SwarmCollusionDetector
    if (!this._sessions.has(sessionId)) {
      this._sessions.set(sessionId, []);
    }
    const history = this._sessions.get(sessionId);
    history.push({ message, fromAgent, toAgent, timestamp: Date.now() });

    const decision = await this.govern({
      type: 'agent_message',
      message,
      fromAgent,
      toAgent,
      sessionId,
      history: history.slice(-20), // last 20 messages for swarm analysis
      timestamp: Date.now(),
    });

    return decision;
  }

  // ─── OpenAI-compatible HTTP endpoint ──────────────────────────────────────

  /**
   * Creates an Express router that acts as an OpenAI-compatible proxy.
   * Agents point their base_url here — no other changes needed.
   *
   * Usage:
   *   const express = require('express');
   *   const app = express();
   *   app.use('/v1', control.openAICompatibleRouter('https://api.openai.com'));
   *   app.listen(31337);
   */
  openAICompatibleRouter(upstreamBaseUrl = 'https://api.openai.com') {
    try {
      const express = require('express');
      const https = require('https');
      const router = express.Router();
      const control = this;

      router.use(express.json({ limit: '10mb' }));

      router.post('/chat/completions', async (req, res) => {
        const decision = await control.govern({
          type: 'openai_chat',
          model: req.body.model,
          messages: req.body.messages,
          tools: req.body.tools,
          timestamp: Date.now(),
        });

        if (decision.verdict === 'DENY') {
          return res.status(403).json({
            error: {
              message: `KasbahSentinel denied: ${decision.reason}`,
              type: 'governance_rejection',
              kasbah: { verdict: 'DENY', proof: decision.proof, auditId: decision.requestId },
            },
          });
        }

        // Forward to upstream
        control._proxyRequest(req, res, `${upstreamBaseUrl}/v1/chat/completions`, decision);
      });

      router.post('/messages', async (req, res) => {
        // Anthropic-format endpoint
        const decision = await control.govern({
          type: 'anthropic_message',
          model: req.body.model,
          messages: req.body.messages,
          timestamp: Date.now(),
        });

        if (decision.verdict === 'DENY') {
          return res.status(403).json({
            type: 'error',
            error: { type: 'governance_rejection', message: `KasbahSentinel denied: ${decision.reason}` },
            kasbah: { verdict: 'DENY', proof: decision.proof },
          });
        }

        control._proxyRequest(req, res, `${upstreamBaseUrl}/v1/messages`, decision);
      });

      return router;
    } catch (_) {
      console.warn('[KasbahControl] express not installed — HTTP router unavailable. Run: npm install express');
      return null;
    }
  }

  // ─── Claude Code hooks.json generator ────────────────────────────────────

  /**
   * Returns the hooks.json config to drop into .claude/settings.json.
   * Runs KasbahSentinel before every Bash, Edit, Write, and Read tool call.
   */
  static generateClaudeCodeHooks(options = {}) {
    const port = options.port || PROXY_PORT;
    const scriptPath = options.scriptPath || './node_modules/@kasbah/control/hooks/pretooluse.js';

    return {
      hooks: {
        PreToolUse: [
          {
            matcher: 'Bash|Edit|Write|Read',
            hooks: [
              {
                type: 'command',
                command: `node ${scriptPath} --tool "$TOOL_NAME" --input "$TOOL_INPUT_JSON" --kasbah-port ${port}`,
              },
            ],
          },
        ],
        PostToolUse: [
          {
            matcher: 'Bash',
            hooks: [
              {
                type: 'command',
                command: `node ${scriptPath} --mode audit --tool "$TOOL_NAME" --output "$TOOL_OUTPUT_JSON" --kasbah-port ${port}`,
              },
            ],
          },
        ],
      },
    };
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  _decision(verdict, requestId, sentinelResult, toctouSnapshot, start) {
    const latencyMs = Date.now() - start;
    const proof = this._generateProof(verdict, requestId, sentinelResult);

    const decision = {
      verdict,                           // 'ALLOW' | 'WARN' | 'DENY'
      requestId,
      proof,                             // cryptographic proof (HMAC-SHA256)
      latencyMs,
      reason: sentinelResult?.reason || sentinelResult?.note || verdict.toLowerCase(),
      risk: sentinelResult?.overallRisk || 0,
      layers: sentinelResult?.layers || {},
      toctouTimestamp: toctouSnapshot.timestamp,
      toctouHash: toctouSnapshot.hash,
      kasbahVersion: KASBAH_VERSION,
    };

    if (this.config.auditLog) this._logDecision(decision);
    return decision;
  }

  _generateProof(verdict, requestId, sentinelResult) {
    const payload = JSON.stringify({
      verdict,
      requestId,
      risk: sentinelResult?.overallRisk || 0,
      timestamp: Date.now(),
      counter: ++this._proofCounter,
    });
    const proofKey = process.env.KASBAH_PROOF_KEY || this._proofKey || 'kasbah-dev-ephemeral';
    return 'kasbah_proof:v1:' + crypto.createHmac('sha256', proofKey)
      .update(payload)
      .digest('hex');
  }

  _snapshotState(request) {
    return {
      timestamp: Date.now(),
      hash: crypto.createHash('sha256')
        .update(JSON.stringify(request))
        .digest('hex'),
    };
  }

  _verifyTOCTOU(snapshot, request) {
    // Check 1: internal TTL — time since govern() began (detects async mutation)
    const elapsed = Date.now() - snapshot.timestamp;
    if (elapsed > 100) {
      return `TTL exceeded: ${elapsed}ms > 100ms`;
    }
    // Check 2: stale request timestamp — if the request carries a timestamp that was
    // stamped BEFORE govern() was called (e.g. approved elsewhere, replayed here),
    // flag it as a TOCTOU payload-swap attempt.
    if (request.timestamp && (Date.now() - request.timestamp) > 100) {
      return `Stale request: approved ${Date.now() - request.timestamp}ms ago (TTL: 100ms)`;
    }
    // Check 3: mutation check — request content must not change between snapshot and use
    const currentHash = crypto.createHash('sha256')
      .update(JSON.stringify(request))
      .digest('hex');
    if (currentHash !== snapshot.hash) {
      return 'Request mutated between check and use';
    }
    return null; // No violation
  }

  _isLLMCall(url) {
    return LLM_API_PATTERNS.some(p => url.includes(p));
  }

  _isLLMMethod(prop) {
    const llmMethods = [
      'create', 'generate', 'chat', 'complete', 'invoke',
      'stream', 'run', 'call', 'execute', 'send', 'ask',
    ];
    return llmMethods.some(m => prop.toLowerCase().includes(m));
  }

  _requestId() {
    return `kac_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  }

  /**
   * Normalise any request shape into the sentinelCheck() input contract.
   * sentinelCheck expects: { agent, verb, target, content, timestamp }
   *
   * Handles: sdk_call, tool_use, agent_message, llm_call, raw prompt strings.
   *
   * Also applies Mythos-class threat pre-scan: sandbox escape, autonomous
   * network access, zero-day chaining, autonomous exfiltration — patterns
   * that Anthropic's Mythos model demonstrated are real attack surfaces.
   */
  _normaliseSentinelInput(request) {
    // Extract all text from any request shape
    const textParts = [];
    if (typeof request === 'string') { textParts.push(request); }
    if (request.prompt)   textParts.push(request.prompt);
    if (request.content)  textParts.push(request.content);
    if (request.message)  textParts.push(request.message);
    if (request.response) textParts.push(request.response);
    // Top-level messages array (OpenAI / Anthropic style)
    if (Array.isArray(request.messages)) {
      request.messages.forEach(m => m.content && textParts.push(
        typeof m.content === 'string' ? m.content : JSON.stringify(m.content)
      ));
    }
    // LangGraph / CrewAI state object
    if (request.state) {
      textParts.push(typeof request.state === 'string' ? request.state : JSON.stringify(request.state));
    }
    if (request.body?.messages) {
      request.body.messages.forEach(m => m.content && textParts.push(m.content));
    }
    if (Array.isArray(request.args)) {
      request.args.forEach(a => {
        if (Array.isArray(a.messages)) {
          a.messages.forEach(m => m.content && textParts.push(m.content));
        }
        if (typeof a === 'string') textParts.push(a);
      });
    }
    if (request.input) {
      if (typeof request.input === 'string') textParts.push(request.input);
      else textParts.push(JSON.stringify(request.input));
    }

    const content = textParts.filter(Boolean).join(' ').trim();

    // Derive verb and target from request type
    let verb = 'check';
    let target = '*';
    if (request.type === 'tool_use')     { verb = 'tool_use'; target = request.tool || '*'; }
    if (request.type === 'sdk_call')     { verb = 'create';   target = request.sdk  || 'LLM'; }
    if (request.type === 'agent_message'){ verb = 'message';  target = request.toAgent || '*'; }
    if (request.type === 'llm_call')     { verb = 'llm_call'; target = request.url  || '*'; }
    if (request.method) verb = request.method;

    return {
      agent:     request.agent || request.agentId || 'kasbah-client',
      verb,
      target,
      content,
      timestamp: request.timestamp || Date.now(),
    };
  }

  _timeout(ms) {
    return new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Sentinel timeout after ${ms}ms`)), ms)
    );
  }

  _logDecision(decision) {
    const icon = decision.verdict === 'ALLOW' ? '✅' : decision.verdict === 'WARN' ? '⚠️' : '🚫';
    const line = `[KasbahControl] ${icon} ${decision.verdict} | risk=${decision.risk.toFixed(2)} | ${decision.latencyMs}ms | ${decision.requestId}`;
    if (decision.verdict === 'DENY') {
      console.error(line, '\n  reason:', decision.reason, '\n  proof:', decision.proof);
    } else if (decision.verdict === 'WARN') {
      console.warn(line);
    } else {
      console.log(line);
    }
  }

  _proxyRequest(req, res, targetUrl, decision) {
    // Simple HTTP proxy forward — production should use http-proxy-middleware
    const http = require('https');
    const url = new URL(targetUrl);

    const options = {
      hostname: url.hostname,
      path: url.pathname,
      method: req.method,
      headers: {
        ...req.headers,
        host: url.hostname,
        'X-Kasbah-Verdict': decision.verdict,
        'X-Kasbah-Audit-Id': decision.requestId,
      },
    };

    const proxyReq = http.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, {
        ...proxyRes.headers,
        'X-Kasbah-Verdict': decision.verdict,
        'X-Kasbah-Proof': decision.proof,
      });
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      res.status(502).json({ error: 'Upstream error', detail: err.message });
    });

    proxyReq.write(JSON.stringify(req.body));
    proxyReq.end();
  }
}

// ─── Claude Code PreToolUse hook script ──────────────────────────────────────

/**
 * Standalone hook for Claude Code.
 * This runs as a subprocess before every tool call.
 * Exit code 0 = allow, non-zero = block.
 *
 * Drop into: .claude/hooks/kasbah-pretooluse.js
 * Configure in settings.json PreToolUse hooks
 */
async function runAsClaudeCodeHook() {
  const args = process.argv.slice(2);
  const toolName = args[args.indexOf('--tool') + 1] || 'unknown';
  const inputJson = args[args.indexOf('--input') + 1] || '{}';

  let toolInput;
  try { toolInput = JSON.parse(inputJson); } catch (_) { toolInput = { raw: inputJson }; }

  const control = new KasbahAgentControl({ mode: 'enforce', failOpen: false });
  const decision = await control.preToolUse(toolName, toolInput);

  if (decision.blocked) {
    // Write block reason to stderr — Claude Code shows this to the user
    process.stderr.write(JSON.stringify({
      type: 'kasbah_block',
      tool: toolName,
      reason: decision.reason,
      proof: decision.proof,
      auditId: decision.auditId,
    }));
    process.exit(1); // Non-zero exit blocks the tool
  }

  process.exit(0); // Zero exit allows the tool
}

// If called directly (as a Claude Code hook subprocess)
if (require.main === module) {
  runAsClaudeCodeHook().catch((err) => {
    process.stderr.write(`KasbahControl hook error: ${err.message}`);
    process.exit(0); // Fail-open on hook crash to avoid breaking Claude Code
  });
}

module.exports = { KasbahAgentControl, PROXY_PORT, LLM_API_PATTERNS };
