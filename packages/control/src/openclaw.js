'use strict';

/**
 * @kasbah/control/openclaw
 * OpenClaw Integration Adapter
 *
 * Plugs Kasbah Agent Control into OpenClaw's agent lifecycle:
 *   - Gateway middleware (intercepts all agent ↔ LLM traffic)
 *   - Agent wrapper (governs individual agent actions)
 *   - Channel guard (monitors incoming channel messages)
 *   - Cron/Webhook audit (governs automated task execution)
 *
 * Usage:
 *   const { KasbahOpenClaw } = require('@kasbah/control/openclaw');
 *   const guard = new KasbahOpenClaw({ mode: 'enforce' });
 *   guard.installGatewayMiddleware(gateway);
 */

const { KasbahAgentControl } = require('./kasbah-agent-control.js');

class KasbahOpenClaw {
  constructor(config = {}) {
    this.control = new KasbahAgentControl({
      mode: config.mode || 'enforce',
      failOpen: config.failOpen || false,
      timeoutMs: config.timeoutMs || 50,
      auditLog: config.auditLog !== false,
      policyPath: config.policyPath,
    });

    this._agentSessions = new Map();
    this._channelPolicies = new Map();
  }

  // ─── Gateway Middleware ──────────────────────────────────────────────────────
  //
  // OpenClaw Gateway is the central hub. All agent ↔ LLM traffic flows through it.
  // This middleware intercepts at the gateway level — every agent is governed.

  /**
   * Install as OpenClaw Gateway middleware.
   * Intercepts all agent requests before they reach the LLM.
   *
   * @param {object} gateway - OpenClaw gateway instance
   * @returns {void}
   */
  installGatewayMiddleware(gateway) {
    // Strategy 1: If gateway exposes middleware hooks
    if (gateway && typeof gateway.use === 'function') {
      gateway.use(this._gatewayMiddleware());
      console.log('[Kasbah×OpenClaw] Gateway middleware installed');
      return;
    }

    // Strategy 2: Transparent fetch proxy (works regardless of gateway internals)
    this.control.installFetchProxy();
    console.log('[Kasbah×OpenClaw] Fetch proxy installed on gateway process');
  }

  /**
   * Express-style middleware for OpenClaw Gateway.
   * Inspects every request, runs 13-layer governance, blocks or allows.
   */
  _gatewayMiddleware() {
    const control = this.control;
    const sessions = this._agentSessions;

    return async (req, res, next) => {
      // Extract agent context from OpenClaw request headers/body
      const agentId = req.headers['x-openclaw-agent-id'] || req.body?.agent_id || 'unknown';
      const channelId = req.headers['x-openclaw-channel-id'] || req.body?.channel_id;
      const sessionId = req.headers['x-openclaw-session-id'] || `oc_${agentId}_${Date.now()}`;

      // Build governance request with OpenClaw context
      const govRequest = {
        type: 'openclaw_gateway',
        agentId,
        channelId,
        sessionId,
        method: req.method,
        path: req.path,
        body: req.body,
        timestamp: Date.now(),
      };

      // Track session for swarm detection across OpenClaw agents
      if (!sessions.has(sessionId)) sessions.set(sessionId, []);
      sessions.get(sessionId).push(govRequest);

      const decision = await control.govern(govRequest);

      // Inject Kasbah headers into response
      res.setHeader('X-Kasbah-Verdict', decision.verdict);
      res.setHeader('X-Kasbah-Audit-Id', decision.requestId);

      if (decision.verdict === 'DENY') {
        return res.status(403).json({
          error: 'KasbahSentinel blocked this agent action',
          kasbah: {
            verdict: 'DENY',
            reason: decision.reason,
            proof: decision.proof,
            auditId: decision.requestId,
            risk: decision.risk,
            layers: decision.layers,
          },
        });
      }

      next();
    };
  }

  // ─── Agent Wrapper ──────────────────────────────────────────────────────────
  //
  // Wraps an individual OpenClaw agent. Every message the agent sends or receives
  // passes through Kasbah governance. Useful for per-agent policies.

  /**
   * Wrap an OpenClaw agent with Kasbah governance.
   *
   * @param {object} agent - OpenClaw agent instance
   * @param {object} options - Per-agent policy overrides
   * @returns {Proxy} Governed agent
   *
   * Usage:
   *   const agent = openclaw.createAgent({ name: 'researcher' });
   *   const safeAgent = guard.wrapAgent(agent, { maxRisk: 0.5 });
   */
  wrapAgent(agent, options = {}) {
    const control = this.control;
    const agentId = agent.id || agent.name || 'unnamed';

    return new Proxy(agent, {
      get(target, prop) {
        const value = target[prop];
        if (typeof value !== 'function') return value;

        // Govern message-sending methods
        const governedMethods = ['send', 'message', 'chat', 'ask', 'execute', 'run', 'reply'];
        if (governedMethods.some(m => prop.toLowerCase().includes(m))) {
          return async function (...args) {
            const content = typeof args[0] === 'string' ? args[0] : JSON.stringify(args[0]);

            const decision = await control.govern({
              type: 'openclaw_agent',
              agentId,
              method: prop,
              content,
              args,
              timestamp: Date.now(),
            });

            if (decision.verdict === 'DENY') {
              const err = new Error(
                `[Kasbah×OpenClaw] Agent "${agentId}" blocked: ${decision.reason}`
              );
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

  // ─── Channel Guard ──────────────────────────────────────────────────────────
  //
  // OpenClaw channels (Discord, Telegram, Slack, etc.) receive external input.
  // The channel guard screens incoming messages before they reach agents.

  /**
   * Guard an OpenClaw channel. Screens all incoming messages.
   *
   * @param {object} channel - OpenClaw channel instance
   * @param {object} policy - Channel-specific policy
   * @returns {void}
   *
   * Usage:
   *   guard.guardChannel(discordChannel, {
   *     denyPatterns: ['rm -rf', 'DROP TABLE'],
   *     maxRisk: 0.6,
   *   });
   */
  guardChannel(channel, policy = {}) {
    const channelId = channel.id || channel.name || 'unknown';
    this._channelPolicies.set(channelId, policy);

    const control = this.control;

    // Hook into channel message handler
    if (channel.onMessage) {
      const originalHandler = channel.onMessage.bind(channel);
      channel.onMessage = async (message, context) => {
        const decision = await control.govern({
          type: 'openclaw_channel_input',
          channelId,
          message: typeof message === 'string' ? message : message.content || JSON.stringify(message),
          sender: context?.sender || message?.author || 'external',
          timestamp: Date.now(),
        });

        if (decision.verdict === 'DENY') {
          console.warn(
            `[Kasbah×OpenClaw] Channel "${channelId}" input blocked:`,
            decision.reason
          );
          return; // Silently drop blocked messages
        }

        return originalHandler(message, context);
      };
    }

    console.log(`[Kasbah×OpenClaw] Channel "${channelId}" guarded`);
  }

  // ─── Cron/Webhook Audit ─────────────────────────────────────────────────────
  //
  // OpenClaw cron jobs and webhooks execute without human oversight.
  // This wrapper ensures automated actions are governed.

  /**
   * Wrap an OpenClaw cron job or webhook handler with governance.
   *
   * @param {function} handler - The cron/webhook handler function
   * @param {string} name - Job name for audit trail
   * @returns {function} Governed handler
   *
   * Usage:
   *   openclaw.cron('0 * * * *', guard.governAutomation(myJob, 'hourly-report'));
   */
  governAutomation(handler, name = 'unnamed-automation') {
    const control = this.control;

    return async function (...args) {
      const decision = await control.govern({
        type: 'openclaw_automation',
        automationName: name,
        args: args.map(a => typeof a === 'string' ? a : JSON.stringify(a)),
        timestamp: Date.now(),
      });

      if (decision.verdict === 'DENY') {
        console.error(
          `[Kasbah×OpenClaw] Automation "${name}" blocked:`,
          decision.reason,
          '\n  proof:', decision.proof
        );
        return { blocked: true, kasbah: decision };
      }

      return handler(...args);
    };
  }

  // ─── Multi-Agent Swarm Monitor ──────────────────────────────────────────────
  //
  // OpenClaw can run multiple agents that communicate. This monitors
  // inter-agent traffic for coordinated attacks (swarm collusion).

  /**
   * Monitor agent-to-agent messages for swarm collusion.
   *
   * @param {string} fromAgent - Sending agent ID
   * @param {string} toAgent - Receiving agent ID
   * @param {string} message - Message content
   * @param {string} sessionId - Session identifier
   * @returns {Promise<object>} Governance decision
   */
  async governAgentMessage(fromAgent, toAgent, message, sessionId) {
    return this.control.governMessage(message, fromAgent, toAgent, sessionId);
  }

  // ─── OpenClaw CLI Hook ──────────────────────────────────────────────────────
  //
  // For users running `openclaw agent --message "..."` from the terminal.

  /**
   * Generate OpenClaw configuration that routes through Kasbah.
   * Sets the LLM base_url to Kasbah's proxy.
   *
   * @param {object} options
   * @returns {object} OpenClaw config patch
   */
  static generateOpenClawConfig(options = {}) {
    const port = options.port || 31337;
    return {
      // OpenClaw config: route LLM traffic through Kasbah proxy
      gateway: {
        llm: {
          base_url: `http://localhost:${port}/v1`,
          // Original API key is passed through — Kasbah only inspects, never stores
        },
      },
      // Kasbah metadata
      kasbah: {
        enabled: true,
        mode: options.mode || 'enforce',
        port,
        version: '1.0.0',
      },
    };
  }

  /**
   * Start the Kasbah proxy server for OpenClaw.
   * OpenClaw agents point base_url here.
   *
   * @param {object} options
   * @returns {Promise<object>} Server instance
   */
  async startProxy(options = {}) {
    const port = options.port || 31337;
    const upstream = options.upstream || 'https://api.openai.com';

    try {
      const express = require('express');
      const app = express();

      app.use(express.json({ limit: '10mb' }));

      // Health check
      app.get('/health', (req, res) => {
        res.json({
          status: 'ok',
          service: 'kasbah-openclaw-proxy',
          mode: this.control.config.mode,
          version: '1.0.0',
        });
      });

      // OpenAI-compatible governance proxy
      const router = this.control.openAICompatibleRouter(upstream);
      if (router) {
        app.use('/v1', router);
      }

      return new Promise((resolve) => {
        const server = app.listen(port, () => {
          console.log(`[Kasbah×OpenClaw] Proxy running on port ${port}`);
          console.log(`[Kasbah×OpenClaw] Set OpenClaw base_url to: http://localhost:${port}/v1`);
          resolve(server);
        });
      });
    } catch (err) {
      console.error('[Kasbah×OpenClaw] Could not start proxy:', err.message);
      console.log('[Kasbah×OpenClaw] Falling back to fetch proxy mode');
      this.control.installFetchProxy();
      return null;
    }
  }
}

module.exports = { KasbahOpenClaw };
module.exports.default = KasbahOpenClaw;
