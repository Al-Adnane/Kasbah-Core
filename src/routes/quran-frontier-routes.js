/**
 * QuranFrontier Bridge API Routes
 *
 * Exposes QuranFrontier capabilities via REST API:
 * - /v1/qf-bridge/audit               - Defensibility auditing (ChainMonitor)
 * - /v1/qf-bridge/validate-tool       - Tool call validation (ToolGuard)
 * - /v1/qf-bridge/score-decision      - Decision quality scoring (AgentSession)
 * - /v1/qf-bridge/session             - Agent session management
 * - /v1/qf-bridge/health              - Bridge health check
 * - /v1/qf-bridge/status              - Integration status
 */

const express = require('express');
const {
  initializeQuranFrontier,
  getQuranFrontierBridge,
  getChainMonitor,
  getToolGuard,
  getOrCreateAgentSession,
  getAgentSessions
} = require('../app');

const router = express.Router();

/**
 * POST /v1/qf-bridge/audit
 * Analyze reasoning defensibility using Bulma Auditor
 *
 * Body: {
 *   claims: string[],
 *   evidence: string[],
 *   narrative: string
 * }
 */
router.post('/qf-bridge/audit', async (req, res) => {
  try {
    const bridge = getQuranFrontierBridge();
    if (!bridge) {
      return res.status(503).json({
        error: 'QuranFrontier bridge not initialized',
        code: 'BRIDGE_NOT_READY'
      });
    }

    const { claims, evidence = [], narrative = '' } = req.body;

    if (!claims || !Array.isArray(claims) || claims.length === 0) {
      return res.status(400).json({
        error: 'claims required and must be non-empty array',
        code: 'INVALID_INPUT'
      });
    }

    const result = await bridge.auditDefensibility(claims, evidence, narrative);

    res.json({
      success: true,
      audit: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[qf-bridge] Audit error:', error);
    res.status(500).json({
      error: error.message,
      code: 'AUDIT_ERROR'
    });
  }
});

/**
 * POST /v1/qf-bridge/validate-tool
 * Validate a tool call using ToolGuard
 *
 * Body: {
 *   tool_name: string,
 *   args: object,
 *   reasoning: string
 * }
 */
router.post('/qf-bridge/validate-tool', async (req, res) => {
  try {
    const guard = getToolGuard();
    if (!guard) {
      return res.status(503).json({
        error: 'ToolGuard not initialized',
        code: 'GUARD_NOT_READY'
      });
    }

    const { tool_name, args = {}, reasoning = '' } = req.body;

    if (!tool_name || typeof tool_name !== 'string') {
      return res.status(400).json({
        error: 'tool_name required (string)',
        code: 'INVALID_INPUT'
      });
    }

    const result = await guard.validateCall(tool_name, args, reasoning);

    res.json({
      success: true,
      validation: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[qf-bridge] Tool validation error:', error);
    res.status(500).json({
      error: error.message,
      code: 'VALIDATION_ERROR'
    });
  }
});

/**
 * POST /v1/qf-bridge/score-decision
 * Score a decision using AgentSession
 *
 * Body: {
 *   agent_id: string,
 *   type: string (e.g., 'decision'),
 *   message: string,
 *   reasoning: string
 * }
 */
router.post('/qf-bridge/score-decision', async (req, res) => {
  try {
    const { agent_id, type = 'decision', message = '', reasoning = '' } = req.body;

    if (!agent_id || typeof agent_id !== 'string') {
      return res.status(400).json({
        error: 'agent_id required (string)',
        code: 'INVALID_INPUT'
      });
    }

    const session = getOrCreateAgentSession(agent_id);
    const logEntry = await session.log({
      type,
      message,
      reasoning
    });

    res.json({
      success: true,
      entry: logEntry,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[qf-bridge] Decision scoring error:', error);
    res.status(500).json({
      error: error.message,
      code: 'SCORING_ERROR'
    });
  }
});

/**
 * GET /v1/qf-bridge/session/:agent_id
 * Get defensibility report for an agent session
 */
router.get('/qf-bridge/session/:agent_id', (req, res) => {
  try {
    const { agent_id } = req.params;
    const session = getOrCreateAgentSession(agent_id);
    const report = session.getDefensibilityReport();

    res.json({
      success: true,
      agent_id,
      report,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[qf-bridge] Session report error:', error);
    res.status(500).json({
      error: error.message,
      code: 'REPORT_ERROR'
    });
  }
});

/**
 * GET /v1/qf-bridge/sessions
 * List all active agent sessions
 */
router.get('/qf-bridge/sessions', (req, res) => {
  try {
    const sessions = getAgentSessions();

    res.json({
      success: true,
      sessions,
      count: sessions.length,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[qf-bridge] Sessions list error:', error);
    res.status(500).json({
      error: error.message,
      code: 'LIST_ERROR'
    });
  }
});

/**
 * POST /v1/qf-bridge/chain-monitor/analyze
 * Analyze a reasoning turn using ChainMonitor
 *
 * Body: {
 *   message: string,
 *   evidence: string[],
 *   context: string
 * }
 */
router.post('/qf-bridge/chain-monitor/analyze', async (req, res) => {
  try {
    const monitor = getChainMonitor();
    if (!monitor) {
      return res.status(503).json({
        error: 'ChainMonitor not initialized',
        code: 'MONITOR_NOT_READY'
      });
    }

    const { message = '', evidence = [], context = '' } = req.body;

    const result = await monitor.analyzeTurn({
      message,
      evidence,
      context
    });

    res.json({
      success: true,
      analysis: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[qf-bridge] Chain monitor error:', error);
    res.status(500).json({
      error: error.message,
      code: 'MONITOR_ERROR'
    });
  }
});

/**
 * GET /v1/qf-bridge/health
 * Health check all QuranFrontier bridges
 */
router.get('/qf-bridge/health', async (req, res) => {
  try {
    const bridge = getQuranFrontierBridge();
    if (!bridge) {
      return res.status(503).json({
        status: 'not_ready',
        error: 'QuranFrontier bridge not initialized'
      });
    }

    const health = await bridge.healthCheck();

    res.json({
      status: 'healthy',
      bridges: health,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[qf-bridge] Health check error:', error);
    res.status(503).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

/**
 * GET /v1/qf-bridge/status
 * Get integration status and statistics
 */
router.get('/qf-bridge/status', (req, res) => {
  try {
    const bridge = getQuranFrontierBridge();
    const monitor = getChainMonitor();
    const guard = getToolGuard();
    const sessions = getAgentSessions();

    res.json({
      status: 'operational',
      components: {
        bridge: !!bridge,
        monitor: !!monitor,
        guard: !!guard
      },
      sessions: {
        active: sessions.length,
        summary: sessions
      },
      config: {
        bulmaApiUrl: process.env.BULMA_API_URL,
        enableBulma: process.env.ENABLE_BULMA_BRIDGE !== 'false',
        enableReasoning: process.env.ENABLE_REASONING_BRIDGE !== 'false',
        enableAlgorithms: process.env.ENABLE_ALGORITHMS_BRIDGE !== 'false',
        enableVerification: process.env.ENABLE_VERIFICATION_BRIDGE !== 'false',
        enableFrontier: process.env.ENABLE_FRONTIER_BRIDGE !== 'false'
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[qf-bridge] Status error:', error);
    res.status(500).json({
      error: error.message,
      code: 'STATUS_ERROR'
    });
  }
});

/**
 * POST /v1/qf-bridge/init
 * Force re-initialization of bridges
 * (Useful for reloading config without restarting)
 */
router.post('/qf-bridge/init', async (req, res) => {
  try {
    console.log('[qf-bridge] Manual initialization requested');

    const result = await initializeQuranFrontier(req.body || {});

    res.json({
      success: true,
      message: 'Bridges reinitialized successfully',
      health: result.health,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[qf-bridge] Initialization error:', error);
    res.status(500).json({
      error: error.message,
      code: 'INIT_ERROR'
    });
  }
});

module.exports = router;
