/**
 * Kasbah + QuranFrontier Integration Bootstrap
 *
 * Initializes and wires all governance and QuranFrontier components.
 * This is the main integration point that orchestrates:
 * - QuranFrontierBridge (all 5 sub-bridges)
 * - ChainMonitor (defensive reasoning)
 * - ToolGuard (tool call validation)
 * - AgentSession (decision quality tracking)
 */

const QuranFrontierBridge = require('./engines/quran-frontier-bridge');
const { ChainMonitor, ToolGuard, AgentSession } = require('./governance-engine');

// ── Singleton instances ────────────────────────────────────────────────────────

let quranFrontierBridge = null;
let chainMonitor = null;
let toolGuard = null;
const agentSessions = new Map(); // agentId → AgentSession

/**
 * Initialize all QuranFrontier bridges and governance systems
 * Call this once at app startup
 */
async function initializeQuranFrontier(config = {}) {
  console.log('[QF-Integration] Initializing QuranFrontier bridges...');

  try {
    // Initialize QuranFrontierBridge
    quranFrontierBridge = new QuranFrontierBridge({
      bulmaApiUrl: process.env.BULMA_API_URL || 'http://localhost:8000',
      pythonServiceUrl: process.env.PYTHON_SERVICE_URL || 'http://localhost:9000',
      frontierServiceUrl: process.env.FRONTIER_SERVICE_URL || 'http://localhost:9000',
      enableBulma: process.env.ENABLE_BULMA_BRIDGE !== 'false',
      enableReasoning: process.env.ENABLE_REASONING_BRIDGE !== 'false',
      enableAlgorithms: process.env.ENABLE_ALGORITHMS_BRIDGE !== 'false',
      enableVerification: process.env.ENABLE_VERIFICATION_BRIDGE !== 'false',
      enableFrontier: process.env.ENABLE_FRONTIER_BRIDGE !== 'false',
      cacheSize: parseInt(process.env.BULMA_CACHE_SIZE) || 10000,
      cacheTTL: parseInt(process.env.BULMA_CACHE_TTL) || 300000,
      timeout: parseInt(process.env.BULMA_TIMEOUT) || 5000,
      ...config
    });

    // Initialize ChainMonitor with Bulma integration
    chainMonitor = new ChainMonitor();
    chainMonitor.setBulmaEngine(quranFrontierBridge);

    // Initialize ToolGuard with Reasoning integration
    toolGuard = new ToolGuard();
    toolGuard.setReasoningBridge(quranFrontierBridge);

    // Health check with timeout
    let healthStatus = { status: 'timeout', message: 'Health check timed out' };
    try {
      const healthPromise = quranFrontierBridge.healthCheck();
      healthStatus = await Promise.race([
        healthPromise,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Health check timeout')), 5000)
        )
      ]);
    } catch (healthError) {
      console.warn('[QF-Integration] Health check failed or timed out:', healthError.message);
      healthStatus = { status: 'unavailable', message: healthError.message };
    }

    console.log('[QF-Integration] Bridge status:', healthStatus.status || 'initialized');
    console.log('[QF-Integration] ✅ All systems initialized successfully');

    return {
      bridge: quranFrontierBridge,
      monitor: chainMonitor,
      guard: toolGuard,
      health: healthStatus
    };

  } catch (error) {
    console.warn('[QF-Integration] Initialization warning:', error.message);
    // Don't throw - allow graceful degradation
    return {
      bridge: null,
      monitor: null,
      guard: null,
      health: { status: 'failed', message: error.message }
    };
  }
}

/**
 * Get or create an AgentSession for an agent
 */
function getOrCreateAgentSession(agentId) {
  if (!agentSessions.has(agentId)) {
    const session = new AgentSession(agentId);
    if (quranFrontierBridge) {
      session.setReasoningBridge(quranFrontierBridge);
    }
    agentSessions.set(agentId, session);
    console.log(`[AgentSession] Created session for agent: ${agentId}`);
  }
  return agentSessions.get(agentId);
}

/**
 * Get all active agent sessions
 */
function getAgentSessions() {
  return Array.from(agentSessions.entries()).map(([id, session]) => ({
    agentId: id,
    decisionsLogged: session.decisions.length,
    scoredDecisions: session.scoringHistory.length,
    averageScore: session.getDefensibilityReport().average_score
  }));
}

/**
 * Shutdown cleanup
 */
async function shutdown() {
  console.log('[QF-Integration] Shutting down...');

  // Save session reports if needed
  for (const [agentId, session] of agentSessions) {
    console.log(`[AgentSession] ${agentId} report:`, session.getDefensibilityReport());
  }

  agentSessions.clear();
  quranFrontierBridge = null;
  chainMonitor = null;
  toolGuard = null;

  console.log('[QF-Integration] ✅ Shutdown complete');
}

module.exports = {
  initializeQuranFrontier,
  getQuranFrontierBridge: () => quranFrontierBridge,
  getChainMonitor: () => chainMonitor,
  getToolGuard: () => toolGuard,
  getOrCreateAgentSession,
  getAgentSessions,
  shutdown
};
