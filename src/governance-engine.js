/**
 * KASBAH GOVERNANCE ENGINE — PHASE 1 (PRODUCTION-READY)
 *
 * Minimal, secure policy enforcement engine for AI agents.
 *
 * Phase 1 Design:
 * ✅ Fail-closed architecture (any error = DENY)
 * ✅ Deterministic audit logging with policy versioning
 * ✅ Forbidden verbs, domain whitelisting, rate limiting
 * ✅ Observable: JSON logs with trace IDs
 * ❌ ZK proofs (defer to Phase 2)
 * ❌ require_approval workflows (defer to Phase 2)
 *
 * Security Principles:
 * - Fail-Closed: On any error, deny the action
 * - Observable: JSON-lines audit logs for full visibility
 * - Verifiable: Policy version hashing for audit verifiability
 * - Simple: No cryptographic proofs yet (complexity = risk)
 */

const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

// Bundled default policy — used when no policy file is found at the specified path.
// This ensures the package works standalone (npm install @kasbah/control) with
// sensible secure defaults out of the box.
const BUNDLED_DEFAULT_POLICY_PATH = path.join(__dirname, '.kasbahpolicy.json');

class GovernanceEngine {
  constructor(policyPath = '.kasbahpolicy.json') {
    this.policy = null;
    this.policyHash = null;
    this.auditLog = [];
    this.rateLimitBuckets = new Map();

    // Load policy (fail-closed if not found, falls back to bundled default)
    this.loadPolicy(policyPath);
  }

  /**
   * Load and validate policy file.
   * Resolution order:
   *   1. KASBAH_POLICY_FILE env var (absolute path)
   *   2. policyPath argument (relative to cwd or absolute)
   *   3. Bundled default policy shipped with the package
   *
   * Throws only if the bundled default is also missing (should never happen).
   */
  loadPolicy(policyPath) {
    // Allow env var override of policy path
    const envPath = process.env.KASBAH_POLICY_FILE;
    const candidates = [
      envPath,
      policyPath,
      BUNDLED_DEFAULT_POLICY_PATH,
    ].filter(Boolean);

    let lastError;
    for (const candidate of candidates) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const rawPolicy = fs.readFileSync(candidate, 'utf8');
        const policy = JSON.parse(rawPolicy);
        this.validatePolicy(policy);
        this.policy = policy;
        this.policyHash = this.computeHash(policy);
        return; // loaded successfully
      } catch (e) {
        lastError = e;
      }
    }

    // Nothing worked — fail-closed
    throw new Error(`[CRITICAL] Failed to load governance policy: ${lastError ? lastError.message : 'no candidates found'}`);
  }

  /**
   * Validate policy has correct structure
   */
  validatePolicy(policy) {
    if (!policy || typeof policy !== 'object') {
      throw new Error('Policy must be a JSON object');
    }

    if (!policy.version || typeof policy.version !== 'string') {
      throw new Error('Policy requires version field (string)');
    }

    if (!policy.governance || typeof policy.governance !== 'object') {
      throw new Error('Policy requires governance section (object)');
    }

    const g = policy.governance;

    // Validate field types
    if (g.forbidden_verbs && !Array.isArray(g.forbidden_verbs)) {
      throw new Error('forbidden_verbs must be array');
    }

    if (g.allowed_domains && !Array.isArray(g.allowed_domains)) {
      throw new Error('allowed_domains must be array');
    }

    if (g.rate_limits && typeof g.rate_limits !== 'object') {
      throw new Error('rate_limits must be object');
    }

    // Validate rate limits are positive integers
    if (g.rate_limits) {
      for (const [key, val] of Object.entries(g.rate_limits)) {
        if (!Number.isInteger(val) || val <= 0) {
          throw new Error(`rate_limits.${key} must be positive integer, got ${val}`);
        }
      }
    }
  }

  /**
   * MAIN: Evaluate an agent action against policy
   *
   * Returns decision object with:
   * - decision_id: unique identifier for this decision
   * - status: ALLOW or DENY
   * - reason: human-readable explanation
   * - policy_hash: SHA256 of policy (for audit verification)
   * - violations: array of policy violations
   * - latency_ms: how long evaluation took
   *
   * FAIL-CLOSED: Any error during evaluation returns DENY
   */
  async check(action) {
    const startTime = Date.now();
    const decisionId = this.generateId();
    const traceId = action.trace_id || decisionId;

    try {
      // Validate action (fail-closed if invalid)
      this.validateAction(action);

      const decision = {
        decision_id: decisionId,
        trace_id: traceId,
        timestamp: new Date().toISOString(),
        status: 'ALLOW',
        reason: 'No violations detected',
        policy_hash: this.policyHash,
        violations: [],
        risk_score: 0
      };

      // CHECK 1: Forbidden verbs (hard block)
      const forbiddenViolation = this.checkForbiddenVerbs(action);
      if (forbiddenViolation) {
        decision.violations.push(forbiddenViolation);
        decision.status = 'DENY';
        decision.reason = forbiddenViolation.reason;
        decision.risk_score = 95;
      }

      // CHECK 2: Domain whitelist (if configured)
      if (!forbiddenViolation && this.policy.governance.allowed_domains?.length > 0) {
        const domainViolation = this.checkDomainWhitelist(action);
        if (domainViolation) {
          decision.violations.push(domainViolation);
          decision.status = 'DENY';
          decision.reason = domainViolation.reason;
          decision.risk_score = 85;
        }
      }

      // CHECK 3: Rate limits (if configured)
      if (this.policy.governance.rate_limits && decision.status === 'ALLOW') {
        const rateViolation = this.checkRateLimits(action);
        if (rateViolation) {
          decision.violations.push(rateViolation);
          decision.status = 'DENY';
          decision.reason = rateViolation.reason;
          decision.risk_score = 75;
        }
      }

      // CHECK 4: Require-approval verbs (human-in-the-loop gate).
      // These are not forbidden, but cannot auto-execute — they must be
      // held for explicit human approval. Only applies when nothing has
      // already DENY'd the action.
      if (decision.status === 'ALLOW') {
        const approvalGate = this.checkRequireApproval(action);
        if (approvalGate) {
          decision.violations.push(approvalGate);
          decision.status = 'REQUIRE_APPROVAL';
          decision.reason = approvalGate.reason;
          decision.risk_score = Math.max(decision.risk_score, 50);
        }
      }

      // Record latency
      decision.latency_ms = Date.now() - startTime;

      // Log decision to audit trail
      this.logDecision(decision, action);

      return decision;

    } catch (e) {
      // FAIL-CLOSED: Any error during evaluation = DENY
      const decision = {
        decision_id: decisionId,
        trace_id: traceId,
        timestamp: new Date().toISOString(),
        status: 'DENY',
        reason: `Engine error (fail-closed): ${e.message}`,
        policy_hash: this.policyHash,
        violations: [{ type: 'engine_error', severity: 'critical' }],
        risk_score: 100,
        latency_ms: Date.now() - startTime
      };

      // Try to log the error
      try {
        this.logDecision(decision, action);
      } catch (logErr) {
        console.error(`[CRITICAL] Governance engine error + logging failure: ${logErr.message}`);
      }

      return decision;
    }
  }

  /**
   * Check if agent verb is forbidden
   */
  checkForbiddenVerbs(action) {
    const { verb } = action;
    const forbidden = this.policy.governance.forbidden_verbs || [];

    if (forbidden.includes(verb)) {
      return {
        type: 'forbidden_verb',
        severity: 'critical',
        reason: `Verb '${verb}' is forbidden by policy`
      };
    }

    return null;
  }

  /**
   * Check if a verb requires explicit human approval before executing.
   * Returns a violation object (gating the action to REQUIRE_APPROVAL) or null.
   */
  checkRequireApproval(action) {
    const { verb } = action;
    const gated = this.policy.governance.require_approval || [];

    if (gated.includes(verb)) {
      return {
        type: 'require_approval',
        severity: 'high',
        reason: `Verb '${verb}' requires explicit human approval before execution`
      };
    }

    return null;
  }

  /**
   * Check if target domain is whitelisted
   * If whitelist is empty, allow all domains
   */
  checkDomainWhitelist(action) {
    const { target } = action;
    const allowed = this.policy.governance.allowed_domains || [];

    if (allowed.length === 0) return null; // No whitelist

    const domain = this.extractDomain(target);
    const match = allowed.some(d => domain.includes(d) || d.includes(domain));

    if (!match) {
      return {
        type: 'domain_whitelist',
        severity: 'high',
        reason: `Domain '${domain}' not in whitelist`
      };
    }

    return null;
  }

  /**
   * Check rate limits using token bucket algorithm
   * Limits are per agent per verb
   */
  checkRateLimits(action) {
    const { agent, verb } = action;
    const limits = this.policy.governance.rate_limits || {};

    // Rate limit key: e.g., "DOWNLOAD_per_minute"
    const limitKey = `${verb.toUpperCase()}_per_minute`;
    const limit = limits[limitKey];

    if (!limit) return null; // No limit configured

    // Get or create token bucket for this agent/verb
    const bucketKey = `${agent}:${verb}`;
    const now = Date.now();
    let bucket = this.rateLimitBuckets.get(bucketKey);

    if (!bucket) {
      bucket = { tokens: limit, lastRefill: now };
    }

    // Refill tokens: linear replenishment over 60 seconds
    const elapsedSec = (now - bucket.lastRefill) / 1000;
    const tokensPerSec = limit / 60;
    bucket.tokens = Math.min(limit, bucket.tokens + elapsedSec * tokensPerSec);
    bucket.lastRefill = now;

    // Check if action is allowed
    if (bucket.tokens < 1) {
      return {
        type: 'rate_limit',
        severity: 'high',
        reason: `Rate limit exceeded (${limit}/min for ${verb})`
      };
    }

    // Consume token
    bucket.tokens -= 1;
    this.rateLimitBuckets.set(bucketKey, bucket);

    return null;
  }

  /**
   * Extract domain from target string
   */
  extractDomain(target) {
    try {
      if (target.startsWith('http://') || target.startsWith('https://')) {
        return new URL(target).hostname;
      }
      if (target.includes('@')) {
        return target.split('@')[1];
      }
      return target.split('/')[0];
    } catch {
      return target;
    }
  }

  /**
   * Validate action structure
   */
  validateAction(action) {
    if (!action || typeof action !== 'object') {
      throw new Error('Action must be object');
    }
    if (typeof action.agent !== 'string' || !action.agent) {
      throw new Error('Action.agent required (string)');
    }
    if (typeof action.verb !== 'string' || !action.verb) {
      throw new Error('Action.verb required (string)');
    }
    if (typeof action.target !== 'string' || !action.target) {
      throw new Error('Action.target required (string)');
    }
  }

  /**
   * Generate unique decision ID
   */
  generateId() {
    return `dec_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  }

  /**
   * Compute deterministic SHA256 hash of policy
   * Used for audit verification: auditor can replay decisions given policy version
   */
  computeHash(policy) {
    return crypto
      .createHash('sha256')
      .update(JSON.stringify(policy))
      .digest('hex');
  }

  /**
   * Log decision to audit trail (append-only)
   * Format: JSON-lines (one JSON object per line)
   * Includes: decision ID, status, violations, policy hash
   * Excludes: sensitive data, action payloads
   */
  logDecision(decision, action) {
    try {
      const logEntry = {
        decision_id: decision.decision_id,
        trace_id: decision.trace_id,
        timestamp: decision.timestamp,
        agent: action.agent,
        verb: action.verb,
        target: action.target,
        status: decision.status,
        violations: decision.violations.map(v => v.type),
        risk_score: decision.risk_score,
        policy_hash: decision.policy_hash,
        latency_ms: decision.latency_ms
      };

      // Store in memory
      this.auditLog.push(logEntry);

      // Append to audit log file (immutable, append-only)
      const auditPath = '.kasbah-audit.jsonl';
      fs.appendFileSync(auditPath, JSON.stringify(logEntry) + '\n');

    } catch (e) {
      // Log failure should not crash, but should be visible
      console.error(`[WARN] Audit log write failed: ${e.message}`);
    }
  }

  /**
   * Get summary of recent decisions (for monitoring)
   */
  getSummary(minutes = 60) {
    const since = new Date(Date.now() - minutes * 60000);
    const recent = this.auditLog.filter(e => new Date(e.timestamp) > since);

    const violations = {};
    recent.forEach(e => {
      (e.violations || []).forEach(v => {
        violations[v] = (violations[v] || 0) + 1;
      });
    });

    return {
      period_minutes: minutes,
      total: recent.length,
      allowed: recent.filter(e => e.status === 'ALLOW').length,
      denied: recent.filter(e => e.status === 'DENY').length,
      avg_latency_ms: recent.length > 0
        ? Math.round(recent.reduce((s, e) => s + (e.latency_ms || 0), 0) / recent.length)
        : 0,
      violations
    };
  }
}

/**
 * ChainMonitor — Defensive Reasoning Auditor
 *
 * Analyzes agent reasoning turns for defensibility issues.
 * Integrates with Bulma Auditor for multi-archetype analysis.
 *
 * Usage:
 *   const monitor = new ChainMonitor();
 *   monitor.setBulmaEngine(quranFrontierBridge);
 *   const result = await monitor.analyzeTurn({ message, evidence, context });
 */
class ChainMonitor {
  constructor() {
    this.bulmaEngine = null;
    this.turnHistory = [];
    this.riskThresholds = {
      manipulation: 0.7,
      fallacy: 0.6,
      contradiction: 0.8,
      unsupported_claim: 0.65
    };
  }

  setBulmaEngine(bridge) {
    this.bulmaEngine = bridge;
  }

  async analyzeTurn(turn) {
    const result = {
      turn_id: this.generateId(),
      timestamp: new Date().toISOString(),
      risks: [],
      defensibility: null,
      safe: true,
      latency_ms: 0
    };

    const startTime = Date.now();

    try {
      if (!this.bulmaEngine) {
        result.risks.push({
          type: 'missing_auditor',
          severity: 'warn',
          message: 'Bulma auditor not initialized'
        });
        return result;
      }

      // Extract claims from message using simple heuristic
      const claims = this.extractClaims(turn.message || '');
      const evidence = turn.evidence || [];
      const narrative = turn.context || '';

      // Audit defensibility via Bulma
      const auditResult = await this.bulmaEngine.auditDefensibility(claims, evidence, narrative);

      result.defensibility = auditResult;

      // Flag risks based on defensibility score
      if (auditResult.defensibility_score < this.riskThresholds.unsupported_claim) {
        result.risks.push({
          type: 'low_defensibility',
          severity: 'high',
          score: auditResult.defensibility_score,
          message: `Claims lack sufficient defensibility (${(auditResult.defensibility_score * 100).toFixed(1)}%)`
        });
        result.safe = false;
      }

      // Check for contradictions or fallacies in archetype scores
      if (auditResult.archetype_scores) {
        const weakArchetypes = auditResult.archetype_scores
          .filter(a => a.score < 0.5)
          .map(a => a.archetype);

        if (weakArchetypes.length > 0) {
          result.risks.push({
            type: 'weak_reasoning_archetypes',
            severity: 'medium',
            archetypes: weakArchetypes,
            message: `Weak reasoning in: ${weakArchetypes.join(', ')}`
          });
        }
      }

      // Flag if confidence is low
      if (auditResult.confidence_level === 'LOW') {
        result.risks.push({
          type: 'low_confidence',
          severity: 'medium',
          message: 'Confidence in claims is LOW'
        });
      }

      this.turnHistory.push(result);

    } catch (error) {
      result.risks.push({
        type: 'analysis_error',
        severity: 'critical',
        message: error.message
      });
      result.safe = false;
    }

    result.latency_ms = Date.now() - startTime;
    return result;
  }

  extractClaims(message) {
    // Simple heuristic: sentences ending with "is", "are", "will", etc.
    const sentences = message.split(/[.!?]+/).filter(s => s.trim().length > 0);
    return sentences.map(s => s.trim()).slice(0, 5); // Limit to first 5 claims
  }

  generateId() {
    return `turn_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  }

  getHistory() {
    return this.turnHistory;
  }
}

/**
 * ToolGuard — Tool Call Validator
 *
 * Validates tool invocations against reasoning quality.
 * Integrates with Strategic Reasoning Bridge.
 *
 * Usage:
 *   const guard = new ToolGuard();
 *   guard.setReasoningBridge(bridge);
 *   const result = await guard.validateCall(toolName, args, reasoning);
 */
class ToolGuard {
  constructor() {
    this.reasoningBridge = null;
    this.callLog = [];
    this.blockedTools = [];
  }

  setReasoningBridge(bridge) {
    this.reasoningBridge = bridge;
  }

  async validateCall(toolName, args, reasoning) {
    const result = {
      call_id: this.generateId(),
      timestamp: new Date().toISOString(),
      tool: toolName,
      allowed: true,
      reason: 'Tool call passed validation',
      reasoning_score: 0,
      latency_ms: 0,
      violations: []
    };

    const startTime = Date.now();

    try {
      // Check if tool is permanently blocked
      if (this.blockedTools.includes(toolName)) {
        result.allowed = false;
        result.reason = `Tool '${toolName}' is permanently blocked`;
        result.violations.push('blocked_tool');
        this.callLog.push(result);
        return result;
      }

      // Validate tool name format
      if (typeof toolName !== 'string' || toolName.length === 0) {
        result.allowed = false;
        result.reason = 'Invalid tool name';
        result.violations.push('invalid_tool_name');
        this.callLog.push(result);
        return result;
      }

      // If reasoning bridge available, validate reasoning quality
      if (this.reasoningBridge) {
        const validationResult = await this.reasoningBridge.validateToolCall(toolName, args, reasoning);

        result.reasoning_score = validationResult.score || 0;

        // Tool call must have minimum reasoning quality
        if (result.reasoning_score < 0.5) {
          result.allowed = false;
          result.reason = `Reasoning quality insufficient (${(result.reasoning_score * 100).toFixed(1)}%)`;
          result.violations.push('low_reasoning_quality');
        }

        if (validationResult.violations) {
          result.violations.push(...validationResult.violations);
        }
      }

      // Sensitive tools require higher reasoning quality
      const sensitiveTools = ['DELETE_DATABASE', 'MODIFY_POLICY', 'EXECUTE_CODE', 'SEND_MESSAGE'];
      if (sensitiveTools.includes(toolName.toUpperCase())) {
        if (result.reasoning_score < 0.7) {
          result.allowed = false;
          result.reason = `Sensitive tool '${toolName}' requires higher reasoning quality (got ${(result.reasoning_score * 100).toFixed(1)}%, need 70%)`;
          result.violations.push('insufficient_reasoning_for_sensitive_tool');
        }
      }

      this.callLog.push(result);

    } catch (error) {
      result.allowed = false;
      result.reason = `Validation error: ${error.message}`;
      result.violations.push('validation_error');
      this.callLog.push(result);
    }

    result.latency_ms = Date.now() - startTime;
    return result;
  }

  blockTool(toolName) {
    if (!this.blockedTools.includes(toolName)) {
      this.blockedTools.push(toolName);
    }
  }

  unblockTool(toolName) {
    this.blockedTools = this.blockedTools.filter(t => t !== toolName);
  }

  generateId() {
    return `call_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  }

  getCallLog() {
    return this.callLog;
  }
}

/**
 * AgentSession — Decision Quality Tracker
 *
 * Tracks agent decision quality over a session.
 * Detects reasoning degradation and maintains audit trail.
 *
 * Usage:
 *   const session = new AgentSession('agent-123');
 *   session.setReasoningBridge(bridge);
 *   await session.log({ type: 'decision', message: '...', reasoning: '...' });
 *   const report = session.getDefensibilityReport();
 */
class AgentSession {
  constructor(agentId) {
    this.agentId = agentId;
    this.reasoningBridge = null;
    this.decisions = [];
    this.scoringHistory = [];
  }

  setReasoningBridge(bridge) {
    this.reasoningBridge = bridge;
  }

  async log(entry) {
    const logEntry = {
      session_id: this.agentId,
      entry_id: this.generateId(),
      timestamp: new Date().toISOString(),
      type: entry.type || 'unknown',
      message: entry.message || '',
      reasoning: entry.reasoning || '',
      decision_score: 0,
      latency_ms: 0
    };

    const startTime = Date.now();

    try {
      // If this is a decision, score it
      if (entry.type === 'decision' && this.reasoningBridge) {
        const scoreResult = await this.reasoningBridge.scoreDecision(
          { message: entry.message, reasoning: entry.reasoning },
          { session: this.agentId }
        );

        logEntry.decision_score = scoreResult.score || 0;
        this.scoringHistory.push({
          timestamp: logEntry.timestamp,
          score: logEntry.decision_score,
          entry_id: logEntry.entry_id
        });
      }

      this.decisions.push(logEntry);

    } catch (error) {
      logEntry.error = error.message;
    }

    logEntry.latency_ms = Date.now() - startTime;
    return logEntry;
  }

  getDefensibilityReport() {
    if (this.scoringHistory.length === 0) {
      return {
        session_id: this.agentId,
        total_decisions: this.decisions.length,
        scored_decisions: 0,
        average_score: null,
        trend: 'insufficient_data',
        alert: 'No scored decisions yet'
      };
    }

    // Calculate average score
    const avgScore = this.scoringHistory.reduce((sum, s) => sum + s.score, 0) / this.scoringHistory.length;

    // Detect trend (degrading, stable, improving)
    let trend = 'stable';
    if (this.scoringHistory.length > 2) {
      const recent = this.scoringHistory.slice(-5);
      const older = this.scoringHistory.slice(0, Math.max(1, this.scoringHistory.length - 5));

      const recentAvg = recent.reduce((sum, s) => sum + s.score, 0) / recent.length;
      const olderAvg = older.reduce((sum, s) => sum + s.score, 0) / older.length;

      const degradation = olderAvg - recentAvg;
      if (degradation > 0.15) trend = 'degrading';
      else if (degradation < -0.15) trend = 'improving';
    }

    return {
      session_id: this.agentId,
      total_decisions: this.decisions.length,
      scored_decisions: this.scoringHistory.length,
      average_score: parseFloat(avgScore.toFixed(3)),
      lowest_score: Math.min(...this.scoringHistory.map(s => s.score)),
      highest_score: Math.max(...this.scoringHistory.map(s => s.score)),
      trend,
      alert: trend === 'degrading' ? '⚠️  Reasoning quality is degrading' : null,
      scoring_history: this.scoringHistory
    };
  }

  generateId() {
    return `entry_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  }

  getScoringHistory() {
    return this.scoringHistory;
  }
}

module.exports = { GovernanceEngine, ChainMonitor, ToolGuard, AgentSession };
