#!/usr/bin/env node
/**
 * KASBAH OS — The Operating System for AI Agents
 *
 * Unified integration layer that connects:
 *   detector.js (12-layer detection, 57+ patterns, 6 nature-inspired techniques)
 *   + governance-engine.js (policy enforcement, fail-closed, audit trail)
 *   + orchestration (agent routing, cost optimization)
 *   + monitoring (real-time metrics, anomaly detection)
 *
 * This is the SINGLE PRODUCT. Everything else is a component of this.
 *
 * Flow: Agent Action → Detector (analyze) → Governance (decide) → Audit (log) → Monitor (track)
 */

const { GovernanceEngine } = require('./governance-engine.js');
const detector = require('../detector.js');
const crypto = require('crypto');
const fs = require('fs');

class KasbahOS {
  constructor(options = {}) {
    this.policyPath = options.policyPath || require('path').resolve(__dirname, '..', '.kasbahpolicy.json');
    this.auditPath = options.auditPath || '.kasbah-audit.jsonl';

    // Layer 1: Governance Engine
    this.governance = new GovernanceEngine(this.policyPath);

    // Layer 2: Detection Engine (already loaded via require)
    this.detector = detector;

    // Layer 3: Orchestration State
    this.agents = new Map();       // registered agents
    this.costTracker = new Map();  // agent → cumulative cost
    this.routingRules = [];        // cost/capability routing

    // Layer 4: Monitoring State
    this.metrics = {
      totalActions: 0,
      allowed: 0,
      denied: 0,
      warned: 0,
      detections: 0,
      avgLatencyMs: 0,
      totalLatencyMs: 0,
      costTotal: 0,
      byAgent: {},
      byVerb: {},
      anomalies: [],
      startTime: Date.now()
    };

    // Verify detector integrity on boot
    this._verifyDetectorIntegrity();
  }

  // ═══════════════════════════════════════════════════════════
  // UNIFIED CHECK: The core operation of the OS
  //
  // Agent does something → detect threats → enforce policy → log → monitor
  // ═══════════════════════════════════════════════════════════

  async check(action) {
    const startTime = Date.now();
    const traceId = `kas_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

    // Step 1: DETECT — Run the 12-layer detector on the action content
    let detection = null;
    if (action.content) {
      detection = this.detector.classify(action.content);
    }

    // Step 2: GOVERN — Run policy enforcement
    const govAction = {
      agent: action.agent,
      verb: action.verb,
      target: action.target,
      trace_id: traceId
    };
    const governance = await this.governance.check(govAction);

    // Step 3: COMBINE — Merge detection + governance into unified decision
    const decision = this._mergeDecision(governance, detection, action, traceId, startTime);

    // Step 4: MONITOR — Update metrics
    this._updateMetrics(decision, action);

    // Step 5: AUDIT — Extended audit log entry
    this._logUnifiedAudit(decision, action, detection);

    return decision;
  }

  // ═══════════════════════════════════════════════════════════
  // LAYER 1: GOVERNANCE (delegates to governance-engine.js)
  // ═══════════════════════════════════════════════════════════

  getPolicy() {
    return this.governance.policy;
  }

  getPolicyHash() {
    return this.governance.policyHash;
  }

  getAuditLog() {
    return this.governance.auditLog;
  }

  // ═══════════════════════════════════════════════════════════
  // LAYER 2: DETECTION (delegates to detector.js)
  // ═══════════════════════════════════════════════════════════

  /**
   * Scan content through the 12-layer detector
   * Returns: { risk, decision, reason, tiers, proof, platform, ... }
   */
  scan(content) {
    return this.detector.classify(content);
  }

  /**
   * Run detector self-test (25 formal invariants)
   */
  selfTest() {
    return this.detector.selfTest();
  }

  /**
   * Verify pattern integrity (Layer 6: tamper detection)
   */
  verifyIntegrity() {
    return this.detector.verifyPatternIntegrity();
  }

  // ═══════════════════════════════════════════════════════════
  // LAYER 3: ORCHESTRATION (agent routing + cost optimization)
  // ═══════════════════════════════════════════════════════════

  /**
   * Register an agent with its capabilities and cost
   */
  registerAgent(name, config) {
    this.agents.set(name, {
      name,
      provider: config.provider || 'unknown',
      model: config.model || name,
      costPer1kTokens: config.costPer1kTokens || 0,
      capabilities: config.capabilities || [],
      maxTokens: config.maxTokens || 4096,
      latencyMs: config.latencyMs || 1000,
      registeredAt: new Date().toISOString()
    });

    this.costTracker.set(name, { totalCost: 0, totalTokens: 0, calls: 0 });
  }

  /**
   * Route a task to the best agent that passes governance
   * Returns: { agent, reason, estimatedCost }
   */
  async route(task) {
    const { verb, target, content, preferCheap, preferFast } = task;
    const candidates = [];

    for (const [name, agent] of this.agents) {
      // Check if this agent is ALLOWED to perform this action
      const govCheck = await this.governance.check({
        agent: name,
        verb: verb,
        target: target
      });

      if (govCheck.status === 'ALLOW') {
        candidates.push({
          agent: name,
          ...agent,
          govDecision: govCheck
        });
      }
    }

    if (candidates.length === 0) {
      return {
        agent: null,
        reason: 'No agent passes governance for this action',
        estimatedCost: 0
      };
    }

    // Sort by cost (cheapest first) or latency (fastest first)
    if (preferFast) {
      candidates.sort((a, b) => a.latencyMs - b.latencyMs);
    } else {
      candidates.sort((a, b) => a.costPer1kTokens - b.costPer1kTokens);
    }

    const chosen = candidates[0];
    return {
      agent: chosen.name,
      provider: chosen.provider,
      model: chosen.model,
      reason: `Selected: ${preferFast ? 'fastest' : 'cheapest'} agent that passes governance`,
      estimatedCost: chosen.costPer1kTokens,
      alternativeCount: candidates.length - 1,
      blockedCount: this.agents.size - candidates.length
    };
  }

  /**
   * Track cost for an agent call
   */
  trackCost(agent, tokens, cost) {
    const tracker = this.costTracker.get(agent) || { totalCost: 0, totalTokens: 0, calls: 0 };
    tracker.totalCost += cost;
    tracker.totalTokens += tokens;
    tracker.calls += 1;
    this.costTracker.set(agent, tracker);
    this.metrics.costTotal += cost;
  }

  /**
   * Get cost report for all agents
   */
  getCostReport() {
    const report = {};
    for (const [name, tracker] of this.costTracker) {
      report[name] = { ...tracker };
    }
    return {
      total: this.metrics.costTotal,
      byAgent: report
    };
  }

  // ═══════════════════════════════════════════════════════════
  // LAYER 4: MONITORING (metrics, anomalies, health)
  // ═══════════════════════════════════════════════════════════

  /**
   * Get real-time metrics dashboard
   */
  getMetrics() {
    const uptimeMs = Date.now() - this.metrics.startTime;
    return {
      uptime: this._formatUptime(uptimeMs),
      uptimeMs,
      totalActions: this.metrics.totalActions,
      allowed: this.metrics.allowed,
      denied: this.metrics.denied,
      warned: this.metrics.warned,
      detections: this.metrics.detections,
      avgLatencyMs: this.metrics.totalActions > 0
        ? (this.metrics.totalLatencyMs / this.metrics.totalActions).toFixed(2)
        : 0,
      denyRate: this.metrics.totalActions > 0
        ? ((this.metrics.denied / this.metrics.totalActions) * 100).toFixed(1) + '%'
        : '0%',
      detectionRate: this.metrics.totalActions > 0
        ? ((this.metrics.detections / this.metrics.totalActions) * 100).toFixed(1) + '%'
        : '0%',
      costTotal: this.metrics.costTotal.toFixed(4),
      byAgent: this.metrics.byAgent,
      byVerb: this.metrics.byVerb,
      anomalies: this.metrics.anomalies.slice(-10),
      registeredAgents: this.agents.size,
      policyHash: this.governance.policyHash,
      detectorVersion: this.detector.PATTERN_VERSION,
      detectorFeatures: this.detector.FEATURES.length,
      integrity: this.verifyIntegrity()
    };
  }

  /**
   * Get governance summary (last N minutes)
   */
  getGovernanceSummary(minutes = 60) {
    return this.governance.getSummary(minutes);
  }

  /**
   * Health check — is everything operational?
   */
  healthCheck() {
    const integrity = this.verifyIntegrity();
    const selfTest = this.selfTest();
    const policyLoaded = !!this.governance.policy;

    return {
      status: integrity.intact && selfTest.passed === selfTest.total && policyLoaded ? 'HEALTHY' : 'DEGRADED',
      components: {
        detector: {
          status: integrity.intact ? 'OK' : 'COMPROMISED',
          version: this.detector.PATTERN_VERSION,
          integrity: integrity.intact,
          integrityIndex: integrity.systemIntegrityIndex,
          selfTest: `${selfTest.passed}/${selfTest.total} passed`
        },
        governance: {
          status: policyLoaded ? 'OK' : 'NO_POLICY',
          policyVersion: this.governance.policy?.version || 'none',
          policyHash: this.governance.policyHash || 'none',
          forbiddenVerbs: this.governance.policy?.governance?.forbidden_verbs?.length || 0,
          allowedDomains: this.governance.policy?.governance?.allowed_domains?.length || 0
        },
        orchestration: {
          status: this.agents.size > 0 ? 'OK' : 'NO_AGENTS',
          registeredAgents: this.agents.size,
          totalCost: this.metrics.costTotal.toFixed(4)
        },
        monitoring: {
          status: 'OK',
          totalActions: this.metrics.totalActions,
          anomalies: this.metrics.anomalies.length,
          uptime: this._formatUptime(Date.now() - this.metrics.startTime)
        }
      }
    };
  }

  // ═══════════════════════════════════════════════════════════
  // INTERNAL: Decision merging, metrics, logging
  // ═══════════════════════════════════════════════════════════

  _mergeDecision(governance, detection, action, traceId, startTime) {
    const latencyMs = Date.now() - startTime;

    // Start with governance decision
    const decision = {
      trace_id: traceId,
      timestamp: new Date().toISOString(),
      status: governance.status,
      reason: governance.reason,
      violations: [...governance.violations],
      risk_score: governance.risk_score,
      policy_hash: governance.policy_hash,
      latency_ms: latencyMs,
      agent: action.agent,
      verb: action.verb,
      target: action.target
    };

    // If detector found something, merge it
    if (detection) {
      decision.detection = {
        risk: detection.risk,
        detectorDecision: detection.decision,
        reason: detection.reason,
        tiers: detection.tiers,
        platform: detection.platform,
        proof: detection.proof,
        version: detection.version,
        features: detection.features.length
      };

      // If detector says DENY and governance says ALLOW, override to DENY
      if (detection.decision === 'DENY' && governance.status === 'ALLOW') {
        decision.status = 'DENY';
        decision.reason = `Detector blocked: ${detection.reason}`;
        decision.risk_score = Math.max(decision.risk_score, detection.risk);
        decision.violations.push({
          type: 'detector_block',
          severity: 'critical',
          reason: detection.reason
        });
      }

      // If detector says WARN, add warning even if governance allows
      if (detection.decision === 'WARN' && governance.status === 'ALLOW') {
        decision.warning = detection.reason;
        decision.risk_score = Math.max(decision.risk_score, detection.risk);
      }
    }

    return decision;
  }

  _updateMetrics(decision, action) {
    this.metrics.totalActions++;
    this.metrics.totalLatencyMs += decision.latency_ms;

    if (decision.status === 'ALLOW') this.metrics.allowed++;
    else if (decision.status === 'DENY') this.metrics.denied++;

    if (decision.detection && decision.detection.risk >= 40) {
      this.metrics.detections++;
    }

    // Track by agent
    if (!this.metrics.byAgent[action.agent]) {
      this.metrics.byAgent[action.agent] = { allowed: 0, denied: 0, total: 0 };
    }
    this.metrics.byAgent[action.agent].total++;
    if (decision.status === 'ALLOW') this.metrics.byAgent[action.agent].allowed++;
    else this.metrics.byAgent[action.agent].denied++;

    // Track by verb
    if (!this.metrics.byVerb[action.verb]) {
      this.metrics.byVerb[action.verb] = { allowed: 0, denied: 0, total: 0 };
    }
    this.metrics.byVerb[action.verb].total++;
    if (decision.status === 'ALLOW') this.metrics.byVerb[action.verb].allowed++;
    else this.metrics.byVerb[action.verb].denied++;

    // Anomaly detection: >5 denials in a row from same agent
    const agentMetrics = this.metrics.byAgent[action.agent];
    if (decision.status === 'DENY' && agentMetrics.denied > 5 && agentMetrics.denied / agentMetrics.total > 0.8) {
      const anomaly = {
        type: 'high_deny_rate',
        agent: action.agent,
        denyRate: (agentMetrics.denied / agentMetrics.total * 100).toFixed(1) + '%',
        timestamp: new Date().toISOString()
      };
      this.metrics.anomalies.push(anomaly);
    }
  }

  _logUnifiedAudit(decision, action, detection) {
    const entry = {
      trace_id: decision.trace_id,
      timestamp: decision.timestamp,
      agent: action.agent,
      verb: action.verb,
      target: action.target,
      status: decision.status,
      reason: decision.reason,
      risk_score: decision.risk_score,
      policy_hash: decision.policy_hash,
      latency_ms: decision.latency_ms,
      detector_risk: detection ? detection.risk : null,
      detector_decision: detection ? detection.decision : null,
      detector_tiers: detection ? detection.tiers : [],
      violations: decision.violations.map(v => v.type)
    };

    try {
      fs.appendFileSync(this.auditPath, JSON.stringify(entry) + '\n');
    } catch (e) {
      // Don't crash on log failure
    }
  }

  _verifyDetectorIntegrity() {
    const integrity = this.detector.verifyPatternIntegrity();
    if (!integrity.intact) {
      console.error('[KASBAH OS] WARNING: Detector pattern integrity check FAILED');
    }
    const test = this.detector.selfTest();
    if (test.passed !== test.total) {
      console.error(`[KASBAH OS] WARNING: Detector self-test ${test.passed}/${test.total} passed`);
    }
  }

  _formatUptime(ms) {
    const s = Math.floor(ms / 1000);
    const m = Math.floor(s / 60);
    const h = Math.floor(m / 60);
    if (h > 0) return `${h}h ${m % 60}m`;
    if (m > 0) return `${m}m ${s % 60}s`;
    return `${s}s`;
  }
}

module.exports = { KasbahOS };
