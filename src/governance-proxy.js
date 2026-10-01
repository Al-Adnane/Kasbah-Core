'use strict';

/**
 * GovernanceProxy — sits BETWEEN a frontier LLM and its tool environment.
 *
 * Intercepts each turn (messages + proposed tool calls), evaluates it through
 * validated Kasbah layers, and emits a bounded advisory signal:
 *
 *     CLEAR | WARN | REQUIRE_APPROVAL
 *
 * Authoritative DENY remains with the validated governance engine (forbidden
 * verbs, domain whitelist, rate limits). Nothing here autonomously denies
 * real traffic.
 *
 * Layers used (all validated, no invented/unvalidated math):
 *   - detector.js              : deterministic content threat classifier (P0.97/R0.60 on bench v1)
 *   - governance-engine.js     : fail-closed policy (DENY / REQUIRE_APPROVAL)
 *   - kasbah-intent-analyzer.js: known multi-step attack trajectory matching
 *
 * Plus:
 *   - a human-in-the-loop pending-approval queue
 *   - a forward-secure audit chain over every decision
 *
 * 2026-07: removed ~30 "novel module" analyzers (nature-features.js,
 * advisory-analyzers.js, detectgpt.js, CHSH coordination, persistent
 * homology, orthogonal-manifold-evasion-bound, hypergraph collusion, etc.).
 * They were explicitly self-documented as running on unvalidated premises
 * ("conclusions have NOT been empirically validated against labelled abuse
 * data") and, unlike the opt-in-gated ones, nature-features.js fed WARN/
 * REQUIRE_APPROVAL escalation on every real request by default — forcing
 * human review on live traffic based on invented math, not evidence. See
 * CHANGELOG.md for the full audit.
 */

const detector = require('./detector.js');
const { GovernanceEngine } = require('./governance-engine.js');
const { ForwardSecureAudit } = require('./forward-secure-audit.js');
const { KasbahIntentAnalyzer } = require('./kasbah-intent-analyzer.js');

const CLEARANCE = { OBSERVER: 0, ANALYST: 1, RESEARCHER: 2, OPERATOR: 3, DIRECTOR: 4 };

// Advisory ordering for combining signals (higher = more scrutiny).
const RANK = { CLEAR: 0, WARN: 1, REQUIRE_APPROVAL: 2 };
// NOTE: There is no DENY rank. Probabilistic/heuristic detectors can only
// escalate to human review, never autonomously block.
function maxSignal(a, b) { return (RANK[a] || 0) >= (RANK[b] || 0) ? a : b; }

class GovernanceProxy {
  constructor(opts = {}) {
    this.governance = opts.governance || new GovernanceEngine();
    this.audit = new ForwardSecureAudit(opts.auditSeed);
    this.pending = new Map();   // actionId -> { turn, advisory, createdAt }
    this.maxHistory = opts.maxHistory || 50;

    // Cross-step distributed-attack detection (kasbah-intent-analyzer island).
    this.intentAnalyzer = new KasbahIntentAnalyzer();
    this._stepHistory = [];   // {id,verb,target,content,status} per turn
  }

  /** Flatten messages to a single text blob for content classification. */
  _flatten(messages = []) {
    return messages.slice(-this.maxHistory)
      .map(m => (typeof m.content === 'string' ? m.content : JSON.stringify(m.content || '')))
      .join('\n');
  }

  /**
   * Map proposed tool calls to a governance action (verb/target/domain) so the
   * fail-closed engine can rule on them. Conservative: if no tool call, treat
   * as a read-only content turn.
   */
  _toolAction(tools = []) {
    if (!Array.isArray(tools) || tools.length === 0) return null;
    const t = tools[0] || {};
    return {
      verb: String(t.verb || t.name || 'CALL_TOOL').toUpperCase(),
      target: t.target || t.domain || 'tool',
      domain: t.domain || t.target || null,
      agent: t.agent || 'llm',
    };
  }

  /**
   * Evaluate one intercepted LLM turn.
   * @returns {{status, signal, detail, audit}} status ∈ allowed|pending_approval
   */
  async evaluateTurn({ messages = [], tools = [], clearance = CLEARANCE.RESEARCHER, edges = null } = {}) {
    const text = this._flatten(messages);

    // 1. Content threat classification (validated deterministic layer).
    const content = detector.classify(text);

    // 2. Cross-step trajectory analysis (distributed/multi-step attacks that
    //    are benign per-step). Build a step from this turn and analyze history.
    const act0 = this._toolAction(tools);
    this._stepHistory.push({
      id: 'step_' + this._stepHistory.length,
      verb: act0 ? act0.verb : 'MESSAGE',
      target: act0 ? act0.target : 'conversation',
      content: text,
      status: 'completed',
    });
    if (this._stepHistory.length > 64) this._stepHistory.shift();
    const trajectory = this.intentAnalyzer.analyze(this._stepHistory);

    // 3. Fail-closed governance on the proposed tool action (authoritative).
    let gov = { status: 'ALLOW', reason: null, risk_score: 0 };
    const action = this._toolAction(tools);
    if (action) {
      try { gov = await this.governance.check(action); }
      catch (e) { gov = { status: 'REQUIRE_APPROVAL', reason: 'governance error (fail-closed): ' + e.message, risk_score: 100 }; }
    }

    // 4. Combine: governance is authoritative (can DENY); content/trajectory
    //    can only raise to WARN / REQUIRE_APPROVAL.
    let signal = 'CLEAR';
    if (gov.status === 'DENY' || gov.status === 'REQUIRE_APPROVAL') signal = 'REQUIRE_APPROVAL';

    if (content.decision === 'DENY') signal = maxSignal(signal, 'REQUIRE_APPROVAL'); // content DENY → human review, not silent block of the turn
    else if (content.decision === 'WARN') signal = maxSignal(signal, 'WARN');

    // Distributed multi-step attack (kasbah-intent-analyzer): a matched attack
    // trajectory → human review even when each step looked benign alone.
    if (trajectory.trajectoryMatch) signal = maxSignal(signal, 'REQUIRE_APPROVAL');
    else if (trajectory.threat || (trajectory.driftScore || 0) >= 0.5) signal = maxSignal(signal, 'WARN');

    const detail = {
      content: { decision: content.decision, risk: content.risk, reason: content.reason, tiers: content.tiers },
      trajectory: { threat: trajectory.threat, driftScore: +(trajectory.driftScore || 0).toFixed(3),
                    match: trajectory.trajectoryMatch ? { id: trajectory.trajectoryMatch.id, name: trajectory.trajectoryMatch.name, severity: trajectory.trajectoryMatch.severity, confidence: trajectory.trajectoryMatch.confidence } : null },
      governance: { status: gov.status, reason: gov.reason, risk: gov.risk_score },
      clearance,
    };

    // 5. Forward-secure audit of the decision.
    const receipt = this.audit.append({ type: 'proxy_turn', signal, detail });

    // 6. Route.
    if (signal === 'DENY' || signal === 'REQUIRE_APPROVAL') {
      const actionId = 'act_' + receipt.hash.slice(0, 16);
      this.pending.set(actionId, { turn: { messages, tools, clearance }, advisory: detail, createdAt: Date.now() });
      return { status: 'pending_approval', actionId, signal, detail, audit: receipt };
    }
    return { status: 'allowed', signal, detail, audit: receipt };
  }

  /** List queued actions awaiting human approval (no message bodies). */
  listPending() {
    return Array.from(this.pending.entries()).map(([id, p]) => ({
      actionId: id, createdAt: p.createdAt,
      signal: 'REQUIRE_APPROVAL',
      content: p.advisory.content, governance: p.advisory.governance,
    }));
  }

  /** Human approves a queued action. Requires OPERATOR+ clearance. */
  approve(actionId, approver = {}) {
    if ((approver.clearance ?? CLEARANCE.OBSERVER) < CLEARANCE.OPERATOR) {
      return { status: 'forbidden', reason: 'approval requires OPERATOR clearance' };
    }
    const p = this.pending.get(actionId);
    if (!p) return { status: 'not_found', reason: 'unknown actionId' };
    this.pending.delete(actionId);
    const receipt = this.audit.append({ type: 'proxy_approval', actionId, approver: approver.id || 'human', decision: 'approved' });
    return { status: 'approved', actionId, audit: receipt };
  }

  /** Human rejects a queued action. */
  reject(actionId, approver = {}) {
    const p = this.pending.get(actionId);
    if (!p) return { status: 'not_found', reason: 'unknown actionId' };
    this.pending.delete(actionId);
    const receipt = this.audit.append({ type: 'proxy_rejection', actionId, approver: approver.id || 'human', decision: 'rejected' });
    return { status: 'rejected', actionId, audit: receipt };
  }

  info() {
    return {
      pending: this.pending.size,
      audit: this.audit.info(),
      layers: ['detector.js', 'governance-engine.js', 'kasbah-intent-analyzer.js', 'forward-secure-audit.js'],
    };
  }
}

module.exports = { GovernanceProxy, CLEARANCE };
