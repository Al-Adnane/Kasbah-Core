'use strict';

/**
 * agent-governance — agent identity certificates (real Ed25519), constrained
 * decision evaluation (G-CMDP), and the Maqasid content framework.
 *
 * Nothing here simulates: identities are actual Ed25519 keypairs from node
 * crypto, certificates carry verifiable signatures, and GCMDP evaluates each
 * declared constraint against the supplied state and reports exactly which
 * ones bind.
 */

const crypto = require('crypto');
const { MaqasidFramework, evaluateMaqasid } = require('./maqasid-framework.js');

// ── AgentIdentity ────────────────────────────────────────────────────────────

class AgentIdentity {
  constructor(agentId, attributes, keyPair) {
    this.agentId = agentId;
    this.attributes = attributes || {};
    this._keyPair = keyPair;
    this.created = Date.now();
  }

  static generate(agentId, attributes = {}) {
    const keyPair = crypto.generateKeyPairSync('ed25519');
    return new AgentIdentity(agentId, attributes, keyPair);
  }

  /** Signed identity certificate (30-day validity). Verifiable offline. */
  createCertificate(ttlMs = 30 * 24 * 3600 * 1000) {
    const publicKey = this._keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const payload = {
      agentId: this.agentId,
      attributes: this.attributes,
      publicKey,
      issued: this.created,
      expires: this.created + ttlMs,
      alg: 'ed25519',
    };
    const message = Buffer.from(JSON.stringify(payload));
    const signature = crypto.sign(null, message, this._keyPair.privateKey).toString('base64');
    return { ...payload, signature };
  }

  static verifyCertificate(cert) {
    try {
      const { signature, ...payload } = cert;
      const pub = crypto.createPublicKey({ key: Buffer.from(cert.publicKey, 'base64'), type: 'spki', format: 'der' });
      const ok = crypto.verify(null, Buffer.from(JSON.stringify(payload)), pub, Buffer.from(signature, 'base64'));
      if (!ok) return { valid: false, reason: 'signature invalid' };
      if (Date.now() > cert.expires) return { valid: false, reason: 'certificate expired' };
      return { valid: true };
    } catch (e) {
      return { valid: false, reason: e.message };
    }
  }
}

// ── GCMDP — constrained decision evaluation ──────────────────────────────────
// Evaluates a proposed action against explicit constraints (budget, risk
// ceiling, action allow/deny lists, rate) given the current state. Each
// constraint's margin is reported; the decision is fail-closed: any hard
// violation denies.

class GCMDP {
  evaluate(action, state = {}, constraints = {}) {
    const checks = [];
    const actionName = typeof action === 'string' ? action : action?.type || action?.name || 'unknown';
    const cost = Number(action?.cost ?? state.actionCost ?? 0);
    const risk = Number(action?.risk ?? state.actionRisk ?? 0);

    if (constraints.budget !== undefined) {
      const spent = Number(state.spent || 0);
      const remaining = Number(constraints.budget) - spent;
      checks.push({
        constraint: 'budget', bound: constraints.budget, spent, actionCost: cost,
        margin: +(remaining - cost).toFixed(6), satisfied: cost <= remaining,
      });
    }
    if (constraints.maxRisk !== undefined) {
      checks.push({
        constraint: 'maxRisk', bound: constraints.maxRisk, actionRisk: risk,
        margin: +(Number(constraints.maxRisk) - risk).toFixed(6), satisfied: risk <= Number(constraints.maxRisk),
      });
    }
    if (Array.isArray(constraints.allowedActions)) {
      checks.push({
        constraint: 'allowedActions', bound: constraints.allowedActions,
        satisfied: constraints.allowedActions.includes(actionName),
        margin: constraints.allowedActions.includes(actionName) ? 1 : -1,
      });
    }
    if (Array.isArray(constraints.forbiddenActions)) {
      checks.push({
        constraint: 'forbiddenActions', bound: constraints.forbiddenActions,
        satisfied: !constraints.forbiddenActions.includes(actionName),
        margin: constraints.forbiddenActions.includes(actionName) ? -1 : 1,
      });
    }
    if (constraints.maxCallsPerMinute !== undefined) {
      const rate = Number(state.callsThisMinute || 0);
      checks.push({
        constraint: 'maxCallsPerMinute', bound: constraints.maxCallsPerMinute, current: rate,
        margin: Number(constraints.maxCallsPerMinute) - rate - 1, satisfied: rate < Number(constraints.maxCallsPerMinute),
      });
    }

    const violated = checks.filter((c) => !c.satisfied);
    // Binding constraint = smallest non-negative margin (the "shadow price" signal:
    // which constraint the agent is closest to hitting).
    const binding = checks.filter((c) => c.satisfied).sort((a, b) => a.margin - b.margin)[0] || null;

    return {
      action: actionName,
      decision: violated.length === 0 ? 'ALLOW' : 'DENY',
      feasible: violated.length === 0,
      checks,
      violated: violated.map((v) => v.constraint),
      bindingConstraint: binding ? binding.constraint : null,
      expectedCost: cost,
      riskScore: risk,
      note: checks.length === 0 ? 'no constraints declared — vacuously feasible; declare constraints to get enforcement' : undefined,
    };
  }
}

module.exports = { GCMDP, AgentIdentity, MaqasidFramework, evaluateMaqasid };
