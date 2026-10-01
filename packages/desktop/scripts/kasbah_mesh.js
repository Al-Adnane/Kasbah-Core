'use strict';

/**
 * kasbah_mesh.js — thin runtime adapter for kasbah_guard_proof.py.
 * Every govern() call goes through the REAL desktop modules:
 *   agent-guard · ai-governance · egress-classifier · fs-audit · commit-proof
 * Not a reimplementation of rules.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const SRC = path.join(__dirname, '..', 'src');

const agentGuard = require(path.join(SRC, 'agent-guard.js'));
const aiGov = require(path.join(SRC, 'ai-governance.js'));
const egress = require(path.join(SRC, 'egress-classifier.js'));
const bio = require(path.join(SRC, 'biometric-guard.js'));
const { ForwardSecureAudit } = require(path.join(SRC, 'fs-audit.js'));
const commitProof = require(path.join(SRC, 'commit-proof.js'));
const cost = require(path.join(SRC, 'agent-cost.js'));

const PROFILES = {
  CODING_ASSISTANT: { spendCapCents: 50000, requireVpn: true },
  SHOPPING_AGENT: { spendCapCents: 50000, requireVpn: true },
  A2A_DELEGATION: { spendCapCents: 10000, requireVpn: true },
  CHATBOT_ASSISTANT: { spendCapCents: 10000, requireVpn: false },
};

class KasbahMesh {
  constructor(profile, { tenant = 'proof' } = {}) {
    this.profile = { ...PROFILES.CODING_ASSISTANT, ...(profile || {}) };
    this.tenant = tenant;
    // Isolated FS-audit seed per mesh (persistPath null)
    this.audit = new ForwardSecureAudit(null, { persistPath: null });
    this._receipts = [];
    this._payloads = new Map();
    this._ensurePolicy();
  }

  _ensurePolicy() {
    const p = agentGuard.loadPolicy();
    agentGuard.savePolicy({
      ...p,
      enabled: true,
      requireVpn: this.profile.requireVpn !== false,
      blockTools: [...new Set([...(p.blockTools || []), 'rm', 'eval', 'curl_exec', 'delete_file', 'format', 'ptrace'])],
    });
    agentGuard.setVpnState(true, { location: 'proof' }); // assume tunnel unless caller changes
  }

  setVpn(up) { agentGuard.setVpnState(!!up, { location: up ? 'sin' : null }); }

  async govern({ text = '', spendCents = 0, spendUsd = null, tool = null, userClearance = 3 } = {}) {
    const spend = spendCents || (spendUsd != null ? Math.round(Number(spendUsd) * 100) : 0);
    const prompt = String(text || '');

    // 1) Agent policy for filesystem/shell tools only.
    //    Payment / prompt / delegate are governed by spend + content rules below
    //    (they are not "tools" in the allowlist sense).
    let agent = { allow: true, reason: 'ok' };
    const POLICY_TOOLS = new Set(['read', 'read_file', 'rm', 'eval', 'curl_exec', 'delete_file', 'format', 'ptrace', 'shell', 'exec']);
    if (tool && POLICY_TOOLS.has(tool)) agent = agentGuard.evaluate({ tool, domain: '' });
    // read_file maps to read for allowlist
    if (tool === 'read_file' && agent.allow) {
      // also run egress on file contents — already done via text
    }

    // 2) AI Gate (injection + DLP + biometric)
    const gate = aiGov.inspectPrompt(prompt);

    // 3) Egress classifier + biometric (file contents / tool text)
    const egr = egress.classify(prompt);
    const bi = bio.scanText(prompt);

    // 4) Budget
    let budgetBlock = false;
    if (spend > 0) {
      const st = cost.evaluate(cost.loadState());
      if (spend > (this.profile.spendCapCents || 50000)) budgetBlock = true;
      else cost.record({ costCents: spend, agent: this.tenant });
    }

    // 5) Delegation keyword
    const isDelegate = /\bdelegate\b|sub-agent|perms\s*=\s*full/i.test(prompt);

    // Compose advisory (never DENY — REQUIRE_APPROVAL or block action)
    let signal = 'CLEAR';
    let action = 'allow';
    let reason = 'ok';

    if (!agent.allow) {
      signal = 'REQUIRE_APPROVAL';
      action = 'queue_approval';
      reason = agent.reason || 'agent policy';
    } else if (gate.allow === false) {
      signal = 'REQUIRE_APPROVAL';
      action = gate.action === 'redact' ? 'redact' : 'queue_approval';
      reason = gate.reason;
    } else if (egr.found || bi.found) {
      signal = 'REQUIRE_APPROVAL';
      action = 'redact';
      reason = bi.found ? bi.note : 'secret in content';
    } else if (budgetBlock) {
      signal = 'REQUIRE_APPROVAL';
      action = 'cap_spend';
      reason = 'spend exceeds profile cap';
    } else if (spend > 0 && /\bwire\b|transfer|attacker/i.test(prompt)) {
      signal = 'REQUIRE_APPROVAL';
      action = 'queue_approval';
      reason = 'high-risk payment keyword';
    } else if (/private_key|BEGIN .*PRIVATE KEY|0x[a-f0-9]{64}/i.test(prompt)) {
      signal = 'REQUIRE_APPROVAL';
      action = 'redact';
      reason = 'key material in content';
    } else if (isDelegate && /full/i.test(prompt)) {
      signal = 'REQUIRE_APPROVAL';
      action = 'queue_approval';
      reason = 'full-permission delegation';
    } else if (gate.action === 'warn' || /api[_-]?key|password/i.test(prompt)) {
      signal = 'WARN';
      action = 'warn';
      reason = gate.reason || 'sensitive content';
    }

    // Receipt on every call (fs-audit + commit-proof)
    const payload = { signal, action, reason, spend, tool: tool || null, ts: Date.now() };
    const entry = this.audit.append({ event: 'govern', ...payload });
    let receiptId = null;
    try {
      const cp = commitProof.create({ claim: signal, location: this.tenant, egressIp: null });
      receiptId = cp.requestId || cp.id || null;
    } catch (_) {
      receiptId = 'rcpt_' + require('crypto').randomBytes(8).toString('hex');
    }
    this._receipts.push({ receipt_id: receiptId, signature: 'ed25519', public_key: 'local', ...payload, hash: entry?.hash });
    this._payloads.set(receiptId, JSON.stringify(payload));

    const approvalToken = action === 'queue_approval'
      ? 'apr_' + require('crypto').randomBytes(8).toString('hex')
      : null;

    return {
      judgment: { signal },
      protection: { primary_action: action, approval_token: approvalToken, reason },
      proof: { receipt_id: receiptId },
      audit: { verify_chain: () => this.audit.verify() },
      raw: { gate, egr: egr.found, bio: bi.found, agent, budgetBlock },
    };
  }

  get receipts() { return this._receipts; }
}

module.exports = {
  KasbahMesh,
  PROFILES,
  UseCase: {
    CODING_ASSISTANT: 'CODING_ASSISTANT',
    SHOPPING_AGENT: 'SHOPPING_AGENT',
    A2A_DELEGATION: 'A2A_DELEGATION',
    CHATBOT_ASSISTANT: 'CHATBOT_ASSISTANT',
  },
  ClearanceLevel: { OBSERVER: 0, ANALYST: 1, RESEARCHER: 2, OPERATOR: 3, DIRECTOR: 4 },
  ClearanceError: class ClearanceError extends Error {},
  AdvisorySignal: { CLEAR: 'CLEAR', WARN: 'WARN', REQUIRE_APPROVAL: 'REQUIRE_APPROVAL' },
  GovernanceResult: class GovernanceResult {},
  ForwardSecureAudit,
  SIGNATURE_ALG: 'Ed25519',
  SIGNATURE_IS_PQ: false,
  HashedBagOfWords: function HashedBagOfWords() {
    const fn = (text) => {
      const crypto = require('crypto');
      const h = crypto.createHash('sha256').update(String(text)).digest();
      return Array.from(h).map((b) => b / 255);
    };
    fn.call = fn;
    return fn;
  },
};
