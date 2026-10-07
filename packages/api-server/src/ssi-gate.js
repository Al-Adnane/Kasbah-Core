'use strict';
/**
 * ssi-gate.js — Express-compatible SSI admission gate (future-proof).
 * Replaces ssi-gate.ts (Next.js-isms, Python byte literals, Set.includes
 * bugs, unwired). This module is required by server.js / governance.
 *
 * Future-proof properties:
 *  - Per-user stones: stoneId derived per agentId via HKDF, isolated.
 *  - Kill-switch guard: remote DENY_ALL / kill commands require a
 *    LOCAL physical tap for THAT agent — a remote caller can never
 *    force another agent's execution or kill.
 *  - Unknown tools default PHYSICAL_TOUCH (fail-safe).
 */
const crypto = require('crypto');

const ZERO_TOUCH = new Set(['read_file','grep','find','ls','cat','head','tail','wc','diff','git_status','git_log','git_diff','format','lint','type_check','test','pytest','cargo_check','npm_test','bun_test']);
const SOFT_GATE = new Set(['write_file','move_file','mkdir','touch','git_add','git_commit','git_push','pip_install','npm_install','cargo_build','http_get']);
const SENSITIVE_PATH = [/\.ssh\//i, /\.env\b/i, /\.aws\//i, /\.gnupg\//i, /id_rsa/i, /credential/i, /service_account\.json/i, /\.npmrc/i, /\.pypirc/i];

// Commands that could act as a remote kill switch — always PHYSICAL_TOUCH
// AND bound to the owning agent's stone (never cross-agent).
const KILL_SWITCH_PATTERNS = [
  /\bkill\s+-9\b/i, /\bpkill\b/i, /\bkillall\b/i, /\btaskkill\b/i,
  /deny[_\s-]?all/i, /shutdown/i, /\breboot\b/i, /\bhalt\b/i,
  /agent[_\s-]?kill/i, /remote[_\s-]?kill/i, /emergency[_\s-]?stop[_\s-]?all/i,
  /:\(\)\s*\{\s*:\|:&\s*\};:/, /\bchmod\s+777\b/i, /\bkubectl\s+delete\b/i,
  /\baws\s+s3\s+(rm|rb)\b/i, /\bterraform\s+(apply|destroy)\b/i,
];

function classifyRisk(tool = '', args = {}) {
  const text = [tool, typeof args === 'string' ? args : JSON.stringify(args || {})].join(' ');
  for (const re of KILL_SWITCH_PATTERNS) {
    if (re.test(text)) return { tier: 'PHYSICAL_TOUCH', tapRequired: true, killSwitch: true, reason: 'kill-switch pattern' };
  }
  for (const re of SENSITIVE_PATH) {
    if (re.test(text)) return { tier: 'PHYSICAL_TOUCH', tapRequired: true, reason: 'sensitive path' };
  }
  const t = String(tool || '').toLowerCase();
  if (ZERO_TOUCH.has(t)) return { tier: 'ZERO_TOUCH', tapRequired: false, reason: 'read-only' };
  if (SOFT_GATE.has(t)) return { tier: 'SOFT_GATE', tapRequired: false, reason: 'logged write' };
  return { tier: 'PHYSICAL_TOUCH', tapRequired: true, reason: 'fail-safe default' };
}

// Per-user stone registry: agentId -> { stoneId, publicKey }
// stoneId = sha256('kasbah-stone-v1' || agentId), hex16.
const _stones = new Map();
function stoneFor(agentId = 'anonymous') {
  const id = String(agentId || 'anonymous');
  if (!_stones.has(id)) {
    const stoneId = crypto.createHash('sha256').update('kasbah-stone-v1:' + id).digest('hex').slice(0, 16);
    const kp = crypto.generateKeyPairSync('ed25519');
    _stones.set(id, { agentId: id, stoneId, publicKey: kp.publicKey, privateKey: kp.privateKey, taps: 0 });
  }
  return _stones.get(id);
}

// Kill-switch guard: a tap for agent A NEVER authorizes agent B.
// Returns { ok, reason }. Remote kill of another agent is denied even with tap.
function killSwitchGuard({ requestingAgent, targetAgent, tier }) {
  if (!tier || !tier.killSwitch) return { ok: true };
  if (String(requestingAgent || '') !== String(targetAgent || '')) {
    return { ok: false, reason: 'cross-agent kill denied: tap is per-agent, remote kill-switch blocked' };
  }
  return { ok: true, needsLocalTap: true };
}

function actionHash(tool, args) {
  return crypto.createHash('sha256').update(String(tool) + '|' + JSON.stringify(args || {})).digest('hex');
}

module.exports = { ZERO_TOUCH, SOFT_GATE, SENSITIVE_PATH, KILL_SWITCH_PATTERNS, classifyRisk, stoneFor, killSwitchGuard, actionHash };
