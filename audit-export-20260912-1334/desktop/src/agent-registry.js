'use strict';

/**
 * Agent Registry — lightweight local registry for AI agents running on this Mac.
 * Tracks registered agents (Claude Code, Cursor, custom), their active sessions,
 * and a 4-phase audit log: Perceive → Reason → Act → Learn.
 *
 * Integrates with agent-guard.js for VPN-drop kill and policy enforcement.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

const DIR     = path.join(os.homedir(), '.kasbah-agents');
const REG     = path.join(DIR, 'registry.json');
const LOG     = path.join(DIR, 'audit.jsonl');

function ensureDir() { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); }

// Strip control/escape characters (terminal-injection, log-injection defense).
// Rendering-layer HTML escaping (see index.html esc()) is the primary XSS
// defense — this is a second layer against garbage entering the registry at
// all, since register()/auditLog() are reachable without authentication from
// any local process that can hit the loopback API.
function sanitizeText(v, max) {
  return String(v == null ? '' : v)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .slice(0, max);
}

function loadRegistry() {
  ensureDir();
  try { return JSON.parse(fs.readFileSync(REG, 'utf8')); }
  catch { return { agents: [], updatedAt: null }; }
}

function saveRegistry(reg) {
  ensureDir();
  reg.updatedAt = new Date().toISOString();
  fs.writeFileSync(REG, JSON.stringify(reg, null, 2), { mode: 0o600 });
}

/** Register or update an agent entry. Returns the agent record. */
function register({ name, kind = 'unknown', pid = null, mcpPort = null, description = '' } = {}) {
  if (!name || typeof name !== 'string') throw new Error('agent name required');
  const reg = loadRegistry();
  let agent = reg.agents.find((a) => a.name === name);
  if (!agent) {
    agent = {
      id:          `agent_${crypto.randomBytes(6).toString('hex')}`,
      name:        sanitizeText(name, 64),
      kind:        sanitizeText(kind, 32) || 'unknown',
      description: sanitizeText(description, 256),
      registeredAt: new Date().toISOString(),
      lastSeenAt:  null,
      sessions:    [],
      status:      'idle',
    };
    reg.agents.push(agent);
  }
  agent.lastSeenAt = new Date().toISOString();
  if (pid !== null) agent.pid = pid;
  if (mcpPort !== null) agent.mcpPort = mcpPort;
  saveRegistry(reg);
  return agent;
}

function unregister(nameOrId) {
  const reg = loadRegistry();
  reg.agents = reg.agents.filter((a) => a.name !== nameOrId && a.id !== nameOrId);
  saveRegistry(reg);
  return { ok: true };
}

function list() { return loadRegistry().agents; }

function get(nameOrId) {
  return loadRegistry().agents.find((a) => a.name === nameOrId || a.id === nameOrId) || null;
}

// ─── 4-Phase Audit Log ────────────────────────────────────────────────────────

const PHASES = new Set(['perceive', 'reason', 'act', 'learn']);

/**
 * Append one phase entry to the audit log.
 * @param {object} opts
 * @param {string} opts.agentId — agent name or registry id
 * @param {'perceive'|'reason'|'act'|'learn'} opts.phase
 * @param {string} opts.summary — one-line description
 * @param {object} [opts.detail] — optional structured data (tool call, URL, etc.)
 * @param {'allow'|'deny'|'warn'|null} [opts.decision]
 */
function auditLog({ agentId, phase, summary, detail = null, decision = null } = {}) {
  if (!PHASES.has(phase)) throw new Error(`Invalid phase: ${phase}. Must be perceive|reason|act|learn`);
  ensureDir();
  const entry = {
    ts:       new Date().toISOString(),
    agentId:  sanitizeText(agentId || 'unknown', 64),
    phase,
    summary:  sanitizeText(summary, 512),
    decision,
    detail:   detail ? JSON.parse(JSON.stringify(detail)) : null,
  };
  fs.appendFileSync(LOG, JSON.stringify(entry) + '\n', { mode: 0o600 });

  // Update agent.lastSeenAt + status
  const reg = loadRegistry();
  const a = reg.agents.find((ag) => ag.name === agentId || ag.id === agentId);
  if (a) {
    a.lastSeenAt = entry.ts;
    a.status = phase === 'act' ? 'active' : phase === 'learn' ? 'idle' : 'thinking';
    saveRegistry(reg);
  }
  return entry;
}

/** Return the last N entries from the audit log. */
function auditTail(n = 50) {
  ensureDir();
  try {
    const lines = fs.readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean);
    return lines.slice(-n).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean).reverse();
  } catch { return []; }
}

/** Return audit entries for a specific agent, newest first. */
function auditForAgent(nameOrId, n = 50) {
  return auditTail(n * 4).filter((e) => e.agentId === nameOrId).slice(0, n);
}

/**
 * Start an agent session — returns a sessionId for correlating phases.
 * Attaches to the named agent's sessions list.
 */
function sessionStart(agentNameOrId, { goal = '', vpnRequired = false } = {}) {
  const reg = loadRegistry();
  const agent = reg.agents.find((a) => a.name === agentNameOrId || a.id === agentNameOrId);
  const sessionId = `sess_${crypto.randomBytes(6).toString('hex')}`;
  const session = { id: sessionId, startedAt: new Date().toISOString(), goal: sanitizeText(goal, 256), vpnRequired, endedAt: null, phaseCount: 0 };
  if (agent) { agent.sessions = (agent.sessions || []).slice(-9); agent.sessions.push(session); agent.status = 'active'; saveRegistry(reg); }
  auditLog({ agentId: agentNameOrId, phase: 'perceive', summary: `Session started: ${goal || 'no goal'}`, detail: { sessionId } });
  return { sessionId, agent: agent || null };
}

function sessionEnd(agentNameOrId, sessionId) {
  const reg = loadRegistry();
  const agent = reg.agents.find((a) => a.name === agentNameOrId || a.id === agentNameOrId);
  if (agent) {
    const s = (agent.sessions || []).find((ss) => ss.id === sessionId);
    if (s) { s.endedAt = new Date().toISOString(); }
    agent.status = 'idle';
    saveRegistry(reg);
  }
  auditLog({ agentId: agentNameOrId, phase: 'learn', summary: 'Session ended', detail: { sessionId } });
  return { ok: true };
}

module.exports = { register, unregister, list, get, auditLog, auditTail, auditForAgent, sessionStart, sessionEnd };
