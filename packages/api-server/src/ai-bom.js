'use strict';

/**
 * AI-BOM — Bill of Materials for AI assets (Lasso-style inventory).
 * Answers: what models, agents, MCP hosts, CLIs, keys, and AI apps are running
 * here, who owns them, and what risk they carry.
 *
 * Aggregates existing discovery.js + policy + kernel state — does not invent
 * a second inventory engine.
 */

const os = require('os');
const fs = require('fs');
const path = require('path');

function _safe(fn, fallback) {
  try { return fn(); } catch (_) { return fallback; }
}

/**
 * @param {object} opts
 * @param {object} [opts.discovery]  result of discovery.scan() / discover* helpers
 * @param {object} [opts.policy]     .kasbahpolicy.json object
 * @param {Array}  [opts.agents]     known agents
 */
function build(opts = {}) {
  const items = [];
  let id = 0;
  const push = (item) => items.push({ id: `bom_${String(++id).padStart(4, '0')}`, ...item });

  // Models / providers from discovery if present
  const disc = opts.discovery || {};
  const models = disc.models || disc.llms || [];
  for (const m of (Array.isArray(models) ? models : [])) {
    push({
      kind: 'model',
      name: m.name || m.id || m.model || 'unknown-model',
      vendor: m.vendor || m.provider || m.family || 'unknown',
      runtime: m.runtime || m.endpoint || m.baseURL || 'cloud',
      risk: m.local || m.runtime === 'local' ? 'low' : 'medium',
      tags: ['model'],
    });
  }

  // MCP hosts
  const mcp = disc.mcpHosts || disc.mcp || [];
  for (const h of (Array.isArray(mcp) ? mcp : Array.isArray(mcp.hosts) ? mcp.hosts : [])) {
    push({
      kind: 'mcp_host',
      name: h.name || h.host || h.id || 'mcp-host',
      vendor: h.vendor || 'mcp',
      runtime: h.path || h.url || 'local',
      risk: 'high',
      tags: ['mcp', 'tool-access'],
    });
  }

  // CLIs / agents
  const clis = disc.clis || disc.tools || [];
  for (const c of (Array.isArray(clis) ? clis : [])) {
    push({
      kind: 'cli',
      name: c.name || c.id || String(c),
      vendor: c.vendor || 'cli',
      runtime: c.path || 'path',
      risk: 'medium',
      tags: ['cli', 'agent-adjacent'],
    });
  }

  // API keys found (names only — never values)
  const keys = disc.apiKeys || disc.keys || [];
  for (const k of (Array.isArray(keys) ? keys : [])) {
    push({
      kind: 'credential',
      name: k.label || k.name || k.id || 'api-key',
      vendor: k.provider || 'unknown',
      runtime: k.source || 'env',
      risk: 'high',
      tags: ['secret', 'credential'],
      note: 'value redacted',
    });
  }

  // Policy-declared agents / surfaces
  const policy = opts.policy || {};
  const forbidden = policy?.governance?.forbidden_verbs || [];
  if (forbidden.length) {
    push({
      kind: 'policy',
      name: 'kasbah-policy',
      vendor: 'kasbah',
      runtime: path.join(process.cwd(), '.kasbahpolicy.json'),
      risk: 'low',
      tags: ['policy-as-code', 'governance'],
      note: `${forbidden.length} forbidden verbs, compliance packs: ${(policy.metadata?.compliance_packs || []).join(',') || '—'}`,
    });
  }

  // Host self
  push({
    kind: 'endpoint',
    name: os.hostname(),
    vendor: 'host',
    runtime: `${os.platform()} ${os.release()}`,
    risk: 'info',
    tags: ['endpoint'],
    note: `user=${os.userInfo?.().username || '?'}`,
  });

  // If nothing discovered, still return a valid empty-ish BOM with host
  const byKind = {};
  for (const it of items) byKind[it.kind] = (byKind[it.kind] || 0) + 1;
  const highRisk = items.filter((i) => i.risk === 'high').length;

  return {
    spec: 'kasbah-ai-bom/v1',
    generatedAt: new Date().toISOString(),
    host: { hostname: os.hostname(), platform: os.platform(), user: _safe(() => os.userInfo().username, '?') },
    summary: {
      total: items.length,
      byKind,
      highRisk,
      posture: highRisk === 0 ? 'clean' : highRisk < 3 ? 'watch' : 'elevated',
    },
    items,
  };
}

module.exports = { build };
