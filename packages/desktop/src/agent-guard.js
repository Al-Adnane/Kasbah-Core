'use strict';

/**
 * Local Agent Guard — policy for AI agents running on this Mac.
 * No cloud. File-based lock + optional HTTP gate for MCP hosts.
 *
 * Unique: if VPN drops, agent tool use is blocked until VPN returns
 * (fail-closed when "require VPN" is on).
 *
 * Content governance (governContent/diagnostics below) delegates to the real
 * @kasbah/control package (packages/control) — KasbahAgentControl for
 * per-call verdicts, CausalLoopBreaker (KL-divergence over recorded agent
 * risk/message history) and TimingChannelDetector (permutation entropy +
 * mutual information over recorded response timestamps) for cross-call
 * diagnostics. All three are real, tested modules; nothing here fabricates
 * a score. If the control package can't be located (e.g. a manually
 * packaged build missing that resource), these functions report
 * `available:false` rather than returning synthetic data.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const crypto = require('crypto');

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const POLICY = path.join(DIR, 'agent-policy.json');
const LOCK = path.join(DIR, 'agent-lock.json');
const EVENTS = path.join(DIR, 'agent-events.json');
const MAX_EVENTS = 500;

function ensure() { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); }

function loadPolicy() {
  const d = defaultPolicy();
  try {
    const p = JSON.parse(fs.readFileSync(POLICY, 'utf8')) || {};
    return {
      ...d,
      ...p,
      // Never let a partial write drop the hard-block list.
      blockTools: [...new Set([...(d.blockTools || []), ...(p.blockTools || [])])],
    };
  } catch {
    return d;
  }
}

function defaultPolicy() {
  return {
    requireVpn: true,
    allowTools: ['read', 'list', 'search', 'kasbah_govern'],
    blockTools: ['delete_file', 'rm', 'format', 'curl_exec', 'eval', 'ptrace'],
    blockDomains: ['pastebin.com'],
    maxCostCents: 500,
    enabled: true,
  };
}

function savePolicy(p) {
  ensure();
  fs.writeFileSync(POLICY, JSON.stringify(p, null, 2), { mode: 0o600 });
  return p;
}

function loadLock() {
  try { return JSON.parse(fs.readFileSync(LOCK, 'utf8')); } catch { return null; }
}

function writeLock(o) {
  ensure();
  fs.writeFileSync(LOCK, JSON.stringify(o, null, 2), { mode: 0o600 });
}

/** Called when VPN state changes. */
function setVpnState(connected, meta = {}) {
  const policy = loadPolicy();
  const lock = loadLock() || {};
  const reason = connected
    ? null
    : (policy.requireVpn ? 'VPN required — tunnel down' : null);
  writeLock({
    blocked: !!reason,
    reason,
    vpnConnected: !!connected,
    meta,
    updatedAt: new Date().toISOString(),
  });
  return loadLock();
}

/**
 * Evaluate a tool call. Returns { allow, reason, receiptHint }.
 * @param {object} call { tool, args, domain, costCents }
 */
function evaluate(call = {}) {
  const policy = loadPolicy();
  if (!policy.enabled) return { allow: true, reason: 'guard disabled' };
  const lock = loadLock();
  if (lock && lock.blocked) {
    return { allow: false, reason: lock.reason || 'locked', code: 'VPN_LOCK' };
  }
  const tool = String(call.tool || '').toLowerCase();
  if ((policy.blockTools || []).some((b) => tool.includes(String(b).toLowerCase()))) {
    return { allow: false, reason: `blocked tool: ${tool}`, code: 'TOOL_BLOCK' };
  }
  if (policy.allowTools && policy.allowTools.length && !policy.allowTools.some((a) => tool.includes(String(a).toLowerCase()))) {
    // allowlist mode — only if allowTools is non-empty AND not a generic read
    if (!/read|list|search|govern/.test(tool)) {
      return { allow: false, reason: `not in allowlist: ${tool}`, code: 'TOOL_NOT_ALLOWED' };
    }
  }
  const domain = String(call.domain || call.url || '');
  if (domain && (policy.blockDomains || []).some((d) => domain.includes(d))) {
    return { allow: false, reason: `blocked domain: ${domain}`, code: 'DOMAIN_BLOCK' };
  }
  if (policy.maxCostCents != null && call.costCents != null && call.costCents > policy.maxCostCents) {
    return { allow: false, reason: 'budget exceeded', code: 'BUDGET' };
  }
  return { allow: true, reason: 'ok' };
}

/**
 * Tiny local HTTP gate for MCP / scripts: POST /evaluate {tool,domain,costCents}
 *
 * SECURITY: requires X-Kasbah-Token (random per start, timing-safe compare) —
 * same posture as llm-proxy.js's gate. Previously this endpoint had no
 * authentication at all, so any local process could read policy/lock state.
 *
 * Honest scope: this is an advisory gate an MCP host/script can choose to
 * call before acting — it does not itself intercept or execute tool calls,
 * so a caller that simply never calls /evaluate is not blocked by it. The
 * fail-closed guarantee (VPN down → tools blocked) only holds for callers
 * that actually consult this endpoint. See claim-ledger.js.
 */
let server = null;
let gateToken = null;

function timingSafeTokenEqual(a, b) {
  const bufA = Buffer.from(String(a || ''));
  const bufB = Buffer.from(String(b || ''));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function startServer(port = 8795) {
  if (server) return { ok: true, port, already: true, token: gateToken };
  gateToken = crypto.randomBytes(24).toString('hex');
  server = http.createServer((req, res) => {
    const got = req.headers['x-kasbah-token'] || '';
    if (!gateToken || !timingSafeTokenEqual(got, gateToken)) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized', hint: 'set header X-Kasbah-Token to the token from the app' }));
      return;
    }
    if (req.method === 'GET' && req.url === '/status') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ policy: loadPolicy(), lock: loadLock() }));
      return;
    }
    if (req.method === 'POST' && req.url === '/evaluate') {
      let b = '';
      req.on('data', (c) => (b += c));
      req.on('end', () => {
        let body = {};
        try { body = JSON.parse(b || '{}'); } catch (_) {}
        const r = evaluate(body);
        res.writeHead(r.allow ? 200 : 403, { 'content-type': 'application/json' });
        res.end(JSON.stringify(r));
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  server.listen(port, '127.0.0.1');
  return { ok: true, port, token: gateToken, note: 'Set header X-Kasbah-Token on every request' };
}

function stopServer() {
  if (server) { try { server.close(); } catch (_) {} server = null; gateToken = null; }
  return { ok: true };
}

function status() {
  return {
    policy: loadPolicy(), lock: loadLock(), listening: !!server, control: controlStatus(),
    tokenHint: gateToken ? gateToken.slice(0, 6) + '…' : null,
    advisoryOnly: true, // this gate is opt-in for callers; see startServer() doc comment
  };
}

// ─── Real content governance (@kasbah/control) ─────────────────────────────
// packages/control is a sibling package, not an npm dependency of
// packages/desktop — resolve it the same way main.js resolves kasbah-vpn /
// api-server (by existence, since a manually packaged Electron.app can
// report isPackaged=false and land Resources differently than dev).
function resolveControlDir() {
  const { app } = (() => { try { return require('electron'); } catch (_) { return {}; } })();
  const candidates = [
    process.resourcesPath ? path.join(process.resourcesPath, 'packages', 'control') : null,
    path.join(__dirname, '../../control'),
    path.join(__dirname, '../../../packages/control'),
    app && app.getAppPath ? path.join(app.getAppPath(), '../packages/control') : null,
  ].filter(Boolean);
  for (const dir of candidates) {
    try { if (fs.existsSync(path.join(dir, 'src', 'index.js'))) return dir; } catch (_) {}
  }
  return null;
}

let _controlMods = undefined; // undefined = not attempted, null = unavailable, object = loaded
function controlMods() {
  if (_controlMods !== undefined) return _controlMods;
  const dir = resolveControlDir();
  if (!dir) { _controlMods = null; return _controlMods; }
  try {
    const { KasbahAgentControl } = require(path.join(dir, 'src', 'index.js'));
    const { CausalLoopBreaker } = require(path.join(dir, 'src', 'causal-loop-breaker.js'));
    const { TimingChannelDetector } = require(path.join(dir, 'src', 'timing-channel-detector.js'));
    _controlMods = {
      dir,
      control: new KasbahAgentControl({ mode: 'enforce', failOpen: false, timeoutMs: 300 }),
      causal: new CausalLoopBreaker(),
      timing: new TimingChannelDetector(),
    };
  } catch (e) {
    _controlMods = null;
    console.error('[agent-guard] @kasbah/control unavailable:', e.message);
  }
  return _controlMods;
}

function controlStatus() {
  const m = controlMods();
  return { available: !!m, dir: m ? m.dir : null };
}

function loadEvents() {
  try { return JSON.parse(fs.readFileSync(EVENTS, 'utf8')); } catch { return []; }
}
function appendEvent(ev) {
  const events = loadEvents();
  events.push({ ts: Date.now(), ...ev });
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
  ensure();
  fs.writeFileSync(EVENTS, JSON.stringify(events), { mode: 0o600 });
  return events;
}
function recentEvents(limit = 100) {
  const events = loadEvents();
  return events.slice(-Math.max(1, Math.min(limit, MAX_EVENTS)));
}

/**
 * Real content governance for a tool call or agent message, on top of the
 * tool/domain allowlist in evaluate() above. Runs the actual KasbahAgentControl
 * decision engine (13-layer KasbahSentinel) against the call's content, and
 * feeds the real cross-call detectors (causal-loop, timing-channel) with the
 * resulting risk score and timestamp so their analysis reflects genuine
 * session activity, not synthetic data.
 *
 * @param {object} call { agent, tool, content }
 * @returns {Promise<object>} { available, verdict, risk, reason, proof, requestId }
 */
async function governContent(call = {}) {
  const m = controlMods();
  if (!m) return { available: false, error: 'control package not found' };

  const agentId = String(call.agent || 'kasbah-client');
  const decision = await m.control.govern({
    type: 'tool_use',
    tool: call.tool || 'unknown',
    input: { content: call.content || '' },
    agent: agentId,
    timestamp: Date.now(),
  });

  const ts = Date.now();
  try { m.causal.recordAgentState(agentId, decision.risk || 0, ts); } catch (_) {}
  try { m.timing.recordResponse(agentId, ts, { tool: call.tool || 'unknown' }); } catch (_) {}

  appendEvent({
    type: 'govern', agent: agentId, tool: call.tool || null,
    verdict: decision.verdict, risk: decision.risk, requestId: decision.requestId,
  });

  return {
    available: true,
    verdict: decision.verdict,
    risk: decision.risk,
    reason: decision.reason,
    proof: decision.proof,
    requestId: decision.requestId,
    latencyMs: decision.latencyMs,
  };
}

let _extraDetectors;
function extraDetectors() {
  if (_extraDetectors !== undefined) return _extraDetectors;
  const dir = resolveControlDir();
  if (!dir) { _extraDetectors = null; return _extraDetectors; }
  const load = (file, pick) => {
    try {
      const m = require(path.join(dir, 'src', file));
      return pick(m);
    } catch (e) { return { __error: e.message }; }
  };
  try {
    _extraDetectors = {
      topo: load('topo-shield.js', (m) => new m.TopoShield()),
      stigmergic: load('stigmergic-covert-channel.js', (m) => new m.StigmergicCovertChannelDetector()),
      hypergraph: load('hypergraph-collusion-detector.js', (m) => new m.HypergraphCollusionDetector()),
      // Additional detectors from packages/control — fail-soft per module.
      detectGpt: load('detectgpt.js', (m) => m.detectAIText),
      conformal: load('conformal-martingale.js', (m) => new m.ConformalMartingaleMonitor()),
      chsh: load('chsh-coordination.js', (m) => new m.CHSHCoordinationDetector()),
      shadow: load('shadow-consensus.js', (m) => new m.ShadowConsensus()),
      surprisal: load('surprisal-budget-manager.js', (m) => new m.SurprisalBudgetManager()),
      panopticon: load('panopticon-asymmetry-detector.js', (m) => new m.PanopticonAsymmetryDetector()),
      flagFuser: load('flag-correlation-weighting.js', (m) => new m.FlagCorrelationFuser()),
      policy: load('kasbah-policy-engine.js', (m) => new m.KasbahPolicyEngine({ packs: ['BIOMETRIC_GUARD'] })),
    };
  } catch (e) {
    _extraDetectors = { error: e.message };
  }
  return _extraDetectors;
}

/** Safe status probe for extra detectors (no heavy analysis). */
function extraDetectorStatus(ex) {
  const out = {};
  if (!ex || ex.error) return { error: ex?.error || 'unavailable' };
  for (const [name, inst] of Object.entries(ex)) {
    if (name === 'error') continue;
    if (inst && inst.__error) { out[name] = { available: false, error: inst.__error }; continue; }
    if (typeof inst === 'function') { out[name] = { available: true, kind: 'function' }; continue; }
    out[name] = { available: !!inst, kind: inst?.constructor?.name || typeof inst };
  }
  return out;
}

/**
 * Real cross-call diagnostics computed from whatever activity has actually
 * been recorded via governContent() so far in this run — not synthetic.
 */
function diagnostics() {
  const m = controlMods();
  if (!m) return { available: false, error: 'control package not found' };
  let causalLoops, timingChannel;
  try { causalLoops = m.causal.analyze(); } catch (e) { causalLoops = { error: e.message }; }
  try { timingChannel = m.timing.analyze(); } catch (e) { timingChannel = { error: e.message }; }

  // Extra detectors (item #3) — feed from recorded events where possible.
  const extra = {};
  const ex = extraDetectors();
  if (ex && !ex.error) {
    try {
      const ev = recentEvents(50);
      const pts = ev.map((e, i) => [i, Number(e.risk || 0), e.verdict === 'ALLOW' ? 0 : 1]);
      if (ex.topo && pts.length >= 3) {
        extra.topo = ex.topo.analyze ? ex.topo.analyze(pts) : { points: pts.length, note: 'TopoShield loaded' };
      } else {
        extra.topo = { available: true, note: 'need ≥3 governed events' };
      }
    } catch (e) { extra.topo = { error: e.message }; }
    try {
      extra.stigmergic = { available: true, note: 'feed via env mutations — idle until traffic' };
      if (ex.stigmergic?.report) extra.stigmergic = ex.stigmergic.report();
    } catch (e) { extra.stigmergic = { error: e.message }; }
    try {
      extra.hypergraph = { available: true, note: 'needs multi-agent tool co-occurrence' };
      if (ex.hypergraph?.getState) extra.hypergraph = ex.hypergraph.getState();
    } catch (e) { extra.hypergraph = { error: e.message }; }
  } else {
    extra.error = ex?.error || 'control package not found';
  }

  return {
    available: true,
    causalLoops,
    timingChannel,
    extra,
    extraStatus: extraDetectorStatus(ex),
    recentEvents: recentEvents(20),
  };
}

module.exports = {
  loadPolicy, savePolicy, setVpnState, evaluate, startServer, stopServer, status, LOCK,
  governContent, diagnostics, recentEvents,
};
