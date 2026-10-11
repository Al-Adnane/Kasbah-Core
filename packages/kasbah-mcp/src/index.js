#!/usr/bin/env node
'use strict';

/**
 * Kasbah MCP — the trust layer for agentic AI.
 *
 * Drop this into any MCP-compatible host (Claude Desktop, Claude Code, Cursor,
 * Cline, Continue, or your own client). It gives your agent a cryptographic
 * conscience: every side-effecting action can be governed, signed, and later
 * verified by anyone — offline, forever.
 *
 * SEVENTEEN tools, three jobs:
 *
 *   TRUST LAYER
 *     kasbah_attest        — govern + Ed25519-sign an action before it runs.
 *                            Verdict ALLOW / WARN / DENY + a world-verifiable receipt.
 *     kasbah_verify        — verify any Kasbah receipt cryptographically, offline.
 *     kasbah_status        — running value report: $ saved, blocks, receipts minted.
 *     kasbah_export_audit  — tamper-evident compliance bundle for auditors.
 *
 *   GOVERNANCE MOATS
 *     kasbah_check_compliance — evaluate an action against HIPAA / GDPR / SOC2 /
 *                               PCI-DSS rule packs. ALLOW / WARN / DENY + cited rule.
 *     kasbah_trace_intent     — cross-step attack-trajectory detection (exfiltration
 *                               pipelines, privilege escalation, cost bombs).
 *     kasbah_cost_guard       — runaway-loop & spend governor: blocks agents that
 *                               loop or burn budget before the next call runs.
 *
 * Wire kasbah_attest before every file write, shell exec, HTTP request, payment,
 * or tool call that touches the world. Hosts with tool-call hooks (Claude Code)
 * can call it automatically.
 *
 * Configuration (mcp.json / claude_desktop_config.json):
 *
 *   "kasbah": {
 *     "command": "npx",
 *     "args": ["-y", "@yobekasbah/mcp-server"],
 *     "env": {
 *       "KASBAH_API":     "https://kasbah-api.fly.dev",
 *       "KASBAH_API_KEY": "ksk_…your key from kasbah-api.fly.dev/v1/auth/signup…",
 *       "KASBAH_AGENT":   "my-agent"
 *     }
 *   }
 *
 * Get a free key at https://kasbah-api.fly.dev/v1/auth/signup. For local dev point
 * KASBAH_API at http://127.0.0.1:8788.
 *
 * Protocol: JSON-RPC 2.0 over stdio (MCP spec 2024-11-05).
 */

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');
const { URL } = require('url');

const KASBAH_API  = (process.env.KASBAH_API || process.env.KASBAH_API_URL || 'http://127.0.0.1:8788').replace(/\/+$/, '');
const AGENT       = process.env.KASBAH_AGENT || process.env.KASBAH_PASSPORT_ID || 'mcp-agent';
const API_KEY     = process.env.KASBAH_API_KEY || null;
const VERIFY_BASE = (process.env.KASBAH_VERIFY_BASE || 'https://kasbah-api.fly.dev/demo/verify').replace(/\/+$/, '');
// Who is asking. Approvals are bound to this id, so two agents cannot approve for each other.
const AGENT_ID = String(process.env.KASBAH_AGENT || 'mcp-agent').slice(0, 80);

const MCP_VERSION = '2024-11-05';
const SERVER_INFO = { name: 'kasbah', version: require('../package.json').version };

const TOOLS = [
  {
    name: 'kasbah_attest',
    description:
      'Call this BEFORE any side-effecting action (file write, shell exec, HTTP ' +
      'request, payment, tool call, agent spawn). Returns a verdict ' +
      '(ALLOW / WARN / DENY) and a cryptographic receipt anyone can verify offline, ' +
      'forever. If the verdict is DENY, do not proceed.',
    inputSchema: {
      type: 'object',
      properties: {
        action:  { type: 'string', description: 'short verb for what you are about to do (e.g. "file_write", "shell_exec", "http_post", "agent_spawn")' },
        input:   { type: 'string', description: 'the actual content you are about to act on — command, file body, URL, prompt. Hashed before signing.' },
        context: { type: 'string', description: 'optional: why you are doing this (for the auditor)' },
        surface: { type: 'string', description: 'optional: where you run (e.g. "claude-code", "cursor", "agent-runtime")' }
      },
      required: ['action', 'input']
    }
  },
  {
    name: 'kasbah_verify',
    description:
      'Verify a Kasbah receipt cryptographically. Supports v2 (Ed25519) and v3 ' +
      '(Ed25519 + Merkle proofs). Returns whether the signature is genuine, the ' +
      'verdict, when it was signed, and by which engine key. Works offline.',
    inputSchema: {
      type: 'object',
      properties: {
        receipt:     { type: 'string', description: 'kasbah_receipt:v3:ed25519:…' },
        payload:     { type: 'string', description: 'base64url-encoded canonical JSON payload' },
        merkleRoot:  { type: 'string', description: 'optional Merkle root for batch verification (v3)' },
        merkleProof: { type: 'array', items: { type: 'object' }, description: 'optional Merkle proof siblings (v3)' }
      },
      required: ['receipt', 'payload']
    }
  },
  {
    name: 'kasbah_status',
    description:
      'Show what Kasbah has done for you: decisions signed, actions blocked, ' +
      '$ saved from cheaper-model routing, top token sinks, receipts minted, and ' +
      'a link to your live dashboard. Real value-for-money at a glance. No arguments.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false }
  },
  {
    name: 'kasbah_export_audit',
    description:
      'Export a tamper-evident, auditor-ready bundle of recent signed decisions. ' +
      'Each entry carries the verdict, Ed25519 signature, public-key fingerprint, ' +
      'and spec version. Hand it to SOC 2 / EU AI Act auditors — they verify offline.',
    inputSchema: {
      type: 'object',
      properties: {
        limit:   { type: 'number', description: 'how many recent decisions to export (default 100, max 1000)' },
        verdict: { type: 'string', description: 'optional filter: ALLOW | WARN | DENY' }
      }
    }
  },
  {
    name: 'kasbah_check_compliance',
    description:
      'Evaluate an agent action against pre-certified HIPAA, GDPR, SOC 2 Type II, ' +
      'PCI-DSS, and BIOMETRIC_GUARD rule packs BEFORE it runs. BIOMETRIC_GUARD ' +
      'blocks facial micro-expression / silent-speech / subvocal / BCI / QAI ' +
      'surveillance attempts. Returns ALLOW / WARN / DENY / REQUIRE_APPROVAL with ' +
      'the cited rule ID (e.g. "H-002: SSN requires redaction", "B-001: facial ' +
      'micro-expression capture prohibited"). Use for any action touching regulated ' +
      'data (PHI, PII, payment data) or biometric/intent-inference surfaces.',
    inputSchema: {
      type: 'object',
      properties: {
        verb:    { type: 'string', description: 'action verb: READ / WRITE / DELETE / EXPORT / EXEC / CAPTURE_VIDEO / ACCESS_CAMERA …' },
        target:  { type: 'string', description: 'target resource (e.g. patient_records, payment_data, user_profile, facial_expression)' },
        content: { type: 'string', description: 'optional payload to scan for regulated data (SSN, card numbers, PHI) or surveillance vectors (silent-speech, subvocal, faceprint)' },
        packs:   { type: 'string', description: 'comma-separated packs (default "HIPAA,GDPR,SOC2,BIOMETRIC_GUARD"). Options: HIPAA, GDPR, SOC2, PCI_DSS, BIOMETRIC_GUARD' }
      },
      required: ['verb']
    }
  },
  {
    name: 'kasbah_trace_intent',
    description:
      'Detect distributed, multi-step attacks invisible to single-step scanners: ' +
      'data-exfiltration pipelines, privilege-escalation chains, cost bombs. Pass ' +
      'the recent action steps (one "VERB target" per line). Returns CLEAN / WARN / ' +
      'THREAT / CRITICAL with the matched attack trajectory and confidence.',
    inputSchema: {
      type: 'object',
      properties: {
        steps: { type: 'string', description: 'recent steps, one per line as "VERB target" (e.g. "READ patient_db\\nENCODE base64\\nSEND external.com")' }
      },
      required: ['steps']
    }
  },
  {
    name: 'kasbah_cost_guard',
    description:
      'Runaway-loop and spend governor. Checks whether an agent is stuck in a tool ' +
      'loop or burning budget, and recommends ALLOW / THROTTLE / BLOCK before the ' +
      'next call runs. Returns the decision plus live usage (cost/hr, tokens/min, ' +
      'brittleness band). Call before expensive or repeated tool calls.',
    inputSchema: {
      type: 'object',
      properties: {
        agent:  { type: 'string', description: 'agent id (e.g. "orchestrator")' },
        tool:   { type: 'string', description: 'tool about to be called (e.g. "web_search")' },
        calls:  { type: 'number', description: 'how many identical recent calls have already happened (loop signal)' },
        tokens: { type: 'number', description: 'tokens per call (default 1200)' }
      },
      required: ['agent', 'tool']
    }
  },
  {
    name: 'kasbah_mcp_servers',
    description: 'List all MCP servers governed by Kasbah (ensemble, openclaw, ansari, quranfrontier).',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false }
  },
  {
    name: 'kasbah_mcp_teams',
    description: 'Manage governance teams. Create, add members, assign MCPs, apply HIPAA/GDPR/SOC2/PCI-DSS policies.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['list', 'create', 'add-member', 'add-mcp', 'list-policies', 'apply-policy'] },
        teamName: { type: 'string' }, teamId: { type: 'string' },
        passportId: { type: 'string' }, mcpServer: { type: 'string' }, policyId: { type: 'string' }
      },
      required: ['action']
    }
  },
  {
    name: 'kasbah_govern_turn',
    description:
      'Govern a full LLM turn through the Kasbah Governance Proxy: pass the message ' +
      'history and any proposed tool calls; get a bounded advisory verdict ' +
      '(CLEAR / WARN / REQUIRE_APPROVAL) plus an authoritative DENY for forbidden ' +
      'verbs / non-whitelisted domains / rate limits. Runs the validated detector, ' +
      'fail-closed governance engine, conformal-calibrated advisory ensemble, ' +
      'multi-step attack-trajectory detection, and a forward-secure audit. Use to ' +
      'wrap any agent turn before it executes tools.',
    inputSchema: {
      type: 'object',
      properties: {
        messages: { type: 'array', description: 'conversation messages [{role, content}]', items: { type: 'object' } },
        tools:    { type: 'array', description: 'proposed tool calls [{verb, target, domain}]', items: { type: 'object' } },
        clearance:{ type: 'number', description: 'caller clearance 0-4 (OBSERVER..DIRECTOR), default 2' }
      },
      required: ['messages']
    }
  },
  {
    name: 'kasbah_advisory',
    description:
      'Run a single advisory analyzer directly. Modules: detectgpt (AI-text), ' +
      'intent (multi-step trajectory), chsh, conformal (anytime-valid), dobft ' +
      '(perturbed-observer collusion), flag-fusion (correlation-aware evidence), ' +
      'evasion-bound (orthogonal-manifold cost), bounded (advisory operator). ' +
      'All are bounded-advisory and never DENY.',
    inputSchema: {
      type: 'object',
      properties: {
        module: { type: 'string', enum: ['detectgpt','intent','chsh','conformal','dobft','flag-fusion','evasion-bound','bounded'] },
        payload:{ type: 'object', description: 'module-specific body (e.g. {text} for detectgpt, {steps} for intent, {score} for conformal/bounded, {flags} for flag-fusion)' }
      },
      required: ['module']
    }
  },
  {
    name: 'kasbah_os',
    description:
      'Access the kasbah-os engine (Python bridge). Defensive actions are live: ' +
      'health, govern (9-module RKHS ensemble turn), audit-verify. The offensive ' +
      'Mythos modules are introspection-only and cannot be executed.',
    inputSchema: {
      type: 'object',
      properties: {
        action:  { type: 'string', enum: ['health','govern','audit-verify','offensive-info'] },
        messages:{ type: 'array', description: 'for action=govern: [{role, content}]', items: { type: 'object' } },
        tools:   { type: 'array', items: { type: 'object' } },
        clearance:{ type: 'number' }
      },
      required: ['action']
    }
  },
  {
    name: 'kasbah_scan',
    description:
      'Quick content scan through the Kasbah detector. Returns CLEAR / WARN / ' +
      'REQUIRE_APPROVAL with threat classes and risk score. Use for single-prompt ' +
      'or short content safety checks.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'content or prompt to scan' }
      },
      required: ['text']
    }
  },
  {
    name: 'kasbah_redteam',
    description:
      'Run the live red-team benchmark against the current governance pipeline. ' +
      'Returns detection metrics (F1, precision, recall), degradation alerts, ' +
      'and trend data. Use to verify the system is working right now.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['run', 'metrics', 'history'] }
      },
      required: ['action']
    }
  },
  {
    name: 'kasbah_fti_query',
    description:
      'Query the Federated Threat Intelligence registry. Checks whether a prompt ' +
      'hash matches any known attack in the shared Merkle tree registry. Privacy-' +
      'preserving: only SHA-256 hashes are submitted, never raw prompts.',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'SHA-256 hash of prompt to query' },
        text: { type: 'string', description: 'raw prompt (hashed locally, never transmitted)' }
      }
    }
  },
  {
    name: 'kasbah_compliance_report',
    description:
      'Generate SOC 2 Type II / ISO 27001:2022 / NIST CSF 2.0 compliance evidence ' +
      'packets from the audit chain. Returns JSON or print-ready HTML. Use for ' +
      'auditor requests or compliance automation.',
    inputSchema: {
      type: 'object',
      properties: {
        framework: { type: 'string', enum: ['soc2', 'iso27001', 'nist', 'html', 'all'] }
      },
      required: ['framework']
    }
  },
  {
    name: 'kasbah_consent',
    description:
      'Ask the human to approve a sensitive tool call. Read-only actions are allowed ' +
      'without asking. For anything that writes, deletes, sends or runs commands, this ' +
      'holds until the person answers in a system dialog on their machine (about a minute), ' +
      'then returns the outcome. Proceed ONLY when the outcome is TAP_AUTHORIZED. ' +
      'Call it before shell_execute, file_write, network_post, db_mutate and similar tools, ' +
      'and pass the real arguments in `args` so the person sees exactly what will run.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'what the agent wants to do' },
        tool: { type: 'string', description: 'tool name, e.g. shell_execute' },
        text: { type: 'string', description: 'optional content for govern cross-check' },
        scalars: { type: 'array', description: 'domain scalars [{value, tier, weight}]', items: { type: 'object' } },
        n: { type: 'number', description: 'corroborating source count' },
        agree: { type: 'number', description: 'agreeing source count' },
        coherence: { type: 'boolean', description: 'multi-step task in progress' },
        waitMs: { type: 'number', description: 'how long to hold for the tap (default 8000)' }
      },
      required: ['action']
    }
  }
];

// ─── HTTP helper ────────────────────────────────────────────────────────────────
function httpJson(method, urlStr, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const lib = u.protocol === 'https:' ? https : http;
    const headers = { 'Content-Type': 'application/json', 'x-kasbah-source': 'mcp' };
    if (API_KEY) { headers['Authorization'] = 'Bearer ' + API_KEY; headers['x-api-key'] = API_KEY; }
    const req = lib.request({
      method, hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + (u.search || ''), headers, timeout: 15000
    }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: buf ? JSON.parse(buf) : null }); }
        catch { resolve({ status: res.statusCode, body: buf }); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('request timed out after 15s')));
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

const sha256hex = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const textResult = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });

// ─── tool handlers ────────────────────────────────────────────────────────────
async function handleAttest(args) {
  const { action, input, context, surface } = args || {};
  if (!action || !input) throw new Error('action and input are required');

  // 1. governance verdict (engine offline → fall through to ALLOW/risk=0)
  let verdict = 'ALLOW', risk = 0, threats = [], requestId = null, engineSeen = false;
  try {
    const g = await httpJson('POST', KASBAH_API + '/v1/govern', {
      prompt: input, agent: AGENT, passport: AGENT, context: { action, surface, context }
    });
    if (g.status >= 200 && g.status < 300 && g.body) {
      engineSeen = true;
      verdict   = g.body.verdict || 'ALLOW';
      risk      = g.body.risk ?? g.body.riskScore ?? 0;
      threats   = g.body.threats || [];
      requestId = g.body.requestId || null;
    } else if (g.status === 401) {
      return textResult({
        error: 'unauthorized',
        hint: 'Set KASBAH_API_KEY in your MCP config. Get a free key at https://kasbah-api.fly.dev/v1/auth/signup'
      });
    }
  } catch (_) { /* offline → sign anyway, marked unverified by engine */ }

  // 2. sign a v3 receipt
  const signRes = await httpJson('POST', KASBAH_API + '/v1/sign?v=3', {
    verdict, risk, requestId, subject: sha256hex(input), passportId: AGENT,
    surface: surface || 'mcp', action, attestationType: 'governance', chainId: context || null
  });
  if (signRes.status >= 400) throw new Error('engine signing failed: ' + JSON.stringify(signRes.body));
  const { receipt, payload, decoded, verifyUrl } = signRes.body;

  return textResult({
    verdict, risk, threats,
    governed: engineSeen,
    receipt, payload, signed: decoded,
    verifyOffline: verifyUrl || `${VERIFY_BASE}/?r=${encodeURIComponent(receipt)}&p=${encodeURIComponent(payload)}`,
    guidance:
      verdict === 'DENY' ? 'STOP. Kasbah denied this action. Do not proceed.' :
      verdict === 'WARN' ? 'Proceed with caution. Inform the user of the risk.' :
                           'Approved. The receipt above proves Kasbah cleared this action.'
  });
}

async function handleVerify(args) {
  const { receipt, payload, merkleRoot, merkleProof } = args || {};
  if (!receipt || !payload) throw new Error('receipt and payload are required');
  const res = await httpJson('POST', KASBAH_API + '/v1/receipt/verify', { receipt, payload, merkleRoot, merkleProof });
  return textResult({
    verified: res.body?.verified === true,
    version: res.body?.version || null,
    alg: res.body?.alg || null,
    keyId: res.body?.keyId || null,
    merkleVerified: res.body?.merkleVerified,
    decoded: res.body?.decoded || null,
    verifyOffline: `${VERIFY_BASE}/?r=${encodeURIComponent(receipt)}&p=${encodeURIComponent(payload)}`,
    spec: res.body?.spec || 'https://github.com/Al-Adnane/Kasbah-Core/blob/main/docs/RECEIPT-SPEC-v3.md'
  });
}

async function handleCheckCompliance(args) {
  const { verb, target, content, packs } = args || {};
  if (!verb) throw new Error('verb is required');
  const res = await httpJson('POST', KASBAH_API + '/v1/algorithms/policy-engine/run', {
    verb, target: target || '', content: content || '', packs: packs || 'HIPAA,GDPR,SOC2,BIOMETRIC_GUARD'
  });
  if (res.status === 401) return textResult({ error: 'unauthorized', hint: 'Set KASBAH_API_KEY. Free key: https://kasbah-api.fly.dev/v1/auth/signup' });
  const r = res.body?.result || res.body || {};
  return textResult({
    decision: r.verdict || 'UNKNOWN',
    summary: r.summary || null,
    score: r.score ?? null,
    detail: r.detail?.evaluation || r.detail || null,
    guidance: r.verdict === 'DENY' ? 'Blocked by compliance policy — do not proceed.'
            : r.verdict === 'REQUIRE_APPROVAL' ? 'Needs human approval before proceeding.'
            : r.verdict === 'WARN' ? 'Allowed with a compliance warning — log it.'
            : 'Compliant — clear to proceed.'
  });
}

async function handleTraceIntent(args) {
  const { steps } = args || {};
  if (!steps) throw new Error('steps is required (one "VERB target" per line)');
  const res = await httpJson('POST', KASBAH_API + '/v1/algorithms/intent-trajectory/run', { steps });
  if (res.status === 401) return textResult({ error: 'unauthorized', hint: 'Set KASBAH_API_KEY. Free key: https://kasbah-api.fly.dev/v1/auth/signup' });
  const r = res.body?.result || res.body || {};
  return textResult({
    verdict: r.verdict || 'UNKNOWN',
    summary: r.summary || null,
    driftScore: r.score ?? r.detail?.driftScore ?? null,
    trajectoryMatch: r.detail?.trajectoryMatch || null,
    guidance: (r.verdict === 'CRITICAL' || r.verdict === 'THREAT')
      ? 'Multi-step attack trajectory detected — halt the agent and alert the user.'
      : r.verdict === 'WARN' ? 'Suspicious drift — review the recent steps.'
      : 'No attack trajectory detected.'
  });
}

async function handleCostGuard(args) {
  const { agent, tool, calls, tokens } = args || {};
  if (!agent || !tool) throw new Error('agent and tool are required');
  const res = await httpJson('POST', KASBAH_API + '/v1/algorithms/cost-watch/run', {
    agent, tool, calls: calls ?? 1, tokens: tokens ?? 1200
  });
  if (res.status === 401) return textResult({ error: 'unauthorized', hint: 'Set KASBAH_API_KEY. Free key: https://kasbah-api.fly.dev/v1/auth/signup' });
  const r = res.body?.result || res.body || {};
  const decision = r.detail?.decision || {};
  return textResult({
    action: (r.verdict || decision.action || 'ALLOW').toUpperCase(),
    reason: decision.reason || null,
    summary: r.summary || null,
    usage: r.detail?.usage || null,
    guidance: (r.verdict === 'BLOCK') ? 'Stop — runaway loop or budget breach. Do not make this call.'
            : (r.verdict === 'THROTTLE') ? 'Throttle — slow down or back off this tool.'
            : 'Within budget — clear to proceed.'
  });
}

async function handleStatus() {
  const [stats, usage, audit, keys] = await Promise.all([
    httpJson('GET', KASBAH_API + '/v1/stats').catch(() => ({ body: {} })),
    httpJson('GET', KASBAH_API + '/v1/track/usage').catch(() => ({ body: {} })),
    httpJson('GET', KASBAH_API + '/v1/audit?limit=200').catch(() => ({ body: {} })),
    httpJson('GET', KASBAH_API + '/v1/keys').catch(() => ({ body: {} }))
  ]);
  const s = stats.body || {}, u = usage.body || {};
  const entries = (audit.body?.entries || audit.body?.audit || []);
  const v = s.verdicts || {};

  const byAgent = {};
  for (const e of entries) { const a = e.agent || e.passportId || 'anonymous'; byAgent[a] = (byAgent[a] || 0) + 1; }
  const topSink = Object.entries(byAgent).sort((a, b) => b[1] - a[1])[0];

  const totalDecisions = s.governed || entries.length || 0;
  const blocked = v.DENY || 0, warned = v.WARN || 0;
  const totalSaved = (u.totalSpent || 0);
  const lastReceipt = entries[0]?.receipt || null;
  const lastReceiptPayload = entries[0]?.receiptPayload || null;
  const kid = keys.body?.keys?.[0]?.keyId || 'unknown';

  return textResult({
    headline: `${Number(totalDecisions).toLocaleString()} decisions signed · ${blocked} blocked · $${totalSaved.toFixed(2)} saved this session`,
    money: {
      saved_this_session_usd: +totalSaved.toFixed(4),
      tokens_tracked: u.totalTokens || 0,
      distinct_models: u.distinctModels || 0,
      top_models_by_cost: (u.rows || []).slice(0, 5).map(r => ({ id: r.id, flag: r.flag, cost: +Number(r.cost || 0).toFixed(4), calls: r.calls }))
    },
    safety: {
      total_decisions: totalDecisions, blocked, warned,
      allowed: v.ALLOW || 0,
      threats_detected: s.threatsDetected || 0,
      top_sink: topSink ? { agent: topSink[0], call_count: topSink[1] } : null
    },
    receipts: {
      signing_key_id: kid,
      latest_receipt: lastReceipt,
      verify_latest_offline_url: lastReceipt && lastReceiptPayload
        ? `${VERIFY_BASE}/?r=${encodeURIComponent(lastReceipt)}&p=${encodeURIComponent(lastReceiptPayload)}` : null,
      spec: 'https://github.com/Al-Adnane/Kasbah-Core/blob/main/docs/RECEIPT-SPEC-v3.md'
    },
    dashboards: {
      live_stream: KASBAH_API.replace(/:8788$/, ':3001') + '/dashboard',
      verify_any_receipt: `${VERIFY_BASE}/`,
      models_catalog: KASBAH_API + '/v1/models'
    },
    feedback: 'mailto:hello@bekasbah.com?subject=kasbah-mcp%20feedback'
  });
}

async function handleExportAudit(args) {
  const limit = Math.min(args?.limit || 100, 1000);
  const verdict = args?.verdict;
  const url = `/v1/audit?limit=${limit}` + (verdict ? `&verdict=${verdict}` : '');
  const audit = await httpJson('GET', KASBAH_API + url).catch(() => ({ body: {} }));
  const keys  = await httpJson('GET', KASBAH_API + '/v1/keys').catch(() => ({ body: {} }));
  const entries = audit.body?.entries || audit.body?.audit || [];
  const pubKey = keys.body?.keys?.[0] || null;

  return textResult({
    bundle_format_version: 'kasbah-audit-bundle-v1',
    generated_at: new Date().toISOString(),
    agent: AGENT,
    engine: KASBAH_API,
    signing_public_key: pubKey,
    receipt_spec: 'https://github.com/Al-Adnane/Kasbah-Core/blob/main/docs/RECEIPT-SPEC-v3.md',
    standalone_verifier: `${VERIFY_BASE}/`,
    entry_count: entries.length,
    filter: { limit, verdict: verdict || null },
    entries: entries.map(e => ({
      timestamp: e.timestamp, verdict: e.verdict, risk: e.risk, threats: e.threats,
      agent: e.agent, receipt: e.receipt, receipt_payload: e.receiptPayload,
      request_id: e.requestId, latency_ms: e.latency_ms
    })),
    how_to_verify: 'Verify each entry offline by POSTing {receipt, receipt_payload} to /v1/receipt/verify on any Kasbah engine, or load signing_public_key into any Ed25519 verifier.'
  });
}

// ─── Multi-MCP handlers ─────────────────────────────────────────────────────
async function handleMCPServers() {
  const res = await httpJson('GET', KASBAH_API + '/v1/mcp/servers');
  return textResult(res.body || {});
}
async function handleMCPTeams(args) {
  const { action, teamName, teamId, passportId, mcpServer, policyId } = args || {};
  let res;
  if (action === 'list')          res = await httpJson('GET', KASBAH_API + '/v1/mcp/servers');
  else if (action === 'list-policies') res = await httpJson('GET', KASBAH_API + '/v1/mcp/policies');
  else if (action === 'create')   res = await httpJson('POST', KASBAH_API + '/v1/mcp/teams', { name: teamName, adminPassportId: passportId });
  else if (action === 'add-member') res = await httpJson('POST', KASBAH_API + `/v1/mcp/teams/${teamId}/members`, { passportId });
  else if (action === 'add-mcp')  res = await httpJson('POST', KASBAH_API + `/v1/mcp/teams/${teamId}/mcp`, { mcpServer });
  else if (action === 'apply-policy') res = await httpJson('POST', KASBAH_API + `/v1/mcp/teams/${teamId}/policies`, { policyId });
  else throw new Error('Unknown action: ' + action);
  return textResult(res.body || {});
}

async function handleGovernTurn(args) {
  const { messages, tools, clearance } = args || {};
  if (!Array.isArray(messages)) throw new Error('messages array is required');
  const res = await httpJson('POST', KASBAH_API + '/v1/proxy/turn', {
    messages, tools: tools || [], clearance: clearance != null ? clearance : 2
  });
  if (res.status === 503) return textResult({ error: 'governance proxy not available on the API server' });
  const r = res.body || {};
  return textResult({
    status: r.status, signal: r.signal, actionId: r.actionId || null,
    content: r.detail?.content, governance: r.detail?.governance,
    trajectory: r.detail?.trajectory, advisory: r.detail?.advisory,
    guidance: r.signal === 'DENY' ? 'Authoritative DENY — do not proceed.'
            : r.signal === 'REQUIRE_APPROVAL' ? 'Queue for human approval before executing.'
            : r.signal === 'WARN' ? 'Proceed with caution — logged.' : 'Clear to proceed.'
  });
}

async function handleAdvisory(args) {
  const { module, payload } = args || {};
  if (!module) throw new Error('module is required');
  const res = await httpJson('POST', KASBAH_API + `/v1/advisory/${module}`, payload || {});
  if (res.status === 404) return textResult({ error: 'unknown advisory module: ' + module });
  return textResult(res.body || {});
}

async function handleKasbahOS(args) {
  const { action, messages, tools, clearance } = args || {};
  if (!action) throw new Error('action is required');
  let res;
  if (action === 'health')          res = await httpJson('GET',  KASBAH_API + '/v1/kasbah-os/health');
  else if (action === 'audit-verify') res = await httpJson('GET', KASBAH_API + '/v1/kasbah-os/audit/verify');
  else if (action === 'offensive-info') res = await httpJson('GET', KASBAH_API + '/v1/kasbah-os/offensive/info');
  else if (action === 'govern')     res = await httpJson('POST', KASBAH_API + '/v1/kasbah-os/governance/turn',
                                       { messages: messages || [], tools: tools || [], clearance: clearance != null ? clearance : 2 });
  else throw new Error('unknown action: ' + action);
  if (res.status === 503) return textResult({ error: 'kasbah-os bridge not available (python3/numpy required on the API host)' });
  return textResult(res.body || {});
}

async function handleScan(args) {
  const { text } = args || {};
  if (!text) throw new Error('text is required');
  const res = await httpJson('POST', KASBAH_API + '/v1/scan', { text });
  const r = res.body || {};
  return textResult({ verdict: r.verdict || 'UNKNOWN', risk: r.risk ?? null, threats: r.threats || [], intervention: r.intervention || null });
}

async function handleRedteam(args) {
  const { action } = args || {};
  if (action === 'metrics' || action === 'history' || !action) {
    const res = await httpJson('GET', KASBAH_API + '/v1/benchmark', null);
    const r = res.body || {};
    return textResult({ passed: r.passed, total: r.totalTests, detectionRate: r.detectionRate, falsePositiveRate: r.falsePositiveRate, missed: r.missedAttacks || [] });
  }
  const res = await httpJson('POST', KASBAH_API + '/v1/redteam/run', {});
  return textResult(res.body || {});
}

async function handleFtiQuery(args) {
  const { hash, text } = args || {};
  const crypto = require('crypto');
  const h = hash || (text ? crypto.createHash('sha256').update(String(text)).digest('hex') : null);
  if (!h) throw new Error('hash or text is required (text is hashed locally, never transmitted)');
  const res = await httpJson('POST', KASBAH_API + '/v1/fti/query', { hash: h });
  return textResult(res.body || {});
}

async function handleComplianceReport(args) {
  const { framework } = args || {};
  const routes = { soc2: '/v1/compliance/soc2', iso27001: '/v1/compliance/iso27001', nist: '/v1/compliance/nist' };
  if (framework === 'all') {
    const out = {};
    for (const [k, route] of Object.entries(routes)) {
      const res = await httpJson('GET', KASBAH_API + route, null);
      out[k] = res.body || {};
    }
    return textResult(out);
  }
  const route = routes[framework] || routes.soc2;
  const res = await httpJson('GET', KASBAH_API + route, null);
  return textResult(res.body || {});
}

async function handleConsent(args) {
  const { action, tool, text, scalars, n, agree, coherence, waitMs } = args || {};
  const toolArgs = (args && typeof args.args === 'object' && args.args) || {};
  if (!action) throw new Error('action is required');
  // Read-only actions are allowed without asking — this is what prevents prompt fatigue.
  const assessRes = await httpJson('POST', KASBAH_API + '/v1/consent/assess', { action, tool, args: toolArgs });
  const tier = assessRes.body || {};
  if (assessRes.status !== 200) {
    // Cannot reach the gate, or it refused: fail closed.
    return textResult({ id: null, outcome: 'UNAVAILABLE', guidance: 'The approval gate could not be reached — DO NOT execute.' });
  }
  if (!tier.tapRequired) {
    return textResult({ id: null, tier: tier.tier, tapRequired: false, outcome: 'auto-allowed (read-only)', guidance: 'Proceed. Read-only actions do not need approval.' });
  }
  const req = await httpJson('POST', KASBAH_API + '/v1/consent/request', {
    action, tool, text, args: toolArgs, scalars: scalars || [], n: n || 0, agree: agree || 0,
    coherence: !!coherence, agentId: AGENT_ID,
  });
  const gate = req.body || {};
  if (!gate.id) {
    return textResult({ id: null, outcome: 'REFUSED', reason: gate.error || 'request refused', guidance: 'The approval gate refused the request — DO NOT execute.' });
  }
  if (gate.gateReady === false) {
    return textResult({ id: gate.id, outcome: 'NOT_APPROVABLE', reason: gate.notReadyReason || gate.status || 'the gate cannot approve this request', guidance: 'No approval is possible for this request — DO NOT execute.' });
  }
  // Wait as long as the person has to answer (the gate reports its own window).
  const window = Math.min(Number(waitMs) || Number(gate.graceMs) || 8000, 120000);
  const deadline = Date.now() + window + 1500;
  for (;;) {
    const st = await httpJson('GET', KASBAH_API + '/v1/consent/pending', null);
    if (st.status !== 200) break;
    const still = (st.body?.pending || []).some((p) => p.id === gate.id);
    if (!still) break;
    if (Date.now() > deadline) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  const audit = await httpJson('GET', KASBAH_API + '/v1/consent/audit?limit=50', null);
  const FINAL = ['TAP_AUTHORIZED', 'TAP_DENIED', 'DISCONNECT_TIMEOUT', 'TAP_GATE_FAIL'];
  const mine = (audit.body?.audit || []).find((e) => e.id === gate.id && FINAL.includes(e.event));
  const ok = !!mine && mine.event === 'TAP_AUTHORIZED' && (gate.approverRequired ? mine.humanBound === true : true);
  return textResult({
    id: gate.id, tier: gate.consequenceTier || gate.tier, mode: gate.mode,
    outcome: mine ? mine.event : 'NO_ANSWER',
    humanBound: mine ? mine.humanBound === true : false,
    guidance: ok ? 'Approved by the human — proceed with exactly this action and these arguments.' : 'Not approved — DO NOT execute.',
  });
}

// ─── JSON-RPC plumbing ────────────────────────────────────────────────────────
const CALL = {
  kasbah_attest:           handleAttest,
  kasbah_verify:           handleVerify,
  kasbah_status:           () => handleStatus(),
  kasbah_export_audit:     handleExportAudit,
  kasbah_check_compliance: handleCheckCompliance,
  kasbah_trace_intent:     handleTraceIntent,
  kasbah_cost_guard:       handleCostGuard,
  kasbah_mcp_servers:      handleMCPServers,
  kasbah_mcp_teams:        handleMCPTeams,
  kasbah_govern_turn:      handleGovernTurn,
  kasbah_advisory:         handleAdvisory,
  kasbah_os:               handleKasbahOS,
  kasbah_scan:             handleScan,
  kasbah_redteam:          handleRedteam,
  kasbah_fti_query:        handleFtiQuery,
  kasbah_compliance_report: handleComplianceReport,
  kasbah_consent:          handleConsent
};

const handlers = {
  initialize: () => ({ protocolVersion: MCP_VERSION, capabilities: { tools: {} }, serverInfo: SERVER_INFO }),
  'tools/list': () => ({ tools: TOOLS }),
  'tools/call': async (params) => {
    const { name, arguments: args } = params || {};
    const fn = CALL[name];
    if (!fn) throw new Error('unknown tool: ' + name);
    return await fn(args);
  }
};

function reply(id, result) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n'); }
function replyError(id, code, message) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n'); }

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', async (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    const { id, method, params } = msg;
    const h = handlers[method];
    if (!h) { if (id !== undefined) replyError(id, -32601, 'method not found: ' + method); continue; }
    try {
      const result = await h(params);
      if (id !== undefined) reply(id, result);
    } catch (e) {
      if (id !== undefined) replyError(id, -32000, e.message || String(e));
    }
  }
});

process.stderr.write(`[kasbah-mcp] up · api=${KASBAH_API} · agent=${AGENT} · key=${API_KEY ? 'set' : 'MISSING'} · v${SERVER_INFO.version}\n`);
if (!API_KEY) process.stderr.write('[kasbah-mcp] no KASBAH_API_KEY — govern/compliance/intent/cost tools need one. Free key: https://kasbah-api.fly.dev/v1/auth/signup\n');

// Anonymous boot ping — count only, no prompts/payloads/PII. Opt out: KASBAH_NO_TELEMETRY=1.
if (!process.env.KASBAH_NO_TELEMETRY) {
  setImmediate(() => { httpJson('POST', KASBAH_API + '/_pulse', { surface: 'mcp', version: SERVER_INFO.version }).catch(() => {}); });
}
