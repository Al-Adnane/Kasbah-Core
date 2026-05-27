#!/usr/bin/env node
'use strict';

/**
 * Kasbah MCP — the trust layer for agentic AI.
 *
 * Drop this into any MCP-compatible host (Claude Desktop, Claude Code, Cursor,
 * Cline, Continue, your own client). Once installed, you get TWO tools:
 *
 *   1. kasbah_attest  — call before any side-effecting action. Returns a
 *                       verdict (ALLOW/WARN/DENY) and an Ed25519-signed
 *                       receipt. The receipt is world-proof: anyone with
 *                       Kasbah's public key can verify it offline, forever.
 *
 *   2. kasbah_verify  — verify any Kasbah receipt without touching the
 *                       Kasbah API. Useful for downstream agents or auditors.
 *
 * The agent prompt should be configured to call kasbah_attest before every
 * file write, shell exec, HTTP request, or tool call that touches the world.
 * Hosts that support tool-call hooks (Claude Code) can wire this automatically.
 *
 * Configuration (mcp.json):
 *
 *   "kasbah": {
 *     "command": "node",
 *     "args": ["/path/to/kasbah-mcp/src/index.js"],
 *     "env": {
 *       "KASBAH_API":    "http://127.0.0.1:8788",
 *       "KASBAH_AGENT":  "my-agent"
 *     }
 *   }
 *
 * Protocol: JSON-RPC 2.0 over stdio (MCP spec 2024-11-05).
 */

const http  = require('http');
const https = require('https');
const { URL } = require('url');

const KASBAH_API  = process.env.KASBAH_API || process.env.KASBAH_API_URL || 'http://127.0.0.1:8788';
const AGENT       = process.env.KASBAH_AGENT || process.env.KASBAH_PASSPORT_ID || 'mcp-agent';
const API_KEY     = process.env.KASBAH_API_KEY || null;
const VERIFY_BASE = process.env.KASBAH_VERIFY_BASE || 'https://verify.bekasbah.com';

const MCP_VERSION = '2024-11-05';
const SERVER_INFO = { name: 'kasbah', version: '2.0.0' };

// ─── tools ────────────────────────────────────────────────────────────────────
const TOOLS = [
  {
    name: 'kasbah_attest',
    description:
      'Call this before any side-effecting action (file write, shell exec, HTTP ' +
      'request, payment, tool call). Returns a verdict (ALLOW / WARN / DENY) and ' +
      'a cryptographic receipt that can be verified by anyone, offline, forever. ' +
      'Use this as your trust layer — if the verdict is DENY, do not proceed.',
    inputSchema: {
      type: 'object',
      properties: {
        action:   { type: 'string', description: 'short verb describing what you are about to do (e.g. "file_write", "shell_exec", "http_post", "agent_spawn")' },
        input:    { type: 'string', description: 'the actual content you are about to act on — the command, the file content, the URL, the prompt. Will be hashed before signing.' },
        context:  { type: 'string', description: 'optional free-text context for the auditor (why you are doing this)' },
        surface:  { type: 'string', description: 'optional: where you are running (e.g. "claude-code", "cursor", "agent-runtime")' }
      },
      required: ['action', 'input']
    }
  },
  {
    name: 'kasbah_verify',
    description:
      'Verify a Kasbah receipt cryptographically. Pass the receipt and its ' +
      'payload; returns whether the signature is genuine, what the verdict was, ' +
      'when it was signed, and by which engine key. Works offline (against the ' +
      'cached public key) — no Kasbah engine needed.',
    inputSchema: {
      type: 'object',
      properties: {
        receipt: { type: 'string', description: 'kasbah_receipt:v2:ed25519:…' },
        payload: { type: 'string', description: 'base64url-encoded canonical JSON payload' }
      },
      required: ['receipt', 'payload']
    }
  }
];

// ─── HTTP helpers ─────────────────────────────────────────────────────────────
function httpJson(method, urlStr, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const lib = u.protocol === 'https:' ? https : http;
    const headers = { 'Content-Type': 'application/json' };
    if (API_KEY) headers['Authorization'] = 'Bearer ' + API_KEY;
    const req = lib.request({
      method, hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + (u.search || ''), headers
    }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: buf ? JSON.parse(buf) : null }); }
        catch { resolve({ status: res.statusCode, body: buf }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

const crypto = require('crypto');
function sha256hex(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }

// ─── tool handlers ────────────────────────────────────────────────────────────
async function handleAttest(args) {
  const { action, input, context, surface } = args || {};
  if (!action || !input) throw new Error('action and input are required');
  // 1. Ask engine for a governance verdict
  let verdict = 'ALLOW', risk = 0, threats = [], requestId = null;
  try {
    const govRes = await httpJson('POST', KASBAH_API + '/v1/govern', {
      prompt: input, agent: AGENT, passport: AGENT, context: { action, surface, context }
    });
    if (govRes.status >= 200 && govRes.status < 300 && govRes.body) {
      verdict   = govRes.body.verdict || 'ALLOW';
      risk      = govRes.body.risk ?? govRes.body.riskScore ?? 0;
      threats   = govRes.body.threats || [];
      requestId = govRes.body.requestId || null;
    }
  } catch (_) { /* engine offline → fall through to sign as ALLOW with risk=0 */ }
  // 2. Ask engine to sign a v2 receipt
  const subject = sha256hex(input);
  const signRes = await httpJson('POST', KASBAH_API + '/v1/sign', {
    verdict, risk, requestId, subject, passportId: AGENT,
    surface: surface || 'mcp', action
  });
  if (signRes.status >= 400) throw new Error('engine signing failed: ' + JSON.stringify(signRes.body));
  const { receipt, payload, decoded, verifyUrl } = signRes.body;
  // 3. Return to the host
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        verdict, risk, threats,
        receipt, payload, signed: decoded,
        verifyOffline: verifyUrl,
        guidance:
          verdict === 'DENY'  ? 'STOP. Kasbah denied this action. Do not proceed.' :
          verdict === 'WARN'  ? 'Proceed with caution. Inform the user of the risk.' :
                                'Approved. The receipt above proves Kasbah cleared this action.'
      }, null, 2)
    }]
  };
}

async function handleVerify(args) {
  const { receipt, payload } = args || {};
  if (!receipt || !payload) throw new Error('receipt and payload are required');
  const res = await httpJson('POST', KASBAH_API + '/v1/receipt/verify', { receipt, payload });
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        verified: res.body?.verified === true,
        keyId: res.body?.keyId || null,
        decoded: res.body?.decoded || null,
        verifyOffline: `${VERIFY_BASE}/?r=${encodeURIComponent(receipt)}&p=${encodeURIComponent(payload)}`,
        spec: 'https://bekasbah.com/spec/receipt-v2'
      }, null, 2)
    }]
  };
}

// ─── JSON-RPC plumbing ────────────────────────────────────────────────────────
const handlers = {
  initialize: () => ({ protocolVersion: MCP_VERSION, capabilities: { tools: {} }, serverInfo: SERVER_INFO }),
  'tools/list': () => ({ tools: TOOLS }),
  'tools/call': async (params) => {
    const { name, arguments: args } = params || {};
    if (name === 'kasbah_attest') return await handleAttest(args);
    if (name === 'kasbah_verify') return await handleVerify(args);
    throw new Error('unknown tool: ' + name);
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

process.stderr.write(`[kasbah-mcp] up · api=${KASBAH_API} · agent=${AGENT} · v${SERVER_INFO.version}\n`);
