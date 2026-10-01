'use strict';

/**
 * Local LLM proxy — optional sidecar on 127.0.0.1:8796.
 * SECURITY:
 *  - Requires X-Kasbah-Token (random per start; printed once)
 *  - Upstream host allowlist only (OpenAI / Anthropic)
 *  - Rejects private/link-local upstream IPs (no SSRF relay)
 *  - Drops hop-by-hop / secret headers
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const dns = require('dns').promises;
const { URL } = require('url');
const net = require('net');
const agentGuard = require('./agent-guard.js');
const aiGov = require('./ai-governance.js');

let server = null;
let token = null;
const stats = { allowed: 0, blocked: 0, errors: 0, authFail: 0, redacted: 0, injection: 0, dlp: 0 };

const ALLOW_HOSTS = new Set([
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.groq.com',
  'api.mistral.ai',
  'api.together.xyz',
]);

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const a = ip.split('.').map(Number);
    if (a[0] === 10 || a[0] === 127 || (a[0] === 169 && a[1] === 254) ||
        (a[0] === 172 && a[1] >= 16 && a[1] <= 31) ||
        (a[0] === 192 && a[1] === 168) || a[0] === 0) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === '::1' || l.startsWith('fe80:') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('::ffff:127.')) return true;
  }
  return false;
}

// Returns a resolved-safe IP for `hostname`, or null if it's private/
// unresolvable. IMPORTANT: the caller must connect to the returned IP
// directly (not re-resolve the hostname) — resolving twice (once to check,
// once to connect) is vulnerable to DNS rebinding, where a second lookup
// can return a private/loopback address after the first one passed.
async function resolveSafe(hostname) {
  if (isPrivateIp(hostname)) return null;
  try {
    const addrs = await dns.lookup(hostname, { all: true });
    if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) return null;
    return addrs[0].address;
  } catch {
    return null;
  }
}

function timingSafeTokenEqual(a, b) {
  const bufA = Buffer.from(String(a || ''));
  const bufB = Buffer.from(String(b || ''));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function start(port = 8796) {
  if (server) return { ok: true, port, already: true, token };
  token = crypto.randomBytes(24).toString('hex');
  server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/status') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ listening: true, stats, requireToken: true }));
      return;
    }
    const got = req.headers['x-kasbah-token'] || '';
    if (!token || !timingSafeTokenEqual(got, token)) {
      stats.authFail++;
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized', hint: 'set header X-Kasbah-Token to the token from the app' }));
      return;
    }
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 2_000_000) req.destroy(); });
    req.on('end', async () => {
      const decision = agentGuard.evaluate({ tool: 'llm_chat', domain: 'llm', costCents: 0 });
      if (!decision.allow) {
        stats.blocked++;
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'kasbah_blocked', reason: decision.reason, code: decision.code }));
        return;
      }
      // Lakera/CF-style local content governance: injection + DLP (+ optional redact)
      const gov = aiGov.inspectPrompt(body);
      if (gov.injection?.length) stats.injection++;
      if (gov.dlp?.length) stats.dlp++;
      if (!gov.allow) {
        stats.blocked++;
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          error: 'kasbah_ai_governance',
          code: gov.action === 'block' && gov.injection?.length ? 'PROMPT_INJECTION' : 'DLP_SECRET',
          reason: gov.reason,
          injection: gov.injection,
          dlp: gov.dlp.map((d) => ({ id: d.id, label: d.label })),
          mode: aiGov.loadPolicy().mode,
        }));
        return;
      }
      if (gov.action === 'redact') {
        body = aiGov.maybeRedactBody(body, gov) || body;
        stats.redacted++;
      }
      let target;
      const custom = req.headers['x-upstream-url'];
      if (custom) {
        try { target = new URL(String(custom)); }
        catch { res.writeHead(400); res.end('{"error":"bad upstream"}'); return; }
      } else {
        const base = (req.url.includes('anthropic') || req.headers['anthropic-version'])
          ? 'https://api.anthropic.com' + req.url
          : 'https://api.openai.com' + req.url;
        target = new URL(base);
      }
      if (!ALLOW_HOSTS.has(target.hostname)) {
        stats.blocked++;
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'upstream_not_allowed', host: target.hostname, allowed: [...ALLOW_HOSTS] }));
        return;
      }
      const safeIp = await resolveSafe(target.hostname);
      if (!safeIp) {
        stats.blocked++;
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'upstream_private_ip_blocked' }));
        return;
      }
      try {
        stats.allowed++;
        const fwdHeaders = { ...req.headers };
        delete fwdHeaders['x-upstream-url'];
        delete fwdHeaders['x-kasbah-token'];
        delete fwdHeaders['x-forward-host'];
        delete fwdHeaders['upstream'];
        fwdHeaders.host = target.host;
        fwdHeaders['accept-encoding'] = 'identity';
        const lib = target.protocol === 'https:' ? https : http;
        // Connect to the already-checked IP directly (not the hostname) so a
        // second DNS lookup can't rebind us to a private address after the
        // allowlist/private-IP check above passed. servername keeps TLS SNI
        // and certificate hostname verification pinned to the real host.
        const fwd = lib.request({
          hostname: safeIp,
          servername: target.hostname,
          port: target.port || (target.protocol === 'https:' ? 443 : 80),
          path: target.pathname + target.search,
          method: req.method,
          headers: fwdHeaders,
        }, (up) => {
          const h = { ...up.headers };
          delete h['set-cookie'];
          res.writeHead(up.statusCode || 502, h);
          up.pipe(res);
        });
        fwd.on('error', (e) => {
          stats.errors++;
          res.writeHead(502, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'upstream', detail: e.message }));
        });
        if (body) fwd.write(body);
        fwd.end();
      } catch (e) {
        stats.errors++;
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
  });
  server.listen(port, '127.0.0.1');
  return { ok: true, port, token, note: 'Set header X-Kasbah-Token on every request' };
}

function stop() {
  if (server) { try { server.close(); } catch (_) {} server = null; token = null; }
  return { ok: true };
}

function status() {
  const policy = aiGov.loadPolicy();
  return {
    listening: !!server,
    stats,
    requireToken: true,
    tokenHint: token ? token.slice(0, 6) + '…' : null,
    aiGov: { mode: policy.mode, enabled: policy.enabled, ...aiGov.stats() },
  };
}

// Write a JSON config file that Cursor / VS Code Claude plugins can pick up.
const CONFIG_PATH = require('path').join(require('os').homedir(), '.kasbah-llmgate.json');

function install(port = 8796) {
  const fs = require('fs');
  const path = require('path');
  const os = require('os');
  const t = token || require('crypto').randomBytes(24).toString('hex');
  const proxyUrl = `http://127.0.0.1:${port}`;
  const cfg = {
    proxy: proxyUrl,
    token: t,
    allowedHosts: Array.from(ALLOW_HOSTS),
    installedAt: new Date().toISOString(),
    note: 'Set OPENAI_BASE_URL=http://127.0.0.1:8796/v1 in your AI client or use http.proxy setting.',
  };
  const written = [];
  // Patch Cursor and VS Code settings.json with http.proxy pointing to this
  // gate — recording each file's prior values so uninstall() can restore
  // them instead of leaving editors permanently pointed at a dead proxy.
  const editorSettingsPaths = [
    path.join(os.homedir(), 'Library', 'Application Support', 'Cursor', 'User', 'settings.json'),
    path.join(os.homedir(), 'Library', 'Application Support', 'Code', 'User', 'settings.json'),
  ];
  const restore = [];
  for (const sp of editorSettingsPaths) {
    try {
      if (!fs.existsSync(sp)) continue;
      const raw = fs.readFileSync(sp, 'utf8');
      let settings = {};
      try { settings = JSON.parse(raw); } catch { continue; }
      // Only write if the proxy isn't already set to our address
      if (settings['http.proxy'] && settings['http.proxy'].includes('127.0.0.1:' + port)) continue;
      restore.push({
        path: sp,
        prevProxy: Object.prototype.hasOwnProperty.call(settings, 'http.proxy') ? settings['http.proxy'] : null,
        prevSupport: Object.prototype.hasOwnProperty.call(settings, 'http.proxySupport') ? settings['http.proxySupport'] : null,
      });
      settings['http.proxy'] = proxyUrl;
      settings['http.proxySupport'] = 'on';
      fs.writeFileSync(sp, JSON.stringify(settings, null, 2), { mode: 0o600 });
      written.push(sp);
    } catch (_) {}
  }
  cfg.patched = restore;
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  return { ok: true, configPath: CONFIG_PATH, proxy: proxyUrl, editorSettingsPatched: written, note: cfg.note };
}

function uninstall() {
  const fs = require('fs');
  try {
    const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    for (const r of (cfg.patched || [])) {
      try {
        const settings = JSON.parse(fs.readFileSync(r.path, 'utf8'));
        if (r.prevProxy === null) delete settings['http.proxy']; else settings['http.proxy'] = r.prevProxy;
        if (r.prevSupport === null) delete settings['http.proxySupport']; else settings['http.proxySupport'] = r.prevSupport;
        fs.writeFileSync(r.path, JSON.stringify(settings, null, 2), { mode: 0o600 });
      } catch (_) {}
    }
  } catch (_) {}
  try { fs.unlinkSync(CONFIG_PATH); } catch (_) {}
  return { ok: true };
}

module.exports = { start, stop, status, install, uninstall };
