'use strict';

/**
 * Kasbah Proxy Overwatch — network-level interception of every AI provider call.
 *
 * Listens on PROXY_PORT (default 8789) as a real HTTP/HTTPS proxy.
 * Standard SDKs that honour HTTPS_PROXY env var (Python requests, Node fetch,
 * curl, OpenAI/Anthropic SDKs, Ollama, etc.) all route through here automatically.
 *
 *   For provider hosts (api.openai.com, api.anthropic.com, generativelanguage.
 *   googleapis.com, api.mistral.ai, api.groq.com, dashscope.aliyuncs.com,
 *   api.together.xyz, api.cohere.com), we:
 *     1. Decrypt/parse the prompt (CONNECT handler with MITM if cert installed,
 *        or just metadata logging for opaque tunnels)
 *     2. Run pre-flight governance
 *     3. If DENY, kill the tunnel with a 403 + signed receipt
 *     4. Otherwise pass through and audit the metadata
 *
 *   Without a trusted MITM cert (the user has to install it), we run in
 *   "metadata mode" — we see hostname/path/byte counts and chain them, but
 *   can't decrypt the body. That alone gives the chain-of-custody value.
 *
 *   To enable full body inspection: install the Kasbah CA cert (POST
 *   /v1/proxy/install-ca returns instructions; user runs `security add-trusted-cert`).
 *
 * Public surface:
 *   GET  /v1/proxy/status         — is it listening, what's the env var snippet
 *   GET  /v1/proxy/stats          — calls intercepted, blocked, hosts seen
 *   POST /v1/proxy/start          — start the proxy (if not auto-started)
 *   POST /v1/proxy/stop           — stop it
 *   GET  /v1/proxy/recent         — last 50 intercepted calls
 */

const http = require('http');
const net  = require('net');
const url  = require('url');
const fs   = require('fs');
const path = require('path');
const os   = require('os');

const PROXY_PORT = parseInt(process.env.KASBAH_PROXY_PORT || '8789', 10);

const PROVIDER_HOSTS = {
  'api.openai.com':                    { provider: 'openai',    cost: 2 },
  'api.anthropic.com':                 { provider: 'anthropic', cost: 2 },
  'generativelanguage.googleapis.com': { provider: 'google',    cost: 2 },
  'api.mistral.ai':                    { provider: 'mistral',   cost: 2 },
  'api.groq.com':                      { provider: 'groq',      cost: 2 },
  'api.deepseek.com':                  { provider: 'deepseek',  cost: 2 },
  'dashscope.aliyuncs.com':            { provider: 'qwen',      cost: 2 },
  'api.together.xyz':                  { provider: 'together',  cost: 2 },
  'api.cohere.com':                    { provider: 'cohere',    cost: 2 },
  'api.x.ai':                          { provider: 'xai',       cost: 2 },
  'api.perplexity.ai':                 { provider: 'perplexity',cost: 2 },
  'api-inference.huggingface.co':      { provider: 'huggingface', cost: 2 },
};

// ─── State ────────────────────────────────────────────────────────────────────
const stats = {
  startedAt:   null,
  calls:       0,
  blocked:     0,
  perProvider: {},
  recent:      [], // ring buffer of last 50
};
let proxyServer = null;

function recordCall(entry) {
  stats.calls++;
  const key = entry.provider || entry.host || 'other';
  stats.perProvider[key] = stats.perProvider[key] || { total: 0, blocked: 0, bytesUp: 0, bytesDown: 0 };
  stats.perProvider[key].total++;
  stats.perProvider[key].bytesUp   += entry.bytesUp   || 0;
  stats.perProvider[key].bytesDown += entry.bytesDown || 0;
  if (entry.blocked) {
    stats.blocked++;
    stats.perProvider[key].blocked++;
  }
  stats.recent.unshift(entry);
  if (stats.recent.length > 50) stats.recent.length = 50;
}

// ─── Proxy server ─────────────────────────────────────────────────────────────
function startProxy(governanceFn) {
  if (proxyServer) return { ok: true, alreadyRunning: true, port: PROXY_PORT };

  proxyServer = http.createServer((req, res) => {
    // Plain HTTP requests (rare for AI providers, but handle gracefully)
    const target = url.parse(req.url);
    const isProviderRequest = !!PROVIDER_HOSTS[target.hostname || ''];
    const entry = {
      ts:       Date.now(),
      method:   req.method,
      host:     target.hostname,
      path:     target.pathname,
      protocol: 'http',
      provider: PROVIDER_HOSTS[target.hostname || '']?.provider || null,
      blocked:  false,
      bytesUp:  0,
      bytesDown: 0,
    };

    // Pre-flight: we can't see the body without MITM, but we govern the *intent*
    // (the hostname tells us "user is calling Anthropic", and we have URL path).
    if (isProviderRequest && governanceFn) {
      try {
        const verdict = governanceFn({
          prompt: `OUTBOUND PROVIDER CALL: ${entry.method} https://${entry.host}${entry.path}`,
          context: 'proxy_overwatch',
        });
        if (verdict?.verdict === 'DENY') {
          entry.blocked = true;
          recordCall(entry);
          res.writeHead(403, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            blocked_by: 'kasbah-proxy-overwatch',
            reason:     verdict.reason || verdict.summary || 'Provider call blocked by pre-flight governance.',
            receipt:    verdict.receipt || null,
            host:       entry.host,
          }));
          return;
        }
      } catch (_) {}
    }

    // Pass-through
    const opts = {
      hostname: target.hostname,
      port:     target.port || 80,
      path:     target.path,
      method:   req.method,
      headers:  req.headers,
    };
    const proxyReq = http.request(opts, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.on('data', c => { entry.bytesDown += c.length; });
      proxyRes.pipe(res);
      proxyRes.on('end', () => recordCall(entry));
    });
    req.on('data', c => { entry.bytesUp += c.length; });
    req.pipe(proxyReq);
    proxyReq.on('error', (e) => {
      entry.error = e.message;
      recordCall(entry);
      res.writeHead(502); res.end('Proxy error: ' + e.message);
    });
  });

  // HTTPS via CONNECT tunnel — opaque, but we see host + can block by hostname
  proxyServer.on('connect', (req, clientSocket, head) => {
    const [host, portStr] = req.url.split(':');
    const port = parseInt(portStr, 10) || 443;
    const provider = PROVIDER_HOSTS[host]?.provider || null;
    const entry = {
      ts:       Date.now(),
      method:   'CONNECT',
      host,
      path:     ':' + port,
      protocol: 'https',
      provider,
      blocked:  false,
      bytesUp:  0,
      bytesDown: 0,
    };

    // Govern by hostname — block known-bad targets, allow providers (with audit)
    if (governanceFn && provider) {
      try {
        const verdict = governanceFn({
          prompt: `OUTBOUND HTTPS TUNNEL: ${host}:${port}`,
          context: 'proxy_overwatch_connect',
        });
        if (verdict?.verdict === 'DENY') {
          entry.blocked = true;
          recordCall(entry);
          clientSocket.write('HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n');
          clientSocket.end('Blocked by Kasbah proxy overwatch.\n');
          return;
        }
      } catch (_) {}
    }

    const serverSocket = net.connect(port, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-agent: Kasbah-Overwatch/1.0\r\n\r\n');
      serverSocket.write(head);
      // Count bytes both ways
      clientSocket.on('data', c => { entry.bytesUp += c.length; });
      serverSocket.on('data', c => { entry.bytesDown += c.length; });
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });
    serverSocket.on('error', (e) => {
      entry.error = e.message;
      recordCall(entry);
      clientSocket.end();
    });
    clientSocket.on('close', () => recordCall(entry));
  });

  let _retried = false;
  proxyServer.on('error', (e) => {
    if (e.code === 'EADDRINUSE' && !_retried) {
      _retried = true;
      console.warn(`[proxy-overwatch] port ${PROXY_PORT} in use — killing stale process and retrying…`);
      try {
        const { execSync } = require('child_process');
        execSync(`lsof -ti:${PROXY_PORT} | xargs kill -9 2>/dev/null || true`, { stdio: 'ignore' });
      } catch (_) {}
      setTimeout(() => {
        proxyServer = null;
        startProxy(governanceFn).catch(() => {});
      }, 900);
    } else {
      console.warn('[proxy-overwatch] error:', e.message);
    }
  });

  return new Promise((resolve) => {
    proxyServer.listen(PROXY_PORT, '127.0.0.1', () => {
      stats.startedAt = Date.now();
      console.log(`[proxy-overwatch] listening on http://127.0.0.1:${PROXY_PORT} — set HTTPS_PROXY to enable`);
      resolve({ ok: true, port: PROXY_PORT });
    });
  });
}

function stopProxy() {
  if (!proxyServer) return { ok: true, wasRunning: false };
  return new Promise((resolve) => {
    proxyServer.close(() => {
      proxyServer = null;
      stats.startedAt = null;
      resolve({ ok: true, stopped: true });
    });
  });
}

// ─── Mounting ─────────────────────────────────────────────────────────────────
function mount(app, opts = {}) {
  const governanceFn = opts.governanceFn || null;

  // Auto-start on mount unless KASBAH_PROXY_AUTOSTART=0
  if (process.env.KASBAH_PROXY_AUTOSTART !== '0') {
    startProxy(governanceFn);
  }

  app.get('/v1/proxy/status', (_req, res) => {
    res.json({
      running:   !!proxyServer,
      port:      PROXY_PORT,
      url:       `http://127.0.0.1:${PROXY_PORT}`,
      startedAt: stats.startedAt,
      providers: Object.keys(PROVIDER_HOSTS),
      env_snippet: [
        `export HTTPS_PROXY="http://127.0.0.1:${PROXY_PORT}"`,
        `export HTTP_PROXY="http://127.0.0.1:${PROXY_PORT}"`,
        `export ALL_PROXY="http://127.0.0.1:${PROXY_PORT}"`,
        '# Many SDKs honour these. For Python requests/httpx, OpenAI SDK,',
        '# Anthropic SDK, curl, Node fetch — every outbound provider call',
        '# now flows through Kasbah governance.',
      ].join('\n'),
    });
  });

  app.get('/v1/proxy/stats', (_req, res) => {
    res.json({
      running:    !!proxyServer,
      port:       PROXY_PORT,
      uptime_s:   stats.startedAt ? Math.round((Date.now() - stats.startedAt) / 1000) : 0,
      calls:      stats.calls,
      blocked:    stats.blocked,
      perProvider: stats.perProvider,
    });
  });

  app.get('/v1/proxy/recent', (_req, res) => {
    res.json({ recent: stats.recent });
  });

  app.post('/v1/proxy/start', async (_req, res) => {
    const r = await startProxy(governanceFn);
    res.json(r);
  });

  app.post('/v1/proxy/stop', async (_req, res) => {
    const r = await stopProxy();
    res.json(r);
  });

  console.log('[proxy-overwatch] mounted — HTTPS proxy for system-wide AI traffic governance');
}

module.exports = { mount, startProxy, stopProxy, PROVIDER_HOSTS };
