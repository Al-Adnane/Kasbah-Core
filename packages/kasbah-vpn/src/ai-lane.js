'use strict';

/**
 * AI lane — local governed egress for AI traffic.
 *
 * A localhost listener that forwards provider-shaped requests to the Kasbah
 * gateway's universal proxy (/v1/proxy/:provider/*), which applies governance
 * (injection/PII/secret/destructive-intent), cost metering, and signs a
 * receipt per call. Point any SDK at it:
 *
 *   OPENAI_BASE_URL=http://127.0.0.1:8790/openai/v1
 *   ANTHROPIC_BASE_URL=http://127.0.0.1:8790/anthropic
 *
 * Streaming (SSE) passes through untouched — the gateway is byte-identical
 * passthrough. This is explicit-proxy capture, not TLS interception: apps opt
 * in via base URL, keys stay in the app's own headers, and nothing is
 * man-in-the-middled.
 */

const http = require('http');
const { AI_PROVIDERS } = require('./providers');

const DEFAULT_PORT = 8790;
const DEFAULT_GATEWAY = process.env.KASBAH_GATEWAY_URL || 'https://kasbah-api.fly.dev';

// Hop-by-hop headers must not be forwarded (RFC 9110 §7.6.1).
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length',
]);

/**
 * Start the AI lane. Returns { server, port, gateway } once listening.
 * onEvent(evt) receives {type:'forward'|'reject', provider, path, status}.
 */
function startAiLane({ port = DEFAULT_PORT, gateway = DEFAULT_GATEWAY, onEvent } = {}) {
  const base = String(gateway).replace(/\/$/, '');
  const slugs = new Set(AI_PROVIDERS.map((p) => p.slug));

  const server = http.createServer(async (req, res) => {
    const [, slug, ...rest] = req.url.split('?')[0].split('/');
    const query = req.url.includes('?') ? '?' + req.url.split('?').slice(1).join('?') : '';

    if (req.url === '/' || req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        service: 'kasbah-vpn ai-lane',
        gateway: base,
        providers: [...slugs],
        usage: `point base URLs at http://127.0.0.1:${port}/<provider>/...`,
      }, null, 2));
      return;
    }

    if (!slugs.has(slug)) {
      onEvent?.({ type: 'reject', provider: slug, path: req.url, status: 404 });
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: `unknown provider "${slug}"`, known: [...slugs] }));
      return;
    }

    const target = `${base}/v1/proxy/${slug}/${rest.join('/')}${query}`;
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (!HOP_BY_HOP.has(k.toLowerCase())) headers[k] = v;
    }
    // Inject lane-level API key when the client did not supply one.
    if (process.env.KASBAH_API_KEY && !headers['authorization'] && !headers['x-api-key']) {
      headers['authorization'] = 'Bearer ' + process.env.KASBAH_API_KEY;
      headers['x-api-key'] = process.env.KASBAH_API_KEY;
    }

    try {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const body = Buffer.concat(chunks);

      const upstream = await fetch(target, {
        method: req.method,
        headers,
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : body,
        duplex: 'half',
      });

      const outHeaders = {};
      upstream.headers.forEach((v, k) => {
        if (!HOP_BY_HOP.has(k)) outHeaders[k] = v;
      });
      res.writeHead(upstream.status, outHeaders);
      onEvent?.({ type: 'forward', provider: slug, path: req.url, status: upstream.status });

      if (upstream.body) {
        // Stream SSE/chunked responses through unbuffered.
        const reader = upstream.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(Buffer.from(value));
        }
      }
      res.end();
    } catch (err) {
      onEvent?.({ type: 'reject', provider: slug, path: req.url, status: 502 });
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'gateway unreachable', detail: String(err?.message || err), gateway: base }));
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', (err) => {
      if (err && err.code === 'EADDRINUSE') {
        reject(new Error(`AI lane port ${port} is already in use — pass a free port, e.g. startAiLane({ port: ${port + 1} })`));
        return;
      }
      reject(err);
    });
    server.listen(port, '127.0.0.1', () => resolve({ server, port, gateway: base }));
  });
}

module.exports = { startAiLane, DEFAULT_PORT, DEFAULT_GATEWAY };
