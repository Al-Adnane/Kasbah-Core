'use strict';

/**
 * Local extension gateway — tiny HTTP server on 127.0.0.1:8788 (or next free).
 * Used by the Kasbah browser extension when the full api-server is not running.
 * Implements only what the extension needs:
 *   GET  /v1/health
 *   POST /v1/scan   { prompt }
 *   POST /v1/attest { prompt }
 *   POST /v1/vc/issue { scanResult, attestResult }
 *
 * All work is local. No third-party egress.
 */

const http = require('http');
const aiGov = require('./ai-governance.js');
const egress = require('./egress-classifier.js');
const bioGuard = require('./biometric-guard.js');

let intervention = null;
try { intervention = require('../../api-server/src/intervention.js'); } catch (_) {}

let server = null;
let port = 0;

function inspectPromptText(prompt) {
  const text = String(prompt || '');
  const inj = aiGov.detectInjection(text);
  const bio = bioGuard.scanText(text);
  const dlp = egress.classify(text);
  const threats = [];
  if (inj.length) threats.push(...inj.map((i) => i.label));
  if (bio.found) threats.push(...bio.findings.map((f) => f.label));
  if (dlp.found) threats.push(...dlp.findings.map((f) => f.label));
  let verdict = 'ALLOW';
  if (bio.found || inj.length) verdict = 'DENY';
  else if (dlp.found) verdict = 'DENY';
  const score = verdict === 'ALLOW' ? 0.05 : 0.9;
  const base = { verdict, threats, score, risk: score, risk_score: score };
  if (intervention) {
    try {
      base.seatbelt = intervention.fromGovern(base, { surface: 'paste', clientKey: 'ext-gateway' });
      base.intervention = base.seatbelt.intervention;
    } catch (_) {}
  }
  return base;
}

function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 2_000_000) req.destroy(); });
    req.on('end', () => {
      try { resolve(JSON.parse(b || '{}')); } catch { resolve({}); }
    });
  });
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
  });
  res.end(body);
}

function start(preferredPort = 8788) {
  if (server) return { ok: true, port, already: true };
  server = http.createServer(async (req, res) => {
    const url = (req.url || '/').split('?')[0];
    if (req.method === 'OPTIONS') { json(res, 204, {}); return; }

    if (req.method === 'GET' && (url === '/v1/health' || url === '/health')) {
      json(res, 200, { ok: true, service: 'kasbah-extension-gateway', local: true });
      return;
    }
    if (req.method === 'POST' && url === '/v1/scan') {
      const body = await readBody(req);
      const r = inspectPromptText(body.prompt || body.text || '');
      json(res, 200, r);
      return;
    }
    if (req.method === 'POST' && url === '/v1/attest') {
      const body = await readBody(req);
      // Prefer real prompt-attest if available
      try {
        const pa = require('./prompt-attest.js');
        const c = pa.commit(String(body.prompt || ''), { label: 'extension' });
        json(res, 200, { ok: true, id: c.id, hash: c.hash, sig: c.sig, ts: c.ts });
        return;
      } catch (e) {
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256').update(String(body.prompt || '')).digest('hex');
        json(res, 200, { ok: true, id: 'att_' + hash.slice(0, 12), hash });
        return;
      }
    }
    if (req.method === 'POST' && url === '/v1/vc/issue') {
      const body = await readBody(req);
      try {
        const vc = require('./vc-export.js');
        const entry = {
          requestId: 'ext-' + Date.now(),
          vpnOn: !!body.scanResult?.vpnOn,
          location: body.scanResult?.location || 'browser',
          claim: 'PROMPT_GOVERNED',
        };
        const r = vc.issue(entry, { expiryDays: 90 });
        json(res, 200, { ok: true, ...r });
        return;
      } catch (e) {
        json(res, 500, { ok: false, error: e.message });
        return;
      }
    }
    json(res, 404, { ok: false, error: 'not found', path: url });
  });

  return new Promise((resolve) => {
    server.on('error', (e) => {
      if (e.code === 'EADDRINUSE') {
        // Try port+1..+5
        let p = preferredPort + 1;
        const tryNext = () => {
          if (p > preferredPort + 5) return resolve({ ok: false, error: 'port in use' });
          const s2 = server;
          server = null;
          start(p).then(resolve);
        };
        tryNext();
        return;
      }
      resolve({ ok: false, error: e.message });
    });
    server.listen(preferredPort, '127.0.0.1', () => {
      port = preferredPort;
      resolve({ ok: true, port });
    });
  });
}

function stop() {
  if (server) { try { server.close(); } catch (_) {} server = null; port = 0; }
  return { ok: true };
}

function status() {
  return { listening: !!server, port: port || null, url: port ? `http://127.0.0.1:${port}` : null };
}

module.exports = { start, stop, status, inspectPromptText };
