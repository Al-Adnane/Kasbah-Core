'use strict';

/**
 * Lakera Guard adapter
 *
 * Requires: LAKERA_API_KEY env var
 * Endpoint: https://api.lakera.ai/v1/guard
 *
 * Maps Lakera's response shape into our standard {verdict, latencyMs}.
 * Returns null if no API key configured — the harness skips silently.
 */

const https = require('https');

const API_KEY = process.env.LAKERA_API_KEY;
const ENDPOINT = process.env.LAKERA_ENDPOINT || 'https://api.lakera.ai/v1/guard';

if (!API_KEY) {
  module.exports = null;
  return;
}

function call(prompt, timeoutMs = 6000) {
  return new Promise((resolve, reject) => {
    const u = new URL(ENDPOINT);
    const data = JSON.stringify({ input: prompt });
    const req = https.request({
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    }, (res) => {
      let body = '';
      res.on('data', (c) => body += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: body ? JSON.parse(body) : null }); }
        catch (e) { resolve({ status: res.statusCode, body }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => req.destroy(new Error('timeout')));
    req.write(data);
    req.end();
  });
}

module.exports = {
  name: 'lakera-guard',
  async run(prompt) {
    const t0 = Date.now();
    const r = await call(prompt);
    const latencyMs = Date.now() - t0;
    if (r.status !== 200) return { verdict: 'ERROR', latencyMs, raw: r.body };
    // Lakera returns { categories: { ... }, results: [{categories: {...}, flagged: bool}] }
    const flagged = r.body?.results?.[0]?.flagged ?? r.body?.flagged ?? false;
    return { verdict: flagged ? 'DENY' : 'ALLOW', latencyMs, raw: r.body };
  }
};
