'use strict';

/**
 * OpenAI Moderation adapter
 *
 * Requires: OPENAI_API_KEY env var
 * Endpoint: https://api.openai.com/v1/moderations
 *
 * OpenAI's moderation API is not a prompt-injection detector per se, but it's
 * the most-deployed safety classifier in the field and a useful baseline.
 */

const https = require('https');

const API_KEY = process.env.OPENAI_API_KEY;
const ENDPOINT = 'https://api.openai.com/v1/moderations';

if (!API_KEY) { module.exports = null; return; }

function call(prompt) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ input: prompt, model: 'omni-moderation-latest' });
    const req = https.request({
      hostname: 'api.openai.com', port: 443, path: '/v1/moderations',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: body ? JSON.parse(body) : null }); }
        catch (e) { resolve({ status: res.statusCode, body }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(6000, () => req.destroy(new Error('timeout')));
    req.write(data); req.end();
  });
}

module.exports = {
  name: 'openai-moderation',
  async run(prompt) {
    const t0 = Date.now();
    const r = await call(prompt);
    const latencyMs = Date.now() - t0;
    if (r.status !== 200) return { verdict: 'ERROR', latencyMs, raw: r.body };
    const result = r.body?.results?.[0];
    if (!result) return { verdict: 'UNKNOWN', latencyMs, raw: r.body };
    return { verdict: result.flagged ? 'DENY' : 'ALLOW', latencyMs, raw: r.body };
  }
};
