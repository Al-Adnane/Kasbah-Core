'use strict';

/**
 * siem-connectors.js — outbound SIEM/enterprise connectors for Kasbah
 * enforcement events.
 *
 * Forwards intervention events (DENY/hard_block, trust-grade changes, enforcer
 * actions) to the enterprise systems where SOC teams already live:
 *
 *   - Splunk HEC  (HTTP Event Collector)  — KASBAH_SPLUNK_HEC_URL + KASBAH_SPLUNK_TOKEN
 *   - Datadog     (events API v1)         — KASBAH_DATADOG_URL + KASBAH_DD_API_KEY
 *   - CrowdStrike / generic webhook       — KASBAH_SIEM_WEBHOOK_URL (+ KASBAH_SIEM_WEBHOOK_TOKEN)
 *
 * Design:
 *   - Fire-and-forget async: a slow/down SIEM endpoint must NEVER slow the
 *     enforcement path (every request has a 5s timeout, failures are logged,
 *     counted, and swallowed).
 *   - Backpressure guard: at most 1 in-flight forward per connector; events
 *     arriving while busy are dropped and counted (SIEMs tolerate loss far
 *     better than the gateway tolerates latency).
 *   - Config is env-only (no secrets in the DB); /v1/siem/status reports what
 *     is configured WITHOUT echoing tokens.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

const _inFlight = { splunk: false, datadog: false, webhook: false };
const _stats = { splunkSent: 0, splunkDropped: 0, splunkFailed: 0, datadogSent: 0, datadogDropped: 0, datadogFailed: 0, webhookSent: 0, webhookDropped: 0, webhookFailed: 0 };

function _post(urlString, headers, body) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(urlString); } catch { resolve({ ok: false, reason: 'bad URL' }); return; }
    const payload = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, { method: 'POST', headers: { ...headers, 'content-length': payload.length }, timeout: 5000 }, (res) => {
      res.resume();
      resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, reason: 'timeout' }); });
    req.on('error', (e) => resolve({ ok: false, reason: e.message }));
    req.write(payload);
    req.end();
  });
}

function _config() {
  return {
    splunk: { url: process.env.KASBAH_SPLUNK_HEC_URL || '', token: process.env.KASBAH_SPLUNK_TOKEN || '' },
    datadog: { url: process.env.KASBAH_DATADOG_URL || 'https://api.datadoghq.com', token: process.env.KASBAH_DD_API_KEY || '' },
    webhook: { url: process.env.KASBAH_SIEM_WEBHOOK_URL || '', token: process.env.KASBAH_SIEM_WEBHOOK_TOKEN || '' },
  };
}

/** What's configured — never echoes tokens. */
function status() {
  const c = _config();
  return {
    connectors: [
      { id: 'splunk', kind: 'Splunk HEC', configured: !!(c.splunk.url && c.splunk.token), env: ['KASBAH_SPLUNK_HEC_URL', 'KASBAH_SPLUNK_TOKEN'], stats: { sent: _stats.splunkSent, dropped: _stats.splunkDropped, failed: _stats.splunkFailed } },
      { id: 'datadog', kind: 'Datadog events', configured: !!c.datadog.token, env: ['KASBAH_DD_API_KEY'], stats: { sent: _stats.datadogSent, dropped: _stats.datadogDropped, failed: _stats.datadogFailed } },
      { id: 'webhook', kind: 'Generic/CrowdStrike webhook', configured: !!c.webhook.url, env: ['KASBAH_SIEM_WEBHOOK_URL', 'KASBAH_SIEM_WEBHOOK_TOKEN'], stats: { sent: _stats.webhookSent, dropped: _stats.webhookDropped, failed: _stats.webhookFailed } },
    ],
    anyConfigured: !!(c.webhook.url || (c.splunk.url && c.splunk.token) || c.datadog.token),
  };
}

/** Normalize an intervention event into the SIEM-agnostic envelope. */
function envelope(event) {
  return {
    source: 'kasbah-guard',
    kind: event.kind || 'intervention',
    ts: event.ts || new Date().toISOString(),
    severity: event.severity || (event.verdict === 'DENY' || event.intervention === 'hard_block' ? 'high' : 'info'),
    verdict: event.verdict || null,
    intervention: event.intervention || null,
    threats: event.threats || [],
    risk: event.risk != null ? +Number(event.risk).toFixed(4) : null,
    surface: event.surface || null,
    apiKey: event.keyId ? String(event.keyId).slice(0, 8) : null, // never full keys
    receiptUrl: event.receiptUrl || null,
  };
}

async function _forwardSplunk(evt) {
  const c = _config();
  if (!c.splunk.url || !c.splunk.token) return;
  if (_inFlight.splunk) { _stats.splunkDropped++; return; }
  _inFlight.splunk = true;
  try {
    const body = { event: evt, sourcetype: '_json', index: process.env.KASBAH_SPLUNK_INDEX || 'kasbah' };
    const r = await _post(c.splunk.url, { authorization: 'Splunk ' + c.splunk.token, 'content-type': 'application/json' }, body);
    if (r.ok) _stats.splunkSent++; else _stats.splunkFailed++;
  } catch (_) { _stats.splunkFailed++; }
  finally { _inFlight.splunk = false; }
}

async function _forwardDatadog(evt) {
  const c = _config();
  if (!c.datadog.token) return;
  if (_inFlight.datadog) { _stats.datadogDropped++; return; }
  _inFlight.datadog = true;
  try {
    const body = {
      title: `Kasbah ${evt.severity}: ${evt.verdict || evt.kind}`,
      text: JSON.stringify(evt),
      priority: evt.severity === 'high' ? 'normal' : 'low',
      tags: ['kasbah', 'ai-governance', 'verdict:' + (evt.verdict || 'none')].filter(Boolean),
      date_happened: Math.floor(new Date(evt.ts || Date.now()).getTime() / 1000),
    };
    const r = await _post(c.datadog.url + '/api/v1/events', { 'DD-API-KEY': c.datadog.token, 'content-type': 'application/json' }, body);
    if (r.ok) _stats.datadogSent++; else _stats.datadogFailed++;
  } catch (_) { _stats.datadogFailed++; }
  finally { _inFlight.datadog = false; }
}

async function _forwardWebhook(evt) {
  const c = _config();
  if (!c.webhook.url) return;
  if (_inFlight.webhook) { _stats.webhookDropped++; return; }
  _inFlight.webhook = true;
  try {
    const headers = { 'content-type': 'application/json' };
    if (c.webhook.token) headers.authorization = 'Bearer ' + c.webhook.token;
    const r = await _post(c.webhook.url, headers, evt);
    if (r.ok) _stats.webhookSent++; else _stats.webhookFailed++;
  } catch (_) { _stats.webhookFailed++; }
  finally { _inFlight.webhook = false; }
}

/**
 * Fire-and-forget forward to every configured connector. Call on DENY /
 * hard_block / enforcer actions. Never throws, never blocks the caller.
 */
function forwardEvent(event) {
  try {
    const evt = envelope(event);
    _forwardSplunk(evt);
    _forwardDatadog(evt);
    _forwardWebhook(evt);
    return true;
  } catch (_) { return false; }
}

module.exports = { status, forwardEvent, envelope };