'use strict';

/**
 * KasbahOS Webhook System
 *
 * Delivers signed POST notifications to customer endpoints on security events.
 * Every delivery is HMAC-SHA256 signed so customers can verify authenticity.
 *
 * Features:
 *   - HMAC-SHA256 signed payloads (Stripe-compatible format)
 *   - Exponential backoff retry: 3 attempts at 2s / 8s / 30s
 *   - Dead-letter queue: permanently-failed deliveries stored for inspection
 *   - Auto-disable: webhook suspended after 10 consecutive failures
 *   - Delivery persistence: recent 1000 deliveries survive restarts (via JSONL)
 *
 * Events fired:
 *   govern.deny      — prompt denied by any detection system
 *   govern.warn      — prompt warned (high risk)
 *   passport.revoke  — passport auto-revoked
 *   circuit.trip     — circuit-breaker tripped on a passport
 *   policy.reload    — .kasbahpolicy.json hot-reloaded
 */

const crypto = require('crypto');
const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');

// ── Slack Notification ────────────────────────────────────────────────────────

/**
 * Send a Slack notification via incoming webhook.
 * Set SLACK_WEBHOOK_URL env var to enable.
 * Falls back to no-op when not configured.
 */
function fireSlack(eventType, payload) {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return;

  const color = eventType.includes('deny') || eventType.includes('kill') ? '#D1242F'
    : eventType.includes('warn') ? '#F59E0B' : '#0F7A50';

  const agentId = payload.agentId || payload.passportId || 'agent';
  const threats = payload.threats?.slice(0, 3).join(', ') || '';

  const body = JSON.stringify({
    attachments: [{
      color,
      title: `Kasbah: ${eventType}`,
      text: `Agent: *${agentId}*${threats ? `\nThreats: ${threats}` : ''}`,
      footer: 'Kasbah Guard',
      ts: Math.floor(Date.now() / 1000)
    }]
  });

  try {
    const parsed = new URL(url);
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + (parsed.search || ''),
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    });
    req.on('error', () => {});
    req.write(body);
    req.end();
  } catch (_) {}
}

// ── Storage ───────────────────────────────────────────────────────────────────

const _webhooks   = new Map();   // webhookId → WebhookRecord
const _deliveries = new Map();   // deliveryId → DeliveryRecord
const _dlq        = [];          // dead-letter queue: permanently failed deliveries

const BASE_DIR          = process.env.KASBAH_DATA_DIR || path.join(process.cwd(), '.kasbah');
const WEBHOOKS_FILE     = path.join(BASE_DIR, 'webhooks.jsonl');
const DELIVERIES_FILE   = path.join(BASE_DIR, 'deliveries.jsonl');
const MAX_DELIVERIES    = 1000;   // cap in-memory + persisted delivery log
const DLQ_MAX           = 500;    // max dead-letter queue entries

// ── Load persisted state on startup ──────────────────────────────────────────

(function loadWebhooks() {
  try {
    const lines = fs.readFileSync(WEBHOOKS_FILE, 'utf8').trim().split('\n');
    lines.forEach(l => {
      try {
        const w = JSON.parse(l);
        if (w && w.id && !w.deleted) _webhooks.set(w.id, w);
      } catch {}
    });
    if (_webhooks.size) console.log(`[webhooks] loaded ${_webhooks.size} webhooks`);
  } catch {}
})();

(function loadDeliveries() {
  try {
    const lines = fs.readFileSync(DELIVERIES_FILE, 'utf8').trim().split('\n');
    let loaded = 0;
    lines.forEach(l => {
      try {
        const d = JSON.parse(l);
        if (d && d.id) { _deliveries.set(d.id, d); loaded++; }
      } catch {}
    });
    if (loaded) console.log(`[webhooks] loaded ${loaded} delivery records`);
  } catch {}
})();

function _ensureDir() {
  try { fs.mkdirSync(BASE_DIR, { recursive: true }); } catch {}
}

function _persistWebhook(record) {
  try {
    _ensureDir();
    fs.appendFileSync(WEBHOOKS_FILE, JSON.stringify(record) + '\n');
  } catch {}
}

function _persistDelivery(record) {
  try {
    _ensureDir();
    fs.appendFileSync(DELIVERIES_FILE, JSON.stringify(record) + '\n');
  } catch {}
}

// ── Webhook CRUD ──────────────────────────────────────────────────────────────

/**
 * Register a new webhook endpoint.
 */
function register({ url, events = ['govern.deny'], secret, passportId, keyId } = {}) {
  if (!url) throw new Error('url is required');
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only http/https URLs supported');
  // Block SSRF — reject private/loopback IP ranges and localhost
  const hostname = parsed.hostname.toLowerCase();
  const PRIVATE_RE = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|0\.0\.0\.0)/;
  if (PRIVATE_RE.test(hostname)) throw new Error('Webhook URL must not target private/loopback addresses');
  if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:') throw new Error('Production webhooks require HTTPS');

  const id            = 'wh_' + crypto.randomBytes(12).toString('hex');
  const signingSecret = secret || ('whsec_' + crypto.randomBytes(24).toString('hex'));

  const record = {
    id,
    url,
    events:           Array.isArray(events) ? events : ['govern.deny'],
    signingSecret,
    passportId:       passportId || null,
    keyId:            keyId || null,
    createdAt:        new Date().toISOString(),
    enabled:          true,
    deliveryCount:    0,
    failCount:        0,
    consecutiveFails: 0,    // resets on success; triggers auto-disable at 10
    lastDeliveryAt:   null,
    lastStatus:       null,
    disabledAt:       null,
    disabledReason:   null,
  };

  _webhooks.set(id, record);
  _persistWebhook(record);

  return { id, url, events, signingSecret, createdAt: record.createdAt };
}

function list(keyId) {
  const all = [..._webhooks.values()];
  return keyId ? all.filter(w => !w.keyId || w.keyId === keyId) : all;
}

function remove(id) {
  const w = _webhooks.get(id);
  if (!w) return false;
  _webhooks.delete(id);
  _persistWebhook({ ...w, deleted: true, deletedAt: new Date().toISOString() });
  return true;
}

function get(id) {
  return _webhooks.get(id) || null;
}

function enable(id) {
  const w = _webhooks.get(id);
  if (!w) return false;
  w.enabled          = true;
  w.consecutiveFails = 0;
  w.disabledAt       = null;
  w.disabledReason   = null;
  _persistWebhook({ ...w, _op: 'enable' });
  return true;
}

// ── Delivery ──────────────────────────────────────────────────────────────────

const MAX_RETRIES      = 3;
const RETRY_DELAYS     = [2000, 8000, 30000];  // 2s, 8s, 30s
const AUTO_DISABLE_AT  = 10;   // consecutive failures before suspension

/**
 * Fire webhooks for a governance event. Non-blocking.
 */
function fire(eventType, payload) {
  // Fire Slack notification (separate from HTTP webhooks, always attempted)
  fireSlack(eventType, payload);

  const matching = [..._webhooks.values()].filter(w =>
    w.enabled &&
    w.events.includes(eventType) &&
    (!w.passportId || w.passportId === payload.passportId)
  );
  for (const webhook of matching) {
    _deliver(webhook, eventType, payload, 0);
  }
}

function _deliver(webhook, eventType, payload, attempt) {
  const deliveryId = 'del_' + crypto.randomBytes(8).toString('hex');
  const timestamp  = Math.floor(Date.now() / 1000);

  const body = JSON.stringify({
    id:        deliveryId,
    event:     eventType,
    timestamp,
    attempt,
    data:      payload,
  });

  // HMAC-SHA256 signature (Stripe-compatible): "t=<ts>,v1=<hmac>"
  const toSign    = `${timestamp}.${body}`;
  const sig       = crypto.createHmac('sha256', webhook.signingSecret)
    .update(toSign).digest('hex');
  const sigHeader = `t=${timestamp},v1=${sig}`;

  const parsed  = new URL(webhook.url);
  const isHttps = parsed.protocol === 'https:';
  const lib     = isHttps ? https : http;

  const options = {
    hostname: parsed.hostname,
    port:     parsed.port || (isHttps ? 443 : 80),
    path:     parsed.pathname + (parsed.search || ''),
    method:   'POST',
    headers: {
      'Content-Type':        'application/json',
      'Content-Length':      Buffer.byteLength(body),
      'X-Kasbah-Signature':  sigHeader,
      'X-Kasbah-Event':      eventType,
      'X-Kasbah-Delivery':   deliveryId,
      'User-Agent':          'KasbahOS-Webhook/1.1',
    },
    timeout: 10000,
  };

  const record = {
    id:         deliveryId,
    webhookId:  webhook.id,
    event:      eventType,
    attempt,
    status:     'pending',
    timestamp:  new Date().toISOString(),
    url:        webhook.url,
  };
  _trackDelivery(record);

  const req = lib.request(options, res => {
    // Drain response body so connection is reused
    res.resume();
    const ok = res.statusCode >= 200 && res.statusCode < 300;
    record.status     = ok ? 'success' : `failed_${res.statusCode}`;
    record.httpStatus = res.statusCode;
    _persistDelivery(record);

    webhook.deliveryCount++;
    webhook.lastDeliveryAt = new Date().toISOString();
    webhook.lastStatus     = res.statusCode;

    if (ok) {
      webhook.consecutiveFails = 0;
    } else {
      webhook.failCount++;
      webhook.consecutiveFails++;
      _checkAutoDisable(webhook, `HTTP ${res.statusCode}`);
      _scheduleRetry(webhook, eventType, payload, attempt, deliveryId);
    }
  });

  req.on('error', err => {
    record.status = 'error';
    record.error  = err.message;
    _persistDelivery(record);
    webhook.failCount++;
    webhook.consecutiveFails++;
    _checkAutoDisable(webhook, `network error: ${err.code || err.message}`);
    _scheduleRetry(webhook, eventType, payload, attempt, deliveryId);
  });

  req.on('timeout', () => {
    req.destroy();
    record.status = 'timeout';
    _persistDelivery(record);
    webhook.failCount++;
    webhook.consecutiveFails++;
    _checkAutoDisable(webhook, 'timeout');
    _scheduleRetry(webhook, eventType, payload, attempt, deliveryId);
  });

  req.write(body);
  req.end();
}

function _scheduleRetry(webhook, eventType, payload, attempt, parentId) {
  if (attempt >= MAX_RETRIES - 1) {
    // All retries exhausted — move to dead-letter queue
    _dlqPush({
      webhookId:   webhook.id,
      url:         webhook.url,
      event:       eventType,
      payload,
      finalAttempt: attempt,
      parentDeliveryId: parentId,
      failedAt:    new Date().toISOString(),
      reason:      `Max retries (${MAX_RETRIES}) exhausted`,
    });
    return;
  }
  const delay = RETRY_DELAYS[attempt] || 30000;
  setTimeout(() => _deliver(webhook, eventType, payload, attempt + 1), delay).unref();
}

/**
 * Auto-disable webhook after too many consecutive failures.
 * Prevents hammering dead endpoints and wasting resources.
 */
function _checkAutoDisable(webhook, reason) {
  if (!webhook.enabled) return;
  if (webhook.consecutiveFails >= AUTO_DISABLE_AT) {
    webhook.enabled       = false;
    webhook.disabledAt    = new Date().toISOString();
    webhook.disabledReason = `Auto-disabled after ${AUTO_DISABLE_AT} consecutive failures (last: ${reason}). Re-enable via DELETE+POST or PATCH /v1/webhooks/:id/enable.`;
    console.warn(`[webhooks] Auto-disabled ${webhook.id} (${webhook.url}) — ${webhook.disabledReason}`);
    _persistWebhook({ ...webhook, _op: 'auto-disable' });
  }
}

// ── Dead-Letter Queue ─────────────────────────────────────────────────────────

function _dlqPush(entry) {
  _dlq.push(entry);
  if (_dlq.length > DLQ_MAX) _dlq.shift();
  // Persist DLQ entry alongside delivery records
  try {
    _ensureDir();
    fs.appendFileSync(path.join(BASE_DIR, 'dlq.jsonl'), JSON.stringify(entry) + '\n');
  } catch {}
}

function dlq(limit = 50) {
  return _dlq.slice(-limit).reverse();
}

// ── Delivery Tracking ─────────────────────────────────────────────────────────

function _trackDelivery(record) {
  _deliveries.set(record.id, record);
  if (_deliveries.size > MAX_DELIVERIES) {
    const oldest = _deliveries.keys().next().value;
    _deliveries.delete(oldest);
  }
}

function deliveries(webhookId, limit = 50) {
  return [..._deliveries.values()]
    .filter(d => !webhookId || d.webhookId === webhookId)
    .sort((a, b) => b.timestamp > a.timestamp ? 1 : -1)
    .slice(0, limit);
}

// ── Stats ─────────────────────────────────────────────────────────────────────

function stats() {
  const webhookList = [..._webhooks.values()];
  return {
    total:      webhookList.length,
    enabled:    webhookList.filter(w => w.enabled).length,
    disabled:   webhookList.filter(w => !w.enabled).length,
    deliveries: webhookList.reduce((s, w) => s + w.deliveryCount, 0),
    failures:   webhookList.reduce((s, w) => s + w.failCount, 0),
    dlqSize:    _dlq.length,
  };
}

module.exports = { register, list, remove, get, enable, fire, fireSlack, deliveries, dlq, stats };
