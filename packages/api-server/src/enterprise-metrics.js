'use strict';

/**
 * enterprise-metrics.js — Prometheus-compatible metrics + structured logging for Kasbah API server
 *
 * Drop-in module for packages/api-server. Exposes:
 *   - GET /metrics           — Prometheus text format endpoint
 *   - GET /v1/health         — Enhanced health with component status
 *   - Structured JSON logger — pino-style interface (zero deps)
 *   - Rate-limit middleware   — token-bucket, in-memory
 *
 * Usage:
 *   const { metricsMiddleware, metricsEndpoint, logger, rateLimiter } = require('./enterprise-metrics');
 *   app.use(metricsMiddleware);
 *   app.get('/metrics', metricsEndpoint);
 *   app.use(rateLimiter({ windowMs: 60000, max: 100 }));
 *   logger.info({ event: 'startup', port: 8788 });
 *
 * Pure JS. Zero dependencies. Node 18+.
 */

// ─── Prometheus Metrics ─────────────────────────────────────────────────────

const counters = new Map();
const histograms = new Map();
const gauges = new Map();

/**
 * Increment a named counter.
 * @param {string} name — metric name (e.g. "requests_total")
 * @param {object} labels — optional label key/values
 * @param {number} by — increment amount (default 1)
 */
function counterInc(name, labels = {}, by = 1) {
  const key = _metricKey(name, labels);
  const current = counters.get(key) || 0;
  counters.set(key, current + by);
}

/**
 * Observe a value for a histogram.
 * @param {string} name — metric name (e.g. "request_duration_ms")
 * @param {number} value — observed value
 * @param {object} labels — optional label key/values
 */
function histogramObserve(name, value, labels = {}) {
  const key = _metricKey(name, labels);
  if (!histograms.has(key)) histograms.set(key, []);
  histograms.get(key).push(value);
  // Keep last 10000 observations
  if (histograms.get(key).length > 10000) histograms.get(key).shift();
}

/**
 * Set a gauge value.
 * @param {string} name
 * @param {number} value
 * @param {object} labels
 */
function gaugeSet(name, value, labels = {}) {
  const key = _metricKey(name, labels);
  gauges.set(key, value);
}

function _metricKey(name, labels) {
  const labelPairs = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${v}"`)
    .join(',');
  return labelPairs ? `${name}{${labelPairs}}` : name;
}

/**
 * Express middleware that counts requests and measures latency.
 */
function metricsMiddleware(req, res, next) {
  const start = Date.now();
  const method = req.method;
  const route = req.route?.path || req.path || 'unknown';

  res.on('finish', () => {
    const duration = Date.now() - start;
    const status = String(res.statusCode);
    counterInc('http_requests_total', { method, route, status });
    histogramObserve('http_request_duration_ms', duration, { method, route });
  });

  next();
}

/**
 * Prometheus text-format metrics endpoint.
 */
function metricsEndpoint(_req, res) {
  const lines = [];

  lines.push('# HELP kasbah_uptime_seconds Engine uptime in seconds');
  lines.push('# TYPE kasbah_uptime_seconds gauge');
  lines.push(`kasbah_uptime_seconds ${process.uptime().toFixed(2)}`);

  lines.push('# HELP kasbah_memory_bytes Memory usage in bytes');
  lines.push('# TYPE kasbah_memory_bytes gauge');
  const mem = process.memoryUsage();
  lines.push(`kasbah_memory_bytes{type="rss"} ${mem.rss}`);
  lines.push(`kasbah_memory_bytes{type="heapUsed"} ${mem.heapUsed}`);
  lines.push(`kasbah_memory_bytes{type="heapTotal"} ${mem.heapTotal}`);

  // Counters
  for (const [key, value] of counters) {
    const [name, ...labelParts] = key.split('{');
    lines.push(`# HELP ${name} Counter`);
    lines.push(`# TYPE ${name} counter`);
    const labels = labelParts.length ? `{${labelParts.join('{')}` : '';
    lines.push(`${name}${labels} ${value}`);
  }

  // Gauges
  for (const [key, value] of gauges) {
    const [name, ...labelParts] = key.split('{');
    lines.push(`# HELP ${name} Gauge`);
    lines.push(`# TYPE ${name} gauge`);
    const labels = labelParts.length ? `{${labelParts.join('{')}` : '';
    lines.push(`${name}${labels} ${value}`);
  }

  // Histograms (summary stats only)
  for (const [key, values] of histograms) {
    const [name, ...labelParts] = key.split('{');
    const labels = labelParts.length ? `{${labelParts.join('{')}` : '';
    const sorted = [...values].sort((a, b) => a - b);
    const count = sorted.length;
    const sum = sorted.reduce((a, b) => a + b, 0);
    const p50 = sorted[Math.floor(count * 0.5)] || 0;
    const p95 = sorted[Math.floor(count * 0.95)] || 0;
    const p99 = sorted[Math.floor(count * 0.99)] || 0;

    lines.push(`# HELP ${name} Histogram`);
    lines.push(`# TYPE ${name} histogram`);
    lines.push(`${name}_count${labels} ${count}`);
    lines.push(`${name}_sum${labels} ${sum.toFixed(2)}`);
    lines.push(`${name}_bucket${labels}{le="50"} ${sorted.filter(v => v <= 50).length}`);
    lines.push(`${name}_bucket${labels}{le="100"} ${sorted.filter(v => v <= 100).length}`);
    lines.push(`${name}_bucket${labels}{le="500"} ${sorted.filter(v => v <= 500).length}`);
    lines.push(`${name}_bucket${labels}{le="1000"} ${sorted.filter(v => v <= 1000).length}`);
    lines.push(`${name}_bucket${labels}{le="+Inf"} ${count}`);
    lines.push(`# ${name}: p50=${p50} p95=${p95} p99=${p99}`);
  }

  res.set('Content-Type', 'text/plain; version=0.0.4');
  res.send(lines.join('\n') + '\n');
}

// ─── Structured Logger ──────────────────────────────────────────────────────

const LOG_LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
let currentLevel = LOG_LEVELS.info;

function _log(level, message, extra = {}) {
  if (LOG_LEVELS[level] < currentLevel) return;
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
    ...extra,
  };
  const out = level === 'error' ? process.stderr : process.stdout;
  out.write(JSON.stringify(entry) + '\n');
}

const logger = {
  debug: (msg, extra) => _log('debug', msg, extra),
  info:  (msg, extra) => _log('info', msg, extra),
  warn:  (msg, extra) => _log('warn', msg, extra),
  error: (msg, extra) => _log('error', msg, extra),
  setLevel: (l) => { if (LOG_LEVELS[l] !== undefined) currentLevel = LOG_LEVELS[l]; },
};

// ─── Rate Limiter ───────────────────────────────────────────────────────────

/**
 * Token-bucket rate limiter (in-memory).
 *
 * @param {object} opts
 * @param {number} opts.windowMs — time window in ms (default 60000 = 1 min)
 * @param {number} opts.max — max requests per window per IP (default 100)
 * @returns {function} Express middleware
 */
function rateLimiter(opts = {}) {
  const windowMs = opts.windowMs || 60000;
  const max = opts.max || 100;
  const buckets = new Map(); // IP → { tokens, lastRefill }

  // Cleanup old entries every 5 minutes
  setInterval(() => {
    const now = Date.now();
    for (const [ip, bucket] of buckets) {
      if (now - bucket.lastRefill > windowMs * 2) buckets.delete(ip);
    }
  }, 300000).unref();

  return (req, res, next) => {
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    let bucket = buckets.get(ip);

    if (!bucket) {
      bucket = { tokens: max, lastRefill: now };
      buckets.set(ip, bucket);
    }

    // Refill
    const elapsed = now - bucket.lastRefill;
    const refill = Math.floor(elapsed / windowMs * max);
    bucket.tokens = Math.min(max, bucket.tokens + refill);
    bucket.lastRefill = now;

    if (bucket.tokens > 0) {
      bucket.tokens--;
      res.set('X-RateLimit-Remaining', String(bucket.tokens));
      res.set('X-RateLimit-Limit', String(max));
      next();
    } else {
      res.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      res.status(429).json({
        error: 'rate_limited',
        message: `Too many requests. Try again in ${Math.ceil(windowMs / 1000)}s.`,
        retryAfter: Math.ceil(windowMs / 1000),
      });
    }
  };
}

// ─── Enhanced Health Endpoint ───────────────────────────────────────────────

/**
 * Enhanced health check with component status.
 *
 * @param {object} components — { name: checkFn() => { status, details } }
 */
function healthEndpoint(components = {}) {
  return (_req, res) => {
    const checks = {};
    let allOk = true;

    for (const [name, checkFn] of Object.entries(components)) {
      try {
        const result = checkFn();
        checks[name] = result;
        if (result.status !== 'ok') allOk = false;
      } catch (e) {
        checks[name] = { status: 'error', error: e.message };
        allOk = false;
      }
    }

    res.status(allOk ? 200 : 503).json({
      status: allOk ? 'ok' : 'degraded',
      version: process.env.KASBAH_VERSION || '3.0.0',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      components: checks,
    });
  };
}

// ─── Exports ────────────────────────────────────────────────────────────────

module.exports = {
  // Prometheus
  counterInc,
  histogramObserve,
  gaugeSet,
  metricsMiddleware,
  metricsEndpoint,

  // Logger
  logger,

  // Rate limiting
  rateLimiter,

  // Health
  healthEndpoint,
};
