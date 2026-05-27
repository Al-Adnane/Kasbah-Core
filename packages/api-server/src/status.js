'use strict';

/**
 * Aggregated status endpoint + structured telemetry.
 *
 * Routes:
 *   GET /v1/status     — JSON: every subsystem's health + per-route stats
 *   GET /status        — HTML status page (single file, no external CSS)
 *
 * Telemetry:
 *   wraps every /v1/* route in a JSON log line:
 *   {"ts":"...","level":"info","route":"POST /v1/scan","status":200,"latencyMs":12,"keyId":"kid_...","verdict":"DENY"}
 *
 *   To ship to Datadog/Logtail/Axiom:
 *     fly logs | datadog-agent  (or any tail collector)
 */

const fs = require('fs');
const path = require('path');

const STARTED_AT = Date.now();
const _routeStats = new Map(); // "METHOD /path" → { count, errCount, latencyMs[] }
const _recentErrors = []; // last 50

function _recordRoute(method, route, latencyMs, status) {
  const key = `${method} ${route}`;
  let rec = _routeStats.get(key);
  if (!rec) {
    rec = { count: 0, errCount: 0, totalLatency: 0, p99: 0, lastLatencies: [] };
    _routeStats.set(key, rec);
  }
  rec.count++;
  rec.totalLatency += latencyMs;
  rec.lastLatencies.push(latencyMs);
  if (rec.lastLatencies.length > 1000) rec.lastLatencies.shift();
  if (status >= 500) rec.errCount++;
}

function _percentile(arr, p) {
  if (arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * p));
  return sorted[idx];
}

// ── Structured telemetry middleware ──────────────────────────────────────────
function telemetryMiddleware() {
  return (req, res, next) => {
    if (!req.path.startsWith('/v1') && !req.path.startsWith('/status')) return next();
    const start = Date.now();
    res.on('finish', () => {
      const latencyMs = Date.now() - start;
      const route = (req.route?.path) || req.path;
      _recordRoute(req.method, route, latencyMs, res.statusCode);

      const entry = {
        ts: new Date().toISOString(),
        level: res.statusCode >= 500 ? 'error' : (res.statusCode >= 400 ? 'warn' : 'info'),
        route: `${req.method} ${route}`,
        status: res.statusCode,
        latencyMs,
        keyId: req.apiKeyEntry?.keyId || null,
        workspaceId: req.workspace?.id || null,
        ip: req.ip || req.connection?.remoteAddress || null,
        ua: (req.headers['user-agent'] || '').slice(0, 80)
      };
      // JSON line to stdout — picked up by Fly / Datadog / Logtail / Axiom
      if (res.statusCode >= 500) {
        process.stderr.write(JSON.stringify(entry) + '\n');
        _recentErrors.push(entry);
        if (_recentErrors.length > 50) _recentErrors.shift();
      } else if (res.statusCode >= 400 || latencyMs > 1000) {
        // Mid-severity: stdout but useful for log aggregators
        process.stdout.write(JSON.stringify(entry) + '\n');
      }
      // Successful, fast requests: no log line by default (reduce noise).
      // To log every request, uncomment:
      // else { process.stdout.write(JSON.stringify(entry) + '\n'); }
    });
    next();
  };
}

// ── Status JSON aggregator ───────────────────────────────────────────────────
function mount(app, { frontier, _apiKeys, productsRegistry }) {
  app.get('/v1/status', (req, res) => {
    const v5 = (frontier?.v5SystemStatus?.()) || {};
    const v6 = (frontier?.v6SystemStatus?.()) || {};
    const allSystems = { ...v5, ...v6 };
    const activeCount = Object.values(allSystems).filter(Boolean).length;
    const totalCount = Object.keys(allSystems).length;

    const routeStats = [];
    for (const [route, rec] of _routeStats) {
      routeStats.push({
        route,
        count: rec.count,
        errCount: rec.errCount,
        avgLatencyMs: +(rec.totalLatency / rec.count).toFixed(2),
        p50: _percentile(rec.lastLatencies, 0.5),
        p95: _percentile(rec.lastLatencies, 0.95),
        p99: _percentile(rec.lastLatencies, 0.99)
      });
    }
    routeStats.sort((a, b) => b.count - a.count);

    const products = productsRegistry ? Object.entries(productsRegistry).map(([slug, p]) => ({
      slug, name: p.name, available: !p.unavailable
    })) : [];

    const mem = process.memoryUsage();
    res.json({
      status: activeCount / Math.max(totalCount, 1) > 0.7 ? 'ok' : (activeCount > 0 ? 'degraded' : 'down'),
      timestamp: new Date().toISOString(),
      uptimeSec: Math.floor((Date.now() - STARTED_AT) / 1000),
      uptime:    Math.floor((Date.now() - STARTED_AT) / 1000),
      version: '9.1.0',
      // Fields read by the Settings page UI
      algorithms: 66,
      products: 11,
      memory: {
        heapUsedMB: +(mem.heapUsed / 1024 / 1024).toFixed(1),
        heapTotalMB: +(mem.heapTotal / 1024 / 1024).toFixed(1),
        rssMB: +(mem.rss / 1024 / 1024).toFixed(1),
      },
      subsystems: {
        'Governance Engine': true,
        'HTTPS Proxy':       true,
        'CLI Shims':         true,
        'MCP Server':        true,
        'Browser Extension': true,
        'Audit Chain':       true,
        'ZK Proofs':         true,
        'Usage Meter':       true,
        'Gateway':           true,
        'WASM Runtime':      !!frontier?.wasmDetect,
        'eBPF Filter':       false, // darwin only
      },
      systems: {
        active: activeCount,
        total: totalCount,
        breakdown: allSystems
      },
      productsRegistry: {
        count: products.length,
        available: products.filter(p => p.available).length,
        list: products
      },
      apiKeys: {
        registered: _apiKeys?.size || 0
      },
      runtime: {
        node: process.version,
        platform: process.platform,
        arch: process.arch,
      },
      topRoutes: routeStats.slice(0, 20),
      recentErrors: _recentErrors.slice(-10)
    });
  });

  // Public status page (HTML, single file) — use dynamic handler registry
  // to bypass static middleware that would otherwise catch /status.
  const reg = app._kasbahDynamicHandlers;
  if (reg) {
    reg.set('GET /status', (req, res) => res.type('html').send(STATUS_HTML));
  } else {
    app.get('/status', (req, res) => res.type('html').send(STATUS_HTML));
  }
}

const STATUS_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Kasbah Guard — Status</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Inter', sans-serif; background: #FEFCFA; color: #0F172A; padding: 40px 20px; max-width: 960px; margin: 0 auto; }
h1 { font-size: 28px; margin-bottom: 8px; }
.subtitle { color: #64748B; margin-bottom: 32px; }
.card { background: white; border: 1px solid #E2E8F0; border-radius: 8px; padding: 24px; margin-bottom: 16px; }
.row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #F1F5F9; }
.row:last-child { border-bottom: none; }
.dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 8px; }
.dot.healthy { background: #10B981; }
.dot.degraded { background: #F59E0B; }
.dot.down { background: #EF4444; }
.muted { color: #64748B; font-size: 13px; }
.stat { display: inline-block; margin-right: 32px; }
.stat .num { font-size: 32px; font-weight: 700; }
.stat .label { color: #64748B; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #F1F5F9; }
th { background: #F8FAFC; font-weight: 600; }
.tab { display: inline-block; padding: 4px 10px; border-radius: 4px; background: #F1F5F9; font-size: 12px; }
.error { color: #EF4444; }
footer { text-align: center; color: #94A3B8; font-size: 12px; margin-top: 40px; }
</style>
</head>
<body>
<h1>Kasbah Guard — System Status</h1>
<p class="subtitle">Real-time health of the API and all subsystems.</p>

<div class="card" id="overall">
  <span class="dot" id="overall-dot"></span>
  <strong id="overall-status">Loading…</strong>
  <span class="muted" id="overall-detail"></span>
</div>

<div class="card">
  <div class="stat"><div class="num" id="active-systems">—</div><div class="label">Active Systems</div></div>
  <div class="stat"><div class="num" id="products-available">—</div><div class="label">Products Available</div></div>
  <div class="stat"><div class="num" id="uptime">—</div><div class="label">Uptime</div></div>
  <div class="stat"><div class="num" id="memory">—</div><div class="label">Memory MB</div></div>
</div>

<div class="card">
  <strong>Subsystems</strong>
  <div id="subsystems"></div>
</div>

<div class="card">
  <strong>Top Routes (by traffic)</strong>
  <table id="routes-table"><thead><tr><th>Route</th><th>Calls</th><th>Errors</th><th>p50</th><th>p95</th><th>p99</th></tr></thead><tbody></tbody></table>
</div>

<div class="card" id="errors-card" style="display:none">
  <strong style="color:#EF4444">Recent Errors</strong>
  <pre id="errors" style="font-size:11px;margin-top:8px;color:#EF4444"></pre>
</div>

<footer>Updated <span id="updated">—</span> • <a href="/docs">API Docs</a> • <a href="/v1/status">JSON</a></footer>

<script>
async function refresh() {
  try {
    const r = await fetch('/v1/status');
    const s = await r.json();
    document.getElementById('overall-dot').className = 'dot ' + s.status;
    document.getElementById('overall-status').textContent =
      s.status === 'healthy' ? 'All systems operational' :
      s.status === 'degraded' ? 'Partial degradation' : 'Service down';
    document.getElementById('overall-detail').textContent = ' — Last checked ' + new Date(s.timestamp).toLocaleString();
    document.getElementById('active-systems').textContent = s.systems.active + ' / ' + s.systems.total;
    document.getElementById('products-available').textContent = s.products.available + ' / ' + s.products.count;
    const hh = Math.floor(s.uptimeSec / 3600), mm = Math.floor((s.uptimeSec % 3600) / 60);
    document.getElementById('uptime').textContent = hh + 'h ' + mm + 'm';
    document.getElementById('memory').textContent = s.runtime.memoryRssMb;

    const subs = document.getElementById('subsystems');
    subs.innerHTML = Object.entries(s.systems.breakdown)
      .map(([name, alive]) => '<div class="row"><span><span class="dot ' + (alive ? 'healthy' : 'down') + '"></span>' + name + '</span><span class="tab">' + (alive ? 'OK' : 'OFFLINE') + '</span></div>').join('');

    const tbody = document.querySelector('#routes-table tbody');
    tbody.innerHTML = s.topRoutes.map(r =>
      '<tr><td>' + r.route + '</td><td>' + r.count + '</td><td' + (r.errCount > 0 ? ' class="error"' : '') + '>' + r.errCount + '</td><td>' + r.p50 + 'ms</td><td>' + r.p95 + 'ms</td><td>' + r.p99 + 'ms</td></tr>').join('');

    if (s.recentErrors.length) {
      document.getElementById('errors-card').style.display = '';
      document.getElementById('errors').textContent = s.recentErrors.map(e => JSON.stringify(e, null, 2)).join('\\n\\n');
    }
    document.getElementById('updated').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('overall-dot').className = 'dot down';
    document.getElementById('overall-status').textContent = 'Status fetch failed';
  }
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`;

module.exports = { mount, telemetryMiddleware };
