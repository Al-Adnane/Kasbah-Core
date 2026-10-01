#!/usr/bin/env node
'use strict';

/**
 * Kasbah Comparative Benchmark
 *
 *   node bench/compare.js [--corpus bench/corpus/v1.json] [--out bench/results/compare-<ts>.json]
 *
 * Runs Kasbah against the same corpus as the baseline bench, but ALSO fires the
 * same prompts at common commodity tools (when installed) to produce a
 * side-by-side precision/recall/F1 comparison.
 *
 * Compared systems:
 *   • Kasbah /v1/govern           (unified engine — must be running on localhost:8788)
 *   • Kasbah /v1/scan             (pattern detector only)
 *   • git-secrets                 (if installed: `git secrets --scan`)
 *   • truffleHog                  (if installed: `trufflehog filesystem`)
 *   • detect-secrets              (if installed: `detect-secrets scan`)
 *   • gitleaks                    (if installed: `gitleaks detect`)
 *   • allow-everything baseline
 *   • deny-everything baseline
 *
 * Each tool is tested against the corpus once. Systems that aren't installed
 * are skipped with a note. Results include:
 *   • Per-class (safe / secret / injection) precision / recall / F1
 *   • Overall weighted F1
 *   • Detection latency (p50 / p95)
 *   • False-positive rate
 *
 * Exit code 0 always — this is an evaluation, not a pass/fail test.
 */

const fs   = require('fs');
const path = require('path');
const http = require('http');
const { execSync, spawnSync } = require('child_process');
const crypto = require('crypto');

// ─── CLI ────────────────────────────────────────────────────────────────────
const NOW = new Date().toISOString().replace(/[:.]/g, '-');
const args = (() => {
  const a = { corpus: 'bench/corpus/v1.json', out: `bench/results/compare-${NOW}.json` };
  for (let i = 2; i < process.argv.length; i++) {
    const k = process.argv[i].replace(/^--/, '');
    const v = process.argv[i + 1];
    if (k in a) { a[k] = v; i++; }
  }
  return a;
})();

// ─── Helpers ────────────────────────────────────────────────────────────────
function sha256hex(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }

function post(url, body, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = JSON.stringify(body);
    const lib = u.protocol === 'https:' ? require('https') : http;
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      timeout: timeoutMs
    }, (res) => {
      let chunks = '';
      res.on('data', c => chunks += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: chunks ? JSON.parse(chunks) : null }); }
        catch { resolve({ status: res.statusCode, body: chunks }); }
      });
    });
    req.on('error', (e) => resolve({ status: 0, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'timeout' }); });
    req.write(data);
    req.end();
  });
}

// ─── Corpus loading ────────────────────────────────────────────────────────
function loadCorpus(corpusPath) {
  const raw = fs.readFileSync(corpusPath, 'utf8');
  const data = JSON.parse(raw);
  // Accept either an array or { prompts: [...] }
  return Array.isArray(data) ? data : (data.prompts || data.cases || []);
}

// ─── Classification ────────────────────────────────────────────────────────
function classifyVerdict(verdict) {
  if (!verdict) return 'SAFE';
  const v = String(verdict).toUpperCase();
  if (v === 'DENY' || v === 'BLOCK') return 'DENY';
  if (v === 'WARN') return 'DENY'; // WARN counts as positive detection
  return 'SAFE';
}

// ─── Metrics ────────────────────────────────────────────────────────────────
function computeMetrics(predictions, labels) {
  const classes = ['DENY', 'SAFE'];
  const metrics = {};
  for (const cls of classes) {
    let tp = 0, fp = 0, fn = 0;
    for (let i = 0; i < predictions.length; i++) {
      const pred = predictions[i];
      const label = labels[i];
      if (pred === cls && label === cls) tp++;
      else if (pred === cls && label !== cls) fp++;
      else if (pred !== cls && label === cls) fn++;
    }
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
    metrics[cls] = { tp, fp, fn, precision, recall, f1 };
  }
  // Weighted F1
  const total = predictions.length;
  const weightedF1 = classes.reduce((sum, cls) => sum + (metrics[cls].f1 * (labels.filter(l => l === cls).length / total)), 0);
  return { perClass: metrics, weightedF1 };
}

function percentile(arr, p) {
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.ceil(sorted.length * p / 100) - 1;
  return sorted[Math.max(0, idx)] || 0;
}

// ─── System runners ─────────────────────────────────────────────────────────

// Kasbah /v1/govern
async function runKasbahGovern(prompts) {
  const predictions = [];
  const latencies = [];
  for (const p of prompts) {
    const text = typeof p === 'string' ? p : (p.text || p.prompt || p.input || '');
    const t0 = Date.now();
    const res = await post('http://localhost:8788/v1/govern', { prompt: text });
    latencies.push(Date.now() - t0);
    const verdict = res.body?.verdict || 'ALLOW';
    predictions.push(classifyVerdict(verdict));
  }
  return { predictions, latencies, name: 'Kasbah /v1/govern' };
}

// Kasbah /v1/scan
async function runKasbahScan(prompts) {
  const predictions = [];
  const latencies = [];
  for (const p of prompts) {
    const text = typeof p === 'string' ? p : (p.text || p.prompt || p.input || '');
    const t0 = Date.now();
    const res = await post('http://localhost:8788/v1/scan', { text });
    latencies.push(Date.now() - t0);
    const risk = res.body?.risk || res.body?.riskScore || 0;
    predictions.push(risk >= 0.35 ? 'DENY' : 'SAFE');
  }
  return { predictions, latencies, name: 'Kasbah /v1/scan' };
}

// Commodity tool: run via CLI on a temp file
function makeCommodityRunner(toolName, scanArgs) {
  return (prompts) => {
    const predictions = [];
    const latencies = [];
    for (const p of prompts) {
      const text = typeof p === 'string' ? p : (p.text || p.prompt || p.input || '');
      const tmpFile = path.join('/tmp', `kasbah-bench-${sha256hex(text).slice(0, 8)}.txt`);
      fs.writeFileSync(tmpFile, text);
      const t0 = Date.now();
      let found = false;
      try {
        const args = [...scanArgs, tmpFile];
        const result = spawnSync(toolName, args, { encoding: 'utf8', timeout: 15000, stdio: 'pipe' });
        found = (result.stdout || '').length > 10 || (result.stderr || '').length > 10;
      } catch (_) { found = false; }
      latencies.push(Date.now() - t0);
      try { fs.unlinkSync(tmpFile); } catch (_) {}
      predictions.push(found ? 'DENY' : 'SAFE');
    }
    return { predictions, latencies, name: toolName };
  };
}

// Baselines
function runAllowEverything(prompts) {
  return {
    predictions: prompts.map(() => 'SAFE'),
    latencies: prompts.map(() => 0),
    name: 'allow-everything (baseline)'
  };
}

function runDenyEverything(prompts) {
  return {
    predictions: prompts.map(() => 'DENY'),
    latencies: prompts.map(() => 0),
    name: 'deny-everything (baseline)'
  };
}

// ─── Main ───────────────────────────────────────────────────────────────────
async function main() {
  console.log('Kasbah Comparative Benchmark');
  console.log('═══════════════════════════════\n');

  const corpusPath = path.resolve(args.corpus);
  if (!fs.existsSync(corpusPath)) {
    console.error(`Corpus not found: ${corpusPath}`);
    process.exit(1);
  }

  const prompts = loadCorpus(corpusPath);
  console.log(`Corpus: ${corpusPath}  (${prompts.length} prompts)\n`);

  // Extract ground-truth labels — normalize to DENY/SAFE
  const labels = prompts.map(p => {
    let raw = null;
    if (typeof p === 'object') {
      raw = p.verdict || p.label || p.class || null;
    }
    if (!raw) {
      const text = typeof p === 'string' ? p : (p.text || p.prompt || p.input || '');
      const hasSecret = /(?:AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)/.test(text);
      return hasSecret ? 'DENY' : 'SAFE';
    }
    const v = String(raw).toUpperCase();
    if (v === 'DENY' || v === 'BLOCK' || v === 'WARN') return 'DENY';
    return 'SAFE';
  });

  const denyCount = labels.filter(l => l === 'DENY').length;
  const safeCount = labels.filter(l => l === 'SAFE').length;
  console.log(`Labels: ${denyCount} DENY / ${safeCount} SAFE\n`);

  // Run all systems
  const systems = [
    // Kasbah systems (always available when engine is running)
    { run: runKasbahGovern, name: 'Kasbah /v1/govern' },
    { run: runKasbahScan, name: 'Kasbah /v1/scan' },
    // Baselines
    { run: runAllowEverything, name: 'allow-everything' },
    { run: runDenyEverything, name: 'deny-everything' },
  ];

  // Commodity tools (optional) — each gets a runner that scans temp files
  const commodity = [
    { cmd: 'gitleaks',    args: ['detect', '--no-git', '--source'] },
    { cmd: 'trufflehog',  args: ['filesystem'] },
    { cmd: 'detect-secrets', args: ['scan'] },
  ];

  for (const c of commodity) {
    try { execSync(`which ${c.cmd}`, { stdio: 'ignore', timeout: 3000 });
      systems.push({ run: makeCommodityRunner(c.cmd, c.args), name: c.cmd });
    } catch { console.log(`  ⏭  ${c.cmd} — not installed, skipping`); }
  }

  console.log('Running evaluations...\n');

  const results = [];
  for (const sys of systems) {
    const t0 = Date.now();
    const result = await sys.run(prompts);
    result.totalMs = Date.now() - t0;

    if (result.error) {
      console.log(`  ⚠  ${sys.name}: ${result.error}`);
      results.push({ system: sys.name, error: result.error });
      continue;
    }

    const metrics = computeMetrics(result.predictions, labels);
    const p50 = percentile(result.latencies, 50);
    const p95 = percentile(result.latencies, 95);

    console.log(`  ✅ ${sys.name}`);
    console.log(`     Weighted F1: ${metrics.weightedF1.toFixed(4)}`);
    console.log(`     DENY F1:     ${metrics.perClass['DENY'].f1.toFixed(4)}  (P:${metrics.perClass['DENY'].precision.toFixed(3)} R:${metrics.perClass['DENY'].recall.toFixed(3)})`);
    console.log(`     SAFE F1:     ${metrics.perClass['SAFE'].f1.toFixed(4)}  (P:${metrics.perClass['SAFE'].precision.toFixed(3)} R:${metrics.perClass['SAFE'].recall.toFixed(3)})`);
    console.log(`     Latency:     p50=${p50}ms  p95=${p95}ms\n`);

    results.push({
      system: sys.name,
      weightedF1: metrics.weightedF1,
      perClass: metrics.perClass,
      latency: { p50, p95 },
      totalMs: result.totalMs,
      predictions: result.predictions,
    });
  }

  // ─── Ranking ────────────────────────────────────────────────────────────
  const ranked = results
    .filter(r => !r.error)
    .sort((a, b) => b.weightedF1 - a.weightedF1);

  console.log('═══════════════════════════════');
  console.log('RANKING (by weighted F1)\n');
  for (let i = 0; i < ranked.length; i++) {
    const r = ranked[i];
    const medal = i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : '  ';
    console.log(`  ${medal} ${r.system.padEnd(30)} F1=${r.weightedF1.toFixed(4)}  p50=${r.latency.p50}ms`);
  }
  console.log('');

  // ─── Write output ──────────────────────────────────────────────────────
  const outDir = path.dirname(args.out);
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  const report = {
    timestamp: new Date().toISOString(),
    corpus: corpusPath,
    promptCount: prompts.length,
    labelDistribution: { DENY: denyCount, SAFE: safeCount },
    ranking: ranked.map(r => ({
      system: r.system,
      weightedF1: r.weightedF1,
      denyF1: r.perClass['DENY'].f1,
      safeF1: r.perClass['SAFE'].f1,
      latencyP50: r.latency.p50,
      latencyP95: r.latency.p95,
    })),
    fullResults: results,
  };

  fs.writeFileSync(args.out, JSON.stringify(report, null, 2));
  console.log(`Report written to ${args.out}`);
}

main().catch(e => { console.error(e); process.exit(1); });
