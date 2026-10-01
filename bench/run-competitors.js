#!/usr/bin/env node
'use strict';

/**
 * Head-to-head benchmark runner — Kasbah vs. external competitors
 *
 *   node bench/run-competitors.js [--corpus bench/corpus/v1.json] [--kasbah http://localhost:8788]
 *
 * For each competitor adapter under bench/competitors/, if it returns non-null
 * (i.e. required env vars are present), it joins the run. Otherwise skipped
 * silently. Kasbah's own /v1/govern is always included as the home column.
 *
 * Output: BENCHMARK-COMPETITORS.md + a JSON dump under bench/results/.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

const args = (() => {
  const a = { kasbah: 'http://localhost:8788', corpus: 'bench/corpus/v1.json' };
  for (let i = 2; i < process.argv.length; i++) {
    const k = process.argv[i].replace(/^--/, '');
    if (k in a) { a[k] = process.argv[i + 1]; i++; }
  }
  return a;
})();

// ─── Load adapters ──────────────────────────────────────────────────────────
function loadAdapters() {
  const dir = path.join(__dirname, 'competitors');
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.js')) continue;
    const mod = require(path.join(dir, f));
    if (mod && typeof mod.run === 'function') out.push(mod);
  }
  return out;
}

// ─── Kasbah govern as the home column ────────────────────────────────────
function kasbahGovern() {
  return {
    name: 'kasbah-govern',
    async run(prompt) {
      const t0 = Date.now();
      try {
        const r = await postJSON(args.kasbah + '/v1/govern', { prompt, agent: 'bench-h2h' });
        const latencyMs = Date.now() - t0;
        const j = r.body || {};
        // Map Kasbah's response (verdict + risk + threats) to our shape
        let verdict = String(j.verdict || '').toUpperCase();
        if (!verdict) {
          if (typeof j.risk === 'number') verdict = j.risk >= 0.60 ? 'DENY' : j.risk >= 0.30 ? 'WARN' : 'ALLOW';
          else verdict = 'UNKNOWN';
        }
        return { verdict, latencyMs, raw: j };
      } catch (e) { return { verdict: 'ERROR', latencyMs: Date.now() - t0, raw: { error: e.message } }; }
    }
  };
}

function postJSON(url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = JSON.stringify(body);
    const lib = u.protocol === 'https:' ? require('https') : http;
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
    }, (res) => {
      let chunks = '';
      res.on('data', c => chunks += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: chunks ? JSON.parse(chunks) : null }); }
        catch (e) { resolve({ status: res.statusCode, body: chunks }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => req.destroy(new Error('timeout')));
    req.write(data); req.end();
  });
}

// ─── Metrics ────────────────────────────────────────────────────────────────
function metrics(rows) {
  let tp=0, fp=0, fn=0, tn=0;
  for (const r of rows) {
    const truth = r.truth !== 'ALLOW';
    const pred  = r.pred  !== 'ALLOW' && r.pred !== 'ERROR' && r.pred !== 'UNKNOWN';
    if (truth && pred) tp++; else if (!truth && pred) fp++;
    else if (truth && !pred) fn++; else tn++;
  }
  const precision = tp+fp===0 ? 1 : tp/(tp+fp);
  const recall    = tp+fn===0 ? 1 : tp/(tp+fn);
  const f1 = precision+recall===0 ? 0 : 2*precision*recall/(precision+recall);
  return { tp, fp, fn, tn, precision, recall, f1, accuracy: (tp+tn)/Math.max(rows.length,1) };
}
function pct(n) { return (n*100).toFixed(1) + '%'; }
function percentile(xs, p) { if (!xs.length) return 0; const s = [...xs].sort((a,b)=>a-b); return s[Math.min(s.length-1, Math.floor(p*s.length))]; }

// ─── Main ───────────────────────────────────────────────────────────────────
async function main() {
  const corpus = JSON.parse(fs.readFileSync(path.resolve(args.corpus), 'utf8'));
  const adapters = [kasbahGovern(), ...loadAdapters()];

  console.log('━━━ Head-to-head benchmark ━━━');
  console.log('  Corpus:    ' + corpus.cases.length + ' cases');
  console.log('  Systems:   ' + adapters.map(a => a.name).join(', '));
  console.log();

  const results = Object.fromEntries(adapters.map(a => [a.name, { rows: [], latencies: [], errors: 0 }]));

  let i = 0;
  for (const c of corpus.cases) {
    i++;
    if (i % 10 === 0) process.stdout.write('  ' + i + '/' + corpus.cases.length + '\r');
    for (const a of adapters) {
      try {
        const r = await a.run(c.prompt);
        results[a.name].rows.push({ id: c.id, truth: c.verdict, pred: r.verdict, class: c.class });
        results[a.name].latencies.push(r.latencyMs);
        if (r.verdict === 'ERROR') results[a.name].errors++;
      } catch (e) {
        results[a.name].rows.push({ id: c.id, truth: c.verdict, pred: 'ERROR', class: c.class });
        results[a.name].errors++;
      }
    }
  }
  console.log('  ' + corpus.cases.length + '/' + corpus.cases.length + ' done.\n');

  // Build summary
  const summary = {};
  const classes = [...new Set(corpus.cases.map(c => c.class))].sort();
  for (const a of adapters) {
    const r = results[a.name];
    summary[a.name] = {
      ...metrics(r.rows),
      latencyP50: percentile(r.latencies, 0.50),
      latencyP95: percentile(r.latencies, 0.95),
      errors: r.errors,
      byClass: Object.fromEntries(classes.map(cls => [cls, metrics(r.rows.filter(x => x.class === cls))]))
    };
  }

  // Print
  const sysNames = Object.keys(summary);
  sysNames.sort((a, b) => (summary[b].f1 || 0) - (summary[a].f1 || 0));
  console.log('┌─ Head-to-head: F1 leaderboard ' + '─'.repeat(40));
  console.log('│ ' + 'System'.padEnd(24) + 'precision'.padStart(11) + '  ' + 'recall'.padStart(8) + '  ' + 'F1'.padStart(8) + '  ' + 'p95(ms)'.padStart(8) + '  err');
  console.log('├' + '─'.repeat(76));
  for (const n of sysNames) {
    const m = summary[n];
    console.log('│ ' + n.padEnd(24) + pct(m.precision).padStart(11) + '  ' + pct(m.recall).padStart(8) + '  ' + pct(m.f1).padStart(8) + '  ' + String(m.latencyP95).padStart(8) + '  ' + m.errors);
  }
  console.log('└' + '─'.repeat(76) + '\n');

  // Write JSON
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.join(__dirname, 'results');
  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'h2h-' + ts + '.json');
  fs.writeFileSync(jsonPath, JSON.stringify({ timestamp: new Date().toISOString(), corpus: { version: corpus.version, totalCases: corpus.cases.length }, summary, raw: results }, null, 2));

  // Write Markdown
  const md = ['# Kasbah Head-to-Head Benchmark', '',
    '_Generated: ' + new Date().toISOString() + '_',
    '', '**Corpus:** ' + corpus.cases.length + ' labeled cases (`bench/corpus/' + path.basename(args.corpus) + '`)',
    '', '## Leaderboard (sorted by F1)', '',
    '| System | Precision | Recall | F1 | Accuracy | p50 (ms) | p95 (ms) | Errors |',
    '|---|---:|---:|---:|---:|---:|---:|---:|',
    ...sysNames.map(n => {
      const m = summary[n];
      return '| ' + (n === 'kasbah-govern' ? '**`' + n + '`**' : '`' + n + '`') +
             ' | ' + pct(m.precision) + ' | ' + pct(m.recall) + ' | **' + pct(m.f1) + '** | ' +
             pct(m.accuracy) + ' | ' + m.latencyP50 + ' | ' + m.latencyP95 + ' | ' + m.errors + ' |';
    }),
    '', '## Per-class F1', '',
    '| Class | ' + sysNames.map(n => '`' + n + '`').join(' | ') + ' |',
    '|---|' + sysNames.map(() => '---:').join('|') + '|',
    ...classes.map(cls => '| ' + cls + ' | ' + sysNames.map(n => {
      const c = summary[n].byClass[cls];
      return c ? pct(c.f1) : '—';
    }).join(' | ') + ' |'),
    '', '## How to reproduce', '',
    '```bash',
    '# 1. Boot Kasbah',
    'node packages/api-server/server.js &',
    '',
    '# 2. Configure adapters with API keys (only configured ones will run)',
    'export LAKERA_API_KEY=lak_xxx',
    'export OPENAI_API_KEY=sk-xxx',
    'export NEMO_URL=http://localhost:8000',
    '',
    '# 3. Run',
    'node bench/run-competitors.js',
    '```',
    ''
  ].join('\n');
  fs.writeFileSync('BENCHMARK-COMPETITORS.md', md);

  console.log('  JSON:     ' + jsonPath);
  console.log('  Markdown: BENCHMARK-COMPETITORS.md\n');
}

main().catch(e => { console.error('FATAL:', e); process.exit(2); });
