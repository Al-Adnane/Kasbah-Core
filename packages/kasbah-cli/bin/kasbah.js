#!/usr/bin/env node
'use strict';

/**
 * Kasbah Guard — unified CLI
 *
 *   kasbah scan "<text>"                      — input governance
 *   kasbah govern --prompt "<text>" [--agent X]
 *   kasbah explain "<text>"                   — causal trace for a verdict
 *   kasbah multiverse "<text>"                — fuse the full engine
 *   kasbah ethics evaluate "<scenario>"       — Nomos parliament
 *   kasbah ethics debate "<scenario>"         — Nomos debate mode
 *   kasbah products list                       — list reference detectors
 *   kasbah products run <slug> "<text>"       — run a specific product
 *   kasbah algorithms list [--category X]      — list 63 algorithms
 *   kasbah algorithms run <slug> --input "<text>"
 *   kasbah agents list                         — list active agent sessions
 *   kasbah redteam suite                       — list adversarial suite
 *   kasbah redteam run                         — run adversarial suite
 *   kasbah bench [--limit N] [--systems s1,s2] — run detection benchmark
 *   kasbah bench corpus                        — corpus summary
 *   kasbah bench last                          — most recent result
 *   kasbah receipt verify <proof>              — offline verification
 *   kasbah os check --content "<text>" [--agent X --verb QUERY]
 *   kasbah os metrics                          — live OS metrics
 *   kasbah os status                           — OS status
 *   kasbah swarm                               — swarm-radar snapshot
 *   kasbah forecast [--window 3600000]         — threat forecast
 *   kasbah biometric <fingerprint|rppg|voice|codec> --json '{...}'
 *   kasbah zk <generate|verify|commitment|range> --json '{...}'
 *   kasbah security <consent|shamir-split|shamir-combine|threshold> --json '{...}'
 *   kasbah honeytokens deploy [--service X]
 *   kasbah honeytokens check "<text>"
 *   kasbah agent gcmdp --action X --state '{...}'
 *   kasbah agent maqasid --content "<text>"
 *   kasbah kernel gate --operation X --context '{...}'
 *   kasbah policy [get|put --file P]           — policy editor
 *   kasbah health
 *
 *   Global flags:
 *     --api <url>          — override KASBAH_API_URL (default http://127.0.0.1:8788)
 *     --json               — emit raw JSON (default: pretty summary)
 *     --quiet              — suppress headers, useful in pipelines
 *
 * Honest scope: this is a thin HTTP wrapper. Every command calls one route
 * on the api-server. Zero local logic, zero new endpoints.
 */

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const url   = require('url');

const PKG_VERSION = '1.0.0';

// ─── arg parsing ────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const flags = {};
const positional = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith('--')) {
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { flags[key] = true; }
    else { flags[key] = next; i++; }
  } else positional.push(a);
}

const API_BASE = flags.api || process.env.KASBAH_API_URL || 'http://127.0.0.1:8788';
const EMIT_JSON = !!flags.json;
const QUIET     = !!flags.quiet;

// ─── http ───────────────────────────────────────────────────────────────────
function request(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(API_BASE + path);
    const lib = u.protocol === 'https:' ? https : http;
    const data = body !== null ? JSON.stringify(body) : null;
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + (u.search || ''), method,
      headers: Object.assign(
        { Accept: 'application/json' },
        data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {},
        process.env.KASBAH_API_KEY ? { Authorization: 'Bearer ' + process.env.KASBAH_API_KEY } : {}
      )
    }, (res) => {
      let chunks = '';
      res.on('data', c => chunks += c);
      res.on('end', () => {
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        let parsed = null;
        try { parsed = chunks ? JSON.parse(chunks) : null; } catch { parsed = chunks; }
        if (!ok) reject(Object.assign(new Error('HTTP ' + res.statusCode), { status: res.statusCode, body: parsed }));
        else resolve(parsed);
      });
    });
    req.on('error', reject);
    req.setTimeout(60000, () => req.destroy(new Error('timeout')));
    if (data) req.write(data);
    req.end();
  });
}

// ─── output helpers ─────────────────────────────────────────────────────────
const C = { reset:'\x1b[0m', dim:'\x1b[2m', bold:'\x1b[1m',
            red:'\x1b[31m', green:'\x1b[32m', yellow:'\x1b[33m',
            blue:'\x1b[34m', cyan:'\x1b[36m', gray:'\x1b[90m' };
const usingColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (color, s) => usingColor ? C[color] + s + C.reset : s;
function header(msg) { if (!QUIET && !EMIT_JSON) console.error(c('dim', msg)); }
function output(obj) {
  if (EMIT_JSON) { console.log(JSON.stringify(obj, null, 2)); return; }
  console.log(typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2));
}
function verdictColor(v) {
  const u = String(v || '').toUpperCase();
  if (u.includes('DENY') || u.includes('BLOCK') || u.includes('PROHIBIT')) return 'red';
  if (u.includes('WARN') || u.includes('FLAG'))                            return 'yellow';
  if (u.includes('ALLOW') || u.includes('PASS') || u.includes('CLEAN'))    return 'green';
  return 'cyan';
}
function deriveVerdict(d) {
  if (!d) return '?';
  const raw = d.verdict || d.decision || d.classification;
  if (raw) return String(raw).toUpperCase();
  const risk = typeof d.risk === 'number' ? d.risk : typeof d.risk_score === 'number' ? d.risk_score : null;
  if (risk !== null) return risk >= 0.6 ? 'DENY' : risk >= 0.3 ? 'WARN' : 'ALLOW';
  if (Array.isArray(d.threats)) return d.threats.length ? 'WARN' : 'ALLOW';
  if (typeof d.safe === 'boolean') return d.safe ? 'ALLOW' : 'WARN';
  return '?';
}
function summary(d, primary = []) {
  const v = deriveVerdict(d);
  const r = typeof d.risk === 'number' ? d.risk : typeof d.risk_score === 'number' ? d.risk_score : null;
  let line = c(verdictColor(v), v);
  if (r !== null) line += '  ' + c('dim', 'risk ' + (r * 100).toFixed(0) + '%');
  if (Array.isArray(d.threats) && d.threats.length) line += '  ' + c('dim', d.threats.slice(0, 3).map(t => typeof t === 'string' ? t : (t.type || t.name)).join(', '));
  if (typeof d.latency_ms === 'number' || typeof d.latencyMs === 'number') {
    line += '  ' + c('dim', (d.latency_ms || d.latencyMs) + 'ms');
  }
  console.log(line);
  for (const k of primary) if (k in d) console.log(c('gray', '  ' + k + ': ') + (typeof d[k] === 'object' ? JSON.stringify(d[k]).slice(0, 120) : d[k]));
}

// ─── smart-inference (mirrors desktop UI) ───────────────────────────────────
function detectUseCase(t) {
  if (!t) return null;
  const low = t.toLowerCase();
  const lines = t.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length >= 2) {
    const verbLines = lines.filter(l => /^(EXTRACT|FORMAT|SEND|READ|WRITE|EXEC|SCAN|LIST|DELETE|UPLOAD|DOWNLOAD|QUERY|SEARCH|CREATE|MODIFY|MOVE|COPY)\s/.test(l));
    if (verbLines.length >= 2 && verbLines.length >= lines.length * 0.5)
      return { slug: 'intent-analyzer', label: 'an agent trajectory' };
  }
  if (/\b(experience|education|skills|employment|résumé|resume|curriculum|cv)\b/.test(low)
      && /^\s*[-•·]\s/m.test(t) && lines.length >= 5)
    return { slug: 'resume-authentic', label: 'a resume or CV' };
  if (/\b(swipe|tinder|bumble|hinge|match|profile|bio|love bombing)\b/.test(low)
      || /\b(send money|western union|gift card|crypto|wire transfer).{0,100}\b(urgent|emergency|stuck|hospital|airport)\b/.test(low))
    return { slug: 'dating-guard', label: 'a dating or romance scenario' };
  if (/\b(you always|you never|i never said|that didn't happen|you're imagining|you're crazy|stop overreacting|after everything I)\b/.test(low))
    return { slug: 'relationship-guard', label: 'a manipulative conversation' };
  if (/\b(plaintiff|defendant|whereas|hereby|witnessed|notarized|jurisdiction|affidavit|statute)\b/.test(low)
      || /\b(article \d|section \d|clause \d|exhibit [A-Z])\b/i.test(t))
    return { slug: 'legal-evidence', label: 'a legal document' };
  if (/\b(dao|on-chain|tokenholders|quorum|snapshot|governance vote|treasury allocation|ratify|abstain)\b/.test(low))
    return { slug: 'dao-vote-guard', label: 'a DAO governance proposal' };
  if (/^@\w+:?/m.test(t) || /\b(retweet|repost|engagement farm|coordinated|botnet|sockpuppet)\b/.test(low))
    return { slug: 'botnet-radar', label: 'a social-media thread' };
  if (/AKIA[A-Z0-9]{16}|sk-proj-|sk_live_|ghp_|-----BEGIN [A-Z ]+PRIVATE KEY-----|rm\s+-rf|drop\s+table|ignore\s+(all|previous)\s+instructions/i.test(t))
    return null;
  return null;
}

function usage() {
  console.error(`Kasbah Guard CLI v${PKG_VERSION}   ·   ${c('dim', 'api: ' + API_BASE)}

  ${c('bold', 'kasbah scan')} "<text>"
  ${c('bold', 'kasbah govern')} --prompt "<text>" [--agent X]
  ${c('bold', 'kasbah explain')} "<text>"
  ${c('bold', 'kasbah multiverse')} "<text>"
  ${c('bold', 'kasbah ethics')} <evaluate|debate> "<scenario>"
  ${c('bold', 'kasbah products')} <list | run <slug> "<text>">
  ${c('bold', 'kasbah algorithms')} <list [--category X] | run <slug> --input "<text>">
  ${c('bold', 'kasbah agents')} list
  ${c('bold', 'kasbah redteam')} <suite | run>
  ${c('bold', 'kasbah bench')} [--limit N | corpus | last]
  ${c('bold', 'kasbah receipt verify')} <proof>
  ${c('bold', 'kasbah os')} <check|status|metrics>
  ${c('bold', 'kasbah swarm')}
  ${c('bold', 'kasbah forecast')} [--window 3600000]
  ${c('bold', 'kasbah biometric')} <fingerprint|rppg|voice|codec> --json '{...}'
  ${c('bold', 'kasbah zk')} <generate|verify|commitment|range> --json '{...}'
  ${c('bold', 'kasbah security')} <consent|shamir-split|shamir-combine|threshold> --json '{...}'
  ${c('bold', 'kasbah honeytokens')} <deploy [--service X] | check "<text>">
  ${c('bold', 'kasbah agent')} <gcmdp|maqasid> ...
  ${c('bold', 'kasbah kernel gate')} --operation X --context '{...}'
  ${c('bold', 'kasbah policy')} [get|put --file P]
  ${c('bold', 'kasbah health')}

  Flags: ${c('dim', '--api <url>  --json  --quiet')}
  Env:   ${c('dim', 'KASBAH_API_URL  KASBAH_API_KEY')}
`);
  process.exit(1);
}

// ─── command dispatch ───────────────────────────────────────────────────────
const cmd = positional[0];
const sub = positional[1];
const rest = positional.slice(2);

async function main() {
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') return usage();

  // Single-word commands first
  if (cmd === 'health')      return summary(await request('GET', '/v1/health'));
  if (cmd === 'swarm')       return output(await request('GET', '/v1/swarm/status'));
  if (cmd === 'forecast')    return output(await request('GET', '/v1/forecast?window=' + (flags.window || 3600000)));

  if (cmd === 'scan') {
    const text = sub || flags.text || flags.prompt;
    if (!text) { console.error('  kasbah scan "<text>"'); process.exit(2); }
    // Smart inference — quietly routes to the right product when the content shape is obvious.
    // Disable with --no-infer or pass --as <slug> to force a specific product.
    const explicit = flags.as;
    const inferred = (flags['no-infer'] || explicit) ? null : detectUseCase(text);
    const slug = explicit || inferred?.slug;
    if (slug && slug !== 'general') {
      if (!QUIET && !EMIT_JSON) console.error(c('dim', '  detected: ' + (inferred?.label || slug) + (explicit ? ' (forced)' : '')));
      if (slug === 'intent-analyzer') {
        return summary(await request('POST', '/v1/algorithms/intent-analyzer/run', { steps: text, input: text }), ['summary']);
      }
      let body;
      if (slug === 'dating-guard')  body = { input: text, profile: { bio: text } };
      else if (slug === 'botnet-radar') body = { accounts:[{id:'a1',posts:[text]},{id:'a2',posts:[text]},{id:'a3',posts:[text]}] };
      else body = { input: text };
      return summary(await request('POST', '/v1/products/' + slug + '/analyze', body), ['summary']);
    }
    return summary(await request('POST', '/v1/scan', { text, prompt: text }));
  }

  if (cmd === 'govern') {
    const prompt = flags.prompt || sub;
    if (!prompt) { console.error('  kasbah govern --prompt "<text>" [--agent X]'); process.exit(2); }
    return summary(await request('POST', '/v1/govern', { prompt, agent: flags.agent || 'cli' }));
  }

  if (cmd === 'explain') {
    const text = sub || flags.text;
    if (!text) { console.error('  kasbah explain "<text>"'); process.exit(2); }
    const r = await request('POST', '/v1/explain', { prompt: text });
    summary(r, ['explanation', 'categories']);
    return;
  }

  if (cmd === 'multiverse') {
    const input = sub || flags.input;
    if (!input) { console.error('  kasbah multiverse "<text>"'); process.exit(2); }
    const r = await request('POST', '/v1/multiverse/analyze', { input });
    summary(r, ['summary']);
    if (r.superposition?.results && !EMIT_JSON) {
      console.log(c('gray', '  universes:'));
      for (const [k, v] of Object.entries(r.superposition.results)) {
        if (v.error) console.log('    ' + k + ' ' + c('red', 'error'));
        else {
          const risk = v.risk_score ?? v.risk ?? v.score ?? null;
          const r2 = risk !== null ? (risk * 100).toFixed(0) + '%' : '—';
          console.log('    ' + k.padEnd(22) + c('dim', r2));
        }
      }
    }
    return;
  }

  if (cmd === 'ethics') {
    const text = rest.join(' ') || flags.scenario || flags.content;
    if (!text) { console.error('  kasbah ethics <evaluate|debate> "<scenario>"'); process.exit(2); }
    if (sub === 'evaluate' || !sub) {
      const r = await request('POST', '/v1/nomos/evaluate', { content: text, context: {} });
      console.log(c(verdictColor(r.verdict), r.verdict || '?'));
      const trads = r.traditions || {};
      for (const [k, t] of Object.entries(trads)) {
        const v = t.verdict || t.judgment || '?';
        console.log('  ' + k.padEnd(15) + c(verdictColor(v), v));
      }
      return;
    }
    if (sub === 'debate') {
      const pre = await request('POST', '/v1/nomos/evaluate', { content: text, context: {} }).catch(() => null);
      const initialVerdict = pre?.verdict || 'CONTESTED';
      const r = await request('POST', '/v1/nomos/debate', {
        content: text, initialVerdict,
        challenge: flags.challenge || 'Argue the opposite verdict.'
      });
      output(r);
      return;
    }
  }

  if (cmd === 'products') {
    if (sub === 'list' || !sub) {
      const r = await request('GET', '/v1/products');
      if (EMIT_JSON) return output(r);
      console.log(c('bold', (r.count || 0) + ' products, ' + (r.available || 0) + ' available'));
      for (const p of r.products || []) {
        const dot = p.available ? c('green', '●') : c('red', '○');
        console.log('  ' + dot + ' ' + p.slug.padEnd(22) + c('dim', p.name));
      }
      return;
    }
    if (sub === 'run') {
      const slug = rest[0];
      const text = rest.slice(1).join(' ') || flags.input;
      if (!slug || !text) { console.error('  kasbah products run <slug> "<text>"'); process.exit(2); }
      const r = await request('POST', '/v1/products/' + slug + '/analyze', { input: text });
      console.log(c(verdictColor(r.verdict), r.verdict || '?') + '  ' + c('dim', (r.summary || '').slice(0, 100)));
      if (typeof r.score === 'number') console.log('  ' + c('gray', 'score: ') + r.score.toFixed(3));
      if (typeof r.latencyMs === 'number') console.log('  ' + c('gray', 'latency: ') + r.latencyMs + 'ms');
      return;
    }
  }

  if (cmd === 'algorithms') {
    if (sub === 'list' || !sub) {
      const r = await request('GET', '/v1/algorithms');
      if (EMIT_JSON) return output(r);
      console.log(c('bold', (r.count || 0) + ' algorithms · ') + c('dim', (r.categories || []).join(' · ')));
      const cat = flags.category;
      for (const a of r.algorithms || []) {
        if (cat && a.category !== cat) continue;
        console.log('  ' + a.slug.padEnd(28) + c('gray', a.category.padEnd(15)) + c('dim', a.name));
      }
      return;
    }
    if (sub === 'run') {
      const slug = rest[0];
      const input = flags.input || rest.slice(1).join(' ');
      if (!slug) { console.error('  kasbah algorithms run <slug> --input "<text>"'); process.exit(2); }
      const body = flags.json ? JSON.parse(flags.json) : { input };
      const r = await request('POST', '/v1/algorithms/' + slug + '/run', body);
      summary(r);
      return;
    }
  }

  if (cmd === 'agents') {
    if (sub === 'list' || !sub) {
      const r = await request('GET', '/v1/agents');
      if (EMIT_JSON) return output(r);
      const sessions = r.sessions || [];
      console.log(c('bold', sessions.length + ' active session' + (sessions.length === 1 ? '' : 's')));
      for (const s of sessions) console.log('  ' + (s.sessionId || s.id || '?').padEnd(20) + c('dim', s.status || ''));
      return;
    }
  }

  if (cmd === 'redteam') {
    if (sub === 'suite') return output(await request('GET', '/v1/redteam/suite'));
    if (sub === 'run' || !sub) {
      const r = await request('POST', '/v1/redteam/run', flags.json ? JSON.parse(flags.json) : {});
      if (EMIT_JSON) return output(r);
      const cases = r.results || r.cases || [];
      const passed = cases.filter(c => c.passed || c.caught).length;
      const pct = cases.length ? Math.round(passed / cases.length * 100) : 0;
      const col = pct >= 80 ? 'green' : pct >= 50 ? 'yellow' : 'red';
      console.log(c(col, pct + '%') + '  ' + passed + '/' + cases.length + ' attacks caught');
      for (const cc of cases.filter(x => !(x.passed || x.caught)).slice(0, 10)) {
        console.log('  ' + c('red', '✕') + ' ' + (cc.id || cc.name || '?').padEnd(20) + c('dim', (cc.prompt || cc.input || '').toString().slice(0, 60)));
      }
      return;
    }
  }

  if (cmd === 'bench') {
    if (sub === 'corpus') return output(await request('GET', '/v1/bench/corpus'));
    if (sub === 'last')   return output(await request('GET', '/v1/bench/last'));
    // run
    const body = { systems: (flags.systems || 'scan,govern,baselines').split(',') };
    if (flags.limit) body.limit = parseInt(flags.limit);
    const r = await request('POST', '/v1/bench/run', body);
    if (EMIT_JSON) return output(r);
    const s = r.summary || {};
    const systems = Object.keys(s).sort((a, b) => (s[b].f1 || 0) - (s[a].f1 || 0));
    console.log(c('bold', 'System'.padEnd(28)) + ['Prec','Rec','F1','Acc'].map(h => c('bold', h.padStart(7))).join('  '));
    for (const name of systems) {
      const m = s[name];
      const isK = !name.startsWith('baseline:');
      const f1col = m.f1 >= 0.75 ? 'green' : m.f1 >= 0.55 ? 'yellow' : 'red';
      console.log(
        (isK ? c('cyan', name) : name).padEnd(28) +
        (m.precision * 100).toFixed(0).padStart(6) + '%  ' +
        (m.recall    * 100).toFixed(0).padStart(6) + '%  ' +
        c(f1col, (m.f1 * 100).toFixed(0).padStart(6) + '%') + '  ' +
        (m.accuracy  * 100).toFixed(0).padStart(6) + '%'
      );
    }
    return;
  }

  if (cmd === 'receipt') {
    if (sub === 'verify') {
      const proof = rest[0];
      if (!proof) { console.error('  kasbah receipt verify <proof>'); process.exit(2); }
      return summary(await request('POST', '/v1/receipt/verify', { receipt: proof }));
    }
  }

  if (cmd === 'os') {
    if (sub === 'status')  return summary(await request('GET', '/v1/os/status'));
    if (sub === 'metrics') return output(await request('GET', '/v1/os/metrics'));
    if (sub === 'check') {
      const content = flags.content || rest.join(' ');
      if (!content) { console.error('  kasbah os check --content "<text>" [--agent X --verb QUERY]'); process.exit(2); }
      return summary(await request('POST', '/v1/os/check', {
        agent: flags.agent || 'cli', verb: flags.verb || 'QUERY', target: 'content', content
      }));
    }
  }

  if (cmd === 'biometric') {
    const map = { fingerprint: 'neural-fingerprint', rppg: 'rppg', voice: 'voice-clone', codec: 'neural-codec' };
    const route = map[sub];
    if (!route) { console.error('  kasbah biometric <fingerprint|rppg|voice|codec> --json \'{...}\''); process.exit(2); }
    const body = flags.json ? JSON.parse(flags.json) : {};
    return output(await request('POST', '/v1/biometric/' + route, body));
  }

  if (cmd === 'zk') {
    const map = { generate: 'proof/generate', verify: 'proof/verify', commitment: 'commitment', range: 'range-proof' };
    const route = map[sub];
    if (!route) { console.error('  kasbah zk <generate|verify|commitment|range> --json \'{...}\''); process.exit(2); }
    const body = flags.json ? JSON.parse(flags.json) : {};
    return output(await request('POST', '/v1/zk/' + route, body));
  }

  if (cmd === 'security') {
    const map = { consent: 'consent/check', 'shamir-split': 'shamir/split', 'shamir-combine': 'shamir/combine', threshold: 'threshold/adjust', 'cross-modal': 'cross-modal/verify' };
    const route = map[sub];
    if (!route) { console.error('  kasbah security <consent|shamir-split|shamir-combine|threshold|cross-modal> --json \'{...}\''); process.exit(2); }
    const body = flags.json ? JSON.parse(flags.json) : {};
    return output(await request('POST', '/v1/security/' + route, body));
  }

  if (cmd === 'honeytokens') {
    if (sub === 'deploy') return output(await request('POST', '/v1/honeytokens/deploy', { service: flags.service || 'cli' }));
    if (sub === 'check')  return output(await request('POST', '/v1/honeytokens/check',  { text: rest.join(' ') }));
  }

  if (cmd === 'agent') {
    if (sub === 'gcmdp') {
      const state = flags.state ? JSON.parse(flags.state) : {};
      return output(await request('POST', '/v1/agent/gcmdp', { action: flags.action || 'READ', state, constraints: {} }));
    }
    if (sub === 'maqasid') {
      return output(await request('POST', '/v1/agent/maqasid', { content: flags.content || rest.join(' ') }));
    }
  }

  if (cmd === 'kernel' && sub === 'gate') {
    const context = flags.context ? JSON.parse(flags.context) : {};
    return output(await request('POST', '/v1/kernel/gate', { operation: flags.operation || 'exec', context }));
  }

  if (cmd === 'policy') {
    if (sub === 'put') {
      if (!flags.file) { console.error('  kasbah policy put --file <path>'); process.exit(2); }
      const policy = JSON.parse(fs.readFileSync(flags.file, 'utf8'));
      return output(await request('PUT', '/v1/policy', policy));
    }
    return output(await request('GET', '/v1/policy'));
  }

  console.error('Unknown command: ' + cmd);
  usage();
}

main().catch((e) => {
  if (EMIT_JSON) console.log(JSON.stringify({ error: e.message, status: e.status, body: e.body }, null, 2));
  else console.error(c('red', '✕ ') + e.message + (e.status ? c('dim', ' (HTTP ' + e.status + ')') : ''));
  process.exit(1);
});
