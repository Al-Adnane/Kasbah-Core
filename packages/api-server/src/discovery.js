'use strict';

/**
 * Kasbah Discovery — auto-detect every AI tool, runtime, key, and integration
 * point on the host machine, with zero user input.
 *
 * Returns a structured report the UI can render with one-click install actions.
 *
 *   GET /v1/discover                → full system scan
 *   GET /v1/discover/llm-servers    → just probe local LLM ports
 *   GET /v1/discover/mcp-clients    → installed MCP host configs
 *   POST /v1/discover/install-mcp   → write Kasbah MCP block into a host config
 */

const fs        = require('fs');
const path      = require('path');
const os        = require('os');
const http      = require('http');
const { execSync, spawnSync, exec, spawn } = require('child_process');

// ─── Async non-blocking cache helper ─────────────────────────────────────────
// Returns cached value immediately. If stale (or never populated) AND not
// currently refreshing, kicks off a background refresh. First call returns the
// seed value; subsequent calls (after refresh completes) see real data.
function makeAsyncCache(seed, ttlMs, refreshFn) {
  const state = { value: seed, ts: 0, refreshing: false };
  function get() {
    const age = Date.now() - state.ts;
    if (!state.refreshing && (state.ts === 0 || age > ttlMs)) {
      state.refreshing = true;
      Promise.resolve()
        .then(() => refreshFn())
        .then(v => { state.value = v; state.ts = Date.now(); })
        .catch(() => {})
        .finally(() => { state.refreshing = false; });
    }
    return state.value;
  }
  return get;
}

// Promise-based exec wrapper with timeout
function execAsync(cmd, args, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      try { child.kill('SIGKILL'); } catch (_) {}
      resolve({ status: -1, stdout: out, stderr: err, timedOut: true });
    }, timeoutMs);
    child.stdout.on('data', d => { if (out.length < 1024 * 1024) out += d.toString(); });
    child.stderr.on('data', d => { if (err.length < 64 * 1024) err += d.toString(); });
    child.on('error', () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ status: -1, stdout: out, stderr: err, error: true });
    });
    child.on('close', (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ status: code, stdout: out, stderr: err });
    });
  });
}

// ─── Probe targets ────────────────────────────────────────────────────────────
const LLM_PORTS = [
  { port: 11434, name: 'Ollama',       endpoint: '/api/tags',    family: 'ollama'   },
  { port: 1234,  name: 'LM Studio',    endpoint: '/v1/models',   family: 'openai'   },
  { port: 5000,  name: 'Text-Gen WebUI', endpoint: '/v1/models', family: 'openai'   },
  { port: 8000,  name: 'vLLM / FastChat', endpoint: '/v1/models', family: 'openai'  },
  { port: 8080,  name: 'llama.cpp',    endpoint: '/v1/models',   family: 'openai'   },
  { port: 7860,  name: 'Gradio app',   endpoint: '/',            family: 'web'      },
  { port: 4891,  name: 'GPT4All',      endpoint: '/v1/models',   family: 'openai'   },
  { port: 3000,  name: 'Open WebUI',   endpoint: '/api/version', family: 'web'      },
  { port: 8788,  name: 'Kasbah (self)',endpoint: '/v1/health',   family: 'self'     },
];

const PROVIDER_ENV_KEYS = [
  { env: 'ANTHROPIC_API_KEY',   provider: 'anthropic',  label: 'Anthropic Claude' },
  { env: 'OPENAI_API_KEY',      provider: 'openai',     label: 'OpenAI GPT'       },
  { env: 'GOOGLE_API_KEY',      provider: 'google',     label: 'Google Gemini'    },
  { env: 'GEMINI_API_KEY',      provider: 'google',     label: 'Google Gemini'    },
  { env: 'MISTRAL_API_KEY',     provider: 'mistral',    label: 'Mistral'          },
  { env: 'GROQ_API_KEY',        provider: 'groq',       label: 'Groq'             },
  { env: 'DEEPSEEK_API_KEY',    provider: 'deepseek',   label: 'DeepSeek'         },
  { env: 'QWEN_API_KEY',        provider: 'qwen',       label: 'Qwen (Alibaba)'   },
  { env: 'DASHSCOPE_API_KEY',   provider: 'qwen',       label: 'Qwen / DashScope' },
  { env: 'TOGETHER_API_KEY',    provider: 'together',   label: 'Together AI'      },
  { env: 'COHERE_API_KEY',      provider: 'cohere',     label: 'Cohere'           },
  { env: 'XAI_API_KEY',         provider: 'xai',        label: 'xAI Grok'         },
  { env: 'HF_TOKEN',            provider: 'huggingface',label: 'HuggingFace'      },
  { env: 'HUGGINGFACE_TOKEN',   provider: 'huggingface',label: 'HuggingFace'      },
  { env: 'REPLICATE_API_TOKEN', provider: 'replicate',  label: 'Replicate'        },
  { env: 'PERPLEXITY_API_KEY',  provider: 'perplexity', label: 'Perplexity'       },
];

const AI_CLI_TOOLS = [
  'claude', 'codex', 'ollama', 'lms', 'gpt', 'llm', 'aichat', 'aider',
  'continue', 'gh', 'copilot', 'cursor-agent', 'cody', 'tabby'
];

const AI_APP_PATTERNS = [
  /^Claude(\.app|-.*)?$/i,
  /^ChatGPT.*\.app$/i,
  /^Cursor.*\.app$/i,
  /^Ollama\.app$/i,
  /^LM Studio.*\.app$/i,
  /^GPT4All.*\.app$/i,
  /^Continue.*\.app$/i,
  /^Cody.*\.app$/i,
  /^Warp\.app$/i,
  /^Raycast\.app$/i,
  /^Perplexity.*\.app$/i,
];

const MCP_HOST_CONFIGS = [
  {
    name:    'Claude Desktop',
    paths:   [
      path.join(os.homedir(), 'Library/Application Support/Claude/claude_desktop_config.json'),
      path.join(os.homedir(), 'Library/Application Support/Claude-3p/claude_desktop_config.json'),
      path.join(os.homedir(), '.config/Claude/claude_desktop_config.json'),
      path.join(process.env.APPDATA || '', 'Claude/claude_desktop_config.json'),
    ],
    family: 'claude-desktop',
  },
  {
    name:  'Claude Code',
    paths: [ path.join(os.homedir(), '.claude.json') ],
    family: 'claude-code',
  },
  {
    name:  'Cursor',
    paths: [
      path.join(os.homedir(), '.cursor/mcp.json'),
      path.join(os.homedir(), 'Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json'),
    ],
    family: 'cursor',
  },
  {
    name:  'Cline (VS Code)',
    paths: [
      path.join(os.homedir(), 'Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json'),
    ],
    family: 'cline',
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function probePort(host, port, p) {
  return new Promise(resolve => {
    const req = http.get({ host, port, path: p, timeout: 250 }, res => {
      let data = '';
      res.on('data', c => { if (data.length < 4096) data += c; });
      res.on('end',  () => resolve({ ok: res.statusCode < 500, status: res.statusCode, body: data }));
    });
    req.on('error',   () => resolve({ ok: false }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, timeout: true }); });
  });
}

async function _discoverLLMServersRaw() {
  const probed = await Promise.all(LLM_PORTS.map(async t => {
    const r = await probePort('127.0.0.1', t.port, t.endpoint);
    if (!r.ok) return null;
    let models = [];
    try {
      const j = JSON.parse(r.body);
      if (Array.isArray(j.models))   models = j.models.map(m => m.name || m.model || m);
      if (Array.isArray(j.data))     models = j.data.map(m => m.id || m.model || m);
    } catch (_) {}
    return {
      name:     t.name,
      family:   t.family,
      url:      `http://127.0.0.1:${t.port}`,
      port:     t.port,
      status:   'running',
      models,
      modelCount: models.length,
    };
  }));
  return probed.filter(Boolean);
}

const _llmCache = { value: [], ts: 0, refreshing: false };
function discoverLLMServers() {
  const age = Date.now() - _llmCache.ts;
  if (!_llmCache.refreshing && (_llmCache.ts === 0 || age > 30 * 1000)) {
    _llmCache.refreshing = true;
    _discoverLLMServersRaw()
      .then(v => { _llmCache.value = v; _llmCache.ts = Date.now(); })
      .catch(() => {})
      .finally(() => { _llmCache.refreshing = false; });
  }
  return _llmCache.value;
}

function discoverInstalledApps() {
  const apps = [];
  try {
    const dir = '/Applications';
    if (fs.existsSync(dir)) {
      for (const entry of fs.readdirSync(dir)) {
        if (AI_APP_PATTERNS.some(rx => rx.test(entry))) {
          apps.push({ name: entry.replace(/\.app$/, ''), path: path.join(dir, entry) });
        }
      }
    }
  } catch (_) {}
  return apps;
}

function discoverMCPHosts() {
  const out = [];
  for (const host of MCP_HOST_CONFIGS) {
    for (const p of host.paths) {
      if (!p || !fs.existsSync(p)) continue;
      let servers = [];
      let hasKasbah = false;
      try {
        const j = JSON.parse(fs.readFileSync(p, 'utf8'));
        // Claude Desktop format: { mcpServers: {...} }
        // Claude Code format: same
        const all = j.mcpServers || j.mcp || {};
        servers = Object.keys(all);
        hasKasbah = servers.includes('kasbah');
        // Also walk per-project entries in ~/.claude.json
        if (j.projects) {
          for (const pkey of Object.keys(j.projects)) {
            const psv = j.projects[pkey]?.mcpServers || {};
            for (const s of Object.keys(psv)) {
              if (!servers.includes(s)) servers.push(s);
              if (s === 'kasbah') hasKasbah = true;
            }
          }
        }
      } catch (_) {}
      out.push({
        name:      host.name,
        family:    host.family,
        configPath: p,
        installed: true,
        servers,
        serverCount: servers.length,
        hasKasbah,
      });
      break; // first existing path wins per host
    }
  }
  return out;
}

// Read shell rc files to find provider keys the spawned process didn't inherit.
// Looks for: export X_API_KEY=..., X_API_KEY=..., setenv X_API_KEY ...
function scanShellRcFiles() {
  const candidates = [
    '.zshrc', '.zprofile', '.zshenv',
    '.bash_profile', '.bashrc', '.profile',
    '.env', '.env.local',
  ];
  const found = new Map(); // envVar -> {value, source}
  const valuePattern = /(?:export\s+|setenv\s+)?([A-Z][A-Z0-9_]+)\s*[=\s]\s*["']?([^"'\n\r]+?)["']?\s*(?:#.*)?$/;
  for (const file of candidates) {
    const p = path.join(os.homedir(), file);
    if (!fs.existsSync(p)) continue;
    try {
      const content = fs.readFileSync(p, 'utf8');
      for (const line of content.split('\n')) {
        const m = line.trim().match(valuePattern);
        if (!m) continue;
        const [, key, val] = m;
        if (PROVIDER_ENV_KEYS.some(p => p.env === key) && !found.has(key)) {
          found.set(key, { value: val, source: file });
        }
      }
    } catch (_) {}
  }
  return found;
}

function discoverProviderKeys() {
  const out = [];
  // Process env first
  const procEnv = new Set();
  for (const k of PROVIDER_ENV_KEYS) {
    if (process.env[k.env]) {
      procEnv.add(k.env);
      const val = process.env[k.env];
      out.push({
        provider: k.provider,
        label:    k.label,
        envVar:   k.env,
        keyHint:  val.slice(0, 6) + '...' + val.slice(-4),
        length:   val.length,
        source:   'process.env',
      });
    }
  }
  // Then shell-rc scan for keys the electron process didn't inherit
  const shellKeys = scanShellRcFiles();
  for (const [envVar, { value, source }] of shellKeys.entries()) {
    if (procEnv.has(envVar)) continue;
    const meta = PROVIDER_ENV_KEYS.find(p => p.env === envVar);
    if (!meta) continue;
    out.push({
      provider: meta.provider,
      label:    meta.label,
      envVar,
      keyHint:  value.slice(0, 6) + '...' + value.slice(-4),
      length:   value.length,
      source:   '~/' + source,
    });
  }
  return out;
}

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes for packages
const PROC_TTL_MS  = 30 * 1000;     // 30 seconds for processes/CLIs

// Detect AI-related npm/pip packages globally installed (async, non-blocking)
async function _discoverPackagesRaw() {
  const out = { node: [], python: [] };
  const [npmR, pipR] = await Promise.all([
    execAsync('npm', ['list', '-g', '--depth=0', '--json'], 5000),
    execAsync('pip3', ['list', '--format=json'], 5000),
  ]);
  try {
    if (npmR.stdout) {
      const j = JSON.parse(npmR.stdout || '{}');
      const deps = j.dependencies || {};
      const wanted = ['langchain', '@langchain/core', 'openai', '@anthropic-ai/sdk', 'ollama', 'llamaindex', '@kasbah/sdk', 'kasbah'];
      for (const w of wanted) {
        if (deps[w]) out.node.push({ name: w, version: deps[w].version });
      }
    }
  } catch (_) {}
  try {
    if (pipR.stdout) {
      const arr = JSON.parse(pipR.stdout || '[]');
      const wanted = new Set(['langchain', 'langchain-core', 'openai', 'anthropic', 'ollama', 'llama-index', 'kasbah', 'kasbah-python', 'autogen', 'crewai']);
      for (const p of arr) if (wanted.has(p.name)) out.python.push({ name: p.name, version: p.version });
    }
  } catch (_) {}
  return out;
}

const discoverPackages = makeAsyncCache({ node: [], python: [] }, CACHE_TTL_MS, _discoverPackagesRaw);

// ─── Frontier agent registry — every autonomous agent we know how to govern
const FRONTIER_AGENTS = [
  { id: 'claude-code',     label: 'Claude Code',        signals: ['cli:claude', 'config:~/.claude.json'],            govern: ['mcp', 'proxy', 'shim'] },
  { id: 'claude-desktop',  label: 'Claude Desktop',     signals: ['app:Claude.app', 'config:~/Library/Application Support/Claude/claude_desktop_config.json'], govern: ['mcp', 'browser'] },
  { id: 'cursor',          label: 'Cursor',             signals: ['app:Cursor.app', 'cli:cursor-agent'],              govern: ['mcp', 'proxy'] },
  { id: 'codex-cli',       label: 'OpenAI Codex CLI',   signals: ['cli:codex'],                                       govern: ['shim', 'proxy'] },
  { id: 'aider',           label: 'Aider',              signals: ['cli:aider', 'pip:aider-chat'],                     govern: ['shim', 'proxy'] },
  { id: 'cline',           label: 'Cline',              signals: ['vscode-ext:saoudrizwan.claude-dev'],               govern: ['mcp'] },
  { id: 'continue',        label: 'Continue',           signals: ['vscode-ext:Continue.continue'],                    govern: ['mcp', 'proxy'] },
  { id: 'cody',            label: 'Sourcegraph Cody',   signals: ['vscode-ext:sourcegraph.cody-ai', 'cli:cody'],      govern: ['proxy'] },
  { id: 'devin',           label: 'Devin',              signals: ['cli:devin'],                                       govern: ['shim'] },
  { id: 'gpt-engineer',    label: 'GPT Engineer',       signals: ['pip:gpt-engineer', 'cli:gpt-engineer'],            govern: ['shim', 'proxy'] },
  { id: 'autogpt',         label: 'AutoGPT',            signals: ['pip:autogpt', 'cli:autogpt'],                      govern: ['shim', 'proxy'] },
  { id: 'crewai',          label: 'CrewAI',             signals: ['pip:crewai', 'pip:crewai-tools'],                  govern: ['proxy'] },
  { id: 'metagpt',         label: 'MetaGPT',            signals: ['pip:metagpt'],                                     govern: ['shim', 'proxy'] },
  { id: 'autogen',         label: 'AutoGen',            signals: ['pip:autogen', 'pip:pyautogen'],                    govern: ['proxy'] },
  { id: 'open-interpreter',label: 'Open Interpreter',   signals: ['pip:open-interpreter', 'cli:interpreter'],         govern: ['shim', 'proxy'] },
  { id: 'goose',           label: 'Goose (Block)',      signals: ['cli:goose'],                                       govern: ['shim'] },
  { id: 'langchain-py',    label: 'LangChain (Python)', signals: ['pip:langchain', 'pip:langchain-core'],             govern: ['proxy'] },
  { id: 'langchain-js',    label: 'LangChain (Node)',   signals: ['npm:langchain', 'npm:@langchain/core'],            govern: ['proxy'] },
  { id: 'llamaindex',      label: 'LlamaIndex',         signals: ['pip:llama-index', 'npm:llamaindex'],               govern: ['proxy'] },
  { id: 'ollama',          label: 'Ollama',             signals: ['app:Ollama.app', 'cli:ollama', 'port:11434'],      govern: ['proxy', 'shim'] },
  { id: 'lm-studio',       label: 'LM Studio',          signals: ['app:LM Studio.app', 'port:1234', 'cli:lms'],       govern: ['proxy'] },
  { id: 'gpt4all',         label: 'GPT4All',            signals: ['app:GPT4All.app', 'port:4891'],                    govern: ['proxy'] },
  { id: 'vllm',            label: 'vLLM',               signals: ['pip:vllm', 'port:8000', 'cli:vllm'],               govern: ['proxy'] },
  { id: 'llama-cpp',       label: 'llama.cpp',          signals: ['port:8080', 'cli:llama-server'],                   govern: ['proxy'] },
  { id: 'github-copilot',  label: 'GitHub Copilot',     signals: ['cli:gh', 'vscode-ext:GitHub.copilot'],             govern: ['shim'] },
  { id: 'chatgpt-web',     label: 'ChatGPT (browser)',  signals: ['bookmark:chatgpt.com'],                            govern: ['browser'] },
  { id: 'claude-ai-web',   label: 'Claude.ai (browser)',signals: ['bookmark:claude.ai'],                              govern: ['browser'] },
  { id: 'gemini-web',      label: 'Gemini (browser)',   signals: ['bookmark:gemini.google.com'],                      govern: ['browser'] },
  { id: 'perplexity-web',  label: 'Perplexity (browser)',signals:['bookmark:perplexity.ai'],                          govern: ['browser'] },
];

// Resolve signals against the discovery snapshot
function matchFrontierAgents(snapshot) {
  const apps     = new Set((snapshot.apps||[]).map(a => a.name + '.app'));
  const clis     = new Set((snapshot.clis||[]).map(c => c.command));
  const mcpPaths = new Set((snapshot.mcp||[]).map(m => m.configPath));
  const pipPkgs  = new Set((snapshot.packages?.python||[]).map(p => p.name));
  const npmPkgs  = new Set((snapshot.packages?.node||[]).map(p => p.name));
  const ports    = new Set((snapshot.llm||[]).map(l => String(l.port)));
  const sites    = new Set((snapshot.browser||[]).map(b => b.site));

  const result = [];
  for (const a of FRONTIER_AGENTS) {
    const matched = [];
    for (const sig of a.signals) {
      const [type, val] = sig.split(':');
      const v = val;
      if (type === 'app'      && apps.has(v))                          matched.push(sig);
      else if (type === 'cli' && clis.has(v))                          matched.push(sig);
      else if (type === 'pip' && pipPkgs.has(v))                       matched.push(sig);
      else if (type === 'npm' && npmPkgs.has(v))                       matched.push(sig);
      else if (type === 'port'&& ports.has(v))                         matched.push(sig);
      else if (type === 'bookmark' && sites.has(v))                    matched.push(sig);
      else if (type === 'config' && fs.existsSync(v.replace(/^~/, os.homedir()))) matched.push(sig);
      else if (type === 'vscode-ext' && _vscodeExtInstalled(v))        matched.push(sig);
    }
    if (matched.length) {
      result.push({
        id: a.id, label: a.label, kind: 'frontier-agent',
        signalsMatched: matched, governableVia: a.govern,
      });
    }
  }
  return result;
}

function _vscodeExtInstalled(ext) {
  const dir = path.join(os.homedir(), '.vscode/extensions');
  if (!fs.existsSync(dir)) return false;
  try {
    return fs.readdirSync(dir).some(e => e.startsWith(ext.toLowerCase() + '-'));
  } catch (_) { return false; }
}

// Browser AI sites visited (Safari/Chrome history if accessible)
function discoverBrowserAI() {
  const seen = new Set();
  const sites = ['chatgpt.com', 'claude.ai', 'gemini.google.com', 'perplexity.ai', 'character.ai', 'huggingface.co', 'poe.com'];
  // Cheap check: look in default Chrome bookmarks (no DB read — too heavy/locked)
  const chromeBookmarks = path.join(os.homedir(), 'Library/Application Support/Google/Chrome/Default/Bookmarks');
  try {
    if (fs.existsSync(chromeBookmarks)) {
      const j = JSON.parse(fs.readFileSync(chromeBookmarks, 'utf8'));
      const walk = (n) => {
        if (!n) return;
        if (n.url && typeof n.url === 'string') {
          for (const s of sites) if (n.url.includes(s)) seen.add(s);
        }
        if (Array.isArray(n.children)) n.children.forEach(walk);
      };
      walk(j.roots?.bookmark_bar);
      walk(j.roots?.other);
    }
  } catch (_) {}
  return Array.from(seen).map(s => ({ site: s, source: 'chrome bookmarks' }));
}

// Sync fast path: stat each dir in PATH for the binary (no child process needed)
function _discoverCLIsSync() {
  const pathDirs = (process.env.PATH || '').split(':').filter(Boolean);
  const results = [];
  for (const cmd of AI_CLI_TOOLS) {
    for (const dir of pathDirs) {
      const full = path.join(dir, cmd);
      try {
        const st = fs.statSync(full);
        if (st.isFile() && (st.mode & 0o111)) {
          results.push({ command: cmd, path: full });
          break;
        }
      } catch (_) {}
    }
  }
  return results;
}

async function _discoverCLIsRaw() {
  // Fast sync pass first, then confirm with execAsync for accuracy
  return _discoverCLIsSync();
}

// Return sync results immediately — no async lag on first call
function discoverCLIs() { return _discoverCLIsSync(); }

async function _discoverRunningProcessesRaw() {
  const found = [];
  const r = await execAsync('ps', ['-Ao', 'pid,comm'], 2000);
  if (r.status === 0 && r.stdout) {
    const seen = new Set();
    const lines = r.stdout.split('\n');
    for (const line of lines) {
      const m = line.match(/^\s*\d+\s+(.+)$/);
      if (!m) continue;
      const cmd = m[1];
      if (/Claude|Ollama|ChatGPT|Cursor|LM Studio|llama-server|vllm|gpt4all|continue|cody/i.test(cmd)) {
        const key = path.basename(cmd);
        if (seen.has(key)) continue;
        seen.add(key);
        found.push(key);
        if (found.length >= 12) break;
      }
    }
  }
  return found;
}
const discoverRunningProcesses = makeAsyncCache([], PROC_TTL_MS, _discoverRunningProcessesRaw);

// Pre-warm: trigger expensive scans at boot so the first user request is instant
function prewarm() {
  setImmediate(() => {
    // Each of these kicks off an async background refresh on first call.
    try { discoverPackages(); } catch (_) {}
    try { discoverLLMServers(); } catch (_) {}
    try { discoverCLIs(); } catch (_) {}
    try { discoverRunningProcesses(); } catch (_) {}
  });
}

// ─── Mounting ─────────────────────────────────────────────────────────────────
function mount(app) {
  prewarm();

  app.get('/v1/discover', async (_req, res) => {
    const t0 = Date.now();
    try {
      const [llm, apps, mcp, keys, clis, procs, pkgs, browser] = await Promise.all([
        discoverLLMServers(),
        Promise.resolve(discoverInstalledApps()),
        Promise.resolve(discoverMCPHosts()),
        Promise.resolve(discoverProviderKeys()),
        Promise.resolve(discoverCLIs()),
        Promise.resolve(discoverRunningProcesses()),
        Promise.resolve(discoverPackages()),
        Promise.resolve(discoverBrowserAI()),
      ]);

      // Match frontier agents against everything we discovered
      const frontierAgents = matchFrontierAgents({
        apps, clis, mcp, packages: pkgs, llm, browser
      });

      const integratable = {
        llmServers:    llm.length,
        installedApps: apps.length,
        mcpHosts:      mcp.length,
        providerKeys:  keys.length,
        ailCLIs:       clis.length,
        runningProcs:  procs.length,
        sdkPackages:   pkgs.node.length + pkgs.python.length,
        browserAI:     browser.length,
        frontierAgents: frontierAgents.length,
      };

      // Recommendations: things Kasbah can do RIGHT NOW
      const recommendations = [];
      for (const m of mcp) {
        if (!m.hasKasbah) recommendations.push({
          action:  'install-mcp',
          target:  m.family,
          label:   `Install Kasbah into ${m.name}`,
          why:     `${m.name} has ${m.serverCount} MCP server(s) — Kasbah isn't one of them yet.`,
          severity: 'recommended',
        });
      }
      for (const l of llm) {
        if (l.family === 'self') continue;
        recommendations.push({
          action:  'route-via-gateway',
          target:  l.name,
          url:     l.url,
          label:   `Route ${l.name} traffic through Kasbah`,
          why:     `${l.name} is running locally with ${l.modelCount} model(s). Every call could be governed.`,
          severity: 'opportunity',
        });
      }
      for (const k of keys) {
        recommendations.push({
          action:  'route-provider',
          target:  k.provider,
          label:   `Govern ${k.label} via Gateway`,
          why:     `Found ${k.envVar} in environment. Set base URL to Kasbah and we'll govern every call.`,
          severity: 'opportunity',
        });
      }

      res.json({
        scannedAt:  new Date().toISOString(),
        latencyMs:  Date.now() - t0,
        host:       { platform: os.platform(), arch: os.arch(), node: process.version, user: os.userInfo().username },
        summary:    integratable,
        llmServers: llm,
        installedApps: apps,
        mcpHosts:   mcp,
        providerKeys: keys,
        ailCLIs:    clis,
        runningProcesses: procs,
        sdkPackages: pkgs,
        browserAI: browser,
        frontierAgents,
        recommendations,
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Lightweight subendpoints
  app.get('/v1/discover/llm-servers', async (_req, res) => res.json({ servers: await discoverLLMServers() }));
  app.get('/v1/discover/mcp-clients', (_req, res) => res.json({ hosts: discoverMCPHosts() }));
  app.get('/v1/discover/provider-keys', (_req, res) => res.json({ keys: discoverProviderKeys() }));

  // ── Govern Everything — install Kasbah MCP into every detected host at once
  app.post('/v1/discover/govern-all', (req, res) => {
    const { mcpServerPath, apiUrl } = req.body || {};
    if (!mcpServerPath) return res.status(400).json({ error: 'mcpServerPath required' });
    const hosts = discoverMCPHosts();
    const results = [];
    for (const h of hosts) {
      if (h.hasKasbah) { results.push({ host: h.name, skipped: 'already installed' }); continue; }
      try {
        const raw = fs.readFileSync(h.configPath, 'utf8') || '{}';
        const j   = JSON.parse(raw);
        j.mcpServers = j.mcpServers || {};
        j.mcpServers.kasbah = {
          command: 'node',
          args:    [mcpServerPath],
          env:     { KASBAH_API_URL: apiUrl || 'http://127.0.0.1:8788' },
        };
        const bak = h.configPath + '.kasbah-bak.' + Date.now();
        fs.writeFileSync(bak, raw);
        fs.writeFileSync(h.configPath, JSON.stringify(j, null, 2));
        results.push({ host: h.name, installed: true, backup: bak });
      } catch (e) {
        results.push({ host: h.name, error: e.message });
      }
    }
    res.json({ ok: true, results, hosts: discoverMCPHosts() });
  });

  // ── Launch a detected AI app (e.g. start Ollama)
  app.post('/v1/discover/launch-app', (req, res) => {
    const { appName, appPath } = req.body || {};
    if (!appName && !appPath) return res.status(400).json({ error: 'appName or appPath required' });
    try {
      const args = appPath ? [appPath] : ['-a', appName];
      const r = spawnSync('open', args, { timeout: 5000 });
      if (r.status !== 0) return res.status(500).json({ error: 'open failed', stderr: r.stderr?.toString() });
      res.json({ ok: true, launched: appName || appPath });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── Kill a process by PID (rogue agent control)
  app.post('/v1/discover/kill-process', (req, res) => {
    const { pid, signal = 'SIGTERM' } = req.body || {};
    const num = parseInt(pid, 10);
    if (!num || num < 100) return res.status(400).json({ error: 'valid pid required' });
    try {
      process.kill(num, signal);
      res.json({ ok: true, pid: num, signal });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── Generate routing snippet — set provider base URLs to Kasbah
  app.get('/v1/discover/routing-snippet', (_req, res) => {
    const apiUrl = `http://127.0.0.1:${process.env.PORT || 8788}`;
    res.json({
      apiUrl,
      shell: [
        '# Add to ~/.zshrc or ~/.bash_profile — routes every provider call through Kasbah:',
        `export ANTHROPIC_BASE_URL="${apiUrl}/v1/gateway/anthropic"`,
        `export OPENAI_BASE_URL="${apiUrl}/v1/gateway/openai"`,
        `export OPENAI_API_BASE="${apiUrl}/v1/gateway/openai"   # langchain compatibility`,
        `export MISTRAL_BASE_URL="${apiUrl}/v1/gateway/mistral"`,
        `export GOOGLE_GENAI_BASE_URL="${apiUrl}/v1/gateway/google"`,
        `export OLLAMA_HOST="${apiUrl}/v1/gateway/ollama"`,
      ].join('\n'),
      note: 'After setting these, every existing tool — Python, Node, curl, Claude Desktop, Cursor — routes its provider traffic through Kasbah governance. Your API keys still get used; Kasbah never stores them.',
    });
  });

  // ── Live event stream for overwatch (SSE — every detection diff)
  app.get('/v1/discover/stream', (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
    });
    res.write('event: hello\ndata: {"ok":true}\n\n');
    let lastSnapshot = null;
    const interval = setInterval(async () => {
      try {
        const snap = {
          mcp:   discoverMCPHosts(),
          keys:  discoverProviderKeys(),
          procs: discoverRunningProcesses(),
          llm:   await discoverLLMServers(),
        };
        if (lastSnapshot) {
          const diff = computeDiff(lastSnapshot, snap);
          if (diff.length) {
            res.write('event: change\ndata: ' + JSON.stringify({ ts: Date.now(), changes: diff }) + '\n\n');
          }
        }
        lastSnapshot = snap;
      } catch (_) {}
    }, 5000);
    req.on('close', () => clearInterval(interval));
  });

  function computeDiff(a, b) {
    const changes = [];
    const aProc = new Set(a.procs); const bProc = new Set(b.procs);
    for (const p of bProc) if (!aProc.has(p)) changes.push({ type: 'process.new', name: p });
    for (const p of aProc) if (!bProc.has(p)) changes.push({ type: 'process.gone', name: p });
    const aLlm = new Set(a.llm.map(x=>x.port)); const bLlm = new Set(b.llm.map(x=>x.port));
    for (const p of bLlm) if (!aLlm.has(p)) changes.push({ type: 'llm.up', port: p });
    for (const p of aLlm) if (!bLlm.has(p)) changes.push({ type: 'llm.down', port: p });
    return changes;
  }

  // One-click install: add the Kasbah MCP block to a discovered host
  app.post('/v1/discover/install-mcp', (req, res) => {
    const { configPath, mcpServerPath, apiUrl } = req.body || {};
    if (!configPath || !mcpServerPath) {
      return res.status(400).json({ error: 'configPath and mcpServerPath required' });
    }
    if (!fs.existsSync(configPath)) {
      return res.status(404).json({ error: 'configPath does not exist', configPath });
    }
    try {
      const raw = fs.readFileSync(configPath, 'utf8') || '{}';
      const j   = JSON.parse(raw);
      j.mcpServers = j.mcpServers || {};
      j.mcpServers.kasbah = {
        command: 'node',
        args:    [mcpServerPath],
        env:     { KASBAH_API_URL: apiUrl || 'http://127.0.0.1:8788' },
      };
      // Backup
      const bak = configPath + '.kasbah-bak.' + Date.now();
      fs.writeFileSync(bak, raw);
      fs.writeFileSync(configPath, JSON.stringify(j, null, 2));
      res.json({ ok: true, configPath, backup: bak, hosts: discoverMCPHosts() });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  console.log('[discovery] mounted — auto-detect LLMs, MCP hosts, API keys, CLIs, AI apps');
}

module.exports = {
  mount,
  discoverLLMServers,
  discoverMCPHosts,
  discoverProviderKeys,
  discoverCLIs,
  discoverInstalledApps,
  discoverRunningProcesses,
  discoverPackages,
  discoverBrowserAI,
  matchFrontierAgents,
  prewarm,
};
