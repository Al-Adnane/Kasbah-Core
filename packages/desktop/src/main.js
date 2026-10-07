'use strict';

/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║          KASBAH GUARD DESKTOP — ELECTRON MAIN PROCESS v4.0               ║
 * ║  Core orchestrator — VPN/Vault/Features delegated to sub-modules          ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 */

const { app, BrowserWindow, Tray, Menu, ipcMain, clipboard,
        Notification, nativeImage, dialog, shell, WebContentsView,
        session: electronSession } = require('electron');
const path   = require('path');
const http   = require('http');
const os     = require('os');
const fs     = require('fs');
const crypto = require('crypto');

const trackerBlocklist = require('./tracker-blocklist.js');
const browserStore     = require('./browser-store.js');

// ── Outclass Brave/DDG/Opera: query-strip + bounce-block ───────────────────
// Strip tracking query params (utm_*, gclid, fbclid, msclkid, ttclid, etc.)
// and skip known bounce trackers by redirecting to the real destination.
const TRACK_PARAMS = new Set(['gclid','fbclid','msclkid','ttclid','yclid','wickedid','utm_source','utm_medium','utm_campaign','utm_term','utm_content','utm_id','mc_cid','mc_eid','igshid','vero_id','mkt_tok','pk_campaign','pk_kwd','piwik_campaign','matomo_campaign']);
const BOUNCE_HOSTS = new Set(['clickserve.dartsearch.net','googleadservices.com','click.google-analytics.com','track.clicksor.com','anrdoezrs.net','dpbolvw.net','kqdnf.com','emjcd.com']);
function cleanTrackingUrl(raw) {
  try {
    const u = new URL(raw);
    let changed = false;
    for (const k of [...u.searchParams.keys()]) {
      if (TRACK_PARAMS.has(k) || k.startsWith('utm_')) { u.searchParams.delete(k); changed = true; }
    }
    // Bounce: ?url= or ?u= or ?redirect= holds the real destination
    if (BOUNCE_HOSTS.has(u.hostname.toLowerCase())) {
      const dest = u.searchParams.get('url') || u.searchParams.get('u') || u.searchParams.get('redirect') || u.searchParams.get('dest');
      if (dest && /^https?:\/\//i.test(dest)) return { redirect: dest };
    }
    if (changed) return { redirect: u.toString() };
  } catch (_) {}
  return null;
}
const privacy          = require('./privacy-engine.js');
const pro              = require('./pro-license.js');
const netIntel         = require('./net-intel.js');
const resilience       = require('./vpn-resilience.js');
const pop              = require('./proof-protection.js');
const agentGuard       = require('./agent-guard.js');
const protectionScore  = require('./protection-score.js');
// Seatbelt product layer (shared with api-server) — maps engine verdicts to
// Silent Pass / Warning Toast / Hard Block without re-deriving risk.
let intervention = null;
try { intervention = require('../../api-server/src/intervention.js'); } catch (_) {}
let aiTrustGrade = null;
try { aiTrustGrade = require('../../api-server/src/ai-trust-grade.js'); } catch (_) {}
const shamir           = require('./shamir-vault.js');
const mmr              = require('./mmr-backup.js');
const deadman          = require('./deadman.js');
const log              = require('./logger.js');
const V                = require('./ipc-validate.js');
const dohResolver      = require('./doh-resolver.js');
const honey            = require('./honeytokens.js');
const { ForwardSecureAudit } = require('./fs-audit.js');
const merkleBatch      = require('./merkle-batch.js');
const { VulnScanner }  = require('./vuln-scanner.js');
const llmProxy         = require('./llm-proxy.js');

const egressClassifier         = require('./egress-classifier.js');
const agentRegistry            = require('./agent-registry.js');
const sitrep                   = require('./sitrep.js');
const exitMarket               = require('./exit-market.js');
const claimLedger              = require('./claim-ledger.js');
const impact                   = require('./impact.js');
const harden                   = require('./harden.js');
const commitProof              = require('./commit-proof.js');
const registerOutlierHandlers  = require('./main-outlier.js');

const registerVpnHandlers      = require('./main-vpn.js');
const registerVaultHandlers    = require('./main-vault.js');
const registerFeatureHandlers  = require('./main-features.js');

// ─── Former orphans — now wired (safe lazy load, logged) ───────────────────
// camera-sentinel, transparency-log, agent-trace, agent-cost, nomos-local,
// self-audit, dkg, dkg-transport, vss-feldman, did-key, pq-seal, wgas:
// previously 0-require modules. Loaded here so every shipped module has a
// live path; failures log instead of crashing boot.
const orphans = {};
for (const name of ['camera-sentinel', 'transparency-log', 'agent-trace', 'agent-cost', 'nomos-local', 'self-audit', 'dkg', 'dkg-transport', 'vss-feldman', 'did-key', 'pq-seal', 'wgas']) {
  try { orphans[name] = require('./' + name + '.js'); }
  catch (e) { orphans[name] = { error: e.message }; }
}

// ─── Lazy-loaded singletons ──────────────────────────────────────────────────

let _zkProtect = null;
function zkProtect() {
  if (!_zkProtect) {
    try { _zkProtect = new (require('./zk-protect.js').ZKProofSystem)(); }
    catch (e) { _zkProtect = { error: e.message }; }
  }
  return _zkProtect;
}

let _vuln = null;
function vuln() {
  if (!_vuln) { try { _vuln = new VulnScanner(); } catch (e) { _vuln = { error: e.message }; } }
  return _vuln;
}

const _fsAudit = new ForwardSecureAudit();

// ─── Constants ───────────────────────────────────────────────────────────────

const IS_DEV   = process.env.NODE_ENV === 'development';
const API_PORT = 8788;
const API_BASE = `http://127.0.0.1:${API_PORT}`;

// Register IPC handlers at module scope so they're ready when preload runs
ipcMain.on('renderer-log', (_e, { level, args }) => {
  const prefix = level === 'error' ? '🔴' : level === 'warn' ? '🟡' : '🟢';
  log.info('renderer', prefix, ...args);
});
ipcMain.on('preload-test', (_e, msg) => {
  log.info('preload', msg);
});
ipcMain.on('preload-error', (_e, msg) => {
  log.error('preload-error', msg);
});

function resolvePackageDir(name, markerFile) {
  const candidates = [
    // Dev source tree — checked first so a local checkout always wins over the bundle
    path.join(os.homedir(), 'Desktop', 'KasbahFinal', 'packages', name),
    path.join(process.resourcesPath || '', 'packages', name),
    path.join(__dirname, '../../packages', name),
    path.join(__dirname, '../../', name),
    path.join(__dirname, '../../../packages', name),
    path.join(app.getAppPath ? app.getAppPath() : __dirname, '../packages', name),
  ];
  for (const dir of candidates) {
    try { if (dir && fs.existsSync(path.join(dir, markerFile))) return dir; } catch (_) {}
  }
  return candidates[0];
}

const RESOURCES      = resolvePackageDir('api-server', 'server.js');
const VPN_RESOURCES  = resolvePackageDir('kasbah-vpn', path.join('src', 'keys.js'));
const CONTROL_RESOURCES = resolvePackageDir('control', path.join('src', 'index.js'));
log.info('desktop', 'VPN_RESOURCES', { path: VPN_RESOURCES });
if (!fs.existsSync(path.join(VPN_RESOURCES, 'src', 'keys.js'))) {
  log.error('desktop', `FATAL: kasbah-vpn not found. Looked near ${__dirname}`);
}

// ─── Path utilities ───────────────────────────────────────────────────────────

function safePathInside(root, name, { ext } = {}) {
  const base = path.resolve(root);
  const p = path.resolve(base, String(name || ''));
  if (p !== base && !p.startsWith(base + path.sep)) throw new Error('path escapes allowed directory');
  if (ext && !p.endsWith(ext)) throw new Error('unexpected file extension');
  return p;
}

function safeExistingFile(filePath) {
  const p = path.resolve(String(filePath || ''));
  if (!p || p.length < 4) throw new Error('invalid path');
  if (!fs.existsSync(p) || !fs.statSync(p).isFile()) throw new Error('file not found');
  return p;
}

// ─── Settings (shared by VPN + Vault modules) ────────────────────────────────

const SETTINGS_PATH = path.join(os.homedir(), '.kasbah-settings.json');
function loadSettings() {
  try { return JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8')); }
  catch { return { autoConnect: false, killSwitch: true, clipWatch: false }; }
}
function saveSettings(patch) {
  const s = { ...loadSettings(), ...patch };
  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(s, null, 2), { mode: 0o600 });
  return s;
}

// ─── App State ───────────────────────────────────────────────────────────────

const State = {
  isProtected: true,
  apiReady:    false,
  server:      null,
  stats: { totalScans: 0, threatsBlocked: 0, allowed: 0, warned: 0, startTime: Date.now() },
  recentActivity: [],
  apiKey: process.env.KASBAH_API_KEY || 'kg_desktop_builtin',
};

// Shared VPN state — mutated by main-vpn.js, read by features + lifecycle.
const vpnState = {
  activeLocation:    null,
  watchdogTimer:     null,
  watchdogFailStreak: 0,
  aiLaneHandle:      null,
  aiLaneEvents:      [],
};

let mainWindow = null;
let tray       = null;
let clipboardInterval = null;
let lastClip   = '';

// ─── Embedded API Server ─────────────────────────────────────────────────────

function startApiServer() {
  return new Promise(async (resolve) => {
    try {
      // Reuse a full API already listening (dev / multi-window / manual start).
      try {
        const existing = await fetch(`http://127.0.0.1:${API_PORT}/v1/health`, { signal: AbortSignal.timeout(800) });
        if (existing.ok) {
          const body = await existing.json().catch(() => ({}));
          log.info('desktop', `reusing api-server already on :${API_PORT} (status=${body.status || 'ok'})`);
          State.apiReady = true;
          return resolve();
        }
      } catch (_) { /* not up yet — spawn */ }

      process.env.PORT           = String(API_PORT);
      process.env.KASBAH_API_KEY = State.apiKey;
      process.env.KASBAH_EMBED   = '1';
      process.env.NODE_ENV       = process.env.NODE_ENV || 'development';
      const serverScript = path.join(RESOURCES, 'server.js');
      if (!fs.existsSync(serverScript)) {
        log.warn('desktop', 'api-server/server.js missing — VPN still works offline');
        return resolve();
      }
      const { spawn } = require('child_process');
      const serverDir = path.dirname(serverScript);
      const serverNodeModules = path.join(serverDir, 'node_modules');
      const existingNodePath = process.env.NODE_PATH || '';
      const nodePath = [serverNodeModules, existingNodePath].filter(Boolean).join(path.delimiter);
      const child = spawn(process.execPath, [serverScript], {
        cwd: serverDir,
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', NODE_PATH: nodePath },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      State.server = child;
      let settled = false, hasOutput = false;
      const settle = (ready) => { if (settled) return; settled = true; State.apiReady = ready; resolve(); };
      child.stdout.on('data', (d) => {
        hasOutput = true; const s = String(d); log.info('api-server', s.trim());
        // Match both "listening on port 8788" and "listening on http://127.0.0.1:8788"
        if (/listening on/i.test(s)) settle(true);
      });
      child.stderr.on('data', (d) => { hasOutput = true; const s = String(d).trim(); if (/EADDRINUSE/.test(s)) settle(true); else if (s) log.warn('api-server', s.split('\n')[0]); });
      child.on('error', (e) => { log.error('desktop', `Failed to spawn API server: ${e.message}`); settle(false); });
      child.on('exit', (code) => { if (!settled) { log.warn('desktop', `API server exited (code ${code})`); settle(false); } });
      // Poll health rather than trusting a single log line — api-server prints
      // "listening on http://…", not "listening on port …".
      const deadline = Date.now() + 20000;
      const poll = async () => {
        if (settled) return;
        try {
          const r = await fetch(`http://127.0.0.1:${API_PORT}/v1/health`, { signal: AbortSignal.timeout(800) });
          if (r.ok) { settle(true); return; }
        } catch (_) {}
        if (Date.now() < deadline) setTimeout(poll, 400);
        else settle(hasOutput);
      };
      setTimeout(poll, 300);
    } catch (e) {
      log.error('desktop', `Failed to start API server: ${e.message}`);
      resolve();
    }
  });
}

/** Fallback HTTP gateway for the browser extension if api-server is absent. */
async function startExtensionGateway() {
  // Prefer the FULL api-server (seatbelt, receipts, trust-grade). Only fall back
  // to the tiny ext-gateway when health is still down after a real wait.
  const probeOnce = async () => {
    try {
      const r = await fetch(`http://127.0.0.1:${API_PORT}/v1/health`, { signal: AbortSignal.timeout(1000) });
      return r.ok;
    } catch (_) { return false; }
  };
  let probe = await probeOnce();
  for (let i = 0; i < 15 && !probe; i++) {
    await new Promise((r) => setTimeout(r, 500));
    probe = await probeOnce();
  }
  if (probe) {
    log.info('desktop', `api-server ready on :${API_PORT} — extension uses full API`);
    State.extGateway = { listening: true, port: API_PORT, via: 'api-server' };
    State.apiReady = true;
    return;
  }
  try {
    const gw = require('./ext-gateway.js');
    const r = await gw.start(API_PORT);
    State.extGateway = { ...r, via: r.ok ? 'ext-gateway' : null };
    log.info('desktop', r.ok
      ? `extension gateway (fallback) on :${r.port} — full api-server not detected`
      : `extension gateway failed: ${r.error}`);
  } catch (e) {
    log.warn('desktop', `extension gateway: ${e.message}`);
  }
}

// ─── Circuit Breaker ─────────────────────────────────────────────────────────

const _cb = { failures: 0, openUntil: 0, THRESHOLD: 5, RESET_MS: 30000 };
function _cbIsOpen() {
  if (_cb.openUntil && Date.now() < _cb.openUntil) return true;
  if (_cb.openUntil) _cb.openUntil = 0;
  return false;
}
function _cbSuccess() { _cb.failures = 0; _cb.openUntil = 0; }
function _cbFail() {
  if (++_cb.failures >= _cb.THRESHOLD) {
    _cb.openUntil = Date.now() + _cb.RESET_MS;
    log.warn('circuit-breaker', `API circuit open for ${_cb.RESET_MS / 1000}s after ${_cb.failures} failures`);
  }
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

const _rl = { window: 60000, max: 300, calls: [], SCAN_MAX: 10, scanCalls: [] };
function _rlAllow(isScan = false) {
  const now = Date.now();
  _rl.calls = _rl.calls.filter((t) => now - t < _rl.window);
  if (_rl.calls.length >= _rl.max) return false;
  if (isScan) {
    _rl.scanCalls = _rl.scanCalls.filter((t) => now - t < 10000);
    if (_rl.scanCalls.length >= _rl.SCAN_MAX) return false;
    _rl.scanCalls.push(now);
  }
  _rl.calls.push(now);
  return true;
}

// ─── API Helper ──────────────────────────────────────────────────────────────

function apiCall(method, apiPath, body, { timeout = 15000 } = {}) {
  if (_cbIsOpen()) return Promise.reject(new Error('circuit open — API temporarily unavailable'));
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: '127.0.0.1', port: API_PORT, path: apiPath, method,
      headers: { 'Content-Type': 'application/json', 'x-api-key': State.apiKey, ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) },
    };
    const req = http.request(opts, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => { _cbSuccess(); try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); } catch { resolve({ status: res.statusCode, body: raw }); } });
    });
    req.setTimeout(timeout, () => req.destroy(new Error('request timeout')));
    req.on('error', (e) => { _cbFail(); reject(e); });
    if (data) req.write(data);
    req.end();
  });
}

// ─── BrowserWindow ───────────────────────────────────────────────────────────

// ── Per-site shields-down (Brave-style): hosts with shields down skip
// tracker/bounce filtering. Module scope — used by session filters
// (createWindow) and the settings IPC handler below.
const _bvHost = new Map(); // viewId/webContentsId → tab hostname
let _shieldExcept = new Set();
function _refreshShieldExcept() {
  try {
    const st = browserStore.settingsGet();
    _shieldExcept = new Set((st.shieldExceptions || []).map(h => String(h).toLowerCase()));
  } catch (_) {}
}
_refreshShieldExcept();
function _shieldsDownFor(webContentsId) {
  const host = _bvHost.get(Number(webContentsId));
  return !!(host && _shieldExcept.has(host.toLowerCase()));
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400, height: 900, minWidth: 1100, minHeight: 700,
    // Matches the light theme (--bg #F7F7F6) so launch never flashes dark;
    // dark mode stays opt-in via the theme-dark class (see index.html).
    backgroundColor: '#F7F7F6', titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 16, y: 18 },
    // vibrancy + backgroundThrottling off made the shell feel sluggish on
    // older Macs; keep the solid background instead.
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      webviewTag: true,
      spellcheck: false,
      backgroundThrottling: false,
    },
    show: true,
  });

  // CSP: UI lives in app.js (not inline) so script-src 'self' is sufficient.
  // Register BEFORE loadFile so the first paint already has the policy.
  try {
    mainWindow.webContents.session.webRequest.onHeadersReceived({ urls: ['file://*/*'] }, (details, callback) => {
      callback({
        responseHeaders: {
          ...details.responseHeaders,
          'Content-Security-Policy': [
            `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: http://127.0.0.1:8788; connect-src 'self' http://127.0.0.1:* ws://127.0.0.1:*; worker-src blob:; frame-src 'none'; object-src 'none';`,
          ],
        },
      });
    });
  } catch (e) {
    log.error('security', `CSP onHeadersReceived failed: ${e.message}`);
  }

  // Theme: respect the OS dark-mode setting (the CSS ships an opt-in
  // theme-dark palette; wiring it to nativeTheme makes the app feel native
  // instead of blinding users with white at night). Default stays light.
  try {
    const { nativeTheme } = require('electron');
    const applyTheme = () => {
      try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.executeJavaScript(
        `document.documentElement.classList.toggle('theme-dark', ${nativeTheme.shouldUseDarkColors ? 'true' : 'false'}); 1`).catch(()=>{}); } catch (_) {}
    };
    applyTheme();
    nativeTheme.on('updated', applyTheme);
  } catch (_) {}

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  if (IS_DEV) mainWindow.webContents.openDevTools({ mode: 'detach' });

  // Prevent navigation away from the file:// origin.
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) { event.preventDefault(); log.warn('security', 'Blocked navigation to external URL', { url }); }
  });

  // Webview hardening: force our preload, deny all permissions, block trackers.
  // PERFORMANCE: one shared session + one webRequest handler (not one per tab).
  const BROWSER_PARTITION = 'persist:private';
  let browserSession = null;
  let browserSessionWired = false;

  mainWindow.webContents.on('will-attach-webview', (_event, webPreferences, params) => {
    webPreferences.preload = path.join(__dirname, 'webview-preload.js');
    webPreferences.contextIsolation = true;
    webPreferences.nodeIntegration = false;
    // Sandboxed: this is where arbitrary third-party websites render (the
    // "private browser" feature) — the OS-level sandbox is the last line of
    // containment against a Chromium renderer exploit for exactly that case.
    // webview-preload.js only uses ipcRenderer/contextBridge and Web APIs,
    // both available under sandbox:true.
    webPreferences.sandbox = true;
    // Share one partition so cookies/cache are one store (faster + coherent).
    if (params) {
      params.partition = BROWSER_PARTITION;
      params.allowpopups = 'true';
      // Slightly better scroll/paint; page can still throttle itself.
      params.backgroundThrottling = 'false';
    }
    webPreferences.additionalArguments = [
      `--kasbah-fp-protection=${browserStore.settingsGet().fingerprintProtection ? '1' : '0'}`,
    ];
  });

  // ── WebContentsView-based private browser (replaces <webview>) ─────────────
  // <webview> has unfixable guest-viewport-sizing bugs in Electron v28+.
  // WebContentsView is positioned by main so the size is always correct.
  // bv:* handlers register ONCE (module-scope guard): createWindow() runs
  // again on every app 'activate', and a second registration crashed the
  // main process with a visible error dialog (the blank-shell bug).
  if (!globalThis.__kasbahBvWired) {
    globalThis.__kasbahBvWired = true;
  }
  const _bvMap = globalThis.__kasbahBvMap || (globalThis.__kasbahBvMap = new Map()); // viewId → WebContentsView

  function _bvWireSession(ses) {
    if (ses._kasbahWired) return;
    ses._kasbahWired = true;
    if (!browserSession) browserSession = ses;
    ses.setPermissionRequestHandler((_wc, _permission, cb) => cb(false));
    if (!browserSessionWired) {
      browserSessionWired = true;
      let _trkOn2 = true, _disabledCats2 = [];
      const _refresh2 = () => {
        try { const s = browserStore.settingsGet(); _trkOn2 = !!s.trackerBlocking; _disabledCats2 = s.disabledTrackerCategories || []; } catch(_) {}
      };
      _refresh2();
      let _buf2 = [], _timer2 = null;
      const _flush2 = () => {
        const b = _buf2; _buf2 = []; _timer2 = null;
        if (!b.length || !mainWindow || mainWindow.isDestroyed()) return;
        const seen = new Map();
        for (const x of b) { const k = x.webContentsId+'|'+x.hostname+'|'+x.category; seen.set(k,(seen.get(k)||0)+1); }
        for (const [k] of seen) {
          const [wid,host,cat] = k.split('|');
          try { mainWindow.webContents.send('tracker-blocked', { webContentsId: Number(wid), hostname: host, category: cat }); } catch(_) {}
        }
      };
      ses.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, (details, cb) => {
        // Query-strip + bounce-block runs even when tracker toggle is off
        try {
          let s = null; try { s = browserStore.settingsGet(); } catch (_) {}
          if (s && s.queryStrip !== false && details.resourceType === 'mainFrame') {
            const cleaned = cleanTrackingUrl(details.url);
            if (cleaned && cleaned.redirect && cleaned.redirect !== details.url) return cb({ redirectURL: cleaned.redirect });
          }
          if (s && s.bounceBlock !== false && details.resourceType !== 'mainFrame') {
            try { if (BOUNCE_HOSTS.has(new URL(details.url).hostname.toLowerCase())) return cb({ cancel: true }); } catch (_) {}
          }
        } catch (_) {}
        if (_shieldsDownFor(details.webContentsId)) return cb({});
        if (!_trkOn2) return cb({});
        if (details.resourceType === 'mainFrame') return cb({});
        try {
          const url = new URL(details.url);
          const host = url.hostname.toLowerCase();
          const entry = trackerBlocklist.BLOCKLIST.find(e => (host === e.domain || host.endsWith('.'+e.domain)) && !_disabledCats2.includes(e.category));
          if (entry) {
            _buf2.push({ webContentsId: details.webContentsId, hostname: host, category: entry.category });
            if (!_timer2) _timer2 = setTimeout(_flush2, 250);
            return cb({ cancel: true });
          }
        } catch(_) {}
        cb({});
      });
    }
  }

  if (!globalThis.__kasbahBvHandlers) {
    globalThis.__kasbahBvHandlers = true;
  ipcMain.handle('bv:create', () => {
    const view = new WebContentsView({
      webPreferences: {
        preload: path.join(__dirname, 'webview-preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        javascript: true,
        webSecurity: false,
        partition: BROWSER_PARTITION,
        backgroundThrottling: false,
        additionalArguments: [
          `--kasbah-fp-protection=${browserStore.settingsGet().fingerprintProtection ? '1' : '0'}`,
        ],
      }
    });
    mainWindow.contentView.addChildView(view);
    view.setBounds({ x: -10000, y: -10000, width: 1, height: 1 }); // start hidden
    const id = view.webContents.id;
    _bvMap.set(id, view);
    _bvWireSession(view.webContents.session);
    view.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    const send = (type, extra) => {
      try { if (!mainWindow.isDestroyed()) mainWindow.webContents.send('bv:event', { id, type, ...extra }); } catch(_) {}
    };
    view.webContents.on('did-start-loading',    ()         => send('did-start-loading', {}));
    view.webContents.on('did-stop-loading',     ()         => send('did-stop-loading',  { url: view.webContents.getURL() }));
    view.webContents.on('did-fail-load',        (_e,ec,_d,u) => send('did-fail-load',   { errorCode: ec, url: u }));
    view.webContents.on('page-title-updated',   (_e,title) => send('page-title-updated',{ title }));
    view.webContents.on('will-navigate',        (_e,url)   => send('will-navigate',     { url }));
    view.webContents.on('did-navigate',         (_e,url)   => send('did-navigate',      { url }));
    view.webContents.on('did-navigate-in-page', (_e,url)   => send('did-navigate-in-page', { url }));
    // Paste gate: forward guest paste-scan requests to the app renderer
    view.webContents.on('ipc-message', (_e, channel, ...args) => {
      if (channel === 'kasbah:paste-scan') {
        try { if (!mainWindow.isDestroyed()) mainWindow.webContents.send('bwr:paste-scan', args[0] || {}); } catch (_) {}
      }
    });
    return id;
  });

  ipcMain.handle('bv:destroy', (_e, id) => {
    const v = _bvMap.get(id);
    if (!v) return;
    try { mainWindow.contentView.removeChildView(v); } catch(_) {}
    try { v.webContents.close(); } catch(_) {}
    _bvMap.delete(id);
  });

  ipcMain.handle('bv:navigate',     (_e, { id, url }) => {
    try { _bvHost.set(Number(id), new URL(String(url)).hostname.toLowerCase()); } catch (_) {}
    _refreshShieldExcept();
    _bvMap.get(id)?.webContents.loadURL(url).catch(()=>{});
  });
  ipcMain.handle('bv:set-bounds',   (_e, { id, x, y, w, h }) => { const v = _bvMap.get(id); if (v) v.setBounds({ x: Math.round(x), y: Math.round(y), width: Math.round(w), height: Math.round(h) }); });
  ipcMain.handle('bv:go-back',      (_e, id) => { const wc = _bvMap.get(id)?.webContents; if (wc?.canGoBack()) wc.goBack(); });
  ipcMain.handle('bv:go-forward',   (_e, id) => { const wc = _bvMap.get(id)?.webContents; if (wc?.canGoForward()) wc.goForward(); });
  ipcMain.handle('bv:reload',       (_e, id) => { _bvMap.get(id)?.webContents.reload(); });
  ipcMain.handle('bv:can-go-back',  (_e, id) => _bvMap.get(id)?.webContents.canGoBack()    ?? false);
  ipcMain.handle('bv:can-go-forward',(_e,id) => _bvMap.get(id)?.webContents.canGoForward() ?? false);
  ipcMain.handle('bv:exec-js',      (_e, { id, code }) => _bvMap.get(id)?.webContents.executeJavaScript(code) ?? Promise.resolve(null));
  ipcMain.handle('bv:hide',         (_e, id) => { const v = _bvMap.get(id); if (v) v.setBounds({ x: -10000, y: -10000, width: 1, height: 1 }); });
  } // ── end once-only bv:* registration ────────────────────────────────────
  // ── end WebContentsView ──────────────────────────────────────────────────

  mainWindow.webContents.on('did-attach-webview', (_event, webContents) => {
    webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    const ses = webContents.session;
    if (!browserSession) browserSession = ses;
    ses.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
    // Install the request filter only once per session.
    if (!browserSessionWired) {
      browserSessionWired = true;
      // Cache settings so onBeforeRequest never hits disk (was ~ms per request).
      let _trkOn = true;
      let _disabledCats = [];
      const _refreshTrk = () => {
        try {
          const s = browserStore.settingsGet();
          _trkOn = !!s.trackerBlocking;
          _disabledCats = Array.isArray(s.disabledTrackerCategories) ? s.disabledTrackerCategories : [];
        } catch (_) {}
      };
      _refreshTrk();
      // IPC throttle: batch block events so the UI doesn't flood.
      let _blockBuf = [];
      let _blockTimer = null;
      const _flushBlocks = () => {
        const buf = _blockBuf;
        _blockBuf = [];
        _blockTimer = null;
        if (!buf.length || !mainWindow || mainWindow.isDestroyed()) return;
        // one IPC per host+category in the flush window
        const seen = new Map();
        for (const b of buf) {
          const k = b.webContentsId + '|' + b.hostname + '|' + b.category;
          seen.set(k, (seen.get(k) || 0) + 1);
        }
        for (const [k, n] of seen) {
          const [webContentsId, hostname, category] = k.split('|');
          mainWindow.webContents.send('bwr:blocked', { webContentsId: Number(webContentsId), hostname, category, count: n });
        }
      };
      ses.webRequest.onBeforeRequest((details, callback) => {
        try {
          let s = null; try { s = browserStore.settingsGet(); } catch (_) {}
          if (s && s.queryStrip !== false && details.resourceType === 'mainFrame') {
            const cleaned = cleanTrackingUrl(details.url);
            if (cleaned && cleaned.redirect && cleaned.redirect !== details.url) return callback({ redirectURL: cleaned.redirect });
          }
          if (s && s.bounceBlock !== false && details.resourceType !== 'mainFrame') {
            try { if (BOUNCE_HOSTS.has(new URL(details.url).hostname.toLowerCase())) return callback({ cancel: true }); } catch (_) {}
          }
          if (_shieldsDownFor(webContents.id)) return callback({ cancel: false });
          if (!_trkOn) return callback({ cancel: false });
          let hostname;
          try { hostname = new URL(details.url).hostname; } catch (_) { return callback({ cancel: false }); }
          if (!hostname) return callback({ cancel: false });
          if (details.resourceType === 'mainFrame') return callback({ cancel: false });
          const category = trackerBlocklist.categoryForWithToggles(hostname, _disabledCats);
          if (category) {
            _blockBuf.push({ webContentsId: webContents.id, hostname, category });
            if (!_blockTimer) _blockTimer = setTimeout(_flushBlocks, 250);
            return callback({ cancel: true });
          }
        } catch (_) {}
        callback({ cancel: false });
      });
      // refresh cache when settings change
      ipcMain.on('browser:settings-changed', () => _refreshTrk());
      ses.on('will-download', (_event, item) => {
        const id = `dl_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
        const record = { id, url: item.getURL(), filename: item.getFilename(), totalBytes: item.getTotalBytes(), receivedBytes: 0, state: 'progressing', startedAt: new Date().toISOString(), savePath: null };
        item.on('updated', (_e, state) => { record.receivedBytes = item.getReceivedBytes(); record.state = state; browserStore.downloadsUpdate(record); mainWindow?.webContents.send('bwr:download-progress', record); });
        item.once('done', (_e, state) => { record.state = state; record.savePath = item.getSavePath(); browserStore.downloadsUpdate(record); mainWindow?.webContents.send('bwr:download-done', record); });
        browserStore.downloadsUpdate(record);
        mainWindow?.webContents.send('bwr:download-start', record);
      });
    }
  });

  // Show as soon as the renderer paints; also force-show after 3s so a
  // CSP/renderer hiccup cannot leave the app looking frozen with no window.
  mainWindow.center();
  mainWindow.once('ready-to-show', () => {
    log.info('desktop', 'ready-to-show fired');
    try {
      const loaded = Object.entries(orphans).map(([k, v]) => `${k}:${v && !v.error ? 'live' : 'stub'}`).join(' ');
      log.info('desktop', `orphan-modules wired — ${loaded}`);
    } catch (_) {}
    mainWindow?.focus();
  });
  mainWindow.webContents.on('did-fail-load', (_e, code, desc, url) => {
    log.error('desktop', `did-fail-load ${code} ${desc} ${url}`);
  });
  mainWindow.webContents.on('console-message', (...args) => {
    // Debug: log raw args to see the actual signature
    log.warn('renderer-console', `args=${JSON.stringify(args).slice(0, 800)}`);
  });
  mainWindow.on('closed', () => { mainWindow = null; });
}

// ─── System Tray ─────────────────────────────────────────────────────────────

function buildTrayMenu() {
  return Menu.buildFromTemplate([
    { label: 'Kasbah Guard', enabled: false },
    { type: 'separator' },
    { label: State.isProtected ? '✅  Protection: ON' : '🔴  Protection: OFF', click: toggleProtection },
    { label: `Scans: ${State.stats.totalScans} | Blocked: ${State.stats.threatsBlocked}`, enabled: false },
    { type: 'separator' },
    { label: 'Open Dashboard', click: () => mainWindow?.show() || createWindow() },
    { label: 'Scan Clipboard Now', click: () => scanClipboardNow() },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.isQuitting = true; app.quit(); } },
  ]);
}

function createTray() {
  const iconPath = path.join(__dirname, '..', 'resources', 'trayTemplate.png');
  const img = nativeImage.createFromPath(iconPath);
  tray = new Tray(img.isEmpty() ? nativeImage.createEmpty() : img);
  tray.setToolTip('Kasbah Guard — AI Governance');
  tray.setContextMenu(buildTrayMenu());
  tray.on('double-click', () => mainWindow?.show() || createWindow());

  // Subscribe protection score — update tray tooltip and push to renderer.
  protectionScore.subscribe((result) => {
    tray?.setToolTip(`Kasbah Guard — ${result.tier.toUpperCase()} (${result.score}/100)`);
    mainWindow?.webContents.send('protection:score', result);
  });
}

function refreshTray() { tray?.setContextMenu(buildTrayMenu()); }

// ─── Protection Toggle ────────────────────────────────────────────────────────

function toggleProtection() {
  State.isProtected = !State.isProtected;
  if (State.isProtected) startClipboardWatcher(); else stopClipboardWatcher();
  syncRecordingGuard();
  refreshTray();
  mainWindow?.webContents.send('state-change', { isProtected: State.isProtected });
  try { new Notification({ title: 'Kasbah Guard', body: State.isProtected ? '🛡️ Protection enabled — mic & camera guarded' : '⚠️ Protection disabled' }).show(); } catch (_) {}
}

// ─── Recording guard — protection ON means recording-proof ─────────────────
// Couples mic/camera enforcement to the master protection switch: when Kasbah
// is on, confirmed unapproved mic/camera captures are physically revoked
// (tcc-reset) unless the user chose another action. Approved apps untouched.
// Enforcement only ever fires on sentinel-CONFIRMED captures, never heuristics.
function syncRecordingGuard() {
  try {
    const enf = require('../../../src/kasbah-enforcer.js');
    if (State.isProtected) {
      try { if (enf.status && enf.status().action === 'alert-only') enf.setAction('tcc-reset'); } catch (_) {}
      enf.setEnforce(true);
      log.info('desktop', 'recording guard ON (enforce + revoke unapproved captures)');
    } else {
      enf.setEnforce(false);
      log.info('desktop', 'recording guard OFF with protection');
    }
  } catch (e) { log.warn('desktop', `recording guard sync failed: ${e.message}`); }
}

// ─── Clipboard Watcher ────────────────────────────────────────────────────────

function startClipboardWatcher() {
  stopClipboardWatcher();
  let active = true;
  function tick() {
    const jitterMs = 1200 + Math.random() * 600;
    clipboardInterval = setTimeout(async () => {
      if (!active) return;
      await new Promise((r) => setImmediate(r));
      const text = clipboard.readText();
      await new Promise((r) => setImmediate(r));
      if (text && text !== lastClip && text.length > 10) {
        lastClip = text;
        if (State.isProtected) {
          try {
            const htResult = honey.check(text);
            if (htResult.found) {
              _fsAudit.append({ event: 'clipboard_secret', source: 'clipboard', type: 'honeytoken', hits: htResult.hits });
              try { new Notification({ title: 'Kasbah Guard — Honeytoken', body: `Canary token detected on clipboard!`, urgency: 'critical' }).show(); } catch (_) {}
            }
          } catch (_) {}
          await handleScan(text, 'clipboard');
        }
      }
      if (active) tick(); // schedule next tick with fresh jitter
    }, jitterMs);
  }
  tick();
  clipboardInterval = { _stop: () => { active = false; } };
}

function stopClipboardWatcher() {
  if (clipboardInterval) {
    if (typeof clipboardInterval._stop === 'function') clipboardInterval._stop();
    else clearTimeout(clipboardInterval);
    clipboardInterval = null;
  }
}

async function scanClipboardNow() {
  const text = clipboard.readText();
  if (!text) return;
  return handleScan(text, 'clipboard-manual');
}

// ─── Core Scan Logic ─────────────────────────────────────────────────────────

async function handleScan(text, source) {
  if (!_rlAllow(true)) { log.warn('scan', `Rate limit hit — dropping scan from ${source}`); return { verdict: 'RATE_LIMITED', threats: [], score: 1 }; }
  State.stats.totalScans++;

  // Fast local egress check (4-tier cascade) — runs before the API call.
  const localCheck = egressClassifier.classify(text);
  let bioCheck = { found: false };
  try { bioCheck = require('./biometric-guard.js').scanText(text); } catch (_) {}
  if (localCheck.found || bioCheck.found) {
    State.stats.threatsBlocked++;
    try { impact.bump('secretsBlocked'); } catch (_) {}
    const labels = [
      ...(localCheck.findings || []).map((f) => f.label),
      ...(bioCheck.findings || []).map((f) => f.label),
    ].join(', ');
    try { new Notification({ title: '🛡️ Kasbah — Threat Detected', body: `Local detection: ${labels}`, urgency: 'critical' }).show(); } catch (_) {}
    try { _fsAudit.append({ event: 'egress_local', source, findings: [...(localCheck.findings||[]), ...(bioCheck.findings||[])].map((f) => ({ id: f.id, tier: f.tier || 'bio' })), tiers: localCheck.tiers }); } catch (_) {}
    try { mainWindow?.webContents.send('egress-threat', { source, findings: [...(localCheck.findings||[]), ...(bioCheck.findings||[])], tiers: localCheck.tiers, biometric: bioCheck.found }); } catch (_) {}
  }
  let result;
  try { const r = await apiCall('POST', '/v1/govern', { prompt: text }); result = r.body; }
  catch (e) { log.warn('scan', `API call failed: ${e.message}`); result = { verdict: 'ERROR', threats: [], score: 1 }; }
  const verdict = result?.verdict || 'ALLOW';
  const threats = result?.threats || [];
  const score   = result?.score != null ? result.score : 1;
  let seatbelt = null;
  try {
    if (intervention) {
      seatbelt = intervention.fromGovern({ ...result, verdict, threats, score }, {
        surface: source || 'desktop',
        clientKey: 'desktop',
      });
    }
  } catch (_) {}
  if (verdict === 'DENY' || verdict === 'WARN' || threats.length > 0) {
    State.stats.threatsBlocked++;
    try { new Notification({ title: '🛡️ Kasbah Guard — Threat Detected', body: `${threats.length} threat(s) | ${Math.round((1 - score) * 100)}% risk | ${source}`, urgency: 'critical' }).show(); }
    catch (notifErr) { log.warn('notification', `Failed to show threat notification: ${notifErr.message}`); }
  }
  const receiptId = result?.receipt || result?.requestId || result?.proof?.hash || '';
  const activity  = { id: Date.now(), ts: Date.now(), source, verdict, threats, text: text.slice(0, 120), score, receiptId, intervention: seatbelt?.intervention || null, seatbelt: seatbelt || null };
  State.recentActivity.unshift(activity);
  if (State.recentActivity.length > 200) State.recentActivity.length = 200;
  try { _fsAudit.append({ event: 'scan', source, verdict, threats: threats.length, score, receiptId: receiptId || undefined }); } catch (_) {}
  if (verdict === 'ALLOW') State.stats.allowed++;
  else if (verdict === 'WARN') State.stats.warned++;
  mainWindow?.webContents.send('activity-update', activity);
  refreshTray();
  return result;
}

// ─── Core IPC Handlers ───────────────────────────────────────────────────────

ipcMain.handle('get-state',         () => ({ ...State, server: undefined }));
ipcMain.handle('toggle-protection', () => { toggleProtection(); return State.isProtected; });
ipcMain.handle('scan-clipboard',    () => scanClipboardNow());

ipcMain.handle('browser:tracker-blocklist', () => trackerBlocklist.CATEGORIES);
ipcMain.handle('browser:history-list',      (_e, limit) => browserStore.historyList(limit));
ipcMain.handle('browser:history-search',    (_e, query) => browserStore.historySearch(query));
ipcMain.handle('browser:history-delete',    (_e, id)    => { browserStore.historyDelete(id); return { ok: true }; });
ipcMain.handle('browser:history-clear',     ()          => { browserStore.historyClear(); return { ok: true }; });
ipcMain.handle('browser:bookmark-list',     ()          => browserStore.bookmarkList());
ipcMain.handle('browser:bookmark-add',      (_e, entry) => browserStore.bookmarkAdd(entry));
ipcMain.handle('browser:bookmark-remove',   (_e, u)     => browserStore.bookmarkRemove(u));
ipcMain.handle('browser:bookmark-is-saved', (_e, url)   => browserStore.bookmarkIsSaved(url));
ipcMain.handle('browser:downloads-list',    ()          => browserStore.downloadsList());
ipcMain.handle('browser:downloads-clear',   ()          => { browserStore.downloadsClear(); return { ok: true }; });
ipcMain.handle('browser:download-open',   (_e, savePath) => {
  try {
    const p = path.resolve(String(savePath || ''));
    const dl = path.resolve(path.join(os.homedir(), 'Downloads'));
    if (!(p === dl || p.startsWith(dl + path.sep))) throw new Error('path outside Downloads');
    shell.openPath(p); return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});
ipcMain.handle('browser:download-reveal', (_e, savePath) => {
  try {
    const p = path.resolve(String(savePath || ''));
    const dl = path.resolve(path.join(os.homedir(), 'Downloads'));
    if (!(p === dl || p.startsWith(dl + path.sep))) throw new Error('path outside Downloads');
    shell.showItemInFolder(p); return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});
ipcMain.handle('browser:settings-get', () => browserStore.settingsGet());
ipcMain.handle('browser:settings-set', (_e, patch) => { const r = browserStore.settingsSet(patch); try { _refreshShieldExcept(); } catch (_) {} try { ipcMain.emit('browser:settings-changed'); } catch (_) {} return r; });

// IPC: renderer asks main to force-resize the webview guest viewport.
// Electron v28+ does not reliably propagate CSS size changes to the guest;
// this is the only reliable path.
ipcMain.handle('browser:resize-webview', (_ev, { webContentsId, width, height }) => {
  try {
    const wc = webContents.fromId(webContentsId);
    if (wc && !wc.isDestroyed()) {
      if (typeof wc.setSize === 'function') {
        wc.setSize({ normal: { width: Math.round(width), height: Math.round(height) } });
      }
    }
  } catch (_) {}
  return null;
});

// API Proxy
const ALLOWED_METHODS   = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);
const ALLOWED_ENDPOINTS = /^\/v[0-9]{1,2}\/[a-z0-9\/-]*(\?[a-z0-9=&-]*)?$/i;
const MAX_BODY_SIZE      = 1000000;

ipcMain.handle('api', async (_e, method, endpoint, body) => {
  // Allow health check through even before State.apiReady is set — the
  // renderer polls /v1/health to decide when to show the shell, and it
  // would wait the full 12-second timeout if we gate it here.
  if (!State.apiReady && endpoint !== '/v1/health') return { status: 503, body: { error: 'API not ready' } };
  if (!_rlAllow()) return { status: 429, body: { error: 'Rate limit exceeded' } };
  const m = String(method || '').toUpperCase();
  if (!ALLOWED_METHODS.has(m)) return { status: 400, body: { error: 'Invalid HTTP method' } };
  const ep = String(endpoint || '');
  if (!ALLOWED_ENDPOINTS.test(ep)) return { status: 400, body: { error: 'Invalid endpoint' } };
  if (body && JSON.stringify(body).length > MAX_BODY_SIZE) return { status: 413, body: { error: 'Payload too large' } };
  try { return await apiCall(m, ep, body); }
  catch (e) { log.error('api-proxy', e.message); return { status: 503, body: { error: 'API request failed' } }; }
});

ipcMain.handle('open-url', (_e, url) => {
  if (url.startsWith('https://') || url.startsWith('http://127.0.0.1')) shell.openExternal(url);
});

// ─── Register sub-module IPC handlers ────────────────────────────────────────

// ctx is passed by reference so sub-modules see live mainWindow / vpnState changes.
const ctx = {
  State, log, V, fs, path, os, crypto,
  shell, dialog, Notification, clipboard, app,
  safePathInside, safeExistingFile,
  vpnState,
  get mainWindow() { return mainWindow; },
  // VPN resources
  VPN_RESOURCES,
  // Settings (shared — VPN:connect reads loadSettings, Vault:settings:set uses both)
  loadSettings, saveSettings,
  // Feature modules
  privacy, pro, pop, agentGuard, shamir, mmr, deadman,
  honey, merkleBatch, zkProtect, vuln, llmProxy, dohResolver, netIntel, resilience,
  egressClassifier, agentRegistry,
  sitrep, exitMarket, claimLedger, impact, harden, commitProof,
  _fsAudit,
  _protectionScore: protectionScore,
  // Set by registerVpnHandlers:
  applyKillSwitch:   null,
  vpnLoadLocations:  null,
  vpnTeardownCmd:    null,
  runAsAdmin:        null,
};

try { registerVpnHandlers(ipcMain, ctx); log.info('desktop', 'vpn handlers ok'); } catch(e) { log.error('desktop', `registerVpnHandlers CRASH: ${e.message}\n${e.stack}`); }
try { registerVaultHandlers(ipcMain, ctx); log.info('desktop', 'vault handlers ok'); } catch(e) { log.error('desktop', `registerVaultHandlers CRASH: ${e.message}\n${e.stack}`); }
try { registerFeatureHandlers(ipcMain, ctx); log.info('desktop', 'feature handlers ok'); } catch(e) { log.error('desktop', `registerFeatureHandlers CRASH: ${e.message}\n${e.stack}`); }
try { registerOutlierHandlers(ipcMain, ctx); log.info('desktop', 'outlier handlers ok'); } catch(e) { log.error('desktop', `registerOutlierHandlers CRASH: ${e.message}\n${e.stack}`); }

// ─── App Lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  log.info('desktop', 'app.whenReady fired');
  try { await startApiServer(); log.info('desktop', `API server ready on :${API_PORT}`); }
  catch (e) { log.error('desktop', `API server failed to start: ${e.message}`); }
  try { await startExtensionGateway(); }
  catch (e) { log.warn('desktop', `extension gateway: ${e.message}`); }

  const PROXY_PORT = 8789;
  process.env.HTTPS_PROXY  = `http://127.0.0.1:${PROXY_PORT}`;
  process.env.HTTP_PROXY   = `http://127.0.0.1:${PROXY_PORT}`;
  process.env.KASBAH_PROXY = `http://127.0.0.1:${PROXY_PORT}`;
  log.info('desktop', `Proxy auto-configured: HTTPS_PROXY=http://127.0.0.1:${PROXY_PORT}`);

  createWindow();
  createTray();
  // Bring the window to front on launch regardless of what app has focus
  try { app.focus({ steal: true }); } catch (_) {}
  if (State.isProtected) startClipboardWatcher();
  syncRecordingGuard();

  // ── First-launch: seed 2 honeytokens if none exist ──────────────────────────
  try {
    if (honey.list().length === 0) {
      honey.deploy('email');
      honey.deploy('aws-key');
      log.info('desktop', 'Seeded 2 default honeytokens on first launch');
    }
  } catch (_) {}

  // ── Auto-connect VPN if settings.autoConnect is set ─────────────────────────
  const _settings = loadSettings();
  if (_settings.autoConnect && ctx.vpnLoadLocations) {
    setTimeout(async () => {
      try {
        const locs = ctx.vpnLoadLocations();
        const preferred = locs.find((l) => l.id === _settings.autoConnectLocation) || locs[0];
        if (preferred) {
          log.info('vpn', `Auto-connecting to ${preferred.name}`);
          ipcMain.emit('vpn:connect', null, { locationId: preferred.id });
        }
      } catch (e) { log.warn('vpn', `Auto-connect failed: ${e.message}`); }
    }, 3000); // wait for sub-modules to finish registering
  }

  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

app.on('before-quit', () => {
  stopClipboardWatcher();
  try { State.server?.close(); } catch (_) {}
  try { vpnState.aiLaneHandle?.server.close(); } catch (_) {}
  // Leave the tunnel up on quit by default — user can Disconnect from the UI.
  // Only tear down if settings.killSwitchTearDownOnQuit is explicitly true.
  try {
    const s = loadSettings ? loadSettings() : {};
    if (s.tearDownVpnOnQuit && vpnState.activeLocation && ctx.vpnLoadLocations && ctx.vpnTeardownCmd && ctx.runAsAdmin) {
      ctx.runAsAdmin(ctx.vpnTeardownCmd(ctx.vpnLoadLocations())).catch(() => {});
    }
  } catch (_) {}
});

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) { app.quit(); }
else { app.on('second-instance', () => { mainWindow?.show(); mainWindow?.focus(); }); }
