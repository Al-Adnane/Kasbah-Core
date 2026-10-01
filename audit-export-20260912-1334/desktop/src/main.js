'use strict';

/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║          KASBAH GUARD DESKTOP — ELECTRON MAIN PROCESS v4.0               ║
 * ║  Core orchestrator — VPN/Vault/Features delegated to sub-modules          ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 */

const { app, BrowserWindow, Tray, Menu, ipcMain, clipboard,
        Notification, nativeImage, dialog, shell } = require('electron');
const path   = require('path');
const http   = require('http');
const os     = require('os');
const fs     = require('fs');
const crypto = require('crypto');

const trackerBlocklist = require('./tracker-blocklist.js');
const browserStore     = require('./browser-store.js');
const privacy          = require('./privacy-engine.js');
const pro              = require('./pro-license.js');
const netIntel         = require('./net-intel.js');
const resilience       = require('./vpn-resilience.js');
const pop              = require('./proof-protection.js');
const agentGuard       = require('./agent-guard.js');
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

function resolvePackageDir(name, markerFile) {
  const candidates = [
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
  return new Promise((resolve) => {
    try {
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
      const child = spawn(process.execPath, [serverScript], {
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      State.server = child;
      let settled = false, hasOutput = false;
      const settle = (ready) => { if (settled) return; settled = true; State.apiReady = ready; resolve(); };
      child.stdout.on('data', (d) => { hasOutput = true; const s = String(d); log.info('api-server', s.trim()); if (/listening on port/i.test(s)) settle(true); });
      child.stderr.on('data', (d) => { hasOutput = true; const s = String(d).trim(); if (/EADDRINUSE/.test(s)) settle(true); else if (s) log.warn('api-server', s.split('\n')[0]); });
      child.on('error', (e) => { log.error('desktop', `Failed to spawn API server: ${e.message}`); settle(false); });
      child.on('exit', (code) => { if (!settled) { log.warn('desktop', `API server exited (code ${code})`); settle(false); } });
      setTimeout(() => settle(hasOutput && State.apiReady), 15000);
    } catch (e) {
      log.error('desktop', `Failed to start API server: ${e.message}`);
      resolve();
    }
  });
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

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400, height: 900, minWidth: 1100, minHeight: 700,
    backgroundColor: '#0a0a14', titleBarStyle: 'hiddenInset',
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
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  // script-src no longer needs 'unsafe-inline': every onclick/onchange/
  // oninput/onkeydown attribute in index.html was converted to a real JS
  // closure dispatched via delegation (see the _h()/_wireHc() registry near
  // the top of its <script>), so there is no inline-attribute JS left for
  // CSP to need to allow. The one remaining inline <script> tag is static
  // content, allowed via a hash of its exact bytes — computed here from the
  // live file rather than hardcoded, so it can never drift out of sync with
  // what's actually shipped. If that hash ever fails to match (e.g. a stray
  // second <script> tag, or this being computed against the wrong file),
  // scripts silently won't run — this logs a warning so that's loud, not
  // silent, during development.
  function scriptSrcHashes() {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
      const matches = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)];
      return matches.map((m) => `'sha256-${crypto.createHash('sha256').update(m[1], 'utf8').digest('base64')}'`);
    } catch (e) {
      log.error('security', `Failed to hash inline scripts for CSP: ${e.message}`);
      return [];
    }
  }
  const hashes = scriptSrcHashes();
  if (!hashes.length) log.error('security', 'No inline <script> hash computed — CSP script-src will block index.html\'s own script.');

  // Inject CSP for the main window (file:// protocol has no HTTP headers).
  mainWindow.webContents.session.webRequest.onHeadersReceived({ urls: ['file://*/*'] }, (details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          `default-src 'self'; script-src 'self' ${hashes.join(' ')}; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' http://127.0.0.1:8788 ws://127.0.0.1:*; worker-src blob:; frame-src 'none'; object-src 'none';`,
        ],
      },
    });
  });

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
          if (!_trkOn) return callback({ cancel: false });
          let hostname;
          try { hostname = new URL(details.url).hostname; } catch (_) { return callback({ cancel: false }); }
          if (!hostname) return callback({ cancel: false });
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

  mainWindow.once('ready-to-show', () => { mainWindow.show(); if (IS_DEV) mainWindow.webContents.openDevTools({ mode: 'detach' }); });
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
}

function refreshTray() { tray?.setContextMenu(buildTrayMenu()); }

// ─── Protection Toggle ────────────────────────────────────────────────────────

function toggleProtection() {
  State.isProtected = !State.isProtected;
  if (State.isProtected) startClipboardWatcher(); else stopClipboardWatcher();
  refreshTray();
  mainWindow?.webContents.send('state-change', { isProtected: State.isProtected });
  try { new Notification({ title: 'Kasbah Guard', body: State.isProtected ? '🛡️ Protection enabled' : '⚠️ Protection disabled' }).show(); } catch (_) {}
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
  if (verdict === 'DENY' || verdict === 'WARN' || threats.length > 0) {
    State.stats.threatsBlocked++;
    try { new Notification({ title: '🛡️ Kasbah Guard — Threat Detected', body: `${threats.length} threat(s) | ${Math.round((1 - score) * 100)}% risk | ${source}`, urgency: 'critical' }).show(); }
    catch (notifErr) { log.warn('notification', `Failed to show threat notification: ${notifErr.message}`); }
  }
  const receiptId = result?.receipt || result?.requestId || result?.proof?.hash || '';
  const activity  = { id: Date.now(), ts: Date.now(), source, verdict, threats, text: text.slice(0, 120), score, receiptId };
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
ipcMain.handle('browser:settings-set', (_e, patch) => browserStore.settingsSet(patch));

// API Proxy
const ALLOWED_METHODS   = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);
const ALLOWED_ENDPOINTS = /^\/v[0-9]{1,2}\/[a-z0-9\/-]*(\?[a-z0-9=&-]*)?$/i;
const MAX_BODY_SIZE      = 1000000;

ipcMain.handle('api', async (_e, method, endpoint, body) => {
  if (!State.apiReady) return { status: 503, body: { error: 'API not ready' } };
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
  // Set by registerVpnHandlers:
  applyKillSwitch:   null,
  vpnLoadLocations:  null,
  vpnTeardownCmd:    null,
  runAsAdmin:        null,
};

registerVpnHandlers(ipcMain, ctx);       // sets ctx.applyKillSwitch + vpnLoadLocations etc.
registerVaultHandlers(ipcMain, ctx);     // vault, backup, settings, wifi
registerFeatureHandlers(ipcMain, ctx);   // privacy, pro, pop, agent, shamir, …
registerOutlierHandlers(ipcMain, ctx);   // sitrep · exit market · claims · impact · harden

// ─── App Lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  try { await startApiServer(); log.info('desktop', `API server ready on :${API_PORT}`); }
  catch (e) { log.error('desktop', `API server failed to start: ${e.message}`); }

  const PROXY_PORT = 8789;
  process.env.HTTPS_PROXY  = `http://127.0.0.1:${PROXY_PORT}`;
  process.env.HTTP_PROXY   = `http://127.0.0.1:${PROXY_PORT}`;
  process.env.KASBAH_PROXY = `http://127.0.0.1:${PROXY_PORT}`;
  log.info('desktop', `Proxy auto-configured: HTTPS_PROXY=http://127.0.0.1:${PROXY_PORT}`);

  createWindow();
  createTray();
  if (State.isProtected) startClipboardWatcher();

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
