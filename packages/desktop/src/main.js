'use strict';

/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║          KASBAH GUARD DESKTOP — ELECTRON MAIN PROCESS v3.0               ║
 * ║  13 Frontier Intelligence Systems • Embedded API • Real-time Governance   ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 */

const { app, BrowserWindow, Tray, Menu, ipcMain, clipboard,
        Notification, nativeImage, dialog, shell } = require('electron');
const path   = require('path');
const http   = require('http');

// ─── Constants ───────────────────────────────────────────────────────────────

const IS_DEV  = process.env.NODE_ENV === 'development';
const API_PORT = 8788;
const API_BASE = `http://127.0.0.1:${API_PORT}`;
const RESOURCES = app.isPackaged
  ? path.join(process.resourcesPath, 'packages', 'api-server')
  : path.join(__dirname, '../../api-server');

// ─── App State ───────────────────────────────────────────────────────────────

const State = {
  isProtected: true,
  apiReady:    false,
  server:      null,     // ChildProcess
  stats: { totalScans: 0, threatsBlocked: 0, allowed: 0, warned: 0, startTime: Date.now() },
  recentActivity: [],
  apiKey: process.env.KASBAH_API_KEY || 'kg_desktop_builtin',
};

// ─── Windows & Tray ──────────────────────────────────────────────────────────

let mainWindow = null;
let tray       = null;
let clipboardInterval = null;
let lastClip   = '';

// ─── Embedded API Server (in-process) ────────────────────────────────────────

function startApiServer() {
  return new Promise((resolve, reject) => {
    try {
      // Set env vars before requiring so server.js picks them up
      process.env.PORT        = String(API_PORT);
      process.env.KASBAH_API_KEY = State.apiKey;
      process.env.KASBAH_EMBED   = '1';

      const serverScript = path.join(RESOURCES, 'server.js');
      const expressApp   = require(serverScript); // module.exports = app

      State.server = expressApp.listen(API_PORT, '127.0.0.1', () => {
        console.log(`[desktop] Kasbah API listening on :${API_PORT}`);
        State.apiReady = true;
        resolve();
      });

      State.server.on('error', (e) => {
        if (e.code === 'EADDRINUSE') {
          // Port already in use — another instance or external server, use it
          console.warn('[desktop] Port already in use, assuming external API server');
          State.apiReady = true;
          resolve();
        } else {
          reject(e);
        }
      });
    } catch (e) {
      console.error('[desktop] Failed to load API server:', e.message);
      // Non-fatal — app still launches, just shows API unavailable
      resolve();
    }
  });
}

// ─── API Helper ──────────────────────────────────────────────────────────────

function apiCall(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: '127.0.0.1', port: API_PORT,
      path, method,
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': State.apiKey,
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      },
    };
    const req = http.request(opts, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ─── Window ──────────────────────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400, height: 900,
    minWidth: 1100, minHeight: 700,
    backgroundColor: '#0a0a14',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 16, y: 18 },
    vibrancy: 'under-window',
    visualEffectState: 'active',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      spellcheck: false,
    },
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (IS_DEV) mainWindow.webContents.openDevTools({ mode: 'detach' });
  });

  mainWindow.on('closed', () => { mainWindow = null; });
}

// ─── System Tray ─────────────────────────────────────────────────────────────

function buildTrayMenu() {
  return Menu.buildFromTemplate([
    { label: 'Kasbah Guard', enabled: false },
    { type: 'separator' },
    {
      label: State.isProtected ? '✅  Protection: ON' : '🔴  Protection: OFF',
      click: toggleProtection,
    },
    { label: `Scans: ${State.stats.totalScans} | Blocked: ${State.stats.threatsBlocked}`, enabled: false },
    { type: 'separator' },
    { label: 'Open Dashboard', click: () => mainWindow?.show() || createWindow() },
    { label: 'Scan Clipboard Now', click: () => scanClipboardNow() },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.isQuitting = true; app.quit(); } },
  ]);
}

function createTray() {
  // Create a simple 16x16 shield icon programmatically
  const iconPath = path.join(__dirname, '..', 'resources', 'trayTemplate.png');
  const img = nativeImage.createFromPath(iconPath);
  tray = new Tray(img.isEmpty() ? nativeImage.createEmpty() : img);
  tray.setToolTip('Kasbah Guard — AI Governance');
  tray.setContextMenu(buildTrayMenu());
  tray.on('double-click', () => mainWindow?.show() || createWindow());
}

function refreshTray() {
  tray?.setContextMenu(buildTrayMenu());
}

// ─── Protection Toggle ────────────────────────────────────────────────────────

function toggleProtection() {
  State.isProtected = !State.isProtected;
  if (State.isProtected) startClipboardWatcher(); else stopClipboardWatcher();
  refreshTray();
  mainWindow?.webContents.send('state-change', { isProtected: State.isProtected });
  new Notification({ title: 'Kasbah Guard', body: State.isProtected ? '🛡️ Protection enabled' : '⚠️ Protection disabled' }).show();
}

// ─── Clipboard Watcher ────────────────────────────────────────────────────────

function startClipboardWatcher() {
  stopClipboardWatcher();
  clipboardInterval = setInterval(async () => {
    if (!State.isProtected || !State.apiReady) return;
    try {
      const text = clipboard.readText();
      if (text.length < 10 || text === lastClip) return;
      lastClip = text;
      await handleScan(text, 'clipboard-auto');
    } catch (_) {}
  }, 1500);
}

function stopClipboardWatcher() {
  if (clipboardInterval) { clearInterval(clipboardInterval); clipboardInterval = null; }
}

async function scanClipboardNow() {
  const text = clipboard.readText();
  if (!text) return;
  return handleScan(text, 'clipboard-manual');
}

// ─── Core Scan Logic ─────────────────────────────────────────────────────────

async function handleScan(text, source) {
  State.stats.totalScans++;
  let result;
  try {
    // Use /v1/govern — the full 13-frontier pipeline with verdict, receipts, and audit trail
    const r = await apiCall('POST', '/v1/govern', { prompt: text });
    result = r.body;
  } catch (e) {
    result = { verdict: 'ERROR', threats: [], score: 1 };
  }

  const verdict = result?.verdict || 'ALLOW';
  const threats = result?.threats || [];
  // score from /v1/govern is a safety score (1=clean, 0=dangerous)
  const score   = result?.score != null ? result.score : 1;

  if (verdict === 'DENY' || verdict === 'WARN' || threats.length > 0) {
    State.stats.threatsBlocked++;
    const riskPct = Math.round((1 - score) * 100);
    new Notification({
      title: '🛡️ Kasbah Guard — Threat Detected',
      body: `${threats.length} threat(s) | ${riskPct}% risk | ${source}`,
      urgency: 'critical',
    }).show();
  }

  const receiptId = result?.receipt || result?.requestId || result?.proof?.hash || '';
  const activity  = {
    id: Date.now(), ts: Date.now(), source, verdict, threats,
    text: text.slice(0, 120), score, receiptId,
  };
  State.recentActivity.unshift(activity);
  if (State.recentActivity.length > 200) State.recentActivity.length = 200;

  if (verdict === 'ALLOW') State.stats.allowed++;
  else if (verdict === 'WARN') State.stats.warned++;

  mainWindow?.webContents.send('activity-update', activity);
  refreshTray();
  return result;
}

// ─── IPC Handlers ────────────────────────────────────────────────────────────

// State
ipcMain.handle('get-state',     () => ({ ...State, server: undefined }));
ipcMain.handle('toggle-protection', () => { toggleProtection(); return State.isProtected; });
ipcMain.handle('scan-clipboard', () => scanClipboardNow());

// API Proxy — all API calls from renderer go through main for security
ipcMain.handle('api', async (_e, method, endpoint, body) => {
  if (!State.apiReady) return { status: 503, body: { error: 'API not ready' } };
  try { return await apiCall(method, endpoint, body); }
  catch (e) { return { status: 503, body: { error: e.message } }; }
});

// Open external URL safely
ipcMain.handle('open-url', (_e, url) => {
  if (url.startsWith('https://') || url.startsWith('http://127.0.0.1')) shell.openExternal(url);
});

// ─── App Lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  // Start embedded API server first
  try {
    await startApiServer();
    console.log(`[desktop] API server ready on :${API_PORT}`);
  } catch (e) {
    console.error('[desktop] API server failed to start:', e.message);
  }

  createWindow();
  createTray();
  if (State.isProtected) startClipboardWatcher();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  stopClipboardWatcher();
  // State.server is an http.Server instance from express.listen()
  try { State.server?.close(); } catch (_) {}
});

// Single instance lock
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) { app.quit(); }
else {
  app.on('second-instance', () => { mainWindow?.show(); mainWindow?.focus(); });
}
