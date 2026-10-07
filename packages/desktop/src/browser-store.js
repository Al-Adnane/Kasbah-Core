'use strict';

/**
 * browser-store.js — local, plain-JSON persistence for the Kasbah Browser:
 * history, bookmarks, downloads log, and privacy settings. Real files on
 * disk (~/.kasbah-browser-*.json), no cloud sync, no telemetry — nothing
 * here ever leaves the machine. Not encrypted (unlike the password vault):
 * history/bookmarks aren't secrets, and encrypting them would just make a
 * user's own "show my history" request need a decrypt round-trip for no
 * security benefit against the actual threat model (this file already lives
 * inside the user's home directory alongside every other browser's history db).
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const DIR = os.homedir();
const HISTORY_FILE   = path.join(DIR, '.kasbah-browser-history.json');
const BOOKMARKS_FILE = path.join(DIR, '.kasbah-browser-bookmarks.json');
const DOWNLOADS_FILE = path.join(DIR, '.kasbah-browser-downloads.json');
const SETTINGS_FILE  = path.join(DIR, '.kasbah-browser-settings.json');

const MAX_HISTORY = 5000;

// ── In-memory caches (critical for browser speed) ───────────────────────────
// settingsGet() was reading disk on EVERY webRequest — that made pages crawl.
let _settingsCache = null;
let _settingsLoaded = false;

function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 0), { mode: 0o600 });
}

// ── History ──────────────────────────────────────────────────────────────────
function historyAdd({ url, title }) {
  if (!url || /^(about|chrome|devtools|file):/.test(url)) return; // don't log internal pages
  const list = readJSON(HISTORY_FILE, []);
  list.unshift({ id: crypto.randomUUID(), url, title: title || url, visitedAt: new Date().toISOString() });
  if (list.length > MAX_HISTORY) list.length = MAX_HISTORY;
  writeJSON(HISTORY_FILE, list);
  return list[0];
}
function historyList(limit = 200) { return readJSON(HISTORY_FILE, []).slice(0, limit); }
function historyDelete(id) { writeJSON(HISTORY_FILE, readJSON(HISTORY_FILE, []).filter((e) => e.id !== id)); }
function historyUpdateTitle(id, title) {
  const list = readJSON(HISTORY_FILE, []);
  const e = list.find((x) => x.id === id);
  if (e) { e.title = title; writeJSON(HISTORY_FILE, list); }
}
function historyClear() { writeJSON(HISTORY_FILE, []); }
function historySearch(query) {
  const q = String(query || '').toLowerCase();
  if (!q) return [];
  return readJSON(HISTORY_FILE, []).filter((e) => e.url.toLowerCase().includes(q) || (e.title || '').toLowerCase().includes(q)).slice(0, 20);
}

// ── Bookmarks ────────────────────────────────────────────────────────────────
function bookmarkList() { return readJSON(BOOKMARKS_FILE, []); }
function bookmarkAdd({ url, title }) {
  const list = bookmarkList();
  if (list.some((b) => b.url === url)) return { ok: false, reason: 'already bookmarked' };
  const entry = { id: crypto.randomUUID(), url, title: title || url, createdAt: new Date().toISOString() };
  list.unshift(entry);
  writeJSON(BOOKMARKS_FILE, list);
  return { ok: true, entry };
}
function bookmarkRemove(urlOrId) {
  const list = bookmarkList().filter((b) => b.id !== urlOrId && b.url !== urlOrId);
  writeJSON(BOOKMARKS_FILE, list);
  return { ok: true };
}
function bookmarkIsSaved(url) { return bookmarkList().some((b) => b.url === url); }

// ── Downloads log (the real file transfer is Electron's session.on('will-download')
//    in main.js; this module just persists the record across restarts) ────────
function downloadsList() { return readJSON(DOWNLOADS_FILE, []); }
function downloadRecord(entry) {
  const list = downloadsList();
  const idx = list.findIndex((d) => d.id === entry.id);
  if (idx >= 0) list[idx] = { ...list[idx], ...entry };
  else list.unshift(entry);
  if (list.length > 500) list.length = 500;
  writeJSON(DOWNLOADS_FILE, list);
}
function downloadsClear() { writeJSON(DOWNLOADS_FILE, []); }

// ── Privacy/safety settings — real runtime toggles, not decorative ─────────────
const DEFAULT_SETTINGS = {
  trackerBlocking: true,       // gates session.webRequest.onBeforeRequest in main.js
  fingerprintProtection: true, // on by default — cheap per-origin noise (was slow before fix)
  httpsOnly: true,             // gates the http->https upgrade in bwrOnWillNavigate
  aiShield: true,              // gates the govern+scan page analysis
  historyEnabled: true,        // gates did-navigate logging in main.js
  queryStrip: true,            // strip utm/gclid/fbclid tracking params (beats DDG defaults)
  bounceBlock: true,           // skip known bounce trackers
  shieldExceptions: [],        // hosts with shields DOWN (tracker+bounce filtering off)
};
function settingsGet() {
  if (_settingsLoaded && _settingsCache) return _settingsCache;
  const disk = readJSON(SETTINGS_FILE, {});
  if (disk && disk.__fpMigrated !== true) {
    disk.fingerprintProtection = true;
    disk.queryStrip = disk.queryStrip !== false;
    disk.bounceBlock = disk.bounceBlock !== false;
    disk.__fpMigrated = true;
    try { writeJSON(SETTINGS_FILE, disk); } catch (_) {}
  }
  _settingsCache = { ...DEFAULT_SETTINGS, ...disk };
  _settingsLoaded = true;
  return _settingsCache;
}
function settingsSet(patch) {
  const next = { ...settingsGet(), ...patch };
  writeJSON(SETTINGS_FILE, next);
  _settingsCache = next;
  _settingsLoaded = true;
  return next;
}
/** Force reload from disk (rare). */
function settingsInvalidate() {
  _settingsCache = null;
  _settingsLoaded = false;
}

module.exports = {
  historyAdd, historyList, historyDelete, historyClear, historySearch, historyUpdateTitle,
  bookmarkList, bookmarkAdd, bookmarkRemove, bookmarkIsSaved,
  downloadsList, downloadRecord, downloadsClear,
  settingsGet, settingsSet, settingsInvalidate,
};
