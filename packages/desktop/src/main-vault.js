'use strict';

/**
 * Vault, backup, settings and Wi-Fi IPC handlers.
 * Call registerVaultHandlers(ipcMain, ctx) once during app startup.
 * Requires ctx.applyKillSwitch to be set (by registerVpnHandlers).
 *
 * ctx shape: State, log, V, fs, path, os, crypto, dialog,
 *            safePathInside, safeExistingFile,
 *            vpnState, applyKillSwitch (set by vpn module),
 *            loadSettings, saveSettings
 */

module.exports = function registerVaultHandlers(ipcMain, ctx) {
  const { log, V, fs, path, os, crypto, dialog,
          safePathInside, safeExistingFile, vpnState } = ctx;

  // ─── Vault crypto ─────────────────────────────────────────────────────────────
  const VAULT_PATH = path.join(os.homedir(), '.kasbah-vault.enc');

  let _vaultPwBuf = null;
  function setVaultMasterPassword(password) {
    if (_vaultPwBuf) _vaultPwBuf.fill(0);
    _vaultPwBuf = password ? Buffer.from(String(password), 'utf8') : null;
  }
  function _vp() { return _vaultPwBuf ? _vaultPwBuf.toString('utf8') : null; }

  function vaultKey(salt, password) {
    if (!password) throw new Error('Vault master password required');
    return crypto.pbkdf2Sync(password, salt, 1000000, 32, 'sha256');
  }

  function vaultRead(password) {
    if (!password) throw new Error('Vault master password required');
    try {
      const raw = fs.readFileSync(VAULT_PATH);
      const salt = raw.slice(0, 16), iv = raw.slice(16, 28), tag = raw.slice(28, 44), ct = raw.slice(44);
      const key = vaultKey(salt, password);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      return JSON.parse(Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8'));
    } catch { return []; }
  }

  function vaultWrite(entries, password) {
    if (!password) throw new Error('Vault master password required');
    const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
    const key = vaultKey(salt, password);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(JSON.stringify(entries), 'utf8'), cipher.final()]);
    fs.writeFileSync(VAULT_PATH, Buffer.concat([salt, iv, cipher.getAuthTag(), ct]), { mode: 0o600 });
  }

  ipcMain.handle('vault:unlock', (_e, password) => {
    try { vaultRead(password); setVaultMasterPassword(password); return { ok: true }; }
    catch { return { ok: false, error: 'Invalid password' }; }
  });

  ipcMain.handle('vault:lock', () => { setVaultMasterPassword(null); return { ok: true }; });

  ipcMain.handle('vault:list', () => {
    if (!_vp()) return [];
    return vaultRead(_vp()).map((e) => ({ ...e, password: undefined, passwordPreview: e.password ? '••••••••' : '' }));
  });

  ipcMain.handle('vault:add', (_e, entry) => {
    if (!_vp()) throw new Error('Vault is locked');
    const entries = vaultRead(_vp());
    const newEntry = { id: `v_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`, ...V.obj(entry, 'entry'), createdAt: new Date().toISOString() };
    entries.push(newEntry);
    vaultWrite(entries, _vp());
    return { ok: true, id: newEntry.id };
  });

  ipcMain.handle('vault:delete', (_e, id) => {
    if (!_vp()) throw new Error('Vault is locked');
    vaultWrite(vaultRead(_vp()).filter((e) => e.id !== id), _vp());
    return { ok: true };
  });

  ipcMain.handle('vault:get', (_e, id) => {
    if (!_vp()) throw new Error('Vault is locked');
    return vaultRead(_vp()).find((e) => e.id === id) || null;
  });

  ipcMain.handle('vault:generate', () => {
    const chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*';
    let pw = '';
    const buf = crypto.randomBytes(24);
    for (let i = 0; i < 24; i++) pw += chars[buf[i] % chars.length];
    return pw;
  });

  // ─── Backup (AES-256-GCM) ─────────────────────────────────────────────────────
  const BACKUP_DIR = path.join(os.homedir(), '.kasbah-backup');

  ipcMain.handle('backup:choose-file', async () => {
    const result = await dialog.showOpenDialog(ctx.mainWindow, { properties: ['openFile', 'multiSelections'] });
    return result.filePaths;
  });

  ipcMain.handle('backup:encrypt', (_e, filePath) => {
    if (!_vp()) return { ok: false, error: 'Vault is locked — unlock vault before encrypting backups' };
    try {
      const src = safeExistingFile(filePath);
      fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });
      const data = fs.readFileSync(src);
      const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
      const key = vaultKey(salt, _vp());
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([cipher.update(data), cipher.final()]);
      const meta = Buffer.from(JSON.stringify({ originalName: path.basename(filePath), size: data.length, ts: new Date().toISOString() }));
      const metaLen = Buffer.alloc(4); metaLen.writeUInt32BE(meta.length);
      const baseName = path.basename(filePath) + '.kbk';
      fs.writeFileSync(path.join(BACKUP_DIR, baseName), Buffer.concat([metaLen, meta, salt, iv, cipher.getAuthTag(), ct]), { mode: 0o600 });
      return { ok: true, outPath: path.join(BACKUP_DIR, baseName), originalName: path.basename(filePath), size: data.length };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('backup:decrypt', (_e, fileName) => {
    if (!_vp()) return { ok: false, error: 'Vault is locked — unlock vault before decrypting backups' };
    try {
      const inPath = safePathInside(BACKUP_DIR, path.basename(String(fileName || '')));
      const raw = fs.readFileSync(inPath);
      const metaLen = raw.readUInt32BE(0);
      const meta = JSON.parse(raw.slice(4, 4 + metaLen).toString('utf8'));
      let offset = 4 + metaLen;
      const salt = raw.slice(offset, offset + 16); offset += 16;
      const iv   = raw.slice(offset, offset + 12); offset += 12;
      const tag  = raw.slice(offset, offset + 16); offset += 16;
      const ct   = raw.slice(offset);
      const key = vaultKey(salt, _vp());
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      const data = Buffer.concat([decipher.update(ct), decipher.final()]);
      const { canceled, filePath } = require('electron').dialog.showSaveDialogSync({
        defaultPath: path.join(os.homedir(), 'Downloads', meta.originalName || fileName.replace('.kbk', '')),
        title: 'Restore backup to…',
      }) || {};
      if (canceled || !filePath) return { ok: false, error: 'Cancelled' };
      fs.writeFileSync(filePath, data);
      return { ok: true, restoredTo: filePath, originalName: meta.originalName, size: data.length };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('backup:list', () => {
    try {
      fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });
      return fs.readdirSync(BACKUP_DIR).filter((f) => f.endsWith('.kbk')).map((f) => {
        try {
          const raw = fs.readFileSync(path.join(BACKUP_DIR, f));
          const metaLen = raw.readUInt32BE(0);
          const meta = JSON.parse(raw.slice(4, 4 + metaLen).toString('utf8'));
          return { file: f, ...meta, encryptedSize: fs.statSync(path.join(BACKUP_DIR, f)).size };
        } catch { return { file: f }; }
      });
    } catch { return []; }
  });

  ipcMain.handle('backup:delete', (_e, file) => {
    try { fs.unlinkSync(safePathInside(BACKUP_DIR, path.basename(String(file || '')))); return { ok: true }; }
    catch (e) { return { ok: false, error: e.message }; }
  });

  // ─── Settings ─────────────────────────────────────────────────────────────────
  ipcMain.handle('settings:get', () => ctx.loadSettings());
  ipcMain.handle('settings:set', async (_e, patch) => {
    const next = ctx.saveSettings(patch || {});
  // after set, notify browser request filter
  try { ipcMain.emit('browser:settings-changed'); } catch (_) {}

    if ('killSwitch' in (patch || {})) {
      await ctx.applyKillSwitch(next.killSwitch && !!vpnState.activeLocation);
    }
    return next;
  });

  // ─── Wi-Fi ────────────────────────────────────────────────────────────────────
  ipcMain.handle('wifi:get-network', () => new Promise((resolve) => {    const { execFile } = require('child_process');
    execFile('networksetup', ['-getairportnetwork', 'en0'], (err, stdout) => {
      if (err) return resolve({ ssid: null, error: err.message });
      const m = stdout.match(/Current Wi-Fi Network:\s*(.+)/);
      const ssid = m ? m[1].trim() : null;
      execFile('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', ['-I'],
        (e2, out2) => {
          const secM = (out2 || '').match(/link auth:\s*(\S+)/);
          resolve({ ssid, security: secM ? secM[1] : 'unknown' });
        });
    });
  }));

  // Exposed for device-pairing export/import (main-features.js). Full
  // entries only while unlocked; import merges by id.
  ctx._vault = {
    isUnlocked: () => !!_vp(),
    listFull: () => (_vp() ? vaultRead(_vp()) : null),
    importEntries: (entries) => {
      if (!_vp()) throw new Error('Vault is locked');
      const cur = vaultRead(_vp());
      const ids = new Set(cur.map((e) => e.id));
      let added = 0;
      for (const e of entries || []) {
        if (!e || typeof e !== 'object') continue;
        const entry = { ...e };
        if (!entry.id || ids.has(entry.id)) entry.id = `v_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
        ids.add(entry.id);
        cur.push(entry);
        added++;
      }
      vaultWrite(cur, _vp());
      return added;
    },
  };
};
