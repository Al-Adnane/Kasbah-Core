'use strict';

/**
 * VPN IPC handlers — extracted from main.js to keep main process manageable.
 * Call registerVpnHandlers(ipcMain, ctx) once during app startup.
 * Sets ctx.applyKillSwitch so the vault/settings module can reference it.
 *
 * ctx shape (all provided by main.js):
 *   State, log, V, fs, path, os, shell, Notification, dialog, app,
 *   agentGuard, netIntel, resilience, _fsAudit,
 *   vpnState: { activeLocation, watchdogTimer, watchdogFailStreak, aiLaneHandle, aiLaneEvents }
 *   mainWindow getter, VPN_RESOURCES, loadSettings
 */

module.exports = function registerVpnHandlers(ipcMain, ctx) {
  const { State, log, V, fs, path, os, shell, Notification, dialog, app,
          agentGuard, netIntel, resilience, _fsAudit,
          vpnState, VPN_RESOURCES, loadSettings } = ctx;

  // ─── WireGuard binary paths ──────────────────────────────────────────────────
  const WG_QUICK = fs.existsSync('/opt/homebrew/bin/wg-quick')
    ? '/opt/homebrew/bin/wg-quick'
    : (fs.existsSync('/usr/local/bin/wg-quick') ? '/usr/local/bin/wg-quick' : 'wg-quick');
  const WG_BINDIR = path.dirname(WG_QUICK);
  const SUDOERS_PATH = '/etc/sudoers.d/kasbah-vpn';
  const MANUAL_OFF = path.join(os.homedir(), '.kasbah-privacy', 'vpn-manual-off');

  function setManualOff(on) {
    try {
      if (on) { fs.mkdirSync(path.dirname(MANUAL_OFF), { recursive: true }); fs.writeFileSync(MANUAL_OFF, new Date().toISOString()); }
      else if (fs.existsSync(MANUAL_OFF)) fs.unlinkSync(MANUAL_OFF);
    } catch (_) {}
  }

  // ─── VPN library lazy loader ─────────────────────────────────────────────────
  let vpnLib = null;
  function vpn() {
    if (!vpnLib) {
      vpnLib = {
        keys:     require(path.join(VPN_RESOURCES, 'src', 'keys.js')),
        psk:      require(path.join(VPN_RESOURCES, 'src', 'psk.js')),
        config:   require(path.join(VPN_RESOURCES, 'src', 'config.js')),
        store:    require(path.join(VPN_RESOURCES, 'src', 'store.js')),
        receipts: require(path.join(VPN_RESOURCES, 'src', 'receipts.js')),
        aiLane:   require(path.join(VPN_RESOURCES, 'src', 'ai-lane.js')),
        obfs:     require(path.join(VPN_RESOURCES, 'src', 'obfs.js')),
      };
    }
    return vpnLib;
  }

  function vpnRedactProfile(profile) {
    if (!profile) return profile;
    return {
      ...profile,
      wg: profile.wg ? { publicKey: profile.wg.publicKey } : null,
      kem: profile.kem ? { publicKey: profile.kem.publicKey } : null,
      client: profile.client ? { ...profile.client, presharedKey: profile.client.presharedKey ? '(set)' : null } : null,
      peers: (profile.peers || []).map((p) => ({ ...p, presharedKey: p.presharedKey ? '(set)' : null })),
    };
  }

  // ─── Locations ───────────────────────────────────────────────────────────────
  const LOCATIONS_DIR  = path.join(os.homedir(), '.kasbah-vpn', 'locations');
  const LOCATIONS_MANIFEST = path.join(LOCATIONS_DIR, 'manifest.json');

  function loadLocations() {
    try {
      const data = JSON.parse(fs.readFileSync(LOCATIONS_MANIFEST, 'utf8'));
      if (!Array.isArray(data)) return [];
      return data.filter((loc) => {
        if (!loc || typeof loc !== 'object') return false;
        if (!loc.id || !/^[a-z0-9-]+$/.test(loc.id)) return false;
        if (!loc.confPath || !loc.name) return false;
        // confPath is later interpolated into a single-quoted shell string
        // (`'${WG_QUICK}' up '${confPath}'`) — a quote in the path would break
        // out of that literal. Reject it here the same way loc.id is already
        // regex-gated for the same reason.
        if (String(loc.confPath).includes("'")) return false;
        if (!fs.existsSync(loc.confPath)) return false;
        try { fs.accessSync(loc.confPath, fs.constants.R_OK); } catch { return false; }
        if (loc.obfsHost && !/^[a-zA-Z0-9.-]+$/.test(loc.obfsHost)) return false;
        if (loc.obfsPort && (loc.obfsPort < 1 || loc.obfsPort > 65535)) return false;
        return true;
      });
    } catch (e) {
      log.error('locations', `Failed to load manifest: ${e.message}`);
      return [];
    }
  }

  // ─── Tier check ──────────────────────────────────────────────────────────────
  async function currentTier() {
    try {
      const r = await fetch(`http://127.0.0.1:8788/v1/usage/me`, { signal: AbortSignal.timeout(4000) });
      const body = await r.json();
      return body.tier || 'free';
    } catch { return 'free'; }
  }

  // ─── Tunnel utilities ────────────────────────────────────────────────────────
  function vpnCleanEnv() {
    const env = { ...process.env };
    ['HTTPS_PROXY','HTTP_PROXY','ALL_PROXY','https_proxy','http_proxy','all_proxy',
     'REQUESTS_CA_BUNDLE','SSL_CERT_FILE'].forEach((k) => delete env[k]);
    return env;
  }

  function vpnPingExit(ip = '10.77.0.1') {
    return new Promise((resolve) => {
      const { execFile } = require('child_process');
      execFile('/sbin/ping', ['-c','1','-W','2000', ip], { env: vpnCleanEnv(), timeout: 6000 },
        (err, stdout) => resolve(!err && /bytes from/.test(stdout || '')));
    });
  }

  /** Parse handshake age from `wg show` output. Returns ms since handshake or null. */
  function parseHandshakeAge(wgShowText) {
    const m = String(wgShowText || '').match(/latest handshake:\s*(.+)/i);
    if (!m) return null;
    const s = m[1].trim();
    // e.g. "8 hours, 28 minutes, 29 seconds ago" / "12 seconds ago" / "just now"
    if (/just now/i.test(s)) return 0;
    let ms = 0;
    const hours = s.match(/(\d+)\s*hour/i); if (hours) ms += Number(hours[1]) * 3600000;
    const mins  = s.match(/(\d+)\s*minute/i); if (mins)  ms += Number(mins[1]) * 60000;
    const secs  = s.match(/(\d+)\s*second/i); if (secs)  ms += Number(secs[1]) * 1000;
    return /ago/i.test(s) || ms ? ms : null;
  }

  function hasFreshHandshake(wgShowText, maxAgeMs = 180000) {
    const age = parseHandshakeAge(wgShowText);
    if (age == null) return false;
    // Missing "ago" with a parsed duration means "N ago"; 0 = just now
    return age <= maxAgeMs;
  }

  function vpnProbeReachable() {
    return new Promise((resolve) => {
      const { execFile } = require('child_process');
      execFile('/usr/bin/curl', ['-s','-o','/dev/null','-w','%{http_code}',
        '--max-time','10','--noproxy','*','https://1.1.1.1/cdn-cgi/trace'],
        { env: vpnCleanEnv() }, (err, stdout) => resolve(!err && stdout.trim() === '200'));
    });
  }

  function vpnTestPaths() {
    const dir = path.join(vpn().store.stateDir(), 'quick-test');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    return { dir, pathA: path.join(dir, 'this-mac-a.conf'), pathB: path.join(dir, 'this-mac-b.conf') };
  }

  function vpnTeardownCmd(locations) {
    const { pathA, pathB } = vpnTestPaths();
    const helper = '/usr/local/libexec/kasbah-wg';
    const useHelper = fs.existsSync(SUDOERS_PATH) && fs.existsSync(helper);
    const cmds = [
      `export PATH="${WG_BINDIR}:/usr/bin:/bin:/usr/sbin:/sbin"`,
      `/usr/bin/pkill -f 'wstunnel client' 2>/dev/null || true`,
      `'${WG_QUICK}' down '${pathA}' 2>/dev/null || true`,
      `'${WG_QUICK}' down '${pathB}' 2>/dev/null || true`,
    ];
    for (const l of locations) {
      if (useHelper && l.id && /^[a-z0-9_-]{1,32}$/i.test(l.id)) {
        cmds.push(`'${helper}' down '${l.id}' 2>/dev/null || true`);
      } else if (l.confPath) {
        cmds.push(`'${WG_QUICK}' down '${l.confPath}' 2>/dev/null || true`);
      }
    }
    return cmds.join(' ; ');
  }

  // ─── Obfuscation ─────────────────────────────────────────────────────────────
  const VPN_OBFS_PROCS = new Map();

  function vpnStopObfs(locationId) {
    const p = locationId ? VPN_OBFS_PROCS.get(locationId) : null;
    if (p) { try { p.kill('SIGTERM'); } catch (_) {} VPN_OBFS_PROCS.delete(locationId); }
    if (!locationId) {
      try { require('child_process').execSync("pkill -f 'wstunnel client' 2>/dev/null || true"); } catch (_) {}
    }
  }

  function vpnStartObfs(loc) {
    const { obfs } = vpn();
    const rawConf = fs.readFileSync(loc.confPath, 'utf8');
    const m = rawConf.match(/^Endpoint\s*=\s*(.+)$/m);
    if (!m) throw new Error('client.conf has no Endpoint');
    const plan = obfs.obfsPlan({
      endpoint: m[1].trim(),
      obfsHost: loc.obfsHost || m[1].trim().split(':')[0],
      obfsPort: loc.obfsPort || 443,
      localPort: loc.obfsLocalPort || 51821,
      mode: loc.obfs === 'wss' ? 'wss' : 'tcp',
    });
    const rewritten = obfs.applyObfsToClientConf(rawConf, plan);
    const obfsConfPath = loc.confPath.replace(/\.conf$/, '.obfs.conf');
    fs.writeFileSync(obfsConfPath, rewritten, { mode: 0o600 });
    const wstunnel = fs.existsSync('/opt/homebrew/bin/wstunnel')
      ? '/opt/homebrew/bin/wstunnel'
      : (fs.existsSync('/usr/local/bin/wstunnel') ? '/usr/local/bin/wstunnel' : 'wstunnel');
    const { spawn } = require('child_process');
    vpnStopObfs(loc.id);
    const child = spawn(wstunnel, [
      'client', '-L', `udp://127.0.0.1:${plan.localPort}:${plan.wgRemote}?timeout_sec=0`,
      plan.mode === 'wss' ? `wss://${plan.obfsHost}:${plan.obfsPort}` : `ws://${plan.obfsHost}:${plan.obfsPort}`,
    ], { stdio: ['ignore','pipe','pipe'], detached: false });
    let errBuf = '';
    child.stderr.on('data', (d) => { errBuf += String(d); });
    child.on('error', (e) => { errBuf += e.message; });
    VPN_OBFS_PROCS.set(loc.id, child);
    return { plan, confPath: obfsConfPath, wstunnelCmd: plan.clientCmd, child, getErr: () => errBuf };
  }

  // ─── Watchdog ─────────────────────────────────────────────────────────────────
  function vpnStopWatchdog() {
    if (vpnState.watchdogTimer) { clearInterval(vpnState.watchdogTimer); vpnState.watchdogTimer = null; }
    vpnState.watchdogFailStreak = 0;
  }

  /**
   * Multi-signal health. ICMP alone is flaky on some Myanmar ISPs —
   * also accept HTTPS egress while the tunnel interface is up.
   */
  async function vpnTunnelHealthy() {
    if (await vpnPingExit()) return true;
    // ICMP blocked? Try HTTPS through the tunnel (still requires a live utun).
    try {
      const { execFile } = require('child_process');
      const ok = await new Promise((resolve) => {
        execFile('/usr/bin/curl', ['-sS', '-o', '/dev/null', '-w', '%{http_code}',
          '--max-time', '8', '--noproxy', '*', 'https://1.1.1.1/cdn-cgi/trace'],
          { env: vpnCleanEnv() }, (err, stdout) => resolve(!err && String(stdout).trim() === '200'));
      });
      if (ok) return true;
    } catch (_) {}
    return false;
  }

  function vpnStartWatchdog() {
    vpnStopWatchdog();
    let reconnecting = false;
    vpnState.watchdogTimer = setInterval(async () => {
      if (!vpnState.activeLocation) return vpnStopWatchdog();
      if (await vpnTunnelHealthy()) { vpnState.watchdogFailStreak = 0; return; }
      vpnState.watchdogFailStreak++;
      // Need several consecutive failures (6 × 15s ≈ 90s) before teardown.
      if (vpnState.watchdogFailStreak < 6) return;

      const lostLoc = vpnState.activeLocation;
      log.warn('vpn', `watchdog: tunnel unhealthy (${vpnState.watchdogFailStreak} streak) — tearing down then reconnecting`);
      try { await runAsAdmin(vpnTeardownCmd(loadLocations())); } catch (_) {}
      vpnStopObfs(null);
      vpnState.activeLocation = null;
      vpnStopWatchdog();
      try { agentGuard.setVpnState(false, { reason: 'watchdog' }); } catch (_) {}
      ctx.mainWindow?.webContents.send('vpn:auto-disconnected', {
        reason: 'Tunnel stopped passing packets — reconnecting…',
        willReconnect: true,
      });
      if (reconnecting) return;
      reconnecting = true;
      try {
        await new Promise((r) => setTimeout(r, 2500));
        const r = await connectWithFallback({ locationId: lostLoc?.id });
        if (r.ok) {
          log.info('vpn', 'watchdog: auto-reconnect succeeded');
          ctx.mainWindow?.webContents.send('vpn:auto-reconnected', { location: r.location, name: r.name });
        } else {
          log.warn('vpn', `watchdog: auto-reconnect failed: ${r.output || ''}`);
          ctx.mainWindow?.webContents.send('vpn:auto-disconnected', {
            reason: r.output || 'Reconnect failed — tap Connect',
            willReconnect: false,
          });
        }
      } catch (e) {
        log.error('vpn', `watchdog reconnect error: ${e.message}`);
      } finally { reconnecting = false; }
    }, 15000);
  }

  // ─── runAsAdmin ───────────────────────────────────────────────────────────────
  function runAsAdmin(shellCmd) {
    return new Promise((resolve) => {
      const { execFile } = require('child_process');
      const logFile = path.join(os.tmpdir(), 'kasbah-vpn-admin.log');
      if (fs.existsSync(SUDOERS_PATH) && process.env.KASBAH_FORCE_OSA !== '1') {
        const helper = '/usr/local/libexec/kasbah-wg';
        if (shellCmd.includes(helper) && fs.existsSync(helper)) {
          execFile('/bin/sh', ['-c', `sudo -n ${shellCmd.replace(/'/g, `'\\''`)} >"${logFile}" 2>&1; cat "${logFile}"; exit 0`],
            { timeout: 120000, env: { ...process.env, PATH: `${WG_BINDIR}:/usr/bin:/bin:/usr/sbin:/sbin` } },
            (err, stdout, stderr) => {
              let fileOut = '';
              try { fileOut = fs.readFileSync(logFile, 'utf8').trim(); } catch (_) {}
              const body = fileOut || stdout || stderr || (err && err.message) || '';
              if (/KASBAH_ADMIN_OK|Backgrounding route monitor|Interface .* is utun/.test(body) || !err)
                return resolve({ ok: true, output: body, helper: true });
              return resolve({ ok: false, output: body || (err && err.message) });
            });
          return;
        }
      }
      const wrapped = `rm -f "${logFile}" ; ${shellCmd} >"${logFile}" 2>&1 ; ec=$? ; ` +
        `if [ $ec -eq 0 ]; then echo KASBAH_ADMIN_OK >>"${logFile}"; ` +
        `else echo KASBAH_ADMIN_FAIL:$ec >>"${logFile}"; fi ; cat "${logFile}" ; exit 0`;
      const esc = wrapped.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      execFile('osascript', ['-e', `do shell script "${esc}" with administrator privileges`],
        { timeout: 120000 }, (err, stdout, stderr) => {
          let fileOut = '';
          try { fileOut = fs.readFileSync(logFile, 'utf8').trim(); } catch (_) {}
          const combined = [stdout, fileOut, stderr].map((s) => (s || '').trim()).filter(Boolean).join('\n');
          const body = fileOut || combined || (err && err.message) || '';
          if (/User canceled|-128/.test(body)) return resolve({ ok: false, cancelled: true, output: 'Cancelled.' });
          if (/KASBAH_ADMIN_OK/.test(body)) return resolve({ ok: true, output: body });
          if (err && !/KASBAH_ADMIN_FAIL/.test(body)) { log.error('admin', body.slice(0, 800)); return resolve({ ok: false, output: body || err.message }); }
          log.error('admin', `script failed: ${body.slice(0, 800)}`);
          resolve({ ok: false, output: body || err.message });
        });
    });
  }

  // ─── Kill switch ──────────────────────────────────────────────────────────────
  async function applyKillSwitch(enable) {
    try {
      if (enable) {
        const rules = ['set skip on lo0', 'block out quick inet', 'pass out quick on utun+ inet'].join('\n');
        const tmpRule = path.join(os.tmpdir(), 'kasbah-ks.conf');
        fs.writeFileSync(tmpRule, rules, { mode: 0o600 });
        await runAsAdmin(`pfctl -f '${tmpRule}' && pfctl -e 2>/dev/null || true`);
        log.info('kill-switch', 'enabled');
      } else {
        await runAsAdmin('pfctl -d 2>/dev/null || true');
        log.info('kill-switch', 'disabled');
      }
    } catch (e) {
      log.error('kill-switch', `Failed to apply: ${e.message}`);
    }
  }
  // Expose so vault/settings module can call it via ctx
  ctx.applyKillSwitch = applyKillSwitch;

  // ─── VPN IPC handlers ────────────────────────────────────────────────────────

  ipcMain.handle('vpn:state', () => {
    const { store, receipts } = vpn();
    const profile = store.loadProfile();
    return {
      profile: vpnRedactProfile(profile),
      receipts: receipts.list(),
      aiLane: vpnState.aiLaneHandle
        ? { running: true, port: vpnState.aiLaneHandle.port, gateway: vpnState.aiLaneHandle.gateway }
        : { running: false },
      aiLaneEvents: vpnState.aiLaneEvents.slice(-20),
    };
  });

  // These fields end up written verbatim into generated WireGuard .conf
  // files (config.clientConf/serverConf/meshConfs). A newline in any of them
  // could inject an extra config directive (e.g. a PostUp/PreDown line) into
  // a file that `wg-quick up` later executes with elevated privileges — so,
  // beyond ipc-validate's generic size caps, reject control characters and
  // constrain to the charsets these fields actually need.
  const RE_SIMPLE_NAME = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
  const RE_HOST_ENDPOINT = /^[A-Za-z0-9.:\[\]-]{1,255}$/; // host[:port], IPv6 in brackets
  const RE_IFACE = /^[A-Za-z0-9]{1,16}$/;
  const RE_SUBNET = /^\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const RE_CIDR = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
  function field(v, re, name) {
    const s = V.str(v, { max: 255, name });
    if (s && !re.test(s)) throw new Error(`invalid ${name}`);
    return s;
  }

  ipcMain.handle('vpn:init', (_e, body = {}) => {
    const { keys, psk, store, receipts } = vpn();
    const b = V.obj(body, 'body');
    if (store.loadProfile() && !V.bool(b.force)) throw new Error('profile exists — use force to overwrite');
    const wgKeys = keys.generateWgKeypair();
    let kem = null;
    try { kem = psk.kemKeypair(); } catch { /* optional dep */ }
    const name = field(b.name, RE_SIMPLE_NAME, 'name') || 'kasbah-vpn';
    const profile = { name, created: new Date().toISOString(), wg: wgKeys, kem, peers: [], server: null, client: null };
    store.saveProfile(profile);
    receipts.record('vpn.init', { publicKey: wgKeys.publicKey, pq: !!kem });
    return { ok: true, profile: vpnRedactProfile(profile) };
  });

  ipcMain.handle('vpn:server-init', (_e, body = {}) => {
    const { config, store, receipts } = vpn();
    const b = V.obj(body, 'body');
    const profile = store.loadProfile();
    if (!profile) throw new Error('no profile — init first');
    if (!b.endpoint) throw new Error('endpoint required');
    profile.server = {
      endpoint: field(b.endpoint, RE_HOST_ENDPOINT, 'endpoint'),
      port: V.num(b.port || config.DEFAULT_PORT, { min: 1, max: 65535, name: 'port' }),
      subnet: b.subnet ? field(b.subnet, RE_SUBNET, 'subnet') : config.DEFAULT_SUBNET,
      wanInterface: b.wanInterface ? field(b.wanInterface, RE_IFACE, 'wanInterface') : 'eth0',
    };
    store.saveProfile(profile);
    receipts.record('server.init', { endpoint: profile.server.endpoint, port: profile.server.port });
    return { ok: true, profile: vpnRedactProfile(profile) };
  });

  ipcMain.handle('vpn:join', (_e, body = {}) => {
    const { keys, psk, config, store, receipts } = vpn();
    const b = V.obj(body, 'body');
    const profile = store.loadProfile();
    if (!profile) throw new Error('no profile — init first');
    if (!b.endpoint || !b.serverPublicKey) throw new Error('endpoint and serverPublicKey required');
    if (!keys.isWgKey(b.serverPublicKey)) throw new Error('serverPublicKey is not a valid WireGuard key');
    let presharedKey = null, ciphertext = null;
    if (b.serverKemPub) { const enc = psk.encapsulate(b.serverKemPub); presharedKey = enc.psk; ciphertext = enc.ciphertext; }
    const endpoint = field(b.endpoint, RE_HOST_ENDPOINT, 'endpoint');
    const address = b.address ? field(b.address, RE_CIDR, 'address') : `${config.DEFAULT_SUBNET}.2/24`;
    profile.client = { endpoint, serverPublicKey: b.serverPublicKey, address, presharedKey };
    store.saveProfile(profile);
    receipts.record('vpn.join', { endpoint, serverPublicKey: b.serverPublicKey, pqPsk: !!presharedKey });
    return { ok: true, profile: vpnRedactProfile(profile), kemCiphertext: ciphertext };
  });

  ipcMain.handle('vpn:peer-add', (_e, body = {}) => {
    const { keys, psk, store, receipts } = vpn();
    const b = V.obj(body, 'body');
    const profile = store.loadProfile();
    if (!profile) throw new Error('no profile — init first');
    if (!profile.server) throw new Error('run server-init first');
    if (!b.name || !b.publicKey) throw new Error('name and publicKey required');
    if (!keys.isWgKey(b.publicKey)) throw new Error('publicKey is not a valid WireGuard key');
    const peerName = field(b.name, RE_SIMPLE_NAME, 'name');
    if (profile.peers.some((p) => p.name === peerName)) throw new Error(`peer "${peerName}" already exists`);
    let presharedKey = null;
    if (b.kemCiphertext) { if (!profile.kem) throw new Error('profile has no KEM key'); presharedKey = psk.decapsulate(profile.kem.secretKey, b.kemCiphertext).psk; }
    const subnet = profile.server.subnet;
    const used = new Set(profile.peers.map((p) => p.address));
    let hostNum = 2;
    while (used.has(`${subnet}.${hostNum}`)) hostNum++;
    const peer = { name: peerName, publicKey: b.publicKey, address: `${subnet}.${hostNum}`, presharedKey };
    profile.peers.push(peer);
    store.saveProfile(profile);
    receipts.record('peer.add', { name: peer.name, publicKey: peer.publicKey, address: peer.address, pqPsk: !!presharedKey });
    return { ok: true, peer: { ...peer, presharedKey: peer.presharedKey ? '(set)' : null }, profile: vpnRedactProfile(profile) };
  });

  ipcMain.handle('vpn:config', async (_e, kind, split) => {
    const { config, store } = vpn();
    const profile = store.loadProfile();
    if (kind === 'client') {
      if (!profile?.client) throw new Error('no client config — join first');
      const base = { privateKey: profile.wg.privateKey, address: profile.client.address, serverPublicKey: profile.client.serverPublicKey, presharedKey: profile.client.presharedKey || undefined, endpoint: profile.client.endpoint };
      if (split) { const { conf, entries } = await config.splitAiClientConf(base); return { conf, entries }; }
      return { conf: config.clientConf(base) };
    }
    if (kind === 'server') {
      if (!profile?.server) throw new Error('no server config — server-init first');
      return { conf: config.serverConf({ privateKey: profile.wg.privateKey, subnet: profile.server.subnet, port: profile.server.port, wanInterface: profile.server.wanInterface, peers: profile.peers }) };
    }
    throw new Error(`unknown config kind "${kind}"`);
  });

  ipcMain.handle('vpn:mesh', (_e, body = {}) => {
    const { keys, psk, config, receipts } = vpn();
    const b = V.obj(body, 'body');
    const names = V.str(b.nodes, { max: 2000, name: 'nodes' }).split(',').map((s) => s.trim()).filter(Boolean);
    if (names.length < 2) throw new Error('need at least 2 comma-separated node names');
    if (names.length > 32) throw new Error('too many nodes');
    for (const n of names) if (!RE_SIMPLE_NAME.test(n)) throw new Error(`invalid node name: ${n}`);
    const endpoints = {};
    for (const pair of V.str(b.endpoints, { max: 4000, name: 'endpoints' }).split(',').filter(Boolean)) {
      const [n, ...ep] = pair.split('=');
      const epVal = field(ep.join('=').trim(), RE_HOST_ENDPOINT, 'endpoint');
      endpoints[n.trim()] = epVal;
    }
    const nodes = names.map((name) => ({ name, ...keys.generateWgKeypair(), endpoint: endpoints[name] ? (endpoints[name].includes(':') ? endpoints[name] : `${endpoints[name]}:${config.DEFAULT_PORT}`) : undefined, psk: {} }));
    for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) nodes[i].psk[nodes[j].name] = psk.randomPsk();
    const confs = config.meshConfs(nodes);
    receipts.record('mesh.init', { nodes: names, endpoints });
    return { ok: true, confs, nodes: nodes.map((n) => ({ name: n.name, publicKey: n.publicKey, endpoint: n.endpoint || '(roaming)' })) };
  });

  ipcMain.handle('vpn:locations', () => loadLocations());

  async function connectWithFallback(body = {}) {
    try {
      const { receipts } = vpn();
      const locations = loadLocations();
      const requested = locations.find((l) => l.id === body.locationId) || locations[0];
      if (!requested) throw new Error('no exit-node location configured yet');

      // Attempt order per location: plain WireGuard first (historically worked
      // from Myanmar), then TCP/WSS obfs if configured. Then other free Asia exits.
      const asia = locations.filter((l) => l.free === true && /asia|sin|nrt|hkg|bkk|singapore|tokyo/i.test(`${l.continent || ''} ${l.region || ''} ${l.name || ''}`));
      const orderLocs = [];
      for (const l of [requested, ...asia, ...locations.filter((x) => x.free === true)]) {
        if (l && !orderLocs.find((x) => x.id === l.id)) orderLocs.push(l);
      }

      const attempts = [];
      const maxTries = 4;
      let tries = 0;

      for (const loc of orderLocs) {
        if (tries >= maxTries) break;
        if (!fs.existsSync(loc.confPath)) {
          attempts.push({ id: loc.id, mode: 'plain', ok: false, reason: 'config missing' });
          continue;
        }
        if (loc.free !== true) {
          const tier = await currentTier();
          if (tier === 'free') {
            attempts.push({ id: loc.id, mode: 'plain', ok: false, reason: 'requires paid plan' });
            continue;
          }
        }
        // 1) Plain UDP
        tries++;
        let r = await vpnConnectAttempt(loc, { useObfs: false });
        attempts.push({ id: loc.id, mode: 'plain', ok: !!r.ok, reason: r.ok ? 'ok' : String(r.output || 'failed').slice(0, 200) });
        if (r.ok) return finishConnect(r, requested, attempts);

        // 2) Obfs (TCP/WSS:443) if the location declares it
        if (loc.obfs && tries < maxTries) {
          tries++;
          r = await vpnConnectAttempt(loc, { useObfs: true });
          attempts.push({ id: loc.id, mode: `obfs-${loc.obfs}`, ok: !!r.ok, reason: r.ok ? 'ok' : String(r.output || 'failed').slice(0, 200) });
          if (r.ok) return finishConnect(r, requested, attempts);
        }
      }

      const last = attempts[attempts.length - 1] || {};
      return {
        ok: false,
        attempts,
        output: `Could not bring a tunnel up. Last: ${last.id}/${last.mode} — ${last.reason || 'unknown'}. Tried: ${attempts.map((a) => `${a.id}:${a.mode}`).join(', ')}.`,
      };
    } catch (e) {
      log.error('vpn', `unexpected error: ${e.message}`);
      vpnStopWatchdog();
      return { ok: false, output: `Connection error: ${e.message}` };
    }
  }

  function finishConnect(r, requested, attempts) {
    if (requested && r.location && r.location !== requested.id) {
      r.output = ((r.output || '') + ` Fallback: connected via ${r.name || r.location}.`).trim();
      r.fallbackFrom = requested.id;
    }
    r.attempts = attempts.map((a) => ({ id: a.id, mode: a.mode, ok: a.ok, reason: a.reason }));
    return r;
  }

  /** One connect try for a location (plain or obfs). Tears down on failure. */
  async function vpnConnectAttempt(loc, { useObfs }) {
    vpnStopWatchdog();
    let confPath = loc.confPath, obfsInfo = null;
    if (useObfs && loc.obfs) {
      try {
        obfsInfo = vpnStartObfs(loc);
        confPath = obfsInfo.confPath;
        // Wait until local UDP bridge is listening
        const port = obfsInfo.plan.localPort;
        for (let i = 0; i < 20; i++) {
          const { execSync } = require('child_process');
          try {
            const out = execSync(`lsof -nP -iUDP:${port} 2>/dev/null || true`, { encoding: 'utf8' });
            if (out.includes(String(port))) break;
          } catch (_) {}
          await new Promise((r) => setTimeout(r, 250));
        }
        await new Promise((r) => setTimeout(r, 400));
      } catch (e) {
        return { ok: false, output: `Obfuscation start failed (install wstunnel?): ${e.message}` };
      }
    }
    const helper = '/usr/local/libexec/kasbah-wg';
    const useHelper = fs.existsSync(SUDOERS_PATH) && fs.existsSync(helper) && loc.id && /^[a-z0-9_-]{1,32}$/i.test(loc.id);
    const upCmd = useHelper ? `'${helper}' up '${loc.id}'` : `'${WG_QUICK}' up '${confPath}'`;
    // Tear down OTHER tunnels first. Do NOT pkill wstunnel here — we may have just started it.
    const downCmds = vpnTeardownCmd(loadLocations())
      .split(' ; ')
      .filter((c) => !/pkill -f 'wstunnel client'/.test(c))
      .join(' ; ');
    const res = await runAsAdmin([downCmds, upCmd + ` ; sleep 1 ; PATH="${WG_BINDIR}:$PATH" '${WG_BINDIR}/wg' show 2>/dev/null || true`].join(' ; '));
    if (!res.ok) {
      if (obfsInfo) vpnStopObfs(loc.id);
      return { ok: false, cancelled: res.cancelled, output: res.output };
    }
    const wgShow = res.output || '';
    let reachable = false;
    let sawHandshake = hasFreshHandshake(wgShow, 180000);
    for (let i = 0; i < 10 && !reachable; i++) {
      if (i > 0) await new Promise((r) => setTimeout(r, 2000));
      try { reachable = await vpnPingExit(); } catch (e) { log.warn('vpn', `ping attempt failed: ${e.message}`); }
    }
    if (!reachable) {
      try { await runAsAdmin(vpnTeardownCmd(loadLocations())); } catch (e) { log.error('vpn', `teardown failed: ${e.message}`); }
      if (obfsInfo) vpnStopObfs(loc.id);
      const hs = sawHandshake ? 'handshake seen' : 'no handshake';
      const rxTx = (wgShow.match(/transfer:\s*([^\n]+)/i) || [])[1] || 'n/a';
      const err = obfsInfo?.getErr?.() ? String(obfsInfo.getErr()).slice(0, 160) : '';
      return {
        ok: false,
        output: `no packets (${hs}; transfer ${rxTx})${err ? ' · wstunnel: ' + err : ''}`,
        diag: { handshake: sawHandshake, transfer: rxTx, obfs: useObfs || null },
      };
    }
    vpnState.activeLocation = { id: loc.id, confPath: loc.confPath, obfs: !!(useObfs && loc.obfs) };
    setManualOff(false); // allow LaunchDaemon to keep this up
    vpnStartWatchdog();
    try { agentGuard.setVpnState(true, { location: loc.id }); } catch (_) {}
    try { _fsAudit.append({ event: 'vpn_connect', location: loc.id, name: loc.name, obfs: useObfs ? loc.obfs : null, handshake: sawHandshake }); } catch (_) {}
    try { receipts.record('vpn.connect', { location: loc.id, name: loc.name, obfs: useObfs ? loc.obfs : null, handshake: sawHandshake }); } catch (_) {}
    const settings = loadSettings();
    if (settings.killSwitch) await applyKillSwitch(true).catch(() => {});
    let egressNote = '';
    try { egressNote = await vpnProbeReachable() ? ' Internet egress OK.' : ' Tunnel is up; first HTTPS may still be warming.'; } catch (_) {}
    return {
      ok: true,
      location: loc.id,
      name: loc.name,
      output: egressNote.trim() || 'Connected.',
      handshake: sawHandshake,
      obfs: useObfs && loc.obfs ? { mode: loc.obfs, cmd: obfsInfo?.plan?.clientCmd } : null,
    };
  }

  ipcMain.handle('vpn:connect', (_e, body = {}) => connectWithFallback(body || {}));

  ipcMain.handle('vpn:disconnect', async () => {
    const { receipts } = vpn();
    vpnStopWatchdog();
    const locations = loadLocations();
    setManualOff(true); // tell LaunchDaemon to stand down
    const res = await runAsAdmin(vpnTeardownCmd(locations));
    vpnStopObfs(null);
    if (res.ok) {
      vpnState.activeLocation = null;
      receipts.record('vpn.disconnect', {});
      try { agentGuard.setVpnState(false, {}); } catch (_) {}
      try { _fsAudit.append({ event: 'vpn_disconnect' }); } catch (_) {}
      applyKillSwitch(false).catch(() => {});
    }
    return { ok: res.ok, cancelled: res.cancelled, output: res.output };
  });

  ipcMain.handle('vpn:check-egress', async () => {
    const probe = await netIntel.realEgressProbe();
    if (!probe.ok) return { ok: false, error: probe.error };
    return { ok: true, ip: probe.ip || '', loc: probe.loc || '', colo: probe.colo || '' };
  });

  ipcMain.handle('vpn:quick-test-ping', async () => {
    return new Promise((resolve) => {
      const { spawn } = require('child_process');
      const p = spawn('ping', ['-c','3','-t','3','10.77.0.2']);
      let out = '';
      p.stdout.on('data', (d) => { out += d; });
      p.stderr.on('data', (d) => { out += d; });
      p.on('close', (code) => resolve({ ok: code === 0, output: out.trim() }));
    });
  });

  ipcMain.handle('vpn:ai-lane-start', async (_e, body = {}) => {
    const { aiLane, receipts } = vpn();
    if (vpnState.aiLaneHandle) return { ok: true, already: true, port: vpnState.aiLaneHandle.port, gateway: vpnState.aiLaneHandle.gateway };
    vpnState.aiLaneEvents = [];
    const lane = await aiLane.startAiLane({ port: Number(body.port || aiLane.DEFAULT_PORT), gateway: body.gateway || aiLane.DEFAULT_GATEWAY, onEvent: (e) => { vpnState.aiLaneEvents.push({ ...e, ts: Date.now() }); } });
    vpnState.aiLaneHandle = lane;
    receipts.record('ai-lane.start', { port: lane.port, gateway: lane.gateway });
    return { ok: true, port: lane.port, gateway: lane.gateway };
  });

  ipcMain.handle('vpn:ai-lane-stop', () => {
    if (vpnState.aiLaneHandle) { vpnState.aiLaneHandle.server.close(); vpn().receipts.record('ai-lane.stop', { port: vpnState.aiLaneHandle.port }); vpnState.aiLaneHandle = null; }
    return { ok: true };
  });

  ipcMain.handle('vpn:receipts-verify', () => vpn().receipts.verifyAll());

  // ─── Helper install ───────────────────────────────────────────────────────────
  ipcMain.handle('vpn:helper-status', () => ({ installed: fs.existsSync(SUDOERS_PATH), path: SUDOERS_PATH }));

  ipcMain.handle('vpn:helper-install', async () => {
    const wg = WG_QUICK;
    const wrapper = '/usr/local/libexec/kasbah-wg';
    const stage = '/var/lib/kasbah-vpn';
    const locRoot = path.join(os.homedir(), '.kasbah-vpn', 'locations');
    const ids = [];
    try {
      if (fs.existsSync(locRoot)) for (const id of fs.readdirSync(locRoot)) {
        if (/^[a-z0-9_-]{1,32}$/i.test(id) && fs.existsSync(path.join(locRoot, id, 'client.conf'))) ids.push(id);
      }
    } catch (_) {}
    if (!ids.length) return { ok: false, cancelled: false, output: 'No location configs found. Connect once with a password first.' };
    const wrapperScript = `#!/bin/sh\nset -eu\nACTION="$1"; ID="$2"\ncase "$ACTION" in up|down) ;; *) echo "usage: kasbah-wg up|down <locationId>" >&2; exit 2;; esac\ncase "$ID" in *[!a-zA-Z0-9_-]*|"") echo "bad id" >&2; exit 2;; esac\nCONF="${stage}/$ID.conf"\n[ -f "$CONF" ] || { echo "unknown location: $ID" >&2; exit 3; }\nif grep -Eiq '^[[:space:]]*(PostUp|PreDown|PostDown)[[:space:]]*=' "$CONF"; then\n  echo "refusing conf with PostUp/PreDown" >&2; exit 4\nfi\nexec "${wg}" "$ACTION" "$CONF"\n`;
    const rules = ids.map((id) => `${wrapper} up ${id}, ${wrapper} down ${id}`).join(', ');
    const cmd = [
      `mkdir -p '${stage}' '${path.dirname(wrapper)}'`,
      `printf '%s' '${wrapperScript.replace(/'/g, `'\\''`)}' > '${wrapper}'`,
      `chmod 755 '${wrapper}'`, `chown root:wheel '${wrapper}'`, `chmod 755 '${stage}'`,
      ...ids.map((id) => { const src = path.join(locRoot, id, 'client.conf'); return `grep -Ev '^[[:space:]]*(PostUp|PreDown|PostDown)[[:space:]]*=' '${src}' > '${stage}/${id}.conf' && chmod 644 '${stage}/${id}.conf'`; }),
      `printf '%s\\n' '${process.env.USER || 'mac'} ALL=(root) NOPASSWD: ${rules}' > /tmp/kasbah-sudoers`,
      `/usr/sbin/visudo -cf /tmp/kasbah-sudoers`,
      `cp /tmp/kasbah-sudoers ${SUDOERS_PATH} && chmod 440 ${SUDOERS_PATH} && rm -f /tmp/kasbah-sudoers`,
    ].join(' && ');
    const res = await runAsAdmin(cmd);
    log.info('vpn', 'helper install (wrapper)', { ok: res.ok, ids });
    return { ok: res.ok, cancelled: res.cancelled, output: res.output, path: SUDOERS_PATH, wrapper, ids };
  });

  ipcMain.handle('vpn:helper-remove', async () => {
    const res = await runAsAdmin(`rm -f ${SUDOERS_PATH} /usr/local/libexec/kasbah-wg`);
    return { ok: res.ok, cancelled: res.cancelled, output: res.output };
  });

  // ─── Browser / network ───────────────────────────────────────────────────────
  ipcMain.handle('browser:clear-data', async () => {
    try {
      const { session } = require('electron');
      const ses = session.fromPartition('persist:private');
      await ses.clearStorageData();
      await ses.clearCache();
      return { ok: true };
    } catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('browser:vpn-status', () => ({
    connected: !!vpnState.activeLocation,
    location: vpnState.activeLocation?.id || null,
  }));

  ipcMain.handle('net:snapshot', async () => {
    const locs = loadLocations();
    const snap = await netIntel.networkSnapshot(locs);
    snap.recommend = netIntel.recommendExit(snap.pings, locs);
    return snap;
  });

  ipcMain.handle('net:dpi-probe', async (_e, body = {}) => {
    return resilience.dpiProbe(body.host || '137.66.42.157', Number(body.port || 51820));
  });

  ipcMain.handle('vpn:auto-reconnect-start', (_e, body = {}) => {
    const locId = body.locationId || vpnState.activeLocation?.id || 'sin';
    return resilience.startAutoReconnect({
      locationId: locId,
      connectFn: async (id) => {
        const locations = loadLocations();
        const loc = locations.find((l) => l.id === id);
        if (!loc) throw new Error('no location');
        const helper = '/usr/local/libexec/kasbah-wg';
        const useHelper = fs.existsSync(SUDOERS_PATH) && fs.existsSync(helper) && loc.id && /^[a-z0-9_-]{1,32}$/i.test(loc.id);
        const upCmd = useHelper ? `'${helper}' up '${loc.id}'` : `'${WG_QUICK}' up '${loc.confPath}'`;
        const res = await runAsAdmin([vpnTeardownCmd(locations), upCmd].join(' ; '));
        if (!res.ok) throw new Error(res.output || 'reconnect failed');
        vpnState.activeLocation = { id: loc.id, confPath: loc.confPath };
        return res;
      },
      checkFn: () => vpnPingExit(),
      onChange: (s) => { ctx.mainWindow?.webContents.send('vpn:auto-reconnect', s); },
    });
  });

  ipcMain.handle('vpn:auto-reconnect-stop', () => resilience.stopAutoReconnect());
  ipcMain.handle('vpn:auto-reconnect-status', () => resilience.autoReconnectStatus());

  // ─── WSS/obfs health check ────────────────────────────────────────────────────
  // Reports whether wstunnel is installed locally and which exits declare obfs support.
  ipcMain.handle('vpn:wss-check', () => {
    const wstunnelPaths = ['/opt/homebrew/bin/wstunnel', '/usr/local/bin/wstunnel', '/usr/bin/wstunnel'];
    const wstunnelInstalled = wstunnelPaths.some((p) => { try { return fs.existsSync(p); } catch { return false; } });
    const locations = loadLocations();
    const obfsLocations = locations.filter((l) => l.obfs).map((l) => ({
      id: l.id, name: l.name, obfsMode: l.obfs, obfsHost: l.obfsHost, obfsPort: l.obfsPort || 443,
    }));
    const ready = wstunnelInstalled && obfsLocations.length > 0;
    return {
      ok: true,
      wstunnelInstalled,
      obfsLocations,
      ready,
      hint: !wstunnelInstalled
        ? 'Install wstunnel to enable DPI bypass: brew install wstunnel'
        : obfsLocations.length === 0
          ? 'No exit servers have WSS:443 configured yet — DPI bypass unavailable'
          : `DPI bypass ready on ${obfsLocations.length} exit(s)`,
    };
  });

  // Expose loadLocations so main.js before-quit can teardown
  ctx.vpnLoadLocations = loadLocations;
  ctx.vpnTeardownCmd = vpnTeardownCmd;
  ctx.runAsAdmin = runAsAdmin;
};
