'use strict';

/**
 * Network intelligence — unique to Kasbah Privacy for Myanmar-class networks.
 * Local only. No cloud.
 */

const os = require('os');
const fs = require('fs');
const { execFile } = require('child_process');

function exec(cmd, args, timeout = 5000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout }, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout: stdout || '', stderr: stderr || '', code: err ? err.code : 0 });
    });
  });
}

/** Guess ISP from default gateway / DNS / hostname patterns. */
async function detectIsp() {
  const ifs = os.networkInterfaces();
  const wan = [];
  for (const list of Object.values(ifs)) {
    for (const a of list || []) {
      if (a.family === 'IPv4' && !a.internal) wan.push(a.address);
    }
  }
  let gateway = '';
  const route = await exec('/sbin/route', ['-n', 'get', 'default']);
  const m = /gateway:\s*(\S+)/.exec(route.stdout);
  if (m) gateway = m[1];

  let ssid = '';
  const wifi = await exec('/usr/sbin/networksetup', ['-getairportnetwork', 'en0']);
  const sm = /Current Wi-Fi Network:\s*(.+)/.exec(wifi.stdout);
  if (sm) ssid = sm[1].trim();

  // Heuristic labels for MM ISPs (LAN/gateway/SSID hints)
  let isp = 'unknown';
  const blob = (gateway + ' ' + ssid + ' ' + wan.join(' ')).toLowerCase();
  if (/frontiir|myanma|mytel|mpt|atom|ooredoo|yatanar|united/.test(blob)) {
    if (/frontiir/.test(blob)) isp = 'Frontiir (MM)';
    else if (/mytel/.test(blob)) isp = 'Mytel (MM)';
    else if (/mpt/.test(blob)) isp = 'MPT (MM)';
    else if (/ooredoo/.test(blob)) isp = 'Ooredoo (MM)';
    else if (/atom/.test(blob)) isp = 'ATOM (MM)';
    else isp = 'Myanmar ISP (guess)';
  } else if (/192\.168\./.test(gateway)) {
    isp = 'home/office LAN';
  }

  return { isp, gateway, ssid, localIps: wan, hostname: os.hostname() };
}

/** Latency sample to a host (ICMP). */
function pingHost(host, count = 3) {
  return exec('/sbin/ping', ['-c', String(count), '-W', '2000', host], 12000).then((r) => {
    const avg = /=\s*([\d.]+)\/([\d.]+)\/([\d.]+)/.exec(r.stdout);
    const loss = /(\d+)% packet loss/.exec(r.stdout);
    return {
      host,
      ok: r.ok && /bytes from/.test(r.stdout),
      avgMs: avg ? parseFloat(avg[2]) : null,
      lossPct: loss ? parseInt(loss[1], 10) : (r.ok ? 0 : 100),
    };
  });
}

/** UDP reachability smoke to a WireGuard endpoint (best-effort). */
async function udpProbe(host, port = 51820) {
  return new Promise((resolve) => {
    const dgram = require('dgram');
    const s = dgram.createSocket('udp4');
    const t = setTimeout(() => { try { s.close(); } catch (_) {} resolve({ host, port, reachable: 'unknown', note: 'no reply (normal for WG)' }); }, 2000);
    s.on('error', () => { clearTimeout(t); try { s.close(); } catch (_) {} resolve({ host, port, reachable: false, note: 'udp error' }); });
    s.send(Buffer.alloc(148, 1), port, host, (err) => {
      clearTimeout(t);
      try { s.close(); } catch (_) {}
      resolve({ host, port, reachable: !err, note: err ? err.message : 'sent (no handshake expected)' });
    });
  });
}

/** Full network snapshot for the dashboard. */
async function networkSnapshot(locations = []) {
  const isp = await detectIsp();
  const targets = [
    { id: 'gateway', host: isp.gateway || '1.1.1.1' },
    { id: 'cloudflare', host: '1.1.1.1' },
    ...locations.filter((l) => l.endpoint).map((l) => ({
      id: l.id,
      host: String(l.endpoint).split(':')[0],
      name: l.name,
    })),
  ].filter((t) => t.host && /^\d+\.\d+\.\d+\.\d+$/.test(t.host) || t.id === 'cloudflare');

  const pings = [];
  for (const t of targets.slice(0, 5)) {
    pings.push(await pingHost(t.host, 2));
  }

  // Load persist log
  const histPath = require('path').join(os.homedir(), '.kasbah-vpn', 'net-history.jsonl');
  let history = [];
  try {
    history = fs.readFileSync(histPath, 'utf8').trim().split('\n').filter(Boolean).slice(-40).map((l) => JSON.parse(l));
  } catch { history = []; }

  const snap = {
    ts: new Date().toISOString(),
    isp,
    pings,
    historyLen: history.length,
  };
  try {
    fs.mkdirSync(require('path').dirname(histPath), { recursive: true });
    fs.appendFileSync(histPath, JSON.stringify(snap) + '\n');
  } catch (_) {}
  return { ...snap, history };
}

/**
 * Real egress IP/location probe — the single source of truth for "what is
 * our actual public egress right now". Every feature that signs or displays
 * a protection claim (pop:mint, commit:create-hidden, sitrep:get) MUST call
 * this rather than accept an egress object from the renderer: a caller with
 * IPC access could otherwise supply an arbitrary ip/loc/colo and get it
 * echoed back inside a "verified" proof or situation report.
 */
async function realEgressProbe() {
  try {
    // Belt-and-suspenders against reading our own local proxy's egress
    // instead of the real one: --noproxy '*' tells curl to ignore any
    // proxy for this request, and stripping the *_PROXY env vars covers
    // any spawned helper that doesn't honor --noproxy.
    const env = { ...process.env };
    for (const k of ['HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'https_proxy', 'http_proxy', 'all_proxy']) delete env[k];
    const text = await new Promise((resolve, reject) => {
      execFile('/usr/bin/curl', ['-sS', '--max-time', '8', '--noproxy', '*', 'https://1.1.1.1/cdn-cgi/trace'],
        { env }, (err, stdout) => (err ? reject(err) : resolve(stdout)));
    });
    const get = (k) => (text.match(new RegExp('^' + k + '=(.*)$', 'm')) || [])[1] || null;
    return { ok: true, ip: get('ip'), loc: get('loc'), colo: get('colo') };
  } catch (e) {
    return { ok: false, ip: null, loc: null, colo: null, error: e.message };
  }
}

/** Recommend exit: lowest ping among live locations. */
function recommendExit(pings = [], locations = []) {
  const byHost = {};
  for (const loc of locations) {
    const host = String(loc.endpoint || '').split(':')[0];
    if (host) byHost[host] = loc;
  }
  const scored = pings
    .filter((p) => p.ok && p.avgMs != null && byHost[p.host])
    .map((p) => ({ ...p, location: byHost[p.host] }))
    .sort((a, b) => a.avgMs - b.avgMs);
  return scored[0] || null;
}

module.exports = { detectIsp, pingHost, udpProbe, networkSnapshot, recommendExit, realEgressProbe };
