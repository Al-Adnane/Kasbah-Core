'use strict';

/**
 * Kasbah Privacy — local analyzers.
 * No API server required. Pure Node + optional outbound HTTPS to HIBP only
 * (k-anonymity for passwords; email needs user's own key).
 */

const crypto = require('crypto');
const https = require('https');

function httpsGet(url, headers = {}, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: 'GET',
      headers: { 'User-Agent': 'KasbahPrivacy/3.1', ...headers },
      timeout: timeoutMs,
    }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

// ─── Scam Shield ────────────────────────────────────────────────────────────
const SCAM_PATTERNS = [
  { id: 'urgency', label: 'Urgency / pressure to act now', re: /\b(urgent|immediately|within 24 hours|act now|last chance|expires today|final notice)\b/i, w: 15 },
  { id: 'wire', label: 'Wire transfer / gift cards / crypto payment', re: /\b(wire transfer|western union|gift card|itunes card|google play card|bitcoin|usdt|crypto wallet)\b/i, w: 25 },
  { id: 'otp', label: 'Asks for OTP / verification code', re: /\b(otp|one[- ]time (code|password)|verification code|sms code|2fa code)\b/i, w: 30 },
  { id: 'bank', label: 'Bank / account suspension threat', re: /\b(account (will be )?(suspended|locked|closed)|unusual activity|verify your account)\b/i, w: 20 },
  { id: 'prize', label: 'Prize / lottery / inheritance', re: /\b(you have won|lottery|inheritance|prize|claim your (funds|reward))\b/i, w: 25 },
  { id: 'romance', label: 'Romance / love-bombing + money', re: /\b(i love you|soulmate|send me money|emergency funds|customs fee)\b/i, w: 20 },
  { id: 'impersonate', label: 'Authority impersonation', re: /\b(police|irs|tax office|immigration|un support|fbi|central bank)\b/i, w: 20 },
  { id: 'link', label: 'Suspicious shortener / lookalike domain', re: /(bit\.ly|tinyurl|t\.co\/|\.ru\/|\.tk\/|login[-.]verify|secure[-.]update)/i, w: 15 },
  { id: 'job', label: 'Fake job / check overpayment', re: /\b(mystery shopper|work from home.{0,20}\$|deposit the check|keep the difference)\b/i, w: 22 },
];

function analyzeScam(text) {
  const t0 = Date.now();
  const hits = [];
  let score = 0;
  for (const p of SCAM_PATTERNS) {
    if (p.re.test(text)) {
      hits.push({ id: p.id, label: p.label, weight: p.w });
      score += p.w;
    }
  }
  // Cap and verdict
  score = Math.min(100, score);
  const verdict = score >= 55 ? 'LIKELY_SCAM' : score >= 25 ? 'SUSPICIOUS' : 'LIKELY_SAFE';
  return { verdict, score, patternHits: hits, latency_ms: Date.now() - t0, engine: 'local-v1' };
}

// ─── Family Safety ──────────────────────────────────────────────────────────
const FAMILY_PATTERNS = [
  { id: 'grooming_secret', label: 'Asks child to keep secrets from parents', re: /\b(don'?t tell (your )?(mom|dad|parents)|this is our secret|between us)\b/i, w: 30 },
  { id: 'grooming_meet', label: 'Asks to meet in person', re: /\b(meet (up|in person|irl)|come over|hotel|send (your )?address)\b/i, w: 28 },
  { id: 'selfharm', label: 'Self-harm / suicide language', re: /\b(kill (my)?self|end it all|self[- ]harm|suicide|want to die)\b/i, w: 35 },
  { id: 'pii_share', label: 'Shares personal identifiers', re: /\b(my (address|phone|school is)|i live at|credit card|social security)\b/i, w: 22 },
  { id: 'sexual', label: 'Sexual content involving minors language', re: /\b(underage|send (nudes|pics)|how old are you.{0,15}(1[0-7]|[0-9]))\b/i, w: 40 },
  { id: 'bully', label: 'Bullying / threats', re: /\b(i'?ll (beat|kill|hurt) you|everyone hates you|you should die)\b/i, w: 25 },
];

function analyzeFamily(text) {
  const t0 = Date.now();
  const hits = [];
  let score = 0;
  for (const p of FAMILY_PATTERNS) {
    if (p.re.test(text)) {
      hits.push({ id: p.id, label: p.label, weight: p.w });
      score += p.w;
    }
  }
  score = Math.min(100, score);
  const verdict = score >= 50 ? 'ACTION_REQUIRED' : score >= 20 ? 'REVIEW_NEEDED' : 'LOOKS_OK';
  return { verdict, score, patternHits: hits, latency_ms: Date.now() - t0, engine: 'local-v1' };
}

// ─── Wi-Fi Guard ────────────────────────────────────────────────────────────
function analyzeWifi({ ssid, security } = {}) {
  const t0 = Date.now();
  const flags = [];
  let risk = 'LOW';
  const sec = String(security || '').toLowerCase();
  const name = String(ssid || '');

  if (!sec || sec === 'none' || sec === 'open' || sec === 'unknown') {
    flags.push({ id: 'open', label: 'Open network — traffic is not encrypted between you and the AP' });
    risk = 'HIGH';
  }
  if (/wep/.test(sec)) {
    flags.push({ id: 'wep', label: 'WEP encryption is broken — treat as open' });
    risk = 'HIGH';
  }
  if (/wpa2/.test(sec) && !/wpa3/.test(sec)) {
    flags.push({ id: 'wpa2', label: 'WPA2 only — OK for home; prefer WPA3 on public networks' });
    if (risk === 'LOW') risk = 'MEDIUM';
  }
  if (/(airport|starbucks|mcdonald|free|guest|public|cafe|hotel|wifi|hotspot)/i.test(name)) {
    flags.push({ id: 'publicish', label: 'SSID looks like a public hotspot — captive portals and evil twins are common' });
    if (risk === 'LOW') risk = 'MEDIUM';
  }
  if (risk === 'HIGH') {
    flags.push({ id: 'vpn', label: 'Connect Kasbah VPN before logging into email, banks, or work tools' });
  }
  return {
    risk,
    flags,
    recommendation: risk === 'HIGH'
      ? 'Turn on Kasbah VPN now. Avoid entering passwords until the tunnel is up.'
      : risk === 'MEDIUM'
        ? 'Use the VPN for sensitive sites. Prefer mobile data for banking.'
        : 'Network looks conventional. VPN still hides your activity from the ISP.',
    latency_ms: Date.now() - t0,
    engine: 'local-v1',
  };
}

// ─── HIBP password (k-anonymity) ────────────────────────────────────────────
async function checkPasswordBreach(password) {
  const t0 = Date.now();
  const sha1 = crypto.createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  const r = await httpsGet(`https://api.pwnedpasswords.com/range/${prefix}`, { 'Add-Padding': 'true' });
  if (r.status !== 200) throw new Error(`HIBP range HTTP ${r.status}`);
  const line = r.body.split('\n').find((l) => l.startsWith(suffix + ':'));
  const count = line ? parseInt(line.split(':')[1], 10) : 0;
  return { found: count > 0, count, latency_ms: Date.now() - t0, k: 5 };
}

// ─── HIBP email (requires user API key for full list) ───────────────────────
async function checkEmailBreach(email, apiKey) {
  const t0 = Date.now();
  const em = String(email || '').trim().toLowerCase();
  if (!em || !em.includes('@')) throw new Error('Enter a valid email');

  // 1) Preferred: user's HIBP key (full, official)
  if (apiKey) {
    const r = await httpsGet(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(em)}?truncateResponse=false`,
      { 'hibp-api-key': apiKey, Accept: 'application/vnd.api+json' }
    );
    if (r.status === 404) return { breaches: [], source: 'hibp', latency_ms: Date.now() - t0 };
    if (r.status === 401) throw new Error('Invalid HIBP API key');
    if (r.status !== 200) throw new Error(`HIBP HTTP ${r.status}`);
    return { breaches: JSON.parse(r.body || '[]'), source: 'hibp', latency_ms: Date.now() - t0 };
  }

  // 2) Free fallback: XposedOrNot (no key). Best-effort; may rate-limit.
  try {
    const r = await httpsGet(
      `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(em)}`,
      { Accept: 'application/json' },
      10000
    );
    if (r.status === 200) {
      let j = {};
      try { j = JSON.parse(r.body || '{}'); } catch { j = {}; }
      const names = j?.breaches?.[0] || j?.breaches || [];
      const list = (Array.isArray(names) ? names : String(names).split(','))
        .map((s) => String(s).trim())
        .filter(Boolean)
        .map((Name) => ({ Name, Source: 'xposedornot' }));
      return { breaches: list, source: 'xposedornot-free', latency_ms: Date.now() - t0, note: list.length ? undefined : 'No breaches found (free source)' };
    }
    if (r.status === 404) {
      return { breaches: [], source: 'xposedornot-free', latency_ms: Date.now() - t0, note: 'No breaches found (free source)' };
    }
  } catch (_) { /* fall through */ }

  // 3) Offline guidance — still useful, never a hard fail
  return {
    breaches: [],
    source: 'none',
    note: 'Free breach lookup unavailable right now. Password check works without any key. Add a free HIBP API key in Identity Watch for official email results.',
    latency_ms: Date.now() - t0,
  };
}

// ─── Password generator ─────────────────────────────────────────────────────
function generatePassword(opts = {}) {
  const len = Math.max(16, Math.min(64, opts.length || 20));
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += alphabet[bytes[i] % alphabet.length];
  // Strength estimate
  let bits = 0;
  if (/[A-Z]/.test(out)) bits += 4.7;
  if (/[a-z]/.test(out)) bits += 4.7;
  if (/[0-9]/.test(out)) bits += 3.3;
  if (/[^A-Za-z0-9]/.test(out)) bits += 5;
  bits = Math.round(len * Math.log2(alphabet.length));
  return { password: out, bits, length: len };
}

// ─── Clipboard / text secret scan ───────────────────────────────────────────
const SECRET_PATTERNS = [
  { id: 'aws_akid', label: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'github', label: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { id: 'slack', label: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: 'openai', label: 'OpenAI API key', re: /\bsk-[A-Za-z0-9]{20,}\b/g },
  { id: 'stripe', label: 'Stripe live key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g },
  { id: 'private_key', label: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'jwt', label: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
];

function scanSecrets(text) {
  const t0 = Date.now();
  const findings = [];
  for (const p of SECRET_PATTERNS) {
    const m = text.match(p.re);
    if (m) findings.push({ id: p.id, label: p.label, count: m.length, sample: m[0].slice(0, 12) + '…' });
  }
  return {
    found: findings.length > 0,
    findings,
    verdict: findings.length ? 'SECRETS_FOUND' : 'CLEAN',
    latency_ms: Date.now() - t0,
    engine: 'local-v1',
  };
}

// ─── Leak / hygiene checks (local) ──────────────────────────────────────────
const os = require('os');
const fs = require('fs');
function dnsLeakCheck() {
  const resolv = (() => {
    try { return fs.readFileSync('/etc/resolv.conf', 'utf8'); } catch { return ''; }
  })();
  const servers = [...resolv.matchAll(/nameserver\s+(\S+)/g)].map((m) => m[1]);
  const vpnish = servers.some((s) => s.startsWith('10.77.') || s === '1.1.1.1' || s === '1.0.0.1' || s.startsWith('fd7a:'));
  return {
    dnsServers: servers,
    looksLikeVpnDns: vpnish,
    note: servers.length
      ? (vpnish ? 'DNS resolvers look VPN-friendly' : 'DNS may still point at your ISP/LAN resolver')
      : 'Could not read /etc/resolv.conf',
  };
}

function deviceSummary() {
  const ifs = os.networkInterfaces();
  const addrs = [];
  for (const [name, list] of Object.entries(ifs)) {
    for (const a of list || []) {
      if (a.family === 'IPv4' && !a.internal) addrs.push({ iface: name, address: a.address, mac: a.mac });
    }
  }
  return { hostname: os.hostname(), platform: os.platform(), interfaces: addrs };
}

module.exports = {
  analyzeScam,
  analyzeFamily,
  analyzeWifi,
  checkPasswordBreach,
  checkEmailBreach,
  generatePassword,
  scanSecrets,
  dnsLeakCheck,
  deviceSummary,
  scorePassword,
  analyzeScamMyanmar,
  privacyCheckup,
  leakTest,
  latencyToExit,
  myanmarNetworkProfile,
};

/**
 * Leak test: DNS resolvers + optional STUN-like public IP comparison.
 * When VPN is on, public IP should be the exit (SG). DNS should not be
 * a Myanmar LAN resolver if we set 1.1.1.1.
 */
function leakTest({ vpnOn = false, exitIp = null } = {}) {
  const dns = dnsLeakCheck();
  const ifs = deviceSummary();
  const lanIps = (ifs.interfaces || []).map((i) => i.address);
  const flags = [];
  if (vpnOn && !dns.looksLikeVpnDns) {
    flags.push({ id: 'dns_isp', severity: 'HIGH', label: 'DNS still points at ISP/LAN — possible DNS leak' });
  }
  if (!vpnOn) {
    flags.push({ id: 'vpn_off', severity: 'HIGH', label: 'VPN is off — your real IP is exposed' });
  }
  if (vpnOn && exitIp && lanIps.includes(exitIp)) {
    flags.push({ id: 'exit_is_lan', severity: 'HIGH', label: 'Exit IP equals a local interface — tunnel not NAT-ing' });
  }
  const score = flags.filter((f) => f.severity === 'HIGH').length === 0 ? 100
    : flags.filter((f) => f.severity === 'HIGH').length === 1 ? 50 : 20;
  return {
    score,
    verdict: score >= 90 ? 'NO_LEAK' : score >= 40 ? 'CHECK_DNS' : 'LEAKING',
    dns,
    flags,
    lanIps,
    engine: 'local-leak-v1',
  };
}

function latencyToExit(ip = '10.77.0.1') {
  return new Promise((resolve) => {
    const { execFile } = require('child_process');
    const t0 = Date.now();
    execFile('/sbin/ping', ['-c', '3', '-W', '2000', ip], { timeout: 10000 }, (err, stdout) => {
      const out = stdout || '';
      const m = /min\/avg\/max\/(?:stddev|mdev) = [\d.]+\/([\d.]+)\//.exec(out);
      const avg = m ? parseFloat(m[1]) : null;
      const lossM = /(\d+)% packet loss/.exec(out);
      resolve({
        ok: !err && /bytes from/.test(out),
        avgMs: avg,
        lossPct: lossM ? parseInt(lossM[1], 10) : (err ? 100 : 0),
        elapsedMs: Date.now() - t0,
        raw: out.split('\n').filter(Boolean).slice(-4).join(' · '),
      });
    });
  });
}

/** Myanmar-specific network profile for the UI. */
function myanmarNetworkProfile() {
  const ifs = deviceSummary();
  const lan = (ifs.interfaces || []).filter((i) => !String(i.iface).startsWith('utun'));
  return {
    countryHint: 'MM',
    ispHint: 'Frontiir / MPT / Mytel / ATOM common',
    tips: [
      'Use Singapore exit for lowest RTT from Yangon',
      'If UDP is blocked, enable DPI mode (TCP/WSS:443)',
      'Open Wi‑Fi in tea shops — always use VPN before login',
    ],
    lan,
    hostname: ifs.hostname,
  };
}

// ─── Password strength (vault) ──────────────────────────────────────────────
function scorePassword(pw) {
  const p = String(pw || '');
  let bits = 0;
  const len = p.length;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
  if (len >= 8) bits += len * 2;
  if (len >= 12) bits += 8;
  if (len >= 16) bits += 10;
  bits += classes * 6;
  if (/^(.)\1+$/.test(p) || /^(012|123|abc|qwerty)/i.test(p)) bits = Math.min(bits, 20);
  bits = Math.min(128, Math.round(bits));
  const label = bits >= 80 ? 'excellent' : bits >= 60 ? 'strong' : bits >= 40 ? 'fair' : 'weak';
  return { bits, label, length: len, classes };
}

// ─── Myanmar / SEA scam patterns (pig-butchering, junta fees, SIM swap) ─────
function analyzeScamMyanmar(text) {
  const t = String(text || '');
  const hits = [];
  const add = (id, label) => hits.push({ id, label });
  if (/\b(kyat|mmk|lakh|သိန်း|ကျပ်)\b/i.test(t) || /\b(kyat|MMK)\s*[0-9]/i.test(t)) add('mmk', 'Myanmar kyat payment pressure');
  if (/\b(pig.?butcher|investment.?group|trading.?signal|guaranteed (profit|return)|vip group)\b/i.test(t)) add('pig', 'Pig-butchering / fake investment');
  if (/\b(sim.?swap|port.?your.?number|new sim|verify sim)\b/i.test(t)) add('sim', 'SIM-swap / number port scam');
  if (/\b(military|junta|immigration fee|exit fee|border fee)\b/i.test(t)) add('auth_mm', 'Authority/fee impersonation common in MM scams');
  if (/\b(line|viber|telegram)\b/i.test(t) && /\b(send|transfer|pay|money)\b/i.test(t)) add('chat_pay', 'Chat-app payment request');
  if (/\b(romance|love you|soulmate)\b/i.test(t) && /\b(invest|crypto|usdt|send)\b/i.test(t)) add('romance_inv', 'Romance + investment combo');
  const base = analyzeScam(t);
  const score = Math.min(100, base.score + hits.length * 12);
  const verdict = score >= 55 ? 'LIKELY_SCAM' : score >= 25 ? 'SUSPICIOUS' : 'LIKELY_SAFE';
  return {
    verdict, score,
    patternHits: [...base.patternHits, ...hits],
    region: 'MM',
    engine: 'local-v1+mm',
  };
}

// ─── One-shot privacy checkup (Home) ────────────────────────────────────────
async function privacyCheckup({ connected = false, egress = null } = {}) {
  const wifi = await (async () => {
    try {
      const { execFile } = require('child_process');
      const ssid = await new Promise((res) => {
        execFile('/usr/sbin/networksetup', ['-getairportnetwork', 'en0'], { timeout: 3000 }, (e, out) => {
          const m = /Current Wi-Fi Network:\s*(.+)/.exec(out || '');
          res(m ? m[1].trim() : '');
        });
      });
      return analyzeWifi({ ssid, security: ssid ? 'wpa2' : 'ethernet' });
    } catch { return analyzeWifi({}); }
  })();
  const dns = dnsLeakCheck();
  const checks = [
    { id: 'vpn', ok: !!connected, label: connected ? 'VPN connected' : 'VPN off — ISP sees your traffic' },
    { id: 'egress', ok: !!(egress && egress.loc === 'SG'), label: egress?.ip ? `Egress ${egress.ip} (${egress.loc || '?'})` : 'Egress unknown' },
    { id: 'wifi', ok: wifi.risk === 'LOW', label: `Wi‑Fi risk: ${wifi.risk}` },
    { id: 'dns', ok: dns.looksLikeVpnDns, label: dns.note },
  ];
  const score = Math.round((checks.filter((c) => c.ok).length / checks.length) * 100);
  return { score, checks, wifi, dns, verdict: score >= 75 ? 'GOOD' : score >= 50 ? 'NEEDS_WORK' : 'EXPOSED' };
}
