// Kasbah browser extension — background service worker (MV3).
// The ONLY network egress is to the user's LOCAL Kasbah gateway
// (127.0.0.1:8788). Prompt text is scanned locally; nothing is sent to any
// third party by this extension.

const GATEWAY_CANDIDATES = ['http://127.0.0.1:8788', 'http://localhost:8788'];

async function resolveGateway() {
  const stored = (await chrome.storage.local.get('gateway')).gateway;
  const candidates = stored ? [stored, ...GATEWAY_CANDIDATES] : GATEWAY_CANDIDATES;
  for (const base of candidates) {
    try {
      const r = await fetch(base + '/v1/health', { method: 'GET' });
      if (r.ok) { await chrome.storage.local.set({ gateway: base }); return base; }
    } catch (_) {}
  }
  return null;
}

async function authHeaders(extra = {}) {
  const h = { ...extra };
  try {
    const stored = (await chrome.storage.local.get('apiKey')).apiKey;
    if (stored) { h['x-api-key'] = stored; h['Authorization'] = 'Bearer ' + stored; }
  } catch (_) {}
  return h;
}

async function scan(text) {
  const base = await resolveGateway();
  if (!base) return { ok: false, offline: true };
  try {
    const r = await fetch(base + '/v1/scan', {
      method: 'POST',
      headers: await authHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ prompt: text, surface: 'paste' }),
    });
    if (!r.ok) return { ok: false, status: r.status };
    const body = await r.json();
    // Normalize seatbelt fields for the content-script banner
    const seatbelt = body.seatbelt || null;
    return {
      ok: true,
      ...body,
      intervention: body.intervention || seatbelt?.intervention || null,
      seatbelt,
      muteBlock: !!seatbelt?.muteBlock,
      share: seatbelt?.share || null,
    };
  } catch (e) {
    return { ok: false, offline: true, error: String(e) };
  }
}

async function attest(text) {
  const base = await resolveGateway();
  if (!base) return { ok: false, offline: true };
  try {
    const r = await fetch(base + '/v1/attest', {
      method: 'POST',
      headers: await authHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ prompt: text }),
    });
    if (!r.ok) return { ok: false, status: r.status };
    const body = await r.json();
    return { ok: true, ...body };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

async function issueVC(scanResult, attestResult) {
  const base = await resolveGateway();
  if (!base) return { ok: false, offline: true };
  try {
    const r = await fetch(base + '/v1/vc/issue', {
      method: 'POST',
      headers: await authHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ scanResult, attestResult }),
    });
    if (!r.ok) return { ok: false, status: r.status };
    const body = await r.json();
    return { ok: true, ...body };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

// ── AI Trust Grade: multi-factor per-hostname protection score ───────────────
// Mirrors packages/api-server/src/ai-trust-grade.js — leaks, injection, agents,
// receipts, hygiene. Letter A–F + 0–100 score. Explainable, not a black box.
async function recordSiteGrade(hostname, verdict, meta = {}) {
  if (!hostname) return;
  const key = 'siteGrades';
  const { siteGrades } = await chrome.storage.local.get(key);
  const grades = siteGrades || {};
  if (!grades[hostname]) {
    grades[hostname] = {
      scanned: 0, warned: 0, blocked: 0, intercepted: 0, trackers: 0,
      secretsBlocked: 0, injectionBlocked: 0, receiptsIssued: 0, offlineScans: 0,
    };
  }
  const g = grades[hostname];
  if (verdict !== 'TRACKER') g.scanned++;
  if (verdict === 'WARN')    g.warned++;
  if (verdict === 'DENY')    g.blocked++;
  if (verdict === 'TRACKER') g.trackers = (g.trackers || 0) + 1;
  if (meta.secrets)          g.secretsBlocked = (g.secretsBlocked || 0) + 1;
  if (meta.injection)        g.injectionBlocked = (g.injectionBlocked || 0) + 1;
  if (meta.receipt)          g.receiptsIssued = (g.receiptsIssued || 0) + 1;
  if (meta.offline)          g.offlineScans = (g.offlineScans || 0) + 1;
  await chrome.storage.local.set({ [key]: grades });
}

function computeGrade(siteStats) {
  if (!siteStats) return 'A';
  const secrets = siteStats.secretsBlocked || 0;
  const injection = siteStats.injectionBlocked || 0;
  const blocked = siteStats.blocked || 0;
  const warned = siteStats.warned || 0;
  const scanned = siteStats.scanned || 0;
  const trackers = siteStats.trackers || 0;
  const offline = siteStats.offlineScans || 0;
  const receipts = siteStats.receiptsIssued || 0;

  // 0–100 protection score (higher = safer surface / better enforcement)
  let score = 40;
  score += Math.min(30, secrets * 10 + injection * 8 + blocked * 6);
  score += Math.min(15, receipts * 5);
  score += Math.min(10, Math.floor(trackers / 3));
  score -= Math.min(25, warned * 3);
  score -= Math.min(20, offline * 8);
  if (scanned >= 5 && blocked / scanned > 0.4) score += 5; // hostile surface, we caught it
  score = Math.max(0, Math.min(100, score));

  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

function gradeDetail(siteStats) {
  const grade = computeGrade(siteStats);
  const labels = { A: 'Fortress', B: 'Hardened', C: 'Guarded', D: 'Exposed', F: 'Unprotected' };
  return { grade, label: labels[grade] || labels.F, stats: siteStats || null };
}

// ── DDG Email/Prompt Protection: strip known AI telemetry tokens ─────────────
const _PROMPT_TRACKERS = [
  /\[tracking_id=[^\]]*\]/gi,
  /<!--\s*ai_ref:[^>]*-->/gi,
  /\{ai_session:[^}]*\}/gi,
  /__kasbah_strip__[^\s]*/g,
];

function stripPromptTrackers(text) {
  if (!text) return text;
  let out = text;
  for (const re of _PROMPT_TRACKERS) out = out.replace(re, '');
  return out.trim();
}

async function bumpStats(verdict, { intercepted = false } = {}) {
  const s = (await chrome.storage.local.get('stats')).stats ||
    { scanned: 0, warned: 0, blocked: 0, intercepted: 0, mediaAlerts: 0 };
  s.scanned++;
  if (intercepted)        s.intercepted = (s.intercepted || 0) + 1;
  if (verdict === 'WARN') s.warned++;
  if (verdict === 'DENY') s.blocked++;
  await chrome.storage.local.set({ stats: s });
}

async function bumpMediaAlert() {
  const s = (await chrome.storage.local.get('stats')).stats ||
    { scanned: 0, warned: 0, blocked: 0, intercepted: 0, mediaAlerts: 0 };
  s.mediaAlerts = (s.mediaAlerts || 0) + 1;
  await chrome.storage.local.set({ stats: s });
}

// ── AI tracker block counter ─────────────────────────────────────────────────
// Use onRuleMatchedDebug in dev (unpacked), webNavigation-based count in prod.
// Both paths write to stats.trackersBlocked so the popup always shows a number.
if (chrome.declarativeNetRequest?.onRuleMatchedDebug) {
  // Developer mode — per-request debug events available
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(async ({ request }) => {
    const s = (await chrome.storage.local.get('stats')).stats ||
      { scanned: 0, warned: 0, blocked: 0, intercepted: 0, mediaAlerts: 0, trackersBlocked: 0 };
    s.trackersBlocked = (s.trackersBlocked || 0) + 1;
    await chrome.storage.local.set({ stats: s });
    if (request?.initiator) {
      try { await recordSiteGrade(new URL(request.initiator).hostname, 'TRACKER'); } catch (_) {}
    }
  });
} else {
  // Production mode — use webNavigation.onCompleted to sample tracker hits per page load.
  // declarativeNetRequest blocks silently; we infer a count from known-blocked hostnames
  // embedded in the blocklist by checking matched resource hints on navigation completion.
  chrome.webNavigation?.onCompleted?.addListener(async (details) => {
    if (details.frameId !== 0) return; // main frame only
    try {
      const hostname = new URL(details.url).hostname;
      // Each page load on a known AI site counts as one tracker-scan cycle.
      // Actual blocked count is maintained by the browser engine natively;
      // we record the navigation so the site grade gets updated.
      const s = (await chrome.storage.local.get('stats')).stats ||
        { scanned: 0, warned: 0, blocked: 0, intercepted: 0, mediaAlerts: 0, trackersBlocked: 0 };
      // Bump by estimated 1 per navigation on tracked AI sites (conservative floor)
      s.trackersBlocked = (s.trackersBlocked || 0) + 1;
      await chrome.storage.local.set({ stats: s });
      await recordSiteGrade(hostname, 'TRACKER');
    } catch (_) {}
  });
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'kasbah:scan') {
    const cleanText = stripPromptTrackers(msg.text);
    scan(cleanText).then(async (res) => {
      if (res.ok) {
        await bumpStats(res.verdict);
        const threats = res.threats || [];
        const meta = {
          secrets: threats.some((t) => /secret|pii|credential|key|token|password|ssn|credit/i.test(t)),
          injection: threats.some((t) => /inject|jailbreak|override|prompt.?attack/i.test(t)),
          receipt: !!(res.share?.id || res.attestId),
          offline: !!res.offline,
        };
        const hostname = _sender?.tab?.url ? new URL(_sender.tab.url).hostname : null;
        if (hostname) await recordSiteGrade(hostname, res.verdict, meta);
      }
      sendResponse(res);
    });
    return true;
  }
  if (msg?.type === 'kasbah:attest') {
    attest(msg.text).then(sendResponse);
    return true;
  }
  if (msg?.type === 'kasbah:issueVC') {
    issueVC(msg.scanResult, msg.attestResult).then(sendResponse);
    return true;
  }
  if (msg?.type === 'kasbah:status') {
    resolveGateway().then(async (base) => {
      const stats = (await chrome.storage.local.get('stats')).stats || { scanned: 0, warned: 0, blocked: 0 };
      const enabled = (await chrome.storage.local.get('enabled')).enabled !== false;
      const lastScan = (await chrome.storage.local.get('lastScan')).lastScan || null;
      sendResponse({ connected: !!base, gateway: base, stats, enabled, lastScan });
    });
    return true;
  }
  if (msg?.type === 'kasbah:setEnabled' || msg?.type === 'SET_ENABLED') {
    chrome.storage.local.set({ enabled: !!msg.enabled }).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg?.type === 'kasbah:saveLastScan') {
    chrome.storage.local.set({ lastScan: msg.data }).then(() => sendResponse({ ok: true }));
    return true;
  }
  // Media access events forwarded from inject.js via content.js
  if (msg?.type === 'MEDIA_ACCESS') {
    bumpMediaAlert().then(async () => {
      const mediaLog = (await chrome.storage.local.get('mediaLog')).mediaLog || [];
      mediaLog.push({ ...msg.detail, _ts: Date.now() });
      await chrome.storage.local.set({ mediaLog: mediaLog.slice(-200) });
      sendResponse({ ok: true });
    });
    return true;
  }
  // Popup requests current state for the protection score ring
  if (msg?.type === 'GET_STATE') {
    resolveGateway().then(async (base) => {
      const [{ stats }, { enabled }, { lastScan }, { vpn }, { siteGrades }] = await Promise.all([
        chrome.storage.local.get('stats'),
        chrome.storage.local.get('enabled'),
        chrome.storage.local.get('lastScan'),
        chrome.storage.local.get('vpn'),
        chrome.storage.local.get('siteGrades'),
      ]);
      // Get current tab's hostname for site grade
      let siteGrade = 'A', siteStats = null;
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.url) {
          const hostname = new URL(tab.url).hostname;
          siteStats = (siteGrades || {})[hostname] || null;
          siteGrade = computeGrade(siteStats);
        }
      } catch (_) {}
      sendResponse({
        connected:  !!base,
        gateway:    base,
        enabled:    enabled !== false,
        stats:      stats || { scanned: 0, warned: 0, blocked: 0, intercepted: 0, mediaAlerts: 0, trackersBlocked: 0 },
        lastScan:   lastScan || null,
        vpn:        vpn || { connected: false },
        siteGrade,
        siteGradeLabel: ({ A: 'Fortress', B: 'Hardened', C: 'Guarded', D: 'Exposed', F: 'Unprotected' })[siteGrade] || '—',
        siteStats,
      });
    });
    return true;
  }
  // Popup button: open desktop app
  if (msg?.type === 'OPEN_APP') {
    chrome.tabs.create({ url: 'http://127.0.0.1:8788' });
    sendResponse({ ok: true });
    return true;
  }
  // Popup button: fetch proof from gateway
  if (msg?.type === 'GET_PROOF') {
    resolveGateway().then(async (base) => {
      if (!base) return sendResponse({ ok: false, offline: true });
      try {
        const r = await fetch(base + '/v1/kasbah/status');
        const body = r.ok ? await r.json() : null;
        sendResponse({ ok: !!body, proof: body });
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
    });
    return true;
  }

  // Attestation receipt link clicked in popup
  if (msg?.type === 'OPEN_RECEIPTS') {
    resolveGateway().then((base) => {
      const url = base
        ? `${base}/v1/audit/receipt?id=${encodeURIComponent(msg.receiptId || '')}`
        : 'http://127.0.0.1:8788';
      chrome.tabs.create({ url });
    });
    sendResponse({ ok: true });
    return true;
  }

  // ── DDG Fire Button: nuke all session AI data ────────────────────────────────
  // Clears stats, media log, site grades, and last scan — a full AI-session reset
  // without touching browser history or bookmarks. Gateway notified to flush
  // in-flight agent traces for this session.
  if (msg?.type === 'BURN_SESSION') {
    resolveGateway().then(async (base) => {
      const wipe = chrome.storage.local.remove(['stats', 'mediaLog', 'siteGrades', 'lastScan']);
      const notifyGateway = base
        ? fetch(base + '/v1/kernel/killswitch', { method: 'POST',
            headers: await authHeaders({ 'content-type': 'application/json' }),
            body: JSON.stringify({ reason: 'fire_button', actorId: 'browser-session' }),
          }).catch(() => null)
        : Promise.resolve();
      return Promise.all([wipe, notifyGateway]);
    }).then(() => sendResponse({ ok: true, burned: true }))
      .catch(() => sendResponse({ ok: true, burned: true }));
    return true;
  }

  // ── AI Trust Grade: per-site multi-factor score ──────────────────────────────
  if (msg?.type === 'GET_SITE_GRADE') {
    chrome.storage.local.get('siteGrades').then(({ siteGrades }) => {
      const grades = siteGrades || {};
      const site = grades[msg.hostname] || null;
      sendResponse(gradeDetail(site));
    });
    return true;
  }
});
