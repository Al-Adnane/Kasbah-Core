'use strict';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function $(id) { return document.getElementById(id); }

function setDot(dotEl, level) {
  dotEl.className = 'dot';
  if (level === 'green')  dotEl.classList.add('dot-green');
  if (level === 'amber')  dotEl.classList.add('dot-amber');
  if (level === 'red')    dotEl.classList.add('dot-red');
  if (level === 'grey')   dotEl.classList.add('dot-grey');
}

const CIRCUMFERENCE = 2 * Math.PI * 40; // r=40 → 251.2

function setRing(score, color) {
  const fill   = $('ring-fill');
  const offset = CIRCUMFERENCE * (1 - score / 100);
  fill.style.strokeDashoffset = offset;
  fill.style.stroke = color;
  $('ring-score').textContent = Math.round(score);
  $('ring-score').style.color = color;
}

// ─── Stats storage ────────────────────────────────────────────────────────────

const STATS_KEY = 'kasbah_stats';

function loadStats() {
  try { return JSON.parse(localStorage.getItem(STATS_KEY) || '{}'); }
  catch { return {}; }
}

// ─── Protection score render ──────────────────────────────────────────────────

function renderScore(score) {
  const tierMap = {
    protected: { label: 'Protected', color: '#22c55e' },
    degraded:  { label: 'Degraded',  color: '#f59e0b' },
    'at-risk': { label: 'At Risk',   color: '#ef4444' },
    critical:  { label: 'Critical',  color: '#a855f7' },
  };
  const tier = score >= 85 ? 'protected'
             : score >= 60 ? 'degraded'
             : score >= 35 ? 'at-risk'
             : 'critical';
  const { label, color } = tierMap[tier];
  setRing(score, color);
  $('ring-tier').textContent = label;
}

// ─── VPN status ───────────────────────────────────────────────────────────────

function renderVpn(state) {
  const dot  = $('dot-vpn');
  const text = $('vpn-text');
  if (!state || state.status === 'disconnected' || state.status === undefined) {
    setDot(dot, 'grey');
    text.textContent = 'Off';
  } else if (state.status === 'connected') {
    setDot(dot, 'green');
    text.textContent = state.location || 'On';
  } else if (state.status === 'degraded') {
    setDot(dot, 'amber');
    text.textContent = 'Degraded';
  } else {
    setDot(dot, 'red');
    text.textContent = 'Error';
  }
}

// ─── Gateway (agent-guard) status ─────────────────────────────────────────────

function renderGateway(enabled) {
  const dot  = $('dot-gw');
  const text = $('gw-text');
  if (enabled) {
    setDot(dot, 'green');
    text.textContent = 'Active';
  } else {
    setDot(dot, 'grey');
    text.textContent = 'Off';
  }
}

// ─── AI shield status ─────────────────────────────────────────────────────────

function renderShield(enabled, blocked) {
  const dot  = $('dot-shield');
  const text = $('shield-text');
  if (!enabled) {
    setDot(dot, 'grey');
    text.textContent = 'Off';
    return;
  }
  if (blocked > 0) {
    setDot(dot, 'amber');
    text.textContent = `${blocked} blocked`;
  } else {
    setDot(dot, 'green');
    text.textContent = 'Scanning';
  }
}

// ─── Last scan result ─────────────────────────────────────────────────────────

function renderLastScan(scan) {
  if (!scan) return;
  const wrap    = $('last-scan-wrap');
  const badge   = $('ls-verdict');
  const threats = $('ls-threats');
  const attest  = $('ls-attest');

  wrap.style.display = 'block';

  const verdictClass = scan.verdict === 'DENY'  ? 'vb-deny'
                     : scan.verdict === 'WARN'  ? 'vb-warn'
                     : 'vb-allow';
  badge.className = 'verdict-badge ' + verdictClass;
  badge.textContent = scan.verdict || 'ALLOW';

  if (scan.threats && scan.threats.length) {
    threats.textContent = scan.threats.join(' · ');
  } else {
    threats.textContent = 'No threats detected';
  }

  if (scan.receiptId) {
    attest.textContent = `Receipt: ${scan.receiptId.slice(0, 16)}…  ↗`;
    attest.onclick = () => {
      chrome.runtime.sendMessage({ type: 'OPEN_RECEIPTS', receiptId: scan.receiptId });
    };
  } else {
    attest.textContent = '';
  }
}

// ─── Enable toggle ────────────────────────────────────────────────────────────

const enabledToggle = $('enabled');
const enabledLabel  = $('enabled-label');

chrome.storage.local.get(['enabled'], (res) => {
  const on = res.enabled !== false;
  enabledToggle.checked = on;
  enabledLabel.textContent = on ? 'On' : 'Off';
});

const keyInput = $('api-key');
chrome.storage.local.get(['apiKey'], (res) => { if (res.apiKey) { keyInput.value = res.apiKey; $('key-msg').textContent = 'Key saved — strict gateways will accept scans.'; } });
$('btn-key').addEventListener('click', () => {
  const v = (keyInput.value || '').trim();
  chrome.storage.local.set({ apiKey: v }, () => { $('key-msg').textContent = v ? 'Key saved.' : 'Key cleared — local mode.'; });
});

enabledToggle.addEventListener('change', () => {
  const on = enabledToggle.checked;
  enabledLabel.textContent = on ? 'On' : 'Off';
  chrome.storage.local.set({ enabled: on });
  chrome.runtime.sendMessage({ type: 'SET_ENABLED', enabled: on });
});

// ─── Buttons ──────────────────────────────────────────────────────────────────

$('btn-open').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'OPEN_APP' });
  window.close();
});

$('btn-proof').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'GET_PROOF' }, (resp) => {
    const btn = $('btn-proof');
    if (resp && resp.ok) {
      btn.classList.add('active');
      btn.textContent = 'Proof ✓';
      setTimeout(() => {
        btn.classList.remove('active');
        btn.textContent = 'Get Proof';
      }, 3000);
    }
  });
});

// ─── Site grade badge (DDG Privacy Grade) ────────────────────────────────────

const GRADE_COLOR = { A: '#22c55e', B: '#84cc16', C: '#f59e0b', D: '#ef4444' };

function renderSiteGrade(grade, siteStats) {
  const el = $('site-grade');
  if (!el) return;
  el.textContent = grade || 'A';
  el.style.background = GRADE_COLOR[grade] || GRADE_COLOR['A'];
  const trackers = siteStats?.trackers || 0;
  const tip = $('site-grade-tip');
  if (tip) tip.textContent = trackers > 0 ? `${trackers} tracker${trackers > 1 ? 's' : ''} blocked` : 'No trackers detected';
}

// ─── Burn session button (DDG Fire Button) ────────────────────────────────────

const burnBtn = $('btn-burn');
if (burnBtn) {
  burnBtn.addEventListener('click', () => {
    if (!confirm('AI Session Burn: wipe all AI session data, media log, and active agent traces?')) return;
    burnBtn.textContent = '🔥 Burning…';
    burnBtn.disabled = true;
    chrome.runtime.sendMessage({ type: 'BURN_SESSION' }, () => {
      burnBtn.textContent = '✓ Burned';
      setTimeout(() => {
        burnBtn.textContent = 'AI Session Burn';
        burnBtn.disabled = false;
      }, 2000);
    });
  });
}

// ─── Main data load ───────────────────────────────────────────────────────────

chrome.runtime.sendMessage({ type: 'GET_STATE' }, (state) => {
  if (!state) {
    renderScore(0);
    renderGateway(false);
    renderVpn(null);
    renderShield(false, 0);
    renderSiteGrade('A', null);
    return;
  }

  const enabled = state.enabled !== false;
  renderGateway(enabled);
  renderVpn(state.vpn);
  renderShield(enabled, state.stats?.blocked || 0);
  renderSiteGrade(state.siteGrade || 'A', state.siteStats);

  // Protection score: base + VPN + tracker evidence + site grade penalty
  const gradeDeduct = { A: 0, B: 5, C: 15, D: 30 };
  let score = 0;
  if (enabled) {
    score += 25;  // AI shield on
    score += 20;  // fingerprint resistance always on
    if (state.vpn?.status === 'connected')   score += 25;
    else if (state.vpn?.status === 'degraded') score += 10;
    if (state.stats?.blocked > 0 || state.stats?.warned > 0) score += 15;
    else score += 10;
    if ((state.stats?.trackersBlocked || 0) > 0) score += 5; // tracker blocking is active
    score -= (gradeDeduct[state.siteGrade] || 0); // worse grade = lower score on this site
  }
  renderScore(Math.max(0, Math.min(score, 100)));

  // Stats row — add trackersBlocked
  const stats = state.stats || {};
  $('s-scanned').textContent  = (stats.scanned        || 0).toLocaleString();
  $('s-trackers').textContent = (stats.trackersBlocked || 0).toLocaleString();
  $('s-blocked').textContent  = (stats.blocked        || 0).toLocaleString();
  $('s-warned').textContent   = (stats.warned         || 0).toLocaleString();

  renderLastScan(state.lastScan);
});
