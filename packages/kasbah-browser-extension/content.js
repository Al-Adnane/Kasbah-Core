// Kasbah content script — injects the "Governed by Kasbah" badge, scans the
// prompt before submission, provides real-time typing scan, and bridges the
// page-world inject.js intercept to the background worker.
// Fail-open: if the local gateway is unreachable the user is never blocked.

(() => {
  // ── inject.js page-world injection ──────────────────────────────────────────
  // Must run before any page script so it wraps native fetch/XHR first.
  try {
    const s = document.createElement('script');
    s.src = chrome.runtime.getURL('inject.js');
    s.onload = () => s.remove();
    (document.head || document.documentElement).prepend(s);
  } catch (_) {}

  // Bridge: inject.js → content script → background worker → content script → inject.js
  window.addEventListener('kasbah:intercept', async (e) => {
    const { id, text } = e.detail || {};
    if (!id || !text) return;
    const res = await chrome.runtime.sendMessage({ type: 'kasbah:scan', text }).catch(() => null);
    const verdict = (res?.ok && res.verdict) || 'ALLOW';
    window.dispatchEvent(new CustomEvent('kasbah:verdict:' + id, { detail: { verdict } }));
    // Show banner for any API-level scan result
    if (verdict !== 'ALLOW') banner(res || { verdict, offline: false });
  });

  // Show banner when inject.js hard-blocks a request
  window.addEventListener('kasbah:blocked', () => {
    banner({ verdict: 'DENY', offline: false, threats: ['API request blocked by Kasbah'] });
  });

  // Media access events from inject.js — screen capture, camera, mic, AI vision.
  // Forward to background so the popup protection score and tray can reflect them.
  window.addEventListener('kasbah:media:access', (e) => {
    const detail = e.detail || {};
    chrome.runtime.sendMessage({ type: 'MEDIA_ACCESS', detail }).catch(() => {});
    // Show a subtle banner for silent screen/camera access.
    if (detail.type === 'screen' || detail.type === 'ai-vision') {
      banner({
        verdict: 'WARN',
        offline:  false,
        threats: [detail.type === 'screen' ? 'Screen capture started' : `AI vision API call (${detail.label || 'unknown'})`],
      });
    }
  });

  const SITES = {
    'chatgpt.com': {
      composer: '#prompt-textarea, [data-id="root"] textarea, div[contenteditable="true"][data-testid], textarea',
      send: 'button[data-testid="send-button"], button[aria-label*="Send"]',
    },
    'chat.openai.com': {
      composer: '#prompt-textarea, textarea, div[contenteditable="true"]',
      send: 'button[data-testid="send-button"], button[aria-label*="Send"]',
    },
    'claude.ai': {
      composer: 'div[contenteditable="true"], textarea',
      send: 'button[aria-label*="Send"], button[type="submit"]',
    },
    'gemini.google.com': {
      composer: 'div[contenteditable="true"], textarea',
      send: 'button[aria-label*="Send"], button[aria-label*="submit"]',
    },
    'www.perplexity.ai': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[aria-label*="Submit"], button[type="submit"]',
    },
    'labs.perplexity.ai': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[aria-label*="Submit"], button[type="submit"]',
    },
    'poe.com': {
      composer: 'textarea',
      send: 'button[class*="sendButton"], button[aria-label*="Send"]',
    },
    'grok.com': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'copilot.microsoft.com': {
      composer: 'textarea, div[contenteditable="true"], #userInput',
      send: 'button[aria-label*="Submit"], button[aria-label*="Send"], button[type="submit"]',
    },
    'www.bing.com': {
      composer: '#sb_form_q, textarea, #searchbox',
      send: 'button#search_icon, button[aria-label*="Search"], button[type="submit"]',
    },
    'copilot.cloud.microsoft': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[aria-label*="Submit"], button[aria-label*="Send"], button[type="submit"]',
    },
    // ── Privacy-AI hosts (Brave Leo / Duck.ai / Opera Aria era) ─────────────
    'duck.ai': {
      composer: 'textarea, div[contenteditable="true"], [contenteditable="true"]',
      send: 'button[aria-label*="Ask"], button[type="submit"], button[aria-label*="Send"]',
    },
    'duckduckgo.com': {
      composer: 'textarea#chatbox-textarea, textarea, div[contenteditable="true"]',
      send: 'button[aria-label*="Ask"], button[aria-label*="Send"], button[type="submit"]',
    },
    'search.brave.com': {
      composer: 'textarea, div[contenteditable="true"], #searchbox',
      send: 'button[type="submit"], button[aria-label*="Search"]',
    },
    'brave.com': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'www.opera.com': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'www.phind.com': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'you.com': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'chat.mistral.ai': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'aistudio.google.com': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Run"], button[aria-label*="Send"]',
    },
    'chat.deepseek.com': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'www.kimi.com': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'chat.qwen.ai': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'www.meta.ai': {
      composer: 'textarea, div[contenteditable="true"]',
      send: 'button[type="submit"], button[aria-label*="Send"]',
    },
    'x.com': {
      composer: 'div[data-testid="tweetTextarea_0"], div[contenteditable="true"], textarea',
      send: 'button[data-testid="tweetButtonInline"], button[data-testid="tweetButton"]',
    },
  };
  const host = location.hostname;
  const cfg = SITES[host];
  if (!cfg) return;

  let enabled = true;
  chrome.storage.local.get('enabled').then((r) => { enabled = r.enabled !== false; });
  chrome.storage.onChanged.addListener((c) => { if (c.enabled) enabled = c.enabled.newValue !== false; });

  // ── Badge ──
  function mountBadge() {
    if (document.getElementById('kasbah-badge')) return;
    const b = document.createElement('div');
    b.id = 'kasbah-badge';
    b.textContent = '🛡 Governed by Kasbah';
    b.title = 'Prompts are scanned locally for secrets, PII and injection before they are sent.';
    document.documentElement.appendChild(b);
  }
  mountBadge();
  new MutationObserver(mountBadge).observe(document.documentElement, { childList: true, subtree: false });

  function getComposer() {
    for (const sel of cfg.composer.split(',')) {
      const el = document.querySelector(sel.trim());
      if (el) return el;
    }
    return null;
  }
  function composerText(el) {
    if (!el) return '';
    return (el.value != null ? el.value : el.innerText || el.textContent || '').trim();
  }

  // Dialog budget: ≤1 modal / 30s, ≤3 toasts / 10min (matches intervention.js)
  const _uiBudget = { modals: [], toasts: [] };
  function _allowUi(kind) {
    const now = Date.now();
    if (kind === 'modal') {
      _uiBudget.modals = _uiBudget.modals.filter((t) => now - t < 30000);
      if (_uiBudget.modals.length >= 1) return false;
      _uiBudget.modals.push(now);
      return true;
    }
    _uiBudget.toasts = _uiBudget.toasts.filter((t) => now - t < 600000);
    if (_uiBudget.toasts.length >= 3) return false;
    _uiBudget.toasts.push(now);
    return true;
  }

  function banner(result) {
    const v = result.verdict;
    const seatbelt = result.seatbelt || result.intervention || null;
    const interventionName = typeof seatbelt === 'string'
      ? seatbelt
      : seatbelt?.intervention || (v === 'DENY' ? 'hard_block' : v === 'WARN' ? 'warning_toast' : 'silent_pass');

    // Respect dialog budgets for non-blocking banners
    const isBlock = v === 'DENY' && !result.offline;
    if (!isBlock && !_allowUi('toast')) return document.getElementById('kasbah-banner');
    if (isBlock && !_allowUi('modal') && document.getElementById('kasbah-banner')) {
      return document.getElementById('kasbah-banner');
    }

    let el = document.getElementById('kasbah-banner');
    if (!el) {
      el = document.createElement('div');
      el.id = 'kasbah-banner';
      document.documentElement.appendChild(el);
    }
    const color = result.offline ? '#c0392b' : v === 'DENY' ? '#c0392b' : v === 'WARN' ? '#b8860b' : '#0f7a50';
    const tierLabel =
      interventionName === 'hard_block' ? 'Hard Block'
      : interventionName === 'mute_block' ? 'Mute Block'
      : interventionName === 'warning_toast' ? 'Warning Toast'
      : 'Silent Pass';
    const label = result.offline
      ? '⚠ Kasbah is offline — this prompt was NOT scanned'
      : result.muteBlock || interventionName === 'mute_block'
        ? `⚠ Would have blocked · ${tierLabel}`
        : v === 'DENY'
          ? `⛔ Hard Block — ${tierLabel}`
          : v === 'WARN'
            ? `⚠ Warning Toast — sensitive content`
            : `✓ Silent Pass — no issues`;
    const threats = (result.threats || []).length
      ? `<div class="kb-th">${result.threats.map(t => `<span>${t}</span>`).join('')}</div>` : '';
    const attestLine = result.attestId
      ? `<div class="kb-attest" title="Attestation ID: ${result.attestId}">📋 Attestation: ${result.attestId.slice(0, 12)}…</div>` : '';
    const shareBtn = (v === 'WARN' || v === 'DENY' || result.share?.worthy)
      ? '<button id="kb-share" title="Copy a bug-report line with proof">Copy receipt for bug report</button>'
      : '';
    el.style.borderColor = color;
    el.innerHTML = `<div class="kb-hd" style="color:${color}">${label}</div>${threats}${attestLine}` +
      (isBlock
        ? `<div class="kb-ac"><button id="kb-send-anyway">Send anyway</button><button id="kb-cancel">Cancel</button>${shareBtn}</div>`
        : shareBtn
          ? `<div class="kb-ac">${shareBtn}</div>`
          : '');
    el.style.display = 'block';
    clearTimeout(el._t);
    if (!isBlock && !result.offline) el._t = setTimeout(() => (el.style.display = 'none'), 5000);
    if (result.offline) el._t = setTimeout(() => (el.style.display = 'none'), 8000);

    const share = el.querySelector('#kb-share');
    if (share) {
      share.addEventListener('click', async () => {
        const line = result.shareUrl
          ? `Kasbah receipt: ${result.shareUrl}`
          : `Kasbah ${tierLabel} · risk ${Math.round((result.risk || result.risk_score || 0) * 100)}% · ${(result.threats || []).slice(0, 3).join(', ') || 'flagged'} · ${location.hostname}`;
        try {
          await navigator.clipboard.writeText(line);
          share.textContent = 'Copied ✓';
          setTimeout(() => { share.textContent = 'Copy receipt for bug report'; }, 2000);
        } catch (_) {
          share.textContent = 'Copy failed';
        }
      }, { once: false });
    }
    return el;
  }

  let lastScanText = '', lastResult = null, overrideOnce = false;

  async function scanNow(text) {
    if (!text) return null;
    if (text === lastScanText && lastResult) return lastResult;
    const res = await chrome.runtime.sendMessage({ type: 'kasbah:scan', text });
    lastScanText = text;
    lastResult = res && res.ok ? res : { offline: !res || res.offline, verdict: 'ALLOW' };

    // Attest clean prompts (best-effort, non-blocking)
    if (lastResult && lastResult.ok && lastResult.verdict !== 'DENY') {
      chrome.runtime.sendMessage({ type: 'kasbah:attest', text }).then((attestRes) => {
        if (attestRes && attestRes.ok && attestRes.id) {
          lastResult = { ...lastResult, attestId: attestRes.id };
          chrome.runtime.sendMessage({
            type: 'kasbah:saveLastScan',
            data: { verdict: lastResult.verdict, threats: lastResult.threats || [], attestId: attestRes.id, ts: Date.now() },
          });
        }
      }).catch(() => {});
    }

    return lastResult;
  }

  // Intercept submit: capture Enter (without Shift) and send-button clicks.
  async function guard(e) {
    if (!enabled) return;
    if (overrideOnce) { overrideOnce = false; return; }
    const el = getComposer();
    const text = composerText(el);
    if (!text) return;
    const res = await scanNow(text);
    if (!res) return;
    banner(res);
    if (res.verdict === 'DENY' && !res.offline) {
      e.preventDefault(); e.stopPropagation();
      const bn = document.getElementById('kasbah-banner');
      bn.querySelector('#kb-send-anyway')?.addEventListener('click', () => {
        overrideOnce = true; bn.style.display = 'none';
        if (el.focus) el.focus();
      }, { once: true });
      bn.querySelector('#kb-cancel')?.addEventListener('click', () => (bn.style.display = 'none'), { once: true });
      return false;
    }
  }

  // ── Real-time typing scan (debounced 600 ms) ─────────────────────────────
  let _rtTimer = null;
  let _rtLast = '';
  function scheduleRtScan() {
    clearTimeout(_rtTimer);
    _rtTimer = setTimeout(async () => {
      if (!enabled) return;
      const el = getComposer();
      const text = composerText(el);
      if (!text || text === _rtLast || text.length < 20) return;
      _rtLast = text;
      const res = await scanNow(text);
      if (res && (res.verdict === 'WARN' || res.verdict === 'DENY')) banner(res);
    }, 600);
  }

  document.addEventListener('input', scheduleRtScan, true);
  document.addEventListener('compositionend', scheduleRtScan, true);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) guard(e);
  }, true);
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (btn && cfg.send && btn.matches(cfg.send)) guard(e);
  }, true);
})();
