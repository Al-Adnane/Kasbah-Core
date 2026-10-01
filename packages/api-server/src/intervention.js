'use strict';

/**
 * Kasbah Intervention Engine — the product decision layer.
 *
 * Turns a risk score into the three-tier seatbelt UX from the Guard spec:
 *
 *   Silent Pass    risk < 0.30   no interruption (optional micro-toast)
 *   Warning Toast  risk 0.30–0.70  non-blocking heads-up
 *   Hard Block     risk ≥ 0.70   modal / deny with one-time override
 *
 * Plus the commercial layer:
 *   Authority Verbs — SIMULATE (free) · SHIELD (1) · REDACT (5) · CERTIFY (20) · EXPORT_BUNDLE (5)
 *   Dialog budgets  — ≤1 modal / 30s, ≤3 toasts / 10min (anti-fatigue)
 *   Hysteresis      — sticky warn/block bands so borderline risk does not flip-flop
 *   Mute Block      — when the enforcement budget is spent, detect + warn but do not enforce
 */

const crypto = require('crypto');

// ─── risk → intervention bands (with hysteresis) ─────────────────────────────
const BANDS = {
  silent:  { enter: 0.30, exit: 0.22 },
  warning: { enter: 0.70, exit: 0.55 },
};

const VERB_COST = {
  SIMULATE: 0,
  SHIELD: 1,
  REDACT: 5,
  CERTIFY: 20,
  EXPORT_BUNDLE: 5,
};

const DIALOG_BUDGETS = {
  modalPerWindowMs: 30 * 1000,
  modalMaxPerWindow: 1,
  toastPerWindowMs: 10 * 60 * 1000,
  toastMaxPerWindow: 3,
  silentMicroToastChance: 0.08,
};

/** In-memory sticky state + dialog budgets. Keyed by apiKeyId or client id. */
const _state = new Map();

function _bucket(key) {
  const k = key || 'anonymous';
  let s = _state.get(k);
  if (!s) {
    s = {
      intervention: 'silent_pass',
      lastRisk: 0,
      modals: [],
      toasts: [],
      counters: {
        silent_pass: 0,
        warning_toast: 0,
        hard_block: 0,
        mute_block: 0,
        would_have_blocked: 0,
        saved: 0,
      },
      updatedAt: Date.now(),
    };
    _state.set(k, s);
  }
  s.updatedAt = Date.now();
  return s;
}

function _prune(arr, windowMs, now) {
  const cut = now - windowMs;
  while (arr.length && arr[0] < cut) arr.shift();
}

function _clamp01(n) {
  return Math.max(0, Math.min(1, n));
}

/**
 * Apply hysteresis: once you enter a band you stay until risk falls past `exit`.
 */
function _stickyBand(current, risk) {
  const cur = current || 'silent_pass';
  if (cur === 'hard_block') {
    return risk >= BANDS.warning.exit ? 'hard_block' : risk >= BANDS.silent.enter ? 'warning_toast' : 'silent_pass';
  }
  if (cur === 'warning_toast') {
    if (risk >= BANDS.warning.enter) return 'hard_block';
    if (risk >= BANDS.silent.exit) return 'warning_toast';
    return 'silent_pass';
  }
  // silent
  if (risk >= BANDS.warning.enter) return 'hard_block';
  if (risk >= BANDS.silent.enter) return 'warning_toast';
  return 'silent_pass';
}

/**
 * Map a risk score + threats to a product intervention decision.
 *
 * @param {object} opts
 * @param {number} opts.risk           0..1
 * @param {string[]} [opts.threats]
 * @param {string} [opts.subject]      what is being protected (e.g. 'prompt')
 * @param {string} [opts.surface]      paste|upload|browse|edit|download|api|other
 * @param {string} [opts.clientKey]    budget/hysteresis key
 * @param {number} [opts.enforcementBudget] remaining SHIELD units; null = unlimited
 * @param {boolean} [opts.wantRedact]  caller wants auto-redaction offered
 * @returns {object} intervention decision
 */
function decide(opts = {}) {
  const risk = _clamp01(typeof opts.risk === 'number' ? opts.risk : 0);
  const threats = Array.isArray(opts.threats) ? opts.threats : [];
  const surface = opts.surface || 'api';
  const key = opts.clientKey || 'anonymous';
  const now = Date.now();
  const st = _bucket(key);

  const next = _stickyBand(st.intervention, risk);
  const changed = next !== st.intervention;
  st.intervention = next;
  st.lastRisk = risk;

  // ── dialog budgets (anti-fatigue) ─────────────────────────────────────────
  let suppressUi = false;
  let suppressReason = null;
  let ui = 'none';

  if (next === 'hard_block') {
    _prune(st.modals, DIALOG_BUDGETS.modalPerWindowMs, now);
    if (st.modals.length >= DIALOG_BUDGETS.modalMaxPerWindow) {
      suppressUi = true;
      suppressReason = 'modal_budget';
      ui = 'none';
    } else {
      st.modals.push(now);
      ui = 'modal';
    }
    st.counters.hard_block++;
  } else if (next === 'warning_toast') {
    _prune(st.toasts, DIALOG_BUDGETS.toastPerWindowMs, now);
    if (st.toasts.length >= DIALOG_BUDGETS.toastMaxPerWindow) {
      suppressUi = true;
      suppressReason = 'toast_budget';
      ui = 'none';
    } else {
      st.toasts.push(now);
      ui = 'toast';
    }
    st.counters.warning_toast++;
  } else {
    st.counters.silent_pass++;
    // rare micro-toast so silent protection stays visible
    ui = Math.random() < DIALOG_BUDGETS.silentMicroToastChance ? 'micro_toast' : 'none';
  }

  // ── authority verb + mute block ───────────────────────────────────────────
  let verb = 'SIMULATE';
  let units = 0;
  let muteBlock = false;
  let enforcement = 'none';

  if (next === 'hard_block') {
    enforcement = 'block';
    verb = 'SHIELD';
    units = VERB_COST.SHIELD;
  } else if (next === 'warning_toast' && opts.wantRedact) {
    enforcement = 'redact';
    verb = 'REDACT';
    units = VERB_COST.REDACT;
  } else if (next === 'warning_toast') {
    enforcement = 'warn';
  }

  const budget = opts.enforcementBudget;
  if (typeof budget === 'number' && budget < units) {
    // Anxiety Gap: still detect and report, do not enforce the costly verb.
    muteBlock = true;
    st.counters.mute_block++;
    if (enforcement === 'block') {
      st.counters.would_have_blocked++;
      enforcement = 'warn';
    } else if (enforcement === 'redact') {
      enforcement = 'warn';
    }
  }

  if (enforcement === 'block' && !muteBlock) st.counters.saved++;

  // ── shareable proof trigger ───────────────────────────────────────────────
  // High-severity events deserve a one-click receipt share.
  const shareWorthy =
    next === 'hard_block' ||
    (next === 'warning_toast' && risk >= 0.55 && threats.some((t) => /secret|pii|injection|credential|key/i.test(t)));

  return {
    intervention: next,
    previous: changed ? (st.intervention === next ? null : 'updated') : undefined,
    ui,
    suppressUi,
    suppressReason,
    enforcement,
    muteBlock,
    surface,
    risk,
    riskPct: Math.round(risk * 100),
    threats,
    labels: {
      silent_pass: 'Silent Pass',
      warning_toast: 'Warning Toast',
      hard_block: muteBlock ? 'Mute Block' : 'Hard Block',
    },
    copy: _copyFor(next, { risk, threats, muteBlock, surface, enforcement }),
    authority: {
      verb,
      units,
      costUnits: units,
      remainingBudget: typeof budget === 'number' ? Math.max(0, budget - (muteBlock ? 0 : units)) : null,
      verbs: VERB_COST,
    },
    share: shareWorthy
      ? {
          worthy: true,
          hint: 'Copy receipt for bug report',
          reason: muteBlock
            ? 'Would have blocked — share the near-miss'
            : 'Protected — share the proof',
        }
      : { worthy: false },
    budgets: {
      modalsRecent: st.modals.length,
      toastsRecent: st.toasts.length,
      limits: DIALOG_BUDGETS,
    },
    hysteresis: {
      enterSilent: BANDS.silent.enter,
      exitSilent: BANDS.silent.exit,
      enterBlock: BANDS.warning.enter,
      exitBlock: BANDS.warning.exit,
    },
  };
}

function _copyFor(intervention, { risk, threats, muteBlock, surface, enforcement }) {
  const pct = Math.round(risk * 100);
  const top = threats.slice(0, 2).join(', ') || 'risky content';
  if (intervention === 'hard_block') {
    if (muteBlock) {
      return {
        title: 'Would have blocked',
        body: `Kasbah would have blocked this ${surface} (risk ${pct}%: ${top}). Enforcement credits are spent — recharge to keep protecting.`,
        toast: `Would have blocked (${pct}% risk) — protection paused`,
        modal: `This action looks dangerous.\n\nRisk ${pct}% · ${top}\n\nYour enforcement credits are exhausted, so Kasbah is warning instead of blocking. Recharge to restore Hard Block.`,
      };
    }
    return {
      title: 'Hard Block',
      body: `Kasbah blocked this ${surface} (risk ${pct}%: ${top}).`,
      toast: `Blocked — ${top}`,
      modal: `Kasbah blocked this action.\n\nRisk ${pct}% · ${top}\n\nNothing left your device. One-time override is available if you accept the risk.`,
    };
  }
  if (intervention === 'warning_toast') {
    return {
      title: 'Warning Toast',
      body: `Heads up — this ${surface} looks sensitive (risk ${pct}%: ${top}).`,
      toast: `Heads up — contains sensitive content (${pct}%)`,
      modal: `Sensitive content detected (risk ${pct}%).\n\n${top}\n\nYou can continue, redact, or cancel.`,
    };
  }
  return {
    title: 'Silent Pass',
    body: 'Looks safe. Kasbah is watching silently.',
    toast: 'Kasbah is protecting this session',
    modal: null,
  };
}

/** Snapshot of session counters (for dashboards / "saved you" digest). */
function snapshot(clientKey) {
  const st = _bucket(clientKey);
  return {
    intervention: st.intervention,
    lastRisk: st.lastRisk,
    counters: { ...st.counters },
    budgets: {
      modalsRecent: st.modals.length,
      toastsRecent: st.toasts.length,
      limits: DIALOG_BUDGETS,
    },
  };
}

/** Reset budgets for a key (tests / support). */
function reset(clientKey) {
  _state.delete(clientKey || 'anonymous');
}

/**
 * Map an EXISTING governance result (ALLOW | WARN | DENY | REQUIRE_APPROVAL | ERROR)
 * into seatbelt UX. Prefer the engine's verdict — do not re-derive risk when
 * the caller already decided. This is the non-reinvented path.
 */
function fromGovern(result = {}, opts = {}) {
  const verdict = String(result.verdict || result.status || 'ALLOW').toUpperCase();
  const risk = typeof result.risk === 'number' ? result.risk
    : typeof result.riskScore === 'number' ? result.riskScore
    : typeof result.score === 'number' && result.score > 1 ? Math.min(1, result.score / 100)
    : verdict === 'DENY' ? 0.92
    : verdict === 'REQUIRE_APPROVAL' ? 0.78
    : verdict === 'WARN' ? 0.5
    : verdict === 'ERROR' ? 0.6
    : 0.08;
  const threats = Array.isArray(result.threats) ? result.threats : [];
  const d = decide({
    risk,
    threats,
    surface: opts.surface || result.surface || 'api',
    clientKey: opts.clientKey || result.passportId || 'anonymous',
    wantRedact: opts.wantRedact,
    enforcementBudget: opts.enforcementBudget,
  });
  // Keep engine verdict as source of truth for hard deny even if hysteresis softens UI.
  if (verdict === 'DENY' && d.intervention !== 'hard_block') {
    d.intervention = 'hard_block';
    d.enforcement = 'block';
    d.labels.hard_block = d.muteBlock ? 'Mute Block' : 'Hard Block';
    d.authority.verb = 'SHIELD';
    d.authority.units = VERB_COST.SHIELD;
  }
  if (verdict === 'REQUIRE_APPROVAL' && d.intervention === 'silent_pass') {
    d.intervention = 'warning_toast';
    d.enforcement = 'warn';
    d.ui = d.ui === 'none' ? 'toast' : d.ui;
  }
  d.engineVerdict = verdict;
  return d;
}

/** Map legacy ALLOW/WARN/DENY verdict to intervention name. */
function fromVerdict(verdict, risk) {
  return fromGovern({ verdict, risk }).intervention;
}

/** Unit costs, exposed for /v1/billing/plans and docs. */
const AUTHORITY_VERBS = { ...VERB_COST };

module.exports = {
  decide,
  fromGovern,
  snapshot,
  reset,
  fromVerdict,
  AUTHORITY_VERBS,
  BANDS,
  DIALOG_BUDGETS,
};
