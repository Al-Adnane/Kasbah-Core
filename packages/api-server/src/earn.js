'use strict';

/**
 * Kasbah Earn — users earn credits for growing Kasbah, credits pay for usage.
 *
 * Ladder (simplest first):
 *   1. Share a receipt  → +10 credits per share (max 10/day, anti-farm)
 *   2. Refer a friend   → friend redeems your code: you +500, friend +500
 *   3. Hold attention   → weekly active protector streak: +50/week (via /earn/checkin)
 *
 * Credits spend automatically before tier caps (usage-meter checks credits
 * first), so earnings directly cut bills. Cash payout above 10,000 credits
 * is a declared roadmap item (needs Stripe Connect), not silently promised.
 *
 * Persistence: JSONL ledger + codes file under dataDir. Safe to delete —
 * balances rebuild from ledger replay.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SHARE_REWARD = 10;
const SHARE_DAILY_CAP = 10;
const REFERRAL_REWARD = 500;
const STREAK_REWARD = 50;
const CASHOUT_THRESHOLD = 10_000;

let _dataDir = null;
let _addCredits = null;
let _codes = new Map();   // CODE -> { owner, createdAt, uses }
let _ledger = [];         // { ts, keyId, type, amount, note }
let _loaded = false;

function _files() {
  return {
    codes: path.join(_dataDir, 'earn-codes.json'),
    ledger: path.join(_dataDir, 'earn-ledger.jsonl'),
  };
}

function init({ dataDir, addCredits }) {
  _dataDir = dataDir;
  _addCredits = addCredits;
  _load();
}

function _load() {
  if (_loaded || !_dataDir) return;
  _loaded = true;
  try { fs.mkdirSync(_dataDir, { recursive: true, mode: 0o700 }); } catch (_) {}
  const f = _files();
  try {
    const raw = JSON.parse(fs.readFileSync(f.codes, 'utf8'));
    for (const [k, v] of Object.entries(raw)) _codes.set(k, v);
  } catch (_) {}
  try {
    const lines = fs.readFileSync(f.ledger, 'utf8').split('\n').filter(Boolean);
    for (const ln of lines.slice(-5000)) {
      try { _ledger.push(JSON.parse(ln)); } catch (_) {}
    }
  } catch (_) {}
}

function _saveCodes() {
  try { fs.writeFileSync(_files().codes, JSON.stringify(Object.fromEntries(_codes), null, 2), { mode: 0o600 }); } catch (_) {}
}

function _record(keyId, type, amount, note) {
  const entry = { ts: new Date().toISOString(), keyId, type, amount, note: note || '' };
  _ledger.push(entry);
  try { fs.appendFileSync(_files().ledger, JSON.stringify(entry) + '\n', { mode: 0o600 }); } catch (_) {}
  return entry;
}

function _codeFor(keyId) {
  const h = crypto.createHash('sha256').update('kasbah-earn:' + keyId).digest('hex').slice(0, 8).toUpperCase();
  return `KASBAH-${h.slice(0, 4)}-${h.slice(4, 8)}`;
}

function myCode(keyId) {
  const code = _codeFor(keyId);
  if (!_codes.has(code)) {
    _codes.set(code, { owner: keyId, createdAt: Date.now(), uses: 0 });
    _saveCodes();
  }
  return code;
}

function balance(keyId) {
  let bal = 0;
  for (const e of _ledger) if (e.keyId === keyId) bal += e.amount;
  return bal;
}

function redeem(code, redeemerKeyId) {
  const c = String(code || '').trim().toUpperCase();
  const rec = _codes.get(c);
  if (!rec) return { error: 'Unknown code' };
  if (rec.owner === redeemerKeyId) return { error: 'That is your own code' };
  const already = _ledger.some(e => e.type === 'referral-redeem' && e.keyId === redeemerKeyId && e.note === c);
  if (already) return { error: 'Code already redeemed by you' };
  rec.uses += 1;
  _saveCodes();
  if (_addCredits) {
    try { _addCredits(rec.owner, REFERRAL_REWARD); } catch (_) {}
    try { _addCredits(redeemerKeyId, REFERRAL_REWARD); } catch (_) {}
  }
  _record(rec.owner, 'referral-earn', REFERRAL_REWARD, `friend joined via ${c}`);
  _record(redeemerKeyId, 'referral-redeem', REFERRAL_REWARD, c);
  return { ok: true, earned: REFERRAL_REWARD, friendEarned: REFERRAL_REWARD };
}

function shareReward(keyId) {
  const day = new Date().toISOString().slice(0, 10);
  const today = _ledger.filter(e => e.keyId === keyId && e.type === 'share' && e.ts.slice(0, 10) === day).length;
  if (today >= SHARE_DAILY_CAP) return { ok: false, error: 'Daily share cap reached', cap: SHARE_DAILY_CAP };
  if (_addCredits) { try { _addCredits(keyId, SHARE_REWARD); } catch (_) {} }
  _record(keyId, 'share', SHARE_REWARD, 'receipt shared');
  return { ok: true, earned: SHARE_REWARD, today: today + 1, cap: SHARE_DAILY_CAP };
}

function checkin(keyId) {
  const week = _weekId();
  const done = _ledger.some(e => e.keyId === keyId && e.type === 'streak' && e.note === week);
  if (done) return { ok: false, error: 'Already checked in this week' };
  if (_addCredits) { try { _addCredits(keyId, STREAK_REWARD); } catch (_) {} }
  _record(keyId, 'streak', STREAK_REWARD, week);
  return { ok: true, earned: STREAK_REWARD, week };
}

function _weekId() {
  const d = new Date();
  const onejan = new Date(d.getFullYear(), 0, 1);
  const week = Math.ceil((((d - onejan) / 86400000) + onejan.getDay() + 1) / 7);
  return `${d.getFullYear()}-W${week}`;
}

function ledger(keyId, limit = 50) {
  return _ledger.filter(e => e.keyId === keyId).slice(-limit).reverse();
}

module.exports = {
  init, myCode, balance, redeem, shareReward, checkin, ledger,
  REWARDS: { SHARE_REWARD, SHARE_DAILY_CAP, REFERRAL_REWARD, STREAK_REWARD, CASHOUT_THRESHOLD },
};
