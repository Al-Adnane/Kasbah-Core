'use strict';

/**
 * Kasbah Viral Growth Loop
 * - Receipt share tracking
 * - Viral coefficient metric
 * - Slack/Discord verify bot webhook
 * - Share card generation
 * - Sign-up wall on /verify
 */

const crypto = require('crypto');
const _shares = new Map(); // receiptId -> { sharedAt, referrer, source }
const _viralEvents = []; // { ts, receiptId, channel }

function recordShare(receiptId, meta = {}) {
  const id = String(receiptId);
  _shares.set(id, {
    sharedAt: Date.now(),
    referrer: meta.referrer || null,
    source: meta.source || 'api',
    channel: meta.channel || 'manual',
  });
  _viralEvents.push({ ts: Date.now(), receiptId: id, channel: meta.channel || 'manual' });
}

function viralCoefficient(windowMs = 7 * 24 * 60 * 60 * 1000) {
  const now = Date.now();
  const cutoff = now - windowMs;
  const recent = _viralEvents.filter(e => e.ts >= cutoff);
  if (recent.length === 0) return 0;
  // Simple proxy: shares per receipt
  const uniqueReceipts = new Set(recent.map(e => e.receiptId)).size;
  const k = recent.length / Math.max(1, uniqueReceipts);
  return k;
}

function shareCard(receipt) {
  const id = receipt.id || receipt.receiptId || 'unknown';
  const url = `https://kasbah.app/verify/${id}`;
  return {
    title: 'Kasbah saved you',
    subtitle: `Risk ${receipt.risk ?? 'unknown'}% blocked`,
    cta: 'Verify proof',
    url,
    image: 'https://kasbah.app/og/verify.png',
    text: `Kasbah receipt ${id} — ${url}`,
  };
}

async function postToSlack(webhookUrl, receipt) {
  if (!webhookUrl) return false;
  try {
    const card = shareCard(receipt);
    const payload = {
      text: card.text,
      attachments: [{
        title: card.title,
        title_link: card.url,
        text: card.subtitle,
        color: 'good',
      }]
    };
    // Node 18 fetch
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.ok;
  } catch (_) { return false; }
}

module.exports = {
  recordShare,
  viralCoefficient,
  shareCard,
  postToSlack,
  // sign-up wall helper
  verifyView(receiptId, isSignedIn) {
    return {
      requiresSignup: !isSignedIn,
      receiptId,
    };
  }
};
