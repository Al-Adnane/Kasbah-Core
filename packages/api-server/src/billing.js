'use strict';

/**
 * Kasbah Guard — Commerce & Billing
 *
 * Five-tier subscription model + pay-as-you-go credits.
 * Stripe-native, gracefully degrades when STRIPE_SECRET_KEY is unset.
 *
 * Tiers (price per month, USD):
 *   Free          $0      100 req/day,   1k/month   — lead-gen
 *   Starter       $19     2k req/day,    20k/month  — individual professionals
 *   Pro           $99     10k req/day,   100k/month — small teams (≤5)
 *   Business      $499    50k req/day,   1M/month   — growing companies (≤25)
 *   Enterprise    custom  unlimited                 — F500, regulated industries
 *
 * Annual = 2 months free (16.7% discount).
 *
 * Pay-as-you-go credits (alternative to subscription):
 *   $50   →  100,000 credits  ($0.0005/credit)
 *   $200  →  500,000 credits  ($0.0004/credit)
 *   $1k   →  3,000,000 credits ($0.00033/credit)
 *
 * Product cost (credits consumed per scan):
 *   general / dating-guard / relationship-guard / resume-authentic / baseline-drift / dao-vote-guard  → 1
 *   quantum-sentinel / neural-witness / chronos-paradox / manifold-validator                          → 2
 *   botnet-radar                                                                                     → 3
 *   legal-evidence (court-admissible ZK proof)                                                       → 5
 *   compliance (PQ-signed SOC 2 / EU AI Act / NIST reports)                                          → 10
 *
 * Env vars (production):
 *   STRIPE_SECRET_KEY
 *   STRIPE_WEBHOOK_SECRET
 *   STRIPE_PRICE_STARTER_MONTHLY, STRIPE_PRICE_STARTER_ANNUAL
 *   STRIPE_PRICE_PRO_MONTHLY,     STRIPE_PRICE_PRO_ANNUAL
 *   STRIPE_PRICE_BUSINESS_MONTHLY, STRIPE_PRICE_BUSINESS_ANNUAL
 *   STRIPE_PRICE_ENTERPRISE
 *   STRIPE_PRICE_CREDITS_50, STRIPE_PRICE_CREDITS_200, STRIPE_PRICE_CREDITS_1000
 */

const crypto = require('crypto');
const usageMeter = require('./usage-meter.js');

// ─── Stripe SDK loader (lazy, graceful) ──────────────────────────────────────
let _stripe = null;
function _stripeSdkAvailable() {
  try { require.resolve('stripe'); return true; } catch { return false; }
}
function _getStripe() {
  if (_stripe) return _stripe;
  if (!process.env.STRIPE_SECRET_KEY) return null;
  try {
    _stripe = require('stripe')(process.env.STRIPE_SECRET_KEY, {
      apiVersion: '2024-06-20',
      appInfo: { name: 'Kasbah Guard', version: '3.0.0', url: 'https://bekasbah.com' }
    });
    return _stripe;
  } catch (e) {
    console.warn('[billing] Stripe SDK not available:', e.message);
    return null;
  }
}

// ─── Plan catalogue ──────────────────────────────────────────────────────────
// Pricing rationale (from market research, May 2026):
// Observability tools (LangSmith $39, AgentOps $40, Helicone $79) = watch only.
// Enforcement commands 3–10x premium. Kasbah is the only pre-execution blocker.
// Free tier: generous enough to activate (5 sessions), limited enough to upgrade.
// Developer ($29): below observability competitors, but adds enforcement — easy switch.
// Team ($99): matches observability enterprise entry (Helicone $799/mo is competitive ceiling).
// Business ($399): SOC2, NIST AI RMF, EU AI Act compliance reports are $500–$2k/report elsewhere.
// Enterprise: custom — regulated industries (finance, health, gov) buy on security posture.

const PLANS = {
  free: {
    tier: 'free',
    name: 'Free',
    tagline: 'Run agents. See what Kasbah catches.',
    priceMonthly: 0,
    priceAnnual:  0,
    limits: { daily: 50, monthly: 500, teamMembers: 1, sessions: 5 },
    features: [
      '5 governed sessions / month',
      'Budget caps & kill switch',
      'All 11 detection engines',
      '7-day audit history',
      'MCP server included',
      'Community support'
    ],
    targetPersona: 'Try it on your Claude Code or Cursor setup',
    cta: 'Start free — no card'
  },
  developer: {
    tier: 'developer',
    name: 'Developer',
    tagline: 'One line. Any SDK. Full governance.',
    priceMonthly: 29,
    priceAnnual:  279,
    limits: { daily: 2_000, monthly: 20_000, teamMembers: 1, sessions: -1 },
    features: [
      'protect(new OpenAI()) — one-line any SDK',
      'Supports: OpenAI, Anthropic, Gemini, Groq, Ollama, Mistral',
      'Unlimited governed sessions',
      'Full ToolGuard enforcement (fail-closed)',
      'Plain English policy editor',
      'All 11 detection engines',
      'Real-time SSE tool call stream',
      '90-day audit trail',
      'SDKs: JS, Python, Go, Swift, Kotlin',
      'Webhooks (HMAC signed)',
      'Email support'
    ],
    targetPersona: 'Developers using Claude Code, Cursor, or building AI-powered apps',
    cta: 'Start Developer',
    competitorNote: 'LangSmith costs $39/mo and only watches. Kasbah blocks.'
  },
  team: {
    tier: 'team',
    name: 'Team',
    tagline: 'Govern every agent across your team.',
    priceMonthly: 99,
    priceAnnual:  950,
    limits: { daily: 10_000, monthly: 100_000, teamMembers: 10, sessions: -1 },
    features: [
      'Everything in Developer',
      'Up to 10 team members',
      'Shared policy library',
      'Team session dashboard',
      'Budget alerts (email + Slack)',
      'SOC 2 audit trail export',
      'API access + webhooks (HMAC signed)',
      'Session replay & timeline',
      'Priority support',
      'SDKs: JS, Python, Go'
    ],
    targetPersona: 'Engineering teams building with AI agents in production',
    cta: 'Start Team',
    badge: 'Most popular'
  },
  business: {
    tier: 'business',
    name: 'Business',
    tagline: 'Compliance-grade governance for AI in production.',
    priceMonthly: 399,
    priceAnnual:  3_830,
    limits: { daily: 50_000, monthly: 1_000_000, teamMembers: 50, sessions: -1 },
    features: [
      'Everything in Team',
      'Up to 50 team members',
      'SSO (Google, GitHub)',
      'HIPAA compliance pack — PHI protection rules',
      'GDPR compliance pack — EU data protection',
      'PCI-DSS compliance pack — payment agent rules',
      'SOC 2 Type II evidence package',
      'EU AI Act compliance reports (signed)',
      'NIST AI RMF attestation',
      'ZK governance proofs (Schnorr protocol)',
      '1-year immutable audit chain',
      'Custom branding on reports',
      'Dedicated support channel'
    ],
    targetPersona: 'CTOs, CISOs, compliance teams — 82% of enterprises deploy agents, only 44% govern them',
    cta: 'Contact sales',
    badge: 'Best for compliance'
  },
  enterprise: {
    tier: 'enterprise',
    name: 'Enterprise',
    tagline: 'Regulated industries. Mission-critical AI.',
    priceMonthly: 'custom',
    priceAnnual:  'custom',
    limits: { daily: 'unlimited', monthly: 'unlimited', teamMembers: 'unlimited', sessions: -1 },
    features: [
      'Unlimited everything',
      'SSO (Google, GitHub, custom)',
      'On-premise / air-gap deployment option',
      'PQ-signed receipts (ML-DSA-65 + SLH-DSA)',
      'Custom detection algorithms',
      'Custom DPA negotiation',
      'Dedicated CSM + solutions engineer',
      'Board-level AI governance reports',
      'Source code review access',
      'Priority SLA'
    ],
    targetPersona: 'Banks, healthcare, government, F500 — where an agent incident means headlines',
    cta: 'Contact enterprise',
    contactEmail: 'enterprise@bekasbah.com'
  }
};

// Credit packs (pay-as-you-go) — for one-off governed runs without a subscription
// Positioned as "run one big job" — e.g. one overnight agent run = $5-20 of credits vs $437 incident
const CREDIT_PACKS = {
  session:  { id: 'credits-10',   priceUsd: 10,   credits: 10_000,    perCredit: 0.001,    label: 'Session pack',  badge: null,         desc: '~20 governed sessions' },
  growth:   { id: 'credits-50',   priceUsd: 50,   credits: 75_000,    perCredit: 0.00067,  label: 'Growth pack',   badge: 'Best value', desc: '~150 governed sessions' },
  scale:    { id: 'credits-200',  priceUsd: 200,  credits: 400_000,   perCredit: 0.0005,   label: 'Scale pack',    badge: null,         desc: 'Teams & pipelines' }
};

// Stripe price ID resolution
function priceIdFor(tier, interval) {
  const env = process.env;
  if (tier === 'developer') return interval === 'annual' ? env.STRIPE_PRICE_DEVELOPER_ANNUAL  : env.STRIPE_PRICE_DEVELOPER_MONTHLY;
  if (tier === 'team')      return interval === 'annual' ? env.STRIPE_PRICE_TEAM_ANNUAL       : env.STRIPE_PRICE_TEAM_MONTHLY;
  if (tier === 'business')  return interval === 'annual' ? env.STRIPE_PRICE_BUSINESS_ANNUAL   : env.STRIPE_PRICE_BUSINESS_MONTHLY;
  if (tier === 'enterprise') return env.STRIPE_PRICE_ENTERPRISE;
  // Legacy aliases
  if (tier === 'starter') return interval === 'annual' ? env.STRIPE_PRICE_DEVELOPER_ANNUAL : env.STRIPE_PRICE_DEVELOPER_MONTHLY;
  if (tier === 'pro')     return interval === 'annual' ? env.STRIPE_PRICE_TEAM_ANNUAL      : env.STRIPE_PRICE_TEAM_MONTHLY;
  return null;
}

function creditPackPriceId(packId) {
  if (packId === 'credits-50')   return process.env.STRIPE_PRICE_CREDITS_50;
  if (packId === 'credits-200')  return process.env.STRIPE_PRICE_CREDITS_200;
  if (packId === 'credits-1000') return process.env.STRIPE_PRICE_CREDITS_1000;
  return null;
}

function priceToTier(priceId) {
  if (!priceId) return null;
  const env = process.env;
  if ([env.STRIPE_PRICE_STARTER_MONTHLY,  env.STRIPE_PRICE_STARTER_ANNUAL].includes(priceId))  return 'starter';
  if ([env.STRIPE_PRICE_PRO_MONTHLY,      env.STRIPE_PRICE_PRO_ANNUAL].includes(priceId))      return 'pro';
  if ([env.STRIPE_PRICE_BUSINESS_MONTHLY, env.STRIPE_PRICE_BUSINESS_ANNUAL].includes(priceId)) return 'business';
  if (priceId === env.STRIPE_PRICE_ENTERPRISE) return 'enterprise';
  return null;
}

// ─── Webhook signature verification (works without Stripe SDK) ──────────────
function verifyWebhookSignature(rawBody, signatureHeader, secret) {
  if (!secret) return { valid: false, error: 'STRIPE_WEBHOOK_SECRET not set' };
  if (!signatureHeader) return { valid: false, error: 'Missing Stripe-Signature header' };

  const parts = signatureHeader.split(',').reduce((acc, p) => {
    const [k, v] = p.split('=');
    acc[k] = v;
    return acc;
  }, {});
  const timestamp   = parts.t;
  const expectedSig = parts.v1;
  if (!timestamp || !expectedSig) return { valid: false, error: 'Malformed signature header' };

  const tsMs = parseInt(timestamp, 10) * 1000;
  if (Date.now() - tsMs > 5 * 60 * 1000) {
    return { valid: false, error: 'Timestamp outside tolerance window' };
  }

  const payload  = timestamp + '.' + rawBody;
  const computed = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  if (computed.length !== expectedSig.length) return { valid: false, error: 'Signature length mismatch' };
  const valid = crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(expectedSig, 'hex'));
  return { valid, timestamp: tsMs };
}

// ─── Mount routes ────────────────────────────────────────────────────────────
function mount(app, { _apiKeys, updateWorkspace, getWorkspace, getUserById }) {

  // GET /v1/billing/plans — public catalogue (always 200)
  app.get('/v1/billing/plans', (req, res) => {
    const interval = (req.query.interval || 'monthly').toLowerCase();
    const plans = Object.values(PLANS).map(p => ({
      ...p,
      currentInterval: interval,
      price: interval === 'annual' ? p.priceAnnual : p.priceMonthly,
      stripePriceId: priceIdFor(p.tier, interval)
    }));
    res.json({
      plans,
      creditPacks: Object.values(CREDIT_PACKS).map(c => ({ ...c, stripePriceId: creditPackPriceId(c.id) })),
      intervals: ['monthly', 'annual'],
      currency: 'usd',
      stripeConfigured: !!process.env.STRIPE_SECRET_KEY,
      contact: 'enterprise@bekasbah.com'
    });
  });

  // POST /v1/billing/checkout — start Stripe Checkout for subscription
  app.post('/v1/billing/checkout', async (req, res) => {
    const { workspaceId, tier, interval = 'monthly', successUrl, cancelUrl, customerEmail } = req.body || {};

    if (!workspaceId) return res.status(400).json({ error: 'workspaceId required' });
    if (!['starter', 'pro', 'business', 'enterprise'].includes(tier)) {
      return res.status(400).json({ error: 'tier must be starter|pro|business|enterprise' });
    }
    if (tier === 'enterprise') {
      return res.json({
        contact: PLANS.enterprise.contactEmail,
        message: 'Enterprise plans are custom-priced. Email enterprise@bekasbah.com or book a call at https://bekasbah.com/enterprise',
        bookingUrl: 'https://bekasbah.com/enterprise'
      });
    }

    const ws = getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ error: 'Workspace not found' });

    const stripe  = _getStripe();
    const priceId = priceIdFor(tier, interval);

    if (!stripe || !priceId) {
      return res.status(503).json({
        error: 'Stripe not configured',
        what:  'Add STRIPE_SECRET_KEY and STRIPE_PRICE_* env vars, then `npm install stripe` in packages/api-server/.',
        plan:  PLANS[tier],
        missing: {
          stripeSecret: !process.env.STRIPE_SECRET_KEY,
          stripePrice:  !priceId,
          stripeSdk:    !_stripeSdkAvailable()
        }
      });
    }

    try {
      const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
        payment_method_types: ['card'],
        line_items: [{ price: priceId, quantity: 1 }],
        success_url: successUrl || 'https://bekasbah.com/billing/success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url:  cancelUrl  || 'https://bekasbah.com/pricing',
        client_reference_id: workspaceId,
        customer_email: customerEmail || undefined,
        allow_promotion_codes: true,
        metadata: { workspaceId, tier, interval, productType: 'subscription' },
        subscription_data: {
          metadata: { workspaceId, tier, interval }
        }
      });
      return res.json({ checkoutUrl: session.url, sessionId: session.id, tier, interval });
    } catch (e) {
      return res.status(500).json({ error: 'Stripe checkout failed', detail: e.message });
    }
  });

  // POST /v1/billing/credits/topup — buy a pay-as-you-go credit pack
  app.post('/v1/billing/credits/topup', async (req, res) => {
    const { keyId, packId, successUrl, cancelUrl } = req.body || {};
    if (!keyId)  return res.status(400).json({ error: 'keyId required' });
    if (!packId) return res.status(400).json({ error: 'packId required (credits-50 | credits-200 | credits-1000)' });

    const pack = Object.values(CREDIT_PACKS).find(p => p.id === packId);
    if (!pack) return res.status(400).json({ error: 'Unknown packId' });

    const stripe  = _getStripe();
    const priceId = creditPackPriceId(packId);

    if (!stripe || !priceId) {
      return res.status(503).json({
        error: 'Stripe not configured for credit packs',
        pack,
        missing: { stripeSecret: !process.env.STRIPE_SECRET_KEY, stripePrice: !priceId }
      });
    }

    try {
      const session = await stripe.checkout.sessions.create({
        mode: 'payment',                          // one-time, not subscription
        payment_method_types: ['card'],
        line_items: [{ price: priceId, quantity: 1 }],
        success_url: successUrl || 'https://bekasbah.com/billing/success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url:  cancelUrl  || 'https://bekasbah.com/pricing',
        client_reference_id: keyId,
        metadata: { keyId, packId, credits: pack.credits, productType: 'credits' }
      });
      return res.json({ checkoutUrl: session.url, sessionId: session.id, pack });
    } catch (e) {
      return res.status(500).json({ error: 'Stripe checkout failed', detail: e.message });
    }
  });

  // POST /v1/billing/portal — Stripe customer portal (manage subscription)
  app.post('/v1/billing/portal', async (req, res) => {
    const stripe = _getStripe();
    const { workspaceId, returnUrl } = req.body || {};
    if (!workspaceId) return res.status(400).json({ error: 'workspaceId required' });
    const ws = getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ error: 'Workspace not found' });
    if (!ws.stripeCustomerId) return res.status(400).json({ error: 'No active subscription for this workspace' });
    if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });
    try {
      const session = await stripe.billingPortal.sessions.create({
        customer: ws.stripeCustomerId,
        return_url: returnUrl || 'https://bekasbah.com/billing'
      });
      return res.json({ portalUrl: session.url });
    } catch (e) {
      return res.status(500).json({ error: 'Portal session failed', detail: e.message });
    }
  });

  // POST /v1/billing/webhook — Stripe webhook receiver
  const express = require('express');
  app.post('/v1/billing/webhook', express.raw({ type: 'application/json' }), (req, res) => {
    const signature = req.headers['stripe-signature'];
    const rawBody = req.body && Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
    const verify = verifyWebhookSignature(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET);
    if (!verify.valid) {
      return res.status(400).json({ error: 'Invalid signature', detail: verify.error });
    }

    let event;
    try { event = JSON.parse(rawBody); }
    catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const meta = session.metadata || {};
        if (meta.productType === 'credits') {
          // Pay-as-you-go credit top-up
          const keyId = session.client_reference_id || meta.keyId;
          const credits = parseInt(meta.credits, 10) || 0;
          if (keyId && credits > 0) {
            usageMeter.addCredits(keyId, credits);
            console.log(`[billing] credits +${credits} → key ${keyId}`);
          }
        } else {
          // Subscription
          const workspaceId = session.client_reference_id || meta.workspaceId;
          if (workspaceId) {
            updateWorkspace(workspaceId, {
              tier:                 meta.tier || 'pro',
              stripeCustomerId:     session.customer,
              stripeSubscriptionId: session.subscription,
              billingInterval:      meta.interval || 'monthly',
              planActivatedAt:      new Date().toISOString()
            });
            console.log(`[billing] workspace ${workspaceId} → ${meta.tier} (${meta.interval})`);
          }
        }
        break;
      }
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const priceId = sub.items?.data?.[0]?.price?.id;
        const newTier = priceToTier(priceId);
        const workspaceId = sub.metadata?.workspaceId;
        if (workspaceId && newTier) {
          updateWorkspace(workspaceId, { tier: newTier });
          console.log(`[billing] workspace ${workspaceId} → ${newTier} (sub.updated)`);
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const workspaceId = sub.metadata?.workspaceId;
        if (workspaceId) {
          updateWorkspace(workspaceId, { tier: 'free', stripeSubscriptionId: null });
          console.log(`[billing] workspace ${workspaceId} → free (sub.deleted)`);
        }
        break;
      }
      case 'invoice.payment_failed': {
        const inv = event.data.object;
        console.warn(`[billing] payment failed for customer ${inv.customer}`);
        // TODO: email user about failed payment
        break;
      }
      default: break;
    }

    return res.json({ received: true, type: event.type });
  });

  // GET /v1/billing/status?workspaceId=... — current subscription state + usage
  app.get('/v1/billing/status', (req, res) => {
    const wsId = req.query.workspaceId;
    if (!wsId) return res.status(400).json({ error: 'workspaceId query param required' });
    const ws = getWorkspace(wsId);
    if (!ws) return res.status(404).json({ error: 'Workspace not found' });
    const plan = PLANS[ws.tier] || PLANS.free;
    res.json({
      workspaceId:          ws.id,
      tier:                 ws.tier,
      tierLabel:            plan.name,
      tagline:              plan.tagline,
      limits:               plan.limits,
      billingInterval:      ws.billingInterval || 'monthly',
      stripeCustomerId:     ws.stripeCustomerId || null,
      stripeSubscriptionId: ws.stripeSubscriptionId || null,
      planActivatedAt:      ws.planActivatedAt || null,
      stripeConfigured:     !!process.env.STRIPE_SECRET_KEY
    });
  });
}

module.exports = { mount, verifyWebhookSignature, priceToTier, PLANS, CREDIT_PACKS };
