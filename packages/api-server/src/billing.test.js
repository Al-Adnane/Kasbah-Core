'use strict';
/**
 * billing.test.js — tier ↔ Stripe price round-trip (audit M4).
 * The two directions used to read different env names, so a subscription could
 * resolve to a null tier. Run: node src/billing.test.js
 */
const assert = require('assert');

const ENV = {
  STRIPE_PRICE_PERSONAL_MONTHLY: 'p_per_m',  STRIPE_PRICE_PERSONAL_ANNUAL: 'p_per_a',
  STRIPE_PRICE_FAMILY_MONTHLY: 'p_fam_m',    STRIPE_PRICE_FAMILY_ANNUAL: 'p_fam_a',
  STRIPE_PRICE_DEVELOPER_MONTHLY: 'p_dev_m', STRIPE_PRICE_DEVELOPER_ANNUAL: 'p_dev_a',
  STRIPE_PRICE_TEAM_MONTHLY: 'p_team_m',     STRIPE_PRICE_TEAM_ANNUAL: 'p_team_a',
  STRIPE_PRICE_BUSINESS_MONTHLY: 'p_biz_m',  STRIPE_PRICE_BUSINESS_ANNUAL: 'p_biz_a',
  STRIPE_PRICE_ENTERPRISE: 'p_ent',
};
Object.assign(process.env, ENV);

const { priceIdFor, priceToTier } = require('./billing.js');

let n = 0;
for (const tier of ['personal', 'family', 'developer', 'team', 'business']) {
  for (const iv of ['monthly', 'annual']) {
    const pid = priceIdFor(tier, iv);
    assert.ok(pid, `${tier}/${iv} must have a price id`);
    assert.strictEqual(priceToTier(pid), tier, `${tier}/${iv} must round-trip`);
    n++;
  }
}
// Legacy aliases resolve to the canonical tier.
assert.strictEqual(priceIdFor('starter'), ENV.STRIPE_PRICE_DEVELOPER_MONTHLY);
assert.strictEqual(priceToTier(ENV.STRIPE_PRICE_TEAM_MONTHLY), 'team');
assert.strictEqual(priceToTier(ENV.STRIPE_PRICE_ENTERPRISE), 'enterprise');
n += 3;

console.log(`billing tier round-trip: ${n} assertions passed`);
