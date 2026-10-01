'use strict';

/**
 * tracker-blocklist.js — single source of truth for the Kasbah Browser's
 * tracker/ad/fingerprinting block list. Required directly by main.js (which
 * does the REAL blocking, via session.webRequest.onBeforeRequest on each
 * webview's own session — this catches sub-resource loads like ad iframes,
 * tracking pixels, and analytics XHR/fetch calls, not just full-page
 * navigations) and exposed read-only to the renderer via IPC so the UI shows
 * the exact same list it's enforcing.
 */

const CATEGORIES = {
  'ad-networks': [
    'doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'adnxs.com',
    'criteo.com', 'criteo.net', 'amazon-adsystem.com', 'adsafeprotected.com', 'moatads.com',
    'advertising.com', 'pubmatic.com', 'rubiconproject.com', 'openx.net', 'casalemedia.com',
    'contextweb.com', 'indexexchange.com', 'smartadserver.com', 'adform.net', 'yieldmo.com',
    'sharethrough.com', 'adroll.com', 'bidswitch.net', 'rlcdn.com', 'mathtag.com',
    'adsrvr.org', 'tapad.com', 'media.net', 'revcontent.com', 'mgid.com', 'zemanta.com',
    'taboola.com', 'outbrain.com', 'adbrite.com', 'tribalfusion.com', 'turn.com',
  ],
  'analytics-trackers': [
    'google-analytics.com', 'googletagmanager.com', 'scorecardresearch.com', 'quantserve.com',
    'segment.io', 'segment.com', 'amplitude.com', 'mixpanel.com', 'heap.io', 'heapanalytics.com',
    'chartbeat.com', 'newrelic.com', 'optimizely.com', 'crazyegg.com', 'kissmetrics.com',
    'clicktale.net', 'statcounter.com', 'matomo.org', 'piwik.pro', 'woopra.com',
    'bugsnag.com', 'sentry-cdn.com', 'pendo.io',
  ],
  'social-widgets': [
    'connect.facebook.net', 'facebook.net', 'platform.twitter.com', 'ads.twitter.com',
    'platform.linkedin.com', 'ads.linkedin.com', 'widgets.pinterest.com',
    'disqus.com', 'disquscdn.com', 'addthis.com', 'sharethis.com',
    'analytics.tiktok.com', 'snap.licdn.com', 'ads-api.tiktok.com',
  ],
  'fingerprinting-services': [
    'fingerprintjs.com', 'fpjs.io', 'fingerprint.com', 'iovation.com', 'threatmetrix.com',
    'sift.com', 'forter.com', 'signifyd.com', 'riskified.com',
    'perimeterx.net', 'perimeterx.com', 'shieldsquare.com', 'distilnetworks.com',
    'datadome.co',
  ],
  'session-replay': [
    'fullstory.com', 'mouseflow.com', 'hotjar.com', 'clarity.ms', 'smartlook.com',
    'luckyorange.com', 'inspectlet.com', 'sessioncam.com', 'decibelinsight.com',
    'quantummetric.com', 'glassbox.com',
  ],
  'crypto-miners': [
    'coinhive.com', 'crypto-loot.com', 'coin-have.com', 'minero.cc', 'webminepool.com',
  ],
};

const FLAT = new Map(); // domain -> category, for O(1) exact lookups
for (const [cat, domains] of Object.entries(CATEGORIES)) {
  for (const d of domains) FLAT.set(d, cat);
}

/** Category name if hostname exactly matches or is a subdomain of a blocked
 *  domain; null otherwise. */
function categoryFor(hostname) {
  if (!hostname) return null;
  if (FLAT.has(hostname)) return FLAT.get(hostname);
  const parts = hostname.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    const suffix = parts.slice(i).join('.');
    if (FLAT.has(suffix)) return FLAT.get(suffix);
  }
  return null;
}

function isBlocked(hostname) { return categoryFor(hostname) !== null; }

/**
 * Like categoryFor, but respects the per-category toggles stored in browser
 * settings. Returns null if the category is disabled.
 * @param {string} hostname
 * @param {string[]} [disabledCategories] — category keys to skip blocking
 */
function categoryForWithToggles(hostname, disabledCategories = []) {
  const cat = categoryFor(hostname);
  if (!cat) return null;
  if (disabledCategories.includes(cat)) return null;
  return cat;
}

module.exports = { CATEGORIES, categoryFor, categoryForWithToggles, isBlocked, count: FLAT.size };
