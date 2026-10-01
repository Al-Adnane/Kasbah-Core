'use strict';

/**
 * Exit market — flight-card comparison of VPN exits.
 * “Price” = latency (ms); “availability” = last ping success.
 */

const netIntel = require('./net-intel.js');

async function listExits(locations = []) {
  const snap = await netIntel.networkSnapshot(locations);
  const byHost = {};
  for (const loc of locations) {
    const host = String(loc.endpoint || '').split(':')[0];
    if (host) byHost[host] = loc;
  }
  const cards = locations.map((loc) => {
    const host = String(loc.endpoint || '').split(':')[0];
    const p = (snap.pings || []).find((x) => x.host === host);
    return {
      id: loc.id,
      name: loc.name,
      flag: loc.flag || '🌐',
      free: loc.free !== false,
      endpoint: loc.endpoint,
      latencyMs: p && p.ok ? p.avgMs : null,
      lossPct: p ? p.lossPct : null,
      reachable: !!(p && p.ok),
      dpi: loc.obfs ? loc.obfs : null,
      // Flight-card metaphor
      priceLabel: p && p.ok ? `${Math.round(p.avgMs)}ms` : '—',
      grade: !p || !p.ok ? 'offline'
        : p.avgMs < 80 ? 'A'
        : p.avgMs < 150 ? 'B'
        : p.avgMs < 250 ? 'C' : 'D',
    };
  }).sort((a, b) => {
    if (a.reachable !== b.reachable) return a.reachable ? -1 : 1;
    return (a.latencyMs || 9999) - (b.latencyMs || 9999);
  });
  return {
    cards,
    recommend: snap.recommend ? snap.recommend.location?.id : (cards[0] && cards[0].id),
    isp: snap.isp,
    sampledAt: snap.ts,
  };
}

module.exports = { listExits };
