'use strict';

/**
 * DNS-over-HTTPS resolver — queries Cloudflare and Google DoH endpoints
 * so DNS lookups never hit the OS resolver (which leaks to the ISP/VPN provider).
 * Used by privacy:dns-leak-check and any internal hostname probes.
 */

const https = require('https');
const dns = require('dns').promises;

const DOH_PROVIDERS = [
  { name: 'cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'google',     url: 'https://dns.google/resolve' },
  { name: 'nextdns',    url: 'https://dns.nextdns.io/dns-query' },
];

/**
 * Resolve `hostname` via DoH. Returns the resolved IPs or throws.
 * @param {string} hostname
 * @param {'A'|'AAAA'} [type='A']
 * @param {string} [providerUrl] - override DoH endpoint
 * @returns {Promise<string[]>} list of IP addresses
 */
function resolve(hostname, type = 'A', providerUrl) {
  const base = providerUrl || DOH_PROVIDERS[0].url;
  const url = `${base}?name=${encodeURIComponent(hostname)}&type=${type}`;
  return new Promise((res, rej) => {
    const req = https.get(url, {
      headers: { Accept: 'application/dns-json' },
      timeout: 5000,
    }, (resp) => {
      let data = '';
      resp.on('data', (d) => { data += d; });
      resp.on('end', () => {
        try {
          const json = JSON.parse(data);
          const answers = (json.Answer || []).filter((a) => a.type === (type === 'A' ? 1 : 28));
          res(answers.map((a) => a.data));
        } catch (e) { rej(e); }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('DoH timeout')); });
    req.on('error', rej);
  });
}

/**
 * Probe all configured DoH providers and compare results.
 * Returns { consistent: bool, results: [{provider, ips}], leakDetected: bool }
 */
async function probeAll(hostname) {
  const results = await Promise.allSettled(
    DOH_PROVIDERS.map(async (p) => ({
      provider: p.name,
      ips: await resolve(hostname, 'A', p.url),
    }))
  );

  const ok = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  const allIps = ok.map((r) => r.ips.sort().join(','));
  const consistent = allIps.length > 1 && new Set(allIps).size === 1;

  return { consistent, results: ok, leakDetected: !consistent && ok.length > 1 };
}

/**
 * DNS leak check: resolve the same real hostname via DoH and via the OS
 * resolver (Node's dns.lookup, which follows the system's normal resolution
 * path — /etc/resolv.conf, mDNSResponder on macOS, etc.) and compare.
 *
 * Honest scope: this can only observe what the OS resolver *returns*, not
 * which network path the query physically took (that would need packet
 * capture). A mismatch is a real signal something is resolving differently
 * than DoH; a match is reassuring but not proof no query ever leaves via a
 * different path outside this process (e.g. another app's own resolver).
 */
async function dnsLeakCheck(hostname = 'example.com') {
  const [dohResult, osResult] = await Promise.allSettled([
    probeAll(hostname),
    dns.lookup(hostname, { all: true, family: 4 }),
  ]);

  const probe = dohResult.status === 'fulfilled' ? dohResult.value : null;
  const osIps = osResult.status === 'fulfilled' ? osResult.value.map((a) => a.address).sort() : null;
  const dohIps = probe ? [...new Set(probe.results.flatMap((r) => r.ips))].sort() : null;

  const osMatchesDoh = !!(osIps && dohIps && osIps.length && dohIps.length &&
    osIps.some((ip) => dohIps.includes(ip)));

  let summary;
  if (!probe) summary = 'DoH unreachable — cannot compare against the OS resolver';
  else if (!osIps) summary = 'OS resolver lookup failed — cannot complete the comparison';
  else if (osMatchesDoh) summary = 'OS resolver result overlaps with DoH — no discrepancy observed';
  else summary = 'OS resolver returned different addresses than DoH — investigate DNS routing';

  return {
    dohWorking: probe !== null,
    providers: probe ? probe.results.map((r) => r.provider) : [],
    consistent: probe ? probe.consistent : false,
    osResolverChecked: osResult.status === 'fulfilled',
    osIps: osIps || [],
    dohIps: dohIps || [],
    osMatchesDoh,
    summary,
  };
}

module.exports = { resolve, probeAll, dnsLeakCheck, DOH_PROVIDERS };
