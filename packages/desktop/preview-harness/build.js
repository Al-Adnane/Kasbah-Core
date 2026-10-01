'use strict';
// Generates a browser-previewable copy of the desktop index.html by stubbing
// the Electron window.kasbah bridge, so the real UI renders in a plain browser
// for visual inspection/screenshots. Not shipped — dev tooling only.
const fs = require('fs');
const path = require('path');

const src = path.join(__dirname, '..', 'src', 'index.html');
const outDir = __dirname;
let html = fs.readFileSync(src, 'utf8');

const stub = `<script>
/* PREVIEW STUB — fakes the Electron bridge so the shell renders in a browser. */
(function(){
  const ok = (body) => Promise.resolve({ status: 200, body: body || {} });
  const noop = () => {};
  const apiFake = (method, endpoint) => {
    // Return shapes a few render paths expect; everything else gets {}.
    if (/\\/discover$/.test(endpoint||'')) return ok({ recommendations: [], surfaces: [] });
    if (/audit\\/chain/.test(endpoint||'')) return ok({ entries: [] });
    if (/stats/.test(endpoint||'')) return ok({ totalScans: 128, threatsBlocked: 7, allowed: 121 });
    if (/usage\\/me/.test(endpoint||'')) return ok({ tier: 'free', tierLabel: 'Free', used: 12, limit: 100 });
    if (/wifi-guard\\/analyze/.test(endpoint||'')) return ok({ ssid:'Starbucks WiFi', security:'open', risk:'HIGH', flags:[{ label:'Network has no encryption (open/no-auth) — all traffic is visible to nearby devices', level:'high' },{ label:'"Free WiFi" network — no authentication required', level:'high' }], recommendation:'Consider connecting via Kasbah VPN on this network' });
    if (/scam-shield\\/check/.test(endpoint||'')) return ok({ verdict:'LIKELY_SCAM', score:0.77, patternHits:[{ id:'irs-govt', label:'Impersonates a government agency with legal threats' },{ id:'verify-now', label:'Pressures immediate "verification" — classic phishing lure' }], engineRisk:0.45, latency_ms:38 });
    if (/family-safety\\/check/.test(endpoint||'')) return ok({ verdict:'REVIEW_NEEDED', score:0.34, patternHits:[{ id:'pii-school', label:'School name shared — location-adjacent PII' }], engineRisk:0.12, latency_ms:29 });
    if (/breach\\/check-password/.test(endpoint||'')) return ok({ ok:true, suffixes:[{ suffix:'B4C3B', count:0 }] });
    return ok({});
  };
  const handler = { get: (t, prop) => (prop in t ? t[prop] : (()=>ok({}))) };
  window.kasbah = new Proxy({
    api: apiFake, request: apiFake,
    get apiBase(){ return 'http://127.0.0.1:8788'; },
    govern: ()=>ok({ verdict:'ALLOW', threats:[] }),
    scan: ()=>ok({ verdict:'ALLOW', threats:[] }),
    health: ()=>ok({ status:'ok' }),
    getState: ()=>ok({ isProtected:true, stats:{ totalScans:128, threatsBlocked:7 } }),
    toggleProtection: ()=>ok(true),
    scanClipboard: ()=>ok({}),
    openUrl: noop, version: ()=>({}),
    onActivity: noop, onStateChange: noop,
    vpn: new Proxy({
      locations: () => Promise.resolve([
        { id:'ams', name:'Amsterdam, Netherlands', continent:'Europe', flag:'🇳🇱', endpoint:'137.66.62.25:51820', free:true },
        { id:'iad', name:'Ashburn, United States', continent:'North America', flag:'🇺🇸', endpoint:'169.155.62.129:51820', free:false },
      ]),
      state: () => Promise.resolve({ profile:null, receipts:[], aiLane:{running:false}, aiLaneEvents:[] }),
      connect: (id) => id === 'iad'
        ? Promise.resolve({ ok:false, requiresUpgrade:true, output:'Ashburn, United States requires a paid plan.' })
        : Promise.resolve({ ok:true, location:id, name:'Amsterdam, Netherlands' }),
    }, { get: (t, prop) => (prop in t ? t[prop] : (()=>ok({ profile:null, receipts:[], aiLane:{running:false}, aiLaneEvents:[] }))) }),
    vault: new Proxy({
      list: () => Promise.resolve([
        { id:'fake-1', site:'github.com', username:'adnane@example.com', passwordPreview:'••••••••' },
        { id:'fake-2', site:'google.com', username:'adnane@gmail.com', passwordPreview:'••••••••' },
      ]),
      add: (e) => Promise.resolve({ ok:true, id:'new-'+Date.now() }),
      delete: () => Promise.resolve({ ok:true }),
      get: (id) => Promise.resolve({ id, site:'example.com', username:'user', password:'demo-pw-123' }),
      generate: () => Promise.resolve('Xk9#mP2$vQn7Rz!4'),
    }, { get: (t,p) => p in t ? t[p] : (()=>ok({})) }),
    wifi: {
      getNetwork: () => Promise.resolve({ ssid:'Starbucks WiFi', security:'open' }),
    },
    backup: new Proxy({
      chooseFile: () => Promise.resolve([]),
      encrypt: () => Promise.resolve({ ok:true, originalName:'demo.pdf', size:12400 }),
      list: () => Promise.resolve([
        { file:'demo.pdf.kbk', originalName:'demo.pdf', size:12400, ts: new Date().toISOString() },
      ]),
      delete: () => Promise.resolve({ ok:true }),
    }, { get: (t,p) => p in t ? t[p] : (()=>ok({})) }),
  }, handler);
  try { localStorage.setItem('kg_ob','1'); } catch(_){}
})();
</script>`;

// Inject the stub as the very first thing after <head> so it runs before the app script.
html = html.replace(/<head>/i, '<head>\n' + stub);
// Also handle no-<head> case (harness wraps): if no <head>, prepend.
if (!/PREVIEW STUB/.test(html)) html = stub + html;

fs.writeFileSync(path.join(outDir, 'index.html'), html);
console.log('wrote preview harness:', path.join(outDir, 'index.html'), html.length, 'bytes');
