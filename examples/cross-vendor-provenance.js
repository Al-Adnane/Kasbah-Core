'use strict';
/*
 * Cross-vendor agent provenance — the demo built for the frontier labs.
 *
 * A single delegated task ("pay supplier invoice #4471 for $9,500") hops across
 * THREE model vendors: an orchestrator on Claude delegates verification to a
 * Gemini agent, which hands the payment action to a GPT agent. Each hop is
 * governed inline and signed — and the receipts CHAIN into one provenance tree.
 *
 * The point: every receipt in the chain is signed by ONE neutral key — Kasbah's,
 * in the request path — NOT by Anthropic, Google, or OpenAI. No single vendor can
 * issue this chain, because no vendor sees (or would be trusted to attest) the
 * other vendors' hops. A regulator who trusts none of the three can still verify
 * the whole thing offline. That neutral, cross-vendor attestation is the thing a
 * lab cannot build for itself.
 *
 * Run:  node packages/api-server/server.js      (terminal 1)
 *       node examples/cross-vendor-provenance.js (terminal 2)
 */
const http = require('http');
const { verify, verifyChain } = require('../packages/kasbah-receipts/src/index.js');

const API = 'http://localhost:8788';
const line = () => console.log('─'.repeat(72));

function call(provider, content, chainId, parentReceipt) {
  const data = JSON.stringify({ model: 'auto', messages: [{ role: 'user', content }] });
  const u = new URL(`${API}/v1/proxy/${provider}/v1/chat/completions`);
  const headers = {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(data),
    'x-kasbah-receipt-alg': 'ed25519',
    'x-kasbah-chain-id': chainId,
  };
  if (parentReceipt) headers['x-kasbah-parent-receipt'] = parentReceipt;
  return new Promise((resolve, reject) => {
    const r = http.request({ method: 'POST', hostname: u.hostname, port: u.port, path: u.pathname, headers }, res => {
      let b = ''; res.on('data', c => b += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(b) }));
    });
    r.on('error', reject); r.write(data); r.end();
  });
}

async function getKey() {
  return new Promise((resolve, reject) => {
    http.get(`${API}/v1/keys`, res => { let b = ''; res.on('data', c => b += c); res.on('end', () => resolve(JSON.parse(b))); }).on('error', reject);
  });
}

(async () => {
  const chainId = 'wf_invoice_4471';
  console.log('\n\x1b[1m  ONE delegated task, THREE vendors, ONE provenance chain\x1b[0m');
  console.log('  task: "approve and pay supplier invoice #4471 — $9,500"');
  line();

  // Hop 1 — orchestrator on Claude delegates the work (root of the chain)
  const h1 = await call('anthropic', 'Orchestrate: verify invoice #4471 then authorise payment of $9,500 to the supplier on file.', chainId, null);
  const r1 = h1.headers['x-kasbah-receipt'], p1 = h1.headers['x-kasbah-receipt-payload'];
  console.log(`  hop 1 · Anthropic (Claude)  delegate     verdict=${h1.body._kasbah.gov.verdict.padEnd(16)} ${r1.slice(0, 46)}…`);

  // Hop 2 — a Gemini agent verifies the invoice, linked to hop 1
  const h2 = await call('google', 'Verify invoice #4471 line items and supplier bank details against the PO.', chainId, r1);
  const r2 = h2.headers['x-kasbah-receipt'], p2 = h2.headers['x-kasbah-receipt-payload'];
  console.log(`  hop 2 · Google (Gemini)     verify       verdict=${h2.body._kasbah.gov.verdict.padEnd(16)} ${r2.slice(0, 46)}…`);

  // Hop 3 — a GPT agent executes the consequential payment action, linked to hop 2
  const h3 = await call('openai', 'Execute wire transfer of $9,500 to supplier account for invoice #4471.', chainId, r2);
  const r3 = h3.headers['x-kasbah-receipt'], p3 = h3.headers['x-kasbah-receipt-payload'];
  console.log(`  hop 3 · OpenAI (GPT)        pay $9,500   verdict=${h3.body._kasbah.gov.verdict.padEnd(16)} ${r3.slice(0, 46)}…`);

  // Who signed these three receipts?
  const keys = await getKey();
  const pem = keys.keys[0].publicKeyPem;
  const signer = keys.keys[0].keyId;
  line();
  console.log(`  every hop signed by ONE key: ${signer}  (the neutral layer — not Anthropic, Google, or OpenAI)`);

  // A neutral auditor reconstructs the whole cross-vendor chain, leaf → root.
  console.log('\n\x1b[1m  Neutral auditor verifies the full chain (offline, one public key)\x1b[0m');
  line();
  const chain = [
    { receipt: r3, payload: p3 },
    { receipt: r2, payload: p2 },
    { receipt: r1, payload: p1 },
  ];
  const res = verifyChain(chain, pem);
  console.log(`  verifyChain([GPT → Gemini → Claude]) → \x1b[${res.valid ? '32' : '31'}m${res.valid ? `✓ VALID · depth ${res.depth} · chainId ${res.chainId}` : '✗ ' + res.error}\x1b[0m`);

  // Tamper any single hop → that hop and everything downstream collapse.
  console.log('\n\x1b[1m  Tamper the Gemini hop — the chain refuses to reconnect\x1b[0m');
  line();
  const forgedChain = [
    { receipt: r3, payload: p3 },
    { receipt: r2.slice(0, -6) + 'AAAAAA', payload: p2 }, // alter the middle receipt
    { receipt: r1, payload: p1 },
  ];
  const bad = verifyChain(forgedChain, pem);
  console.log(`  verifyChain(tampered hop 2) → \x1b[${bad.valid ? '31' : '32'}m${bad.valid ? '✗ accepted (BAD)' : '✓ REJECTED — ' + bad.error}\x1b[0m`);

  line();
  console.log('\n  No single vendor can issue this chain — each sees only its own hop.');
  console.log('  A neutral layer in the request path can. That is the trust fabric the');
  console.log('  multi-vendor agent economy needs — and what makes those agents deployable.\n');
})().catch(e => { console.error(e); process.exit(1); });
