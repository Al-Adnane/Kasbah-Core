#!/usr/bin/env node
'use strict';

/* kasbah-verify — offline verifier for Kasbah receipts.
 *
 * Usage:
 *   kasbah-verify <receipt> <payloadB64> --key public.pem
 *   kasbah-verify <receipt> <payloadB64> --issuer https://gateway.example.com
 *   kasbah-verify --json receipts.json --key public.pem      (chain: leaf→root array)
 */

const fs = require('fs');
const { verify, verifyChain, fetchPublicKeys } = require('../src/index.js');

function usage(code) {
  console.log('Usage:\n  kasbah-verify <receipt> <payloadB64> --key <public.pem>\n  kasbah-verify <receipt> <payloadB64> --issuer <base-url>\n  kasbah-verify --json <chain.json> --key <public.pem>');
  process.exit(code);
}

async function main() {
  const args = process.argv.slice(2);
  if (!args.length || args.includes('--help') || args.includes('-h')) usage(0);

  const opt = (name) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : null;
  };

  let publicKey = null;
  const keyPath = opt('--key');
  const issuer = opt('--issuer');
  if (keyPath) {
    publicKey = fs.readFileSync(keyPath, 'utf8');
  } else if (issuer) {
    const keys = await fetchPublicKeys(issuer);
    if (!keys.length) { console.error('no keys published at issuer'); process.exit(2); }
    publicKey = keys[0].pem || Buffer.from(keys[0].x, 'base64');
  } else {
    console.error('one of --key or --issuer is required');
    usage(2);
  }

  const jsonPath = opt('--json');
  if (jsonPath) {
    const chain = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    const res = verifyChain(chain, publicKey);
    console.log(JSON.stringify(res, null, 2));
    process.exit(res.valid ? 0 : 1);
  }

  const positional = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--key' && args[i - 1] !== '--issuer' && args[i - 1] !== '--json');
  if (positional.length < 2) usage(2);
  const res = verify(positional[0], positional[1], publicKey);
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.valid ? 0 : 1);
}

main().catch(e => { console.error(e.message); process.exit(2); });
