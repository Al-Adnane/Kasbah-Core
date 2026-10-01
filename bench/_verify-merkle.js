const mb = require('../packages/crypto-utils/src/merkle-batch.js');
const crypto = require('crypto');
function sha256hex(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }

const receipts = [
  { receipt: 'kasbah_receipt:v3:ed25519:aaa:sig1', payload: 'payload1' },
  { receipt: 'kasbah_receipt:v3:ed25519:bbb:sig2', payload: 'payload2' },
  { receipt: 'kasbah_receipt:v3:ed25519:ccc:sig3', payload: 'payload3' },
];

const { root, proofs, leaves } = mb.buildMerkleTree(receipts);
console.log('Root:', root);
console.log('Sorted leaves:', leaves);

// Match receipts to their leaf hashes and verify
let allValid = true;
for (const r of receipts) {
  const leafHash = sha256hex(r.receipt + '|' + r.payload);
  const proof = proofs.get(leafHash);
  console.log('Receipt hash:', leafHash, 'has proof:', !!proof);
  if (proof) {
    const valid = mb.verifyMerkleProof(r.receipt, r.payload, proof, root);
    console.log('  valid:', valid);
    if (!valid) allValid = false;
  }
}
console.log('All proofs valid:', allValid);
console.log('Batch verify:', mb.verifyBatch(receipts, root).verified);
console.log('Deterministic:', mb.buildMerkleTree(receipts).root === root);
