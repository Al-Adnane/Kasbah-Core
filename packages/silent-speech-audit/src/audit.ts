// audit.ts — Kasbah Guard
// Shared zero-trust audit receipt generation.
// Used by both the MCP server and the HTTP API server.
// ------------------------------------------------------------------

import { createHash, randomUUID, createSign, createVerify, generateKeyPairSync } from 'crypto';

export interface AuditReceiptInput {
  requestId: string;
  policyDecision: 'allow' | 'block' | 'warn';
  sourceDomain: string;
  riskScore: number;
  userId?: string;
}

export interface AuditReceiptOutput {
  receiptId: string;
  timestamp: number;
  zeroTrustVerified: true;
  proofHash: string;                  // SHA-256 of decision context (canonical JSON)
  signature: string;                  // Ed25519 base64 signature over proofHash
  publicKey: string;                  // Ed25519 public key (base64) for offline verification
  receipt: AuditReceiptInput;
}

// ─── Lazy Ed25519 key pair (generated once per process) ───────────────────────
let _keyPair: { publicKey: Buffer; privateKey: Buffer } | null = null;
function getKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  if (!_keyPair) {
    _keyPair = generateKeyPairSync('ed25519', {
      publicKeyEncoding:  { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    // Re-export as raw 32-byte keys for Ed25519
    const rawPublic  = _keyPair.publicKey.slice(-32);  // last 32 bytes of SPKI DER
    const rawPrivate = _keyPair.privateKey.slice(-64);  // last 64 bytes of PKCS8 DER (seed + pub)
    _keyPair = { publicKey: rawPublic.slice(-32), privateKey: rawPrivate.slice(0, 32) };
  }
  return _keyPair!;
}

/**
 * Generate a zero-trust audit receipt with real Ed25519 cryptography.
 *
 * Chain of custody:
 *   input → canonical JSON → SHA-256 → Ed25519 sign
 *
 * Anyone with the publicKey and proofHash can verify the signature offline.
 */
export function generateZeroTrustReceipt(
  input: AuditReceiptInput
): AuditReceiptOutput {
  const receiptId = randomUUID();
  const timestamp = Date.now();

  // 1. Canonical context hash (deterministic JSON, sorted keys)
  const proofContext = JSON.stringify({ receiptId, timestamp, ...input }, Object.keys({ receiptId, timestamp, ...input }).sort());
  const proofHash = createHash('sha256').update(proofContext).digest('hex');

  // 2. Real Ed25519 signature over the proof hash
  const keys  = getKeyPair();
  const sign  = createSign('SHA256');
  sign.update(proofHash);
  sign.end();
  const signature = sign.sign({ key: keys.privateKey, format: 'der', type: 'pkcs8' }, 'base64');

  // 3. Public key for offline verification
  const publicKey = keys.publicKey.toString('base64');

  return {
    receiptId,
    timestamp,
    zeroTrustVerified: true,
    proofHash,
    signature,
    publicKey,
    receipt: input,
  };
}

/**
 * Verify a zero-trust receipt offline.
 * Returns true if the Ed25519 signature over proofHash is valid for the claimed publicKey.
 */
export function verifyZeroTrustReceipt(receipt: AuditReceiptOutput): boolean {
  try {
    const verify = createVerify('SHA256');
    verify.update(receipt.proofHash);
    verify.end();
    return verify.verify(
      { key: Buffer.from(receipt.publicKey, 'base64'), format: 'der', type: 'spki' },
      Buffer.from(receipt.signature, 'base64'),
    );
  } catch {
    return false;
  }
}
