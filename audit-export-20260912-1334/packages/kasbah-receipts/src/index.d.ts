/** @kasbah/receipts — signed, portable, offline-verifiable receipts for AI agent actions. */

import { KeyObject } from 'crypto';

export type Verdict = 'ALLOW' | 'WARN' | 'DENY';
export type Algorithm =
  | 'ed25519'
  | 'dilithium2' | 'dilithium3' | 'dilithium5'
  | 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';

export interface ReceiptPayload {
  verdict: Verdict;
  risk: number;
  requestId: string;
  subject?: string | null;
  passportId?: string | null;
  id?: string;
  ts?: number;
  engine?: string;
  surface?: string;
  action?: string;
  attestationType?: string;
  chainId?: string | null;
  parentReceipt?: string | null;
  merkleRoot?: string | null;
  merkleProof?: MerkleProofElement[] | null;
  [key: string]: unknown;
}

export type PublicKeyInput = string | Buffer | Uint8Array | KeyObject;
export type PrivateKeyInput = string | Buffer | Uint8Array | KeyObject;

export interface SignKeys {
  privateKey?: PrivateKeyInput;       // Ed25519
  secretKey?: Uint8Array;             // ML-DSA
  publicKey?: Uint8Array;             // ML-DSA
}

export interface SignOptions {
  algorithm?: Algorithm;
  attestationType?: string;
  chainId?: string | null;
  parentReceipt?: string | null;
  merkleRoot?: string | null;
  merkleProof?: MerkleProofElement[] | null;
  engine?: string;
}

export interface SignedReceipt {
  receipt: string;
  payload: string;
  decoded: ReceiptPayload & { v: number; keyId: string };
  keyId: string;
}

export interface VerifyResult {
  valid: boolean;
  decoded?: ReceiptPayload & { v: number; keyId: string };
  keyId?: string;
  algorithm?: string;
  error?: string;
}

export interface ChainResult {
  valid: boolean;
  depth?: number;
  chainId?: string | null;
  error?: string;
  failedAt?: number;
}

export interface MerkleProofElement {
  hash: string;
  pos: 'left' | 'right';
}

export interface ReceiptRef {
  receipt: string;
  payload: string;
}

export interface KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
  publicKeyRaw: Buffer;
  keyId: string;
}

export interface WellKnownKey {
  kid?: string;
  alg?: string;
  x?: string;
  pem?: string;
}

export function sign(payload: ReceiptPayload, keys: SignKeys | PrivateKeyInput, opts?: SignOptions): SignedReceipt;
export function verify(receipt: string, payloadB64: string, publicKey: PublicKeyInput): VerifyResult;
export function verifyChain(chain: ReceiptRef[], publicKey: PublicKeyInput): ChainResult;
export function merkleBatch(batch: ReceiptRef[]): { root: string; proofs: Map<string, MerkleProofElement[]> };
export function verifyMerkleProof(receipt: string, payloadB64: string, proof: MerkleProofElement[], root: string): { valid: boolean; error?: string };
export function receiptHash(receipt: string, payloadB64: string): string;
export function canonicalJSON(obj: unknown): string;
export function generateKeyPair(): KeyPair;
export function keyIdOf(publicKey: PublicKeyInput): string;
export function fetchPublicKeys(baseUrl: string): Promise<WellKnownKey[]>;
export function b64url(buf: Buffer | Uint8Array | string): string;
export function b64urlDecode(s: string): Buffer;
