/**
 * Kasbah Crypto Utils — Production Cryptography
 * 
 * Real encryption, signing, and hashing utilities.
 * No stubs. No mocks. Production-ready.
 * 
 * Features:
 * - AES-256-GCM encryption/decryption
 * - Ed25519 signing/verification
 * - SHA-256/512 hashing
 * - HMAC-SHA256
 * - Key derivation (PBKDF2)
 * - Random bytes generation
 * - Base64/hex encoding
 * 
 * @package @kasbah/crypto-utils
 * @version 1.0.0
 */

import * as CryptoJS from 'crypto-js';
import * as forge from 'node-forge';
import nacl from 'tweetnacl';

// ═══════════════════════════════════════════════════════════
// AES-256-GCM Encryption
// ═══════════════════════════════════════════════════════════

export interface EncryptedData {
  ciphertext: string;
  iv: string;
  authTag: string;
  salt: string;
}

/**
 * Encrypt data using AES-256-GCM
 * 
 * @param plaintext - Data to encrypt
 * @param password - Password for key derivation
 * @returns EncryptedData with ciphertext, iv, authTag, salt
 */
export function encrypt(plaintext: string, password: string): EncryptedData {
  // Generate random salt
  const salt = forge.random.getBytesSync(16);
  
  // Derive 256-bit key from password using PBKDF2
  const key = forge.pkcs5.pbkdf2(password, salt, 100000, 32, forge.md.sha256.create());
  
  // Generate random IV
  const iv = forge.random.getBytesSync(12);
  
  // Create cipher
  const cipher = forge.cipher.createCipher('AES-GCM', key);
  cipher.start({ iv });
  
  // Encrypt
  cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
  cipher.finish();
  
  // Get encrypted data
  const ciphertext = cipher.output.getBytes();
  const authTag = cipher.mode.tag.getBytes();
  
  return {
    ciphertext: forge.util.encode64(ciphertext),
    iv: forge.util.encode64(iv),
    authTag: forge.util.encode64(authTag),
    salt: forge.util.encode64(salt)
  };
}

/**
 * Decrypt data using AES-256-GCM
 *
 * @param encrypted - EncryptedData from encrypt()
 * @param password - Password for key derivation
 * @returns Decrypted plaintext
 */
export function decrypt(encrypted: EncryptedData, password: string): string {
  // Decode from base64
  const salt = forge.util.decode64(encrypted.salt);
  const iv = forge.util.decode64(encrypted.iv);
  const ciphertext = forge.util.decode64(encrypted.ciphertext);
  const authTag = forge.util.decode64(encrypted.authTag);

  // Derive key from password
  const key = forge.pkcs5.pbkdf2(password, salt, 100000, 32, forge.md.sha256.create());

  // Create decipher
  const decipher = forge.cipher.createDecipher('AES-GCM', key);
  decipher.start({ iv: iv as any, tag: authTag as any });

  // Decrypt
  decipher.update(forge.util.createBuffer(ciphertext));
  const result = decipher.finish();

  if (!result) {
    throw new Error('Decryption failed - invalid password or corrupted data');
  }

  return decipher.output.toString();
}

// ═══════════════════════════════════════════════════════════
// Ed25519 Signing (TweetNaCl)
// ═══════════════════════════════════════════════════════════

export interface KeyPair {
  publicKey: string;
  secretKey: string;
}

export interface Signature {
  signature: string;
  publicKey: string;
}

/**
 * Generate Ed25519 key pair
 *
 * @returns KeyPair with publicKey and secretKey (base64)
 */
export function generateKeyPair(): KeyPair {
  const pair = nacl.sign.keyPair();

  return {
    publicKey: Buffer.from(pair.publicKey).toString('base64'),
    secretKey: Buffer.from(pair.secretKey).toString('base64')
  };
}

/**
 * Sign message with Ed25519
 *
 * @param message - Message to sign
 * @param secretKey - Secret key (base64)
 * @returns Signature with signature and publicKey
 */
export function sign(message: string, secretKey: string): Signature {
  const secretKeyBytes = Buffer.from(secretKey, 'base64');
  const messageBytes = Buffer.from(message, 'utf8');

  const signature = nacl.sign(
    messageBytes,
    secretKeyBytes
  );

  // Extract public key from secret key (first 32 bytes of secret key)
  const publicKeyBytes = secretKeyBytes.slice(32, 64);

  return {
    signature: Buffer.from(signature).toString('base64'),
    publicKey: Buffer.from(publicKeyBytes).toString('base64')
  };
}

/**
 * Verify Ed25519 signature
 *
 * @param message - Original message
 * @param signature - Signature (base64)
 * @param publicKey - Public key (base64)
 * @returns true if signature is valid
 */
export function verify(message: string, signature: string, publicKey: string): boolean {
  const signatureBytes = Buffer.from(signature, 'base64');
  const publicKeyBytes = Buffer.from(publicKey, 'base64');
  const messageBytes = Buffer.from(message, 'utf8');

  // Open signed message (verifies and extracts original)
  const result = nacl.sign.open(signatureBytes, publicKeyBytes);

  if (!result) {
    return false;
  }

  // Compare messages
  const originalMessage = Buffer.from(result).toString('utf8');
  return originalMessage === message;
}

// ═══════════════════════════════════════════════════════════
// Hashing (SHA-256, SHA-512)
// ═══════════════════════════════════════════════════════════

/**
 * SHA-256 hash
 * 
 * @param data - String or Buffer to hash
 * @returns Hex-encoded hash
 */
export function sha256(data: string | Buffer): string {
  const str = typeof data === 'string' ? data : data.toString('utf8');
  return CryptoJS.SHA256(str).toString();
}

/**
 * SHA-512 hash
 * 
 * @param data - String or Buffer to hash
 * @returns Hex-encoded hash
 */
export function sha512(data: string | Buffer): string {
  const str = typeof data === 'string' ? data : data.toString('utf8');
  return CryptoJS.SHA512(str).toString();
}

/**
 * HMAC-SHA256
 * 
 * @param data - Data to sign
 * @param secret - Secret key
 * @returns Hex-encoded HMAC
 */
export function hmac(data: string, secret: string): string {
  return CryptoJS.HmacSHA256(data, secret).toString();
}

/**
 * Hash file content
 * 
 * @param buffer - File buffer
 * @returns Object with sha256 and sha512 hashes
 */
export function hashFile(buffer: Buffer): { sha256: string; sha512: string } {
  return {
    sha256: sha256(buffer),
    sha512: sha512(buffer)
  };
}

// ═══════════════════════════════════════════════════════════
// Key Derivation (PBKDF2)
// ═══════════════════════════════════════════════════════════

/**
 * Derive key from password using PBKDF2
 * 
 * @param password - Password
 * @param salt - Salt (hex string)
 * @param iterations - Number of iterations (default: 100000)
 * @param keyLength - Key length in bytes (default: 32)
 * @returns Hex-encoded derived key
 */
export function deriveKey(
  password: string,
  salt: string,
  iterations: number = 100000,
  keyLength: number = 32
): string {
  const saltBytes = forge.util.hexToBytes(salt);
  const key = forge.pkcs5.pbkdf2(password, saltBytes, iterations, keyLength, forge.md.sha256.create());
  return forge.util.bytesToHex(key);
}

/**
 * Generate random salt
 * 
 * @param length - Salt length in bytes (default: 16)
 * @returns Hex-encoded salt
 */
export function generateSalt(length: number = 16): string {
  const salt = forge.random.getBytesSync(length);
  return forge.util.bytesToHex(salt);
}

// ═══════════════════════════════════════════════════════════
// Random Bytes
// ═══════════════════════════════════════════════════════════

/**
 * Generate cryptographically secure random bytes
 * 
 * @param length - Number of bytes
 * @returns Hex-encoded random bytes
 */
export function randomBytes(length: number = 32): string {
  const bytes = forge.random.getBytesSync(length);
  return forge.util.bytesToHex(bytes);
}

/**
 * Generate random string (for tokens, IDs, etc.)
 * 
 * @param length - String length
 * @returns Random alphanumeric string
 */
export function randomString(length: number = 32): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  
  const randomValues = forge.random.getBytesSync(length);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues.charCodeAt(i) % chars.length];
  }
  
  return result;
}

// ═══════════════════════════════════════════════════════════
// Encoding Utilities
// ═══════════════════════════════════════════════════════════

/**
 * Base64 encode
 */
export function base64Encode(data: string | Buffer): string {
  const str = typeof data === 'string' ? data : data.toString('utf8');
  return forge.util.encode64(str);
}

/**
 * Base64 decode
 */
export function base64Decode(encoded: string): string {
  return forge.util.decode64(encoded);
}

/**
 * Hex encode
 */
export function hexEncode(data: string | Buffer): string {
  const str = typeof data === 'string' ? data : data.toString('utf8');
  return forge.util.bytesToHex(str);
}

/**
 * Hex decode
 */
export function hexDecode(hex: string): string {
  return forge.util.hexToBytes(hex);
}

// ═══════════════════════════════════════════════════════════
// Export All
// ═══════════════════════════════════════════════════════════

export const crypto = {
  encrypt,
  decrypt,
  generateKeyPair,
  sign,
  verify,
  sha256,
  sha512,
  hmac,
  hashFile,
  deriveKey,
  generateSalt,
  randomBytes,
  randomString,
  base64Encode,
  base64Decode,
  hexEncode,
  hexDecode
};

export default crypto;

// ═══════════════════════════════════════════════════════════
// Advanced Cryptographic Primitives
// ═══════════════════════════════════════════════════════════

// Shamir's Secret Sharing (GF-256)
export { split, combine } from './shamir';

// Merkle Mountain Range
export { MMR } from './mmr';
export type { MerkleProof } from './mmr';

// Verifiable Delay Function
export {
  compute as vdfCompute,
  verify as vdfVerify,
  spotCheckVerify,
  extractCheckpoints,
  estimateTime,
  iterationsForDuration,
  benchmarkIterationsPerSecond,
  DEFAULT_1MIN,
  DEFAULT_1HOUR,
  DEFAULT_1DAY,
} from './vdf';
export type { VDFOutput } from './vdf';
