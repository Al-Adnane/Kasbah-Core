'use strict';

/**
 * Post-quantum hybrid preshared keys for WireGuard.
 *
 * WireGuard's handshake is X25519 — quantum-vulnerable to
 * harvest-now-decrypt-later. Its designed escape hatch is the PresharedKey
 * slot: a 32-byte symmetric key mixed into the handshake, so the tunnel stays
 * confidential even if Curve25519 falls. This module fills that slot from an
 * ML-KEM-768 (FIPS 203) encapsulation, the same pattern Rosenpass and
 * Mullvad's quantum-resistant tunnels use:
 *
 *   responder: kemKeypair()            → publish publicKey
 *   initiator: encapsulate(publicKey)  → send ciphertext, keep psk
 *   responder: decapsulate(secretKey, ciphertext) → same psk
 *
 * Both sides HKDF the KEM shared secret before use so the raw secret never
 * leaves this module. The result is a standard wg-format base64 PSK.
 *
 * Requires optional peer dep @noble/post-quantum. Everything else in the
 * package works without it.
 */

const crypto = require('crypto');

const HKDF_INFO = 'kasbah-vpn wireguard psk v1';

let _mlkem = null;
function mlkem() {
  if (!_mlkem) {
    try {
      _mlkem = require('@noble/post-quantum/ml-kem.js').ml_kem768;
    } catch {
      throw new Error(
        'post-quantum PSK requires optional dependency @noble/post-quantum (npm i @noble/post-quantum)'
      );
    }
  }
  return _mlkem;
}

function pskFromSharedSecret(sharedSecret) {
  const okm = crypto.hkdfSync('sha256', Buffer.from(sharedSecret), Buffer.alloc(0), HKDF_INFO, 32);
  return Buffer.from(okm).toString('base64');
}

/** Responder: generate an ML-KEM-768 keypair. Returns base64 strings. */
function kemKeypair() {
  const { publicKey, secretKey } = mlkem().keygen();
  return {
    publicKey: Buffer.from(publicKey).toString('base64'),
    secretKey: Buffer.from(secretKey).toString('base64'),
  };
}

/** Initiator: encapsulate against the responder's KEM public key. */
function encapsulate(kemPublicKeyB64) {
  const pk = Buffer.from(String(kemPublicKeyB64).trim(), 'base64');
  const { cipherText, sharedSecret } = mlkem().encapsulate(new Uint8Array(pk));
  return {
    ciphertext: Buffer.from(cipherText).toString('base64'),
    psk: pskFromSharedSecret(sharedSecret),
  };
}

/** Responder: decapsulate the initiator's ciphertext → identical PSK. */
function decapsulate(kemSecretKeyB64, ciphertextB64) {
  const sk = Buffer.from(String(kemSecretKeyB64).trim(), 'base64');
  const ct = Buffer.from(String(ciphertextB64).trim(), 'base64');
  const sharedSecret = mlkem().decapsulate(new Uint8Array(ct), new Uint8Array(sk));
  return { psk: pskFromSharedSecret(sharedSecret) };
}

/** Classical fallback PSK (still hardens WG, no PQ property). */
function randomPsk() {
  return crypto.randomBytes(32).toString('base64');
}

module.exports = { kemKeypair, encapsulate, decapsulate, randomPsk, HKDF_INFO };
