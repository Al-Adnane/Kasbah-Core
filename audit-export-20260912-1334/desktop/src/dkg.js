'use strict';

/**
 * dkg.js — Two-round Feldman VSS Distributed Key Generation.
 *
 * Protocol (Pedersen DKG, Gennaro et al. 1999 simplified for t-of-n):
 *
 *   Round 1 — Commitment broadcast
 *     Each participant i generates a random polynomial f_i of degree t−1:
 *       f_i(x) = a_{i,0} + a_{i,1}x + … + a_{i,t-1}x^{t-1}
 *     Broadcasts Feldman commitments: C_{i,k} = G^{a_{i,k}}  for k = 0..t-1
 *
 *   Round 2 — Share distribution
 *     Participant i sends share f_i(j) privately to each participant j.
 *     Participant j verifies: G^{f_i(j)} == prod_k C_{i,k}^{j^k}
 *     Each j's final share: S_j = sum_i f_i(j)  (mod ORDER)
 *
 *   Master public key: Y = prod_i C_{i,0}  (known to everyone, no trusted dealer)
 *   Master secret:     s = sum_i a_{i,0}   (known to NO single participant)
 *
 * What this is NOT:
 *   - Not robust (no complaint-and-disqualification round; Gennaro 2007).
 *   - Not distributed in network terms; share delivery transport is the
 *     app's existing authenticated channel. Each share f_i(j) MUST be
 *     encrypted to j's transport public key before transmission.
 *   - Not post-quantum.
 *
 * All coefficient randomness uses crypto.randomBytes (CSPRNG). Math.random()
 * is never used.
 */

const crypto = require('crypto');

/* ── load @noble/curves ──────────────────────────────────────────────────── */
let _ristretto255;
(function loadNoble() {
  const candidates = [
    '@noble/curves/ed25519.js',
    require('path').join(__dirname, '..', '..', '..', '..', 'node_modules', '@noble/curves', 'ed25519.js'),
    require('path').join(process.resourcesPath || '', 'app', 'node_modules', '@noble/curves', 'ed25519.js'),
  ];
  for (const c of candidates) {
    try { const m = require(c); _ristretto255 = m.ristretto255; return; } catch (_) {}
  }
  throw new Error('@noble/curves not found');
})();

const Point = _ristretto255.Point;
const ORDER = Point.Fn.ORDER;
const G     = Point.BASE;

const mod = (x) => ((x % ORDER) + ORDER) % ORDER;
const mul = (P, s) => { s = mod(s); return s === 0n ? Point.ZERO : P.multiply(s); };
const ph  = (P) => P.toHex();
const pp  = (hex) => Point.fromHex(hex);

function randScalar() {
  return mod(BigInt('0x' + crypto.randomBytes(64).toString('hex')));
}

/* ── Round 1: generate polynomial + commitments ─────────────────────────── */

/**
 * Start Round 1 for participant `id` (1-indexed).
 * Returns the state (keep private) and the broadcast commitments.
 *
 * @param {number} id                — this participant's id (1..n)
 * @param {number} threshold t       — minimum shares needed to reconstruct
 * @param {number} totalParticipants — n
 * @returns {{ state: DKGState, broadcast: DKGBroadcast }}
 */
function round1(id, threshold, totalParticipants) {
  if (!Number.isInteger(id) || id < 1 || id > totalParticipants) {
    throw new Error('id must be an integer in [1, totalParticipants]');
  }
  if (!Number.isInteger(threshold) || threshold < 2 || threshold > totalParticipants) {
    throw new Error('threshold must be an integer in [2, totalParticipants]');
  }

  const poly = [];
  const comms = [];
  for (let k = 0; k < threshold; k++) {
    const coeff = randScalar();
    poly.push(coeff);
    comms.push(ph(mul(G, coeff)));
  }

  const state = {
    id,
    threshold,
    n: totalParticipants,
    poly,          // KEEP SECRET — never broadcast
    comms,         // same as broadcast.commitments
  };

  const broadcast = {
    fromId: id,
    commitments: comms,  // C_{i,k} = G^{a_{i,k}} for k=0..t-1
  };

  return { state, broadcast };
}

/* ── Round 1 → 2: compute share for peer ────────────────────────────────── */

/**
 * Evaluate f_i(peerId) for delivery to peer.
 * The returned share value must be sent over an authenticated+encrypted channel.
 *
 * @param {DKGState} state
 * @param {number}   peerId — recipient participant id (1..n)
 * @returns {{ fromId, toId, value: bigint }}
 */
function computeShareForPeer(state, peerId) {
  if (peerId < 1 || peerId > state.n) throw new Error('peerId out of range');
  const x = mod(BigInt(peerId));
  let y = 0n;
  let xPow = 1n;
  for (const coeff of state.poly) {
    y = mod(y + coeff * xPow);
    xPow = mod(xPow * x);
  }
  return { fromId: state.id, toId: peerId, value: y };
}

/* ── Round 2: verify an incoming share ──────────────────────────────────── */

/**
 * Verify that share.value === f_{fromId}(myId) by checking against the
 * Feldman commitments broadcast by fromId.
 *
 * @param {{ fromId, toId, value: bigint }} share
 * @param {string[]} commitmentsFromSender   — fromId's broadcast commitments (hex)
 * @param {number}   myId
 * @returns {boolean}
 */
function verifyShare(share, commitmentsFromSender, myId) {
  try {
    if (share.toId !== myId) return false;
    const x = mod(BigInt(myId));
    // lhs = G^{f_i(j)}
    const lhs = mul(G, share.value);
    // rhs = prod_k C_{i,k}^{j^k}
    let rhs   = Point.ZERO;
    let xPow  = 1n;
    for (const Chex of commitmentsFromSender) {
      rhs  = rhs.add(mul(pp(Chex), xPow));
      xPow = mod(xPow * x);
    }
    return lhs.equals(rhs);
  } catch { return false; }
}

/* ── Round 2: aggregate shares → final key material ─────────────────────── */

/**
 * Aggregate verified shares to produce this participant's secret share and
 * the group's master public key.
 *
 * @param {DKGState}   state
 * @param {{ fromId, toId, value: bigint }[]} receivedShares — one per other participant
 * @param {Map<number, string[]>} allCommitments  — fromId → commitments[]
 * @returns {{ myShare: bigint, masterPublicKey: string }}
 */
function aggregate(state, receivedShares, allCommitments) {
  let myShare = 0n;

  // Include own share
  const ownShare = computeShareForPeer(state, state.id);
  myShare = mod(myShare + ownShare.value);

  for (const share of receivedShares) {
    if (share.toId !== state.id) continue;
    const comms = allCommitments.get(share.fromId);
    if (!comms) throw new Error(`missing commitments from participant ${share.fromId}`);
    if (!verifyShare(share, comms, state.id)) {
      throw new Error(`share from participant ${share.fromId} failed Feldman verification`);
    }
    myShare = mod(myShare + share.value);
  }

  // Master public key = sum of C_{i,0} for ALL participants (allCommitments includes own)
  let masterPk = Point.ZERO;
  for (const [, comms] of allCommitments) {
    masterPk = masterPk.add(pp(comms[0]));
  }

  return {
    myShare,
    masterPublicKey: ph(masterPk),
  };
}

/* ── Persistence helpers ─────────────────────────────────────────────────── */

/**
 * Serialize state for storage. poly coefficients are serialized as hex.
 * Store result at rest with the same AES-256-GCM the vault uses.
 */
function serializeState(state) {
  return {
    id: state.id,
    threshold: state.threshold,
    n: state.n,
    poly: state.poly.map((c) => c.toString(16)),
    comms: state.comms,
  };
}

function deserializeState(obj) {
  return {
    id: obj.id,
    threshold: obj.threshold,
    n: obj.n,
    poly: obj.poly.map((h) => BigInt('0x' + h)),
    comms: obj.comms,
  };
}

/* ── Self-test ──────────────────────────────────────────────────────────── */

function selfTest() {
  const N = 5, T = 3;
  const states = [];
  const broadcasts = new Map();

  // Round 1
  for (let i = 1; i <= N; i++) {
    const { state, broadcast } = round1(i, T, N);
    states.push(state);
    broadcasts.set(i, broadcast.commitments);
  }

  // Each participant sends all shares
  const inbox = new Map(); // toId → shares[]
  for (const state of states) {
    for (let j = 1; j <= N; j++) {
      if (j === state.id) continue;
      const share = computeShareForPeer(state, j);
      if (!inbox.has(j)) inbox.set(j, []);
      inbox.get(j).push(share);
    }
  }

  // Each participant aggregates
  const results = [];
  for (const state of states) {
    const received = inbox.get(state.id) || [];
    const r = aggregate(state, received, broadcasts);
    results.push(r);
  }

  // All participants must see the same master public key
  for (let i = 1; i < N; i++) {
    if (results[i].masterPublicKey !== results[0].masterPublicKey) {
      throw new Error(`master PK mismatch: participant ${i + 1}`);
    }
  }

  // Shares must be distinct
  const shareSet = new Set(results.map((r) => r.myShare.toString()));
  if (shareSet.size !== N) throw new Error('shares not all distinct');

  // Tampered share must fail verification
  const badShare = { fromId: 1, toId: 2, value: mod(results[0].myShare + 1n) };
  if (verifyShare(badShare, broadcasts.get(1), 2)) {
    throw new Error('tampered share accepted — verification broken');
  }

  return { ok: true, participants: N, threshold: T };
}

module.exports = {
  round1,
  computeShareForPeer,
  verifyShare,
  aggregate,
  serializeState,
  deserializeState,
  selfTest,
};
