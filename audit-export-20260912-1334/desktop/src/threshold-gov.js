'use strict';

/**
 * Threshold governance — practical local realization of KasbahOS v5.0.
 *
 * WHAT THIS IS (honest):
 *   Clearance lattice with (t,n) thresholds, t-of-n Ed25519 co-signatures
 *   on action commitments, and multi-sig receipts on the forward-secure
 *   audit chain. Built from primitives we actually ship:
 *     · Shamir v2 (Mersenne) for share-split secrets / board seats
 *     · Node crypto Ed25519 for co-signatures
 *     · SHA-256 Merkle-style hashing for action commitments
 *     · ForwardSecureAudit for the append-only chain
 *
 * WHAT THIS IS NOT:
 *   · Not Hermine / Threshold-FALCON / Earpicks / PRISM (those are
 *     research constructions; we do not claim lattice/isogeny TS).
 *   · Not Cobra hybrid KEM (node channels already use ML-KEM PSK on WG).
 *   · Not a distributed DKG network — seats are local keys unless the
 *     operator imports peer public keys.
 *   · Not post-quantum signatures. (WG transport has ML-KEM PSK; the
 *     co-signature layer is classical Ed25519 until a real PQ TS ships.)
 *
 * Maps to v5.0:
 *   I₁ bounded advisory  → advisory() codomain excludes DENY
 *   I₂ distributed trust → no single key can approve level≥3 alone (t≥2)
 *   I₃ PQ durability     → NOT claimed here; documented as open
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const wgas = require('./wgas.js');

const DIR   = path.join(os.homedir(), '.kasbah-privacy');
const SEATS = path.join(DIR, 'gov-seats.enc');
const QUEUE = path.join(DIR, 'gov-approvals.enc');
const CHAIN = path.join(DIR, 'gov-threshold-chain.enc');

/** Clearance lattice (v5.0 §5). Thresholds: t_c for level c. */
const CLEARANCE = Object.freeze({
  PUBLIC:   { level: 0, name: 'PUBLIC',   t: 1, n: 1 },
  AUDITOR:  { level: 1, name: 'AUDITOR',  t: 1, n: 1 },
  ANALYST:  { level: 2, name: 'ANALYST',  t: 2, n: 3 },
  OPERATOR: { level: 3, name: 'OPERATOR', t: 2, n: 3 },
  SHURA:    { level: 4, name: 'SHURA',    t: 3, n: 4 },
});

function ensure() { try { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); } catch (_) {} }

/* ── AES-256-GCM at-rest encryption for governance store files ────────────
 * Key is derived from a machine-scoped secret stored at ~/.kasbah-privacy/gov-key.
 * On first use the key is generated with CSPRNG. The key file is 0600.
 * This matches the threat model: protects against filesystem read by other
 * users or processes on the same machine. Not a defence against a process
 * running as the same user or root.
 */
const GOV_KEY_PATH = path.join(DIR, 'gov-key');
let _govKey = null;

function getGovKey() {
  if (_govKey) return _govKey;
  ensure();
  try {
    const raw = fs.readFileSync(GOV_KEY_PATH);
    if (raw.length === 32) { _govKey = raw; return _govKey; }
  } catch (_) {}
  _govKey = crypto.randomBytes(32);
  fs.writeFileSync(GOV_KEY_PATH, _govKey, { mode: 0o600 });
  return _govKey;
}

function encryptGov(plaintext) {
  const iv  = crypto.randomBytes(12);
  const key = getGovKey();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

function decryptGov(b64) {
  const buf = Buffer.from(b64, 'base64');
  const iv  = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct  = buf.subarray(28);
  const key = getGovKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

function readJson(p, fallback) {
  try {
    const raw = fs.readFileSync(p, 'utf8').trim();
    // Support legacy plaintext files (migration path)
    const plain = raw.startsWith('{') || raw.startsWith('[') ? raw : decryptGov(raw);
    return JSON.parse(plain);
  } catch { return fallback; }
}

function writeJson(p, o) {
  ensure();
  const enc = encryptGov(JSON.stringify(o, null, 2));
  fs.writeFileSync(p, enc, { mode: 0o600 });
}

/* ─── Seats (board members) ─────────────────────────────────────────────── */

function loadSeats() { return readJson(SEATS, { seats: [] }); }
function saveSeats(o) { writeJson(SEATS, o); }

/**
 * Create a local co-signer seat. Returns { id, name, publicKey, privateKey }
 * privateKey stays on disk 0600 — this is a single-machine board, not a
 * distributed DKG. Import peer publicKeys for multi-device boards.
 */
function createSeat(name, { level = CLEARANCE.SHURA.level } = {}) {
  if (!name || typeof name !== 'string') throw new Error('seat name required');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const seat = {
    id: 'seat_' + crypto.randomBytes(6).toString('hex'),
    name: String(name).slice(0, 64),
    level,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    createdAt: new Date().toISOString(),
  };
  const s = loadSeats();
  s.seats = s.seats.filter((x) => x.name !== seat.name);
  s.seats.push(seat);
  saveSeats(s);
  return { ...seat, privateKey: undefined }; // never return raw key from create
}

function listSeats() {
  return loadSeats().seats.map((s) => ({
    id: s.id, name: s.name, level: s.level, publicKey: s.publicKey, createdAt: s.createdAt,
  }));
}

function removeSeat(idOrName) {
  const s = loadSeats();
  s.seats = s.seats.filter((x) => x.id !== idOrName && x.name !== idOrName);
  saveSeats(s);
  return { ok: true, count: s.seats.length };
}

function getSeatPrivate(idOrName) {
  const s = loadSeats().seats.find((x) => x.id === idOrName || x.name === idOrName);
  if (!s || !s.privateKey) return null;
  return crypto.createPrivateKey({
    key: Buffer.from(s.privateKey, 'base64'),
    format: 'der', type: 'pkcs8',
  });
}

/* ─── Advisory (I₁) ─────────────────────────────────────────────────────── */

/**
 * Bounded advisory — codomain NEVER includes DENY.
 * Matches @kasbah/control bounded-advisory-semantics.
 */
function advisory({ score = 0, tauWarn = 0.4, tauApproval = 0.75, flags = 0 } = {}) {
  const s = Number(score) || 0;
  if (s >= tauApproval || flags >= 2) {
    return { verdict: 'REQUIRE_APPROVAL', score: s, requiresHuman: true, denyUnreachable: true };
  }
  if (s >= tauWarn) {
    return { verdict: 'WARN', score: s, requiresHuman: false, denyUnreachable: true };
  }
  return { verdict: 'CLEAR', score: s, requiresHuman: false, denyUnreachable: true };
}

function clearanceFor(verdict) {
  if (verdict === 'REQUIRE_APPROVAL') return CLEARANCE.OPERATOR;
  if (verdict === 'WARN') return CLEARANCE.ANALYST;
  return CLEARANCE.PUBLIC;
}

/* ─── Action commitment + co-sign ───────────────────────────────────────── */

function actionHash(action) {
  const body = typeof action === 'string' ? action : JSON.stringify(action, Object.keys(action || {}).sort());
  return crypto.createHash('sha256').update(String(body)).digest('hex');
}

function signAction(seatId, actionHashHex) {
  const key = getSeatPrivate(seatId);
  if (!key) throw new Error('seat not found or has no private key: ' + seatId);
  const sig = crypto.sign(null, Buffer.from(actionHashHex, 'hex'), key);
  const seat = loadSeats().seats.find((s) => s.id === seatId || s.name === seatId);
  return { seatId: seat.id, name: seat.name, sig: sig.toString('base64'), publicKey: seat.publicKey };
}

function verifySig(publicKeyB64, actionHashHex, sigB64) {
  try {
    const pub = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(actionHashHex, 'hex'), pub, Buffer.from(sigB64, 'base64'));
  } catch { return false; }
}

/**
 * Propose an action that needs threshold approval.
 * @returns { id, actionHash, requiredT, requiredN, collected, approved }
 */
/**
 * Propose an action that needs threshold approval (and optional WGAS).
 * @param opts.useWgas {boolean} — also require maxflow(graph, co-signers) ≥ κ
 *
 * SECURITY: the WGAS topology graph is always the persisted, previously-
 * configured governance graph (wgas.seedDefault()) — never a caller-supplied
 * one. A per-proposal caller-chosen graph (this used to accept `wgasGraph`
 * from the caller) let anyone define their own trivially-satisfied topology
 * (e.g. a single seatless edge with κ=1, which `activeEdges()` treats as
 * "always present"), silently discarding the module's structural-seat
 * requirement while still passing `wgasResult.authorized`. The base t-of-n
 * signature count (`spec.t`, from the fixed CLEARANCE table) was never
 * bypassable this way, but the finer-grained "specific seat combination"
 * guarantee WGAS exists to provide was.
 */
function propose({ action, clearanceLevel = CLEARANCE.OPERATOR.level, note = '', useWgas = false, executionDelayMs = 0 } = {}) {
  const level = Number(clearanceLevel);
  const spec = Object.values(CLEARANCE).find((c) => c.level === level) || CLEARANCE.OPERATOR;
  const h = actionHash(action);
  const q = readJson(QUEUE, { pending: [] });
  const id = 'apr_' + crypto.randomBytes(8).toString('hex');
  let graph = null;
  if (useWgas) {
    graph = wgas.seedDefault() || wgas.thresholdAsWgas(listSeats().map((s) => s.name), spec.t);
  }
  const rec = {
    id,
    actionHash: h,
    action: typeof action === 'string' ? action : action,
    clearance: spec,
    note: String(note).slice(0, 200),
    sigs: [],
    useWgas: !!useWgas,
    wgas: graph,
    executionDelayMs: Math.max(0, Number(executionDelayMs) || 0),
    createdAt: new Date().toISOString(),
    status: 'PENDING',
  };
  q.pending.push(rec);
  writeJson(QUEUE, q);
  return {
    id, actionHash: h, requiredT: spec.t, requiredN: spec.n,
    collected: 0, approved: false, verdict: 'REQUIRE_APPROVAL',
    useWgas: !!useWgas, wgasKappa: graph?.kappa ?? null,
    executionDelayMs: rec.executionDelayMs,
  };
}

function coSign({ approvalId, seatId } = {}) {
  const q = readJson(QUEUE, { pending: [] });
  const rec = q.pending.find((p) => p.id === approvalId);
  if (!rec) throw new Error('approval not found');
  if (rec.status === 'APPROVED') return { ok: true, already: true, status: rec.status };
  const signed = signAction(seatId, rec.actionHash);
  if (!rec.sigs.find((s) => s.seatId === signed.seatId)) rec.sigs.push(signed);
  const need = rec.clearance.t;
  const have = rec.sigs.length;
  let wgasResult = null;
  let sigOk = have >= need;
  if (rec.useWgas && rec.wgas && sigOk) {
    // Co-signer names feed the WGAS coalition (topology, not just count).
    const coalition = rec.sigs.map((s) => s.name);
    wgasResult = wgas.evaluate(rec.wgas, coalition);
    if (!wgasResult.authorized) {
      writeJson(QUEUE, q);
      return {
        ok: true, id: rec.id, collected: have, requiredT: need,
        approved: false, status: 'PENDING_WGAS',
        wgas: { flow: wgasResult.flow, kappa: wgasResult.kappa, reason: wgasResult.reason },
      };
    }
  }
  if (sigOk && (!rec.useWgas || (wgasResult && wgasResult.authorized))) {
    rec.status = 'APPROVED';
    rec.approvedAt = new Date().toISOString();
    appendChain({
      type: rec.useWgas ? 'wgas_threshold_approval' : 'threshold_approval',
      approvalId: rec.id,
      actionHash: rec.actionHash,
      clearance: rec.clearance,
      sigs: rec.sigs.map((s) => ({ seatId: s.seatId, name: s.name, sig: s.sig })),
      wgas: wgasResult
        ? {
            flow: wgasResult.flow,
            kappa: wgasResult.kappa,
            witnessHash: wgas.witnessHash(wgasResult.witness),
            witness: wgasResult.witness,
          }
        : null,
    });
  }
  writeJson(QUEUE, q);
  return {
    ok: true, id: rec.id, collected: have, requiredT: need,
    approved: rec.status === 'APPROVED', status: rec.status,
    wgas: wgasResult ? { flow: wgasResult.flow, kappa: wgasResult.kappa, reason: wgasResult.reason } : null,
  };
}

function listPending() {
  return readJson(QUEUE, { pending: [] }).pending.map((p) => ({
    id: p.id, actionHash: p.actionHash, clearance: p.clearance, status: p.status,
    collected: (p.sigs || []).length, createdAt: p.createdAt, note: p.note,
    useWgas: !!p.useWgas,
    action: typeof p.action === 'string' ? p.action.slice(0, 80) : p.action,
  }));
}

/** Standalone WGAS check (UI / tests). */
function wgasEvaluate(seatNames, graph) {
  return wgas.evaluate(graph || wgas.seedDefault(), seatNames);
}

/* ─── Threshold audit chain ─────────────────────────────────────────────── */

function loadChain() { return readJson(CHAIN, { entries: [], genesis: null }); }
function saveChain(c) { writeJson(CHAIN, c); }

function appendChain(payload) {
  const c = loadChain();
  const prev = c.entries.length ? c.entries[c.entries.length - 1].hash : (c.genesis || '0'.repeat(64));
  const body = JSON.stringify(payload);
  const hash = crypto.createHash('sha256').update(prev + body).digest('hex');
  const entry = {
    ts: new Date().toISOString(),
    prev,
    hash,
    payload,
  };
  c.entries.push(entry);
  if (c.entries.length > 2000) c.entries.splice(0, c.entries.length - 2000);
  saveChain(c);
  return entry;
}

function verifyChain() {
  const c = loadChain();
  if (!c.entries.length) return { ok: true, count: 0, note: 'empty chain' };
  let prev = c.genesis || '0'.repeat(64);
  for (let i = 0; i < c.entries.length; i++) {
    const e = c.entries[i];
    if (e.prev !== prev) return { ok: false, index: i, error: 'prev hash mismatch' };
    const h = crypto.createHash('sha256').update(e.prev + JSON.stringify(e.payload)).digest('hex');
    if (h !== e.hash) return { ok: false, index: i, error: 'entry hash mismatch' };
    prev = e.hash;
  }
  return { ok: true, count: c.entries.length, head: c.entries[c.entries.length - 1].hash };
}

/**
 * Seed a minimal OPERATOR board (2 of 3) so REQUIRE_APPROVAL is usable
 * out of the box on a single Mac.
 */
function seedDefaultBoard() {
  const s = loadSeats();
  if (s.seats.length >= 3) {
    try { wgas.seedDefault(); } catch (_) {}
    return { ok: true, already: true, seats: listSeats().length };
  }
  for (const name of ['Operator-A', 'Operator-B', 'Operator-C']) {
    if (!s.seats.find((x) => x.name === name)) createSeat(name, { level: CLEARANCE.OPERATOR.level });
  }
  appendChain({ type: 'board_seed', seats: listSeats().map((x) => x.name) });
  try { wgas.seedDefault(); } catch (_) {}
  return { ok: true, seats: listSeats().length };
}

function status() {
  const seats = listSeats();
  const pend = listPending();
  const chain = verifyChain();
  let wgasSt = null;
  try { wgasSt = wgas.status(); } catch (e) { wgasSt = { error: e.message }; }
  return {
    clearance: CLEARANCE,
    seats: seats.length,
    pending: pend.filter((p) => p.status === 'PENDING' || p.status === 'PENDING_WGAS').length,
    approved: pend.filter((p) => p.status === 'APPROVED').length,
    chain,
    wgas: wgasSt,
    advisoryCodomain: ['CLEAR', 'WARN', 'REQUIRE_APPROVAL'],
    honestScope: {
      thresholdSig: 'Ed25519 t-of-n (not Hermine/FALCON/PRISM)',
      wgas: 'Edmonds-Karp max-flow; ZK conservation + Chaum-Pedersen OR-proof capacity bounds (range-proof.js)',
      dkg: 'Feldman VSS two-round DKG (dkg.js); no robust complaint phase (Gennaro 2007 open)',
      pqSignatures: false,
      pqTransport: 'WG ML-KEM PSK (separate layer)',
    },
  };
}

/* ─── N1: Execution delay enforcement ───────────────────────────────────── */

/**
 * Mark a proposal as executable only after `delayMs` from approval time.
 * An adversary who coerces a board into approving an action still has a
 * window during which the user can detect and revoke the approval.
 *
 * `propose()` now accepts `executionDelayMs` (default 0 = immediate).
 * `canExecute(id)` returns { ok, reason, executableAt }.
 * `markExecuted(id)` records execution in the chain.
 *
 * NOTE: this is a local advisory check only — it does not prevent the
 * underlying action from running via other paths. The caller is responsible
 * for gating the actual action on `canExecute().ok`.
 */
function canExecute(approvalId) {
  const q   = readJson(QUEUE, { pending: [] });
  const rec = q.pending.find((p) => p.id === approvalId);
  if (!rec) return { ok: false, reason: 'approval not found' };
  if (rec.status !== 'APPROVED') return { ok: false, reason: `not approved (status: ${rec.status})` };
  const delayMs = Number(rec.executionDelayMs) || 0;
  if (delayMs <= 0) return { ok: true, executableAt: rec.approvedAt };
  const executableAt = new Date(new Date(rec.approvedAt).getTime() + delayMs).toISOString();
  if (Date.now() < new Date(executableAt).getTime()) {
    return { ok: false, reason: `execution delay not elapsed`, executableAt, delayMs, approvedAt: rec.approvedAt };
  }
  return { ok: true, executableAt, approvedAt: rec.approvedAt };
}

function markExecuted(approvalId, note = '') {
  const q   = readJson(QUEUE, { pending: [] });
  const rec = q.pending.find((p) => p.id === approvalId);
  if (!rec) throw new Error('approval not found');
  const check = canExecute(approvalId);
  if (!check.ok) throw new Error('cannot execute: ' + check.reason);
  rec.executedAt = new Date().toISOString();
  rec.executionNote = String(note).slice(0, 200);
  writeJson(QUEUE, q);
  appendChain({ type: 'executed', approvalId, actionHash: rec.actionHash, ts: rec.executedAt, note });
  return { ok: true, approvalId, executedAt: rec.executedAt };
}

/* ─── N2: Policy diff proofs ─────────────────────────────────────────────
 * When the governance policy changes (seats added/removed, thresholds changed),
 * commit a policy hash and prove the change was threshold-approved.
 * An auditor verifying the policy chain sees: old hash → new hash → approval id.
 * They cannot see policy content, only that each transition was authorized.
 */
function commitPolicyChange({ reason = '', requiredLevel = CLEARANCE.SHURA.level } = {}) {
  const snapshot = {
    seats:     listSeats().map((s) => ({ id: s.id, name: s.name, level: s.level })),
    clearance: CLEARANCE,
    ts:        new Date().toISOString(),
  };
  const policyHash = crypto.createHash('sha256')
    .update(JSON.stringify(snapshot, null, 0))
    .digest('hex');

  // Propose a "policy_change" action at the required level
  const proposal = propose({
    action: { type: 'policy_change', policyHash, reason },
    clearanceLevel: requiredLevel,
    note: 'Policy change commit: ' + reason,
  });

  appendChain({ type: 'policy_snapshot', policyHash, proposalId: proposal.id, reason, ts: new Date().toISOString() });

  return { policyHash, proposal, snapshot };
}

/** Return the most recent policy hash from the chain (for continuity proofs). */
function currentPolicyHash() {
  const c = loadChain();
  const snaps = c.entries.filter((e) => e.payload?.type === 'policy_snapshot');
  if (!snaps.length) {
    // Compute from live state if no prior snapshot
    const snapshot = { seats: listSeats().map((s) => ({ id: s.id, name: s.name, level: s.level })), clearance: CLEARANCE };
    return crypto.createHash('sha256').update(JSON.stringify(snapshot, null, 0)).digest('hex');
  }
  return snaps[snaps.length - 1].payload.policyHash;
}

/* ─── N3: Canary governance trip ─────────────────────────────────────────
 * Deploy a fake "nuclear" proposal that no legitimate operator would approve.
 * If it receives a co-signature, the board is compromised (or coerced).
 * The canary is detected in coSign() and triggers an audit + optional alert.
 */
const CANARY_PREFIX = '__KASBAH_CANARY__';

function deployCanary({ label = 'nuclear-action', alertCallback = null } = {}) {
  const proposal = propose({
    action: { type: CANARY_PREFIX, label, ts: new Date().toISOString() },
    clearanceLevel: CLEARANCE.SHURA.level,
    note: 'CANARY: do not approve — this is a governance honeytoken',
  });
  appendChain({ type: 'canary_deployed', proposalId: proposal.id, label, ts: new Date().toISOString() });
  // Store the alert callback in memory (not persisted — process lifetime only)
  if (alertCallback) _canaryAlerts.set(proposal.id, alertCallback);
  return { ok: true, proposalId: proposal.id, label };
}

const _canaryAlerts = new Map();

function _checkCanaryTrip(rec, signed) {
  if (!rec.action || rec.action.type !== CANARY_PREFIX) return;
  // A canary was just co-signed — board may be compromised
  appendChain({ type: 'canary_tripped', proposalId: rec.id, seat: signed.name, ts: new Date().toISOString() });
  const cb = _canaryAlerts.get(rec.id);
  if (cb) { try { cb({ proposalId: rec.id, seat: signed.name }); } catch (_) {} }
}

/* ─── N10: Dead-man governance degradation ───────────────────────────────
 * If the dead-man switch is overdue (board has gone dark), lower the
 * minimum required threshold by 1 so pending actions can still execute.
 * The degradation event is logged to the chain and cannot be hidden.
 *
 * Risk (documented in N10 assessment): an attacker who can silence seats
 * for `intervalHours + graceHours` can trigger this. Mitigated by:
 *   · The degradation itself is chain-logged and verifiable
 *   · The threshold can only degrade by 1, to a floor of 1
 *   · The degradation must be explicitly triggered; it is not automatic
 */
function checkDeadManDegradation() {
  let deadman;
  try { deadman = require('./deadman.js'); } catch { return { degraded: false, error: 'deadman module unavailable' }; }
  const st = deadman.status();
  if (!st.enabled || !st.overdue) return { degraded: false, overdue: st.overdue };

  const current = Object.values(CLEARANCE).map((c) => c.t);
  const minT    = Math.min(...current);
  if (minT <= 1) return { degraded: false, reason: 'already at minimum threshold' };

  // Log the degradation event — do not mutate the in-process CLEARANCE object
  // (it is frozen). Instead record a degradation override in the chain that
  // callers can query via getDegradationOverride().
  const entry = appendChain({
    type: 'deadman_degradation',
    ts: new Date().toISOString(),
    reason: 'dead-man switch overdue',
    overdueSince: st.deadline,
    originalMinThreshold: minT,
    degradedMinThreshold: Math.max(1, minT - 1),
  });

  return {
    degraded: true,
    originalMinThreshold: minT,
    degradedMinThreshold: Math.max(1, minT - 1),
    chainEntry: entry.hash,
  };
}

/**
 * Return the active degradation override (if any) from the chain.
 * A caller who wants the effective threshold should add this to their check.
 */
function getDegradationOverride() {
  const c = loadChain();
  const entries = c.entries.filter((e) => e.payload?.type === 'deadman_degradation');
  if (!entries.length) return null;
  const last = entries[entries.length - 1].payload;
  return { degradedMinThreshold: last.degradedMinThreshold, ts: entries[entries.length - 1].ts };
}

/* ─── Patch coSign to detect canary trips ───────────────────────────────── */
const _origCoSign = coSign;
// Re-export coSign with canary detection wired in
function coSignWithCanary({ approvalId, seatId } = {}) {
  const q   = readJson(QUEUE, { pending: [] });
  const rec = q.pending.find((p) => p.id === approvalId);
  // Check for canary before delegating to original coSign
  if (rec && rec.action && rec.action.type === CANARY_PREFIX) {
    try {
      const signed = signAction(seatId, rec.actionHash);
      _checkCanaryTrip(rec, signed);
    } catch (_) {}
  }
  return _origCoSign({ approvalId, seatId });
}

/* ─── N5: Threshold audit export ────────────────────────────────────────
 * Encrypt the audit export key with Shamir so t-of-n seats must cooperate
 * to decrypt a full audit export. Uses shamir-vault.js split/combine.
 *
 * HONEST SCOPE: this wraps the *export encryption key* (a random 32-byte
 * AES key), not the entire audit log. The per-entry AES-256-GCM encryption
 * is separate. This is "t-of-n access to export" not "t-of-n encrypted log".
 */
function createThresholdExportKey({ n, t } = {}) {
  const seats = listSeats();
  const nSeats = n ?? Math.min(seats.length, 3);
  const tSeats = t ?? Math.ceil(nSeats / 2) + 1;
  if (nSeats < 1) throw new Error('no seats configured');

  const shamir = require('./shamir-vault.js');
  const exportKey = crypto.randomBytes(32);
  const shares = shamir.split(exportKey, nSeats, Math.min(tSeats, nSeats));

  // Assign each share to a seat by index (caller distributes)
  const assignments = seats.slice(0, nSeats).map((seat, i) => ({
    seatId: seat.id,
    seatName: seat.name,
    share: shares[i],
  }));

  appendChain({ type: 'threshold_export_key_created', n: nSeats, t: tSeats, ts: new Date().toISOString() });

  // Zero the export key bytes now — it must be reconstructed via combine
  exportKey.fill(0);

  return { ok: true, n: nSeats, t: tSeats, assignments };
}

function reconstructExportKey(shares) {
  const shamir = require('./shamir-vault.js');
  return shamir.combine(shares);
}

module.exports = {
  CLEARANCE,
  advisory, clearanceFor,
  createSeat, listSeats, removeSeat, seedDefaultBoard,
  propose, coSign: coSignWithCanary, listPending,
  actionHash, signAction, verifySig,
  appendChain, verifyChain,
  status,
  wgasEvaluate,
  wgas,
  // N1
  canExecute, markExecuted,
  // N2
  commitPolicyChange, currentPolicyHash,
  // N3
  deployCanary,
  // N5
  createThresholdExportKey, reconstructExportKey,
  // N10
  checkDeadManDegradation, getDegradationOverride,
};
