var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod2, isNodeMode, target) => (target = mod2 != null ? __create(__getProtoOf(mod2)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod2 || !mod2.__esModule ? __defProp(target, "default", { value: mod2, enumerable: true }) : target,
  mod2
));
var __toCommonJS = (mod2) => __copyProps(__defProp({}, "__esModule", { value: true }), mod2);
var pvs_exports = {};
__export(pvs_exports, {
  CHUNK_BYTES: () => CHUNK_BYTES,
  FORMAT_V: () => FORMAT_V,
  H: () => H,
  combine: () => combine,
  refresh: () => refresh,
  selfTest: () => selfTest,
  split: () => split,
  splitInput: () => splitInput,
  verifyRefresh: () => verifyRefresh,
  verifyShare: () => verifyShare
});
module.exports = __toCommonJS(pvs_exports);
var import_node_crypto = __toESM(require("node:crypto"));
var import_secp256k1 = require("@noble/curves/secp256k1.js");
const Point = import_secp256k1.secp256k1.Point;
const G = Point.BASE;
const Q = Point.CURVE().n;
const P_FIELD = Point.CURVE().p;
const ZERO = Point.ZERO;
const mod = (a, m = Q) => {
  a %= m;
  return a < 0n ? a + m : a;
};
const addq = (a, b) => {
  const s = a + b;
  return s >= Q ? s - Q : s;
};
const subq = (a, b) => {
  const d = a - b;
  return d < 0n ? d + Q : d;
};
const mulq = (a, b) => mod(a * b, Q);
const powq = (a, e) => {
  let r = 1n;
  a = mod(a);
  while (e > 0n) {
    if (e & 1n) r = mulq(r, a);
    a = mulq(a, a);
    e >>= 1n;
  }
  return r;
};
const invq = (a) => {
  if (a === 0n) throw new Error("invq(0): duplicate or zero x");
  return powq(a, Q - 2n);
};
function liftX(x) {
  if (x >= P_FIELD) return null;
  const y2 = mod(x * x * x + 7n, P_FIELD);
  let y = 1n;
  let base = y2;
  let exp = P_FIELD + 1n >> 2n;
  while (exp > 0n) {
    if (exp & 1n) y = mod(y * base, P_FIELD);
    base = mod(base * base, P_FIELD);
    exp >>= 1n;
  }
  if (mod(y * y, P_FIELD) !== y2) return null;
  return new Point(x, y & 1n ? P_FIELD - y : y, 1n);
}
function computeH() {
  for (let i = 0; i < 4096; i++) {
    const h = import_node_crypto.default.createHash("sha256").update(`pvs-r-h-generator-v1:${i}`).digest();
    const x = BigInt("0x" + h.toString("hex")) % P_FIELD;
    const pt = liftX(x);
    if (pt && !pt.equals(G) && !pt.equals(ZERO)) return pt;
  }
  throw new Error("could not generate H");
}
const H = computeH();
const CHUNK_BYTES = 31;
const FORMAT_V = 4;
const MAX_N = 200;
const MAX_EPOCHS = 1e3;
const INF = "00";
function commitToHex(a, b) {
  const pa = a === 0n ? ZERO : G.multiply(a);
  const pb = b === 0n ? ZERO : H.multiply(b);
  const p = pa.add(pb);
  if (p.equals(ZERO)) return INF;
  return p.toHex(true);
}
function pointFromHex(hex) {
  if (hex === INF) return ZERO;
  return Point.fromHex(hex);
}
function scalarMulG(a) {
  return a === 0n ? ZERO : G.multiply(a);
}
function scalarMulH(a) {
  return a === 0n ? ZERO : H.multiply(a);
}
function fsHash(...parts) {
  const h = import_node_crypto.default.createHash("sha256");
  for (const p of parts) h.update(String(p) + "|");
  return mod(BigInt("0x" + h.digest("hex")));
}
function proveZ0IsZero(w, C) {
  const r = randFieldQ();
  const R = scalarMulH(r);
  const e = fsHash("pvs-z0-proof", C.toHex(true), R.toHex(true));
  const s = addq(r, mulq(e, w));
  return { R: R.toHex(true), e: e.toString(16), s: s.toString(16) };
}
function verifyZ0IsZero(C, proof) {
  try {
    const R = pointFromHex(proof.R);
    const e = BigInt("0x" + proof.e);
    const s = BigInt("0x" + proof.s);
    const lhs = scalarMulH(s);
    const rhs = R.add(C.multiply(e));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}
function randFieldQ() {
  for (; ; ) {
    const v = BigInt("0x" + import_node_crypto.default.randomBytes(32).toString("hex"));
    if (v > 0n && v < Q) return v;
  }
}
function randXQ() {
  let x;
  do {
    x = randFieldQ();
  } while (x === 0n);
  return x;
}
function lagrangeAtZeroQ(xs) {
  const k = xs.length;
  const lam = new Array(k);
  for (let i = 0; i < k; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < k; j++) {
      if (j === i) continue;
      num = mulq(num, subq(0n, xs[j]));
      den = mulq(den, subq(xs[i], xs[j]));
    }
    lam[i] = mulq(num, invq(den));
  }
  return lam;
}
function split(secret, n, k) {
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || n < k || n > MAX_N) {
    throw new Error(`need integers 2 \u2264 k \u2264 n \u2264 ${MAX_N}`);
  }
  const chunks = [];
  for (let i = 0; i < secret.length; i += CHUNK_BYTES) {
    chunks.push(secret.subarray(i, i + CHUNK_BYTES));
  }
  if (chunks.length === 0) chunks.push(Buffer.alloc(0));
  const nChunks = chunks.length;
  const xs = [];
  const seen = /* @__PURE__ */ new Set();
  while (xs.length < n) {
    const x = randXQ();
    if (seen.has(x)) continue;
    seen.add(x);
    xs.push(x);
  }
  const fxBig = Array.from({ length: n }, () => new Array(nChunks));
  const bxBig = Array.from({ length: n }, () => new Array(nChunks));
  const commits = Array.from({ length: nChunks }, () => new Array(k));
  const fCoeffs = new Array(k);
  const bCoeffs = new Array(k);
  for (let c = 0; c < nChunks; c++) {
    const chunk = chunks[c];
    const s = chunk.length ? BigInt("0x" + chunk.toString("hex")) : 0n;
    if (s >= Q) throw new Error("chunk value \u2265 q");
    fCoeffs[0] = s;
    for (let i = 1; i < k; i++) fCoeffs[i] = randFieldQ();
    for (let i = 0; i < k; i++) bCoeffs[i] = randFieldQ();
    for (let i = 0; i < k; i++) commits[c][i] = commitToHex(fCoeffs[i], bCoeffs[i]);
    for (let j = 0; j < n; j++) {
      let fy = 0n, by = 0n;
      const xi = xs[j];
      for (let d = k - 1; d >= 0; d--) {
        fy = addq(mulq(fy, xi), fCoeffs[d]);
        by = addq(mulq(by, xi), bCoeffs[d]);
      }
      fxBig[j][c] = fy.toString(16);
      bxBig[j][c] = by.toString(16);
    }
  }
  const commitRoot = fsHash("pvs-commit-root", JSON.stringify(commits)).toString(16);
  const shares = fxBig.map((fx, i) => ({
    v: FORMAT_V,
    epoch: 0,
    x: "0x" + xs[i].toString(16),
    fx: fx.join(","),
    bx: bxBig[i].join(","),
    threshold: k,
    total: n,
    chunks: nChunks,
    len: secret.length,
    commitRoot
  }));
  const commitment = {
    v: FORMAT_V,
    curve: "secp256k1",
    epoch: 0,
    commits
  };
  return { shares, commitment };
}
function verifyShare(share, commitment) {
  if (commitment.v !== FORMAT_V) throw new Error("commitment is not v4");
  if (share.chunks !== commitment.commits.length) throw new Error("chunk mismatch");
  const k = share.threshold;
  if (commitment.commits[0].length !== k) throw new Error("commitment width \u2260 threshold");
  const x = BigInt(share.x);
  if (x <= 0n || x >= Q) throw new Error("x out of range");
  const fxParts = share.fx.split(",");
  const bxParts = share.bx.split(",");
  for (let c = 0; c < share.chunks; c++) {
    const fy = BigInt("0x" + (fxParts[c] === "" ? "0" : fxParts[c]));
    const by = BigInt("0x" + (bxParts[c] === "" ? "0" : bxParts[c]));
    if (fy >= Q || by >= Q) throw new Error("y out of range");
    let ok = false;
    try {
      const lhs = scalarMulG(fy).add(scalarMulH(by));
      const cs = commitment.commits[c];
      let acc = pointFromHex(cs[k - 1]);
      for (let i = k - 2; i >= 0; i--) {
        acc = acc.multiply(x).add(pointFromHex(cs[i]));
      }
      ok = lhs.equals(acc);
    } catch {
      ok = false;
    }
    if (!ok) return false;
  }
  return true;
}
function refresh(shares, commitment) {
  if (shares.length === 0) throw new Error("no shares supplied");
  const k = shares[0].threshold;
  const nChunks = shares[0].chunks;
  const fromEpoch = commitment.epoch;
  if (fromEpoch >= MAX_EPOCHS) throw new Error("epoch overflow");
  const n = shares.length;
  const deltas = Array.from({ length: nChunks }, () => new Array(k));
  const proofs = new Array(nChunks);
  const zCoeffs = new Array(k);
  const wCoeffs = new Array(k);
  for (let c = 0; c < nChunks; c++) {
    zCoeffs[0] = 0n;
    for (let i = 1; i < k; i++) zCoeffs[i] = randFieldQ();
    for (let i = 0; i < k; i++) wCoeffs[i] = randFieldQ();
    for (let i = 0; i < k; i++) deltas[c][i] = commitToHex(zCoeffs[i], wCoeffs[i]);
    const delta0 = pointFromHex(deltas[c][0]);
    proofs[c] = proveZ0IsZero(wCoeffs[0], delta0);
  }
  const newShares = shares.map((s) => {
    const x = BigInt(s.x);
    const fxParts = s.fx.split(",");
    const bxParts = s.bx.split(",");
    const nFx = new Array(nChunks);
    const nBx = new Array(nChunks);
    for (let c = 0; c < nChunks; c++) {
      let zy = 0n, wy = 0n;
      for (let d = k - 1; d >= 0; d--) {
        zy = addq(mulq(zy, x), zCoeffs[d]);
        wy = addq(mulq(wy, x), wCoeffs[d]);
      }
      const fy = BigInt("0x" + (fxParts[c] === "" ? "0" : fxParts[c]));
      const by = BigInt("0x" + (bxParts[c] === "" ? "0" : bxParts[c]));
      nFx[c] = addq(fy, zy).toString(16);
      nBx[c] = addq(by, wy).toString(16);
    }
    return {
      ...s,
      epoch: fromEpoch + 1,
      fx: nFx.join(","),
      bx: nBx.join(",")
    };
  });
  const newCommits = commitment.commits.map(
    (cs, c) => cs.map((Ci, i) => {
      const p = pointFromHex(Ci).add(pointFromHex(deltas[c][i]));
      return p.equals(ZERO) ? INF : p.toHex(true);
    })
  );
  const newCommitRoot = fsHash("pvs-commit-root", JSON.stringify(newCommits)).toString(16);
  for (const s of newShares) s.commitRoot = newCommitRoot;
  const newCommitment = {
    ...commitment,
    epoch: fromEpoch + 1,
    commits: newCommits
  };
  const refreshProof = {
    v: FORMAT_V,
    fromEpoch,
    toEpoch: fromEpoch + 1,
    deltas,
    proofs
  };
  return { shares: newShares, commitment: newCommitment, refresh: refreshProof };
}
function verifyRefresh(oldCommit, newCommit, refresh2) {
  if (refresh2.fromEpoch !== oldCommit.epoch) throw new Error("epoch mismatch (from)");
  if (refresh2.toEpoch !== newCommit.epoch) throw new Error("epoch mismatch (to)");
  if (refresh2.toEpoch !== refresh2.fromEpoch + 1) throw new Error("non-contiguous epochs");
  if (refresh2.deltas.length !== oldCommit.commits.length) throw new Error("chunk mismatch");
  const nChunks = refresh2.deltas.length;
  const k = oldCommit.commits[0].length;
  const chunkResults = [];
  let allOk = true;
  for (let c = 0; c < nChunks; c++) {
    const delta0 = pointFromHex(refresh2.deltas[c][0]);
    let z0Ok = false;
    try {
      z0Ok = verifyZ0IsZero(delta0, refresh2.proofs[c]);
    } catch {
      z0Ok = false;
    }
    let transOk = true;
    try {
      for (let i = 0; i < k; i++) {
        const expected = pointFromHex(oldCommit.commits[c][i]).add(pointFromHex(refresh2.deltas[c][i]));
        const got = pointFromHex(newCommit.commits[c][i]);
        const expHex = expected.equals(ZERO) ? INF : expected.toHex(true);
        if (expHex !== got.toHex(true)) {
          transOk = false;
          break;
        }
      }
    } catch {
      transOk = false;
    }
    const ok = z0Ok && transOk;
    chunkResults.push({ c, z0IsZero: z0Ok });
    if (!ok) allOk = false;
  }
  return { valid: allOk, chunkResults };
}
function combine(shares, commitment) {
  if (!Array.isArray(shares) || shares.length === 0) throw new Error("no shares supplied");
  const ref = shares[0];
  for (const s of shares) {
    if (Number(s.threshold) !== Number(ref.threshold)) throw new Error("inconsistent threshold");
    if (Number(s.total) !== Number(ref.total)) throw new Error("inconsistent total");
    if (Number(s.chunks) !== Number(ref.chunks)) throw new Error("inconsistent chunks");
    if (s.binary !== ref.binary) throw new Error("inconsistent binary flag");
  }
  const sameEpoch = shares.every((s) => s.commitRoot === ref.commitRoot);
  const k = ref.threshold;
  if (shares.length < k) throw new Error(`need ${k} shares, got ${shares.length}`);
  let verified = true;
  for (const s of shares) {
    try {
      if (!verifyShare(s, commitment)) verified = false;
    } catch {
      verified = false;
    }
  }
  const use = shares.slice(0, k);
  const seen = /* @__PURE__ */ new Set();
  for (const u of use) {
    const x = BigInt(u.x);
    if (x <= 0n || x >= Q) throw new Error("x out of range");
    if (seen.has(x)) throw new Error("duplicate x-values among shares");
    seen.add(x);
  }
  const xs = use.map((u) => BigInt(u.x));
  const lambdas = lagrangeAtZeroQ(xs);
  const nChunks = use[0].chunks;
  const out = new Array(nChunks);
  for (let c = 0; c < nChunks; c++) {
    let secret = 0n;
    for (let i = 0; i < k; i++) {
      const parts = use[i].fx.split(",");
      const fy = BigInt("0x" + (parts[c] === "" ? "0" : parts[c]));
      secret = addq(secret, mulq(lambdas[i], fy));
    }
    const w = Math.min(CHUNK_BYTES, use[0].len - c * CHUNK_BYTES);
    let hex = secret.toString(16);
    hex = w <= 0 ? "" : hex.padStart(2 * w, "0");
    out[c] = hex.length ? Buffer.from(hex, "hex") : Buffer.alloc(0);
  }
  let buf = Buffer.concat(out);
  if (use[0].len > buf.length) throw new Error("len metadata exceeds data");
  buf = buf.subarray(0, use[0].len);
  return { buf, verified, sameEpoch };
}
function toBuffer(secret) {
  if (Buffer.isBuffer(secret)) return { buf: secret, isBuf: true };
  if (secret instanceof Uint8Array) return { buf: Buffer.from(secret), isBuf: true };
  return { buf: Buffer.from(String(secret), "utf8"), isBuf: false };
}
function splitInput(secret, n, k) {
  const { buf, isBuf } = toBuffer(secret);
  const res = split(buf, n, k);
  for (const s of res.shares) s.binary = isBuf;
  return res;
}
function selfTest() {
  const cases = [];
  let passed = 0;
  const expect = (name, cond) => {
    if (cond) {
      passed++;
      cases.push(`\u2713 ${name}`);
    } else {
      cases.push(`\u2717 ${name}`);
      throw new Error(`PVS-R self-test failed: ${name}`);
    }
  };
  {
    const buf = Buffer.from("the eagle flies at midnight", "utf8");
    const { shares, commitment } = split(buf, 5, 3);
    const { buf: rec, verified, sameEpoch } = combine(shares.slice(0, 3), commitment);
    expect("honest round-trip k=3", rec.equals(buf));
    expect("shares verify pre-combine", verified);
    expect("same epoch", sameEpoch);
  }
  {
    const buf = Buffer.from("hello world", "utf8");
    const { shares, commitment } = split(buf, 5, 3);
    const a = combine([shares[0], shares[2], shares[4]], commitment);
    const b = combine([shares[1], shares[3], shares[0]], commitment);
    expect("any-k subset A", a.buf.equals(buf) && a.verified);
    expect("any-k subset B", b.buf.equals(buf) && b.verified);
  }
  {
    const buf = Buffer.from("refresh preserves me", "utf8");
    const { shares, commitment } = split(buf, 5, 3);
    const r = refresh(shares, commitment);
    const { buf: rec, verified } = combine(r.shares.slice(0, 3), r.commitment);
    expect("refresh preserves secret", rec.equals(buf));
    expect("refreshed shares verify", verified);
  }
  {
    const buf = Buffer.from("forward security", "utf8");
    const { shares, commitment } = split(buf, 5, 3);
    const r = refresh(shares, commitment);
    const mixed = combine([shares[0], shares[1], r.shares[2]], commitment);
    expect("mixed-epoch combine \u2192 sameEpoch=false", !mixed.sameEpoch);
    expect("mixed-epoch reconstructs garbage (\u2260 secret)", !mixed.buf.equals(buf));
  }
  {
    const buf = Buffer.from("verify refresh", "utf8");
    const { shares, commitment } = split(buf, 4, 3);
    const r = refresh(shares, commitment);
    const vr = verifyRefresh(commitment, r.commitment, r.refresh);
    expect("honest refresh verifies publicly", vr.valid);
    expect("all chunks z\u2080=0", vr.chunkResults.every((c) => c.z0IsZero));
  }
  {
    const buf = Buffer.from("catch bad refresh", "utf8");
    const { shares, commitment } = split(buf, 4, 3);
    const r = refresh(shares, commitment);
    const badRefresh = {
      ...r.refresh,
      deltas: r.refresh.deltas.map(
        (d, c) => c === 0 ? [commitToHex(1n, randFieldQ()), ...d.slice(1)] : d
      )
      // proof is now invalid for the tampered Δ[0][0]
    };
    const vr = verifyRefresh(commitment, r.commitment, badRefresh);
    expect("tampered refresh (z\u2080\u22600) rejected", !vr.valid);
    expect("tampered chunk flagged z\u2080\u22600", !vr.chunkResults[0].z0IsZero);
  }
  {
    const buf = Buffer.from("transition check", "utf8");
    const { shares, commitment } = split(buf, 4, 3);
    const r = refresh(shares, commitment);
    const badNewCommit = {
      ...r.commitment,
      commits: r.commitment.commits.map(
        (cs, c) => c === 0 ? [commitToHex(randFieldQ(), 0n), ...cs.slice(1)] : cs
      )
    };
    const vr = verifyRefresh(commitment, badNewCommit, r.refresh);
    expect("inconsistent transition rejected", !vr.valid);
  }
  {
    const buf = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) buf[i] = i;
    const { shares, commitment } = split(buf, 5, 3);
    const { buf: rec, verified } = combine(shares.slice(0, 3), commitment);
    expect("binary NUL round-trips", rec.equals(buf));
    expect("binary shares verify", verified);
  }
  {
    const buf = Buffer.from("kminus1", "utf8");
    const { shares, commitment } = split(buf, 5, 3);
    let rej = false;
    try {
      combine([shares[0], shares[1]], commitment);
    } catch {
      rej = true;
    }
    expect("k\u22121 shares rejected", rej);
  }
  {
    const buf = Buffer.from("dupx", "utf8");
    const { shares, commitment } = split(buf, 3, 2);
    let rej = false;
    try {
      combine([shares[0], { ...shares[0] }], commitment);
    } catch {
      rej = true;
    }
    expect("duplicate x rejected", rej);
  }
  {
    const buf = Buffer.from("survive three epochs", "utf8");
    const { shares, commitment } = split(buf, 5, 3);
    let curShares = shares;
    let curCommit = commitment;
    for (let e = 1; e <= 3; e++) {
      const r = refresh(curShares, curCommit);
      const vr = verifyRefresh(curCommit, r.commitment, r.refresh);
      expect(`epoch ${e} refresh verifies`, vr.valid);
      curShares = r.shares;
      curCommit = r.commitment;
    }
    const { buf: rec, verified } = combine(curShares.slice(0, 3), curCommit);
    expect("secret survives 3 epochs", rec.equals(buf));
    expect("shares verify after 3 epochs", verified);
    expect("epoch counter reached 3", curCommit.epoch === 3);
  }
  {
    const buf = Buffer.from("old shares vs new commit", "utf8");
    const { shares, commitment } = split(buf, 4, 3);
    const r = refresh(shares, commitment);
    let oldStillValid = true;
    try {
      oldStillValid = verifyShare(shares[0], r.commitment);
    } catch {
      oldStillValid = false;
    }
    expect("old shares fail verify against new commitment", !oldStillValid);
  }
  expect("PVS-R self-test completed", true);
  return { passed, cases };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  CHUNK_BYTES,
  FORMAT_V,
  H,
  combine,
  refresh,
  selfTest,
  split,
  splitInput,
  verifyRefresh,
  verifyShare
});
