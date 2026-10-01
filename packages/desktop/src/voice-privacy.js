"use strict";
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
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var voice_exports = {};
__export(voice_exports, {
  H: () => H,
  buildRegistry: () => buildRegistry,
  commitUtterance: () => commitUtterance,
  orSigmaProveKeyword: () => orSigmaProveKeyword,
  orSigmaVerifyKeyword: () => orSigmaVerifyKeyword,
  rerandomizeUtterance: () => rerandomizeUtterance,
  selfTest: () => selfTest,
  simulateSilentSpeech: () => simulateSilentSpeech,
  simulateVoiceprint: () => simulateVoiceprint,
  voiceAuthProve: () => voiceAuthProve,
  voiceAuthVerify: () => voiceAuthVerify
});
module.exports = __toCommonJS(voice_exports);
var import_node_crypto = __toESM(require("node:crypto"));
var import_secp256k1 = require("@noble/curves/secp256k1.js");
const Point = import_secp256k1.secp256k1.Point;
const G = Point.BASE;
const Q = Point.CURVE().n;
const P_FIELD = Point.CURVE().p;
const ZERO = Point.ZERO;
const INF = "00";
const modq = (a) => {
  a %= Q;
  return a < 0n ? a + Q : a;
};
const addq = (a, b) => {
  const s = a + b;
  return s >= Q ? s - Q : s;
};
const subq = (a, b) => {
  const d = a - b;
  return d < 0n ? d + Q : d;
};
const mulq = (a, b) => modq(a * b);
function modP(a) {
  a %= P_FIELD;
  return a < 0n ? a + P_FIELD : a;
}
function liftX(x) {
  if (x >= P_FIELD) return null;
  const y2 = modP(x * x * x + 7n);
  let y = 1n;
  let base = y2;
  let exp = P_FIELD + 1n >> 2n;
  while (exp > 0n) {
    if (exp & 1n) y = modP(y * base);
    base = modP(base * base);
    exp >>= 1n;
  }
  if (modP(y * y) !== y2) return null;
  return new Point(x, y & 1n ? P_FIELD - y : y, 1n);
}
function computeH() {
  for (let i = 0; i < 4096; i++) {
    const h = import_node_crypto.default.createHash("sha256").update(`voice-h-generator-v1:${i}`).digest();
    const x = BigInt("0x" + h.toString("hex")) % P_FIELD;
    const pt = liftX(x);
    if (pt && !pt.equals(G) && !pt.equals(ZERO)) return pt;
  }
  throw new Error("could not generate H");
}
const H = computeH();
function scalarMulG(a) {
  return a === 0n ? ZERO : G.multiply(a);
}
function scalarMulH(a) {
  return a === 0n ? ZERO : H.multiply(a);
}
function pointToHex(p) {
  if (p.equals(ZERO)) return INF;
  return p.toHex(true);
}
function pointFromHex(hex) {
  if (hex === INF) return ZERO;
  return Point.fromHex(hex);
}
function pedersenCommit(m, r) {
  if (r === void 0) r = randFieldQ();
  return { c: scalarMulG(r).add(scalarMulH(m)), r, m };
}
function randFieldQ() {
  for (; ; ) {
    const v = BigInt("0x" + import_node_crypto.default.randomBytes(32).toString("hex"));
    if (v > 0n && v < Q) return v;
  }
}
function fsHash(tag, ...parts) {
  const h = import_node_crypto.default.createHash("sha256");
  h.update(tag + "|");
  for (const p of parts) h.update(String(p) + "|");
  return modq(BigInt("0x" + h.digest("hex")));
}
function commitUtterance(tokens) {
  const commitments = [];
  const blinds = [];
  for (const tok of tokens) {
    const c = pedersenCommit(BigInt(tok));
    commitments.push(pointToHex(c.c));
    blinds.push(c.r.toString(16));
  }
  return {
    utterance: { commitments, numTokens: tokens.length },
    secret: { tokens, blinds }
  };
}
function orSigmaProveKeyword(utterance, secret, keyword) {
  const n = utterance.numTokens;
  if (n !== secret.tokens.length || n !== secret.blinds.length) {
    throw new Error("utterance/secret length mismatch");
  }
  const honestIdx = secret.tokens.indexOf(keyword);
  if (honestIdx < 0) throw new Error("keyword not present in utterance");
  const kw = BigInt(keyword);
  const instances = [];
  for (let i = 0; i < n; i++) {
    const Ci = pointFromHex(utterance.commitments[i]);
    instances.push(Ci.add(scalarMulH(kw).negate()));
  }
  const A = new Array(n);
  const c = new Array(n);
  const z = new Array(n);
  let cSimSum = 0n;
  for (let i = 0; i < n; i++) {
    if (i === honestIdx) continue;
    const zi = randFieldQ();
    const ci = randFieldQ();
    const Ai = scalarMulG(zi).add(instances[i].multiply(subq(Q, ci)));
    A[i] = pointToHex(Ai);
    c[i] = ci.toString(16);
    z[i] = zi.toString(16);
    cSimSum = addq(cSimSum, ci);
  }
  const s = randFieldQ();
  A[honestIdx] = pointToHex(scalarMulG(s));
  const cFs = fsHash("silent-speech-keyword", keyword, ...utterance.commitments, ...A);
  c[honestIdx] = subq(cFs, cSimSum).toString(16);
  const rHonest = BigInt("0x" + secret.blinds[honestIdx]);
  z[honestIdx] = addq(s, mulq(BigInt("0x" + c[honestIdx]), rHonest)).toString(16);
  return { A, c, z };
}
function orSigmaVerifyKeyword(utterance, keyword, proof) {
  const n = utterance.numTokens;
  if (proof.A.length !== n || proof.c.length !== n || proof.z.length !== n) return false;
  const cFs = fsHash("silent-speech-keyword", keyword, ...utterance.commitments, ...proof.A);
  let cSum = 0n;
  for (let i = 0; i < n; i++) cSum = addq(cSum, BigInt("0x" + proof.c[i]));
  if (cSum !== cFs) return false;
  const kw = BigInt(keyword);
  const negKwH = scalarMulH(kw).negate();
  for (let i = 0; i < n; i++) {
    const Ci = pointFromHex(utterance.commitments[i]);
    const inst = Ci.add(negKwH);
    const zi = BigInt("0x" + proof.z[i]);
    const ci = BigInt("0x" + proof.c[i]);
    const lhs = scalarMulG(zi);
    const rhs = pointFromHex(proof.A[i]).add(inst.multiply(ci));
    if (!lhs.equals(rhs)) return false;
  }
  return true;
}
function rerandomizeUtterance(utterance, secret) {
  const newCommitments = [];
  const newBlinds = [];
  for (let i = 0; i < utterance.numTokens; i++) {
    const s = randFieldQ();
    const Ci = pointFromHex(utterance.commitments[i]);
    newCommitments.push(pointToHex(Ci.add(scalarMulG(s))));
    newBlinds.push(addq(BigInt("0x" + secret.blinds[i]), s).toString(16));
  }
  return {
    utterance: { commitments: newCommitments, numTokens: utterance.numTokens },
    secret: { tokens: [...secret.tokens], blinds: newBlinds }
  };
}
function buildRegistry(voiceprints) {
  const commitments = [];
  const creds = [];
  for (let i = 0; i < voiceprints.length; i++) {
    const c = pedersenCommit(BigInt(voiceprints[i]));
    commitments.push(pointToHex(c.c));
    creds.push({
      voiceprint: voiceprints[i].toString(),
      blind: c.r.toString(16),
      registryIndex: i
    });
  }
  return { registry: { commitments }, creds };
}
function voiceAuthProve(credential, registry) {
  const k = registry.commitments.length;
  if (credential.registryIndex >= k) throw new Error("credential index out of range");
  const V = BigInt(credential.voiceprint);
  const rMe = randFieldQ();
  const Cme = scalarMulG(rMe).add(scalarMulH(V));
  const instances = [];
  for (let i = 0; i < k; i++) {
    const Ci = pointFromHex(registry.commitments[i]);
    instances.push(Cme.add(Ci.negate()));
  }
  const honestIdx = credential.registryIndex;
  const A = new Array(k);
  const c = new Array(k);
  const z = new Array(k);
  let cSimSum = 0n;
  for (let i = 0; i < k; i++) {
    if (i === honestIdx) continue;
    const zi = randFieldQ();
    const ci = randFieldQ();
    const Ai = scalarMulG(zi).add(instances[i].multiply(subq(Q, ci)));
    A[i] = pointToHex(Ai);
    c[i] = ci.toString(16);
    z[i] = zi.toString(16);
    cSimSum = addq(cSimSum, ci);
  }
  const s = randFieldQ();
  A[honestIdx] = pointToHex(scalarMulG(s));
  const cFs = fsHash("voice-auth", pointToHex(Cme), ...registry.commitments, ...A);
  c[honestIdx] = subq(cFs, cSimSum).toString(16);
  const rReg = BigInt("0x" + credential.blind);
  const witness = subq(rMe, rReg);
  z[honestIdx] = addq(s, mulq(BigInt("0x" + c[honestIdx]), witness)).toString(16);
  return { freshCommitment: pointToHex(Cme), A, c, z };
}
function voiceAuthVerify(registry, proof) {
  const k = registry.commitments.length;
  if (proof.A.length !== k || proof.c.length !== k || proof.z.length !== k) return false;
  const Cme = pointFromHex(proof.freshCommitment);
  const cFs = fsHash("voice-auth", proof.freshCommitment, ...registry.commitments, ...proof.A);
  let cSum = 0n;
  for (let i = 0; i < k; i++) cSum = addq(cSum, BigInt("0x" + proof.c[i]));
  if (cSum !== cFs) return false;
  for (let i = 0; i < k; i++) {
    const Ci = pointFromHex(registry.commitments[i]);
    const inst = Cme.add(Ci.negate());
    const zi = BigInt("0x" + proof.z[i]);
    const ci = BigInt("0x" + proof.c[i]);
    const lhs = scalarMulG(zi);
    const rhs = pointFromHex(proof.A[i]).add(inst.multiply(ci));
    if (!lhs.equals(rhs)) return false;
  }
  return true;
}
function simulateSilentSpeech(numTokens, vocabSize = 1e3) {
  const tokens = [];
  for (let i = 0; i < numTokens; i++) {
    tokens.push(1 + import_node_crypto.default.randomInt(1, vocabSize));
  }
  return tokens;
}
function simulateVoiceprint() {
  return import_node_crypto.default.randomInt(1, 1e6);
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
      throw new Error(`voice self-test failed: ${name}`);
    }
  };
  {
    const tokens = [101, 202, 303, 404, 505];
    const { utterance, secret } = commitUtterance(tokens);
    const proof = orSigmaProveKeyword(utterance, secret, 303);
    expect("silent speech honest keyword verifies", orSigmaVerifyKeyword(utterance, 303, proof));
  }
  {
    const tokens = [101, 202, 303];
    const { utterance, secret } = commitUtterance(tokens);
    const proof = orSigmaProveKeyword(utterance, secret, 101);
    expect("silent speech wrong keyword rejected", !orSigmaVerifyKeyword(utterance, 999, proof));
  }
  {
    const tokens = [101, 202, 303];
    const { utterance, secret } = commitUtterance(tokens);
    let rejected = false;
    try {
      orSigmaProveKeyword(utterance, secret, 999);
    } catch {
      rejected = true;
    }
    expect("silent speech absent keyword rejected by prover", rejected);
  }
  {
    const tokens = [101, 202, 303, 404];
    const { utterance, secret } = commitUtterance(tokens);
    const proof = orSigmaProveKeyword(utterance, secret, 303);
    const fake = pedersenCommit(999n);
    const tampered = {
      commitments: [pointToHex(fake.c), ...utterance.commitments.slice(1)],
      numTokens: utterance.numTokens
    };
    expect("silent speech utterance substitution rejected", !orSigmaVerifyKeyword(tampered, 303, proof));
  }
  {
    const tokens = [101, 202, 303];
    const { utterance, secret } = commitUtterance(tokens);
    const { utterance: utt2, secret: sec2 } = rerandomizeUtterance(utterance, secret);
    expect("rerandomize preserves tokens", JSON.stringify(sec2.tokens) === JSON.stringify(secret.tokens));
    expect("rerandomize changes commitments", JSON.stringify(utt2.commitments) !== JSON.stringify(utterance.commitments));
    const proof2 = orSigmaProveKeyword(utt2, sec2, 303);
    expect("rerandomized utterance proof verifies", orSigmaVerifyKeyword(utt2, 303, proof2));
  }
  {
    const { registry, creds } = buildRegistry([1111, 2222, 3333]);
    const proof = voiceAuthProve(creds[1], registry);
    expect("voice auth authorized speaker verifies", voiceAuthVerify(registry, proof));
  }
  {
    const { registry, creds } = buildRegistry([1111, 2222]);
    const p1 = voiceAuthProve(creds[0], registry);
    const p2 = voiceAuthProve(creds[0], registry);
    expect("voice auth unlinkable (fresh commitments differ)", p1.freshCommitment !== p2.freshCommitment);
  }
  {
    const { registry, creds } = buildRegistry([1111, 2222, 3333]);
    const bad = { voiceprint: "9999", blind: randFieldQ().toString(16), registryIndex: 0 };
    const badProof = voiceAuthProve(bad, registry);
    expect("voice auth unauthorized rejected", !voiceAuthVerify(registry, badProof));
  }
  {
    const tokens = [101, 202, 303];
    const { utterance, secret } = commitUtterance(tokens);
    const proof = orSigmaProveKeyword(utterance, secret, 303);
    const keys = Object.keys(proof);
    expect("silent speech proof has no token fields", !keys.includes("tokens") && !keys.includes("blinds"));
  }
  {
    for (const pos of [0, 1, 2, 3]) {
      const tokens = [101, 202, 303, 404];
      tokens[pos] = 777;
      const { utterance, secret } = commitUtterance(tokens);
      const proof = orSigmaProveKeyword(utterance, secret, 777);
      expect(`silent speech keyword at position ${pos} verifies`, orSigmaVerifyKeyword(utterance, 777, proof));
    }
  }
  expect("voice self-test completed", true);
  return { passed, cases };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  H,
  buildRegistry,
  commitUtterance,
  orSigmaProveKeyword,
  orSigmaVerifyKeyword,
  rerandomizeUtterance,
  selfTest,
  simulateSilentSpeech,
  simulateVoiceprint,
  voiceAuthProve,
  voiceAuthVerify
});
