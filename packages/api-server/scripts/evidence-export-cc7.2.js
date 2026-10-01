#!/usr/bin/env node
'use strict';

/**
 * Evidence export — SOC 2 CC7.2 "System Monitoring"
 * ---------------------------------------------------
 * CC7.2 (AICPA Trust Services Criteria) requires the entity to monitor
 * system components for anomalies that are indicative of malicious acts,
 * natural disasters, and errors affecting the entity's ability to meet
 * its objectives, and to analyze those anomalies for potential security
 * events.
 *
 * This script does NOT claim CC7.2 is "satisfied" or that Kasbah is
 * "SOC 2 compliant." It exports the specific, real, already-existing
 * evidence this system produces that bears on CC7.2, in a form a real
 * external auditor could pull, hash-check, and independently verify
 * without trusting the Kasbah server that generated it. It also states
 * plainly what this evidence package does NOT cover.
 *
 * Evidence sources (all real, already shipped in this repo before this
 * script; nothing new is fabricated here):
 *   1. The tamper-evident audit hash chain — packages/api-server/src/frontier.js
 *      (auditAppend/auditVerify/auditGetChain), persisted as an append-only
 *      JSONL file under KASBAH_DATA_DIR/audit-chain.jsonl and replayed on boot.
 *      Every governed request (ALLOW/WARN/DENY) that flows through
 *      POST /v1/govern (or the honeytoken/maqasid DENY paths in server.js)
 *      is appended here with a timestamp and SHA-256 link to the prior
 *      entry — this is the "system monitors and records" evidence.
 *   2. Ed25519/ML-DSA-signed governance receipts — packages/kasbah-receipts
 *      and packages/api-server/src/engine-key.js — attached to some audit
 *      entries (see "receipt"/"receiptPayload" fields), independently
 *      verifiable offline against the engine's published public key.
 *
 * Usage:
 *   node packages/api-server/scripts/evidence-export-cc7.2.js [--out FILE] [--limit N]
 *
 * Requires no server to be running — reads the JSONL file directly, exactly
 * as frontier.js does at boot, and re-derives the hash chain independently
 * (this script does not call frontier.js at all, so its verification is not
 * trusting the same code path that wrote the file).
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const KASBAH_DATA_DIR = process.env.KASBAH_DATA_DIR
  || path.join(__dirname, '..', '..', '..', '.kasbah');
const CHAIN_FILE = path.join(KASBAH_DATA_DIR, 'audit-chain.jsonl');
const GENESIS_HASH = '0'.repeat(64);

function parseArgs(argv) {
  const out = { limit: 500, outFile: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--limit') out.limit = parseInt(argv[++i], 10) || 500;
    if (argv[i] === '--out')   out.outFile = argv[++i];
  }
  return out;
}

/**
 * Independently re-derive and verify the hash chain from the raw JSONL file.
 * Deliberately reimplemented here (not imported from frontier.js) so this
 * check does not depend on trusting the same module that wrote the file —
 * an auditor reading this script can see the whole verification logic
 * in one place, in ~25 lines, with no hidden dependency.
 */
function loadAndVerifyChain(file) {
  let lines = [];
  try {
    const raw = fs.readFileSync(file, 'utf8');
    lines = raw.split('\n').filter(l => l.trim().length > 0);
  } catch (e) {
    return { entries: [], integrity: { valid: true, length: 0 }, fileExists: false, error: e.code };
  }

  const entries = lines.map(l => JSON.parse(l));

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const expectedPrev = i === 0 ? GENESIS_HASH : entries[i - 1].hash;
    if (entry.prevHash !== expectedPrev) {
      return { entries, integrity: { valid: false, brokenAt: i, reason: 'prevHash mismatch' }, fileExists: true };
    }
    const dataHash = crypto.createHash('sha256').update(JSON.stringify(entry.data)).digest('hex');
    const expectedHash = crypto.createHash('sha256')
      .update(entry.prevHash + dataHash + entry.ts.toString())
      .digest('hex');
    if (entry.hash !== expectedHash) {
      return { entries, integrity: { valid: false, brokenAt: i, reason: `hash mismatch at index ${i} — entry tampered` }, fileExists: true };
    }
  }

  const integrity = entries.length === 0
    ? { valid: true, length: 0 }
    : { valid: true, length: entries.length, tip: entries[entries.length - 1].hash, tipTs: entries[entries.length - 1].ts };

  return { entries, integrity, fileExists: true };
}

/**
 * Verify any Ed25519/ML-DSA governance receipts attached to audit entries,
 * using the same offline verification logic described in
 * packages/kasbah-receipts/SPEC.md (independent of the live server).
 */
function verifyAttachedReceipts(entries) {
  let engineKey;
  try {
    engineKey = require('../src/engine-key.js');
  } catch (e) {
    return { checked: 0, valid: 0, invalid: 0, results: [], error: `engine-key module unavailable: ${e.message}` };
  }

  const results = [];
  for (const e of entries) {
    const d = e.data || {};
    if (!d.receipt || !d.receiptPayload) continue;
    let result;
    try {
      result = engineKey.verify(d.receipt, d.receiptPayload);
    } catch (err) {
      result = { valid: false, error: err.message };
    }
    results.push({
      auditIndex: e.index,
      requestId: d.requestId || null,
      verdict: d.verdict || null,
      receiptValid: !!result.valid,
      receiptError: result.error || undefined,
      algorithm: result.algorithm || null,
    });
  }

  return {
    checked: results.length,
    valid: results.filter(r => r.receiptValid).length,
    invalid: results.filter(r => !r.receiptValid).length,
    results,
  };
}

function buildEvidencePackage({ limit }) {
  const chainResult = loadAndVerifyChain(CHAIN_FILE);
  const entries = chainResult.entries.slice(-limit);

  const monitoringEntries = entries.map(e => ({
    index: e.index,
    timestamp: new Date(e.ts).toISOString(),
    verdict: e.data && e.data.verdict,
    reason: (e.data && (e.data.threats || e.data.reason)) || null,
    requestId: (e.data && e.data.requestId) || null,
    passportId: (e.data && e.data.passportId) || null,
    prevHash: e.prevHash,
    hash: e.hash,
  }));

  const denyCount = monitoringEntries.filter(e => e.verdict === 'DENY').length;
  const warnCount = monitoringEntries.filter(e => e.verdict === 'WARN').length;
  const allowCount = monitoringEntries.filter(e => e.verdict === 'ALLOW').length;

  const receiptCheck = verifyAttachedReceipts(chainResult.entries);

  return {
    control: {
      framework: 'SOC 2 Type II (AICPA Trust Services Criteria)',
      id: 'CC7.2',
      name: 'System Monitoring',
      description:
        'The entity monitors system components and the operation of those ' +
        'components for anomalies that are indicative of malicious acts, ' +
        'natural disasters, and errors affecting the entity\'s ability to ' +
        'meet its objectives; anomalies are analyzed to determine whether ' +
        'they represent security events.',
    },
    generatedAt: new Date().toISOString(),
    dataSource: {
      chainFile: CHAIN_FILE,
      fileExists: chainResult.fileExists,
    },
    // Real, independently re-derived chain integrity — not the value reported
    // by the running server, computed fresh from the JSONL file in this script.
    chainIntegrity: chainResult.integrity,
    monitoringEvidence: {
      description:
        'Every governance decision (ALLOW/WARN/DENY) made by the governance ' +
        'engine is appended to a SHA-256 hash chain at the moment of decision, ' +
        'with a wall-clock timestamp and a reason/threat classification. Each ' +
        'entry cryptographically commits to the previous entry\'s hash, so any ' +
        'retroactive edit or deletion of a past entry is detectable via ' +
        'chainIntegrity above.',
      totalEntriesInWindow: monitoringEntries.length,
      totalEntriesInFullChain: chainResult.entries.length,
      denyCount,
      warnCount,
      allowCount,
      entries: monitoringEntries,
    },
    signedReceiptEvidence: {
      description:
        'Where a governance decision produced a signed receipt (Ed25519 or ' +
        'ML-DSA / post-quantum, per packages/kasbah-receipts/SPEC.md), this ' +
        'export independently re-verifies the signature against the engine\'s ' +
        'published public key using packages/api-server/src/engine-key.js\'s ' +
        'verify() — the same offline verification path a third-party auditor ' +
        'would run themselves, no server trust required.',
      ...receiptCheck,
    },
    howAnAuditorVerifiesThisIndependently: [
      'Do not trust this JSON file alone — it is a claim, not proof.',
      '1. Obtain the raw audit-chain.jsonl file directly (not this export) — ' +
        'each line is one JSON record with {index, prevHash, hash, ts, data}.',
      '2. For each line i, recompute dataHash = SHA-256(JSON.stringify(data)), ' +
        'then hash = SHA-256(prevHash + dataHash + ts). Confirm it equals the ' +
        'recorded "hash", and that "prevHash" equals the previous line\'s "hash" ' +
        '(or 64 zeros for line 0). This is the entire algorithm — no proprietary ' +
        'library or Kasbah server call is needed to check it.',
      '3. For any entry with a "receipt" + "receiptPayload" pair, verify the ' +
        'signature offline per packages/kasbah-receipts/SPEC.md section 5, ' +
        'using the engine\'s published public key at GET /.well-known/kasbah-keys.json.',
      '4. Compare the recomputed chain tip hash and receipt-verification results ' +
        'to the ones in this export. If they match, this export is an accurate ' +
        'summary of the underlying tamper-evident data; if they don\'t, treat ' +
        'this export as unreliable and prefer the raw file.',
    ],
    notYetCovered: [
      'This does NOT prove the governance engine\'s DENY/WARN/ALLOW decisions ' +
        'were *correct* (i.e. that a real threat was actually blocked, or that ' +
        'no real threat was missed) — it proves the decisions that were made ' +
        'are recorded immutably and can be reviewed. Decision quality is a ' +
        'separate question from monitoring integrity.',
      'This does NOT cover monitoring of infrastructure/host-level anomalies ' +
        '(CPU, disk, network intrusion at the OS level) — only application-layer ' +
        'governance decisions that flow through the /v1/govern-family endpoints.',
      'This does NOT prove every request that should have been governed actually ' +
        'was — it only attests to the integrity of entries that WERE recorded. ' +
        'A request that bypassed the governance path entirely would leave no ' +
        'trace here and this export cannot detect that gap.',
      'Hash-chain persistence is a single local JSONL file today (no off-host ' +
        'replication, no WORM storage, no independent third-party timestamping ' +
        'service). A person with write access to the host filesystem and the ' +
        'ability to rewrite the entire file from genesis could still forge a ' +
        'self-consistent fake chain — this evidence proves tamper-evidence ' +
        '(detects post-hoc edits to an existing chain), not tamper-proofness ' +
        'against a full-file replacement by someone with host access.',
      'This is not a SOC 2 report, attestation, or certification of any kind, ' +
        'and does not claim one. It is raw evidence for one control family, ' +
        'for a human auditor to evaluate as part of a real audit engagement.',
    ],
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const pkg = buildEvidencePackage(args);
  const json = JSON.stringify(pkg, null, 2);

  if (args.outFile) {
    fs.writeFileSync(args.outFile, json);
    console.error(`Evidence package written to ${args.outFile}`);
  } else {
    process.stdout.write(json + '\n');
  }

  console.error(
    `\nchainIntegrity.valid=${pkg.chainIntegrity.valid} ` +
    `entries=${pkg.monitoringEvidence.totalEntriesInFullChain} ` +
    `(deny=${pkg.monitoringEvidence.denyCount} warn=${pkg.monitoringEvidence.warnCount} allow=${pkg.monitoringEvidence.allowCount}) ` +
    `receipts checked=${pkg.signedReceiptEvidence.checked} valid=${pkg.signedReceiptEvidence.valid} invalid=${pkg.signedReceiptEvidence.invalid}`
  );
}

if (require.main === module) main();

module.exports = { buildEvidencePackage, loadAndVerifyChain, verifyAttachedReceipts };
