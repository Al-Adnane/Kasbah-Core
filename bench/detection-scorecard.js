'use strict';
/**
 * bench/detection-scorecard.js — detector-level precision/recall/F1 benchmark.
 *
 * Runs the two live, validated regex/checksum detectors:
 *   - packages/api-server/src/governance/secret-leak.js
 *   - packages/api-server/src/systems/multilingual-pii.js
 * against a labeled corpus (bench/corpus/detection-scorecard-v1.json) and
 * computes precision, recall, F1 overall and per category. This is boring,
 * well-understood confusion-matrix evaluation — no novel math, same
 * methodology as research/validate-all.js and bench/run.js.
 *
 * Regression gate: fails (non-zero exit) if precision or recall for either
 * detector drops below the checked-in baseline in BASELINE below. Update
 * the baseline deliberately (in the same commit as the detector change)
 * when a real improvement or an accepted tradeoff is made — don't just
 * lower the bar to make CI pass.
 *
 * Run: node bench/detection-scorecard.js
 * Writes: bench/results/detection-scorecard-<timestamp>.json, SCORECARD.md
 */

const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');

const { detect: secretLeakDetect } = require(path.join(ROOT, 'packages/api-server/src/governance/secret-leak.js'));
const { multilingualPiiCheck } = require(path.join(ROOT, 'packages/api-server/src/systems/multilingual-pii.js'));

const CORPUS_PATH = path.join(ROOT, 'bench/corpus/detection-scorecard-v1.json');
const corpus = JSON.parse(fs.readFileSync(CORPUS_PATH, 'utf8'));

// Regression gate — checked-in baseline. Do not lower without a real reason
// documented in the same commit + CHANGELOG.md entry.
const BASELINE = {
  // secret-leak: measured 100.0% precision / 100.0% recall on the 2026-07-07 corpus
  // (v1.0.0, 34 cases). Floor set a few points below measured to tolerate minor
  // corpus additions without false alarms; ratchet up as real improvements land.
  'secret-leak':      { minPrecision: 0.95, minRecall: 0.95 },
  // multilingual-pii: measured 100.0% precision / 100.0% recall on the 2026-07-07
  // corpus (v1.0.0, 23 cases) AFTER fixing the false-positive bug that had capped
  // precision at 64.7%: PHONE_INTL / DOB_ISO / MA_CIN / ID_KTP / JP_MYNUMBER_B
  // matched digit substrings inside UUIDs, invoice numbers, order dates, SKUs and
  // payment cards. Fixed via boundary lookarounds, context-aware validators
  // (dobContextValid/notProductCode/notPaymentCard), and a general UUID-span
  // skip in the detect loop. Floor set a few points below measured.
  'multilingual-pii': { minPrecision: 0.90, minRecall: 0.95 },
};

function confusionMatrix(rows) {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  for (const r of rows) {
    if (r.expected && r.predicted) tp++;
    else if (!r.expected && r.predicted) fp++;
    else if (r.expected && !r.predicted) fn++;
    else tn++;
  }
  return { tp, fp, fn, tn };
}

function metrics({ tp, fp, fn, tn }) {
  const precision = (tp + fp) > 0 ? tp / (tp + fp) : (tp === 0 ? 1 : 0);
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : (tp === 0 ? 1 : 0);
  const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = (tp + fp + fn + tn) > 0 ? (tp + tn) / (tp + fp + fn + tn) : 0;
  return { precision, recall, f1, accuracy };
}

function byCategory(rows) {
  const cats = {};
  for (const r of rows) {
    cats[r.category] = cats[r.category] || [];
    cats[r.category].push(r);
  }
  const out = {};
  for (const [cat, catRows] of Object.entries(cats)) {
    out[cat] = { ...metrics(confusionMatrix(catRows)), n: catRows.length };
  }
  return out;
}

// ── run secret-leak ──────────────────────────────────────────────────────────
const secretRows = corpus.secretLeakCases.map(c => {
  const result = secretLeakDetect(c.text);
  const predicted = result.risk >= 0.5; // matches typical governance risk threshold
  return { id: c.id, category: c.category, expected: c.expect_detect, predicted, risk: result.risk, threats: result.threats };
});
const secretCM = confusionMatrix(secretRows);
const secretMetrics = metrics(secretCM);
const secretByCategory = byCategory(secretRows);

// ── run multilingual-pii ─────────────────────────────────────────────────────
const piiRows = corpus.multilingualPiiCases.map(c => {
  const result = multilingualPiiCheck(c.text);
  const predicted = result.detected === true;
  return { id: c.id, category: c.category, expected: c.expect_detect, predicted, riskScore: result.riskScore, findingTypes: (result.findings || []).map(f => f.type) };
});
const piiCM = confusionMatrix(piiRows);
const piiMetrics = metrics(piiCM);
const piiByCategory = byCategory(piiRows);

// ── regression gate ──────────────────────────────────────────────────────────
let gateFailed = false;
const gateResults = [];
for (const [name, m, base] of [
  ['secret-leak', secretMetrics, BASELINE['secret-leak']],
  ['multilingual-pii', piiMetrics, BASELINE['multilingual-pii']],
]) {
  const precOk = m.precision >= base.minPrecision;
  const recOk = m.recall >= base.minRecall;
  gateResults.push({ detector: name, precOk, recOk, precision: m.precision, recall: m.recall, baseline: base });
  if (!precOk || !recOk) gateFailed = true;
}

// ── console report ───────────────────────────────────────────────────────────
console.log('=== Kasbah Detection Coverage Scorecard ===');
console.log('Corpus:', CORPUS_PATH);
console.log('secret-leak cases:', secretRows.length, ' multilingual-pii cases:', piiRows.length);
console.log('');
console.log('-- secret-leak --');
console.log('  precision=' + (secretMetrics.precision * 100).toFixed(1) + '%',
            'recall=' + (secretMetrics.recall * 100).toFixed(1) + '%',
            'f1=' + (secretMetrics.f1 * 100).toFixed(1) + '%',
            'TP=' + secretCM.tp, 'FP=' + secretCM.fp, 'FN=' + secretCM.fn, 'TN=' + secretCM.tn);
console.log('-- multilingual-pii --');
console.log('  precision=' + (piiMetrics.precision * 100).toFixed(1) + '%',
            'recall=' + (piiMetrics.recall * 100).toFixed(1) + '%',
            'f1=' + (piiMetrics.f1 * 100).toFixed(1) + '%',
            'TP=' + piiCM.tp, 'FP=' + piiCM.fp, 'FN=' + piiCM.fn, 'TN=' + piiCM.tn);
console.log('');
console.log('-- regression gate --');
for (const g of gateResults) {
  console.log('  ' + g.detector + ':', (g.precOk && g.recOk) ? 'PASS' : 'FAIL',
    '(precision ' + (g.precision * 100).toFixed(1) + '% >= ' + (g.baseline.minPrecision * 100).toFixed(1) + '%: ' + g.precOk + ',',
    'recall ' + (g.recall * 100).toFixed(1) + '% >= ' + (g.baseline.minRecall * 100).toFixed(1) + '%: ' + g.recOk + ')');
}

// false positives / false negatives detail (for debugging regressions)
const secretFPs = secretRows.filter(r => !r.expected && r.predicted);
const secretFNs = secretRows.filter(r => r.expected && !r.predicted);
const piiFPs = piiRows.filter(r => !r.expected && r.predicted);
const piiFNs = piiRows.filter(r => r.expected && !r.predicted);

if (secretFPs.length) { console.log('\nsecret-leak false positives:'); secretFPs.forEach(r => console.log('  ' + r.id + ' (' + r.category + ') risk=' + r.risk.toFixed(2) + ' threats=' + JSON.stringify(r.threats))); }
if (secretFNs.length) { console.log('\nsecret-leak false negatives:'); secretFNs.forEach(r => console.log('  ' + r.id + ' (' + r.category + ')')); }
if (piiFPs.length) { console.log('\nmultilingual-pii false positives:'); piiFPs.forEach(r => console.log('  ' + r.id + ' (' + r.category + ') types=' + JSON.stringify(r.findingTypes))); }
if (piiFNs.length) { console.log('\nmultilingual-pii false negatives:'); piiFNs.forEach(r => console.log('  ' + r.id + ' (' + r.category + ')')); }

// ── write JSON results ───────────────────────────────────────────────────────
const timestamp = new Date().toISOString();
const resultsDir = path.join(ROOT, 'bench/results');
if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });
const resultsFile = path.join(resultsDir, 'detection-scorecard-' + timestamp.replace(/[:.]/g, '-') + '.json');
const output = {
  timestamp,
  corpus: { path: 'bench/corpus/detection-scorecard-v1.json', version: corpus.version,
    secretLeakCases: secretRows.length, multilingualPiiCases: piiRows.length },
  secretLeak: { confusionMatrix: secretCM, metrics: secretMetrics, byCategory: secretByCategory, rows: secretRows },
  multilingualPii: { confusionMatrix: piiCM, metrics: piiMetrics, byCategory: piiByCategory, rows: piiRows },
  regressionGate: { passed: !gateFailed, results: gateResults },
};
fs.writeFileSync(resultsFile, JSON.stringify(output, null, 2));
console.log('\nwrote', path.relative(ROOT, resultsFile));

// ── write SCORECARD.md ───────────────────────────────────────────────────────
function pct(x) { return (x * 100).toFixed(1) + '%'; }
function catTable(byCategory) {
  const lines = ['| Category | Precision | Recall | F1 | n |', '|---|---:|---:|---:|---:|'];
  for (const [cat, m] of Object.entries(byCategory).sort()) {
    lines.push('| ' + cat + ' | ' + pct(m.precision) + ' | ' + pct(m.recall) + ' | ' + pct(m.f1) + ' | ' + m.n + ' |');
  }
  return lines.join('\n');
}

const scorecardMd = `# Kasbah Detection Coverage Scorecard

_Generated: ${timestamp}_

Corpus: \`bench/corpus/detection-scorecard-v1.json\` (v${corpus.version}) — ${secretRows.length} secret-leak cases, ${piiRows.length} multilingual-pii cases.

Reproduce: \`node bench/detection-scorecard.js\` (also \`npm run bench:detection\`)

## Headline

| Detector | Precision | Recall | F1 | Accuracy | TP | FP | FN | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| secret-leak (\`packages/api-server/src/governance/secret-leak.js\`) | ${pct(secretMetrics.precision)} | ${pct(secretMetrics.recall)} | ${pct(secretMetrics.f1)} | ${pct(secretMetrics.accuracy)} | ${secretCM.tp} | ${secretCM.fp} | ${secretCM.fn} | ${secretCM.tn} |
| multilingual-pii (\`packages/api-server/src/systems/multilingual-pii.js\`) | ${pct(piiMetrics.precision)} | ${pct(piiMetrics.recall)} | ${pct(piiMetrics.f1)} | ${pct(piiMetrics.accuracy)} | ${piiCM.tp} | ${piiCM.fp} | ${piiCM.fn} | ${piiCM.tn} |

## Regression gate

Checked-in baseline (\`BASELINE\` in \`bench/detection-scorecard.js\`): secret-leak requires precision/recall >= ${pct(BASELINE['secret-leak'].minPrecision)}/${pct(BASELINE['secret-leak'].minRecall)}; multilingual-pii requires >= ${pct(BASELINE['multilingual-pii'].minPrecision)}/${pct(BASELINE['multilingual-pii'].minRecall)}. Script exits non-zero if either detector drops below its floor.

**Result this run: ${gateFailed ? 'FAIL' : 'PASS'}**

## secret-leak — per category

${catTable(secretByCategory)}

## multilingual-pii — per category

${catTable(piiByCategory)}

## False positives (this run)

${secretFPs.length ? secretFPs.map(r => '- secret-leak `' + r.id + '` (' + r.category + '): risk=' + r.risk.toFixed(2) + ', threats=' + JSON.stringify(r.threats)).join('\n') : '- secret-leak: none'}
${piiFPs.length ? piiFPs.map(r => '- multilingual-pii `' + r.id + '` (' + r.category + '): types=' + JSON.stringify(r.findingTypes)).join('\n') : '- multilingual-pii: none'}

## False negatives (this run)

${secretFNs.length ? secretFNs.map(r => '- secret-leak `' + r.id + '` (' + r.category + ')').join('\n') : '- secret-leak: none'}
${piiFNs.length ? piiFNs.map(r => '- multilingual-pii `' + r.id + '` (' + r.category + ')').join('\n') : '- multilingual-pii: none'}

## What this measures (and what it does not)

- **Measures**: precision/recall/F1 of the two live regex/checksum detectors against a hand-labeled corpus of real-shaped credentials/PII (positives) and realistic false-positive traps (negatives: example.com domains, git SHAs, UUIDs, invoice/order numbers, version strings, checksummed-invalid lookalikes).
- **Does not measure**: performance on adversarial obfuscation (e.g. base64-wrapped secrets, zero-width characters), real production traffic distribution, or detectors other than these two (secret-leak, multilingual-pii).
- **False-positive traps in the corpus** (PII-NEG-001/002/003/007/010/012): digit runs inside UUIDs, invoice numbers, order-date references, product SKUs and failed-checksum card/IBAN lookalikes. Earlier versions of the multilingual-pii \`PHONE_INTL\` and \`DOB_ISO\` patterns matched these; they are kept as negatives so a regression shows up in the tables above. Any that fail in this run are listed under "False positives (this run)".
- **One case per category**: each category score is a single pass/fail, so 100% means "no regression on this case", not a measured detection rate.
- **Corpus size**: ${secretRows.length + piiRows.length} total labeled cases (${secretRows.length} secret-leak, ${piiRows.length} multilingual-pii). Small relative to production traffic — treat this as a floor/regression check, not a claim of exhaustive coverage.
`;

fs.writeFileSync(path.join(ROOT, 'SCORECARD.md'), scorecardMd);
console.log('wrote', path.relative(ROOT, path.join(ROOT, 'SCORECARD.md')));

if (gateFailed) {
  console.error('\nREGRESSION GATE FAILED — precision or recall dropped below checked-in baseline.');
  process.exit(1);
}
process.exit(0);
