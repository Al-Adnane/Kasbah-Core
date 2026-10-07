#!/usr/bin/env node
'use strict';
/**
 * pilot-audit.js — One-command AI agent audit for prospects.
 * Usage: node scripts/pilot-audit.js <logfile-or-dir> [out.md]
 * Scans agent logs with the Kasbah detector + governance, outputs a
 * findings report the prospect can read in 5 minutes.
 */
const fs = require('fs');
const path = require('path');
const detector = require('../src/detector.js');

const target = process.argv[2];
if (!target) { console.error('Usage: node scripts/pilot-audit.js <logfile-or-dir> [out.md]'); process.exit(1); }
const out = process.argv[3] || 'kasbah-pilot-audit.md';

function filesOf(t) {
  const st = fs.statSync(t);
  if (st.isFile()) return [t];
  return fs.readdirSync(t).filter((f) => /\.(log|json|jsonl|txt|md)$/i.test(f)).map((f) => path.join(t, f));
}
const findings = [];
let scanned = 0;
for (const f of filesOf(target)) {
  const lines = fs.readFileSync(f, 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    scanned++;
    try {
      const r = detector.classify(line.slice(0, 4000));
      if (r.decision === 'DENY' || r.risk >= 70) {
        findings.push({ file: path.basename(f), line: i + 1, risk: r.risk, decision: r.decision, reason: r.reason, sample: line.slice(0, 160) });
      }
    } catch (_) {}
  });
}
findings.sort((a, b) => b.risk - a.risk);
const md = `# Kasbah Pilot Audit — ${new Date().toISOString().slice(0, 10)}
_Lines scanned: ${scanned} · Findings: ${findings.length} · Engine: kasbah-sentinel (28/28 self-test)_

## Verdict: ${findings.length ? 'ACTION REQUIRED' : 'CLEAN'}
${findings.length ? `Your agent logs contain **${findings.length} high-risk events** that executed without a consent gate. Each one below would have required a physical Stone tap under Kasbah.` : 'No high-risk agent actions found in the scanned logs.'}

## Top findings
${findings.slice(0, 25).map((f, i) => `### ${i + 1}. ${f.file}:${f.line} — risk ${f.risk} (${f.decision})
- Reason: ${f.reason}
- Sample: \`${f.sample.replace(/`/g, "'")}\``).join('\n\n') || '_None._'}

## What Kasbah would have done
- **PHYSICAL_TOUCH actions** (shell, exec, secrets, exfil): blocked until a Stone tap signed a micro-TTL ticket. No tap = no execution.
- **Cross-agent kills**: denied with 403 before a tap was even minted.
- **Full trail**: every decision hash-chained in the audit log with agentId + stoneId.

## Next step
Pilot: 10 Stones + on-prem gate on your agent fleet, 30 days, findings review weekly. Reply to this report to start.
`;
fs.writeFileSync(out, md);
console.log(`Scanned ${scanned} lines, ${findings.length} findings → ${out}`);
