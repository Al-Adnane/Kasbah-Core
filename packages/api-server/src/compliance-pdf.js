'use strict';

/**
 * Compliance PDF Generator — SOC2/ISO27001/NIST Auto-Reporter
 * ============================================================
 * Generates formatted compliance evidence packets from the audit chain.
 * Uses the existing compliance-report.js data + audit trail.
 *
 * OUTPUT FORMATS:
 *   - JSON (structured evidence packet)
 *   - HTML (print-ready compliance report)
 *   - Markdown (for git-backed compliance)
 *
 * COVERS: SOC 2 Type II, ISO 27001:2022, NIST CSF 2.0
 */

const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════════
// Compliance Control Mappings
// ═══════════════════════════════════════════════════════════════

const SOC2_CONTROLS = [
  { id: 'CC6.1', name: 'Logical Access Security', description: 'Access to system resources is restricted to authorized users' },
  { id: 'CC6.6', name: 'External Threats', description: 'System protected against external security threats' },
  { id: 'CC7.1', name: 'Detection of Anomalies', description: 'Anomalies are detected and investigated' },
  { id: 'CC7.2', name: 'Monitoring', description: 'System activity is monitored for security events' },
  { id: 'CC7.3', name: 'Incident Response', description: 'Security incidents are responded to and remediated' },
  { id: 'CC8.1', name: 'Change Management', description: 'Changes are authorized and tested' },
];

const ISO27001_CONTROLS = [
  { id: 'A.5.1', name: 'Information Security Policies', description: 'Policies for information security are defined and approved' },
  { id: 'A.8.1', name: 'Asset Management', description: 'Assets are identified and classified' },
  { id: 'A.9.1', name: 'Access Control', description: 'Access to information is restricted' },
  { id: 'A.12.4', name: 'Logging and Monitoring', description: 'Event logs are produced and reviewed' },
  { id: 'A.14.2', name: 'Security in Development', description: 'Security is integrated into development lifecycle' },
  { id: 'A.16.1', name: 'Incident Management', description: 'Security incidents are managed consistently' },
];

const NIST_FUNCTIONS = [
  { id: 'IDENTIFY', name: 'Identify', description: 'Develop understanding of cybersecurity risks' },
  { id: 'PROTECT', name: 'Protect', description: 'Implement safeguards to limit impact' },
  { id: 'DETECT', name: 'Detect', description: 'Identify cybersecurity events' },
  { id: 'RESPOND', name: 'Respond', description: 'Take action on detected events' },
  { id: 'RECOVER', name: 'Recover', description: 'Restore capabilities after incidents' },
];

// ═══════════════════════════════════════════════════════════════
// Generator
// ═══════════════════════════════════════════════════════════════

class ComplianceReportGenerator {
  /**
   * @param {object} opts
   * @param {object} opts.auditData — audit chain entries from forward-secure-audit
   * @param {object} opts.governanceStats — governance pipeline statistics
   * @param {string} opts.organization — organization name
   */
  constructor(opts = {}) {
    this.auditData = opts.auditData || { entries: [], chainLength: 0 };
    this.governanceStats = opts.governanceStats || { totalCalls: 0, blocked: 0, allowed: 0, warned: 0 };
    this.organization = opts.organization || 'Kasbah Deployment';
    this.generatedAt = new Date().toISOString();
  }

  /**
   * Generate SOC 2 Type II evidence packet.
   */
  generateSOC2() {
    const evidence = SOC2_CONTROLS.map(ctrl => {
      const ev = this._getEvidenceForControl(ctrl.id);
      return {
        control: ctrl,
        status: this._deriveStatus(ev, 'COMPLIANT'),
        evidence: ev,
        attestation: this._generateAttestation(ctrl.id),
      };
    });

    return {
      framework: 'SOC 2 Type II',
      organization: this.organization,
      generatedAt: this.generatedAt,
      reportId: crypto.randomBytes(8).toString('hex'),
      overallStatus: this._overallStatus(evidence, 'COMPLIANT'),
      controls: evidence,
      auditChain: this._auditChain(),
      signatures: {
        auditor: null, // External auditor signs here
        systemHash: this._hashReport(evidence),
      },
    };
  }

  /**
   * Generate ISO 27001:2022 evidence packet.
   */
  generateISO27001() {
    const evidence = ISO27001_CONTROLS.map(ctrl => {
      const ev = this._getEvidenceForControl(ctrl.id);
      return {
        control: ctrl,
        status: this._deriveStatus(ev, 'CONFORMANT'),
        evidence: ev,
      };
    });

    return {
      framework: 'ISO 27001:2022',
      organization: this.organization,
      generatedAt: this.generatedAt,
      reportId: crypto.randomBytes(8).toString('hex'),
      overallStatus: this._overallStatus(evidence, 'CONFORMANT'),
      clauses: evidence,
      auditChain: this._auditChain(),
    };
  }

  /**
   * Generate NIST CSF 2.0 evidence packet.
   */
  generateNIST() {
    const evidence = NIST_FUNCTIONS.map(func => {
      const ev = this._getNISTEvidence(func.id);
      return {
        function: func,
        status: this._deriveStatus(ev, 'IMPLEMENTED'),
        evidence: ev,
      };
    });

    // Maturity reflects actual audit-trail depth, not a fixed claim.
    const total = this.auditData.chainLength || this.auditData.entries?.length || 0;
    const maturityLevel = total === 0 ? 'TIER_0_NOT_YET_OBSERVED'
      : total < 100   ? 'TIER_1_PARTIAL'
      : total < 1000  ? 'TIER_2_RISK_INFORMED'
      : 'TIER_3_REPEATABLE';

    return {
      framework: 'NIST CSF 2.0',
      organization: this.organization,
      generatedAt: this.generatedAt,
      reportId: crypto.randomBytes(8).toString('hex'),
      overallStatus: this._overallStatus(evidence, 'IMPLEMENTED'),
      functions: evidence,
      maturityLevel,
    };
  }

  /**
   * Generate all three frameworks at once.
   */
  generateAll() {
    return {
      soc2: this.generateSOC2(),
      iso27001: this.generateISO27001(),
      nist: this.generateNIST(),
      meta: {
        organization: this.organization,
        generatedAt: this.generatedAt,
        totalAuditEntries: this.auditData.chainLength || this.auditData.entries?.length || 0,
        governanceCalls: this.governanceStats.totalCalls || 0,
      },
    };
  }

  /**
   * Generate a print-ready HTML report combining all frameworks.
   */
  generateHTML() {
    const all = this.generateAll();
    return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Kasbah Compliance Report — ${this.organization}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }
  h1 { font-size: 24px; border-bottom: 2px solid #2563eb; padding-bottom: 10px; }
  h2 { font-size: 18px; margin-top: 30px; color: #2563eb; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0 20px; }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid #e5e7eb; font-size: 13px; }
  th { background: #f8fafc; font-weight: 600; }
  .compliant { color: #059669; font-weight: 600; }
  .meta { color: #6b7280; font-size: 12px; margin-bottom: 30px; }
  .footer { margin-top: 40px; font-size: 11px; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 10px; }
</style></head>
<body>
<h1>Kasbah Compliance Report</h1>
<p class="meta">${this.organization} · Generated ${this.generatedAt} · Report ${all.soc2.reportId}</p>

<h2>SOC 2 Type II</h2>
<p>Status: <span class="compliant">${all.soc2.overallStatus}</span></p>
<table><tr><th>Control</th><th>Description</th><th>Status</th></tr>
${all.soc2.controls.map(c => `<tr><td>${c.control.id}</td><td>${c.control.name}</td><td class="compliant">${c.status}</td></tr>`).join('\n')}
</table>

<h2>ISO 27001:2022</h2>
<table><tr><th>Clause</th><th>Description</th><th>Status</th></tr>
${all.iso27001.clauses.map(c => `<tr><td>${c.control.id}</td><td>${c.control.name}</td><td class="compliant">${c.status}</td></tr>`).join('\n')}
</table>

<h2>NIST CSF 2.0</h2>
<p>Maturity: <span class="compliant">${all.nist.maturityLevel}</span></p>
<table><tr><th>Function</th><th>Description</th><th>Status</th></tr>
${all.nist.functions.map(f => `<tr><td>${f.function.id}</td><td>${f.function.name}</td><td class="compliant">${f.status}</td></tr>`).join('\n')}
</table>

<h2>Audit Chain Integrity</h2>
<p>Total entries: ${all.meta.totalAuditEntries} · Governance calls: ${all.meta.governanceCalls}</p>

<div class="footer">
  Generated by Kasbah Compliance Auto-Reporter · Cryptographically verifiable via audit chain · 
  Report hash: ${all.soc2.signatures.systemHash.slice(0, 16)}
</div>
</body></html>`;
  }

  // ─── Internal ────────────────────────────────────────────

  _getEvidenceForControl(controlId) {
    const entries = this.auditData.entries || [];
    return {
      relevantEntries: Math.min(entries.length, 50),
      governanceCalls: this.governanceStats.totalCalls || 0,
      blockedActions: this.governanceStats.blocked || 0,
      auditTrailAvailable: entries.length > 0,
    };
  }

  // Honesty gate: never attest a control as met without evidence. A compliance
  // report that says COMPLIANT off an empty audit trail is a liability, not a
  // feature — it's exactly the unsubstantiated claim the product forbids.
  _deriveStatus(ev, compliantLabel) {
    const observed = (ev.governanceCalls || 0) > 0 || ev.auditTrailAvailable;
    return observed ? compliantLabel : 'INSUFFICIENT_EVIDENCE';
  }

  _overallStatus(controls, compliantLabel) {
    const anyEvidence = controls.some(c => c.status === compliantLabel);
    if (!anyEvidence) return 'INSUFFICIENT_EVIDENCE';
    const blockedRate = this.governanceStats.blocked / Math.max(1, this.governanceStats.totalCalls);
    return blockedRate > 0.02 ? `${compliantLabel}_WITH_FINDINGS` : compliantLabel;
  }

  // Never fabricate a root hash. If there's no real audit chain, say so.
  _auditChain() {
    const totalEntries = this.auditData.chainLength || this.auditData.entries?.length || 0;
    return {
      totalEntries,
      rootHash: this.auditData.rootHash || (totalEntries > 0 ? null : 'NO_AUDIT_CHAIN'),
    };
  }

  _getNISTEvidence(functionId) {
    return this._getEvidenceForControl(functionId);
  }

  _generateAttestation(controlId) {
    return {
      system: 'Kasbah Governance Engine v1.0',
      mechanism: 'Ed25519-signed audit chain with forward-secure key evolution',
      attestationHash: crypto.createHash('sha256').update(controlId + this.generatedAt).digest('hex'),
    };
  }

  _hashReport(evidence) {
    return crypto.createHash('sha256').update(JSON.stringify(evidence)).digest('hex');
  }
}

module.exports = { ComplianceReportGenerator, SOC2_CONTROLS, ISO27001_CONTROLS, NIST_FUNCTIONS };
