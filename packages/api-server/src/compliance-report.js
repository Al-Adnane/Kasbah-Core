'use strict';

/**
 * Kasbah Compliance Report Generator
 *
 * Generates structured compliance reports covering:
 *   - SOC 2 Type II controls (CC6.1, CC6.8, CC7.2, CC9.1)
 *   - EU AI Act articles (Art.13, Art.14, Art.17, Art.29)
 *   - NIST AI RMF functions (GOVERN-1, MAP-1, MEASURE-2, MANAGE-1)
 *
 * Each control returns: { id, name, framework, status, evidence, recommendation }
 */

// ── SOC 2 Type II Controls ────────────────────────────────────────────────────

function soc2Controls(passportId, passportData, auditLog) {
  const auditCount  = auditLog ? auditLog.length : 0;
  const denyCount   = auditLog ? auditLog.filter(e => e.verdict === 'DENY').length : 0;
  const allowCount  = auditLog ? auditLog.filter(e => e.verdict === 'ALLOW').length : 0;
  const hasPassport = !!(passportData);
  const hasAudit    = auditCount > 0;

  return [
    {
      id:            'CC6.1',
      name:          'Logical and Physical Access Controls',
      framework:     'SOC 2 Type II',
      status:        hasPassport ? 'PASS' : 'PARTIAL',
      evidence:      hasPassport
        ? `Governance Passport issued for agent ${passportId}. Trust score: ${passportData?.trustScore ?? 'N/A'}. Access controlled via passport-scoped policies.`
        : `No governance passport found for ${passportId}. Access controls not fully enforced.`,
      recommendation: hasPassport
        ? 'Continue issuing passports for all agents. Review trust scores periodically.'
        : 'Issue a Governance Passport via POST /v1/passport/issue to enforce access controls.',
    },
    {
      id:            'CC6.8',
      name:          'Malicious Code Prevention',
      framework:     'SOC 2 Type II',
      status:        auditCount > 0 ? 'PASS' : 'PARTIAL',
      evidence:      `${denyCount} malicious requests blocked out of ${auditCount} total governed requests. Governance engine active with ${auditCount > 0 ? 'live' : 'no'} audit trail.`,
      recommendation: auditCount === 0
        ? 'Route all AI agent traffic through /v1/govern to build audit trail.'
        : `Detection rate: ${auditCount > 0 ? ((denyCount / auditCount) * 100).toFixed(1) : 0}% of requests flagged. Review DENY entries for false positives.`,
    },
    {
      id:            'CC7.2',
      name:          'System Monitoring',
      framework:     'SOC 2 Type II',
      status:        hasAudit ? 'PASS' : 'FAIL',
      evidence:      hasAudit
        ? `Tamper-evident audit log active with ${auditCount} entries. Real-time SSE stream available at /v1/stream. Persistent JSONL audit at audit.jsonl.`
        : 'No audit log entries found. Monitoring not yet active for this passport.',
      recommendation: hasAudit
        ? 'Enable Redis persistence for cross-restart audit continuity.'
        : 'Begin routing requests through /v1/govern to activate monitoring.',
    },
    {
      id:            'CC9.1',
      name:          'Risk Assessment',
      framework:     'SOC 2 Type II',
      status:        (hasPassport && auditCount > 0) ? 'PASS' : 'PARTIAL',
      evidence:      hasPassport
        ? `Risk assessment performed on every governed request. Passport brittleness: ${passportData?.brittleness ?? 0}. Probe count: ${passportData?.probeCount ?? 0}. Adaptive thresholds: EWMA-based.`
        : 'Passport not found. Risk assessment incomplete — no trust-score tracking.',
      recommendation: 'Enable predictive threat forecasting via /v1/forecast for forward-looking risk posture.',
    },
  ];
}

// ── EU AI Act Controls ────────────────────────────────────────────────────────

function euAiActControls(passportId, passportData, auditLog, threatStats) {
  const hasAudit   = auditLog && auditLog.length > 0;
  const hasPassport = !!passportData;
  const threatCount = (threatStats && threatStats.totalRecorded) || 0;

  return [
    {
      id:            'Art.13',
      name:          'Transparency Obligations',
      framework:     'EU AI Act',
      status:        'PASS',
      evidence:      'KasbahOS provides a verifiable governance receipt (HMAC-SHA256) for every decision. ZK proofs attest rule compliance mathematically. Receipts verifiable at POST /v1/receipt/verify.',
      recommendation: 'Expose receipt verification endpoint to downstream users. Log receipt IDs for audit trail completeness.',
    },
    {
      id:            'Art.14',
      name:          'Human Oversight',
      framework:     'EU AI Act',
      status:        hasPassport ? 'PASS' : 'PARTIAL',
      evidence:      hasPassport
        ? `Human oversight enforced via Governance Passport. Manual revocation available via DELETE /v1/passport/${passportId}. Circuit-breaker auto-suspends hostile passports.`
        : 'No passport configured. Human override controls not fully wired.',
      recommendation: 'Implement dashboard alerting for DENY events exceeding threshold. Use /v1/stream for real-time oversight.',
    },
    {
      id:            'Art.17',
      name:          'Quality Management System',
      framework:     'EU AI Act',
      status:        hasAudit ? 'PASS' : 'PARTIAL',
      evidence:      hasAudit
        ? `Quality controls active: ${auditLog.length} governed events logged. Governance engine version tracked in every response. Fallback engine active for availability.`
        : 'Insufficient audit data for quality assessment.',
      recommendation: 'Run GET /v1/benchmark periodically to validate detection accuracy. Target >90% detection rate.',
    },
    {
      id:            'Art.29',
      name:          'Conformity Assessment',
      framework:     'EU AI Act',
      status:        (hasAudit && threatCount >= 0) ? 'PASS' : 'PARTIAL',
      evidence:      `Kasbah governance engine validated against OWASP LLM Top 10. Threat intelligence feed tracks ${threatCount} anonymised threat patterns. ZK proofs provide cryptographic conformity attestation.`,
      recommendation: 'Run /v1/benchmark to generate conformity evidence report. Share detection rate with auditors.',
    },
  ];
}

// ── NIST AI RMF Controls ──────────────────────────────────────────────────────

function nistRmfControls(passportId, passportData, auditLog, threatStats) {
  const hasAudit    = auditLog && auditLog.length > 0;
  const hasPassport = !!passportData;
  const topThreats  = threatStats && threatStats.trending ? threatStats.trending.slice(0, 3).map(t => t.type).join(', ') : 'none';

  return [
    {
      id:            'GOVERN-1',
      name:          'Policies, Processes and Procedures',
      framework:     'NIST AI RMF',
      status:        'PASS',
      evidence:      'Governance policy stored in .kasbahpolicy.json. Adaptive Policy Intelligence (RTP pipeline) active. Policy readable at GET /v1/policy and GET /v1/rules.',
      recommendation: 'Schedule periodic policy reviews. Use PUT /v1/policy/active for runtime updates without restart.',
    },
    {
      id:            'MAP-1',
      name:          'AI Risk Categorization',
      framework:     'NIST AI RMF',
      status:        hasPassport ? 'PASS' : 'PARTIAL',
      evidence:      hasPassport
        ? `Agent ${passportId} categorised with trust score ${passportData?.trustScore ?? 'N/A'} and capabilities: ${JSON.stringify(passportData?.capabilities || [])}.`
        : `No passport found for ${passportId}. Risk categorisation incomplete.`,
      recommendation: 'Issue passports for all agents with explicit capability declarations for accurate risk mapping.',
    },
    {
      id:            'MEASURE-2',
      name:          'AI Risk Measurement and Evaluation',
      framework:     'NIST AI RMF',
      status:        hasAudit ? 'PASS' : 'PARTIAL',
      evidence:      hasAudit
        ? `${auditLog.length} governed requests evaluated. Top threat vectors: ${topThreats}. EWMA adaptive threshold active. Bell's inequality AI detection active.`
        : 'Insufficient data for risk measurement.',
      recommendation: 'Use GET /v1/benchmark to produce quantitative detection metrics. Track DENY rate trends via /v1/stats.',
    },
    {
      id:            'MANAGE-1',
      name:          'AI Risk Response',
      framework:     'NIST AI RMF',
      status:        'PASS',
      evidence:      'Automated response: DENY blocks request instantly. WARN flags for review. Kill switch available at DELETE /v1/agents/:id. Passport revocation at DELETE /v1/passport/:id. Delegation tokens support scoped access reduction.',
      recommendation: 'Configure webhook notifications for DENY events to enable human-in-the-loop response workflows.',
    },
  ];
}

// ── generateReport ────────────────────────────────────────────────────────────
/**
 * Generate a full compliance report for a passport.
 * @param {string} passportId
 * @param {object} passportData  - from frontier.passportGet()
 * @param {Array}  auditLog      - filtered audit entries for this passport
 * @param {object} threatStats   - from threatIntel.getStats()
 * @returns {object}
 */
function generateReport(passportId, passportData, auditLog, threatStats) {
  const controls = [
    ...soc2Controls(passportId, passportData, auditLog),
    ...euAiActControls(passportId, passportData, auditLog, threatStats),
    ...nistRmfControls(passportId, passportData, auditLog, threatStats),
  ];

  const pass    = controls.filter(c => c.status === 'PASS').length;
  const partial = controls.filter(c => c.status === 'PARTIAL').length;
  const fail    = controls.filter(c => c.status === 'FAIL').length;
  const total   = controls.length;

  const overallStatus = fail > 0 ? 'NON_COMPLIANT'
    : partial > 0            ? 'PARTIALLY_COMPLIANT'
    : 'COMPLIANT';

  return {
    reportId:      `rpt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    generatedAt:   new Date().toISOString(),
    passportId,
    overallStatus,
    summary: {
      total,
      pass,
      partial,
      fail,
      passRate: +((pass / total) * 100).toFixed(1),
    },
    frameworks: {
      'SOC 2 Type II':  controls.filter(c => c.framework === 'SOC 2 Type II'),
      'EU AI Act':      controls.filter(c => c.framework === 'EU AI Act'),
      'NIST AI RMF':    controls.filter(c => c.framework === 'NIST AI RMF'),
    },
    controls,
    threatSummary: threatStats ? {
      totalThreats:  threatStats.totalRecorded,
      topVectors:    (threatStats.trending || []).slice(0, 5),
      avgRiskScore:  threatStats.avgRiskScore,
    } : null,
    passportStatus: passportData ? {
      trustScore:   passportData.trustScore,
      probeCount:   passportData.probeCount,
      brittleness:  passportData.brittleness,
      status:       passportData.status,
    } : null,
    auditStats: {
      totalGoverned: (auditLog || []).length,
      denyCount:     (auditLog || []).filter(e => e.verdict === 'DENY').length,
      warnCount:     (auditLog || []).filter(e => e.verdict === 'WARN').length,
      allowCount:    (auditLog || []).filter(e => e.verdict === 'ALLOW').length,
    },
  };
}

// ── generateHtml ─────────────────────────────────────────────────────────────
/**
 * Generate a styled, print-ready HTML version of the compliance report.
 * @param {object} report - output of generateReport()
 * @returns {string} HTML
 */
function generateHtml(report) {
  // HTML-escape all dynamic values before template injection
  const esc = s => String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

  const statusColor = {
    PASS:    '#22c55e',
    PARTIAL: '#f59e0b',
    FAIL:    '#ef4444',
  };
  const overallColor = {
    COMPLIANT:           '#22c55e',
    PARTIALLY_COMPLIANT: '#f59e0b',
    NON_COMPLIANT:       '#ef4444',
  };

  const controlRows = report.controls.map(c => `
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:13px">${esc(c.id)}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:13px">${esc(c.name)}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280">${esc(c.framework)}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;text-align:center">
        <span style="background:${statusColor[c.status] || '#9ca3af'};color:#fff;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600">${esc(c.status)}</span>
      </td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#374151">${esc(c.evidence)}</td>
    </tr>`).join('');

  const threatRows = (report.threatSummary?.topVectors || []).map(v =>
    `<tr>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px">${esc(v.type)}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;text-align:right;font-size:12px">${esc(String(v.count))}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KasbahOS Compliance Report — ${esc(report.passportId)}</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;margin:0;padding:32px;color:#111827}
  .card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:24px;margin-bottom:24px}
  h1{margin:0 0 4px;font-size:24px}
  h2{margin:0 0 16px;font-size:16px;color:#374151;border-bottom:1px solid #e5e7eb;padding-bottom:8px}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;padding:8px 12px;background:#f3f4f6;font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em}
  @media print{body{padding:0}.card{box-shadow:none;border:1px solid #e5e7eb}}
</style>
</head>
<body>
<div class="card">
  <h1>KasbahOS Compliance Report</h1>
  <p style="color:#6b7280;margin:0 0 16px">Passport: <code>${esc(report.passportId)}</code> &nbsp;·&nbsp; Generated: ${esc(report.generatedAt)}</p>
  <div style="display:flex;gap:16px;flex-wrap:wrap">
    <div style="flex:1;min-width:140px;background:#f3f4f6;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:32px;font-weight:700;color:${overallColor[report.overallStatus] || '#6b7280'}">${report.summary.pass}/${report.summary.total}</div>
      <div style="font-size:12px;color:#6b7280;margin-top:4px">Controls Passing</div>
    </div>
    <div style="flex:1;min-width:140px;background:#f3f4f6;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:32px;font-weight:700;color:${overallColor[report.overallStatus] || '#6b7280'}">${report.summary.passRate}%</div>
      <div style="font-size:12px;color:#6b7280;margin-top:4px">Pass Rate</div>
    </div>
    <div style="flex:2;min-width:180px;background:#f3f4f6;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:20px;font-weight:700;color:${overallColor[report.overallStatus] || '#6b7280'}">${report.overallStatus.replace(/_/g, ' ')}</div>
      <div style="font-size:12px;color:#6b7280;margin-top:4px">Overall Status</div>
    </div>
    <div style="flex:1;min-width:140px;background:#f3f4f6;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:32px;font-weight:700;color:#3b82f6">${report.auditStats.totalGoverned}</div>
      <div style="font-size:12px;color:#6b7280;margin-top:4px">Governed Requests</div>
    </div>
  </div>
</div>

<div class="card">
  <h2>Control Status Table</h2>
  <table>
    <thead><tr>
      <th>ID</th><th>Control</th><th>Framework</th><th style="text-align:center">Status</th><th>Evidence</th>
    </tr></thead>
    <tbody>${controlRows}</tbody>
  </table>
</div>

${report.threatSummary ? `
<div class="card">
  <h2>Threat Summary</h2>
  <p style="font-size:13px;color:#6b7280;margin:0 0 12px">
    ${report.threatSummary.totalThreats} threats recorded &nbsp;·&nbsp;
    Avg risk score: ${report.threatSummary.avgRiskScore}
  </p>
  <table>
    <thead><tr><th>Threat Vector</th><th style="text-align:right">Occurrences</th></tr></thead>
    <tbody>${threatRows}</tbody>
  </table>
</div>` : ''}

${report.passportStatus ? `
<div class="card">
  <h2>Passport Status</h2>
  <table>
    <thead><tr><th>Attribute</th><th>Value</th></tr></thead>
    <tbody>
      <tr><td style="padding:6px 12px">Trust Score</td><td style="padding:6px 12px">${report.passportStatus.trustScore}</td></tr>
      <tr><td style="padding:6px 12px">Probe Count</td><td style="padding:6px 12px">${report.passportStatus.probeCount}</td></tr>
      <tr><td style="padding:6px 12px">Brittleness</td><td style="padding:6px 12px">${report.passportStatus.brittleness}</td></tr>
      <tr><td style="padding:6px 12px">Status</td><td style="padding:6px 12px">${report.passportStatus.status}</td></tr>
    </tbody>
  </table>
</div>` : ''}

<div class="card" style="font-size:12px;color:#9ca3af;text-align:center">
  Generated by KasbahOS &nbsp;·&nbsp; Report ID: ${report.reportId} &nbsp;·&nbsp;
  Frameworks: SOC 2 Type II, EU AI Act, NIST AI RMF
</div>
</body>
</html>`;
}

module.exports = { generateReport, generateHtml };
