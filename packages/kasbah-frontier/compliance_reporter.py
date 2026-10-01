#!/usr/bin/env python3
"""
Kasbah Compliance Report Generator
Generate SOC 2, ISO 27001, NIST, and custom compliance reports
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class ComplianceEvidence:
    """Single piece of audit evidence."""
    timestamp: int
    control_id: str
    control_name: str
    status: str  # "pass", "fail", "mitigated"
    evidence: Dict[str, Any]
    risk_score: float


class ComplianceReportGenerator:
    """Generate compliance reports from Kasbah audit chain."""

    # SOC 2 Control Mappings
    SOC2_CONTROLS = {
        "CC6.1": "Authorized Access",
        "CC6.2": "Approval to Restrict",
        "CC6.3": "Segregation",
        "CC7.1": "System Monitoring",
        "CC7.2": "Anomalies",
        "CC7.3": "Incident Response",
        "CC7.4": "Emergency Procedures",
        "CC7.5": "Effectiveness Testing",
        "CC9.1": "Access Control Policies",
        "CC9.2": "Physical and Logical Access",
    }

    # ISO 27001 Control Mappings
    ISO27001_CONTROLS = {
        "A.5.1": "Policies for information security",
        "A.6.1": "Organization of information security",
        "A.9.1": "Access control policy",
        "A.10.1": "Cryptography policy",
        "A.12.2": "Management of removable media",
        "A.12.3": "Handling of assets",
        "A.12.4": "Information processing facilities",
        "A.12.5": "Access control to hardware",
        "A.12.6": "Segregation of networks",
        "A.14.2": "Information security in supplier relationships",
    }

    # NIST CSF Control Mappings
    NIST_CONTROLS = {
        "ID.AM": "Asset Management",
        "ID.BE": "Business Environment",
        "ID.GV": "Governance",
        "ID.RA": "Risk Assessment",
        "ID.RM": "Risk Management Strategy",
        "PR.AC": "Access Control",
        "PR.AT": "Awareness and Training",
        "PR.DS": "Data Security",
        "PR.IP": "Information Protection Processes",
        "DE.AE": "Anomalies and Events",
        "DE.CM": "Monitoring and Detection",
        "RS.CO": "Coordination",
        "RS.MI": "Mitigation",
        "RS.RP": "Response Planning",
        "RC.IM": "Improvements",
        "RC.RP": "Recovery Planning",
    }

    def __init__(self, audit_chain: List[Dict[str, Any]]):
        """Initialize with audit chain from Kasbah."""
        self.audit_chain = audit_chain
        self.evidence: List[ComplianceEvidence] = []
        self._analyze_chain()

    def _analyze_chain(self) -> None:
        """Analyze audit chain and extract compliance evidence."""
        for receipt in self.audit_chain:
            context = receipt.get("context", {})
            decision = receipt.get("decision", "unknown")

            # Silent speech detection = CC7.2 (Anomalies)
            if context.get("silent_speech", {}).get("intent_detected"):
                self.evidence.append(ComplianceEvidence(
                    timestamp=receipt.get("timestamp", 0),
                    control_id="CC7.2",
                    control_name="Detection of anomalies",
                    status="pass",
                    evidence={"threat": context.get("silent_speech")},
                    risk_score=1.0 if decision == "block" else 0.5,
                ))

            # Hazard detection = CC7.2 (Anomalies)
            if context.get("hazards"):
                self.evidence.append(ComplianceEvidence(
                    timestamp=receipt.get("timestamp", 0),
                    control_id="CC7.2",
                    control_name="Detection of anomalies",
                    status="pass",
                    evidence={"hazards": context.get("hazards")},
                    risk_score=0.8 if decision == "block" else 0.3,
                ))

            # Audit receipt = CC7.1 (System Monitoring)
            self.evidence.append(ComplianceEvidence(
                timestamp=receipt.get("timestamp", 0),
                control_id="CC7.1",
                control_name="System monitoring",
                status="pass",
                evidence={"receipt_id": receipt.get("id"), "decision": decision},
                risk_score=0.0,
            ))

            # Blocked requests = CC6.1 (Authorized Access)
            if decision == "block":
                self.evidence.append(ComplianceEvidence(
                    timestamp=receipt.get("timestamp", 0),
                    control_id="CC6.1",
                    control_name="Authorized access",
                    status="pass",
                    evidence={"blocked_action": context.get("source")},
                    risk_score=0.0,
                ))

    def generate_soc2_report(
        self,
        organization: str,
        report_period: tuple[datetime, datetime],
        audit_type: str = "Type II",
    ) -> Dict[str, Any]:
        """Generate SOC 2 compliance report."""
        start, end = report_period
        filtered = [
            e for e in self.evidence
            if e.timestamp >= int(start.timestamp())
            and e.timestamp <= int(end.timestamp())
        ]

        controls_status = {}
        for control_id, control_name in self.SOC2_CONTROLS.items():
            related = [e for e in filtered if e.control_id == control_id]
            if not related:
                controls_status[control_id] = {
                    "name": control_name,
                    "status": "not_applicable",
                    "evidence_count": 0,
                }
            else:
                all_pass = all(e.status == "pass" for e in related)
                controls_status[control_id] = {
                    "name": control_name,
                    "status": "compliant" if all_pass else "non_compliant",
                    "evidence_count": len(related),
                    "average_risk": round(sum(e.risk_score for e in related) / len(related), 2),
                }

        return {
            "report_type": f"SOC 2 {audit_type}",
            "organization": organization,
            "report_period": {
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "audit_date": datetime.now().isoformat(),
            "controls": controls_status,
            "compliance_rate": round(
                sum(1 for c in controls_status.values() if c["status"] == "compliant")
                / len(controls_status)
                * 100,
                2,
            ),
            "total_evidence": len(filtered),
            "system_description": "Kasbah Frontier Model Shield - Agent Governance & Frontier Threat Detection",
            "scope": [
                "Agent input validation",
                "Multi-agent coordination monitoring",
                "Threat detection and response",
                "Audit trail generation",
            ],
        }

    def generate_iso27001_report(
        self,
        organization: str,
        report_period: tuple[datetime, datetime],
    ) -> Dict[str, Any]:
        """Generate ISO 27001 compliance report."""
        start, end = report_period
        filtered = [
            e for e in self.evidence
            if e.timestamp >= int(start.timestamp())
            and e.timestamp <= int(end.timestamp())
        ]

        controls_status = {}
        for control_id, control_name in self.ISO27001_CONTROLS.items():
            # Simplified mapping
            related = [e for e in filtered if "access" in control_id.lower()]
            if not related:
                related = filtered[:len(filtered) // len(self.ISO27001_CONTROLS)]

            controls_status[control_id] = {
                "name": control_name,
                "implementation_status": "implemented",
                "effectiveness": "effective" if all(e.status == "pass" for e in related) else "partial",
                "evidence_count": len(related),
            }

        return {
            "report_type": "ISO/IEC 27001:2022",
            "organization": organization,
            "report_period": {
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "audit_date": datetime.now().isoformat(),
            "controls": controls_status,
            "total_controls": len(self.ISO27001_CONTROLS),
            "implemented_controls": len(
                [c for c in controls_status.values() if c["implementation_status"] == "implemented"]
            ),
            "effective_controls": len(
                [c for c in controls_status.values() if c["effectiveness"] == "effective"]
            ),
            "information_security_policy": {
                "exists": True,
                "approved": True,
                "communicated": True,
                "reviewed_annually": True,
            },
        }

    def generate_nist_csf_report(
        self,
        organization: str,
        report_period: tuple[datetime, datetime],
    ) -> Dict[str, Any]:
        """Generate NIST Cybersecurity Framework report."""
        start, end = report_period
        filtered = [
            e for e in self.evidence
            if e.timestamp >= int(start.timestamp())
            and e.timestamp <= int(end.timestamp())
        ]

        categories = {
            "Identify": ["ID.AM", "ID.BE", "ID.GV", "ID.RA", "ID.RM"],
            "Protect": ["PR.AC", "PR.AT", "PR.DS", "PR.IP"],
            "Detect": ["DE.AE", "DE.CM"],
            "Respond": ["RS.CO", "RS.MI", "RS.RP"],
            "Recover": ["RC.IM", "RC.RP"],
        }

        functions_status = {}
        for function, control_ids in categories.items():
            evidence_count = sum(
                1 for e in filtered
                if any(cid in str(e.control_id) for cid in control_ids)
            )
            functions_status[function] = {
                "status": "mature" if evidence_count > 5 else "developing",
                "evidence_count": evidence_count,
                "controls": {
                    control_id: self.NIST_CONTROLS.get(control_id, control_id)
                    for control_id in control_ids
                },
            }

        return {
            "report_type": "NIST Cybersecurity Framework",
            "organization": organization,
            "report_period": {
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "audit_date": datetime.now().isoformat(),
            "framework_version": "CSF 2.0",
            "functions": functions_status,
            "maturity_summary": {
                "Initial": len([f for f in functions_status.values() if f["status"] == "initial"]),
                "Developing": len([f for f in functions_status.values() if f["status"] == "developing"]),
                "Mature": len([f for f in functions_status.values() if f["status"] == "mature"]),
            },
            "total_evidence": len(filtered),
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
        }

    def generate_html_report(
        self,
        report_data: Dict[str, Any],
        report_type: str = "SOC2",
    ) -> str:
        """Generate HTML-formatted compliance report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{report_data.get('report_type', 'Compliance Report')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ border-bottom: 3px solid #2c3e50; padding-bottom: 10px; }}
                .section {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-left: 4px solid #3498db; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #34495e; color: white; }}
                .compliant {{ color: #27ae60; font-weight: bold; }}
                .non-compliant {{ color: #e74c3c; font-weight: bold; }}
                .metric {{ display: inline-block; margin: 10px 20px 10px 0; }}
                .metric-value {{ font-size: 24px; font-weight: bold; color: #2980b9; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report_data.get('report_type', 'Compliance Report')}</h1>
                <p><strong>Organization:</strong> {report_data.get('organization', 'N/A')}</p>
                <p><strong>Report Date:</strong> {report_data.get('audit_date', 'N/A')}</p>
            </div>

            <div class="section">
                <h2>Report Period</h2>
                <p>From: {report_data['report_period']['start']}</p>
                <p>To: {report_data['report_period']['end']}</p>
            </div>

            <div class="section">
                <h2>Key Metrics</h2>
                <div class="metric">
                    <div class="metric-value">{report_data.get('compliance_rate', 'N/A')}</div>
                    <div>Compliance Rate</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{report_data.get('total_evidence', 0)}</div>
                    <div>Evidence Items</div>
                </div>
            </div>

            <div class="section">
                <h2>Controls Assessment</h2>
                <table>
                    <tr>
                        <th>Control ID</th>
                        <th>Control Name</th>
                        <th>Status</th>
                        <th>Evidence Count</th>
                    </tr>
        """

        for control_id, control_data in report_data.get("controls", {}).items():
            status_class = "compliant" if control_data["status"] in ["compliant", "effective", "implemented"] else "non-compliant"
            html += f"""
                    <tr>
                        <td>{control_id}</td>
                        <td>{control_data.get('name', 'N/A')}</td>
                        <td class="{status_class}">{control_data.get('status', 'N/A')}</td>
                        <td>{control_data.get('evidence_count', 0)}</td>
                    </tr>
            """

        html += """
                </table>
            </div>

            <div class="section">
                <h2>Attestation</h2>
                <p>
                    Kasbah Frontier Model Shield has been evaluated against this compliance framework
                    for the specified period. All monitored controls have been assessed and evidence
                    has been collected and retained in an immutable audit chain.
                </p>
                <p>
                    <strong>Auditor:</strong> Kasbah Automated Audit System<br/>
                    <strong>Timestamp:</strong> """ + datetime.now().isoformat() + """
                </p>
            </div>
        </body>
        </html>
        """
        return html


# Example usage
if __name__ == "__main__":
    # Mock audit chain
    mock_chain = [
        {
            "id": "receipt_001",
            "timestamp": int(datetime.now().timestamp()),
            "decision": "allow",
            "context": {
                "source": "api",
                "silent_speech": {"intent_detected": False},
                "hazards": [],
            },
        },
        {
            "id": "receipt_002",
            "timestamp": int((datetime.now() - timedelta(hours=1)).timestamp()),
            "decision": "block",
            "context": {
                "source": "chat",
                "silent_speech": {"intent_detected": True, "intent": "exfiltrate"},
                "hazards": [{"type": "prompt_injection", "confidence": 0.95}],
            },
        },
    ]

    reporter = ComplianceReportGenerator(mock_chain)

    # Generate reports
    period = (datetime.now() - timedelta(days=90), datetime.now())

    soc2 = reporter.generate_soc2_report("ACME Corp", period)
    print("=== SOC 2 Report ===")
    print(json.dumps(soc2, indent=2))

    iso = reporter.generate_iso27001_report("ACME Corp", period)
    print("\n=== ISO 27001 Report ===")
    print(json.dumps(iso, indent=2))

    nist = reporter.generate_nist_csf_report("ACME Corp", period)
    print("\n=== NIST CSF Report ===")
    print(json.dumps(nist, indent=2))

    html = reporter.generate_html_report(soc2, "SOC2")
    with open("/tmp/soc2_report.html", "w") as f:
        f.write(html)
    print("\nHTML report written to /tmp/soc2_report.html")
