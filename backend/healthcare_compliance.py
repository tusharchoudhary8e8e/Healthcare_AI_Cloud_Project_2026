"""
Healthcare Compliance Knowledge Engine
Maps security vulnerabilities and code patterns to HIPAA Security Rules, FDA SaMD Guidance, and HL7/FHIR Specifications.
"""
from typing import Dict, List, Any

HEALTHCARE_STANDARDS = {
    "HIPAA": {
        "164.312(a)(1)": {
            "title": "Access Control - Technical Safeguards",
            "requirement": "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to those persons or software programs that have been granted access rights.",
            "subclauses": {
                "encryption_at_rest": "Implement a mechanism to encrypt and decrypt electronic protected health information (ePHI) when stored at rest (AES-256).",
                "auto_logoff": "Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity.",
                "emergency_access": "Establish procedures for obtaining necessary ePHI during an emergency."
            },
            "severity_weight": 0.95
        },
        "164.312(b)": {
            "title": "Audit Controls",
            "requirement": "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information.",
            "subclauses": {
                "phi_access_logging": "All queries or modifications touching Patient, Condition, or Medication records must create immutable audit trails."
            },
            "severity_weight": 0.85
        },
        "164.312(c)(1)": {
            "title": "Integrity Controls",
            "requirement": "Implement policies and procedures to protect electronic protected health information from improper alteration or destruction.",
            "subclauses": {
                "data_validation": "Validate electronic protected health information to ensure it has not been altered or destroyed in an unauthorized manner."
            },
            "severity_weight": 0.90
        },
        "164.312(d)": {
            "title": "Person or Entity Authentication",
            "requirement": "Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed.",
            "subclauses": {
                "mfa_oauth": "Multi-factor authentication (MFA) and granular JWT/OAuth token verification for clinical endpoints."
            },
            "severity_weight": 0.92
        },
        "164.312(e)(1)": {
            "title": "Transmission Security",
            "requirement": "Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network.",
            "subclauses": {
                "tls_encryption": "Enforce TLS 1.3 or strong encryption algorithms for all external EHR, FHIR, and HL7 interfaces in transit."
            },
            "severity_weight": 0.98
        }
    },
    "FDA_SaMD": {
        "FDA-SaMD-4.1": {
            "title": "Threat Modeling & Risk Analysis",
            "requirement": "Medical device manufacturers must document threat modeling identifying safety hazards from software vulnerabilities.",
            "severity_weight": 0.88
        },
        "FDA-SaMD-4.2": {
            "title": "Cryptographic Protection & Key Management",
            "requirement": "Hardware or software-based cryptographic keys protecting medical telemetry must not be hardcoded or stored insecurely.",
            "severity_weight": 0.96
        },
        "FDA-SaMD-4.3": {
            "title": "Software Bill of Materials (SBOM) & Vulnerability Management",
            "requirement": "Maintain machine-readable SBOM and remediate all high/critical CVEs in open-source third-party dependencies.",
            "severity_weight": 0.91
        },
        "FDA-SaMD-4.4": {
            "title": "Tamper Resistance & Firmware Integrity",
            "requirement": "Ensure integrity of executable binaries and container base images with cryptographic verification.",
            "severity_weight": 0.89
        }
    },
    "HL7_FHIR": {
        "FHIR-SEC-1": {
            "title": "SMART on FHIR Authorization Scopes",
            "requirement": "FHIR REST endpoints must enforce SMART-on-FHIR OAuth 2.0 scopes (e.g. 'patient/*.read', 'user/Observation.write') preventing overprivileged access.",
            "severity_weight": 0.94
        },
        "FHIR-SEC-2": {
            "title": "Transport Security & Endpoint Hardening",
            "requirement": "All FHIR v4/v5 resource operations must reject unencrypted HTTP traffic and enforce strict CORS and HSTS headers.",
            "severity_weight": 0.93
        },
        "FHIR-SEC-3": {
            "title": "De-identification and PHI Sanitization",
            "requirement": "Data exported for analytics or logging must strip 18 HIPAA Safe Harbor identifiers (Names, MRNs, SSNs, Geocodes, Biometrics).",
            "severity_weight": 0.97
        }
    }
}

class HealthcareComplianceEngine:
    """Evaluates security scan findings against healthcare regulatory ontologies."""
    
    def evaluate_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        violations = []
        passed_controls = []
        hipaa_impact_score = 0.0
        fda_impact_score = 0.0
        fhir_impact_score = 0.0
        
        rule_mappings = {
            "UNENCRYPTED_PHI_STORAGE": [
                ("HIPAA", "164.312(a)(1)", "Plaintext PHI stored in persistent database/cache without AES-256 encryption"),
                ("FDA_SaMD", "FDA-SaMD-4.2", "Unprotected patient telemetry storage violates medical device cryptographic requirements")
            ],
            "UNENCRYPTED_TRANSMISSION": [
                ("HIPAA", "164.312(e)(1)", "ePHI transmitted over unencrypted protocol (Plain HTTP instead of TLS 1.3)"),
                ("HL7_FHIR", "FHIR-SEC-2", "FHIR API endpoint accepts unencrypted HTTP traffic")
            ],
            "HARDCODED_SECRETS": [
                ("HIPAA", "164.312(d)", "Hardcoded credentials bypass entity authentication safeguards"),
                ("FDA_SaMD", "FDA-SaMD-4.2", "Embedded cryptographic secrets / AWS keys in clinical application source code")
            ],
            "SQL_INJECTION_EHR": [
                ("HIPAA", "164.312(c)(1)", "SQL injection allows unauthorized tampering and exfiltration of EHR patient records"),
                ("HIPAA", "164.312(a)(1)", "Bypasses database role-based access control policies")
            ],
            "PERMISSIVE_FHIR_SCOPE": [
                ("HL7_FHIR", "FHIR-SEC-1", "Wildcard FHIR authorization scopes ('*.*') allow unauthorized clinical data read/write"),
                ("HIPAA", "164.312(a)(1)", "Violates HIPAA Minimum Necessary Rule for patient record access")
            ],
            "MISSING_AUDIT_LOG": [
                ("HIPAA", "164.312(b)", "Missing audit logging for PHI record retrieval and clinical modification"),
                ("FDA_SaMD", "FDA-SaMD-4.4", "Clinical application lacks tamper-evident audit logging for device operations")
            ],
            "CRITICAL_CVE_DEPENDENCY": [
                ("FDA_SaMD", "FDA-SaMD-4.3", "Vulnerable open-source package with RCE present in Medical Device SBOM"),
                ("HIPAA", "164.312(c)(1)", "Known software vulnerability compromises EHR system integrity")
            ],
            "PHI_IN_LOGS": [
                ("HIPAA", "164.312(a)(1)", "Raw patient identifiers (SSN, MRN, Patient Name) leaked into application logs"),
                ("HL7_FHIR", "FHIR-SEC-3", "Failure to de-identify health records in diagnostic log streams")
            ],
            "INSECURE_IAC_K8S_EHR": [
                ("HIPAA", "164.312(a)(1)", "Kubernetes container running as privileged root with access to clinical DB network"),
                ("FDA_SaMD", "FDA-SaMD-4.4", "Infrastructure configuration lacks container isolation controls")
            ]
        }
        
        flagged_rules = set()
        
        for finding in findings:
            ftype = finding.get("type", "")
            severity = finding.get("severity", "MEDIUM").upper()
            
            if ftype in rule_mappings:
                for std, code, reason in rule_mappings[ftype]:
                    std_info = HEALTHCARE_STANDARDS.get(std, {}).get(code, {})
                    rule_key = f"{std}:{code}"
                    
                    if rule_key not in flagged_rules:
                        flagged_rules.add(rule_key)
                        weight = std_info.get("severity_weight", 0.8)
                        
                        violation_entry = {
                            "standard": std,
                            "control_id": code,
                            "title": std_info.get("title", code),
                            "finding_ref": finding.get("title", ftype),
                            "reason": reason,
                            "statute_text": std_info.get("requirement", ""),
                            "weight": weight,
                            "severity": severity,
                            "file": finding.get("file", "unknown"),
                            "line": finding.get("line", 1)
                        }
                        violations.append(violation_entry)
                        
                        if std == "HIPAA":
                            hipaa_impact_score += weight * 22.0
                        elif std == "FDA_SaMD":
                            fda_impact_score += weight * 24.0
                        elif std == "HL7_FHIR":
                            fhir_impact_score += weight * 26.0
                            
        for std, controls in HEALTHCARE_STANDARDS.items():
            for code, data in controls.items():
                rule_key = f"{std}:{code}"
                if rule_key not in flagged_rules:
                    passed_controls.append({
                        "standard": std,
                        "control_id": code,
                        "title": data.get("title", code),
                        "status": "COMPLIANT"
                    })
                    
        total_violations = len(violations)
        compliance_status = "PASSED" if total_violations == 0 else ("FAIL_CRITICAL" if any(v["severity"] == "CRITICAL" for v in violations) else "WARNING_REVIEW")
        
        return {
            "compliance_status": compliance_status,
            "total_violations": total_violations,
            "violations": violations,
            "passed_controls": passed_controls,
            "scores": {
                "hipaa_risk_index": min(100.0, round(hipaa_impact_score, 1)),
                "fda_risk_index": min(100.0, round(fda_impact_score, 1)),
                "fhir_risk_index": min(100.0, round(fhir_impact_score, 1)),
                "overall_compliance_penalty": min(100.0, round((hipaa_impact_score + fda_impact_score + fhir_impact_score) / 2.2, 1))
            }
        }

healthcare_compliance_engine = HealthcareComplianceEngine()

