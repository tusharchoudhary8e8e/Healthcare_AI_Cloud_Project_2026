"""Unit tests for the Healthcare Compliance Engine."""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.healthcare_compliance import HealthcareComplianceEngine, HEALTHCARE_STANDARDS

engine = HealthcareComplianceEngine()


class TestComplianceMapping:
    """Verify findings map to correct regulatory standards."""
    
    def test_unencrypted_phi_maps_to_hipaa(self):
        findings = [{"type": "UNENCRYPTED_PHI_STORAGE", "severity": "CRITICAL"}]
        result = engine.evaluate_findings(findings)
        standards = [v["standard"] for v in result["violations"]]
        assert "HIPAA" in standards
    
    def test_permissive_fhir_maps_to_hl7(self):
        findings = [{"type": "PERMISSIVE_FHIR_SCOPE", "severity": "HIGH"}]
        result = engine.evaluate_findings(findings)
        standards = [v["standard"] for v in result["violations"]]
        assert "HL7_FHIR" in standards
    
    def test_cve_dependency_maps_to_fda(self):
        findings = [{"type": "CRITICAL_CVE_DEPENDENCY", "severity": "CRITICAL"}]
        result = engine.evaluate_findings(findings)
        standards = [v["standard"] for v in result["violations"]]
        assert "FDA_SaMD" in standards
    
    def test_clean_findings_pass(self):
        result = engine.evaluate_findings([])
        assert result["compliance_status"] == "PASSED"
        assert result["total_violations"] == 0
        assert len(result["passed_controls"]) == len(sum([list(c.keys()) for c in HEALTHCARE_STANDARDS.values()], []))
    
    def test_multiple_findings_aggregate(self):
        findings = [
            {"type": "UNENCRYPTED_PHI_STORAGE", "severity": "CRITICAL"},
            {"type": "HARDCODED_SECRETS", "severity": "CRITICAL"},
            {"type": "PHI_IN_LOGS", "severity": "HIGH"},
        ]
        result = engine.evaluate_findings(findings)
        assert result["total_violations"] >= 3
        assert result["compliance_status"] == "FAIL_CRITICAL"
        assert result["scores"]["overall_compliance_penalty"] > 0
