"""Unit tests for the Automated Remediation Engine."""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.remediation_engine import remediation_engine, REMEDIATION_TEMPLATES


class TestRemediationTemplates:
    """Verify all vulnerability types have remediation templates."""
    
    EXPECTED_TYPES = [
        "UNENCRYPTED_PHI_STORAGE", "HARDCODED_SECRETS", "SQL_INJECTION_EHR",
        "PERMISSIVE_FHIR_SCOPE", "PHI_IN_LOGS", "UNENCRYPTED_TRANSMISSION",
        "CVE_LIBWEBP_VULNERABILITY", "INSECURE_IAC_K8S_EHR", "MISSING_AUDIT_LOG"
    ]
    
    def test_all_types_have_templates(self):
        for t in self.EXPECTED_TYPES:
            assert t in REMEDIATION_TEMPLATES, f"Missing template for {t}"
    
    def test_templates_have_required_fields(self):
        for name, tpl in REMEDIATION_TEMPLATES.items():
            assert "title" in tpl, f"{name} missing title"
            assert "description" in tpl, f"{name} missing description"
            assert "code_before" in tpl, f"{name} missing code_before"
            assert "code_after" in tpl, f"{name} missing code_after"
            assert "diff" in tpl, f"{name} missing diff"


class TestRemediationGeneration:
    """Verify remediation output for various finding types."""
    
    def test_generates_remediation_for_known_type(self):
        findings = [{"type": "UNENCRYPTED_PHI_STORAGE", "title": "Test", "file": "test.py", "line": 1}]
        result = remediation_engine.get_remediations_for_findings(findings)
        assert len(result) >= 1
        assert result[0]["remediation_generator"] == "Deterministic Healthcare Rulebase (Offline Guaranteed)"
    
    def test_cve_type_normalization(self):
        findings = [{"type": "CRITICAL_CVE_DEPENDENCY", "title": "CVE Test", "file": "req.txt", "line": 1}]
        result = remediation_engine.get_remediations_for_findings(findings)
        assert len(result) >= 1
    
    def test_unknown_type_no_crash(self):
        findings = [{"type": "TOTALLY_UNKNOWN_TYPE", "title": "Unknown", "file": "x.py", "line": 1}]
        result = remediation_engine.get_remediations_for_findings(findings)  # Should not crash
        # May return empty or matched result, but must not throw
    
    def test_deduplication(self):
        """Same finding type appearing twice should only produce one remediation."""
        findings = [
            {"type": "HARDCODED_SECRETS", "title": "Secret 1", "file": "a.py", "line": 1},
            {"type": "HARDCODED_SECRETS", "title": "Secret 2", "file": "b.py", "line": 5},
        ]
        result = remediation_engine.get_remediations_for_findings(findings)
        hardcoded_count = sum(1 for r in result if "HARDCODED" in r.get("finding_type", ""))
        assert hardcoded_count == 1
