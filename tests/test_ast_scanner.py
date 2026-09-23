"""Unit tests for the Healthcare AST Taint-Flow Analyzer."""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanner_simulator import ScannerSimulator, HealthcareASTTaintAnalyzer

scanner = ScannerSimulator()

VULNERABLE_CODE = '''
import psycopg2, boto3

DB_PASS = "ClinicalPass2026!#"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

def store_patient_vitals(db, patient_id, ssn, mrn, heart_rate, bp):
    record = {"patient_id": patient_id, "ssn": ssn, "mrn": mrn, "vitals": heart_rate}
    db.collection("vitals").insert_one(record)
    
    query = f"INSERT INTO clinical_vitals VALUES ('{patient_id}', '{ssn}')"
    db.execute(query)
    
    print(f"Recorded vitals for SSN: {ssn}, MRN: {mrn}")
    return True
'''

HARDENED_CODE = '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import boto3

kms = boto3.client('kms', region_name='us-east-1')

def save_patient_record(db, patient_id, ssn, diagnosis, vitals):
    dek = kms.generate_data_key(KeyId='alias/healthcare-phi-key', KeySpec='AES_256')
    aesgcm = AESGCM(dek['Plaintext'])
    nonce = os.urandom(12)
    payload = f"{ssn}|{diagnosis}|{vitals}".encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, payload, patient_id.encode('utf-8'))
    
    db.collection("patients").insert_one({
        "patient_id": patient_id,
        "encrypted_data": ciphertext.hex(),
        "is_encrypted": True
    })
    return True
'''


class TestASTVulnerableCodeDetection:
    """Verify AST analyzer detects all vulnerability types in insecure code."""
    
    def setup_method(self):
        self.result = scanner.scan_custom_code("test_service.py", VULNERABLE_CODE, "EHR")
        self.findings = self.result["findings"]
        self.types = [f["type"] for f in self.findings]
    
    def test_ast_mode_active(self):
        assert self.result["ast_analysis_active"] is True
    
    def test_detects_hardcoded_secrets(self):
        assert "HARDCODED_SECRETS" in self.types
    
    def test_detects_unencrypted_phi_storage(self):
        assert "UNENCRYPTED_PHI_STORAGE" in self.types
    
    def test_detects_sql_injection(self):
        assert "SQL_INJECTION_EHR" in self.types
    
    def test_detects_phi_in_logs(self):
        assert "PHI_IN_LOGS" in self.types
    
    def test_minimum_findings_count(self):
        assert len(self.findings) >= 4, f"Expected >= 4 findings, got {len(self.findings)}"
    
    def test_all_findings_have_required_fields(self):
        for f in self.findings:
            assert "id" in f
            assert "source" in f
            assert "type" in f
            assert "severity" in f
            assert "file" in f


class TestASTHardenedCodeSuppression:
    """Verify AST analyzer produces zero findings for cryptographically hardened code."""
    
    def setup_method(self):
        self.result = scanner.scan_custom_code("hardened_service.py", HARDENED_CODE, "EHR")
        self.findings = self.result["findings"]
    
    def test_ast_mode_active(self):
        assert self.result["ast_analysis_active"] is True
    
    def test_zero_findings_for_hardened_code(self):
        assert len(self.findings) == 0, f"Expected 0 findings for hardened code, got {len(self.findings)}: {[f['type'] for f in self.findings]}"


class TestFallbackScanner:
    """Verify line-based fallback scanner works for non-Python code."""
    
    def test_non_python_triggers_fallback(self):
        non_python = 'function getPatient(ssn) { return db.find({ssn: ssn}); }'
        result = scanner.scan_custom_code("patient.js", non_python, "EHR")
        assert result["ast_analysis_active"] is False


class TestSCAScanner:
    """Verify SCA requirements.txt dependency scanning detects CVEs."""
    
    def test_detects_vulnerable_pillow(self):
        req_content = "pillow==9.4.0\nrequests==2.25.0\n"
        result = scanner.scan_custom_code("requirements.txt", req_content)
        assert result["scan_mode"] == "sca_requirements"
        findings = result["findings"]
        types = [f["type"] for f in findings]
        assert "CRITICAL_CVE_DEPENDENCY" in types
        assert any("CVE-2023-4863" in f["title"] for f in findings)

    def test_clean_requirements(self):
        req_content = "pillow>=10.0.1\nrequests>=2.31.0\n"
        result = scanner.scan_custom_code("requirements.txt", req_content)
        assert result["scan_mode"] == "sca_requirements"
        assert len(result["findings"]) == 0


class TestIaCScanner:
    """Verify IaC Dockerfile scanner detects root execution and sensitive ports."""
    
    def test_detects_root_and_sensitive_port(self):
        dockerfile = """FROM python:3.11-slim
USER root
EXPOSE 22
CMD ["python", "app.py"]
"""
        result = scanner.scan_custom_code("Dockerfile", dockerfile)
        assert result["scan_mode"] == "iac_dockerfile"
        findings = result["findings"]
        titles = [f["title"] for f in findings]
        assert any("root" in t.lower() for t in titles)
        assert any("22" in t for t in titles)

    def test_clean_dockerfile(self):
        dockerfile = """FROM python:3.11-slim
RUN useradd -u 10001 clinicaluser
USER 10001
HEALTHCHECK CMD curl -f http://localhost:8000/ || exit 1
EXPOSE 8000
"""
        result = scanner.scan_custom_code("Dockerfile", dockerfile)
        assert len(result["findings"]) == 0


class TestSemanticDataflowAndAsync:
    """Verify async functions, variable aliasing, format/% SQL injection, and fake sanitizer rejection."""
    
    def test_async_function_fhir_scope_detection(self):
        async_code = """
@app.get("/Observation")
async def get_obs(patient_id: str, scope: str = "*.*"):
    return query(patient_id)
"""
        res = scanner.scan_custom_code("fhir.py", async_code)
        assert any(f["type"] == "PERMISSIVE_FHIR_SCOPE" for f in res["findings"])

    def test_variable_alias_propagation(self):
        alias_code = """
def save(db, ssn):
    alias_var = ssn
    db.collection("patients").insert_one(alias_var)
"""
        res = scanner.scan_custom_code("alias.py", alias_code)
        assert any(f["type"] == "UNENCRYPTED_PHI_STORAGE" for f in res["findings"])

    def test_format_and_mod_sqli_detection(self):
        sqli_code = """
def query(db, ssn):
    q1 = "SELECT * FROM patients WHERE ssn = {}".format(ssn)
    q2 = "SELECT * FROM patients WHERE ssn = '%s'" % ssn
    db.execute(q1)
"""
        res = scanner.scan_custom_code("sqli.py", sqli_code)
        sqli_findings = [f for f in res["findings"] if f["type"] == "SQL_INJECTION_EHR"]
        assert len(sqli_findings) >= 2

    def test_fake_sanitizer_rejected(self):
        fake_code = """
def save(db, ssn):
    x = rehash_noop("unrelated")
    db.collection("patients").insert_one(ssn)
"""
        res = scanner.scan_custom_code("fake.py", fake_code)
        assert any(f["type"] == "UNENCRYPTED_PHI_STORAGE" for f in res["findings"])

