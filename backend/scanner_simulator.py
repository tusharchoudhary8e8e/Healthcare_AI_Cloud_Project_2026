"""
Multi-Source DevSecOps Scanner Simulator
Provides realistic healthcare scenarios and a dynamic code vulnerability parser.
"""
import ast
from typing import Dict, Any, List

HEALTHCARE_SCENARIOS = {
    "ehr-patient-portal": {
        "id": "ehr-patient-portal",
        "name": "EHR Patient Record Service (v2.4.1)",
        "service_type": "Hospital Electronic Health Record (EHR)",
        "repo": "github.com/hospital-tech/ehr-patient-service",
        "branch": "feature/direct-patient-export",
        "commit": "a8f3b9c",
        "author": "dev-clinical-team@hospital.org",
        "domain_risk_weight": 0.95,
        "raw_code": """# EHR Service Patient Storage Controller
import json, psycopg2

DB_USER = "ehr_admin"
DB_PASS = "ClinicalPass2026!#"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

def save_patient_record(db, patient_id, ssn, diagnosis, vitals):
    # Plaintext storage of ePHI
    record = {
        "patient_id": patient_id,
        "ssn": ssn,
        "diagnosis": diagnosis,
        "vitals": vitals
    }
    db.collection("patients").insert_one(record)
    return True

def query_patient_by_ssn(ssn):
    # Raw SQL query vulnerable to injection
    query = f"SELECT * FROM patient_records WHERE ssn = '{ssn}'"
    return db_cursor.execute(query)
""",
        "findings": [
            {
                "id": "F-001",
                "source": "SAST",
                "type": "UNENCRYPTED_PHI_STORAGE",
                "severity": "CRITICAL",
                "title": "Plaintext ePHI Storage in Database (No Encryption at Rest)",
                "file": "services/patient_service.py",
                "line": 10,
                "detail": "Patient SSN and clinical diagnosis stored without AES-256 envelope encryption."
            },
            {
                "id": "F-002",
                "source": "SAST",
                "type": "HARDCODED_SECRETS",
                "severity": "CRITICAL",
                "title": "Hardcoded Clinical Database Credentials & AWS Keys",
                "file": "config/database.py",
                "line": 4,
                "detail": "Hardcoded DB_PASS and AWS_SECRET_KEY embedded directly in source repository."
            },
            {
                "id": "F-003",
                "source": "SAST",
                "type": "SQL_INJECTION_EHR",
                "severity": "HIGH",
                "title": "SQL Injection in Patient Record Search Endpoint",
                "file": "api/patient_query.py",
                "line": 18,
                "detail": "Unescaped string formatting in SQL query allows full patient record dump."
            },
            {
                "id": "F-004",
                "source": "SAST",
                "type": "MISSING_AUDIT_LOG",
                "severity": "MEDIUM",
                "title": "Missing HIPAA ?164.312(b) Immutable Access Audit Trail",
                "file": "services/patient_service.py",
                "line": 8,
                "detail": "Patient record reads and writes are executed without dispatching audit log events."
            }
        ]
    },
    "smart-fhir-gateway": {
        "id": "smart-fhir-gateway",
        "name": "SMART-on-FHIR Telehealth API (v1.9.0)",
        "service_type": "Telehealth Interoperability Gateway",
        "repo": "github.com/hospital-tech/telehealth-fhir-gateway",
        "branch": "main",
        "commit": "3c7d91e",
        "author": "interop-team@hospital.org",
        "domain_risk_weight": 0.90,
        "raw_code": """# SMART on FHIR Observation API Gateway
import logging
logger = logging.getLogger("fhir-api")

@app.get("/fhir/r4/Patient/{id}/Observation")
async def get_observations(id: str, token_scope: str = "*.*"):
    # Over-permissive wildcard scope allows full access
    logger.info(f"Processing clinical order for patient: John Doe, SSN: 000-12-3456, MRN: 98765")
    return ehr_engine.query_observations(patient_id=id)

@app.post("/fhir/r4/Patient")
def create_patient_http(payload: dict):
    # Plain HTTP transmission without TLS
    http_endpoint = "http://api.internal.hospital.org/fhir/create"
    return requests.post(http_endpoint, json=payload)
""",
        "findings": [
            {
                "id": "F-101",
                "source": "SAST",
                "type": "PERMISSIVE_FHIR_SCOPE",
                "severity": "CRITICAL",
                "title": "Wildcard OAuth Scope (*.*) Enabled on FHIR REST Endpoint",
                "file": "api/fhir_endpoints.py",
                "line": 5,
                "detail": "SMART on FHIR endpoint does not enforce granular 'patient/Observation.read' scopes."
            },
            {
                "id": "F-102",
                "source": "SAST",
                "type": "PHI_IN_LOGS",
                "severity": "HIGH",
                "title": "Unmasked Patient SSN and MRN Leaked in Application Logger",
                "file": "api/fhir_endpoints.py",
                "line": 7,
                "detail": "Raw patient identifiers logged into standard console streams violating HIPAA Safe Harbor."
            },
            {
                "id": "F-103",
                "source": "DAST",
                "type": "UNENCRYPTED_TRANSMISSION",
                "severity": "CRITICAL",
                "title": "ePHI Transmitted Over Insecure Plain HTTP Protocol",
                "file": "api/fhir_endpoints.py",
                "line": 13,
                "detail": "FHIR resource payload dispatched over unencrypted HTTP endpoint without TLS 1.3."
            }
        ]
    },
    "samd-imaging-worker": {
        "id": "samd-imaging-worker",
        "name": "Medical Device SaMD DICOM Processing Pod (v3.1.0)",
        "service_type": "Software as Medical Device (FDA Class II)",
        "repo": "github.com/hospital-tech/samd-dicom-worker",
        "branch": "release/510k-candidate",
        "commit": "e5b801a",
        "author": "med-device-team@hospital.org",
        "domain_risk_weight": 0.98,
        "raw_code": """# Dockerfile & DICOM Worker for Medical Imaging
# Insecure Container running as root
FROM python:3.11-slim
USER root
COPY requirements.txt .
# Vulnerable package: libwebp CVE-2023-4863 (CVSS 8.8)
RUN pip install pillow==9.5.0 pydicom==2.3.0
COPY . /app
WORKDIR /app
CMD ["python", "process_dicom_scan.py"]
""",
        "findings": [
            {
                "id": "F-201",
                "source": "SCA",
                "type": "CRITICAL_CVE_DEPENDENCY",
                "severity": "CRITICAL",
                "cvss": 8.8,
                "title": "CVE-2023-4863: Critical Heap Buffer Overflow in Image Processing Dependency",
                "file": "requirements.txt",
                "line": 6,
                "detail": "Vulnerable third-party image decoding library allows remote arbitrary code execution in SaMD pod."
            },
            {
                "id": "F-202",
                "source": "IaC",
                "type": "INSECURE_IAC_K8S_EHR",
                "severity": "HIGH",
                "title": "Container Running as Root in Clinical Kubernetes Cluster",
                "file": "Dockerfile",
                "line": 3,
                "detail": "Medical device processing container lacks non-root user isolation and drop capabilities."
            }
        ]
    },
    "hardened-hospital-microservice": {
        "id": "hardened-hospital-microservice",
        "name": "Hardened Clinical Telemetry API (v4.0.0)",
        "service_type": "HIPAA & FDA Hardened Microservice",
        "repo": "github.com/hospital-tech/hardened-clinical-api",
        "branch": "main",
        "commit": "90fe2b1",
        "author": "secops-lead@hospital.org",
        "domain_risk_weight": 0.85,
        "raw_code": """# Fully Hardened HIPAA & FDA Compliant Clinical Service
import boto3, os, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Security, HTTPException

kms = boto3.client('kms', region_name='us-east-1')

def save_patient_record(db, patient_id, ssn, diagnosis, vitals):
    # Envelope encryption using AWS KMS & AES-256-GCM
    dek = kms.generate_data_key(KeyId='alias/healthcare-phi-key', KeySpec='AES_256')
    aesgcm = AESGCM(dek['Plaintext'])
    nonce = os.urandom(12)
    payload = f"{ssn}|{diagnosis}|{vitals}".encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, payload, patient_id.encode('utf-8'))
    
    db.collection("patients").insert_one({
        "patient_id": patient_id,
        "encrypted_data": ciphertext.hex(),
        "nonce": nonce.hex(),
        "kms_key_blob": dek['CiphertextBlob'].hex(),
        "is_encrypted": True
    })
    return True
""",
        "findings": []  # Clean baseline!
    }
}

EPHI_SOURCE_NAMES = {
    "ssn", "mrn", "diagnosis", "vitals", "patient_id", "patient_name", 
    "dob", "ephi", "clinical_notes", "prescription", "heart_rate", "blood_pressure"
}

SECRET_KEYWORDS = {"secret", "password", "db_pass", "api_key", "token", "aws_secret", "aws_key", "private_key"}

# Known vulnerable packages for SCA scanning (from NVD feeds)
KNOWN_VULNERABLE_PACKAGES = {
    "pillow": {"cve": "CVE-2023-4863", "cvss": 8.8, "fixed_version": "10.0.1", "detail": "Heap buffer overflow in libwebp via malformed WebP image (RCE)"},
    "flask": {"cve": "CVE-2023-30861", "cvss": 7.5, "fixed_version": "2.3.2", "detail": "Cookie session data exposure via caching proxy"},
    "cryptography": {"cve": "CVE-2023-49083", "cvss": 7.5, "fixed_version": "41.0.6", "detail": "NULL pointer dereference in PKCS12 key parsing"},
    "requests": {"cve": "CVE-2023-32681", "cvss": 6.1, "fixed_version": "2.31.0", "detail": "Proxy-Authorization header leakage on HTTPS redirects"},
    "pydicom": {"cve": "CVE-2023-45811", "cvss": 7.5, "fixed_version": "2.4.3", "detail": "Path traversal in DICOM file decompression"},
    "numpy": {"cve": "CVE-2021-33430", "cvss": 5.3, "fixed_version": "1.22.0", "detail": "Buffer overflow in array reshaping operations"},
    "django": {"cve": "CVE-2024-27351", "cvss": 7.5, "fixed_version": "4.2.11", "detail": "ReDoS in truncatewords_html template filter"},
    "paramiko": {"cve": "CVE-2023-48795", "cvss": 5.9, "fixed_version": "3.4.0", "detail": "Terrapin SSH prefix truncation attack"},
}

class HealthcareASTTaintAnalyzer(ast.NodeVisitor):
    """
    Abstract Syntax Tree (AST) Taint-Flow Analysis Engine for Healthcare Software.
    Tracks data-flow from designated ePHI sources (parameters, clinical models) to insecure sinks:
    - SINK-1: Unencrypted persistence (db.collection.insert_one)
    - SINK-2: Injection into dynamic SQL formatting (f-string, %, .format)
    - SINK-3: Leakage into unmasked telemetry/logging sinks
    - SINK-4: Hardcoded clinical database/cloud credentials
    - SINK-5: Unencrypted HTTP cleartext transmission
    - SINK-6: Over-permissive SMART-on-FHIR OAuth authorization scopes
    """
    def __init__(self, filename: str = "clinical_service.py"):
        self.filename = filename
        self.tainted_vars = set()
        self.tainted_containers = {}  # dict_var -> set of tainted field names
        self.sanitized_vars = set()   # variables produced by cryptographic operations
        self.findings = []
        self._finding_count = 0

    def _next_id(self, prefix: str = "AST") -> str:
        self._finding_count += 1
        return f"{prefix}-{self._finding_count:03d}"

    def _is_ephi_term(self, name: str) -> bool:
        lower = name.lower()
        return any(term in lower for term in EPHI_SOURCE_NAMES)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # 1. Parameter ePHI Source Identification
        for arg in node.args.args:
            if self._is_ephi_term(arg.arg):
                self.tainted_vars.add(arg.arg)
                
        # 2. Check for Permissive FHIR scopes in decorators or default args
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call):
                for keyword in dec.keywords:
                    if keyword.arg in ["scope", "scopes"]:
                        if isinstance(keyword.value, ast.Constant) and "*.*" in str(keyword.value.value):
                            self.findings.append({
                                "id": self._next_id("AST-AUTH"),
                                "source": "SAST",
                                "type": "PERMISSIVE_FHIR_SCOPE",
                                "severity": "HIGH",
                                "title": f"Wildcard SMART-on-FHIR OAuth Scope in Route Decorator (Line {dec.lineno})",
                                "file": self.filename,
                                "line": dec.lineno,
                                "detail": f"Route decorator specifies wildcard scope '{keyword.value.value}', violating HIPAA least privilege."
                            })
                            
        for default in node.args.defaults:
            if isinstance(default, ast.Constant) and isinstance(default.value, str):
                if "*.*" in default.value or default.value == "*":
                    self.findings.append({
                        "id": self._next_id("AST-AUTH"),
                        "source": "SAST",
                        "type": "PERMISSIVE_FHIR_SCOPE",
                        "severity": "HIGH",
                        "title": f"Wildcard OAuth Scope (*.*) Enabled as Default Parameter (Line {node.lineno})",
                        "file": self.filename,
                        "line": node.lineno,
                        "detail": f"Function '{node.name}' permits unrestricted wildcard FHIR scope by default."
                    })
                    
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # 1. Hardcoded Secrets Detection
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_name = target.id.lower()
                if any(sec in target_name for sec in SECRET_KEYWORDS):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        secret_val = node.value.value
                        if len(secret_val) > 3 and not secret_val.startswith("os.getenv"):
                            self.findings.append({
                                "id": self._next_id("AST-SEC"),
                                "source": "SAST",
                                "type": "HARDCODED_SECRETS",
                                "severity": "CRITICAL",
                                "title": f"Hardcoded Clinical Secret in AST Assignment: '{target.id}' (Line {node.lineno})",
                                "file": self.filename,
                                "line": node.lineno,
                                "detail": f"Credential variable '{target.id}' assigned static string literal directly in source code."
                            })

        # 2. Cryptographic Sanitation Tracking (e.g. ciphertext = aesgcm.encrypt(...))
        if isinstance(node.value, ast.Call):
            func_name = getattr(node.value.func, "attr", getattr(node.value.func, "id", ""))
            if any(c in func_name.lower() for c in ["encrypt", "aesgcm", "kms", "hash", "sha256", "mask"]):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.sanitized_vars.add(target.id)

        # 3. Taint Propagation via Dictionaries (e.g. record = {"ssn": ssn, ...})
        if isinstance(node.value, ast.Dict):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    dict_name = target.id
                    tainted_keys = set()
                    for k, v in zip(node.value.keys, node.value.values):
                        k_str = k.value if isinstance(k, ast.Constant) else ""
                        is_val_tainted = False
                        if isinstance(v, ast.Name) and v.id in self.tainted_vars and v.id not in self.sanitized_vars:
                            is_val_tainted = True
                        elif self._is_ephi_term(str(k_str)):
                            if isinstance(v, ast.Name) and v.id in self.sanitized_vars:
                                is_val_tainted = False
                            else:
                                is_val_tainted = True
                        if is_val_tainted:
                            tainted_keys.add(str(k_str))
                    if tainted_keys:
                        self.tainted_containers[dict_name] = tainted_keys
                        self.tainted_vars.add(dict_name)

        # 4. Taint Propagation via Formatted Strings (f-string) and SQL Injection Sink
        if isinstance(node.value, ast.JoinedStr):
            fstring_tainted = False
            for part in node.value.values:
                if isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name):
                    if part.value.id in self.tainted_vars or self._is_ephi_term(part.value.id):
                        fstring_tainted = True
            
            raw_text = "".join([p.value for p in node.value.values if isinstance(p, ast.Constant)]).upper()
            is_sql = any(kw in raw_text for kw in ["SELECT ", "INSERT ", "UPDATE ", "DELETE ", "FROM "])
            
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if fstring_tainted:
                        self.tainted_vars.add(target.id)
                    if is_sql and fstring_tainted:
                        self.findings.append({
                            "id": self._next_id("AST-SQLI"),
                            "source": "SAST",
                            "type": "SQL_INJECTION_EHR",
                            "severity": "CRITICAL",
                            "title": f"AST Taint Flow: ePHI Variable Interpolated Into SQL Query String (Line {node.lineno})",
                            "file": self.filename,
                            "line": node.lineno,
                            "detail": f"Unescaped ePHI taint flows directly into dynamic SQL query assigned to '{target.id}'."
                        })

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = getattr(node.func, "attr", getattr(node.func, "id", ""))
        
        # 1. Plaintext Storage Sink Detection (e.g., db.collection.insert_one(record))
        if func_name in ["insert_one", "insert", "save", "save_record", "put_item", "insert_many"]:
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    if (arg.id in self.tainted_containers or arg.id in self.tainted_vars) and arg.id not in self.sanitized_vars:
                        tainted_fields = ", ".join(self.tainted_containers.get(arg.id, [arg.id]))
                        self.findings.append({
                            "id": self._next_id("AST-PHI"),
                            "source": "SAST",
                            "type": "UNENCRYPTED_PHI_STORAGE",
                            "severity": "CRITICAL",
                            "title": f"ePHI Taint Propagation to Plaintext Storage Sink: '{func_name}' (Line {node.lineno})",
                            "file": self.filename,
                            "line": node.lineno,
                            "detail": f"Object '{arg.id}' carrying unencrypted ePHI [{tainted_fields}] persists to database without cryptographic envelope."
                        })

        # 2. Insecure Network Transmission Sink (e.g. requests.post("http://..."))
        if func_name in ["post", "get", "put", "delete", "request"]:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith("http://") and "localhost" not in arg.value and "127.0.0.1" not in arg.value:
                        self.findings.append({
                            "id": self._next_id("AST-NET"),
                            "source": "DAST",
                            "type": "UNENCRYPTED_TRANSMISSION",
                            "severity": "CRITICAL",
                            "title": f"Cleartext ePHI Transport Sink: Insecure HTTP Protocol Detected (Line {node.lineno})",
                            "file": self.filename,
                            "line": node.lineno,
                            "detail": f"Network transmission call '{func_name}' initiates plaintext HTTP connection to: {arg.value}"
                        })

        # 3. ePHI Leakage into Logging/Telemetry Sink
        if func_name in ["info", "debug", "warning", "error", "critical", "print"]:
            call_tainted = False
            for arg in node.args:
                if isinstance(arg, ast.Name) and (arg.id in self.tainted_vars or self._is_ephi_term(arg.id)):
                    call_tainted = True
                elif isinstance(arg, ast.JoinedStr):
                    for part in arg.values:
                        if isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name):
                            if part.value.id in self.tainted_vars or self._is_ephi_term(part.value.id):
                                call_tainted = True
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if any(term in arg.value.lower() for term in ["ssn:", "mrn:", "patient:", "diagnosis:"]):
                        call_tainted = True
            if call_tainted:
                self.findings.append({
                    "id": self._next_id("AST-LOG"),
                    "source": "SAST",
                    "type": "PHI_IN_LOGS",
                    "severity": "HIGH",
                    "title": f"AST Taint Sink: Identifiable ePHI Dispatched to Application Logger (Line {node.lineno})",
                    "file": self.filename,
                    "line": node.lineno,
                    "detail": f"Logging/telemetry sink '{func_name}' serializes unmasked clinical identifiers into system logs."
                })

        self.generic_visit(node)


class ScannerSimulator:
    def _scan_requirements_sca(self, filename: str, content: str) -> list:
        """SCA scanner: checks pip dependencies against known CVE database."""
        findings = []
        import re as _re
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Parse package==version or package>=version or just package
            match = _re.match(r'^([a-zA-Z0-9_.-]+)\s*([=<>!~]+)?\s*([\d.]*)', line)
            if match:
                pkg_name = match.group(1).lower().replace("-", "").replace("_", "")
                pkg_version = match.group(3) or "0.0.0"
                # Check against known vulnerable packages
                for known_pkg, vuln_info in KNOWN_VULNERABLE_PACKAGES.items():
                    if known_pkg.replace("-", "").replace("_", "") == pkg_name:
                        # Simple version check (vulnerable if < fixed_version)
                        try:
                            installed = tuple(int(x) for x in pkg_version.split(".")[:3])
                            fixed = tuple(int(x) for x in vuln_info["fixed_version"].split(".")[:3])
                            if installed < fixed:
                                findings.append({
                                    "id": f"SCA-{len(findings)+1:03d}",
                                    "source": "SCA",
                                    "type": "CRITICAL_CVE_DEPENDENCY",
                                    "severity": "CRITICAL" if vuln_info["cvss"] >= 7.0 else "HIGH",
                                    "cvss": vuln_info["cvss"],
                                    "title": f"{vuln_info['cve']}: {known_pkg} {pkg_version} < {vuln_info['fixed_version']} ({vuln_info['detail'][:80]})",
                                    "file": filename,
                                    "line": content.splitlines().index(line) + 1 if line in content.splitlines() else 1,
                                    "detail": f"Package '{known_pkg}=={pkg_version}' has known vulnerability {vuln_info['cve']} (CVSS {vuln_info['cvss']}). Upgrade to >= {vuln_info['fixed_version']}."
                                })
                        except (ValueError, IndexError):
                            pass
        return findings

    def _scan_dockerfile_iac(self, filename: str, content: str) -> list:
        """IaC scanner: checks Dockerfiles for container security misconfigurations."""
        findings = []
        lines = content.splitlines()
        has_user_directive = False
        has_healthcheck = False
        
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            upper = stripped.upper()
            
            # Check for USER directive (non-root)
            if upper.startswith("USER "):
                user_val = stripped[5:].strip()
                if user_val.lower() not in ["root", "0"]:
                    has_user_directive = True
                    
            # Check for HEALTHCHECK
            if upper.startswith("HEALTHCHECK"):
                has_healthcheck = True
                
            # Detect USER root explicitly
            if upper.startswith("USER ") and stripped[5:].strip().lower() in ["root", "0"]:
                findings.append({
                    "id": f"IAC-{len(findings)+1:03d}",
                    "source": "IaC",
                    "type": "INSECURE_IAC_K8S_EHR",
                    "severity": "HIGH",
                    "title": f"Container running as root user (Line {idx})",
                    "file": filename,
                    "line": idx,
                    "detail": "Clinical container must run as non-root user for FDA SaMD isolation requirements."
                })
                
            # Detect exposed sensitive ports
            if upper.startswith("EXPOSE"):
                ports = stripped[6:].strip().split()
                for p in ports:
                    p_num = p.split("/")[0]
                    if p_num in ["22", "3306", "5432", "27017", "6379"]:
                        findings.append({
                            "id": f"IAC-{len(findings)+1:03d}",
                            "source": "IaC",
                            "type": "INSECURE_IAC_K8S_EHR",
                            "severity": "HIGH",
                            "title": f"Sensitive port {p_num} exposed in clinical container (Line {idx})",
                            "file": filename,
                            "line": idx,
                            "detail": f"Port {p_num} should not be directly exposed in a healthcare container image."
                        })
            
            # Detect vulnerable pip installs
            if "pip install" in stripped.lower():
                for known_pkg, vuln_info in KNOWN_VULNERABLE_PACKAGES.items():
                    if known_pkg in stripped.lower():
                        findings.append({
                            "id": f"IAC-SCA-{len(findings)+1:03d}",
                            "source": "SCA",
                            "type": "CRITICAL_CVE_DEPENDENCY",
                            "severity": "CRITICAL" if vuln_info["cvss"] >= 7.0 else "HIGH",
                            "cvss": vuln_info["cvss"],
                            "title": f"{vuln_info['cve']}: {known_pkg} in Dockerfile pip install (CVSS {vuln_info['cvss']})",
                            "file": filename,
                            "line": idx,
                            "detail": vuln_info["detail"]
                        })

        # Missing USER directive entirely
        if not has_user_directive and any(l.strip().upper().startswith("FROM") for l in lines):
            findings.append({
                "id": f"IAC-{len(findings)+1:03d}",
                "source": "IaC",
                "type": "INSECURE_IAC_K8S_EHR",
                "severity": "HIGH",
                "title": "No non-root USER directive in Dockerfile",
                "file": filename,
                "line": 1,
                "detail": "Container defaults to root. Add 'USER <non-root>' for FDA SaMD container isolation."
            })
            
        return findings

    def scan_custom_code(self, filename: str, code_content: str, domain_type: str = "EHR") -> Dict[str, Any]:
        findings = []
        ast_success = False
        scan_mode = "python_ast"

        # Auto-detect file type for multi-modal ingestion
        fname_lower = filename.lower()
        if fname_lower.endswith(".txt") or "requirements" in fname_lower or "pipfile" in fname_lower:
            scan_mode = "sca_requirements"
            findings = self._scan_requirements_sca(filename, code_content)
            ast_success = True  # SCA mode doesn't need AST
        elif fname_lower.startswith("dockerfile") or fname_lower.endswith(".dockerfile"):
            scan_mode = "iac_dockerfile"
            findings = self._scan_dockerfile_iac(filename, code_content)
            ast_success = True  # IaC mode doesn't need AST
        else:
            # Python AST taint analysis (existing logic)
            try:
                tree = ast.parse(code_content)
                analyzer = HealthcareASTTaintAnalyzer(filename=filename)
                analyzer.visit(tree)
                findings = analyzer.findings
                ast_success = True
            except SyntaxError:
                # Fallback for non-python or partial code snippets
                ast_success = False

        # If non-Python or partial code snippet failed AST, use line scanner fallback
        if not ast_success:
            lines = code_content.splitlines()
            for idx, line in enumerate(lines, 1):
                lower_line = line.lower()
                
                # 1. Plaintext PHI detection
                if any(term in lower_line for term in ["ssn", "diagnosis", "mrn", "vitals", "patient_name"]):
                    if any(op in line for op in ["=", ":", "insert", "save", "record"]):
                        if not any(enc in lower_line for enc in ["aes", "encrypt", "hash", "cipher", "dek", "mask", "kms"]):
                            findings.append({
                                "id": f"DYN-{len(findings)+1}",
                                "source": "SAST",
                                "type": "UNENCRYPTED_PHI_STORAGE",
                                "severity": "CRITICAL",
                                "title": f"Plaintext ePHI assignment/storage detected at line {idx}",
                                "file": filename,
                                "line": idx,
                                "detail": line.strip()
                            })
                        
                # 2. Hardcoded Secrets
                if any(sec in lower_line for sec in ["password", "secret", "api_key", "aws_secret_key", "db_pass"]):
                    if "=" in line and ("'" in line or '"' in line):
                        findings.append({
                            "id": f"DYN-{len(findings)+1}",
                            "source": "SAST",
                            "type": "HARDCODED_SECRETS",
                            "severity": "CRITICAL",
                            "title": f"Hardcoded credential or API secret exposed at line {idx}",
                            "file": filename,
                            "line": idx,
                            "detail": line.strip()
                        })
                    
                # 3. SQL Injection in EHR
                if any(sql in lower_line for sql in ["select ", "insert ", "update ", "delete "]):
                    is_formatted = ("{" in line and "}" in line) or ("+" in line) or ("%s" not in line and "%" in line)
                    if is_formatted and any(v in lower_line for v in ["ssn", "patient", "mrn", "query"]):
                        findings.append({
                            "id": f"DYN-{len(findings)+1}",
                            "source": "SAST",
                            "type": "SQL_INJECTION_EHR",
                            "severity": "HIGH",
                            "title": f"Potential SQL Injection in clinical database query at line {idx}",
                            "file": filename,
                            "line": idx,
                            "detail": line.strip()
                        })
                    
                # 4. Insecure HTTP endpoint
                if "http://" in lower_line and "localhost" not in lower_line and "127.0.0.1" not in lower_line:
                    findings.append({
                        "id": f"DYN-{len(findings)+1}",
                        "source": "DAST",
                        "type": "UNENCRYPTED_TRANSMISSION",
                        "severity": "CRITICAL",
                        "title": f"Unencrypted HTTP URL (Non-TLS 1.3) detected at line {idx}",
                        "file": filename,
                        "line": idx,
                        "detail": line.strip()
                    })
                    
                # 5. Permissive FHIR Scopes
                if "*.*" in line or 'scopes=["*"]' in line or "scopes=['*']" in line:
                    findings.append({
                        "id": f"DYN-{len(findings)+1}",
                        "source": "SAST",
                        "type": "PERMISSIVE_FHIR_SCOPE",
                        "severity": "HIGH",
                        "title": f"Wildcard SMART-on-FHIR authorization scope at line {idx}",
                        "file": filename,
                        "line": idx,
                        "detail": line.strip()
                    })
                    
                # 6. PHI in Logger
                if any(log in lower_line for log in ["logger.", "print(", "logging."]) and any(p in lower_line for p in ["ssn", "patient", "mrn"]):
                    if not any(safe in lower_line for safe in ["mask", "hash", "sha256", "***"]):
                        findings.append({
                            "id": f"DYN-{len(findings)+1}",
                            "source": "SAST",
                            "type": "PHI_IN_LOGS",
                            "severity": "HIGH",
                            "title": f"Unsanitized ePHI identifiers in application logging statement at line {idx}",
                            "file": filename,
                            "line": idx,
                            "detail": line.strip()
                        })
                    
        return {
            "id": "custom-scan",
            "name": f"Custom Clinical Upload ({filename})",
            "service_type": f"Healthcare Service ({domain_type})",
            "repo": "custom-upload",
            "branch": "feature/custom-scan",
            "commit": "user-submission",
            "author": "developer@hospital.org",
            "domain_risk_weight": 0.90,
            "raw_code": code_content,
            "findings": findings,
            "ast_analysis_active": ast_success,
            "scan_mode": scan_mode
        }

scanner_simulator = ScannerSimulator()
