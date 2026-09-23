"""
AegisMed Empirical Benchmark Evaluation
Compares AegisMed AST Taint-Flow Analyzer against Conventional Regex & Generic Rule-Based SAST.
Evaluates Precision, Recall, and F1-Score across clinical benchmark code testcases.
"""
import time
import ast
import re
from backend.scanner_simulator import scanner_simulator, HealthcareASTTaintAnalyzer

BENCHMARK_CASES = [
    {
        "id": "CASE-01",
        "name": "ePHI Alias Propagation to Plaintext DB Sink",
        "code": """
def store_records(db, ssn, mrn):
    temp_alias = ssn
    db.collection('patients').insert_one(temp_alias)
""",
        "expected_vulns": ["UNENCRYPTED_PHI_STORAGE"],
        "description": "Variable alias (temp_alias = ssn) propagating to database insert"
    },
    {
        "id": "CASE-02",
        "name": "Cryptographically Hardened AESGCM Storage (Sanitizer Suppression)",
        "code": """
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def save_hardened(db, ssn, patient_id):
    aes = AESGCM(os.urandom(32))
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, ssn.encode('utf-8'), patient_id.encode('utf-8'))
    db.collection('patients').insert_one({'patient_id': patient_id, 'enc': ciphertext.hex()})
""",
        "expected_vulns": [],
        "description": "Properly encrypted envelope storage should produce 0 false positives"
    },
    {
        "id": "CASE-03",
        "name": "SQL Injection via .format() and % Operators",
        "code": """
def search_records(db, ssn):
    q1 = "SELECT * FROM patients WHERE ssn = {}".format(ssn)
    q2 = "SELECT * FROM patients WHERE ssn = '%s'" % ssn
    db.execute(q1)
""",
        "expected_vulns": ["SQL_INJECTION_EHR"],
        "description": "Dynamic SQL construction using .format() and % formatting"
    },
    {
        "id": "CASE-04",
        "name": "Async SMART-on-FHIR Endpoint with Wildcard Scope",
        "code": """
@app.get("/Observation")
async def get_obs(patient_id: str, scope: str = "*.*"):
    return query(patient_id)
""",
        "expected_vulns": ["PERMISSIVE_FHIR_SCOPE"],
        "description": "Async FastAPI endpoint with wildcard OAuth authorization scope"
    },
    {
        "id": "CASE-05",
        "name": "Fake Cryptographic Sanitizer Function (Non-Sanitized Flow)",
        "code": """
def save_fake(db, ssn):
    dummy = rehash_noop("unrelated_seed")
    db.collection('patients').insert_one(ssn)
""",
        "expected_vulns": ["UNENCRYPTED_PHI_STORAGE"],
        "description": "Functions with crypto substrings that do not sanitize the tainted variable must not suppress findings"
    },
    {
        "id": "CASE-06",
        "name": "Unmasked Patient Telemetry in Application Logger",
        "code": """
def log_vitals(logger, patient_id, heart_rate):
    logger.info(f"Patient vitals recorded: {patient_id}, heart_rate={heart_rate}")
""",
        "expected_vulns": ["PHI_IN_LOGS"],
        "description": "Direct clinical identifiers and vitals passed to system log stream"
    },
    {
        "id": "CASE-07",
        "name": "Cleartext HTTP Remote Endpoint Transmission",
        "code": """
def sync_fhir(records):
    target = "http://remote-ehr.hospital.net/api/sync"
    requests.post(target, json=records)
""",
        "expected_vulns": ["UNENCRYPTED_TRANSMISSION"],
        "description": "Cleartext HTTP transport sink violating HIPAA transmission safeguard"
    },
    {
        "id": "CASE-08",
        "name": "Benign Financial Math Function (Clean Baseline)",
        "code": """
def compute_hospital_budget(invoices, tax_rate):
    total = sum(i['amount'] for i in invoices)
    return total * (1.0 + tax_rate)
""",
        "expected_vulns": [],
        "description": "Non-clinical financial math should produce zero security warnings"
    }
]

def run_regex_baseline(code: str) -> list:
    """Baseline 1: Standard regex/keyword pattern matching."""
    findings = []
    # Pattern 1: detect passwords
    if re.search(r'(?i)(password|secret)\s*=\s*["\'][^"\']+["\']', code):
        findings.append("HARDCODED_SECRETS")
    # Pattern 2: detect SQL keywords
    if re.search(r'(?i)select\s+.*\s+from\s+', code):
        findings.append("SQL_INJECTION_EHR")
    # Pattern 3: detect http://
    if "http://" in code:
        findings.append("UNENCRYPTED_TRANSMISSION")
    # Pattern 4: detect ssn/patient in string
    if re.search(r'(?i)(ssn|patient)', code) and "insert" in code:
        findings.append("UNENCRYPTED_PHI_STORAGE")
    return list(set(findings))

def run_generic_ast_baseline(code: str) -> list:
    """Baseline 2: Generic SAST rule checker (Bandit-style, without taint propagation)."""
    findings = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings
    for node in ast.walk(tree):
        # Rule 1: JoinedStr with SQL keywords
        if isinstance(node, ast.JoinedStr):
            text = "".join([p.value for p in node.values if isinstance(p, ast.Constant)])
            if any(k in text.upper() for k in ["SELECT ", "INSERT "]):
                findings.append("SQL_INJECTION_EHR")
        # Rule 2: Constant with http://
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.startswith("http://"):
                findings.append("UNENCRYPTED_TRANSMISSION")
        # Rule 3: Function with name insert
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "insert_one":
            findings.append("UNENCRYPTED_PHI_STORAGE")
    return list(set(findings))

def evaluate_scanner(scanner_fn, name: str) -> dict:
    tp = 0
    fp = 0
    fn = 0
    tn = 0
    t0 = time.time()
    
    for case in BENCHMARK_CASES:
        detected = scanner_fn(case["code"])
        expected = case["expected_vulns"]
        
        # Check detected vs expected
        detected_set = set(detected)
        expected_set = set(expected)
        
        # True Positives
        matched = detected_set.intersection(expected_set)
        tp += len(matched)
        
        # False Positives (detected but not expected)
        fp += len(detected_set - expected_set)
        
        # False Negatives (expected but not detected)
        fn += len(expected_set - detected_set)
        
        if len(detected_set) == 0 and len(expected_set) == 0:
            tn += 1

    elapsed = (time.time() - t0) * 1000
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "engine": name,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "latency_ms": round(elapsed, 2)
    }

def run_aegismed(code: str) -> list:
    res = scanner_simulator.scan_custom_code("eval.py", code)
    return list(set([f["type"] for f in res.get("findings", [])]))

if __name__ == "__main__":
    b1 = evaluate_scanner(run_regex_baseline, "Generic Regex / Keyword Matching")
    b2 = evaluate_scanner(run_generic_ast_baseline, "Generic AST Rule Checker (Bandit/Semgrep-style)")
    b3 = evaluate_scanner(run_aegismed, "AegisMed AST Taint-Flow Analyzer")

    print("=" * 85)
    print("AEGISMED EMPIRICAL BENCHMARK EVALUATION ON CLINICAL TESTCASES")
    print("=" * 85)
    headers = f"{'Engine':<45} | {'Prec':<6} | {'Recall':<6} | {'F1':<6} | {'FP':<4} | {'FN':<4} | {'Time':<7}"
    print(headers)
    print("-" * 85)
    for res in [b1, b2, b3]:
        row = f"{res['engine']:<45} | {res['precision']:<6.3f} | {res['recall']:<6.3f} | {res['f1_score']:<6.3f} | {res['false_positives']:<4} | {res['false_negatives']:<4} | {res['latency_ms']:<5.1f}ms"
        print(row)
    print("=" * 85)
