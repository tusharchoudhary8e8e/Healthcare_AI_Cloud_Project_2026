# AegisMed — Intelligent Healthcare DevSecOps XAI Risk Framework

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![Pytest](https://img.shields.io/badge/Tests-49%20Passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-Academic-orange.svg)]()

> **A context-aware DevSecOps CI/CD security gating system for healthcare software, powered by AST taint-flow analysis, monotonic gradient boosting, Tree-SHAP & finding-level cooperative game theory, and discrete MILP counterfactual optimization.**

---

## Overview

AegisMed is a healthcare DevSecOps risk assessment platform engineered for automated security gating in CI/CD pipelines for clinical software (EHR, FHIR gateways, SaMD). Unlike generic SAST/DAST tools, AegisMed understands healthcare-specific data flows (HIPAA 18 Safe Harbor ePHI, MRN, SSN), tracks variable aliases, verifies cryptographic sanitizers by inspecting argument flows, and maps vulnerabilities directly to HIPAA §164.312, FDA SaMD (FD&C Section 524B), and HL7 FHIR regulatory requirements.

### Key Novelty Claims

| # | Component | What's Novel |
|---|---|---|
| 1 | **AST Semantic Taint-Flow Analyzer** | Tracks ePHI variables from source → variable aliases → sinks using Python's `ast.NodeVisitor`. Supports `AsyncFunctionDef` for modern FHIR routes, multi-syntax SQL injection (.format, %, f-strings), and verifies cryptographic sanitizers by argument inspection (AES-GCM, KMS). |
| 2 | **Monotonic ML Risk Model & HHS Grounding** | `HistGradientBoostingRegressor` with monotonic non-decreasing constraints ($\frac{\partial f}{\partial x_i} \ge 0$, 5-fold CV $R^2 \approx 0.962$). Grounded on 1,656 federal HHS OCR hospital breach records and CISA KEV exploit likelihood factors. |
| 3 | **Two-Tier Game-Theoretic Explainability** | Combines 10-feature Tree-SHAP with exact Finding-Level Shapley attribution ($\sum \Phi_j = v(\text{All}) - v(\text{Empty})$ to machine precision), aggregating blame directly to HIPAA statutory clauses. |
| 4 | **Discrete MILP Optimizer & Closed-Loop Verification** | Solves $\min \sum c_j z_j$ subject to target risk drop and HIPAA zero-tolerance hard bounds ($z_j = 1$) via `scipy.optimize.milp`, followed by closed-loop source code patching and AST re-scan verification. |

---

## Empirical Benchmark Evaluation

Formal benchmark comparison (`benchmark_comparison.py`) evaluating AegisMed against standard regex matching and generic AST rule checkers (Bandit/Semgrep-style) across clinical software patterns:

| Analysis Engine | Precision | Recall | F1 Score | False Positives | False Negatives | Latency |
|---|---|---|---|---|---|---|
| **Generic Regex / Keyword Matching** | 0.800 | 0.667 | 0.727 | 1 | 2 | 0.4 ms |
| **Generic AST Rule Checker (Bandit-style)** | 0.750 | 0.500 | 0.600 | 1 | 3 | 0.5 ms |
| **AegisMed AST Taint-Flow Analyzer** | **1.000** | **1.000** | **1.000** | **0** | **0** | **0.5 ms** |

---

## Architecture

```
Developer Code Commit
        │
        ▼
┌──────────────────────────────────────────────┐
│  Multi-Modal Scanner Ingestion               │
│  • AST Taint Analyzer (Aliasing + Async)     │
│  • SCA Dependency Scanner (CISA KEV)         │
│  • IaC Dockerfile Analyzer (Root & Ports)    │
│  • Fallback Line-Based Scanner               │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Healthcare Compliance Engine                │
│  HIPAA §164.312 │ FDA SaMD 524B │ HL7 FHIR   │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Monotonic ML Risk Engine                    │
│  10-D Feature Vector → HistGradientBoosting  │
│  Monotonic Constraints: df/dx_i >= 0         │
│  Gate: BLOCKED / MANUAL_REVIEW / APPROVED    │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Two-Tier Game-Theoretic XAI                 │
│  • Feature Tree-SHAP (Local Efficiency)      │
│  • Finding-Level Shapley: sum Phi_j = Delta  │
│  • Statutory HIPAA Clause Aggregation        │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Discrete MILP & Closed-Loop Verification    │
│  • scipy.optimize.milp (0-1 Integer Program) │
│  • HIPAA Zero-Tolerance Hard Bounds (z_j=1)  │
│  • Closed-Loop AST Re-Scan on Patched Code   │
└──────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- pip

### Installation
```bash
git clone https://github.com/tusharchoudhary8e8e/Healthcare_AI_Cloud_Project_2026.git
cd Healthcare_AI_Cloud_Project_2026
pip install -r requirements.txt
```

### Run Web Application
```bash
python run_app.py
```
Opens dashboard automatically at `http://127.0.0.1:8000`.

### Run Automated Tests (49 Passing Tests)
```bash
python -m pytest tests/ -v
```

### Run Benchmark Comparison
```bash
python benchmark_comparison.py
```

### Generate Faculty PDF Technical Dossier
```bash
python generate_faculty_pdf.py
```

---

## Project Structure

```
Healthcare_AI_Cloud_Project_2026/
├── backend/
│   ├── __init__.py
│   ├── main.py                    # FastAPI routes & CI/CD gating endpoints
│   ├── scanner_simulator.py       # AST taint analyzer (aliasing, async, sanitizers)
│   ├── ml_engine.py               # Monotonic HistGradientBoosting + HHS breach priors
│   ├── xai_engine.py              # Tree-SHAP + finding-level Shapley + MILP solver
│   ├── healthcare_compliance.py   # HIPAA/FDA/FHIR compliance mapping
│   └── remediation_engine.py      # Cryptographic code patch templates
├── datasets/
│   ├── hhs_major_data_breaches.csv              # 1,656 HHS OCR breach records
│   ├── hhs_cyber_security_breaches.csv          # Historical incident trends
│   ├── nist_nvd_healthcare_cves.json            # NIST NVD CVE feed
│   ├── cve_2023_4863_libwebp_samd.json          # SaMD-specific CVE spec
│   └── healthcare_devsecops_cicd_benchmark_dataset.csv  # 2,500 ML training records
├── static/
│   ├── index.html                 # Dashboard UI
│   ├── app.js                     # Frontend controller
│   └── styles.css                 # Styling
├── tests/
│   ├── test_ast_scanner.py        # AST analyzer & aliasing tests
│   ├── test_ml_engine.py          # ML model & monotonicity tests
│   ├── test_xai_engine.py         # SHAP axioms, finding Shapley & MILP tests
│   ├── test_remediation_engine.py # Remediation coverage tests
│   └── test_compliance_engine.py  # Compliance mapping tests
├── docs/
│   ├── PATENT_DISCLOSURE_AND_NOVELTY.md
│   ├── FACULTY_VIVA_QA.md
│   ├── AWS_ARCHITECTURE.md
│   └── AegisMed_Faculty_Project_Dossier.pdf
├── benchmark_comparison.py        # Empirical comparison benchmark
├── generate_faculty_pdf.py        # PDF documentation generator
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── run_app.py
```

---

## Documentation

- [Patent Disclosure & Novelty](docs/PATENT_DISCLOSURE_AND_NOVELTY.md)
- [Faculty Viva Q&A Defense Guide](docs/FACULTY_VIVA_QA.md)
- [AWS Cloud Architecture & $50 Learner Lab Deployment](docs/AWS_ARCHITECTURE.md)
- [Faculty Project Dossier (PDF)](docs/AegisMed_Faculty_Project_Dossier.pdf)

---

## License

This project is developed for academic research and patent novelty evaluation.
