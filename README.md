# AegisMed — Intelligent Healthcare DevSecOps XAI Risk Framework

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-Academic-orange.svg)]()

> **A context-aware DevSecOps CI/CD security gating system for healthcare software, powered by AST taint-flow analysis, Tree-SHAP explainable AI, and constrained inverse counterfactual optimization.**

---

## Overview

AegisMed is a prototype healthcare DevSecOps risk assessment platform that demonstrates a novel approach to automated security gating in CI/CD pipelines for clinical software (EHR, FHIR gateways, SaMD). Unlike generic SAST/DAST tools, AegisMed understands healthcare-specific data flows (ePHI, MRN, SSN) and maps vulnerabilities directly to HIPAA §164.312, FDA SaMD, and HL7 FHIR regulatory requirements.

### Key Novelty Claims

| # | Component | What's Novel |
|---|---|---|
| 1 | **AST Taint-Flow Analyzer** | Tracks ePHI variables from source → propagation → sink using Python's `ast` module. Recognizes cryptographic sanitizers (AES-GCM, KMS) to suppress false positives. |
| 2 | **HHS-Calibrated ML Risk Model** | Ensemble (RandomForest + GradientBoosting) trained on 2,500 healthcare CI/CD benchmark records, calibrated against 1,656 real HHS OCR hospital breach cases. |
| 3 | **True Tree-SHAP Attribution** | Exact Shapley values (Lundberg et al., Nature MI 2020) satisfying Local Efficiency axiom: `f(x) = E[f] + Σφᵢ`. |
| 4 | **Constrained Inverse Counterfactual Solver** | Computes Pareto-optimal minimal developer effort to transition gate from BLOCKED → APPROVED via greedy coordinate descent with HIPAA zero-tolerance constraints. |

---

## Architecture

```
Developer Code Commit
        │
        ▼
┌──────────────────────────────────┐
│  Multi-Modal Scanner Ingestion   │
│  • Python AST Taint Analyzer     │
│  • SCA Dependency CVE Scanner    │
│  • IaC Dockerfile Analyzer       │
│  • Fallback Line-Based Scanner   │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│  Healthcare Compliance Engine    │
│  HIPAA §164.312 │ FDA SaMD │ HL7 │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│  ML Risk Engine (Ensemble)       │
│  10-D Feature Vector → Score     │
│  Gate: BLOCKED/REVIEW/APPROVED   │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│  XAI Engine (Tree-SHAP)          │
│  • Feature Attribution           │
│  • Counterfactual Solver         │
│  • Dual Narratives               │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│  Remediation Engine              │
│  9 Healthcare-Specific Patches   │
│  Optional LLM Synthesis Hook     │
└──────────────────────────────────┘
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- pip

### Installation
```bash
git clone <repository-url>
cd cloud-project
pip install -r requirements.txt
```

### Run
```bash
python run_app.py
```
Opens browser at `http://127.0.0.1:8000`

### Run Tests
```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Project Structure

```
cloud-project/
├── backend/
│   ├── __init__.py
│   ├── main.py                    # FastAPI routes & API endpoints
│   ├── scanner_simulator.py       # AST taint analyzer + SCA + IaC scanners
│   ├── ml_engine.py               # Ensemble ML risk model (RF + GB)
│   ├── xai_engine.py              # Tree-SHAP + counterfactual solver
│   ├── healthcare_compliance.py   # HIPAA/FDA/FHIR compliance mapping
│   └── remediation_engine.py      # Code patch templates + LLM hook
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
│   ├── test_ast_scanner.py        # AST analyzer tests
│   ├── test_ml_engine.py          # ML model tests
│   ├── test_xai_engine.py         # SHAP axiom verification
│   ├── test_remediation_engine.py # Remediation coverage tests
│   └── test_compliance_engine.py  # Compliance mapping tests
├── docs/
│   ├── PATENT_DISCLOSURE_AND_NOVELTY.md
│   ├── FACULTY_VIVA_QA.md
│   └── AWS_ARCHITECTURE.md
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── run_app.py
```

---

## Datasets

| Dataset | Source | Records | Role |
|---|---|---|---|
| `hhs_major_data_breaches.csv` | U.S. HHS Office for Civil Rights | 1,656 | Real hospital breach cases for empirical calibration |
| `hhs_cyber_security_breaches.csv` | Rdatasets / Cyber Incident Mirror | ~500 | Historical breach trends |
| `nist_nvd_healthcare_cves.json` | NIST National Vulnerability Database | 50+ CVEs | Healthcare software CVE feed |
| `cve_2023_4863_libwebp_samd.json` | MITRE CVE Project v5 | 1 CVE | SaMD imaging vulnerability |
| `healthcare_devsecops_cicd_benchmark_dataset.csv` | Compiled Benchmark | 2,500 | ML training matrix |

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Run full DevSecOps assessment |
| `POST` | `/api/xai/whatif` | Interactive What-If risk recalculation |
| `GET` | `/api/scenarios` | List preset healthcare scenarios |
| `GET` | `/api/datasets/info` | Dataset metadata & statistics |
| `GET` | `/api/audit/export` | Generate HIPAA audit certificate |

---

## Documentation

- [Patent Disclosure & Novelty](docs/PATENT_DISCLOSURE_AND_NOVELTY.md)
- [Faculty Viva Q&A](docs/FACULTY_VIVA_QA.md)
- [AWS Architecture & Deployment](docs/AWS_ARCHITECTURE.md)

---

## License

This project is developed for academic research purposes.
