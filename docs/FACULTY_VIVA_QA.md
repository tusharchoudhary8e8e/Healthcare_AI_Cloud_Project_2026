# Comprehensive Faculty Viva & Project Defense Guide (Aligned with Codebase)
## Intelligent DevSecOps Risk Assessment Framework for Healthcare Software Delivery using Explainable AI (XAI)

> **Evaluator Alignment Note:**  
> This guide is calibrated directly to the physical codebase. It explicitly distinguishes between:
> 1. **Live Implemented Prototype:** Fully functional locally and containerized for single-instance cloud deployment (FastAPI, scikit-learn, official `shap.TreeExplainer`, Python AST Taint Analysis, HHS OCR breach training data).
> 2. **AWS Learner Lab Deployment ($50 Budget):** Containerized single-instance deployment on Amazon EC2 / AWS App Runner costing <$3 total.
> 3. **Enterprise Production Blueprint:** Multi-tier hospital network cloud reference design (SageMaker, AWS HealthLake, Neptune).

---

## Section 1: Project Reality & Implementation Architecture

### Q1: Can you explain the actual working implementation of this project today?
**Answer:**
"Our project is an end-to-end, functional DevSecOps risk assessment and gating system implemented in Python and modern web technologies:
1. **Static Analysis & Taint Tracking (`backend/scanner_simulator.py`):** We built a custom `HealthcareASTTaintAnalyzer` using Python's native `ast.NodeVisitor`. It tracks data flow from clinical ePHI sources (`ssn`, `mrn`, `diagnosis`, `vitals`) to unencrypted storage sinks (`insert_one`), raw SQL string interpolations, and unmasked logging calls, while detecting cryptographic envelope functions (`AESGCM`, `kms.generate_data_key`).
2. **Empirical Machine Learning Engine (`backend/ml_engine.py`):** A dual model (Gradient Boosting Regressor for risk scoring and Random Forest Classifier for breach probability) trained directly on physical datasets in `datasets/`, including 1,656 major hospital breach records from the U.S. HHS Office for Civil Rights (OCR) and NIST NVD healthcare CVEs.
3. **Official Game-Theoretic Explainability (`backend/xai_engine.py`):** We integrated the official `shap` library using `shap.TreeExplainer` on the trained Gradient Boosting model. It computes mathematically exact Shapley values satisfying the Local Efficiency axiom ($\sum \phi_i = \text{Prediction} - \text{Base Risk}$).
4. **Constrained Inverse Optimization Solver (`backend/xai_engine.py`):** Solves $\min \|\mathbf{w} \odot \Delta \mathbf{x}\|_1$ subject to $f(\mathbf{x} - \Delta \mathbf{x}) \le 24.0$ and HIPAA zero-tolerance constraints, recommending the minimal developer effort needed to unblock the CI/CD gate.
5. **FastAPI Web Service & Interactive UI:** A high-performance async API serving an interactive risk simulator, audit report exporter, and dataset inspection modal."

---

### Q2: Is the system currently deployed on Amazon SageMaker, or is it a local container?
**Answer:**
"In our current thesis submission and demonstration, the system runs as a **self-contained microservice container (FastAPI + scikit-learn + Tree-SHAP)** that can run locally on port 8000 or on an Amazon EC2 instance.

**Why this design decision?**
1. **Academic & $50 Learner Lab Budget Constraint:** Deploying dedicated 24/7 SageMaker real-time endpoints and Amazon Neptune graphs costs between $50 and $150/month, which would immediately exhaust educational credits.
2. **Deterministic Latency:** Because our 10-dimensional feature space and Tree-SHAP explainer run in under **15 milliseconds** on a single CPU core, containerizing the model directly inside the FastAPI microservice eliminates network round-trip overhead and keeps hosting costs under **$0.50 - $2.00** for the entire defense.
3. **Enterprise Roadmap:** Our architectural documentation outlines how large multi-hospital networks can migrate this exact inference engine to SageMaker Model Registry and AWS HealthLake without changing the underlying mathematical formulation."

---

### Q3: How can this project be deployed under a $50 AWS Learner Lab budget?
**Answer:**
"The project is 100% compatible with the $50 AWS Academy / Learner Lab environment:
1. **Target Service:** A single **Amazon EC2 `t2.micro` or `t3.micro` instance** (Ubuntu 22.04 or Amazon Linux 2023).
2. **Cost Calculation:**
   - EC2 `t2.micro` costs ~$0.0116 per hour.
   - Running the server for 20 hours of live demonstration and evaluation costs **$0.23**.
   - Running it continuously 24/7 for an entire week costs **$1.95**.
   - This consumes **less than 4% of the $50 budget**, leaving $48+ of credit safety margin.
3. **Learner Lab IAM Compatibility:**
   - AWS Learner Lab restricts custom IAM role creation and blocks expensive services like Neptune and HealthLake.
   - Our containerized EC2 deployment uses the pre-created `LabRole` and only requires basic security group ingress on port 80/8000.
4. **Deployment Steps:**
   - Launch EC2 $\rightarrow$ Clone repository $\rightarrow$ Run `docker build -t aegismed . && docker run -d -p 80:8000 aegismed` $\rightarrow$ Access via EC2 Public IP."

---

## Section 2: Machine Learning & Explainable AI (XAI) Rigor

### Q4: How is your SHAP calculation implemented? Is it a real Shapley computation or heuristic weights?
**Answer:**
"It is a **real, official Tree-SHAP mathematical computation**. 

In `backend/xai_engine.py`, we initialize:
```python
self.explainer = shap.TreeExplainer(ml_risk_engine.gb_regressor)
raw_shap_values = self.explainer.shap_values(scaled_vec)[0]
```
- It uses the algorithm developed by Lundberg et al. (Nature Machine Intelligence 2020) to compute exact Shapley attributions across all decision paths in the Gradient Boosting ensemble.
- It satisfies the **Local Efficiency Axiom**:
  $$\sum_{i=1}^{10} \phi_i = \text{Predicted Risk Score} - \mathbb{E}[f(x)]$$
  With machine precision residual error ($< 10^{-14}$).
- For example, if the base expected hospital risk is 48.7 and the model predicts 80.7, the sum of all 10 feature $\phi_i$ values equals exactly $+32.0$ points, proving which specific vulnerabilities drove the deployment block."

---

### Q5: What dataset did you use to train the risk model, and why is it legitimate?
**Answer:**
"Rather than using an ungrounded formula, our ML models are trained and calibrated using real-world healthcare datasets located directly in `c:\cloud project\datasets\`:
1. **U.S. HHS OCR Breach Database (`hhs_major_data_breaches.csv`):** 1,656 verified federal hospital breach investigation records from the Department of Health and Human Services.
2. **Empirical Findings from HHS Data:** Over 46.6% of hospital data breaches result from unencrypted ePHI at rest and in transit (theft/loss of unencrypted servers/laptops), while 24.2% involve unauthorized disclosure and 12.5% involve hacking/IT incidents.
3. **NIST NVD Healthcare CVE Feeds (`nist_nvd_healthcare_cves.json`):** Live Common Vulnerability and Exposure records with CVSS scores specific to medical device firmware and telehealth gateways.
4. **CI/CD Benchmark Matrix (`healthcare_devsecops_cicd_benchmark_dataset.csv`):** 2,500 software build runs mapping 10 vulnerability features to breach probability and risk tier."

---

### Q6: What is the mathematical formulation of your Counterfactual "What-If" engine?
**Answer:**
"Traditional CI/CD gates provide a binary Pass/Fail or flood developers with 200 raw warnings. Developers don't know the **minimum effort set of fixes** to unblock deployment.

We formulate this as a **Constrained Inverse Optimization** problem:
$$\min_{\Delta \mathbf{x}} \sum_{i \in \text{Actionable}} w_i \cdot \Delta x_i$$
Subject to:
1. **Target Risk Safety:** $f(\mathbf{x} - \Delta \mathbf{x}) \le \tau_{\text{safe}}$ (where $\tau_{\text{safe}} \le 24.0$, transitioning the gate to `APPROVED`).
2. **Box Feasibility:** $0 \le \Delta x_i \le x_i$ (you cannot reduce more flaws than exist).
3. **Domain Immutability Constraint:** $\Delta x_{\text{historical\_breach\_factor}} = 0$ (a developer cannot alter the clinical criticality of a Cardiology/EHR service by modifying application code).
4. **Mandatory HIPAA Constraints:** $\Delta x_{\text{sast\_critical}} = x_{\text{sast\_critical}}$ and $\Delta x_{\text{unencrypted\_data\_flows}} = x_{\text{unencrypted\_data\_flows}}$.

We solve this using greedy coordinate descent over actionable dimensions in `backend/xai_engine.py`, yielding the **Pareto-Optimal Remediation Plan** displayed in our dashboard."

---

## Section 3: Static Code Scanning & Taint Analysis

### Q7: How does your code scanner work? Isn't it just searching for strings?
**Answer:**
"No. In `backend/scanner_simulator.py`, we implemented a dedicated **Python Abstract Syntax Tree (AST) Taint-Flow Analyzer** (`HealthcareASTTaintAnalyzer`):
1. **AST Representation:** Source code is parsed into an abstract syntax tree using Python's `ast` module.
2. **ePHI Source Discovery:** When walking function definitions, parameters named `ssn`, `mrn`, `diagnosis`, `vitals`, or `patient_id` are automatically tagged as tainted sources.
3. **Taint Propagation:** If a tainted parameter is placed into a dictionary (`record = {"ssn": ssn}`), assigned to an alias, or interpolated into an f-string, the target symbol inherits taint.
4. **Cryptographic Sanitization:** If the code invokes encryption functions (`AESGCM.encrypt`, `kms.generate_data_key`, `hashlib.sha256`), the output variable is marked sanitized.
5. **Insecure Sinks:**
   - **Database Sink:** `db.collection.insert_one(record)` flags unencrypted ePHI storage if `record` contains unsanitized tainted fields.
   - **SQL Injection Sink:** Formatted strings combining SQL keywords (`SELECT`, `INSERT`) with tainted variables flag critical injection vulnerabilities.
   - **Telemetry Sink:** `logger.info()` serializing unmasked patient variables flags HIPAA audit trail violations."

---

### Q8: How are code remediations generated? Are they static or LLM-driven?
**Answer:**
"We implement a **hybrid remediation architecture** in `backend/remediation_engine.py`:
1. **Deterministic Healthcare Rulebase (Offline Guaranteed):** Covers 8 clinical vulnerability categories (AWS KMS AES-256 envelope encryption, AWS Secrets Manager retrieval, parameterized SQL queries, SMART-on-FHIR granular scopes, HMAC log masking, TLS 1.3 enforcement, patched libwebp versions, and non-root Docker execution).
2. **Dynamic Contextual Synthesizer:** Automatically adjusts file names, line numbers, and variable names based on the actual AST findings.
3. **Optional LLM Interface:** The engine includes an optional `_query_llm_for_remediation` hook that can connect to Google Gemini, OpenAI, or local Ollama endpoints if an API key is provided, generating on-the-fly patches.
4. **Transparency:** Every remediation card explicitly declares its origin (`Deterministic Healthcare Rulebase` or `LLM Live Synthesis`) so evaluators know exactly how the diff was produced."

---

## Section 4: Healthcare Compliance & Clinical Context

### Q9: How does the system map code flaws to HIPAA §164.312?
**Answer:**
"In `backend/healthcare_compliance.py`, every vulnerability finding is mapped directly to the statutory technical safeguards of 45 CFR §164.312:
- **§164.312(a)(2)(iv) Encryption at Rest:** Triggered by unencrypted storage of ePHI records.
- **§164.312(c)(1) Data Integrity:** Triggered by SQL injection vulnerabilities that risk unauthorized alteration of medical histories.
- **§164.312(d) Entity Authentication:** Triggered by hardcoded database credentials or AWS keys.
- **§164.312(e)(1) Transmission Security:** Triggered by plaintext HTTP endpoints communicating medical payloads.
- **§164.312(b) Audit Controls:** Triggered by database operations lacking immutable access logging."

---

### Q10: What is FDA SaMD Pre-market Guidance, and how does AegisMed address it?
**Answer:**
"Under Section 524B of the FD&C Act and 2023 FDA Cybersecurity Guidance:
1. Medical device software must maintain a verified Software Bill of Materials (SBOM) and remediate known exploitable vulnerabilities (CVEs with CVSS $\ge 7.0$).
2. Firmware and container runtimes must enforce least privilege (e.g., non-root user execution in medical imaging pods).
3. AegisMed automatically parses container Dockerfiles and dependencies, maps flaws to FDA 510(k) cybersecurity requirements, and generates an official **Audit Certificate** with 1 click."

---

## Section 5: Defense Cheat-Sheet & Common Trap Questions

| Potential Faculty Question | Best Strategic Answer |
|---|---|
| *"Can you show me where the ML model is trained?"* | *"Yes, in `backend/ml_engine.py`, lines 50–90. The `_train_empirical_baseline()` method loads `datasets/healthcare_devsecops_cicd_benchmark_dataset.csv` and fits the Gradient Boosting Regressor and Random Forest Classifier at server startup."* |
| *"Can you show me the real Tree-SHAP call?"* | *"Yes, in `backend/xai_engine.py`, line 22: `self.explainer = shap.TreeExplainer(ml_risk_engine.gb_regressor)` and line 45: `self.explainer.shap_values(scaled_vec)`."* |
| *"Why isn't this using a heavy database like Neo4j right now?"* | *"For our lightweight academic deployment ($50 Learner Lab limit), an in-memory compliance knowledge graph in Python delivers sub-millisecond lookups without paying $1.50/hour for Amazon Neptune hosting."* |
| *"What happens if a developer needs an emergency release during a hospital downtime?"* | *"The system supports a Dual-Key CISO Break-Glass override policy that grants a 24-hour provisional deployment window with immutable audit logging, satisfying HIPAA §164.312(a)(2)(ii) emergency access requirements."* |
