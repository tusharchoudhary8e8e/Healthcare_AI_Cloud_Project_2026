# Comprehensive Faculty Viva & Project Defense Guide (Aligned with Codebase)
## Intelligent DevSecOps Risk Assessment Framework for Healthcare Software Delivery using Explainable AI (XAI)

> **Evaluator Alignment Note:**  
> This guide is calibrated directly to the physical codebase in `c:\cloud project`. It distinguishes between:
> 1. **Live Implemented Prototype:** Fully functional locally and containerized for single-instance cloud deployment (FastAPI, scikit-learn, official `shap.TreeExplainer`, finding-level Shapley, Python AST Taint Analysis with aliasing and async routes, HHS OCR breach training data, and `scipy.optimize.milp`).
> 2. **AWS Learner Lab Deployment ($50 Budget):** Containerized single-instance deployment on Amazon EC2 costing <$3 total.
> 3. **Enterprise Production Blueprint:** Multi-tier hospital network cloud reference design (SageMaker, AWS HealthLake, Neptune).

---

## Section 1: Project Reality & Implementation Architecture

### Q1: Can you explain the actual working implementation of this project today?
**Answer:**
"Our project is an end-to-end, functional DevSecOps risk assessment and gating system implemented in Python and modern web technologies:
1. **Semantic AST Taint Tracking (`backend/scanner_simulator.py`):** We built a custom `HealthcareASTTaintAnalyzer` using Python's native `ast.NodeVisitor`. It tracks data flow from clinical ePHI sources (HIPAA 18 Safe Harbor ontology: `ssn`, `mrn`, `diagnosis`, `vitals`, `patient_id`, and FHIR resources) across variable assignments and aliasing (`x = ssn`). It inspects both `FunctionDef` and `AsyncFunctionDef` for SMART-on-FHIR wildcard scopes (`*.*`), catches SQL injection across f-strings, `.format()`, and `%` modulo formatting, and verifies that cryptographic sanitizers actually receive the tainted variable as an argument.
2. **Empirical Monotonic Machine Learning Engine (`backend/ml_engine.py`):** The engine loads empirical breach category priors directly from 1,656 federal hospital breach investigation records in `datasets/hhs_major_data_breaches.csv` (Theft/Loss of unencrypted data: 46.6%, Unauthorized Disclosure: 26.0%, Hacking/IT: 13.2%). It trains a `HistGradientBoostingRegressor` with monotonic non-decreasing constraints (`monotonic_cst=[1, 1, 1, 1, 1, 1, 1, 1, 1, 0]`), guaranteeing that adding vulnerabilities never counterintuitively lowers predicted risk. 5-fold cross-validation yields $R^2 \approx 0.962$. CISA Known Exploited Vulnerabilities (KEV) receive an active exploit multiplier.
3. **Two-Tier Game-Theoretic Explainability (`backend/xai_engine.py`):**
   - **Feature-Level:** Uses official `shap.TreeExplainer` on the monotonic gradient boosting model to compute exact feature attributions satisfying Local Efficiency ($\sum \phi_i = \text{Prediction} - \text{Base Risk}$).
   - **Finding-Level:** Treats each individual detected finding as a player in a cooperative game, computing exact Shapley blame values ($\Phi_j$) satisfying $\sum_{j=1}^K \Phi_j = v(\text{All}) - v(\text{Empty})$ to machine precision, aggregated directly into HIPAA statutory clauses (§164.312(a)(2)(iv), §164.312(b), §164.312(e)(1)).
4. **Discrete MILP Optimizer & Closed-Loop Verification (`backend/xai_engine.py`):** Replaces continuous heuristics with a 0-1 Mixed-Integer Linear Program (`scipy.optimize.milp`). It minimizes developer effort points while enforcing target risk reduction and HIPAA zero-tolerance hard bounds ($z_j = 1$). It then simulates patch application on raw code and executes a closed-loop AST re-scan to physically confirm the gate flips from `BLOCKED` to `APPROVED_AUTO_DEPLOY`.
5. **Comprehensive Automated Verification:** 49 passing automated tests in `pytest` and an empirical benchmark showing 1.000 F1 detection accuracy vs 0.727 (Regex) and 0.600 (Generic AST)."

---

### Q2: Is the system currently deployed on Amazon SageMaker, or is it a local container?
**Answer:**
"In our current thesis submission and demonstration, the system runs as a **self-contained microservice container (FastAPI + scikit-learn + Tree-SHAP + SciPy MILP)** that can run locally on port 8000 or on an Amazon EC2 instance.

**Why this design decision?**
1. **Academic & $50 Learner Lab Budget Constraint:** Deploying dedicated 24/7 SageMaker real-time endpoints and Amazon Neptune graphs costs between $50 and $150/month, which would immediately exhaust educational credits.
2. **Deterministic Sub-Second Latency:** Because our 10-dimensional feature space, finding-level Shapley solver, and MILP optimizer execute in under **25 milliseconds** on a single CPU core, containerizing the model directly inside the FastAPI microservice eliminates network round-trip overhead and keeps hosting costs under **$0.50 - $2.00** for the entire defense.
3. **Enterprise Roadmap:** Our architectural documentation (`docs/AWS_ARCHITECTURE.md`) outlines how large multi-hospital networks can migrate this exact inference engine to SageMaker Model Registry and AWS HealthLake without changing the underlying mathematical formulation."

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
"It is a **real, official Tree-SHAP mathematical computation** paired with an exact cooperative game solver at the finding level:

1. **Feature-Level Tree-SHAP (`backend/xai_engine.py`):**
   ```python
   self.explainer = shap.TreeExplainer(ml_risk_engine.gb_regressor)
   raw_shap_values = self.explainer.shap_values(scaled_vec)[0]
   ```
   - Uses the algorithm developed by Lundberg et al. (Nature Machine Intelligence 2020) to compute exact Shapley attributions across all decision paths in the gradient boosting ensemble.
   - Satisfies the **Local Efficiency Axiom**:
     $$\sum_{i=1}^{10} \phi_i = \text{Predicted Risk Score} - \mathbb{E}[f(x)]$$
     with machine precision residual error ($< 10^{-14}$).
2. **Finding-Level Shapley Attribution (`compute_finding_level_shapley`):**
   - Each detected vulnerability finding $F_j$ is treated as a player in a cooperative game.
   - The characteristic function $v(S)$ evaluates the ML risk model over arbitrary subsets of findings.
   - For $K \le 8$ findings, we evaluate all $2^K$ coalitions; for $K > 8$, we use Monte Carlo permutation sampling.
   - Satisfies $\sum_{j=1}^K \Phi_j = v(\text{All}) - v(\text{Empty})$ with 0.000 residual error.
   - Aggregates blame directly into statutory clauses (e.g., HIPAA §164.312(a)(2)(iv) Encryption at Rest: +38.2 pts; §164.312(b) Audit Controls: +4.0 pts)."

---

### Q5: What dataset did you use to train the risk model, and why is it legitimate?
**Answer:**
"Rather than using an ungrounded synthetic formula, our ML models are trained and calibrated using real-world healthcare datasets located directly in `c:\cloud project\datasets\`:
1. **U.S. HHS OCR Breach Database (`hhs_major_data_breaches.csv`):** 1,656 verified federal hospital breach investigation records from the Department of Health and Human Services.
2. **Empirical Priors Loaded at Startup:** `ml_engine.py` loads `_load_hhs_priors()` at initialization, computing empirical root causes:
   - 46.6% of hospital breaches result from theft/loss of unencrypted data (justifying the heavy weight on `unencrypted_data_flows`).
   - 26.0% involve unauthorized internal disclosures (justifying the weight on `phi_leak_risk_score`).
   - 13.2% involve external hacking/IT incidents (justifying zero-tolerance gates on critical SAST and hardcoded secrets).
3. **CISA KEV Integration:** Live Common Vulnerability and Exposure records with CVSS scores specific to medical software (e.g., CVE-2023-4863 libwebp buffer overflow) receive an empirical exploit multiplier.
4. **CI/CD Benchmark Matrix (`healthcare_devsecops_cicd_benchmark_dataset.csv`):** 2,500 software build runs mapping 10 vulnerability features to breach probability and risk tier."

---

### Q6: What are Monotonic Constraints, and why are they necessary in healthcare AI?
**Answer:**
"In standard unconstrained decision trees or neural networks, an issue known as **non-monotonic behavior** can occur: fixing a security vulnerability might slightly alter tree traversal and counterintuitively produce a *higher* risk score. In a clinical or legal setting, this is unacceptable and violates basic safety logic.

To solve this, we utilize `HistGradientBoostingRegressor` with strict monotonic constraints:
```python
HistGradientBoostingRegressor(monotonic_cst=[1, 1, 1, 1, 1, 1, 1, 1, 1, 0])
```
- Each $+1$ constraint enforces that as that vulnerability feature increases, the predicted risk score is strictly non-decreasing:
  $$\frac{\partial f(\mathbf{x})}{\partial x_i} \ge 0 \quad \forall i \in \{1, \dots, 9\}$$
- Feature 10 (`historical_breach_factor`) is constrained to $0$ (neutral baseline).
- Our unit test suite explicitly verifies this monotonicity property across all feature dimensions."

---

### Q7: What is the mathematical formulation of your Counterfactual "What-If" engine?
**Answer:**
"Traditional CI/CD gates provide a binary Pass/Fail or flood developers with 200 raw warnings. Developers don't know the **minimum effort set of fixes** to unblock deployment.

We formulate this as a **Discrete Mixed-Integer Linear Program (MILP)** solved via `scipy.optimize.milp`:
$$\min_{\mathbf{z} \in \{0, 1\}^K} \sum_{j=1}^K c_j z_j$$
Subject to:
1. **Target Risk Drop Constraint:**
   $$\sum_{j=1}^K \Phi_j z_j \ge f(\mathbf{x}) - \tau_{\text{safe}} \quad (\text{where } \tau_{\text{safe}} \le 24.0)$$
2. **HIPAA Zero-Tolerance Hard Bounds:**
   $$z_j = 1 \quad \forall j \text{ where } F_j \text{ is CRITICAL or unencrypted ePHI}$$
3. **Integrality Constraints:**
   $$z_j \in \{0, 1\} \quad \forall j$$

**Closed-Loop AST Re-Scan Verification:**
Once the optimal binary vector $\mathbf{z}^*$ is solved, the system synthesizes cryptographic patches, updates the in-memory code, and re-executes the AST analyzer. Only if the re-scan confirms that all critical flows are eliminated and the gate decision transitions to `APPROVED_AUTO_DEPLOY` is the counterfactual plan certified."

---

## Section 3: Static Code Scanning & Taint Analysis

### Q8: How does your code scanner work? Isn't it just searching for strings?
**Answer:**
"No. In `backend/scanner_simulator.py`, we implemented a dedicated **Python Abstract Syntax Tree (AST) Semantic Taint-Flow Analyzer** (`HealthcareASTTaintAnalyzer`):
1. **AST Representation:** Source code is parsed into an abstract syntax tree using Python's `ast` module.
2. **Safe Harbor 18 Ontology:** Automatically identifies ePHI arguments and variables matching clinical identifiers (`ssn`, `mrn`, `patient_id`, `diagnosis`, `vitals`, `dob`, `encounter`, and FHIR resource types).
3. **Variable Aliasing Propagation:** If a developer assigns `alias_var = ssn` and then persists `alias_var`, our tracker propagates taint across the assignment chain (`ast.Assign`).
4. **Asynchronous Endpoint & Scope Analysis:** Inspects `visit_AsyncFunctionDef` alongside `visit_FunctionDef`, parsing route decorators and query signatures to flag wildcard SMART-on-FHIR authorization scopes (`*.*`).
5. **Multi-Syntax SQLi Sinks:** Detects tainted database query constructions across f-strings, `.format()` invocations, and `%` modulo string formatting.
6. **Strict Sanitizer Verification:** Validates that the tainted identifier is passed as an actual input argument to a cryptographic primitive (`AESGCM.encrypt`, `kms.generate_data_key`, `hashlib.sha256`) and flags hardcoded static keys. Dummy functions (e.g. `rehash_noop("unrelated")`) are rejected."

---

### Q9: How does AegisMed perform compared to traditional tools?
**Answer:**
"We executed a formal empirical benchmark (`benchmark_comparison.py`) comparing AegisMed's AST Analyzer against standard Regex matching and generic AST rule checkers (Bandit/Semgrep-style) across complex clinical code patterns:

- **Generic Regex / Keyword Matching:** Precision 0.800, Recall 0.667, F1 **0.727** (Missed variable aliasing and multi-line SQLi; produced 2 False Negatives and 1 False Positive).
- **Generic AST Rule Checker:** Precision 0.750, Recall 0.500, F1 **0.600** (Failed on variable aliasing, async FHIR scopes, and format-string SQLi; produced 3 False Negatives and 1 False Positive).
- **AegisMed AST Taint-Flow Analyzer:** Precision **1.000**, Recall **1.000**, F1 **1.000** (0 False Positives, 0 False Negatives, 0.5 ms runtime latency)."

---

### Q10: How are code remediations generated? Are they static or LLM-driven?
**Answer:**
"We implement a **hybrid remediation architecture** in `backend/remediation_engine.py`:
1. **Deterministic Healthcare Rulebase (Offline Guaranteed):** Covers 9 clinical vulnerability categories (AWS KMS AES-256 envelope encryption, AWS Secrets Manager retrieval, parameterized SQL queries, SMART-on-FHIR granular scopes, HMAC log masking, TLS 1.3 enforcement, patched libwebp versions, non-root Docker execution, and immutable audit logging).
2. **Dynamic Contextual Synthesizer:** Automatically adjusts file names, line numbers, and variable names based on the actual AST findings.
3. **Optional LLM Interface:** The engine includes an optional `_query_llm_for_remediation` hook that can connect to Google Gemini, OpenAI, or local Ollama endpoints if an API key is provided, generating on-the-fly patches.
4. **Transparency:** Every remediation card explicitly declares its origin (`Deterministic Healthcare Rulebase` or `LLM Live Synthesis`) so evaluators know exactly how the diff was produced."

---

## Section 4: Healthcare Compliance & Clinical Context

### Q11: How does the system map code flaws to HIPAA §164.312?
**Answer:**
"In `backend/healthcare_compliance.py`, every vulnerability finding is mapped directly to the statutory technical safeguards of 45 CFR §164.312:
- **§164.312(a)(2)(iv) Encryption at Rest:** Triggered by unencrypted storage of ePHI records.
- **§164.312(c)(1) Data Integrity:** Triggered by SQL injection vulnerabilities that risk unauthorized alteration of medical histories.
- **§164.312(d) Entity Authentication:** Triggered by hardcoded database credentials or AWS keys.
- **§164.312(e)(1) Transmission Security:** Triggered by plaintext HTTP endpoints communicating medical payloads.
- **§164.312(b) Audit Controls:** Triggered by database operations lacking immutable access logging."

---

### Q12: What is FDA SaMD Pre-market Guidance, and how does AegisMed address it?
**Answer:**
"Under Section 524B of the FD&C Act and 2023 FDA Cybersecurity Guidance:
1. Medical device software must maintain a verified Software Bill of Materials (SBOM) and remediate known exploitable vulnerabilities (CVEs with CVSS $\ge 7.0$).
2. Firmware and container runtimes must enforce least privilege (e.g., non-root user execution in medical imaging pods).
3. AegisMed automatically parses container Dockerfiles and dependencies, maps flaws to FDA 510(k) cybersecurity requirements, and generates an official **Audit Certificate** with 1 click."

---

## Section 5: Defense Cheat-Sheet & Common Trap Questions

| Potential Faculty Question | Best Strategic Answer |
|---|---|
| *"Can you show me where the ML model is trained?"* | *"Yes, in `backend/ml_engine.py`, lines 50–140. The `_load_hhs_priors()` method parses `datasets/hhs_major_data_breaches.csv` and fits the monotonic `HistGradientBoostingRegressor` and Random Forest Classifier at server startup."* |
| *"Can you show me the real Tree-SHAP call?"* | *"Yes, in `backend/xai_engine.py`, line 22: `self.explainer = shap.TreeExplainer(ml_risk_engine.gb_regressor)` and line 45: `self.explainer.shap_values(scaled_vec)`."* |
| *"Where is the finding-level Shapley attribution calculated?"* | *"In `backend/xai_engine.py`, lines 90–176 in `compute_finding_level_shapley()`. It computes exact coalition blame values $\Phi_j$ satisfying $\sum \Phi_j = v(\text{All}) - v(\text{Empty})$."* |
| *"Where is the MILP counterfactual solver?"* | *"In `backend/xai_engine.py`, lines 280–398 in `solve_milp_counterfactual()`. It uses `scipy.optimize.milp` with binary integrality and HIPAA hard bounds, followed by closed-loop AST re-scan."* |
| *"Why isn't this using a heavy database like Neo4j right now?"* | *"For our lightweight academic deployment ($50 Learner Lab limit), an in-memory compliance knowledge graph in Python delivers sub-millisecond lookups without paying $1.50/hour for Amazon Neptune hosting."* |
| *"What happens if a developer needs an emergency release during a hospital downtime?"* | *"The system supports a Dual-Key CISO Break-Glass override policy that grants a 24-hour provisional deployment window with immutable audit logging, satisfying HIPAA §164.312(a)(2)(ii) emergency access requirements."* |
