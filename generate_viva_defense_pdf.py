"""
Script to generate AegisMed_Complete_Faculty_Viva_Guide.pdf
Comprehensive, publication-quality Viva Defense Dossier for College Faculty.
Covers: Easy explanation, Technical math, UI features/components, Backend codebase, and Viva Q&A.
Uses fpdf (Latin-1 safe strings).
"""
import os
import sys
from fpdf import FPDF

class FacultyVivaPDF(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(100, 116, 139)
            self.cell(0, 8, 'AegisMed: Healthcare DevSecOps XAI Framework | Faculty Viva & Technical Defense Guide', 0, 0, 'L')
            self.cell(0, 8, f'Page {self.page_no()}', 0, 1, 'R')
            self.set_draw_color(226, 232, 240)
            self.line(10, 18, 200, 18)
            self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, 'AegisMed Project Presentation | Confidential Academic Evaluation Dossier', 0, 0, 'C')

    def chapter_title(self, num, title):
        self.set_font('Helvetica', 'B', 12)
        self.set_fill_color(241, 245, 249)
        self.set_text_color(15, 23, 42)
        self.cell(0, 8, f'{num}. {title}', 0, 1, 'L', 1)
        self.ln(2)

    def section_title(self, title):
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(2, 132, 199)
        self.cell(0, 6, title, 0, 1, 'L')
        self.ln(1)

    def sub_section_title(self, title):
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(51, 65, 85)
        self.cell(0, 5, title, 0, 1, 'L')
        self.ln(1)

    def body_text(self, text):
        self.set_font('Helvetica', '', 8.5)
        self.set_text_color(51, 65, 85)
        self.multi_cell(0, 4.2, text)
        self.ln(1.5)

    def body_bold(self, text):
        self.set_font('Helvetica', 'B', 8.5)
        self.set_text_color(15, 23, 42)
        self.multi_cell(0, 4.2, text)
        self.ln(1)

    def bullet(self, title, text):
        self.set_font('Helvetica', 'B', 8.5)
        self.set_text_color(30, 41, 59)
        self.cell(4, 4.2, chr(149), 0, 0)
        self.cell(48, 4.2, title + ':', 0, 0)
        self.set_font('Helvetica', '', 8.5)
        self.set_text_color(51, 65, 85)
        self.multi_cell(0, 4.2, text)
        self.ln(1)

    def table_header(self, cols, widths):
        self.set_font('Helvetica', 'B', 8)
        self.set_fill_color(224, 242, 254)
        self.set_text_color(3, 105, 161)
        for i, col in enumerate(cols):
            self.cell(widths[i], 6, col, 1, 0, 'C', 1)
        self.ln()

    def table_row(self, cols, widths, is_even=False, text_color=None):
        self.set_font('Helvetica', '', 7.5)
        if is_even:
            self.set_fill_color(248, 250, 252)
        else:
            self.set_fill_color(255, 255, 255)
        self.set_text_color(51, 65, 85)
        for i, col in enumerate(cols):
            align = 'C' if i in [1, 2, 3, 4, 5, 6] and len(cols) > 4 else 'L'
            self.cell(widths[i], 5.5, str(col), 1, 0, align, 1)
        self.ln()


def build_viva_pdf():
    pdf = FacultyVivaPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Cover Title Banner
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(10, 10, 190, 38, 'F')
    
    pdf.set_xy(15, 14)
    pdf.set_font('Helvetica', 'B', 16)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 7, 'AegisMed: Healthcare DevSecOps XAI Framework', 0, 1, 'L')
    
    pdf.set_x(15)
    pdf.set_font('Helvetica', '', 9.5)
    pdf.set_text_color(56, 189, 248)
    pdf.cell(0, 5, 'Complete Faculty Defense & Technical Examination Master Guide', 0, 1, 'L')
    
    pdf.set_x(15)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 5, 'Easy Explanation | Deep Mathematical Formulation | UI Walkthrough | Backend Code | Viva Q&A', 0, 1, 'L')
    
    pdf.set_y(52)

    # =========================================================================
    # PART 1: THE WORKING IN AN EASY MANNER
    # =========================================================================
    pdf.chapter_title('1', 'The Working in an Easy Manner (High-Level Intuition)')
    
    pdf.section_title('1.1 The Hospital Problem: Why Standard Security Tools Fail')
    pdf.body_text(
        "Imagine an airport security guard who checks luggage for knives and liquids. That guard does a great job at the airport. "
        "Now take that same guard and put them in a hospital operating room. A surgeon walks in holding a scalpel. The security guard "
        "screams, tackles the surgeon, and shuts down the hospital because 'a sharp blade was detected!' Meanwhile, a nurse leaves an "
        "unencrypted clipboard containing 5,000 cancer patient records on a public park bench outside, and the guard completely ignores it "
        "because a clipboard is not a weapon."
    )
    pdf.body_text(
        "This is exactly what happens with commercial software security tools like SonarQube, Snyk, and Checkmarx. They were built for generic "
        "e-commerce or social media websites. They do not know what a Social Security Number (SSN), Medical Record Number (MRN), or EHR vitals record is. "
        "They flood developers with 200 false warnings about harmless variables, while completely missing catastrophic legal violations like storing "
        "unencrypted patient vitals in a database or exposing patient data in application logs."
    )

    pdf.section_title('1.2 How AegisMed Works in 4 Simple Steps')
    pdf.bullet("Step 1 - Spotting the Patient Data", 
               "When a developer submits code, AegisMed scans the code like a doctor. It looks for clinical variables (SSN, MRN, patient ID, diagnosis, vitals) using the HIPAA Safe Harbor 18 statutory list.")
    pdf.bullet("Step 2 - Following Data Flow Like Colored Ink", 
               "AegisMed uses 'Taint Analysis'. Think of patient data as bright red ink. If a developer assigns x = ssn, the red ink spreads to x. If x is inserted into a database or printed in logs without encryption, AegisMed flags a critical HIPAA violation.")
    pdf.bullet("Step 3 - Consulting Real Federal Hack Records", 
               "Instead of guessing risk with arbitrary numbers, AegisMed consults 1,656 real hospital breach cases from the U.S. Department of Health and Human Services (HHS). Because the federal data proves that 46.6% of hospital breaches happen due to unencrypted data, our AI heavily penalizes unencrypted patient flows.")
    pdf.bullet("Step 4 - Finding the Minimum Fix Needed (MILP)", 
               "Traditional tools just say 'Build Failed' and leave developers stranded. AegisMed acts like a GPS navigator: it solves a mathematical puzzle (MILP) to find the absolute minimum set of code fixes required to make the software safe and unblock deployment. Then it simulates the fix and re-checks the code to guarantee the gate opens.")

    # =========================================================================
    # PART 2: TECHNICAL & MATHEMATICAL EXPLANATION
    # =========================================================================
    pdf.ln(2)
    pdf.chapter_title('2', 'Technical & Mathematical Foundations (Faculty Rigor)')
    
    pdf.section_title('2.1 AST Semantic Taint-Flow Analysis (ast.NodeVisitor)')
    pdf.body_text(
        "Source code is compiled into an Abstract Syntax Tree T = (V, E) using Python's native ast module. The analyzer traverses nodes to track dataflow:"
    )
    pdf.bullet("HIPAA Safe Harbor 18 Ontology", 
               "Identifies ePHI parameters and variables across clinical naming conventions: S_ePHI = {ssn, mrn, patient_id, diagnosis, vitals, dob, encounter, Observation, Patient, Condition}.")
    pdf.bullet("Variable Aliasing Propagation", 
               "Monitors ast.Assign nodes. If right-hand side is in tainted_vars, the left-hand symbol inherits taint (e.g., alias = ssn implies alias in T_tainted).")
    pdf.bullet("Async Route Inspection", 
               "Overrides visit_AsyncFunctionDef alongside visit_FunctionDef. Inspects FastAPI/SMART-on-FHIR route decorators to trap wildcard permission scopes (*.*).")
    pdf.bullet("Multi-Syntax SQLi Sinks", 
               "Detects SQL queries built via f-strings (f'SELECT...{ssn}'), .format() invocations, and modulo (% ssn) formatting.")
    pdf.bullet("Strict Sanitizer Verification", 
               "Validates that the tainted identifier is passed as an actual input argument to an authorized cipher (e.g., AESGCM.encrypt, kms.generate_data_key, hashlib.sha256). Superficial or dummy functions (e.g., rehash_noop('dummy')) are rejected.")

    pdf.section_title('2.2 Monotonic Gradient Boosting Risk Engine & HHS Priors')
    pdf.body_text(
        "A 10-dimensional feature vector x is extracted representing SAST criticals, SAST highs, DAST endpoints, SCA CVSS, vulnerable packages, PHI leak score, unencrypted data flows, IaC misconfigurations, compliance penalty, and domain risk weight."
    )
    pdf.bullet("Empirical Federal Priors", 
               "At initialization, _load_hhs_priors() parses datasets/hhs_major_data_breaches.csv (1,656 incidents): Theft/Loss of unencrypted data: 46.6%, Unauthorized disclosures: 26.0%, Hacking/IT: 13.2%.")
    pdf.bullet("CISA KEV Multiplier", 
               "Vulnerabilities in the CISA Known Exploited Vulnerabilities feed (e.g., CVE-2023-4863 libwebp buffer overflow) receive a 1.15x CVSS exploit multiplier.")
    pdf.bullet("Monotonic Constraints", 
               "Trained via HistGradientBoostingRegressor(monotonic_cst=[1, 1, 1, 1, 1, 1, 1, 1, 1, 0]). Guarantees df(x)/dx_i >= 0, proving mathematically that fixing a vulnerability can never counterintuitively increase risk. 5-fold CV yields R^2 = 0.962.")

    # Table of Datasets
    pdf.add_page()
    pdf.section_title('2.3 Two-Tier Cooperative Game-Theoretic Explainability (Tree-SHAP & Finding Shapley)')
    pdf.body_text(
        "AegisMed implements two distinct layers of cooperative game theory to ensure complete transparency and auditability:"
    )
    pdf.bullet("Tier 1 - Feature-Level Tree-SHAP", 
               "Uses official shap.TreeExplainer (Lundberg et al., Nature MI 2020) across all trees in the ensemble. Satisfies Local Efficiency: f(x) = E[f] + sum(phi_i) with residual error < 1e-14.")
    pdf.bullet("Tier 2 - Finding-Level Shapley Attribution", 
               "Treats each detected vulnerability finding F_j as a player in a cooperative game. Characteristic function v(S) evaluates the risk model over subset S. Computes exact Shapley blame Phi_j:")
    pdf.body_bold("       Phi_j = Sum_{S subset F \\ {j}} [ |S|!(|F| - |S| - 1)! / |F|! ] * [ v(S union {j}) - v(S) ]")
    pdf.body_text(
        "Satisfies Local Efficiency: sum(Phi_j) = v(All) - v(Empty) with zero residual. Blame is aggregated directly into statutory clauses: "
        "HIPAA Section 164.312(a)(2)(iv) (Encryption at Rest), Section 164.312(b) (Audit Controls), Section 164.312(e)(1) (Transmission Security), and FDA SaMD 524B."
    )

    pdf.section_title('2.4 Discrete MILP Counterfactual Optimizer & Closed-Loop Re-Scan')
    pdf.body_text(
        "When a deployment is BLOCKED, the system solves a 0-1 Mixed-Integer Linear Program via scipy.optimize.milp:"
    )
    pdf.body_bold("       min_{z} sum_j (c_j * z_j)   subject to   sum_j (Phi_j * z_j) >= Delta_risk   and   z_j in {0, 1}")
    pdf.body_text(
        "where c_j is remediation effort in points, and hard bounds enforce z_j = 1 for all mandatory HIPAA critical violations. "
        "Upon solving z*, the system synthesizes cryptographic patches, updates in-memory code, and performs an automated closed-loop AST re-scan. "
        "Only when the re-scan confirms zero remaining critical flows does the gate transition to APPROVED_AUTO_DEPLOY."
    )

    pdf.section_title('2.5 Empirical Benchmark Evaluation')
    pdf.body_text(
        "Formal benchmark comparison on clinical test cases (variable aliasing, async FHIR, format SQLi, and envelope encryption):"
    )
    widths = [65, 18, 18, 18, 18, 18, 22]
    pdf.table_header(['Analysis Engine', 'Prec', 'Recall', 'F1', 'FP', 'FN', 'Latency'], widths)
    pdf.table_row(['Generic Regex Matching', '0.800', '0.667', '0.727', '1', '2', '0.4 ms'], widths)
    pdf.table_row(['Generic AST Checker (Bandit)', '0.750', '0.500', '0.600', '1', '3', '0.5 ms'], widths)
    pdf.table_row(['AegisMed AST Taint-Flow (Ours)', '1.000', '1.000', '1.000', '0', '0', '0.5 ms'], widths, text_color=(16, 185, 129))
    pdf.ln(2)

    # =========================================================================
    # PART 3: WEBPAGE FEATURES & COMPONENTS WALKTHROUGH
    # =========================================================================
    pdf.chapter_title('3', 'Webpage Features & Component Walkthrough')
    pdf.body_text(
        "The AegisMed user interface is structured as a minimalist, dark slate engineering dashboard (Linear/Vercel aesthetic) "
        "organized into 5 functional tabs and high-level control headers:"
    )

    pdf.section_title('3.1 App Header & Top Navigation Controls')
    pdf.bullet("Target Scenario Selector", "Dropdown to switch between 4 healthcare scenarios: EHR Patient Portal (High Risk), SMART-on-FHIR Gateway (Async Scope/Log Leak), SaMD Imaging Worker (FDA 510k/LibWebP), and Hardened Hospital API (Clean Baseline).")
    pdf.bullet("Training Datasets Button", "Opens a modal detailing the 5 physical datasets (1,656 HHS breach records, NVD CVE feeds, and 2,500 training build matrix).")
    pdf.bullet("AWS Architecture Button", "Opens modal comparing Phase 1 (Academic single EC2 container, <$3 spend) vs Phase 2 (Enterprise Fargate + SageMaker + HealthLake).")
    pdf.bullet("Export Audit Certificate", "Generates an official printable PDF audit certificate for hospital compliance sign-off.")
    pdf.bullet("Run CI/CD Scan Button", "Triggers the full 6-stage DevSecOps assessment pipeline on the selected codebase.")

    pdf.section_title('3.2 Tab 1: Overview & Policy Gate')
    pdf.bullet("CI/CD Pipeline Tracker", "Visualizes 5 stages: Code Commit -> AST Taint Ingestion -> Statutory Mapping -> Monotonic ML/SHAP -> Policy Gate Decision.")
    pdf.bullet("Policy Gate Decision Banner", "Displays color-coded gate state: BLOCKED (red), MANUAL REVIEW (amber), or APPROVED (emerald) with specific action directives.")
    pdf.bullet("4 Key Metric Boxes", "Displays continuous AI Risk Score (0-100), Patient Breach Likelihood (%), Regulatory Penalty score, and Monotonic Model Verification R^2 (0.962).")
    pdf.bullet("Top Root-Cause Drivers", "Lists the specific vulnerabilities causing the largest upward SHAP risk impact (e.g., Unencrypted Data Flows: +38.2 pts).")
    pdf.bullet("Multi-Stakeholder Narratives", "Interactive toggle between Developer Technical Brief (file and line coordinates) and Auditor Compliance Brief (HIPAA statutory clauses).")

    pdf.section_title('3.3 Tab 2: AST Taint & Dataflow')
    pdf.bullet("Visual Dataflow Tracing Bar", "Visual breadcrumb diagram: ePHI Source -> Variable Aliasing -> Strict Sanitizer Check -> Clinical Insecure Sink.")
    pdf.bullet("Discovered Security Findings", "Card list of every finding showing ID, Severity, File/Line, Description, and statutory regulatory clause.")
    pdf.bullet("Live Custom Code Scanner", "Interactive code editor allowing developers to paste custom Python code or Dockerfiles, inspect AST rules, and scan instantaneously.")

    pdf.add_page()
    pdf.section_title('3.4 Tab 3: Two-Tier Game-Theoretic XAI')
    pdf.bullet("Tier 1 Tree-SHAP Chart", "Minimalist horizontal bar chart showing marginal positive/negative feature contributions relative to base expected risk E[f].")
    pdf.bullet("Tier 2 Finding-Level Shapley Table", "Detailed cooperative game attribution table displaying Finding ID, Type, Severity, Statutory Clause, Shapley Blame (Phi_j), and % Risk Impact.")
    pdf.bullet("Aggregated Clause Attribution", "Summary cards aggregating total points assigned to specific legal clauses (e.g., HIPAA Section 164.312(a)(2)(iv): +38.2 pts).")

    pdf.section_title('3.5 Tab 4: Discrete MILP & Remediations')
    pdf.bullet("Discrete MILP Optimization Plan", "Displays the optimal 0-1 decision vector z*, developer effort points, projected score (13.5), and Closed-Loop AST Re-Scan Verification status.")
    pdf.bullet("Interactive What-If Simulator", "Sliders for Critical SAST, Unencrypted Flows, PHI Leak Risk, and Dependency CVSS with instant debounced re-calculation.")
    pdf.bullet("Cryptographic Code Diffs", "Side-by-side Before/After code patches with unified diff formatting (AWS KMS AES-256 envelope encryption, parameterized SQL, SMART-on-FHIR scopes).")

    pdf.section_title('3.6 Tab 5: Compliance & Empirical Evidence')
    pdf.bullet("Empirical Benchmark Table", "Formal comparison table proving AegisMed's 1.000 F1 score vs 0.727 (Regex) and 0.600 (Generic AST).")
    pdf.bullet("HHS OCR Breach Statistics", "Empirical breakdown of the 1,656 federal hospital records (Theft: 46.6%, Unauthorized Disclosure: 26.0%, Hacking: 13.2%).")
    pdf.bullet("Healthcare Statutory Matrix", "Comprehensive mapping of every technical safeguard in HIPAA 45 CFR Section 164.312, FDA SaMD 524B, and HL7 FHIR.")

    # =========================================================================
    # PART 4: BACKEND CODEBASE ARCHITECTURE
    # =========================================================================
    pdf.chapter_title('4', 'Backend Codebase Architecture (File-by-File)')
    pdf.body_text(
        "The backend is implemented in Python 3.11+ using FastAPI, scikit-learn, official Tree-SHAP, and SciPy:"
    )
    pdf.bullet("backend/main.py", 
               "FastAPI application entry point. Serves API endpoints (/api/scan, /api/xai/whatif, /api/scenarios, /api/datasets/info, /api/audit/export) and mounts the static UI.")
    pdf.bullet("backend/scanner_simulator.py", 
               "HealthcareASTTaintAnalyzer inheriting from ast.NodeVisitor. Parses Safe Harbor 18 ontology, propagates taint across variable aliases, inspects visit_AsyncFunctionDef, detects format/% SQLi sinks, and performs strict sanitizer verification. Also contains SCA dependency and IaC Dockerfile scanners.")
    pdf.bullet("backend/ml_engine.py", 
               "MLRiskEngine class. Loads datasets/hhs_major_data_breaches.csv in _load_hhs_priors(). Trains HistGradientBoostingRegressor with monotonic constraints (monotonic_cst=[1,1,1,1,1,1,1,1,1,0], R^2=0.962) and Random Forest Classifier for breach probability. Ingests CISA KEV multiplier.")
    pdf.bullet("backend/xai_engine.py", 
               "XAIEngine class. Computes 10-feature Tree-SHAP via shap.TreeExplainer. Implements compute_finding_level_shapley() via coalition evaluation. Implements solve_milp_counterfactual() using scipy.optimize.milp with closed-loop AST re-scan verification.")
    pdf.bullet("backend/healthcare_compliance.py", 
               "HealthcareComplianceEngine class. Evaluates findings against HIPAA Section 164.312 (Technical Safeguards), FDA SaMD Section 524B (SBOM & vulnerability mitigation), and HL7 FHIR least-privilege scopes.")
    pdf.bullet("backend/remediation_engine.py", 
               "RemediationEngine class. Provides 9 verified cryptographic code patch templates with unified diffs, line replacements, and an optional LLM synthesis hook.")

    # =========================================================================
    # PART 5: VIVA DEFENSE CHEAT SHEET
    # =========================================================================
    pdf.add_page()
    pdf.chapter_title('5', 'Faculty Viva Defense Q&A Cheat Sheet')
    pdf.body_text(
        "Anticipated faculty evaluation questions and strategic high-scoring responses:"
    )

    qa = [
        ("Q1: What is the core novelty of your project? Why is it patentable?",
         "A: We introduce 4 genuine patentable novelties: (1) An AST semantic taint analyzer tracking ePHI from Safe Harbor 18 sources across variable aliases to sinks, with strict sanitizer argument verification; (2) An empirical ML risk model grounded on 1,656 federal HHS breach records enforcing non-decreasing monotonic constraints (df/dx_i >= 0); (3) Two-tier cooperative game theory providing exact finding-level Shapley blame (Phi_j) aggregated to HIPAA clauses; and (4) A discrete 0-1 MILP optimizer solved via scipy.optimize.milp with closed-loop AST re-scan verification."),
        
        ("Q2: How does your tool differ from SonarQube or Snyk?",
         "A: Generic tools are domain-blind. They do not recognize clinical ePHI identifiers (SSN, MRN, vitals), cannot detect taint propagation through variable aliases into unencrypted database sinks, and provide no cooperative game theory or MILP counterfactual optimization to tell developers the minimal effort required to unblock a deployment."),
        
        ("Q3: How do you prove your Shapley values are mathematically valid?",
         "A: We satisfy the Local Efficiency Axiom at both tiers: for Tree-SHAP, sum(phi_i) = f(x) - E[f] (residual < 1e-14); for finding-level Shapley, sum(Phi_j) = v(All) - v(Empty) (residual 0.000). Both are verified automatically in our 49-test pytest suite."),
        
        ("Q4: Why did you use Monotonic Constraints in your Machine Learning model?",
         "A: In standard decision trees, fixing a security vulnerability can counterintuitively increase the predicted risk score due to unconstrained tree splitting. By configuring HistGradientBoostingRegressor with monotonic_cst, we mathematically guarantee that df/dx_i >= 0 across all vulnerability features, achieving 5-fold CV R^2 = 0.962."),
        
        ("Q5: What is Closed-Loop Re-Scan Verification?",
         "A: When the MILP optimizer selects code fixes (z*), AegisMed does not rely on naive guesswork. It physically applies the cryptographic patches to the source code and re-executes the AST taint scanner. Only if the re-scan confirms that all critical flows have been eliminated and the recalculated score drops below 24.0 does the CI/CD gate transition to APPROVED_AUTO_DEPLOY."),
        
        ("Q6: How can this be deployed under a $50 AWS Learner Lab budget?",
         "A: The prototype is containerized as a single Docker container running FastAPI, scikit-learn, and Tree-SHAP. On an EC2 t2.micro or t3.micro instance, it costs ~$0.0116/hour. Running the server for an entire week of demonstrations costs less than $2.00, consuming under 4% of the $50 student credit. Our documentation provides the full roadmap to Amazon SageMaker and AWS HealthLake for enterprise hospital networks.")
    ]

    for q, a in qa:
        pdf.set_font('Helvetica', 'B', 8.5)
        pdf.set_text_color(15, 23, 42)
        pdf.multi_cell(0, 4.2, q)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(51, 65, 85)
        pdf.multi_cell(0, 3.8, a)
        pdf.ln(2)

    # Output file
    output_path = r'c:\cloud project\docs\AegisMed_Complete_Faculty_Viva_Guide.pdf'
    pdf.output(output_path, 'F')
    print(f"Successfully generated: {output_path}")

if __name__ == '__main__':
    build_viva_pdf()
