# AWS Cloud Architecture & Deployment Guide: Academic Learner Lab to Enterprise
## Intelligent DevSecOps Risk Assessment Framework for Healthcare Delivery using XAI

---

## 1. Executive Summary & Two-Phase Strategy

Deploying cloud architectures for healthcare software requires balancing **regulatory compliance (HIPAA & FDA SaMD)** with **hosting cost realities**. 

To satisfy both immediate academic defense requirements under an **AWS Learner Lab ($50 credit limit)** and the long-term vision of an **Enterprise Hospital System**, this architecture is structured in two distinct phases:

```
+-----------------------------------------------------------------------------------------+
| PHASE 1: ACADEMIC DEFENSE & AWS LEARNER LAB ($50 BUDGET)                               |
| Single-Instance Containerized Architecture (Amazon EC2 t2/t3 / AWS App Runner)          |
| Total Cost: < $3.00 USD (Leaves $47+ of Learner Lab Credit Intact)                     |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v  (Enterprise Roadmap)
+-----------------------------------------------------------------------------------------+
| PHASE 2: ENTERPRISE MULTI-HOSPITAL HEALTHCARE NETWORK                                  |
| Multi-AZ Fargate + SageMaker Serverless Inference + Neptune Graph + AWS HealthLake      |
| Production SLA: <2.0s Gate Latency, Multi-Region Disaster Recovery, HIPAA BAA           |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Phase 1: AWS Learner Lab Deployment ($50 Budget Limit)

### 2.1 Feasibility & Cost Calculation in AWS Learner Lab
**Can this project be deployed under the $50 AWS Learner Lab budget?**  
**YES — with an estimated spend of under $3.00 for the entire evaluation period.**

| AWS Resource | Configuration | Hourly Rate | Estimated Usage | Total Cost (USD) |
|---|---|---|---|---|
| **Amazon EC2** | `t2.micro` or `t3.micro` (1 vCPU, 1 GB RAM) | $0.0116 / hr | 40 hours of active testing | **$0.46** |
| **Amazon EBS Storage** | 10 GB General Purpose SSD (gp3) | $0.08 / GB-month | 1 month | **$0.80** |
| **Data Transfer** | Outbound Web Traffic | Free up to 100 GB | 1 GB | **$0.00** |
| **Total Estimated Spend** | | | | **~$1.26 USD** |
| **Remaining Learner Lab Credit** | | | | **$48.74 USD (Safe)** |

### 2.2 Learner Lab Constraints Handled
1. **IAM Role Restriction:** AWS Learner Lab prevents creating custom IAM Roles. Our deployment attaches to the pre-existing **`LabRole`** automatically provided by AWS Academy.
2. **Blocked Services:** Expensive managed services (Amazon Neptune at $1.50/hr, AWS HealthLake, or multi-model SageMaker endpoints) are intentionally not deployed in Phase 1 to prevent draining the $50 credit. Instead, the container packages the FastAPI middleware, trained scikit-learn models, Tree-SHAP explainer, and AST taint engine into a single optimized Docker image.

### 2.3 Step-by-Step Deployment Instructions on AWS Learner Lab

#### Step 1: Start AWS Learner Lab & Launch EC2
1. Log into your **AWS Academy Learner Lab** console and click **Start Lab**.
2. Navigate to the **Amazon EC2 Console**.
3. Click **Launch Instance**:
   - **Name:** `AegisMed-Healthcare-DevSecOps`
   - **OS:** Ubuntu Server 22.04 LTS or Amazon Linux 2023.
   - **Instance Type:** `t2.micro` or `t3.micro` (Free Tier / Learner Lab approved).
   - **Key Pair:** Create or select an existing `.pem` key pair.
   - **IAM Instance Profile:** Select `LabRole`.
   - **Network Settings / Security Group:**
     - Allow SSH (Port 22) from your IP.
     - Allow Custom TCP (Port 8000) from Anywhere (`0.0.0.0/0`).
     - Allow HTTP (Port 80) from Anywhere (`0.0.0.0/0`).
4. Click **Launch Instance**.

#### Step 2: Connect to EC2 and Setup Environment
Connect via SSH or EC2 Instance Connect in your browser:
```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Python 3.11 and Docker
sudo apt install -y python3-pip python3-venv git docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu
```

#### Step 3: Deploy via Docker (Recommended)
```bash
# Clone project repository
git clone <YOUR_REPO_URL> aegismed
cd aegismed

# Build Docker Container
sudo docker build -t aegismed-app .

# Run Container on Port 80
sudo docker run -d \
  --name aegismed \
  --restart unless-stopped \
  -p 80:8000 \
  aegismed-app
```

#### Step 4: Access the Live Dashboard
Open your web browser and navigate to:
```
http://<YOUR-EC2-PUBLIC-IP>
```
The full interactive DevSecOps dashboard will load, with real-time AST code scanning, Tree-SHAP attributions, counterfactual What-If simulations, and audit export capabilities.

---

## 3. Phase 2: Enterprise Reference Cloud Architecture

When scaling from an academic prototype to a Level-1 Trauma Center or Regional Hospital System, the microservice separates into a multi-AZ enterprise cloud architecture:

```
+------------------------------------------------------------------------------------------+
|                               DEVELOPER / CI/CD ZONE                                     |
|                                                                                          |
|   [Developer Git Push] ---> [AWS CodeCommit / GitHub Enterprise]                         |
|                                      | (Webhook Trigger)                                 |
|                                      v                                                   |
|                      [AWS CodePipeline Orchestrator]                                     |
|                                      |                                                   |
|                                      v                                                   |
|                    [AWS CodeBuild (Multi-Scanner Tasks)]                                 |
|                      * SAST: AST Taint Analyzer (ePHI / SQLi Rules)                      |
|                      * DAST: OWASP ZAP (TLS & Endpoint checks)                           |
|                      * SCA:  Trivy / Grype (SBOM & CVEs)                                 |
|                      * IaC:  Checkov (K8s & S3 Policies)                                 |
+------------------------------------------------------------------------------------------+
                                       | Raw Scan Telemetry (JSON)
                                       v
+------------------------------------------------------------------------------------------+
|                     INTELLIGENT XAI INFERENCE & GOVERNANCE LAYER                         |
|                                                                                          |
|   +----------------------------------------------------------------------------------+   |
|   | Amazon API Gateway (Private VPC Endpoint + Mutual TLS 1.3)                       |   |
|   +----------------------------------------------------------------------------------+   |
|                                          |                                               |
|                                          v                                               |
|   +----------------------------------------------------------------------------------+   |
|   | Amazon ECS Fargate (AegisMed FastAPI Engine across 3 AZs)                        |   |
|   |   * Ingests Multi-Scanner Findings & Vectorizes 10-D Features                    |   |
|   |   * Computes Tree-SHAP Shapley Attributions                                      |   |
|   |   * Solves Constrained Inverse Optimization for Minimal Remediation              |   |
|   +----------------------------------------------------------------------------------+   |
|           |                               |                               |              |
|           v                               v                               v              |
|   [Amazon SageMaker]            [Amazon Neptune Graph]         [AWS Security Hub]        |
|   Serverless Endpoint           HIPAA §164.312 / FDA           Centralized DevSecOps     |
|   Model Registry & Drift        Ontology Graph                 Compliance Posture        |
+------------------------------------------------------------------------------------------+
            | Gate Decision (BLOCK / APPROVE)                              |
            v                                                              v
+----------------------------------------+        +----------------------------------------+
|      CI/CD GATING & REMEDIATION        |        |        HEALTHCARE DATA SERVICES        |
|                                        |        |                                        |
|  * BLOCKED: Fail pipeline + Comment    |        |  * AWS HealthLake (FHIR Datastore)     |
|    PR with SHAP diff & KMS patch       |        |  * AWS KMS (FIPS 140-2 Envelope Enc)   |
|  * APPROVED: Promote container image   |        |  * AWS Secrets Manager (Auto Rotation) |
|    to Amazon ECR -> Deploy to EKS      |        |  * Amazon CloudWatch & CloudTrail      |
+----------------------------------------+        +----------------------------------------+
```

---

## 4. Enterprise AWS Service Roles & Mapping

| AWS Service | Architecture Layer | Specific Enterprise Responsibility | Healthcare / Compliance Relevance |
|---|---|---|---|
| **AWS CodePipeline** | CI/CD Orchestration | Manages build stages: Source $\rightarrow$ Test $\rightarrow$ Multi-Scan $\rightarrow$ AI Gate $\rightarrow$ Staging $\rightarrow$ Prod. | Enforces automated gate blocking before release. |
| **AWS CodeBuild** | Pipeline Scanners | Runs ephemeral Docker containers executing AST scanners and SBOM generators. | Isolated, zero-persistence build sandbox. |
| **Amazon SageMaker** | AI & XAI Engine | Hosts the Random Forest + Gradient Boosting risk model & Tree-SHAP explainer. | Serverless inference with auto-scaling & model versioning. |
| **Amazon Neptune** | Compliance Graph | Stores OWL/RDF knowledge graph linking code flaws to HIPAA & FDA controls. | Fast graph traversal across regulations and software modules. |
| **AWS Security Hub** | Security Aggregation | Ingests vulnerability findings in AWS Security Finding Format (ASFF). | Centralized visibility for Hospital CISO. |
| **AWS HealthLake** | Healthcare Data Store | Managed HIPAA-eligible FHIR datastore for clinical health records. | Strict SMART-on-FHIR authorization policies. |
| **AWS KMS (Key Management)** | Cryptographic Core | Stores Customer Master Keys (CMKs) for AES-256-GCM envelope encryption. | Satisfies HIPAA §164.312(a)(2)(iv) at-rest encryption. |
| **AWS Secrets Manager** | Identity & Auth | Secure storage & rotation for clinical DB passwords & API credentials. | Eliminates hardcoded passwords in Git repositories. |
| **Amazon S3 (Object Lock)** | Audit & SBOM Store | Stores raw scan logs, SBOM manifests, and signed audit certificates. | Versioned, immutable storage satisfying FDA 21 CFR Part 11. |
| **Amazon CloudWatch & CloudTrail** | Audit & Telemetry | Records all pipeline events, API requests, and gating decisions. | Immutable audit logs satisfying HIPAA §164.312(b). |
| **Amazon ECS (Fargate)** | Application Hosting | Runs the FastAPI DevSecOps middleware and dashboard web application. | Serverless container execution with zero OS maintenance. |

---

## 5. Summary for Viva & Defense

When presenting this architecture to academic evaluators or industry reviewers:
1. **Highlight Cost-Consciousness:** Explicitly state that Phase 1 was containerized to run on a single EC2 instance for **under $3.00**, respecting educational credit limits in AWS Learner Lab without compromising algorithmic rigor.
2. **Highlight Algorithmic Parity:** Emphasize that the exact same Python AST Taint Analyzer, scikit-learn models, Tree-SHAP explainer, and Constrained Inverse Optimizer run identically locally, on EC2, and in enterprise Fargate containers.
3. **Highlight Enterprise Scalability:** Point to Phase 2 to demonstrate your understanding of enterprise cloud scalability, high availability across 3 AZs, and native integration with HIPAA-eligible AWS services.
