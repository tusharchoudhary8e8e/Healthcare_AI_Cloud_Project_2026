"""
Machine Learning Risk Assessment Engine
Ensemble model (RandomForest + GradientBoosting) trained on Healthcare Vulnerability and Breach Indicators.
"""
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, Tuple

FEATURE_NAMES = [
    "sast_critical",
    "sast_high",
    "dast_critical",
    "sca_max_cvss",
    "sca_vulnerable_pkg_count",
    "phi_leak_risk_score",
    "unencrypted_data_flows",
    "iac_misconfig_score",
    "compliance_penalty",
    "historical_breach_factor"
]

class DevSecOpsMLRiskModel:
    def __init__(self):
        self.rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=6)
        self.gb_regressor = GradientBoostingRegressor(n_estimators=100, random_state=42, max_depth=4)
        self.scaler = StandardScaler()
        self.is_trained = False
        self._train_synthetic_baseline()
        
    def _train_synthetic_baseline(self):
        """Loads or creates the 2,500 healthcare vulnerability records from the datasets directory."""
        import csv
        csv_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "datasets", "healthcare_devsecops_cicd_benchmark_dataset.csv")
        
        if os.path.exists(csv_file):
            X_rows = []
            y_score_rows = []
            y_class_rows = []
            with open(csv_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    feat_row = [float(r[k]) for k in FEATURE_NAMES]
                    X_rows.append(feat_row)
                    y_score_rows.append(float(r["predicted_risk_score"]))
                    y_class_rows.append(int(r["breach_incident_label"]))
            X = np.array(X_rows)
            y_score = np.array(y_score_rows)
            y_class = np.array(y_class_rows)
        else:
            np.random.seed(42)
            n_samples = 2500
            sast_crit = np.random.poisson(lam=0.8, size=n_samples)
            sast_high = np.random.poisson(lam=1.5, size=n_samples)
            dast_crit = np.random.poisson(lam=0.5, size=n_samples)
            sca_cvss = np.random.uniform(0.0, 10.0, size=n_samples)
            sca_pkgs = np.random.poisson(lam=2.0, size=n_samples)
            phi_leak = np.random.uniform(0.0, 100.0, size=n_samples)
            unenc_flows = np.random.choice([0, 1, 2, 3], size=n_samples, p=[0.5, 0.3, 0.15, 0.05])
            iac_score = np.random.uniform(0.0, 50.0, size=n_samples)
            comp_penalty = np.random.uniform(0.0, 100.0, size=n_samples)
            hist_factor = np.random.uniform(0.5, 1.0, size=n_samples)
            X = np.column_stack([
                sast_crit, sast_high, dast_crit, sca_cvss, sca_pkgs,
                phi_leak, unenc_flows, iac_score, comp_penalty, hist_factor
            ])
        
            # Calculate ground-truth latent risk based on healthcare risk domain mechanics
            latent_risk = (
                sast_crit * 22.0 +
                sast_high * 10.0 +
                dast_crit * 20.0 +
                (sca_cvss >= 7.5) * (sca_cvss * 2.5) +
                sca_pkgs * 3.0 +
                (phi_leak / 100.0) * 30.0 +
                unenc_flows * 18.0 +
                (iac_score / 50.0) * 15.0 +
                (comp_penalty / 100.0) * 35.0
            ) * hist_factor
            y_score = np.clip(latent_risk / 1.6, 0.0, 100.0)
            y_class = (y_score >= 60.0).astype(int)
        
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        self.rf_classifier.fit(X_scaled, y_class)
        self.gb_regressor.fit(X_scaled, y_score)
        self.is_trained = True
        
    def extract_features(self, scan_data: Dict[str, Any], compliance_data: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, float]]:
        findings = scan_data.get("findings", [])
        
        sast_crit = sum(1 for f in findings if f.get("source") == "SAST" and f.get("severity") == "CRITICAL")
        sast_high = sum(1 for f in findings if f.get("source") == "SAST" and f.get("severity") == "HIGH")
        dast_crit = sum(1 for f in findings if f.get("source") == "DAST" and f.get("severity") in ["CRITICAL", "HIGH"])
        
        sca_findings = [f for f in findings if f.get("source") == "SCA"]
        sca_max_cvss = max([f.get("cvss", 0.0) for f in sca_findings], default=0.0)
        sca_vulnerable_pkg_count = len(sca_findings)
        
        phi_leak_risk_score = 0.0
        if any(f.get("type") == "PHI_IN_LOGS" for f in findings):
            phi_leak_risk_score += 45.0
        if any(f.get("type") == "UNENCRYPTED_PHI_STORAGE" for f in findings):
            phi_leak_risk_score += 55.0
        phi_leak_risk_score = min(100.0, phi_leak_risk_score)
        
        unencrypted_data_flows = sum(1 for f in findings if f.get("type") in ["UNENCRYPTED_TRANSMISSION", "UNENCRYPTED_PHI_STORAGE"])
        iac_misconfigs = sum(1 for f in findings if f.get("source") == "IaC") * 25.0
        iac_misconfig_score = min(50.0, iac_misconfigs)
        
        comp_penalty = compliance_data.get("scores", {}).get("overall_compliance_penalty", 0.0)
        hist_factor = float(scan_data.get("domain_risk_weight", 0.90))
        
        feature_dict = {
            "sast_critical": float(sast_crit),
            "sast_high": float(sast_high),
            "dast_critical": float(dast_crit),
            "sca_max_cvss": float(sca_max_cvss),
            "sca_vulnerable_pkg_count": float(sca_vulnerable_pkg_count),
            "phi_leak_risk_score": float(phi_leak_risk_score),
            "unencrypted_data_flows": float(unencrypted_data_flows),
            "iac_misconfig_score": float(iac_misconfig_score),
            "compliance_penalty": float(comp_penalty),
            "historical_breach_factor": float(hist_factor)
        }
        
        feature_vector = np.array([[feature_dict[k] for k in FEATURE_NAMES]])
        return feature_vector, feature_dict

    def predict(self, feature_vector: np.ndarray, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        X_scaled = self.scaler.transform(feature_vector)
        
        # Predict breach probability & risk score
        prob_class = self.rf_classifier.predict_proba(X_scaled)[0]
        breach_prob = float(prob_class[1]) if len(prob_class) > 1 else float(prob_class[0])
        raw_score = float(self.gb_regressor.predict(X_scaled)[0])
        risk_score = min(100.0, max(0.0, round(raw_score, 1)))
        
        # Categorize Risk Tier & Pipeline Gate Decision
        if risk_score >= 75.0 or feature_dict["sast_critical"] > 0 or feature_dict["phi_leak_risk_score"] >= 80.0:
            risk_tier = "CRITICAL"
            gate_decision = "BLOCKED"
            gate_badge = "FAIL"
            gate_message = "Deployment Blocked: High probability of HIPAA/Patient Data Breach. Remediation required."
        elif risk_score >= 45.0:
            risk_tier = "HIGH"
            gate_decision = "MANUAL_REVIEW_REQUIRED"
            gate_badge = "WARNING"
            gate_message = "Deployment Paused: Requires CISO / Healthcare Security Officer Sign-off."
        elif risk_score >= 20.0:
            risk_tier = "MEDIUM"
            gate_decision = "APPROVED_WITH_WARNINGS"
            gate_badge = "PASS_WARN"
            gate_message = "Approved for Staging with advisory security alerts."
        else:
            risk_tier = "LOW"
            gate_decision = "APPROVED_AUTO_DEPLOY"
            gate_badge = "PASS"
            gate_message = "Deployment Approved: Code meets HIPAA & FDA Cybersecurity baselines."
            
        global_importances = dict(zip(FEATURE_NAMES, [round(float(v), 4) for v in self.rf_classifier.feature_importances_]))
        
        return {
            "risk_score": risk_score,
            "breach_probability": round(breach_prob, 3),
            "risk_tier": risk_tier,
            "gate_decision": gate_decision,
            "gate_badge": gate_badge,
            "gate_message": gate_message,
            "confidence_score": round(max(prob_class) * 100, 1),
            "global_feature_importances": global_importances,
            "feature_dict": feature_dict
        }

ml_risk_engine = DevSecOpsMLRiskModel()
