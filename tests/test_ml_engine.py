"""Unit tests for the ML Risk Assessment Engine."""
import pytest
import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ml_engine import ml_risk_engine, FEATURE_NAMES, DevSecOpsMLRiskModel


class TestModelTraining:
    """Verify the ML model trains successfully from dataset."""
    
    def test_model_is_trained(self):
        assert ml_risk_engine.is_trained is True
    
    def test_feature_count(self):
        assert len(FEATURE_NAMES) == 10
    
    def test_scaler_fitted(self):
        assert hasattr(ml_risk_engine.scaler, 'mean_')


class TestGateDecisions:
    """Verify risk tier and gate decision thresholds."""
    
    def _predict(self, **kwargs):
        fdict = {f: 0.0 for f in FEATURE_NAMES}
        fdict["historical_breach_factor"] = 0.85
        fdict.update(kwargs)
        vec = np.array([[fdict[k] for k in FEATURE_NAMES]])
        return ml_risk_engine.predict(vec, fdict)
    
    def test_clean_baseline_approved(self):
        """Zero vulnerabilities should be approved."""
        pred = self._predict()
        assert pred["gate_decision"] in ["APPROVED_AUTO_DEPLOY", "APPROVED_WITH_WARNINGS"]
    
    def test_critical_sast_always_blocked(self):
        """Any sast_critical > 0 must block, regardless of risk score."""
        pred = self._predict(sast_critical=1.0)
        assert pred["gate_decision"] == "BLOCKED"
        assert pred["risk_tier"] == "CRITICAL"
    
    def test_high_phi_leak_blocked(self):
        """phi_leak_risk_score >= 80 must block."""
        pred = self._predict(phi_leak_risk_score=85.0)
        assert pred["gate_decision"] == "BLOCKED"
    
    def test_risk_score_bounded(self):
        """Risk score must be in [0, 100]."""
        pred = self._predict(sast_critical=5.0, sast_high=5.0, dast_critical=3.0,
                             sca_max_cvss=9.8, phi_leak_risk_score=100.0,
                             unencrypted_data_flows=3.0, compliance_penalty=100.0)
        assert 0.0 <= pred["risk_score"] <= 100.0


class TestFeatureExtraction:
    """Verify feature extraction from scan data."""
    
    def test_extract_from_findings(self):
        scan_data = {
            "findings": [
                {"source": "SAST", "severity": "CRITICAL", "type": "SQL_INJECTION_EHR"},
                {"source": "SAST", "severity": "HIGH", "type": "HARDCODED_SECRETS"},
                {"source": "SCA", "severity": "CRITICAL", "type": "CRITICAL_CVE_DEPENDENCY", "cvss": 8.8},
            ],
            "domain_risk_weight": 0.95
        }
        compliance = {"scores": {"overall_compliance_penalty": 45.0}}
        vec, fdict = ml_risk_engine.extract_features(scan_data, compliance)
        
        assert fdict["sast_critical"] == 1.0
        assert fdict["sast_high"] == 1.0
        assert fdict["sca_max_cvss"] == 8.8
        assert fdict["compliance_penalty"] == 45.0
        assert vec.shape == (1, 10)


class TestMonotonicityAndPriors:
    """Verify monotonic constraints (adding findings can never decrease risk) and HHS priors."""
    
    def test_hhs_priors_loaded(self):
        priors = ml_risk_engine.hhs_empirical_priors
        assert "total_hhs_cases" in priors
        assert priors["total_hhs_cases"] >= 1600
        assert priors["theft_unencrypted_prior"] > 0.40
        assert priors["calibrated_weight_unencrypted"] > 15.0

    def test_model_cv_metrics(self):
        metrics = ml_risk_engine.model_metrics
        assert "5_fold_cv_r2_mean" in metrics
        assert metrics["5_fold_cv_r2_mean"] > 0.85
        assert metrics["monotonic_constraints_enforced"] is True

    def test_monotonicity_property(self):
        """Property-based verification: increasing vulnerability counts never decreases predicted score."""
        baseline_dict = {f: 0.0 for f in FEATURE_NAMES}
        baseline_dict["historical_breach_factor"] = 0.85
        base_vec = np.array([[baseline_dict[k] for k in FEATURE_NAMES]])
        base_pred = ml_risk_engine.predict(base_vec, baseline_dict)["risk_score"]
        
        # Test increasing each of the 9 actionable features
        for feat in FEATURE_NAMES[:9]:
            inc_dict = dict(baseline_dict)
            inc_dict[feat] = 3.0 if "count" in feat or "sast" in feat or "dast" in feat or "flows" in feat else 25.0
            inc_vec = np.array([[inc_dict[k] for k in FEATURE_NAMES]])
            inc_pred = ml_risk_engine.predict(inc_vec, inc_dict)["risk_score"]
            assert inc_pred >= base_pred, f"Monotonicity violated for feature {feat}: {inc_pred} < {base_pred}"

