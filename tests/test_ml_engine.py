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
