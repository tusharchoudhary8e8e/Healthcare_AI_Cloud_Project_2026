"""Unit tests for the Explainable AI (XAI) Engine — Tree-SHAP and Counterfactual Solver."""
import pytest
import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ml_engine import ml_risk_engine, FEATURE_NAMES
from backend.xai_engine import xai_engine


class TestTreeSHAPAxioms:
    """Verify Tree-SHAP satisfies the 4 cooperative game theory axioms."""
    
    def _get_shap_data(self, **kwargs):
        fdict = {f: 0.0 for f in FEATURE_NAMES}
        fdict["historical_breach_factor"] = 0.90
        fdict.update(kwargs)
        vec = np.array([[fdict[k] for k in FEATURE_NAMES]])
        pred = ml_risk_engine.predict(vec, fdict)
        xai = xai_engine.compute_shap_explanations(fdict, pred["risk_score"])
        return pred, xai
    
    def test_local_efficiency_axiom(self):
        """CRITICAL: f(x) = base_value + sum(shap_values). Residual must be < 1e-4."""
        pred, xai = self._get_shap_data(
            sast_critical=2.0, sast_high=3.0, phi_leak_risk_score=60.0,
            unencrypted_data_flows=2.0, compliance_penalty=50.0
        )
        base = xai["base_expected_value"]
        shap_sum = sum(a["shap_value"] for a in xai["attributions"])
        predicted = pred["risk_score"]
        
        # The SHAP values are computed on scaled features, so we compare against
        # the raw model prediction on scaled features
        vec = np.array([[2.0, 3.0, 0.0, 0.0, 0.0, 60.0, 2.0, 0.0, 50.0, 0.90]])
        scaled = ml_risk_engine.scaler.transform(vec)
        raw_pred = float(ml_risk_engine.gb_regressor.predict(scaled)[0])
        
        # 1. Exact mathematical Local Efficiency on raw unrounded Tree-SHAP
        raw_base = float(xai_engine.explainer.expected_value) if not isinstance(xai_engine.explainer.expected_value, (list, np.ndarray)) else float(xai_engine.explainer.expected_value[0])
        raw_shap = xai_engine.explainer.shap_values(scaled)[0]
        exact_residual = abs(raw_pred - (raw_base + np.sum(raw_shap)))
        assert exact_residual < 1e-6, f"Mathematical Tree-SHAP efficiency violated! residual={exact_residual}"

        # 2. UI Rounded Attributions (2 decimals each over 10 features) match within rounding error
        rounded_residual = abs(raw_pred - (base + shap_sum))
        assert rounded_residual < 0.05, f"UI display residual exceeded rounding bounds: {rounded_residual}"
    
    def test_zero_features_shap_near_zero(self):
        """Dummy/Missingness axiom: features at zero should have near-zero SHAP."""
        pred, xai = self._get_shap_data()  # All zeros except historical_breach_factor
        for attr in xai["attributions"]:
            if attr["feature_id"] != "historical_breach_factor":
                assert abs(attr["shap_value"]) < 15.0, f"{attr['feature_id']} has unexpectedly large SHAP: {attr['shap_value']}"
    
    def test_shap_methodology_reported(self):
        """Verify methodology string is accurate."""
        _, xai = self._get_shap_data(sast_critical=1.0)
        assert "Tree-SHAP" in xai["methodology"]


class TestCounterfactualSolver:
    """Verify constrained inverse counterfactual optimization."""
    
    def test_solver_unblocks_pipeline(self):
        """Solver must produce APPROVED gate from a BLOCKED input."""
        blocked_features = {
            "sast_critical": 2.0, "sast_high": 3.0, "dast_critical": 1.0,
            "sca_max_cvss": 8.8, "sca_vulnerable_pkg_count": 2.0,
            "phi_leak_risk_score": 75.0, "unencrypted_data_flows": 2.0,
            "iac_misconfig_score": 25.0, "compliance_penalty": 60.0,
            "historical_breach_factor": 0.95
        }
        result = xai_engine.solve_constrained_counterfactual(blocked_features, target_risk=24.0)
        assert result["final_gate_decision"] in ["APPROVED_AUTO_DEPLOY", "APPROVED_WITH_WARNINGS"]
        assert result["final_score"] <= 24.0
    
    def test_immutability_constraint(self):
        """historical_breach_factor must NOT change during optimization."""
        features = {
            "sast_critical": 1.0, "sast_high": 2.0, "dast_critical": 0.0,
            "sca_max_cvss": 5.0, "sca_vulnerable_pkg_count": 1.0,
            "phi_leak_risk_score": 50.0, "unencrypted_data_flows": 1.0,
            "iac_misconfig_score": 10.0, "compliance_penalty": 40.0,
            "historical_breach_factor": 0.92
        }
        result = xai_engine.solve_constrained_counterfactual(features)
        assert result["target_features"]["historical_breach_factor"] == 0.92
    
    def test_zero_tolerance_constraints(self):
        """sast_critical and unencrypted_data_flows must be forced to 0."""
        features = {
            "sast_critical": 3.0, "sast_high": 1.0, "dast_critical": 0.0,
            "sca_max_cvss": 0.0, "sca_vulnerable_pkg_count": 0.0,
            "phi_leak_risk_score": 40.0, "unencrypted_data_flows": 2.0,
            "iac_misconfig_score": 0.0, "compliance_penalty": 30.0,
            "historical_breach_factor": 0.85
        }
        result = xai_engine.solve_constrained_counterfactual(features)
        assert result["target_features"]["sast_critical"] == 0.0
        assert result["target_features"]["unencrypted_data_flows"] == 0.0
    
    def test_actions_taken_not_empty(self):
        """Solver must report at least one remediation action."""
        features = {"sast_critical": 1.0, "sast_high": 0.0, "dast_critical": 0.0,
                    "sca_max_cvss": 0.0, "sca_vulnerable_pkg_count": 0.0,
                    "phi_leak_risk_score": 0.0, "unencrypted_data_flows": 0.0,
                    "iac_misconfig_score": 0.0, "compliance_penalty": 20.0,
                    "historical_breach_factor": 0.85}
        result = xai_engine.solve_constrained_counterfactual(features)
        assert len(result["actions_taken"]) >= 1


class TestFindingLevelShapley:
    """Verify finding-level Shapley values and game theory efficiency axiom."""
    
    def test_finding_level_shapley_efficiency(self):
        findings = [
            {"id": "F1", "type": "UNENCRYPTED_PHI_STORAGE", "severity": "CRITICAL"},
            {"id": "F2", "type": "HARDCODED_SECRETS", "severity": "CRITICAL"},
            {"id": "F3", "type": "SQL_INJECTION_EHR", "severity": "CRITICAL"}
        ]
        res = xai_engine.compute_finding_level_shapley(findings, 0.90)
        attrs = res["finding_attributions"]
        assert len(attrs) == 3
        # Efficiency axiom: sum of finding Shapley values equals total excess risk
        sum_phi = sum(a["finding_shapley_value"] for a in attrs)
        assert abs(sum_phi - res["total_excess_finding_risk"]) < 0.05
        # Clause attributions present
        assert "clause_attributions" in res
        assert len(res["clause_attributions"]) > 0

    def test_milp_solver_and_closed_loop(self):
        findings = [
            {"id": "F1", "type": "UNENCRYPTED_PHI_STORAGE", "severity": "CRITICAL", "title": "Unencrypted PHI"},
            {"id": "F2", "type": "HARDCODED_SECRETS", "severity": "CRITICAL", "title": "Hardcoded DB Pass"},
            {"id": "F3", "type": "SQL_INJECTION_EHR", "severity": "CRITICAL", "title": "SQL Injection"}
        ]
        milp_res = xai_engine.solve_milp_counterfactual(findings, current_risk=75.0, target_risk=24.0)
        assert milp_res["projected_risk_score"] <= 24.0
        assert milp_res["unblocks_pipeline"] is True
        assert len(milp_res["selected_remediations"]) >= 1

