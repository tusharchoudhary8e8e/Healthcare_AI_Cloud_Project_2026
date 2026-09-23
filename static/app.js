/**
 * Intelligent Healthcare DevSecOps XAI - Interactive Frontend Controller
 */

let currentScanData = null;
let shapChartInstance = null;
let activeFeatures = {};
let currentOriginalScore = 89.4;

document.addEventListener("DOMContentLoaded", () => {
    initEventListeners();
    loadScenario("ehr-patient-portal");
});

function initEventListeners() {
    // Scenario Dropdown
    document.getElementById("scenarioSelect").addEventListener("change", (e) => {
        loadScenario(e.target.value);
    });

    // Run Scan Button
    document.getElementById("btnRunScan").addEventListener("click", () => {
        const scenario = document.getElementById("scenarioSelect").value;
        loadScenario(scenario);
    });

    // Narrative View Toggles
    document.getElementById("btnDevView").addEventListener("click", () => {
        document.getElementById("btnDevView").classList.add("active");
        document.getElementById("btnComplianceView").classList.remove("active");
        document.getElementById("developerNarrativeBox").classList.remove("hidden");
        document.getElementById("complianceNarrativeBox").classList.add("hidden");
    });

    document.getElementById("btnComplianceView").addEventListener("click", () => {
        document.getElementById("btnComplianceView").classList.add("active");
        document.getElementById("btnDevView").classList.remove("active");
        document.getElementById("complianceNarrativeBox").classList.remove("hidden");
        document.getElementById("developerNarrativeBox").classList.add("hidden");
    });

    // Sliders
    const sliders = ["sast_critical", "unencrypted_data_flows", "phi_leak_risk_score", "sca_max_cvss"];
    sliders.forEach(key => {
        const slider = document.getElementById(`slider_${key}`);
        if (slider) {
            slider.addEventListener("input", (e) => {
                document.getElementById(`val_${key}`).textContent = e.target.value;
                debounceWhatIfCalculation();
            });
        }
    });

    // Reset Simulation
    document.getElementById("btnResetSimulation").addEventListener("click", () => {
        resetSlidersToCurrentScan();
    });

    // Custom Code Scanner
    document.getElementById("btnScanCustomCode").addEventListener("click", () => {
        const customCode = document.getElementById("customCodeInput").value;
        scanCustomCode(customCode);
    });

    // Export Audit Report
    document.getElementById("btnExportAudit").addEventListener("click", () => {
        const scenario = document.getElementById("scenarioSelect").value;
        window.open(`/api/audit/export?scenario_id=${scenario}`, "_blank");
    });

    // AWS Architecture Modal
    const awsModal = document.getElementById("awsModal");
    document.getElementById("btnAwsArch").addEventListener("click", () => {
        awsModal.classList.remove("hidden");
    });
    document.getElementById("btnCloseModal").addEventListener("click", () => {
        awsModal.classList.add("hidden");
    });
    document.getElementById("btnModalCloseOk").addEventListener("click", () => {
        awsModal.classList.add("hidden");
    });
    awsModal.addEventListener("click", (e) => {
        if (e.target === awsModal) awsModal.classList.add("hidden");
    });

    // Datasets Modal - handled by inline script in index.html for reliability
}

async function loadScenario(scenarioId) {
    showLoadingState();
    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario_id: scenarioId })
        });
        const data = await res.json();
        currentScanData = data;
        renderDashboard(data);
    } catch (err) {
        console.error("Failed to load scenario:", err);
        document.getElementById("gateHeadline").textContent = "Error: Could not connect to backend";
        document.getElementById("gateExplanation").textContent = "Ensure the server is running (python run_app.py) and try again.";
    }
}

async function scanCustomCode(code) {
    showLoadingState();
    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                custom_code: code,
                filename: "custom_ehr_service.py",
                domain_type: "Clinical Service"
            })
        });
        const data = await res.json();
        currentScanData = data;
        renderDashboard(data);
    } catch (err) {
        console.error("Failed to scan custom code:", err);
    }
}

function showLoadingState() {
    document.getElementById("gateHeadline").textContent = "Running AI Security Assessment...";
    document.getElementById("gateExplanation").textContent = "Ingesting SAST/DAST/SCA scanners, running Healthcare Knowledge Graph, computing SHAP values...";
}

function renderDashboard(data) {
    const meta = data.pipeline_metadata;
    const pred = data.prediction;
    const comp = data.compliance;
    const xai = data.xai;
    currentOriginalScore = pred.risk_score;

    // 1. Pipeline Header & Stage Info
    document.getElementById("pipelineServiceName").textContent = meta.service_name || "Healthcare Service";
    document.getElementById("pipelineRepo").textContent = meta.repository || "hospital-tech/ehr-service";
    document.getElementById("pipelineCommit").innerHTML = `<i class="fa-solid fa-code-commit"></i> ${meta.commit || "master"}`;
    document.getElementById("pipelineTimestamp").innerHTML = `<i class="fa-regular fa-clock"></i> ${meta.timestamp}`;
    document.getElementById("scannerCount").textContent = `${data.findings.length} Findings`;

    // 2. Gate Decision Banner & Stage
    const gateStage = document.getElementById("stageGate");
    const gatePill = document.getElementById("gatePill");
    const gateContainer = document.getElementById("gateDecisionContainer");
    const gateIcon = document.getElementById("gateIcon");

    gateStage.className = "pipeline-stage";
    gateContainer.className = "metric-card gate-decision-card glass-panel";
    gatePill.className = "gate-status-pill";

    if (pred.gate_decision === "BLOCKED") {
        gateStage.classList.add("gate-blocked");
        gatePill.classList.add("blocked");
        gatePill.textContent = "BLOCKED";
        document.getElementById("gateStageStatus").textContent = "BLOCKED";
        document.getElementById("gateHeadline").textContent = "Deployment Gated: Security Threshold Breached";
        gateIcon.innerHTML = `<i class="fa-solid fa-ban"></i>`;
    } else if (pred.gate_decision === "MANUAL_REVIEW_REQUIRED") {
        gateStage.classList.add("active");
        gatePill.classList.add("review");
        gatePill.textContent = "PAUSED (REVIEW)";
        document.getElementById("gateStageStatus").textContent = "REVIEW REQUIRED";
        document.getElementById("gateHeadline").textContent = "Manual Review Required by CISO";
        gateIcon.innerHTML = `<i class="fa-solid fa-pause"></i>`;
    } else {
        gateStage.classList.add("gate-passed");
        gateContainer.classList.add("passed");
        gatePill.classList.add("approved");
        gatePill.textContent = "APPROVED";
        document.getElementById("gateStageStatus").textContent = "PASSED";
        document.getElementById("gateHeadline").textContent = "Deployment Approved for Production";
        gateIcon.innerHTML = `<i class="fa-solid fa-circle-check"></i>`;
    }

    document.getElementById("gateExplanation").textContent = pred.gate_message;

    // 3. Score Gauges & Cards
    document.getElementById("riskScoreVal").textContent = pred.risk_score;
    const tierBadge = document.getElementById("riskTierBadge");
    tierBadge.textContent = `${pred.risk_tier} RISK TIER`;
    tierBadge.className = `score-tier tier-${pred.risk_tier.toLowerCase()}`;
    
    // Circle Gauge gradient
    const circle = document.getElementById("scoreCircle");
    const scorePct = pred.risk_score;
    const circleColor = scorePct >= 65 ? "#ef4444" : (scorePct >= 35 ? "#f59e0b" : "#10b981");
    circle.style.background = `conic-gradient(${circleColor} ${scorePct}%, rgba(255,255,255,0.06) 0)`;
    circle.style.boxShadow = `0 0 20px ${circleColor}40`;

    document.getElementById("modelConfidence").textContent = `${pred.confidence_score}%`;
    
    // Breach Prob
    const breachPct = (pred.breach_probability * 100).toFixed(1);
    document.getElementById("breachProbVal").textContent = `${breachPct}%`;
    document.getElementById("breachProgressBar").style.width = `${breachPct}%`;
    document.getElementById("breachProgressBar").className = `progress-bar ${breachPct >= 60 ? 'bg-critical' : (breachPct >= 30 ? 'bg-warning' : 'bg-green')}`;

    // Compliance Penalty
    const compPenalty = comp.scores.overall_compliance_penalty;
    document.getElementById("compliancePenaltyVal").textContent = compPenalty;
    document.getElementById("complianceProgressBar").style.width = `${compPenalty}%`;
    document.getElementById("complianceViolationsSummary").textContent = `${comp.total_violations} Regulatory Controls Flagged`;

    // 4. Render SHAP Waterfall Chart
    renderShapChart(xai.attributions);

    // 5. Narratives & Top Drivers
    document.getElementById("devNarrativeText").textContent = data.narratives.developer_summary;
    document.getElementById("complianceNarrativeText").textContent = data.narratives.compliance_officer_summary;

    const driversContainer = document.getElementById("topDriversList");
    driversContainer.innerHTML = "";
    if (xai.top_risk_drivers && xai.top_risk_drivers.length > 0) {
        xai.top_risk_drivers.forEach(d => {
            const row = document.createElement("div");
            row.className = "driver-item";
            row.innerHTML = `
                <span class="driver-name"><i class="fa-solid fa-triangle-exclamation text-critical"></i> ${d.feature_name} (Value: ${d.feature_value})</span>
                <span class="driver-impact">+${d.shap_value} SHAP pts</span>
            `;
            driversContainer.appendChild(row);
        });
    } else {
        driversContainer.innerHTML = `<div class="driver-item text-green"><i class="fa-solid fa-check"></i> Codebase complies with all baseline security thresholds.</div>`;
    }

    const compActionList = document.getElementById("complianceActionList");
    compActionList.innerHTML = "";
    if (comp.violations && comp.violations.length > 0) {
        comp.violations.forEach(v => {
            const li = document.createElement("li");
            li.innerHTML = `<b>${v.standard} ${v.control_id}</b>: ${v.reason}`;
            compActionList.appendChild(li);
        });
    } else {
        compActionList.innerHTML = `<li style="color:#10b981;">No active non-compliance items. All HIPAA and FDA controls satisfied.</li>`;
    }

    // 6. Setup Sliders & Counterfactual Presets
    activeFeatures = Object.assign({}, pred.feature_dict);
    resetSlidersToCurrentScan();
    renderCounterfactualCards(data.counterfactuals);

    // 7. Compliance Table
    renderComplianceTable(comp);

    // 8. Remediations & Code Diffs
    renderRemediations(data.remediations);
}

function renderShapChart(attributions) {
    const ctx = document.getElementById("shapChart").getContext("2d");
    if (shapChartInstance) {
        shapChartInstance.destroy();
    }

    const labels = attributions.map(a => a.feature_name);
    const dataValues = attributions.map(a => a.shap_value);
    const bgColors = attributions.map(a => a.shap_value >= 0 ? "rgba(239, 68, 68, 0.85)" : "rgba(16, 185, 129, 0.85)");
    const borderColors = attributions.map(a => a.shap_value >= 0 ? "#ef4444" : "#10b981");

    shapChartInstance = new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "SHAP Marginal Contribution",
                data: dataValues,
                backgroundColor: bgColors,
                borderColor: borderColors,
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const val = context.raw;
                            return ` Impact: ${val >= 0 ? '+' : ''}${val} points to Risk Score`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#94a3b8", font: { family: "'JetBrains Mono', monospace", size: 11 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: "#cbd5e1", font: { family: "'Plus Jakarta Sans', sans-serif", size: 12, weight: 600 } }
                }
            }
        }
    });
}

function resetSlidersToCurrentScan() {
    if (!activeFeatures) return;
    const sliders = ["sast_critical", "unencrypted_data_flows", "phi_leak_risk_score", "sca_max_cvss"];
    sliders.forEach(key => {
        const val = activeFeatures[key] || 0;
        const slider = document.getElementById(`slider_${key}`);
        if (slider) {
            slider.value = val;
            document.getElementById(`val_${key}`).textContent = val;
        }
    });
    updateWhatIfDisplay(currentOriginalScore, "BLOCKED");
}

let debounceTimer = null;
function debounceWhatIfCalculation() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(async () => {
        const overrides = Object.assign({}, activeFeatures);
        overrides["sast_critical"] = parseFloat(document.getElementById("slider_sast_critical").value);
        overrides["unencrypted_data_flows"] = parseFloat(document.getElementById("slider_unencrypted_data_flows").value);
        overrides["phi_leak_risk_score"] = parseFloat(document.getElementById("slider_phi_leak_risk_score").value);
        overrides["sca_max_cvss"] = parseFloat(document.getElementById("slider_sca_max_cvss").value);

        try {
            const res = await fetch("/api/xai/whatif", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ feature_overrides: overrides })
            });
            const data = await res.json();
            const rec = data.recalculated_prediction;
            updateWhatIfDisplay(rec.risk_score, rec.gate_decision);
        } catch (err) {
            console.error("What-If recalculation failed:", err);
        }
    }, 200);
}

function updateWhatIfDisplay(newScore, gateDecision) {
    document.getElementById("simulatedRiskScore").textContent = newScore.toFixed(1);
    const delta = currentOriginalScore - newScore;
    const deltaEl = document.getElementById("simulatedRiskDelta");
    if (delta > 0) {
        deltaEl.textContent = `-${delta.toFixed(1)} pts (Improved)`;
        deltaEl.style.color = "#10b981";
    } else if (delta < 0) {
        deltaEl.textContent = `+${Math.abs(delta).toFixed(1)} pts (Higher Risk)`;
        deltaEl.style.color = "#ef4444";
    } else {
        deltaEl.textContent = "0.0 pts";
        deltaEl.style.color = "#94a3b8";
    }

    const badge = document.getElementById("simulatedGateBadge");
    badge.textContent = gateDecision;
    if (gateDecision === "APPROVED_AUTO_DEPLOY" || gateDecision === "APPROVED_WITH_WARNINGS") {
        badge.style.background = "#10b981";
        document.getElementById("simulatedOutcomeTip").textContent = "? Fixes satisfy compliance criteria! Pipeline Gate UNBLOCKED.";
    } else {
        badge.style.background = "#ef4444";
        document.getElementById("simulatedOutcomeTip").textContent = "Adjust controls to reach Low risk tier (< 20.0) for automated production deployment.";
    }
}

function renderCounterfactualCards(scenarios) {
    const container = document.getElementById("counterfactualCardsContainer");
    container.innerHTML = "";
    if (!scenarios || scenarios.length === 0) {
        container.innerHTML = "<p style='font-size:12px;color:#94a3b8;'>No immediate counterfactuals required for clean codebase.</p>";
        return;
    }

    scenarios.forEach(sc => {
        const card = document.createElement("div");
        card.className = "cf-card";
        card.innerHTML = `
            <div class="cf-title"><i class="fa-solid fa-sparkles text-cyan"></i> ${sc.title}</div>
            <div class="cf-desc">${sc.action}</div>
            <div class="cf-impact"><i class="fa-solid fa-arrow-trend-down"></i> Drops Risk to ${sc.new_risk_score} (-${sc.risk_reduction_points} pts) &bull; Gate: <span class="badge ${sc.unblocks_pipeline ? 'badge-pass' : 'badge-warn'}">${sc.new_gate_decision}</span></div>
        `;
        card.addEventListener("click", () => {
            if (sc.id === "optimal_inverse_plan" && sc.target_features) {
                for (let k in sc.target_features) {
                    let el = document.getElementById(`slider_${k}`);
                    if (el) el.value = sc.target_features[k];
                }
            } else if (sc.id === "encrypt_phi_flow") {
                document.getElementById("slider_unencrypted_data_flows").value = 0;
                document.getElementById("slider_phi_leak_risk_score").value = 0;
            } else if (sc.id === "fix_sast_secrets") {
                document.getElementById("slider_sast_critical").value = 0;
            } else if (sc.id === "full_compliance_hardening") {
                document.getElementById("slider_sast_critical").value = 0;
                document.getElementById("slider_unencrypted_data_flows").value = 0;
                document.getElementById("slider_phi_leak_risk_score").value = 0;
                document.getElementById("slider_sca_max_cvss").value = 2.0;
            }
            const sliders = ["sast_critical", "unencrypted_data_flows", "phi_leak_risk_score", "sca_max_cvss"];
            sliders.forEach(k => {
                const el = document.getElementById(`slider_${k}`);
                const valEl = document.getElementById(`val_${k}`);
                if (el && valEl) valEl.textContent = el.value;
            });
            debounceWhatIfCalculation();
        });
        container.appendChild(card);
    });
}

function renderComplianceTable(compliance) {
    const tbody = document.getElementById("complianceTableBody");
    tbody.innerHTML = "";

    document.getElementById("hipaaRiskChip").textContent = `HIPAA Risk: ${compliance.scores.hipaa_risk_index}`;
    document.getElementById("fdaRiskChip").textContent = `FDA Risk: ${compliance.scores.fda_risk_index}`;
    document.getElementById("fhirRiskChip").textContent = `FHIR Risk: ${compliance.scores.fhir_risk_index}`;

    if (compliance.violations && compliance.violations.length > 0) {
        compliance.violations.forEach(v => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><b>${v.standard}</b></td>
                <td><span class="badge-tech">${v.control_id}</span></td>
                <td>${v.title}</td>
                <td>${v.reason}</td>
                <td><span class="${v.severity === 'CRITICAL' ? 'badge-sev-crit' : 'badge-sev-high'}">${v.severity}</span></td>
                <td><span style="color:#38bdf8;font-size:12px;"><i class="fa-solid fa-wrench"></i> ${v.file}:${v.line}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } else {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#10b981;padding:20px;"><i class="fa-solid fa-circle-check"></i> <b>All HIPAA ?164.312 and FDA SaMD Controls PASSED. Code is Compliant.</b></td></tr>`;
    }
}

function renderRemediations(remediations) {
    const container = document.getElementById("remediationTabsContainer");
    container.innerHTML = "";

    if (!remediations || remediations.length === 0) {
        container.innerHTML = "<p style='font-size:13px;color:#10b981;'><i class='fa-solid fa-circle-check'></i> No code modifications required. All cryptographic & access control safeguards are in place.</p>";
        return;
    }

    remediations.forEach(rem => {
        const card = document.createElement("div");
        card.className = "remediation-card";
        card.innerHTML = `
            <div class="rem-header">
                <div class="rem-title"><i class="fa-solid fa-shield-virus text-cyan"></i> ${rem.title}</div>
                <span class="badge-tech">${rem.impact}</span>
            </div>
            <p style="font-size:12px;color:#94a3b8;margin-bottom:10px;">${rem.description}</p>
            <div class="rem-diff-box">${escapeHtml(rem.diff)}</div>
        `;
        container.appendChild(card);
    });
}

function escapeHtml(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Global modal helpers for instant reliable clicking
window.openDatasetsModal = async function() {
    const modal = document.getElementById("datasetsModal");
    if (modal) {
        modal.classList.remove("hidden");
        try {
            const res = await fetch("/api/datasets/info");
            const d = await res.json();
            if (d && d.hhs_empirical_insights) {
                const totalEl = document.getElementById("modalHhsTotal");
                const unencEl = document.getElementById("modalUnencRate");
                if (totalEl) totalEl.textContent = d.hhs_empirical_insights.total_hospital_breaches.toLocaleString();
                if (unencEl) unencEl.textContent = d.hhs_empirical_insights.missing_encryption_rate;
            }
        } catch (err) {
            console.error("Dataset fetch error:", err);
        }
    }
};

window.closeDatasetsModal = function() {
    const modal = document.getElementById("datasetsModal");
    if (modal) {
        modal.classList.add("hidden");
    }
};
