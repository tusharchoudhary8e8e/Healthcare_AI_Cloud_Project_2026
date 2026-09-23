/**
 * AegisMed — Intelligent Healthcare DevSecOps XAI Interactive Controller
 * Minimalist, low-color, high-clarity engineering dashboard
 */

let currentScanData = null;
let shapChartInstance = null;
let activeFeatures = {};
let currentOriginalScore = 89.4;

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initEventListeners();
    loadScenario("ehr-patient-portal");
});

function initTabs() {
    const tabButtons = document.querySelectorAll(".nav-tab-btn");
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-tab");
            switchTab(targetId);
        });
    });
}

function switchTab(targetId) {
    document.querySelectorAll(".nav-tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

    const activeBtn = document.querySelector(`.nav-tab-btn[data-tab="${targetId}"]`);
    const activePane = document.getElementById(targetId);

    if (activeBtn) activeBtn.classList.add("active");
    if (activePane) activePane.classList.add("active");

    // Resize chart if switching to XAI tab
    if (targetId === "tab-xai" && shapChartInstance) {
        setTimeout(() => shapChartInstance.resize(), 50);
    }
}

function initEventListeners() {
    // Scenario Select
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
        document.getElementById("developerNarrativeBox").style.display = "block";
        document.getElementById("complianceNarrativeBox").style.display = "none";
    });

    document.getElementById("btnComplianceView").addEventListener("click", () => {
        document.getElementById("btnComplianceView").classList.add("active");
        document.getElementById("btnDevView").classList.remove("active");
        document.getElementById("complianceNarrativeBox").style.display = "block";
        document.getElementById("developerNarrativeBox").style.display = "none";
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

    // Modals
    setupModal("btnDatasets", "datasetsModal", ["btnCloseDatasetsModal", "btnModalCloseDatasetsOk"]);
    setupModal("btnAwsArch", "awsModal", ["btnCloseModal", "btnModalCloseOk"]);
}

function setupModal(triggerBtnId, modalId, closeBtnIds) {
    const trigger = document.getElementById(triggerBtnId);
    const modal = document.getElementById(modalId);
    if (!trigger || !modal) return;

    trigger.addEventListener("click", () => {
        modal.classList.remove("hidden");
    });

    closeBtnIds.forEach(id => {
        const btn = document.getElementById(id);
        if (btn) {
            btn.addEventListener("click", () => modal.classList.add("hidden"));
        }
    });

    modal.addEventListener("click", (e) => {
        if (e.target === modal) modal.classList.add("hidden");
    });
}

async function loadScenario(scenarioId) {
    showLoadingState();
    let data;
    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario_id: scenarioId })
        });
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        data = await res.json();
    } catch (netErr) {
        console.error("Failed to connect to backend:", netErr);
        document.getElementById("gateHeadline").textContent = "Error: Could not connect to backend";
        document.getElementById("gateExplanation").textContent = "Ensure the server is running (python run_app.py) and try again.";
        return;
    }

    try {
        currentScanData = data;
        renderDashboard(data);
    } catch (renderErr) {
        console.error("Dashboard rendering error:", renderErr);
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
        switchTab("tab-ast");
    } catch (err) {
        console.error("Failed to scan custom code:", err);
    }
}

function showLoadingState() {
    document.getElementById("gateHeadline").textContent = "Running AI Security Assessment...";
    document.getElementById("gateExplanation").textContent = "Parsing AST taint flows, checking variable aliases & sanitizers, computing finding-level Shapley & MILP...";
}

function renderDashboard(data) {
    const meta = data.pipeline_metadata;
    const pred = data.prediction;
    const comp = data.compliance;
    const xai = data.xai;
    currentOriginalScore = pred.risk_score;

    // =========================================================================
    // 1. Pipeline Header & Stage Info
    // =========================================================================
    document.getElementById("pipelineServiceName").textContent = meta.service_name || "Healthcare Service";
    document.getElementById("pipelineRepo").textContent = meta.repository || "hospital-tech/ehr-service";
    document.getElementById("pipelineCommit").innerHTML = `<i class="fa-solid fa-code-commit"></i> ${meta.commit || "main"}`;
    document.getElementById("pipelineTimestamp").innerHTML = `<i class="fa-regular fa-clock"></i> ${meta.timestamp}`;
    document.getElementById("scannerCount").textContent = `${data.findings.length} Findings`;
    document.getElementById("tabFindingsCount").textContent = `${data.findings.length} findings`;

    // =========================================================================
    // 2. Gate Decision Banner & Stage Nodes
    // =========================================================================
    const gateStage = document.getElementById("stageGate");
    const gatePill = document.getElementById("gatePill");
    const gateContainer = document.getElementById("gateDecisionContainer");
    const gateIcon = document.getElementById("gateIcon");

    gateStage.className = "stage-node";
    gateContainer.className = "policy-gate-banner";
    gatePill.className = "gate-badge-pill";

    if (pred.gate_decision === "BLOCKED") {
        gateStage.classList.add("blocked");
        gateContainer.classList.add("blocked");
        gatePill.classList.add("blocked");
        gatePill.textContent = "BLOCKED";
        document.getElementById("gateStageStatus").textContent = "BLOCKED";
        document.getElementById("gateHeadline").textContent = "Deployment Blocked: Security Threshold Breached";
        gateIcon.innerHTML = `<i class="fa-solid fa-ban"></i>`;
    } else if (pred.gate_decision === "MANUAL_REVIEW_REQUIRED") {
        gateStage.classList.add("review");
        gateContainer.classList.add("review");
        gatePill.classList.add("review");
        gatePill.textContent = "MANUAL REVIEW";
        document.getElementById("gateStageStatus").textContent = "REVIEW";
        document.getElementById("gateHeadline").textContent = "Manual Review Required by Clinical CISO";
        gateIcon.innerHTML = `<i class="fa-solid fa-pause"></i>`;
    } else {
        gateStage.classList.add("passed");
        gateContainer.classList.add("passed");
        gatePill.classList.add("passed");
        gatePill.textContent = "APPROVED";
        document.getElementById("gateStageStatus").textContent = "PASSED";
        document.getElementById("gateHeadline").textContent = "Deployment Approved for Production Auto-Deploy";
        gateIcon.innerHTML = `<i class="fa-solid fa-circle-check"></i>`;
    }

    document.getElementById("gateExplanation").textContent = pred.gate_message;

    // =========================================================================
    // 3. 4 Main Metric Cards
    // =========================================================================
    document.getElementById("riskScoreVal").textContent = pred.risk_score.toFixed(1);
    const tierBadge = document.getElementById("riskTierBadge");
    tierBadge.textContent = `${pred.risk_tier} RISK`;

    const scoreFill = document.getElementById("riskScoreBar");
    scoreFill.style.width = `${pred.risk_score}%`;
    scoreFill.className = `progress-fill ${pred.risk_score >= 60 ? 'fill-critical' : (pred.risk_score >= 25 ? 'fill-warning' : 'fill-success')}`;

    // Breach Prob
    const breachPct = (pred.breach_probability * 100).toFixed(1);
    document.getElementById("breachProbVal").textContent = `${breachPct}%`;
    document.getElementById("breachProgressBar").style.width = `${breachPct}%`;
    document.getElementById("breachProgressBar").className = `progress-fill ${breachPct >= 60 ? 'fill-critical' : (breachPct >= 30 ? 'fill-warning' : 'fill-success')}`;

    // Compliance Penalty
    const compPenalty = comp.scores.overall_compliance_penalty;
    document.getElementById("compliancePenaltyVal").textContent = compPenalty.toFixed(1);
    document.getElementById("complianceProgressBar").style.width = `${Math.min(100, compPenalty)}%`;
    document.getElementById("complianceViolationsSummary").textContent = `${comp.total_violations} Regulatory Controls Flagged`;

    // Model CV Metrics
    if (pred.model_metrics && pred.model_metrics["5_fold_cv_r2_mean"]) {
        document.getElementById("modelCvR2Val").textContent = pred.model_metrics["5_fold_cv_r2_mean"].toFixed(3);
    }

    // =========================================================================
    // 4. Narratives & Top Drivers
    // =========================================================================
    document.getElementById("devNarrativeText").textContent = data.narratives.developer_summary;
    document.getElementById("complianceNarrativeText").textContent = data.narratives.compliance_officer_summary;

    const driversContainer = document.getElementById("topDriversList");
    driversContainer.innerHTML = "";
    if (xai.top_risk_drivers && xai.top_risk_drivers.length > 0) {
        xai.top_risk_drivers.forEach(d => {
            const row = document.createElement("div");
            row.className = "driver-item-row";
            row.innerHTML = `
                <span class="driver-name"><i class="fa-solid fa-triangle-exclamation text-critical"></i> ${d.feature_name} (Val: ${d.feature_value})</span>
                <span class="driver-shap-impact">+${d.shap_value.toFixed(1)} pts</span>
            `;
            driversContainer.appendChild(row);
        });
    } else {
        driversContainer.innerHTML = `<div class="driver-item-row text-success"><i class="fa-solid fa-check"></i> Codebase complies with all baseline security thresholds.</div>`;
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
        compActionList.innerHTML = `<li style="color:#34d399;">No active non-compliance items. All HIPAA and FDA controls satisfied.</li>`;
    }

    // =========================================================================
    // 5. AST Semantic Taint & Findings
    // =========================================================================
    renderAstFindings(data.findings);

    // =========================================================================
    // 6. Two-Tier Game-Theoretic XAI (Tree-SHAP + Finding Shapley)
    // =========================================================================
    renderShapChart(xai.attributions);
    renderFindingLevelShapley(xai.finding_shapley);

    // =========================================================================
    // 7. Discrete MILP & Counterfactual Remediations
    // =========================================================================
    activeFeatures = Object.assign({}, pred.feature_dict);
    resetSlidersToCurrentScan();
    renderMilpPlan(data.counterfactuals);
    renderRemediations(data.remediations);

    // =========================================================================
    // 8. Compliance Matrix
    // =========================================================================
    renderComplianceTable(comp);
}

function renderAstFindings(findings) {
    const container = document.getElementById("astFindingsList");
    container.innerHTML = "";

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="panel" style="padding: 16px; text-align: center; color: var(--status-success);">
                <i class="fa-solid fa-circle-check" style="font-size: 20px; margin-bottom: 6px;"></i>
                <div>Zero AST taint flow findings detected. All patient data paths are cryptographically enclosed.</div>
            </div>
        `;
        return;
    }

    findings.forEach(f => {
        const card = document.createElement("div");
        const isCrit = f.severity === "CRITICAL";
        card.className = `finding-card ${isCrit ? 'critical' : 'high'}`;
        card.innerHTML = `
            <div class="finding-header-row">
                <div>
                    <span class="badge-tag" style="margin-right: 6px;">${f.id || 'AST-FINDING'}</span>
                    <span class="finding-title-text">${f.title}</span>
                </div>
                <span class="badge-tag ${isCrit ? 'text-critical' : 'text-warning'}">${f.severity}</span>
            </div>
            <div class="finding-detail-text">${f.detail || 'Dataflow taint reaches insecure execution sink.'}</div>
            <div class="finding-footer-meta">
                <span><i class="fa-solid fa-file-code"></i> ${f.file || 'service.py'}:${f.line || 1}</span>
                <span>&bull;</span>
                <span><i class="fa-solid fa-tag"></i> Type: <b>${f.type}</b></span>
                <span>&bull;</span>
                <span><i class="fa-solid fa-layer-group"></i> Source: <b>${f.source || 'SAST'}</b></span>
            </div>
        `;
        container.appendChild(card);
    });
}

function renderShapChart(attributions) {
    const ctx = document.getElementById("shapChart").getContext("2d");
    if (shapChartInstance) {
        shapChartInstance.destroy();
    }

    const labels = attributions.map(a => a.feature_name);
    const dataValues = attributions.map(a => a.shap_value);
    const bgColors = attributions.map(a => a.shap_value >= 0 ? "rgba(248, 113, 113, 0.75)" : "rgba(52, 211, 153, 0.75)");
    const borderColors = attributions.map(a => a.shap_value >= 0 ? "#f87171" : "#34d399");

    shapChartInstance = new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "SHAP Marginal Impact",
                data: dataValues,
                backgroundColor: bgColors,
                borderColor: borderColors,
                borderWidth: 1,
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
                            return ` Impact: ${val >= 0 ? '+' : ''}${val.toFixed(2)} pts to Risk Score`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#94a3b8", font: { family: "'JetBrains Mono', monospace", size: 10 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: "#cbd5e1", font: { family: "'Plus Jakarta Sans', sans-serif", size: 11, weight: 600 } }
                }
            }
        }
    });
}

function renderFindingLevelShapley(findingShapley) {
    const tbody = document.getElementById("findingShapleyTableBody");
    tbody.innerHTML = "";

    if (!findingShapley || !findingShapley.finding_attributions || findingShapley.finding_attributions.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:16px; color:#34d399;"><i class="fa-solid fa-circle-check"></i> Zero excess finding risk. Baseline risk only.</td></tr>`;
        document.getElementById("totalExcessRiskVal").textContent = "Total Excess Finding Risk: 0.0 pts";
        return;
    }

    const totalExcess = findingShapley.total_excess_finding_risk || 0;
    document.getElementById("totalExcessRiskVal").textContent = `Total Excess Finding Risk: +${totalExcess.toFixed(1)} pts`;

    findingShapley.finding_attributions.forEach(f => {
        const phi = f.finding_shapley_value || 0;
        const pct = totalExcess > 0 ? ((phi / totalExcess) * 100).toFixed(1) : "0.0";
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="font-mono"><b>${f.finding_id}</b></td>
            <td><b>${f.finding_type}</b></td>
            <td><span class="badge-tag ${f.severity === 'CRITICAL' ? 'text-critical' : 'text-warning'}">${f.severity}</span></td>
            <td>${f.statutory_clause}</td>
            <td style="text-align: right;" class="font-mono text-critical"><b>+${phi.toFixed(2)} pts</b></td>
            <td style="text-align: right;" class="font-mono text-muted">${pct}%</td>
        `;
        tbody.appendChild(tr);
    });

    // Clause Aggregations
    const clauseContainer = document.getElementById("clauseAttributionContainer");
    clauseContainer.innerHTML = "";
    if (findingShapley.clause_attributions) {
        for (let [clause, val] of Object.entries(findingShapley.clause_attributions)) {
            const box = document.createElement("div");
            box.className = "panel";
            box.style.padding = "10px 14px";
            box.innerHTML = `
                <div style="font-size: 11px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">${clause}</div>
                <div class="font-mono text-critical" style="font-size: 15px; font-weight: 800;">+${val.toFixed(1)} pts</div>
            `;
            clauseContainer.appendChild(box);
        }
    }
}

function renderMilpPlan(counterfactuals) {
    const box = document.getElementById("milpPlanDetailsBox");
    box.innerHTML = "";

    if (!counterfactuals || counterfactuals.length === 0) {
        box.innerHTML = `<p style="color: var(--status-success);"><i class="fa-solid fa-circle-check"></i> Pipeline is in an approved state. No MILP optimization required.</p>`;
        return;
    }

    const milpCf = counterfactuals[0];
    const isVerified = milpCf.closed_loop_verified;

    const badge = document.getElementById("closedLoopBadge");
    if (isVerified) {
        badge.className = "badge-tag badge-tag-green";
        badge.innerHTML = `<i class="fa-solid fa-circle-check"></i> Closed-Loop AST Re-Scan Verified: Gate Passes`;
    } else {
        badge.className = "badge-tag";
        badge.innerHTML = `<i class="fa-solid fa-clock"></i> Closed-Loop Verification Pending`;
    }

    const planDiv = document.createElement("div");
    planDiv.innerHTML = `
        <div class="grid-2col" style="margin-bottom: 14px;">
            <div class="panel" style="padding: 12px; background: var(--bg-base);">
                <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Optimization Method</div>
                <div style="font-size: 13px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">
                    Mixed-Integer Linear Programming (<code>scipy.optimize.milp</code>)
                </div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
                    Enforces 0-1 binary integrality with HIPAA zero-tolerance hard equality bounds (<code>z<sub>j</sub> = 1</code>).
                </div>
            </div>
            <div class="panel" style="padding: 12px; background: var(--bg-base); display: flex; align-items: center; justify-content: space-around;">
                <div style="text-align: center;">
                    <div style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Current Score</div>
                    <div class="font-mono text-critical" style="font-size: 20px; font-weight: 800;">${currentOriginalScore.toFixed(1)}</div>
                </div>
                <i class="fa-solid fa-arrow-right text-muted"></i>
                <div style="text-align: center;">
                    <div style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Projected Score</div>
                    <div class="font-mono text-success" style="font-size: 20px; font-weight: 800;">${milpCf.new_risk_score.toFixed(1)}</div>
                </div>
                <div style="text-align: center;">
                    <div style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Projected Gate</div>
                    <span class="gate-badge-pill passed" style="font-size: 10px; padding: 3px 8px;">${milpCf.new_gate_decision}</span>
                </div>
            </div>
        </div>

        <div style="font-size: 12px; font-weight: 700; margin-bottom: 8px; color: var(--text-primary);">
            Minimal Developer Remediation Actions Selected by MILP:
        </div>
        <div style="display: flex; flex-direction: column; gap: 6px;">
            ${(milpCf.action ? (typeof milpCf.action === "string" ? milpCf.action.split("; ") : milpCf.action) : []).map(a => `
                <div class="panel" style="padding: 10px 14px; background: var(--bg-base); display: flex; align-items: center; justify-content: space-between; font-size: 12px;">
                    <span><i class="fa-solid fa-check text-success" style="margin-right: 8px;"></i> ${a}</span>
                    <span class="badge-tag badge-tag-blue font-mono">z<sub>j</sub> = 1 (Active)</span>
                </div>
            `).join('')}
        </div>
    `;
    box.appendChild(planDiv);
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
    }, 150);
}

function updateWhatIfDisplay(newScore, gateDecision) {
    document.getElementById("simulatedRiskScore").textContent = newScore.toFixed(1);
    const delta = currentOriginalScore - newScore;
    const deltaEl = document.getElementById("simulatedRiskDelta");
    if (delta > 0) {
        deltaEl.textContent = `-${delta.toFixed(1)} pts (Improved)`;
        deltaEl.style.color = "var(--status-success)";
    } else if (delta < 0) {
        deltaEl.textContent = `+${Math.abs(delta).toFixed(1)} pts (Higher Risk)`;
        deltaEl.style.color = "var(--status-critical)";
    } else {
        deltaEl.textContent = "0.0 pts";
        deltaEl.style.color = "var(--text-muted)";
    }

    const badge = document.getElementById("simulatedGateBadge");
    badge.textContent = gateDecision;
    badge.className = `gate-badge-pill ${gateDecision === 'APPROVED_AUTO_DEPLOY' || gateDecision === 'APPROVED_WITH_WARNINGS' ? 'passed' : 'blocked'}`;

    if (gateDecision === "APPROVED_AUTO_DEPLOY" || gateDecision === "APPROVED_WITH_WARNINGS") {
        document.getElementById("simulatedOutcomeTip").textContent = "✓ Fixes satisfy statutory thresholds! CI/CD Gate UNBLOCKED.";
    } else {
        document.getElementById("simulatedOutcomeTip").textContent = "Adjust controls to reach Low risk tier (< 24.0) to auto-deploy.";
    }
}

function renderRemediations(remediations) {
    const container = document.getElementById("remediationTabsContainer");
    container.innerHTML = "";

    if (!remediations || remediations.length === 0) {
        container.innerHTML = "<p style='font-size:12px;color:var(--status-success);'><i class='fa-solid fa-circle-check'></i> No code modifications required. All safeguards are verified.</p>";
        return;
    }

    remediations.forEach(rem => {
        const card = document.createElement("div");
        card.className = "diff-card";
        card.innerHTML = `
            <div class="diff-header">
                <div><i class="fa-solid fa-shield-halved text-blue" style="margin-right: 6px;"></i> ${rem.title}</div>
                <span class="badge-tag">${rem.impact}</span>
            </div>
            <div style="padding: 10px 14px; font-size: 12px; color: var(--text-secondary); background: var(--bg-surface); border-bottom: 1px solid var(--border-subtle);">
                ${rem.description}
            </div>
            <pre class="diff-box">${escapeHtml(rem.diff)}</pre>
        `;
        container.appendChild(card);
    });
}

function renderComplianceTable(compliance) {
    const tbody = document.getElementById("complianceTableBody");
    tbody.innerHTML = "";

    if (compliance.violations && compliance.violations.length > 0) {
        compliance.violations.forEach(v => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><b>${v.standard}</b></td>
                <td><span class="badge-tag font-mono">${v.control_id}</span></td>
                <td>${v.title}</td>
                <td>${v.reason}</td>
                <td><span class="badge-tag ${v.severity === 'CRITICAL' ? 'text-critical' : 'text-warning'}">${v.severity}</span></td>
                <td class="font-mono text-blue">${v.file}:${v.line}</td>
            `;
            tbody.appendChild(tr);
        });
    } else {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--status-success);padding:18px;"><i class="fa-solid fa-circle-check"></i> <b>All HIPAA §164.312 and FDA SaMD Safeguards PASSED. Code is Compliant.</b></td></tr>`;
    }
}

function escapeHtml(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
