async function runSampZapScan() {
            const selectEl = document.getElementById("samp-assessment-select");
            if (!selectEl) return;
            const assessmentId = selectEl.value;
            if (!assessmentId) {
                alert("Please select an assessment session first.");
                return;
            }

            const targetUrl = document.getElementById("zap-target-url").value.trim();
            if (!targetUrl) {
                alert("Please enter a valid target URL.");
                return;
            }

            const term = document.getElementById("zap-terminal");
            term.innerHTML = `<div class="terminal-line info" style="color: #38bdf8;">[SYSTEM] Initiating scan for: ${targetUrl}...</div>`;

            const usePython = (typeof window !== "undefined" && window.location && window.location.protocol && window.location.protocol.startsWith("http"));
            if (usePython) {
                try {
                    term.innerHTML += `<div class="terminal-line info" style="color: #38bdf8;">[ZAP] Request dispatched. Handshaking with automated client...</div>`;
                    const res = await apiPost('/api/scanners/audit', {
                        target_url: targetUrl,
                        assessment_id: parseInt(assessmentId, 10)
                    });

                    if (res && res.success) {
                        term.innerHTML += `<div class="terminal-line info" style="color: #38bdf8;">[HTTP HEADERS] Ingestion complete.</div>`;
                        if (res.scans && res.scans.http_headers && res.scans.http_headers.report) {
                            Object.entries(res.scans.http_headers.report).forEach(([code, report]) => {
                                const col = report.passed ? "#16a34a" : "#dc2626";
                                term.innerHTML += `<div class="terminal-line" style="color: ${col};">[HTTP HEADERS] ${code}: ${report.passed ? 'PASS' : 'FAIL'} - ${report.details}</div>`;
                            });
                        }

                        term.innerHTML += `<div class="terminal-line info" style="color: #38bdf8;">[ZAP VULNERABILITIES] Ingestion complete.</div>`;
                        if (res.scans && res.scans.zap_vulnerabilities && res.scans.zap_vulnerabilities.alerts) {
                            res.scans.zap_vulnerabilities.alerts.forEach(alert => {
                                const col = alert.risk === 'High' ? "#dc2626" : alert.risk === 'Medium' ? "#f59e0b" : "#3b82f6";
                                term.innerHTML += `<div class="terminal-line" style="color: ${col};">[ZAP] Alert: ${alert.alert} (${alert.risk}) - ${alert.description}</div>`;
                            });
                        }

                        term.innerHTML += `<div class="terminal-line info" style="color: #16a34a;">[SYSTEM] Scan completed successfully. Evidence registered and signed!</div>`;

                        // Re-evaluate assessment findings to map new evidence
                        term.innerHTML += `<div class="terminal-line info" style="color: #38bdf8;">[SYSTEM] Re-evaluating checklist findings...</div>`;
                        await apiPost(`/api/checklist/evaluate/${assessmentId}`);

                        // Reload checklist and findings UI
                        handleSampAssessmentChange();

                        const riskSelect = document.getElementById("risk-assessment-select");
                        if (riskSelect && riskSelect.value === assessmentId) {
                            handleRiskAssessmentChange();
                        }

                        alert("Security audit scan complete! Automated findings updated.");
                    } else {
                        const errMsg = res ? res.message || res.detail : "Unknown scan error";
                        term.innerHTML += `<div class="terminal-line error" style="color: #dc2626;">[ERROR] Scan execution failed: ${errMsg}</div>`;
                        alert(`Scan failed: ${errMsg}`);
                    }
                } catch (err) {
                    console.error(err);
                    term.innerHTML += `<div class="terminal-line error" style="color: #dc2626;">[ERROR] System fault during audit: ${err.message}</div>`;
                    alert(`Scan failed: ${err.message}`);
                }
            } else {
                // Offline / file:// mock implementation
                term.innerHTML += `<div class="terminal-line info" style="color: #38bdf8;">[OFFLINE] Simulation mode active. Running offline checks...</div>`;
                setTimeout(async () => {
                    term.innerHTML += `<div class="terminal-line" style="color: #16a34a;">[HTTP HEADERS] CTRL-001: PASS - HSTS Header exists.</div>`;
                    term.innerHTML += `<div class="terminal-line" style="color: #dc2626;">[HTTP HEADERS] CTRL-002: FAIL - Missing secure flags.</div>`;
                    term.innerHTML += `<div class="terminal-line" style="color: #f59e0b;">[ZAP] Alert: Content Security Policy Header Not Set (Medium)</div>`;
                    term.innerHTML += `<div class="terminal-line" style="color: #16a34a;">[SYSTEM] Offline scan complete. Mocks updated in local evidence store.</div>`;

                    const evidence = localDB.getEvidence();
                    const collected_at_str = new Date().toISOString();

                    evidence.push({
                        id: evidence.length + 1,
                        assessment_id: parseInt(assessmentId, 10),
                        source: "HTTP_CHECK",
                        raw_data: "CTRL-001 Status: PASS Details: HSTS Header exists.\nCTRL-002 Status: FAIL Details: Missing secure flags.",
                        hash_signature: "mock_sha256_" + Math.random().toString(36).substring(2, 15),
                        collected_at: collected_at_str,
                        is_verified: true,
                        created_at: collected_at_str
                    });

                    evidence.push({
                        id: evidence.length + 1,
                        assessment_id: parseInt(assessmentId, 10),
                        source: "ZAP",
                        raw_data: "ZAP Alert: Content Security Policy Header Not Set Severity: Medium Vulnerability Details: CSP missing.\nZAP Alert: Missing Anti-Clickjacking Header Severity: Medium Vulnerability Details: X-Frame-Options not found.",
                        hash_signature: "mock_sha256_" + Math.random().toString(36).substring(2, 15),
                        collected_at: collected_at_str,
                        is_verified: true,
                        created_at: collected_at_str
                    });

                    localDB.saveEvidence(evidence);

                    await apiPost(`/api/checklist/evaluate/${assessmentId}`);
                    handleSampAssessmentChange();

                    const riskSelect = document.getElementById("risk-assessment-select");
                    if (riskSelect && riskSelect.value === assessmentId) {
                        handleRiskAssessmentChange();
                    }

                    alert("Offline scan simulation complete! Findings updated.");
                }, 1500);
            }
        }

        async function exportSampReport(format) {
            const selectEl = document.getElementById("samp-assessment-select");
            if (!selectEl) return;
            const assessmentId = selectEl.value;
            if (!assessmentId) {
                alert("Please select an assessment session first.");
                return;
            }

            logToTerminal(`[SAMP Auditor] Fetching and exporting compliance report in ${format.toUpperCase()} format...`);
            const endpoint = `/api/reports/${assessmentId}/${format}`;
            const usePython = (typeof window !== "undefined" && window.location && window.location.protocol && window.location.protocol.startsWith("http"));
            if (usePython) {
                try {
                    const response = await fetch(endpoint);
                    if (!response.ok) throw new Error("Network response was not ok");
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `SAMP_Report_Assessment_${assessmentId}.${format === 'pdf' ? 'pdf' : format === 'html' ? 'html' : 'json'}`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    window.URL.revokeObjectURL(url);
                    logToTerminal(`[SAMP Auditor] ${format.toUpperCase()} report exported successfully.`, "info");
                } catch (err) {
                    console.error(err);
                    logToTerminal(`[SAMP Auditor Error] Failed to export report: ${err.message}`, "error");
                    alert(`Failed to export report: ${err.message}`);
                }
            } else {
                let reportData = {};
                if (format === 'json') {
                    reportData = {
                        assessment_id: assessmentId,
                        status: "OFFLINE_REPORT",
                        generated_at: new Date().toISOString(),
                        findings: sampFindings
                    };
                } else if (format === 'html') {
                    reportData = `
                    <html>
                    <head><title>SAMP Compliance Report (Offline)</title></head>
                    <body style="font-family: sans-serif; padding: 20px; background: #0f172a; color: #f8fafc;">
                        <h1>SAMP Offline Compliance Report</h1>
                        <p>Assessment ID: ${assessmentId}</p>
                        <p>Generated at: ${new Date().toISOString()}</p>
                        <hr/>
                        <h2>Checklist Findings</h2>
                        <ul>
                            ${sampFindings.map(f => `<li><strong>${f.control_code}</strong>: ${f.status} - ${f.details}</li>`).join('')}
                        </ul>
                    </body>
                    </html>`;
                } else {
                    alert("PDF generation is not supported in offline (file://) mode. Please run with Python backend.");
                    return;
                }

                const blob = new Blob([format === 'json' ? JSON.stringify(reportData, null, 2) : reportData], { type: format === 'json' ? 'application/json' : 'text/html' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `SAMP_Report_Assessment_${assessmentId}_Offline.${format}`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
                logToTerminal(`[SAMP Auditor] Offline ${format.toUpperCase()} report exported successfully.`, "info");
            }
        }

        async function exportSampFindingsData() {
            const selectEl = document.getElementById("samp-assessment-select");
            if (!selectEl) return;
            const assessmentId = selectEl.value;
            if (!assessmentId) {
                alert("Please select an assessment session first.");
                return;
            }

            logToTerminal(`[SAMP Auditor] Fetching assessment session #${assessmentId} findings for data export...`);
            const res = await apiGet(`/api/assessments/${assessmentId}`);
            if (!res) {
                alert("Failed to fetch assessment data for export.");
                return;
            }

            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(res, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", `samp_assessment_${assessmentId}_data.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
            logToTerminal(`[SAMP Auditor] Assessment data exported successfully.`, "info");
        }

        function importSampFindingsData(event) {
            const file = event.target.files[0];
            if (!file) return;
            const selectEl = document.getElementById("samp-assessment-select");
            const assessmentId = selectEl.value;
            if (!assessmentId) {
                alert("Please select an assessment session first to import findings into.");
                return;
            }

            const reader = new FileReader();
            reader.onload = async function (e) {
                try {
                    const data = JSON.parse(e.target.result);
                    const findings = data.findings || (Array.isArray(data) ? data : []);
                    if (findings.length === 0) {
                        alert("No findings found in the imported file.");
                        return;
                    }

                    logToTerminal(`[SAMP Auditor] Importing ${findings.length} findings into assessment #${assessmentId}...`);
                    let successCount = 0;

                    for (const importedFinding of findings) {
                        const currentFinding = sampFindings.find(f => f.control_code === importedFinding.control_code);
                        if (currentFinding) {
                            const status = importedFinding.status || "FAIL";
                            const details = importedFinding.details || "";
                            const rec = importedFinding.recommendation || "";

                            const url = `/api/assessments/findings/${currentFinding.id}?status=${status}&details=${encodeURIComponent(details)}&recommendation=${encodeURIComponent(rec)}`;
                            const res = await apiPost(url, {}, 'PUT');
                            if (res && res.id) {
                                successCount++;
                            }
                        }
                    }

                    logToTerminal(`[SAMP Auditor] Successfully imported and updated ${successCount} findings.`, "info");
                    alert(`Successfully imported ${successCount} findings.`);
                    handleSampAssessmentChange();

                    const riskSelect = document.getElementById("risk-assessment-select");
                    if (riskSelect && riskSelect.value === assessmentId) {
                        handleRiskAssessmentChange();
                    }

                    event.target.value = "";
                } catch (err) {
                    console.error(err);
                    logToTerminal(`[SAMP Auditor] Failed to import findings: ${err.message}`, "error");
                    alert("Failed to parse file. Ensure it is a valid assessment JSON export.");
                }
            };
            reader.readAsText(file);
        }

        function toggleSidebarGroup(groupName) {
            const groups = ["siem", "risk", "samp", "reconciler"];
            groups.forEach(g => {
                const submenu = document.getElementById(`submenu-${g}`);
                const header = document.getElementById(`group-header-${g}`);
                if (submenu) {
                    if (g === groupName) {
                        submenu.style.display = "block";
                        if (header) header.classList.add("active");
                    } else {
                        submenu.style.display = "none";
                        if (header) header.classList.remove("active");
                    }
                }
            });
        }

        let activeAssessmentsList = [];
        let selectedAssessmentDetails = null;
        let sampFindings = [];
        let sampActiveControlIndex = 0;
        const manualControlCodes = ["CTRL-011", "CTRL-012", "CTRL-013", "CTRL-014", "CTRL-015"];

        async function loadAssessmentsForSelectors() {
            const res = await apiGet('/api/assessments');
            if (res && Array.isArray(res)) {
                if (res.length === 0) {
                    logToTerminal("[Database Manager] Seeding default Enterprise Audit assessment...");
                    const seedRes = await apiPost('/api/assessments', {
                        name: "AM/NS Enterprise Audit 2026",
                        environment: "Production"
                    });
                    if (seedRes && seedRes.id) {
                        loadAssessmentsForSelectors();
                    }
                    return;
                }

                activeAssessmentsList = res;

                const riskSelect = document.getElementById("risk-assessment-select");
                const sampSelect = document.getElementById("samp-assessment-select");

                if (riskSelect && sampSelect) {
                    riskSelect.innerHTML = "";
                    sampSelect.innerHTML = "";

                    res.forEach(a => {
                        const opt1 = document.createElement("option");
                        opt1.value = a.id;
                        opt1.innerText = `${a.name} (${a.environment})`;
                        riskSelect.appendChild(opt1);

                        const opt2 = document.createElement("option");
                        opt2.value = a.id;
                        opt2.innerText = `${a.name} (${a.environment})`;
                        sampSelect.appendChild(opt2);
                    });

                    handleRiskAssessmentChange();
                    handleSampAssessmentChange();
                }
            }
        }

        async function handleRiskAssessmentChange() {
            const selectEl = document.getElementById("risk-assessment-select");
            if (!selectEl) return;
            const assessmentId = selectEl.value;
            if (!assessmentId) return;

            const res = await apiGet(`/api/assessments/${assessmentId}`);
            if (res) {
                selectedAssessmentDetails = res;

                const envSelect = document.getElementById("risk-env-select");
                if (envSelect) {
                    envSelect.value = res.environment || "Production";
                }

                const scoreValEl = document.getElementById("risk-score-value");
                const ratingEl = document.getElementById("risk-rating-label");
                if (scoreValEl && ratingEl) {
                    if (res.overall_score !== null && res.overall_score !== undefined) {
                        scoreValEl.innerText = `${res.overall_score}%`;

                        if (res.overall_score >= 90) {
                            scoreValEl.style.color = "var(--status-low)";
                            ratingEl.innerText = "LOW COMPLIANCE RISK";
                            ratingEl.style.color = "var(--status-low)";
                        } else if (res.overall_score >= 70) {
                            scoreValEl.style.color = "var(--status-medium)";
                            ratingEl.innerText = "MEDIUM COMPLIANCE RISK";
                            ratingEl.style.color = "var(--status-medium)";
                        } else {
                            scoreValEl.style.color = "var(--status-critical)";
                            ratingEl.innerText = "HIGH/CRITICAL COMPLIANCE RISK";
                            ratingEl.style.color = "var(--status-critical)";
                        }
                    } else {
                        scoreValEl.innerText = "--";
                        ratingEl.innerText = "UNSCORED / PENDING EVALUATION";
                        ratingEl.style.color = "var(--text-secondary)";
                    }
                }

                renderRiskFindingsTable(res.findings || []);
            }
        }

        function renderRiskFindingsTable(findings) {
            const tbody = document.getElementById("risk-findings-tbody");
            if (!tbody) return;
            tbody.innerHTML = "";

            if (!findings || findings.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No findings evaluated yet. Click 'Calculate Risk Score'.</td></tr>`;
                return;
            }

            const sorted = [...findings].sort((a, b) => {
                if (a.status === b.status) return a.control_code.localeCompare(b.control_code);
                return a.status === 'FAIL' ? -1 : 1;
            });

            sorted.forEach(f => {
                const tr = document.createElement("tr");
                const baseSeverities = {
                    "CTRL-001": "HIGH", "CTRL-002": "MEDIUM", "CTRL-003": "HIGH", "CTRL-004": "LOW",
                    "CTRL-005": "LOW", "CTRL-006": "HIGH", "CTRL-007": "LOW", "CTRL-008": "LOW",
                    "CTRL-009": "HIGH", "CTRL-010": "HIGH", "CTRL-011": "HIGH", "CTRL-012": "MEDIUM",
                    "CTRL-013": "HIGH", "CTRL-014": "MEDIUM", "CTRL-015": "HIGH"
                };
                const baseSev = baseSeverities[f.control_code] || f.severity;

                tr.innerHTML = `
                    <td style="font-weight: 700; font-family: var(--font-mono); color: var(--text-primary);">${f.control_code}</td>
                    <td style="color: var(--text-primary); font-weight: 600;">${f.control_title}</td>
                    <td><span class="badge" style="font-size: 0.65rem; border-color: var(--border-clean); color: var(--text-secondary); background: transparent;">${baseSev}</span></td>
                    <td><span class="badge ${f.severity === 'HIGH' ? 'status-critical-bg' : f.severity === 'MEDIUM' ? 'status-medium-bg' : 'status-low-bg'}" style="font-size: 0.65rem;">${f.severity}</span></td>
                    <td><span class="badge ${f.status === 'PASS' ? 'status-low-bg' : 'status-critical-bg'}" style="font-size: 0.65rem; border-radius: 3px; font-weight: 800; padding: 0.2rem 0.5rem;">${f.status}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function triggerRiskCalculation() {
            const selectEl = document.getElementById("risk-assessment-select");
            if (!selectEl) return;
            const assessmentId = selectEl.value;
            if (!assessmentId) return;

            const env = document.getElementById("risk-env-select").value;

            logToTerminal(`[Risk Engine] Synchronizing assessment #${assessmentId} environment context to "${env}"...`);
            await apiPost(`/api/assessments/${assessmentId}`, { environment: env }, 'PUT');

            logToTerminal(`[Risk Engine] Triggering environment-aware compliance rating index calculations...`);
            await apiPost(`/api/checklist/evaluate/${assessmentId}`);

            const calcRes = await apiPost(`/api/risk/calculate/${assessmentId}`);
            if (calcRes && calcRes.id) {
                logToTerminal(`[Risk Engine] Calculations complete. Composite compliance score: ${calcRes.overall_score}%`, "info");
                handleRiskAssessmentChange();
                alert(`Risk calculation complete!\n\nOverall Score: ${calcRes.overall_score}%\nEnvironment: ${calcRes.environment}`);
            } else {
                logToTerminal(`[Risk Engine Error] Calculation failed.`, "error");
            }
        }

        const manualControls = [
            { code: "CTRL-011", title: "Role-Based Access Control", desc: "Auditors verify RBAC authorization checks are enforced on endpoints.", rec: "Conduct audit of access policies, map all endpoints to roles, and verify restriction." },
            { code: "CTRL-012", title: "Inactive Account Disable", desc: "Auditors verify LDAP/AD deactivation policies are active.", rec: "Review Active Directory account deactivation logs for accounts idle > 90 days." },
            { code: "CTRL-013", title: "Audit Log Completeness", desc: "Auditors verify access, modifications, and security events are logged.", rec: "Review centralized logging daemon configs to verify auditing completeness." },
            { code: "CTRL-014", title: "Security Alerting", desc: "Auditors verify alerts are raised on anomalous login attempts.", rec: "Check SIEM alerting rules for brute-force or anomalous geolocation logins." },
            { code: "CTRL-015", title: "Logout Session Kill", desc: "Auditors verify backend session tokens are revoked upon logout.", rec: "Test session revocation endpoint and confirm server-side token state is deleted." }
        ];

        async function handleSampAssessmentChange() {
            const selectEl = document.getElementById("samp-assessment-select");
            if (!selectEl) return;
            const assessmentId = selectEl.value;
            if (!assessmentId) return;

            const res = await apiGet(`/api/assessments/${assessmentId}`);
            if (res) {
                if (!res.findings || res.findings.length === 0) {
                    logToTerminal(`[SAMP Auditor] Findings database uninitialized. Seeding automated checklists...`);
                    await apiPost(`/api/checklist/evaluate/${assessmentId}`);
                    handleSampAssessmentChange();
                    return;
                }

                sampFindings = res.findings;
                renderSampChecklistProgress();
                loadSampControl(sampActiveControlIndex);
            }
        }

        function renderSampChecklistProgress() {
            const manualFindings = sampFindings.filter(f => manualControlCodes.includes(f.control_code));
            const evaluated = manualFindings.filter(f => !f.details.includes("Pending auditor manual")).length;

            const progEl = document.getElementById("samp-progress-label");
            if (progEl) {
                progEl.innerText = `${evaluated} / 5 Controls`;
            }

            const listContainer = document.getElementById("samp-checklist-items-container");
            if (listContainer) {
                listContainer.innerHTML = "";

                manualControls.forEach((c, idx) => {
                    const finding = sampFindings.find(f => f.control_code === c.code);
                    const status = finding ? finding.status : "FAIL";
                    const isEvaluated = finding && !finding.details.includes("Pending auditor manual");
                    const activeClass = (idx === sampActiveControlIndex) ? "border-color: var(--color-accent) !important; background: rgba(185, 28, 28, 0.05);" : "";

                    const div = document.createElement("div");
                    div.className = "card";
                    div.style = `padding: 0.85rem; border: 1px solid var(--border-clean); border-radius: 4px; cursor: pointer; transition: all 0.2s ease; display: flex; align-items: center; justify-content: space-between; ${activeClass}`;
                    div.onclick = () => {
                        sampActiveControlIndex = idx;
                        handleSampAssessmentChange();
                    };

                    div.innerHTML = `
                        <div>
                            <div style="font-family: var(--font-mono); font-size: 0.72rem; font-weight: 800; color: var(--text-secondary);">${c.code}</div>
                            <h5 style="margin: 0.15rem 0 0 0; font-size: 0.8rem; font-weight: 700; color: var(--text-primary); border: none; padding: 0;">${c.title}</h5>
                        </div>
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            <span class="badge ${isEvaluated ? 'group-sift' : 'group-non-sift'}" style="font-size: 0.6rem;">${isEvaluated ? 'AUDITED' : 'PENDING'}</span>
                            <span class="badge ${status === 'PASS' ? 'status-low-bg' : 'status-critical-bg'}" style="font-size: 0.6rem; font-weight: 800;">${status}</span>
                        </div>
                    `;
                    listContainer.appendChild(div);
                });
            }
        }

        function loadSampControl(idx) {
            sampActiveControlIndex = idx;
            const ctrl = manualControls[idx];
            if (!ctrl) return;

            document.getElementById("samp-ctrl-code").innerText = ctrl.code;
            document.getElementById("samp-ctrl-title").innerText = ctrl.title;
            document.getElementById("samp-ctrl-desc").innerText = ctrl.desc;

            const finding = sampFindings.find(f => f.control_code === ctrl.code);
            const status = finding ? finding.status : "FAIL";
            const notes = finding ? (finding.details.includes("Pending auditor manual") ? "" : finding.details) : "";

            document.getElementById("samp-ctrl-notes").value = notes;

            const btnPass = document.getElementById("btn-samp-pass");
            const btnFail = document.getElementById("btn-samp-fail");

            if (status === 'PASS') {
                btnPass.style.background = "#16a34a";
                btnPass.style.color = "#ffffff";
                btnFail.style.background = "transparent";
                btnFail.style.color = "#dc2626";
            } else {
                btnPass.style.background = "transparent";
                btnPass.style.color = "#16a34a";
                btnFail.style.background = "#dc2626";
                btnFail.style.color = "#ffffff";
            }

            btnPass.setAttribute("data-active", status === 'PASS' ? "true" : "false");
            btnFail.setAttribute("data-active", status === 'FAIL' ? "true" : "false");
        }

        function setSampControlStatus(status) {
            const btnPass = document.getElementById("btn-samp-pass");
            const btnFail = document.getElementById("btn-samp-fail");

            if (status === 'PASS') {
                btnPass.style.background = "#16a34a";
                btnPass.style.color = "#ffffff";
                btnFail.style.background = "transparent";
                btnFail.style.color = "#dc2626";
                btnPass.setAttribute("data-active", "true");
                btnFail.setAttribute("data-active", "false");
            } else {
                btnPass.style.background = "transparent";
                btnPass.style.color = "#16a34a";
                btnFail.style.background = "#dc2626";
                btnFail.style.color = "#ffffff";
                btnPass.setAttribute("data-active", "false");
                btnFail.setAttribute("data-active", "true");
            }
        }

        async function saveSampControlOverride() {
            const selectEl = document.getElementById("samp-assessment-select");
            const assessmentId = selectEl.value;
            const ctrl = manualControls[sampActiveControlIndex];
            const notes = document.getElementById("samp-ctrl-notes").value.trim() || "Audited and verified manual checklist compliance control.";

            const btnPass = document.getElementById("btn-samp-pass");
            const status = (btnPass.getAttribute("data-active") === "true") ? "PASS" : "FAIL";

            const finding = sampFindings.find(f => f.control_code === ctrl.code);
            if (!finding) {
                logToTerminal(`[SAMP Auditor] Error: Finding record for ${ctrl.code} not found.`, "error");
                return;
            }

            logToTerminal(`[SAMP Auditor] Dispatching override request for control ${ctrl.code} (Status: ${status})...`);

            const url = `/api/assessments/findings/${finding.id}?status=${status}&details=${encodeURIComponent(notes)}&recommendation=${encodeURIComponent(ctrl.rec)}`;
            const res = await apiPost(url, {}, 'PUT');

            if (res && res.id) {
                logToTerminal(`[SAMP Auditor] Override complete for ${ctrl.code}. Status committed to DB.`, "info");

                handleSampAssessmentChange();

                const riskSelect = document.getElementById("risk-assessment-select");
                if (riskSelect && riskSelect.value === assessmentId) {
                    handleRiskAssessmentChange();
                }

                alert(`Control ${ctrl.code} audit finding saved successfully!`);
            } else {
                logToTerminal(`[SAMP Auditor] Error saving control finding override.`, "error");
            }
        }

        async function signSampControlEvidence() {
            const selectEl = document.getElementById("samp-assessment-select");
            const assessmentId = selectEl.value;
            const ctrl = manualControls[sampActiveControlIndex];
            const notes = document.getElementById("samp-ctrl-notes").value.trim() || "Audited and verified manual checklist compliance control.";

            const btnPass = document.getElementById("btn-samp-pass");
            const status = (btnPass.getAttribute("data-active") === "true") ? "PASS" : "FAIL";

            logToTerminal(`[SAMP Auditor] Cryptographically signing manual audit check evidence for ${ctrl.code}...`);

            const evidencePayload = {
                source: "Manual",
                raw_data: JSON.stringify({
                    control_code: ctrl.code,
                    control_title: ctrl.title,
                    audit_status: status,
                    auditor_notes: notes,
                    verified_at: new Date().toISOString()
                }, null, 4),
                collected_at: new Date().toISOString(),
                assessment_id: parseInt(assessmentId, 10)
            };

            const res = await apiPost('/api/evidence/', evidencePayload);
            if (res && res.id) {
                logToTerminal(`[SAMP Auditor] Immutable evidence registered. ID #${res.id}.`, "info");
                logToTerminal(`[SAMP Auditor] SHA-256 Hash Signature: ${res.hash_signature}`, "info");
                logToTerminal(`[SAMP Auditor] Non-repudiation registry secure status: SECURE`, "info");
                alert(`Evidence signed successfully!\n\nEvidence ID: #${res.id}\nHash: ${res.hash_signature}`);
            } else {
                logToTerminal(`[SAMP Auditor] Failed to register cryptographic evidence.`, "error");
            }
        }

        // --- Simplified Compliance & Policy Governance Scripting Blocks ---

        currentPolicyTab = "all";

        function switchPolicyTab(tabId) {
            currentPolicyTab = tabId;
            document.querySelectorAll("#section-risk .tab-btn").forEach(btn => btn.classList.remove("active"));
            const clickedBtn = document.getElementById(`policy-filter-btn-${tabId}`);
            if (clickedBtn) clickedBtn.classList.add("active");
            renderPoliciesGrid();
        }

        function getAvailablePolicies() {
            const list = [
                "Active Directory (AD) Enrollment",
                "BitLocker Drive Encryption",
                "Zscaler Client Connector",
                "Nessus Vulnerability Agent",
                "SentinelOne Endpoint Protection",
                "SCCM Management Agent"
            ];

            // Gather all custom properties from fleetDataset that represent spreadsheet compliance columns
            const customKeys = new Set();
            fleetDataset.forEach(dev => {
                if (dev.custom_properties) {
                    Object.keys(dev.custom_properties).forEach(k => {
                        if (k.startsWith('[') && k.includes(']')) {
                            customKeys.add(k);
                        }
                    });
                }
            });

            customKeys.forEach(k => list.push(k));
            return list;
        }

        function populatePolicyFilterDropdown() {
            const select = document.getElementById("fleet-filter-policy");
            if (!select) return;

            const selectedValue = select.value || "ALL";

            let html = `<option value="ALL">All Policies</option>`;

            const policies = getAvailablePolicies();
            policies.forEach(name => {
                const isCore = !name.startsWith('[');
                const displayName = isCore ? name : name.replace(/^\[.*?\]\s*/, '') + ' (' + name.match(/^\[(.*?)\]/)[1] + ')';

                if (isCore) {
                    const swCatalogItem = sampleSoftwareCatalog.find(sw => sw.name === name);
                    const key = swCatalogItem ? swCatalogItem.key : "";
                    if (key) {
                        html += `<option value="core:${key}:COMPLIANT">${escapeHTML(displayName)}: Compliant</option>`;
                        html += `<option value="core:${key}:NON_COMPLIANT">${escapeHTML(displayName)}: Non-Compliant</option>`;
                    }
                } else {
                    html += `<option value="custom:${name}:COMPLIANT">${escapeHTML(displayName)}: Compliant</option>`;
                    html += `<option value="custom:${name}:NON_COMPLIANT">${escapeHTML(displayName)}: Non-Compliant</option>`;
                }
            });

            select.innerHTML = html;
            if (select.options && Array.from(select.options).some(opt => opt.value === selectedValue)) {
                select.value = selectedValue;
            } else {
                select.value = "ALL";
            }
        }


        function handleReportingSearch(val) {
            reportingSearchQuery = val.toLowerCase();
            reportingCurrentPage = 1;
            renderReportingAgentTable();
        }

        function changeReportingPage(dir) {
            const activeFleet = fleetDataset.filter(dev => dev.condition === "IN_USE");
            const filtered = activeFleet.filter(dev => {
                const assetTag = (dev.custom_properties && dev.custom_properties["Asset Tag"]) || dev.serial || "";
                const name = dev.canonical_name || "";
                const id = dev.id || "";
                return assetTag.toLowerCase().includes(reportingSearchQuery) ||
                    name.toLowerCase().includes(reportingSearchQuery) ||
                    id.toLowerCase().includes(reportingSearchQuery);
            });

            const maxPage = Math.ceil(filtered.length / reportingPageSize) || 1;
            reportingCurrentPage += dir;
            if (reportingCurrentPage < 1) reportingCurrentPage = 1;
            if (reportingCurrentPage > maxPage) reportingCurrentPage = maxPage;

            renderReportingAgentTable();
        }

        function toggleReportingPolicy(name) {
            const current = enforcedPolicies[name] !== false;
            enforcedPolicies[name] = !current;

            logToTerminal(`[Reporting Audit] Excluded policy "${name}" status changed to ${enforcedPolicies[name] ? 'REQUIRED' : 'OPTIONAL (Negated)'}.`, enforcedPolicies[name] ? 'info' : 'warning');

            recalculateAllScores();
            generateComplianceReport();
        }

        function renderReportingAgentTable() {
            const tableHead = document.getElementById("reporting-table-head-row");
            const tbody = document.getElementById("reporting-agent-tbody");
            if (!tableHead || !tbody) return;

            const policies = [
                "Active Directory (AD) Enrollment",
                "BitLocker Drive Encryption",
                "Zscaler Client Connector",
                "Nessus Vulnerability Agent",
                "SentinelOne Endpoint Protection",
                "SCCM Management Agent"
            ];

            let headHtml = `
                <th style="text-align: left;">Asset Tag</th>
                <th style="text-align: left;">Device ID / Name</th>
            `;
            policies.forEach(name => {
                const cleanName = name.startsWith('[') ? name.replace(/^\[.*?\]\s*/, '') : name;
                headHtml += `<th style="text-align: center;">${escapeHTML(cleanName)}</th>`;
            });
            headHtml += `<th style="text-align: center;">Overall Compliance</th>`;
            tableHead.innerHTML = headHtml;

            const conditionFilter = (document.getElementById("fleet-filter-condition") || {}).value || "ALL";
            const activeFleet = fleetDataset.filter(dev => {
                return (conditionFilter === "ALL") || (dev.condition === conditionFilter);
            });
            const filtered = activeFleet.filter(dev => {
                const assetTag = (dev.custom_properties && dev.custom_properties["Asset Tag"]) || dev.serial || "";
                const name = dev.canonical_name || "";
                const id = dev.id || "";
                return assetTag.toLowerCase().includes(reportingSearchQuery) ||
                    name.toLowerCase().includes(reportingSearchQuery) ||
                    id.toLowerCase().includes(reportingSearchQuery);
            });

            const total = filtered.length;
            const startIdx = (reportingCurrentPage - 1) * reportingPageSize;
            const endIdx = Math.min(startIdx + reportingPageSize, total);

            const displaySlice = filtered.slice(startIdx, endIdx);
            tbody.innerHTML = "";

            if (displaySlice.length === 0) {
                const colSpan = 3 + policies.length;
                tbody.innerHTML = `<tr><td colspan="${colSpan}" style="text-align: center; color: var(--text-secondary); font-style: italic; padding: 2rem;">No matching assets found.</td></tr>`;
            } else {
                displaySlice.forEach(dev => {
                    const assetTag = (dev.custom_properties && dev.custom_properties["Asset Tag"]) || dev.serial || "-";

                    let rowHtml = `
                        <td><strong>${escapeHTML(assetTag)}</strong></td>
                        <td>${escapeHTML(dev.canonical_name.toUpperCase())} <span style="font-size:0.7rem; color:var(--text-muted); font-family:var(--font-mono);">(${dev.id})</span></td>
                    `;

                    policies.forEach(policyName => {
                        const isRequired = enforcedPolicies[policyName] !== false;

                        const coreSw = sampleSoftwareCatalog.find(sw => sw.name === policyName);
                        if (coreSw) {
                            const sw = dev.software && dev.software.find(s => s.name === policyName);
                            if (!sw) {
                                rowHtml += `<td style="text-align: center;"><span class="badge group-non-sift" style="font-size:0.65rem;">UNREPORTED</span></td>`;
                            } else {
                                const opacityStyle = isRequired ? '' : ' style="opacity: 0.65;"';
                                const isCompliant = sw.status === "COMPLIANT";
                                rowHtml += `<td style="text-align: center;"><span class="badge ${isCompliant ? 'risk-low' : 'risk-critical'}" style="font-size:0.65rem;"${opacityStyle}>${escapeHTML(sw.installed)}</span></td>`;
                            }
                        } else {
                            const val = (dev.custom_properties && dev.custom_properties[policyName] !== undefined) ? dev.custom_properties[policyName] : "MISSING";
                            const isCompliant = val !== "MISSING" && !["fail", "failed", "inactive", "missing", "no", "disabled"].includes(val.toLowerCase());
                            const opacityStyle = isRequired ? '' : ' style="opacity: 0.65;"';
                            rowHtml += `<td style="text-align: center;"><span class="badge ${isCompliant ? 'risk-low' : 'risk-critical'}" style="font-size:0.65rem;"${opacityStyle}>${escapeHTML(val)}</span></td>`;
                        }
                    });

                    const overallCompliant = isDeviceCompliantForReporting(dev);
                    const levelText = overallCompliant ? "COMPLIANT" : "NON_COMPLIANT";
                    rowHtml += `<td style="text-align: center;"><span class="badge ${overallCompliant ? 'risk-low' : 'risk-critical'}">${levelText}</span></td>`;

                    const tr = document.createElement("tr");
                    tr.innerHTML = rowHtml;
                    tbody.appendChild(tr);
                });
            }

            document.getElementById("reporting-pag-start").innerText = total === 0 ? 0 : (startIdx + 1).toLocaleString();
            document.getElementById("reporting-pag-end").innerText = endIdx.toLocaleString();
            document.getElementById("reporting-pag-total").innerText = total.toLocaleString();
        }

        // Per-render cache for getPolicyStats — avoids re-scanning 14k rows multiple times per render
        var _policyStatsCache = null;
        var _policyStatsCacheFilter = null;

        function invalidatePolicyStatsCache() {
            _policyStatsCache = null;
            _policyStatsCacheFilter = null;
        }

        function getPolicyStats(name, conditionFilter) {
            if (!conditionFilter) {
                const filterEl = document.getElementById("fleet-filter-condition");
                conditionFilter = filterEl ? filterEl.value : "ALL";
            }

            // Build or retrieve the cache for this condition filter
            if (_policyStatsCache === null || _policyStatsCacheFilter !== conditionFilter) {
                _policyStatsCache = {};
                _policyStatsCacheFilter = conditionFilter;

                // Single pass over fleetDataset — compute stats for ALL core policies at once
                const corePolicyNames = [
                    "Active Directory (AD) Enrollment",
                    "BitLocker Drive Encryption",
                    "Zscaler Client Connector",
                    "Nessus Vulnerability Agent",
                    "SentinelOne Endpoint Protection",
                    "SCCM Management Agent"
                ];
                const windowsOnlyPolicies = new Set(["Active Directory (AD) Enrollment", "BitLocker Drive Encryption", "SCCM Management Agent"]);

                // Initialize accumulators for core policies
                corePolicyNames.forEach(n => {
                    _policyStatsCache[n] = { filteredCompliant: 0, filteredTotal: 0, inUseCompliant: 0, inUseTotal: 0, allCompliant: 0, allTotal: 0, isUnreported: false, _checked: false };
                });

                // Determine unreported status for each core policy upfront
                corePolicyNames.forEach(n => {
                    const swCatalogItem = sampleSoftwareCatalog.find(sw => sw.name === n);
                    const swKey = swCatalogItem ? swCatalogItem.key : "";
                    const isUploaded = isSheetUploadedForSoftware(swKey);
                    const isEverMerged = typeof mergedSoftwareAgents !== "undefined" && mergedSoftwareAgents.has(swKey);
                    const alwaysReported = swKey === "ad";
                    if (!alwaysReported && !isUploaded && !isEverMerged) {
                        _policyStatsCache[n].isUnreported = true;
                    }
                    _policyStatsCache[n]._alwaysReported = alwaysReported;
                });

                // Single O(N) pass over the entire fleet dataset
                for (let i = 0; i < fleetDataset.length; i++) {
                    const dev = fleetDataset[i];
                    if (dev.is_rogue) continue;
                    const isActive = dev.condition === "IN_USE";
                    const matchesFilter = (conditionFilter === "ALL" || dev.condition === conditionFilter);
                    const isWindows = dev.os_family && String(dev.os_family).toLowerCase().includes("win");

                    for (let k = 0; k < corePolicyNames.length; k++) {
                        const n = corePolicyNames[k];
                        const acc = _policyStatsCache[n];
                        if (acc.isUnreported) continue;

                        // Windows-only policies skip non-Windows devices
                        if (windowsOnlyPolicies.has(n) && !isWindows) continue;

                        const isRequired = enforcedPolicies[n] !== false;
                        const sw = dev.software && dev.software.find(s => s.name === n);

                        if (isRequired) {
                            acc.allTotal++;
                            if (isActive) acc.inUseTotal++;
                            if (matchesFilter) acc.filteredTotal++;
                            const compliant = sw && sw.status === "COMPLIANT";
                            if (compliant) acc.allCompliant++;
                            if (compliant && isActive) acc.inUseCompliant++;
                            if (compliant && matchesFilter) acc.filteredCompliant++;
                        } else {
                            if (sw && sw.installed && !sw.installed.toLowerCase().includes("missing")) {
                                acc.allTotal++;
                                if (isActive) acc.inUseTotal++;
                                if (matchesFilter) acc.filteredTotal++;
                                const compliant = sw.status === "COMPLIANT";
                                if (compliant) acc.allCompliant++;
                                if (compliant && isActive) acc.inUseCompliant++;
                                if (compliant && matchesFilter) acc.filteredCompliant++;
                            }
                        }
                    }
                }
            }

            const isCore = !name.startsWith('[');

            // Return cached core policy result
            if (isCore && _policyStatsCache[name]) {
                const acc = _policyStatsCache[name];
                return {
                    filteredCompliant: acc.filteredCompliant,
                    filteredTotal: acc.filteredTotal,
                    inUseCompliant: acc.inUseCompliant,
                    inUseTotal: acc.inUseTotal,
                    allCompliant: acc.allCompliant,
                    allTotal: acc.allTotal,
                    isUnreported: acc.isUnreported,
                    get compliantCount() { return this.filteredCompliant; },
                    get totalCount() { return this.filteredTotal; }
                };
            }

            // Custom/Excel policy — compute inline (not cached, typically fewer rows)
            const hasProperty = fleetDataset.some(dev => dev.custom_properties && dev.custom_properties[name] !== undefined);
            if (!hasProperty) {
                return {
                    filteredCompliant: 0, filteredTotal: 0, inUseCompliant: 0, inUseTotal: 0,
                    allCompliant: 0, allTotal: 0, isUnreported: true,
                    get compliantCount() { return 0; }, get totalCount() { return 0; }
                };
            }

            const isRequired = enforcedPolicies[name] !== false;
            let filteredCompliant = 0, filteredTotal = 0;
            let inUseCompliant = 0, inUseTotal = 0;
            let allCompliant = 0, allTotal = 0;

            fleetDataset.forEach(dev => {
                const isActive = dev.condition === "IN_USE";
                const matchesFilter = (conditionFilter === "ALL" || dev.condition === conditionFilter) && !dev.is_rogue;
                const val = (dev.custom_properties && dev.custom_properties[name] !== undefined) ? dev.custom_properties[name] : "MISSING";
                const compliant = val !== "MISSING" && !["fail", "failed", "inactive", "missing", "no", "disabled"].includes(val.toLowerCase());
                if (isRequired) {
                    allTotal++;
                    if (isActive) inUseTotal++;
                    if (matchesFilter) filteredTotal++;
                    if (compliant) allCompliant++;
                    if (compliant && isActive) inUseCompliant++;
                    if (compliant && matchesFilter) filteredCompliant++;
                } else {
                    if (val !== "MISSING") {
                        allTotal++;
                        if (isActive) inUseTotal++;
                        if (matchesFilter) filteredTotal++;
                        if (compliant) allCompliant++;
                        if (compliant && isActive) inUseCompliant++;
                        if (compliant && matchesFilter) filteredCompliant++;
                    }
                }
            });

            return {
                filteredCompliant, filteredTotal, inUseCompliant, inUseTotal,
                allCompliant, allTotal, isUnreported: false,
                get compliantCount() { return this.filteredCompliant; },
                get totalCount() { return this.filteredTotal; }
            };
        }

        function getFailedControlsForDevice(dev) {
            const failedControls = [];

            const policies = getAvailablePolicies();
            policies.forEach(name => {
                const isRequired = enforcedPolicies[name] !== false;
                if (!isRequired) return;

                if (!name.startsWith('[')) {
                    const sw = dev.software && dev.software.find(s => s.name === name);
                    if (sw) {
                        const isUploaded = isSheetUploadedForSoftware(sw.key);
                        const isEverMerged = typeof mergedSoftwareAgents !== "undefined" && mergedSoftwareAgents.has(sw.key);
                        const alwaysReported = sw.key === "ad";

                        if (!alwaysReported && !isUploaded && !isEverMerged) {
                            return; // bypassed
                        }
                        if (sw.status === "NON_COMPLIANT") {
                            failedControls.push(name);
                        }
                    }
                } else {
                    const val = (dev.custom_properties && dev.custom_properties[name] !== undefined) ? dev.custom_properties[name] : "MISSING";
                    const isCompliant = val !== "MISSING" && !["fail", "failed", "inactive", "missing", "no", "disabled"].includes(val.toLowerCase());
                    if (!isCompliant) {
                        failedControls.push(name);
                    }
                }
            });

            return failedControls;
        }

        // Token to cancel any in-flight chunk loop before starting a new recalculation
        var _recalcToken = 0;

        function recalculateAllScores() {
            // Invalidate caches before recalculating
            invalidatePolicyStatsCache();
            populatePolicyFilterDropdown();

            // Cancel any previous in-flight chunk loop
            const myToken = ++_recalcToken;

            const CHUNK_SIZE = 2000; // process 2000 devices per tick to keep UI responsive
            const policies = getAvailablePolicies();
            const total = fleetDataset.length;

            if (total === 0) {
                _finishRecalculate(policies);
                return;
            }

            // Show a non-blocking progress indicator
            const progressEl = document.getElementById("import-progress-indicator");
            if (progressEl) { progressEl.style.display = "flex"; progressEl.querySelector("span").textContent = `Recalculating scores (0/${total})...`; }

            showLoading("Recalculating compliance scores...");

            let offset = 0;
            function processChunk() {
                // Bail out if a newer recalculation has started
                if (myToken !== _recalcToken) return;

                const end = Math.min(offset + CHUNK_SIZE, total);
                for (let i = offset; i < end; i++) {
                    recalculateSingleDeviceScore(fleetDataset[i], policies);
                }
                offset = end;

                if (progressEl) progressEl.querySelector("span").textContent = `Recalculating scores (${offset.toLocaleString()}/${total.toLocaleString()})...`;

                const pct = Math.round((offset / total) * 100);
                showLoading(`Recalculating compliance scores (${pct}%)...`);

                if (offset < total) {
                    setTimeout(processChunk, 0); // yield to browser between chunks
                } else {
                    if (progressEl) progressEl.style.display = "none";
                    _finishRecalculate(policies);
                }
            }
            processChunk();
        }

        function _finishRecalculate(policies) {
            hideLoading();
            invalidatePolicyStatsCache();
            updateFleetWideMetrics();
            // Use _doFleetFilter directly to avoid double-debounce delay
            _doFleetFilter();

            // Re-render active views if open
            const reportingSection = document.getElementById("section-reporting");
            if (reportingSection && reportingSection.style.display !== "none") {
                generateComplianceReport();
            }
            const riskSection = document.getElementById("section-risk");
            if (riskSection && riskSection.style.display !== "none") {
                renderPoliciesGrid();
            }
        }

        function renderPoliciesGrid() {
            const grid = document.getElementById("policies-governance-grid");
            const alertEl = document.getElementById("policy-admin-alert");
            if (!grid) return;

            const isAdmin = (currentSession.role === "admin");
            if (alertEl) {
                alertEl.style.display = isAdmin ? "none" : "block";
            }

            const policies = getAvailablePolicies();

            // Calculate tab totals dynamically
            const allCount = policies.length;
            const coreCount = policies.filter(p => !p.startsWith('[')).length;
            const excelCount = policies.filter(p => p.startsWith('[')).length;

            const allCountEl = document.getElementById("policy-count-all");
            const coreCountEl = document.getElementById("policy-count-core");
            const excelCountEl = document.getElementById("policy-count-excel");

            if (allCountEl) allCountEl.innerText = allCount.toLocaleString();
            if (coreCountEl) coreCountEl.innerText = coreCount.toLocaleString();
            if (excelCountEl) excelCountEl.innerText = excelCount.toLocaleString();

            // Filter policies according to active tab selection
            let filteredPolicies = policies;
            if (currentPolicyTab === "core") {
                filteredPolicies = policies.filter(p => !p.startsWith('['));
            } else if (currentPolicyTab === "excel") {
                filteredPolicies = policies.filter(p => p.startsWith('['));
            }

            grid.innerHTML = "";

            if (filteredPolicies.length === 0) {
                grid.style.display = "block";
                grid.innerHTML = `<div style="text-align: center; color: var(--text-secondary); font-style: italic; padding: 3rem; background: var(--bg-card); border: 1px solid var(--border-clean); border-radius: 4px;">No policies found in this category.</div>`;
            } else {
                grid.style.display = "grid";
                filteredPolicies.forEach(name => {
                    const isRequired = enforcedPolicies[name] !== false; // default true

                    // Count telemetry passes via unified stats helper
                    const stats = getPolicyStats(name);
                    const compliantCount = stats.compliantCount;
                    const totalCount = stats.totalCount;
                    const isUnreported = stats.isUnreported;

                    const passRate = totalCount > 0 ? (compliantCount / totalCount) * 100 : 100;
                    const card = document.createElement("div");
                    card.className = "metric-widget";
                    card.style.border = "1px solid var(--border-clean)";
                    card.style.display = "flex";
                    card.style.flexDirection = "column";
                    card.style.gap = "0.75rem";
                    card.style.padding = "1.25rem";
                    card.style.background = "var(--bg-card)";
                    card.style.borderRadius = "4px";

                    const badgeClass = isUnreported ? "group-non-sift" : (isRequired ? "risk-low" : "group-non-sift");
                    const badgeLabel = isUnreported ? "UNREPORTED" : (isRequired ? "REQUIRED" : "OPTIONAL");

                    // Core mandates are simple display names
                    const displayName = name;
                    const displaySubtitle = 'Core System Mandate';

                    const telemetryText = isUnreported ? "Sheet Missing" : `${compliantCount.toLocaleString()} / ${totalCount.toLocaleString()} Pass`;
                    const passRateText = isUnreported ? "N/A (Unreported)" : `${passRate.toFixed(1)}%`;
                    const passRateColor = isUnreported ? "var(--text-muted)" : (passRate === 100 ? "var(--status-low)" : (isRequired ? "var(--status-critical)" : "var(--text-primary)"));

                    card.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 0.5rem;">
                            <div style="display: flex; flex-direction: column;">
                                <span style="font-size: 0.85rem; font-weight: 700; color: var(--text-primary); text-transform: none; line-height: 1.3;">${escapeHTML(displayName)}</span>
                                <span style="font-size: 0.65rem; color: var(--text-muted); margin-top: 0.15rem;">${escapeHTML(displaySubtitle)}</span>
                            </div>
                            <span class="badge ${badgeClass}" style="font-size: 0.65rem; padding: 0.15rem 0.4rem; font-weight: 700;">${badgeLabel}</span>
                        </div>
                        
                        <div style="font-size: 0.75rem; color: var(--text-secondary); display: flex; flex-direction: column; gap: 0.25rem; margin-top: 0.25rem;">
                            <div style="display: flex; justify-content: space-between;">
                                <span>Active Telemetry:</span>
                                <strong style="color: ${isUnreported ? 'var(--text-muted)' : 'var(--text-primary)'}; font-family: var(--font-mono);">${escapeHTML(telemetryText)}</strong>
                            </div>
                            <div style="display: flex; justify-content: space-between;">
                                <span>Mandate Pass Rate:</span>
                                <strong style="color: ${passRateColor}; font-family: var(--font-mono);">${escapeHTML(passRateText)}</strong>
                            </div>
                        </div>
                        
                        <div style="margin-top: auto; padding-top: 0.75rem; border-top: 1px solid var(--border-clean);">
                            <button class="btn" style="width: 100%; font-size: 0.7rem; padding: 0.45rem; background: ${isUnreported ? 'var(--border-clean)' : (isRequired ? 'rgba(220, 53, 69, 0.15)' : 'rgba(21, 128, 61, 0.15)')}; border: 1px solid ${isUnreported ? 'var(--border-clean)' : (isRequired ? 'rgba(220, 53, 69, 0.4)' : 'rgba(21, 128, 61, 0.4)')}; color: ${isUnreported ? 'var(--text-muted)' : (isRequired ? '#ff6b6b' : '#15803d')}; font-weight: 700; cursor: ${isAdmin && !isUnreported ? 'pointer' : 'not-allowed'}; opacity: ${isAdmin && !isUnreported ? 1 : 0.6};" 
                                ${isUnreported ? 'disabled' : ''}
                                onclick="togglePolicyEnforcement(decodeURIComponent('${encodeURIComponent(name)}'))">
                                ${isUnreported ? 'Telemetry Unavailable' : (isRequired ? 'Exclude Policy (Make Optional)' : 'Enforce Policy (Make Required)')}
                            </button>
                        </div>
                    `;
                    grid.appendChild(card);
                });
            }
        }

        function togglePolicyEnforcement(name) {
            if (currentSession.role !== "admin") {
                logToTerminal(`[Security Alert] Policy override denied: User "${currentSession.username}" lacks Global Security Administrator clearance.`, "error");
                alert("Access Denied: Only a Global Security Administrator (admin) is authorized to modify compliance policy enforcement parameters.");
                return;
            }

            const current = enforcedPolicies[name] !== false; // default true
            enforcedPolicies[name] = !current;

            logToTerminal(`[Policy Board] Policy "${name}" enforcement status changed to ${enforcedPolicies[name] ? 'REQUIRED' : 'OPTIONAL'}.`, enforcedPolicies[name] ? 'info' : 'warning');

            recalculateAllScores();
        }

        function isDeviceCompliantForReporting(dev) {
            if (dev.is_isolated) return false;
            const conditionFilter = (document.getElementById("fleet-filter-condition") || {}).value || "ALL";
            const targetCondition = conditionFilter === "ALL" ? ["IN_USE", "UNKNOWN"] : [conditionFilter];
            if (!targetCondition.includes(dev.condition)) return false;
            if (dev.is_rogue) return false;

            const corePolicies = [
                "Active Directory (AD) Enrollment",
                "BitLocker Drive Encryption",
                "Zscaler Client Connector",
                "Nessus Vulnerability Agent",
                "SentinelOne Endpoint Protection",
                "SCCM Management Agent"
            ];

            let hasNonCompliant = false;
            for (let name of corePolicies) {
                const isRequired = enforcedPolicies[name] !== false; // Required by default
                if (!isRequired) continue;

                // Check OS applicability for AD, BitLocker, and SCCM (Windows-only)
                const isWindows = dev.os_family && String(dev.os_family).toLowerCase().includes("win");
                const isApplicable = !["Active Directory (AD) Enrollment", "BitLocker Drive Encryption", "SCCM Management Agent"].includes(name) || isWindows;
                if (!isApplicable) continue;

                const sw = dev.software && dev.software.find(s => s.name === name);
                if (sw) {
                    const isUploaded = isSheetUploadedForSoftware(sw.key);
                    const isEverMerged = typeof mergedSoftwareAgents !== "undefined" && mergedSoftwareAgents.has(sw.key);
                    const alwaysReported = sw.key === "ad";

                    if (!alwaysReported && !isUploaded && !isEverMerged) {
                        continue;
                    }

                    if (sw.status === "NON_COMPLIANT") {
                        hasNonCompliant = true;
                        break;
                    }
                } else {
                    hasNonCompliant = true;
                    break;
                }
            }
            return !hasNonCompliant;
        }

        function generateComplianceReport() {
            const container = document.getElementById("reporting-dashboard-content");
            if (!container) return;

            const conditionFilter = (document.getElementById("fleet-filter-condition") || {}).value || "ALL";
            const activeFleet = fleetDataset.filter(dev => {
                return (conditionFilter === "ALL") || (dev.condition === conditionFilter);
            });
            const totalDevices = activeFleet.length;
            let compliantCount = 0;
            let nonCompliantCount = 0;

            activeFleet.forEach(dev => {
                if (isDeviceCompliantForReporting(dev)) compliantCount++;
                else nonCompliantCount++;
            });

            const compliantPct = totalDevices > 0 ? (compliantCount / totalDevices) * 100 : 0;
            const nonCompliantPct = totalDevices > 0 ? (nonCompliantCount / totalDevices) * 100 : 0;

            // Calculate circle properties for SLA SVG dial gauge
            const radius = 40;
            const circumference = 2 * Math.PI * radius; // 251.327
            const offset = circumference - (compliantPct / 100) * circumference;
            const gaugeColor = compliantPct >= 85 ? 'var(--status-low)' : (compliantPct >= 65 ? 'var(--status-medium)' : 'var(--status-critical)');

            let html = `
                <!-- SLA Gauge and Quick Stats Row -->
                <div style="display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 1.5rem; width: 100%;">
                    <!-- Dial Gauge Card -->
                    <div class="card" style="padding: 1.5rem; border: 1px solid var(--border-clean); background: var(--bg-card); display: flex; flex-direction: row; align-items: center; justify-content: space-between; border-radius: 4px; gap: 1rem;">
                        <div style="display: flex; flex-direction: column; gap: 0.5rem; max-width: 65%;">
                            <h3 style="margin: 0; font-size: 0.95rem; border: none; padding: 0; font-weight: 700; color: var(--text-primary); text-transform: uppercase; letter-spacing: 0.05em;">Fleet Compliance SLA Status</h3>
                            <p style="font-size: 0.8rem; color: var(--text-secondary); margin: 0; line-height: 1.45;">
                                The fleet composite score is <strong style="color: ${gaugeColor};">${compliantPct.toFixed(2)}%</strong> compliant. Calculated dynamically across all <strong>${totalDevices.toLocaleString()}</strong> active endpoint assets.
                            </p>
                            <div style="display: flex; gap: 0.75rem; margin-top: 0.25rem;">
                                <span class="badge" style="background: ${compliantPct >= 85 ? 'rgba(21, 128, 61, 0.1)' : 'rgba(220, 53, 69, 0.1)'}; border: 1px solid ${compliantPct >= 85 ? 'rgba(21, 128, 61, 0.3)' : 'rgba(220, 53, 69, 0.3)'}; color: ${compliantPct >= 85 ? 'var(--status-low)' : 'var(--status-critical)'}; font-size: 0.65rem; font-weight: 700; padding: 0.1rem 0.35rem;">
                                    ${compliantPct >= 85 ? 'COMPLIANT ▲' : 'VIOLATION ▼'}
                                </span>
                            </div>
                        </div>
                        <div style="width: 100px; height: 100px; position: relative; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                            <svg viewBox="0 0 100 100" style="width: 100%; height: 100%; transform: rotate(-90deg);">
                                <circle cx="50" cy="50" r="${radius}" fill="transparent" stroke="var(--bg-main)" stroke-width="8" />
                                <circle cx="50" cy="50" r="${radius}" fill="transparent" stroke="${gaugeColor}" stroke-width="8" 
                                        stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" 
                                        stroke-linecap="round" style="transition: stroke-dashoffset 0.6s ease;" />
                            </svg>
                            <div style="position: absolute; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center;">
                                <span style="font-family: var(--font-mono); font-size: 1.15rem; font-weight: 800; color: var(--text-primary);">${compliantPct.toFixed(1)}%</span>
                                <span style="font-size: 0.5rem; text-transform: uppercase; font-weight: 700; color: var(--text-muted); letter-spacing: 0.05em;">SLA Score</span>
                            </div>
                        </div>
                    </div>

                    <!-- Compliant Fleet Assets Card -->
                    <div class="metric-widget" style="border: 1px solid var(--border-clean); padding: 1.5rem; background: var(--bg-card); border-radius: 4px; display: flex; flex-direction: column; justify-content: center;">
                        <span style="font-size: 0.7rem; text-transform: uppercase; color: var(--status-low); font-weight: 700; letter-spacing: 0.05em;">Compliant Assets</span>
                        <div class="val" style="font-size: 2rem; font-family: var(--font-mono); margin-top: 0.25rem; font-weight: 800; color: var(--status-low);">${compliantCount.toLocaleString()}</div>
                        <p style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.2rem;">${compliantPct.toFixed(1)}% pass rate</p>
                    </div>
                    
                    <!-- Non-Compliant Exceptions Card -->
                    <div class="metric-widget" style="border: 1px solid var(--border-clean); padding: 1.5rem; background: var(--bg-card); border-radius: 4px; display: flex; flex-direction: column; justify-content: center;">
                        <span style="font-size: 0.7rem; text-transform: uppercase; color: var(--status-critical); font-weight: 700; letter-spacing: 0.05em;">Non-Compliant</span>
                        <div class="val" style="font-size: 2rem; font-family: var(--font-mono); margin-top: 0.25rem; font-weight: 800; color: var(--status-critical);">${nonCompliantCount.toLocaleString()}</div>
                        <p style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.2rem; color: var(--status-critical); font-weight: 700;">${nonCompliantPct.toFixed(1)}% fail rate</p>
                    </div>
                </div>
            `;

            const policies = [
                "Active Directory (AD) Enrollment",
                "BitLocker Drive Encryption",
                "Zscaler Client Connector",
                "Nessus Vulnerability Agent",
                "SentinelOne Endpoint Protection",
                "SCCM Management Agent"
            ];
            let controlRowsHtml = "";

            if (policies.length === 0) {
                controlRowsHtml = `<tr><td colspan="5" style="text-align: center; color: var(--text-secondary); font-style: italic; padding: 2rem;">No security policies loaded.</td></tr>`;
            } else {
                policies.forEach(name => {
                    const isRequired = enforcedPolicies[name] !== false;
                    const stats = getPolicyStats(name);
                    const compliantCount = stats.compliantCount;
                    const totalCount = stats.totalCount;
                    const isUnreported = stats.isUnreported;

                    const passPct = totalCount > 0 ? (compliantCount / totalCount) * 100 : 100;
                    const barColor = isUnreported ? 'var(--border-clean)' : (isRequired ? (passPct === 100 ? 'var(--status-low)' : 'var(--status-critical)') : 'var(--text-muted)');
                    const barBg = "rgba(255, 255, 255, 0.05)";

                    const displayName = name.startsWith('[') ? name.replace(/^\[.*?\]\s*/, '') : name;
                    const displaySubtitle = name.startsWith('[') ? `Source: ${name.match(/^\[(.*?)\]/)[1]}` : 'Core System Mandate';

                    const telemetryText = isUnreported ? "Sheet Missing" : `${compliantCount.toLocaleString()} / ${totalCount.toLocaleString()}`;
                    const passRateText = isUnreported ? "N/A" : `${passPct.toFixed(1)}%`;
                    const passRateColor = isUnreported ? "var(--text-muted)" : (passPct === 100 ? "var(--status-low)" : (isRequired ? "var(--status-critical)" : "var(--text-primary)"));
                    const barWidth = isUnreported ? 0 : passPct;

                    controlRowsHtml += `
                        <tr>
                            <td>
                                <strong style="color: var(--text-primary); display: block;">${escapeHTML(displayName)}</strong>
                                <span style="font-size: 0.7rem; color: var(--text-muted);">${escapeHTML(displaySubtitle)}</span>
                            </td>
                            <td><span class="badge ${isUnreported ? 'group-non-sift' : (isRequired ? 'risk-low' : 'group-non-sift')}" style="font-size: 0.65rem; font-weight: 700; padding: 0.15rem 0.4rem;">${isUnreported ? 'UNREPORTED' : (isRequired ? 'REQUIRED' : 'OPTIONAL')}</span></td>
                            <td style="font-family: var(--font-mono); font-weight: 600; text-align: center; color: ${isUnreported ? 'var(--text-muted)' : 'var(--text-primary)'};">${escapeHTML(telemetryText)}</td>
                            <td style="font-family: var(--font-mono); font-weight: 700; color: ${passRateColor};">${escapeHTML(passRateText)}</td>
                            <td style="width: 180px; vertical-align: middle;">
                                <div style="width: 100%; height: 6px; background: ${barBg}; border-radius: 3px; overflow: hidden; position: relative;">
                                    <div style="width: ${barWidth}%; height: 100%; background: ${barColor}; transition: width 0.3s;"></div>
                                </div>
                            </td>
                        </tr>
                    `;
                });
            }

            html += `
                <div class="card" style="padding: 2rem; border: 1px solid var(--border-clean);">
                    <div style="border-bottom: 1px solid var(--border-clean); padding-bottom: 0.75rem; margin-bottom: 1.25rem;">
                        <h3 style="margin: 0; font-size: 1.1rem; border: none; padding: 0; font-weight: 700;">Global Security Policy Audit Summary</h3>
                        <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">Real-time breakdown of control validation passes across active, reconciled endpoints.</p>
                    </div>
                    <table class="fleet-table" style="font-size: 0.85rem; width: 100%;">
                        <thead>
                            <tr>
                                <th style="text-align: left;">Compliance Policy mandated</th>
                                <th style="text-align: left; width: 110px;">Status</th>
                                <th style="text-align: center; width: 140px;">Verification Matches</th>
                                <th style="text-align: left; width: 100px;">Pass Rate</th>
                                <th style="text-align: left; width: 180px;">SLA Verification Bar</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${controlRowsHtml}
                        </tbody>
                    </table>
                </div>
            `;

            const nonCompliantDevices = activeFleet.filter(dev => !isDeviceCompliantForReporting(dev)).slice(0, 10);
            let exceptionsRowsHtml = "";

            if (nonCompliantDevices.length === 0) {
                exceptionsRowsHtml = `<tr><td colspan="5" style="text-align: center; color: var(--status-low); font-style: italic; padding: 2rem; font-weight: 700;"> No non-compliance exceptions detected! Active fleet is 100% compliant.</td></tr>`;
            } else {
                nonCompliantDevices.forEach(dev => {
                    const failedControls = getFailedControlsForDevice(dev).filter(name => !name.startsWith('['));
                    let failedMarkup = "";

                    if (dev.condition !== "IN_USE") {
                        failedMarkup = `<span class="badge risk-critical">Physical: ${escapeHTML(dev.condition.replace("_", " "))}</span>`;
                    } else if (dev.is_isolated) {
                        failedMarkup = `<span class="badge risk-critical">Host Containment Active</span>`;
                    } else if (failedControls.length === 0) {
                        failedMarkup = `<span class="badge risk-low">None (Optional Control Bypass)</span>`;
                    } else {
                        failedMarkup = failedControls.map(c => {
                            const displayName = c.startsWith('[') ? c.replace(/^\[.*?\]\s*/, '') : c;
                            return `<span class="badge risk-critical" style="font-size: 0.65rem; margin-right: 0.25rem; display: inline-block; margin-bottom: 0.15rem;" title="${escapeHTML(c)}">${escapeHTML(displayName)}</span>`;
                        }).join("");
                    }

                    exceptionsRowsHtml += `
                        <tr>
                            <td><strong style="color: var(--text-primary);">${escapeHTML(dev.canonical_name.toUpperCase())}</strong></td>
                            <td style="font-family: var(--font-mono); color: var(--text-secondary); font-size: 0.8rem;">${escapeHTML(dev.id)}</td>
                            <td style="color: var(--text-primary); font-size: 0.8rem;">${escapeHTML(dev.os)}</td>
                            <td style="vertical-align: middle; padding: 0.4rem 0;">
                                <div style="display: flex; flex-wrap: wrap; max-width: 420px; gap: 0.2rem;">
                                    ${failedMarkup}
                                </div>
                            </td>
                            <td style="text-align: right; width: 120px;">
                                <button class="btn" style="font-size: 0.7rem; padding: 0.35rem 0.65rem; background: rgba(220, 53, 69, 0.15); border: 1px solid rgba(220, 53, 69, 0.4); color: #ff6b6b; font-weight: 700; width: auto; cursor: pointer;"
                                    onclick="goToRemediation('${dev.id}')">
                                     Remediate
                                </button>
                            </td>
                        </tr>
                    `;
                });
            }

            html += `
                <div class="card" style="padding: 2rem; border: 1px solid var(--border-clean);">
                    <div style="border-bottom: 1px solid var(--border-clean); padding-bottom: 0.75rem; margin-bottom: 1.25rem; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <h3 style="margin: 0; font-size: 1.1rem; border: none; padding: 0; font-weight: 700; color: var(--status-critical);">Top Fleet Compliance Exceptions</h3>
                            <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">Lists the top systems currently violating required security mandates. Direct action required.</p>
                        </div>
                        <span class="badge risk-critical" style="font-weight: 800; font-size: 0.7rem; padding: 0.25rem 0.5rem;">IMMEDIATE ACTIONS REQUIRED</span>
                    </div>
                    <table class="fleet-table" style="font-size: 0.85rem; width: 100%;">
                        <thead>
                            <tr>
                                <th style="text-align: left;">Device Name</th>
                                <th style="text-align: left; width: 100px;">Device ID</th>
                                <th style="text-align: left; width: 150px;">OS Platform</th>
                                <th style="text-align: left;">Policy Violation Gaps</th>
                                <th style="text-align: right; width: 120px;">Remediation Path</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${exceptionsRowsHtml}
                        </tbody>
                    </table>
                </div>
            `;
            // Build dynamic negation controls checkboxes
            let negationControlsHtml = "";
            policies.forEach(name => {
                const isRequired = enforcedPolicies[name] !== false;
                const cleanLabel = name.startsWith('[') ? name.replace(/^\[.*?\]\s*/, '') : name;
                const sourceLabel = name.startsWith('[') ? ` (${name.match(/^\[(.*?)\]/)[1]})` : '';
                const checkboxId = `negate-policy-${name.replace(/[^a-zA-Z0-9]/g, "-")}`;
                negationControlsHtml += `
                    <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; font-weight: 600; color: var(--text-primary); cursor: pointer;">
                        <input type="checkbox" id="${checkboxId}" ${isRequired ? 'checked' : ''} onchange="toggleReportingPolicy('${escapeHTML(name)}')" style="accent-color: var(--color-accent); width: 14px; height: 14px; cursor: pointer;">
                        <span>${escapeHTML(cleanLabel)}<span style="font-size: 0.65rem; color: var(--text-muted); font-weight: normal;">${escapeHTML(sourceLabel)}</span></span>
                    </label>
                `;
            });

            html += `
                <div class="card" style="padding: 2rem; border: 1px solid var(--border-clean); display: flex; flex-direction: column; gap: 1.5rem;">
                    <div style="border-bottom: 1px solid var(--border-clean); padding-bottom: 0.75rem; margin-bottom: 0.5rem;">
                        <h3 style="margin: 0; font-size: 1.1rem; border: none; padding: 0; font-weight: 700; color: var(--text-primary);">Interactive Policy Negation & Agent Compliance Audit</h3>
                        <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">Negate specific policies to exclude them from calculations, and audit individual agent compliance pass rates compared across all active asset tags.</p>
                    </div>

                    <!-- Negation Controls Grid -->
                    <div>
                        <h4 style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 0.75rem;">Active Compliance Mandates (Uncheck to Negate)</h4>
                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 1rem; padding: 1.25rem; background: var(--bg-secondary); border: 1px solid var(--border-clean); border-radius: 4px;">
                            ${negationControlsHtml}
                        </div>
                    </div>

                    <!-- Agent Compliance Grid (compared individually with Asset Tag) -->
                    <div>
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 1rem;">
                            <h4 style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary);">Asset Tag Agent Compliance Ledger</h4>
                            <!-- Search field inside reporting for these asset tags -->
                            <input type="text" id="reporting-search-input" value="${escapeHTML(reportingSearchQuery)}" placeholder="Search by Asset Tag or Name..." oninput="handleReportingSearch(this.value)" style="border: 1px solid var(--border-clean); padding: 0.4rem 0.75rem; font-size: 0.8rem; outline: none; background: var(--bg-card); border-radius: 4px; width: 220px; color: var(--text-primary);">
                        </div>
                        
                        <div class="fleet-table-container">
                            <table class="fleet-table" style="font-size: 0.85rem; width: 100%;">
                                <thead>
                                    <tr id="reporting-table-head-row">
                                        <!-- Dynamic headers -->
                                    </tr>
                                </thead>
                                <tbody id="reporting-agent-tbody">
                                    <!-- Dynamic rows paginated -->
                                </tbody>
                            </table>
                        </div>

                        <!-- Reporting pagination -->
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid var(--border-clean);">
                            <div style="font-size: 0.8rem; color: var(--text-secondary);">
                                Showing <span id="reporting-pag-start" style="font-weight: 700; color: var(--text-primary);">0</span> to <span id="reporting-pag-end" style="font-weight: 700; color: var(--text-primary);">0</span> of <span id="reporting-pag-total" style="font-weight: 700; color: var(--text-primary);">0</span> records
                            </div>
                            <div style="display: flex; gap: 0.5rem;">
                                <button class="btn btn-secondary" style="font-size: 0.7rem; padding: 0.35rem 0.75rem;" onclick="changeReportingPage(-1)">Previous</button>
                                <button class="btn btn-secondary" style="font-size: 0.7rem; padding: 0.35rem 0.75rem;" onclick="changeReportingPage(1)">Next</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            container.innerHTML = html;
            renderReportingAgentTable();
        }

        function goToRemediation(deviceId) {
            switchNavSection("compliance");
            showDeviceAuditDetails(deviceId);
        }

        