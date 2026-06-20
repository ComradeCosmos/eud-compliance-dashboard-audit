function handleCsvImport(event) {
            const file = event.target.files[0];
            if (!file) return;

            logToTerminal(`[Import] Upload request recognized for file: "${file.name}"`);
            const isExcel = file.name.toLowerCase().endsWith(".xlsx") || file.name.toLowerCase().endsWith(".xls");
            const usePython = (typeof window !== "undefined" && window.location && window.location.protocol && window.location.protocol.startsWith("http"));

            if (usePython) {
                // Use readAsDataURL — browser handles binary-to-base64 natively (avoids freezing btoa loop)
                const reader = new FileReader();
                reader.onload = function (e) {
                    try {
                        const dataUrl = e.target.result;
                        const base64 = dataUrl.substring(dataUrl.indexOf(",") + 1);

                        logToTerminal(`[Import] Uploading "${file.name}" to Python backend for validation...`, "info");

                        fetch('/api/validate-sheet', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ filename: file.name, content: base64 })
                        })
                            .then(res => res.json())
                            .then(data => {
                                if (data.success) {
                                    logToTerminal(`[Import] Python validation completed for "${file.name}"`, "info");
                                    if (data.validation_report && data.validation_report.warnings.length > 0) {
                                        data.validation_report.warnings.forEach(warn => {
                                            logToTerminal(`[Validation Warning] ${warn}`, "warn");
                                        });
                                    }
                                    if (data.validation_report && data.validation_report.errors.length > 0) {
                                        data.validation_report.errors.forEach(err => {
                                            logToTerminal(`[Validation Error] ${err}`, "error");
                                        });
                                    }
                                    ingestParsedRows(data.rows);
                                } else {
                                    logToTerminal(`[Import] Python validation failed: ${data.message}`, "error");
                                    alert(`❌ Python Validation Failed: ${data.message}`);
                                }
                            })
                            .catch(err => {
                                logToTerminal(`[Import] Backend connection error: ${err.message}. Falling back to client-side parsing.`, "warn");
                                runFallbackCsvParse(file, isExcel);
                            });
                    } catch (err) {
                        logToTerminal(`[Import] Error preparing backend upload: ${err.message}. Falling back to client-side parsing.`, "warn");
                        runFallbackCsvParse(file, isExcel);
                    }
                };
                reader.readAsDataURL(file);
            } else {
                runFallbackCsvParse(file, isExcel);
            }
            event.target.value = "";
        }

        function runFallbackCsvParse(file, isExcel) {
            const reader = new FileReader();
            reader.onload = function (e) {
                let data = e.target.result;
                let workbook;
                try {
                    if (isExcel) {
                        const bytes = new Uint8Array(data);
                        workbook = XLSX.read(bytes, { type: "array" });
                    } else {
                        workbook = XLSX.read(data, { type: "string" });
                    }
                } catch (err) {
                    logToTerminal(`[Import] Parsing failed: ${err.message}`, "error");
                    return;
                }

                const firstSheetName = workbook.SheetNames[0];
                const worksheet = workbook.Sheets[firstSheetName];
                const rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: "" });
                ingestParsedRows(rows);
            };

            if (isExcel) {
                reader.readAsArrayBuffer(file);
            } else {
                reader.readAsText(file);
            }
        }

        function ingestParsedRows(rows) {
            if (!rows || rows.length < 2) {
                logToTerminal(`[Import] Failed: File contains insufficient rows.`, "error");
                alert(`❌ Ingestion Failed: File has no data or has too few rows.`);
                return;
            }

            const headers = rows[0].map(h => String(h).trim());
            const lowerHeaders = headers.map(h => h.toLowerCase());

            function findColIdx(keywords) {
                for (let kw of keywords) {
                    for (let idx = 0; idx < headers.length; idx++) {
                        const h = lowerHeaders[idx];
                        if (kw.length <= 3) {
                            const words = h.split(/[^a-z0-9]+/);
                            if (words.includes(kw)) return idx;
                        } else {
                            if (h.includes(kw)) return idx;
                        }
                    }
                }
                return -1;
            }

            const nameIdx = findColIdx(["devicename", "hostname", "device", "host", "name", "computer", "machine", "system"]);
            const idIdx = findColIdx(["deviceid", "device id", "id", "assetid", "asset id", "uuid"]);
            const serialIdx = findColIdx(["serialnumber", "serial", "s/n", "sn", "uuid", "service tag", "servicetag", "tag", "asset tag", "assettag"]);
            const macIdx = findColIdx(["macaddress", "mac", "physical", "ethernet", "hardware"]);
            const mfgIdx = findColIdx(["manufacturer", "mfg", "make", "brand"]);
            const osIdx = findColIdx(["os", "operating system", "osversion", "os version", "platform"]);
            const osFamilyIdx = findColIdx(["osfamily", "os family"]);
            const userIdx = findColIdx(["assigneduser", "user", "username", "owner", "assigned"]);
            const loginIdx = findColIdx(["lastlogin", "login", "active", "date", "time"]);
            const locIdx = findColIdx(["location", "site", "office", "building"]);
            const locGrpIdx = findColIdx(["locationgroup", "locgroup", "group"]);
            const condIdx = findColIdx(["condition", "status", "state"]);

            // Compliance policy indices
            const adIdx = findColIdx(["active directory", "ad", "active_directory", "domain"]);
            const bitlockerIdx = findColIdx(["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"]);
            const zscalerIdx = findColIdx(["zscaler", "zscalar", "zscalr", "z-scaler", "z-scalar", "z-scalr", "zscaler client connector", "zscalar client connector", "zscalr client connector", "vpn"]);
            const nessusIdx = findColIdx(["nessus", "tenable", "vulnerability agent", "nessus agent", "scanner"]);
            const s1Idx = findColIdx(["sentinelone", "sentinel one", "s1", "endpoint agent", "edr", "antivirus"]);
            const sccmIdx = findColIdx(["sccm", "sccm agent", "mecm", "management agent", "patch agent"]);

            const standardIndices = new Set([
                nameIdx, idIdx, serialIdx, macIdx, mfgIdx, osIdx, osFamilyIdx,
                userIdx, loginIdx, locIdx, locGrpIdx, condIdx,
                adIdx, bitlockerIdx, zscalerIdx, nessusIdx, s1Idx, sccmIdx
            ]);

            const newDataset = [];
            const dataRows = rows.slice(1);

            dataRows.forEach((row, rIdx) => {
                if (!row || row.every(cell => String(cell).trim() === "")) return;

                while (row.length < headers.length) {
                    row.push("");
                }

                const devName = nameIdx !== -1 ? String(row[nameIdx]).trim() : `import-device-${rIdx + 1}`;
                const devId = idIdx !== -1 ? String(row[idIdx]).trim() : `dev-${Math.random().toString(36).substring(2, 8)}`;
                const serial = serialIdx !== -1 ? String(row[serialIdx]).trim() : `SN-IMP-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
                const mac = macIdx !== -1 ? String(row[macIdx]).trim() : `00:1A:2B:3C:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}`;
                const manufacturer = mfgIdx !== -1 ? String(row[mfgIdx]).trim() : "Imported Asset";
                const os = osIdx !== -1 ? String(row[osIdx]).trim() : "Windows 11 Enterprise";
                let os_family = osFamilyIdx !== -1 ? String(row[osFamilyIdx]).trim() : "";
                if (!os_family) {
                    os_family = (os.toLowerCase().includes("mac") ? "macOS" : (os.toLowerCase().includes("linux") || os.toLowerCase().includes("ubuntu") ? "Linux" : "Windows"));
                } else {
                    const lowFamily = os_family.toLowerCase();
                    if (lowFamily.includes("win")) os_family = "Windows";
                    else if (lowFamily.includes("mac") || lowFamily.includes("osx")) os_family = "macOS";
                    else if (lowFamily.includes("linux") || lowFamily.includes("ubuntu") || lowFamily.includes("redhat")) os_family = "Linux";
                    else os_family = "Windows";
                }
                const user_assigned = userIdx !== -1 ? String(row[userIdx]).trim() : "unassigned";
                const last_login = loginIdx !== -1 ? String(row[loginIdx]).trim() : "-";
                const location = locIdx !== -1 ? String(row[locIdx]).trim() : "Remote";
                const location_group = locGrpIdx !== -1 ? String(row[locGrpIdx]).trim() : "Non-Sift";

                let condition = "UNKNOWN";
                if (condIdx !== -1) {
                    const rawCond = String(row[condIdx]).trim().toUpperCase().replace(/[\s-]+/g, "_").replace(/[^A-Z0-9_]/g, "");
                    const validConditions = ["IN_USE", "IN_REPAIR", "IN_STORE", "EXPIRED", "DISPOSED", "DECOMMISSIONED", "LOANABLE_RESERVED", "NOT_TRACEABLE", "RESERVED", "UNKNOWN"];
                    if (validConditions.includes(rawCond)) {
                        condition = rawCond;
                    } else if (rawCond === "ACTIVE" || rawCond === "USE") {
                        condition = "IN_USE";
                    } else if (rawCond === "RETIRED") {
                        condition = "DISPOSED";
                    }
                }

                function getAgentStatus(idx, agentName) {
                    if (idx === -1) return { installed: "MISSING (AGENT UNREPORTED)", status: "NON_COMPLIANT" };
                    const val = String(row[idx]).trim();

                    if (agentName.toLowerCase().includes("ad") || agentName.toLowerCase().includes("active directory")) {
                        const lowerVal = val.toLowerCase();
                        const nonCompliantAD = ["workgroup", "none", "no", "failed", "false", "0", "not enrolled", "not_enrolled", "unenrolled", "missing", "-", "not joined", "not_joined", "non-joined", "unjoined", "not domain joined", "not domain-joined", "unassociated", "notregistered", "not registered"];
                        if (lowerVal && !nonCompliantAD.includes(lowerVal)) {
                            return { installed: val, status: "COMPLIANT" };
                        }
                    }

                    const statusObj = evaluateComplianceValue(val);
                    return {
                        installed: statusObj.status === "COMPLIANT" ? "INSTALLED" : (val || "MISSING"),
                        status: statusObj.status
                    };
                }

                const software = [
                    { name: "Active Directory (AD) Enrollment", key: "ad", ...getAgentStatus(adIdx, "AD Enrollment") },
                    { name: "BitLocker Drive Encryption", key: "bitlocker", ...getAgentStatus(bitlockerIdx, "BitLocker") },
                    { name: "Zscaler Client Connector", key: "zscaler", ...getAgentStatus(zscalerIdx, "Zscaler Client Connector") },
                    { name: "Nessus Vulnerability Agent", key: "nessus", ...getAgentStatus(nessusIdx, "Nessus Vulnerability Agent") },
                    { name: "SentinelOne Endpoint Protection", key: "sentinelone", ...getAgentStatus(s1Idx, "SentinelOne Endpoint Protection") },
                    { name: "SCCM Management Agent", key: "sccm", ...getAgentStatus(sccmIdx, "SCCM Management Agent") }
                ];

                const custom_properties = {};
                headers.forEach((h, idx) => {
                    if (!standardIndices.has(idx)) {
                        custom_properties[h] = String(row[idx]).trim();
                    }
                });

                newDataset.push({
                    id: devId,
                    canonical_name: devName.toLowerCase(),
                    serial: serial,
                    mac: mac,
                    manufacturer: manufacturer,
                    os: os,
                    os_family: os_family,
                    score: 100.00,
                    level: "COMPLIANT",
                    condition: condition,
                    software: software,
                    user_assigned: user_assigned,
                    last_login: last_login,
                    location: location,
                    location_group: (location_group.toLowerCase() === "sift" ? "Sift" : "Non-Sift"),
                    is_isolated: false,
                    is_rogue: false,
                    custom_properties: custom_properties
                });
            });

            fleetDataset = newDataset;
            filteredDataset = [...fleetDataset];
            selectedDevice = null;

            activeTableHeaders = ["Device ID", "Canonical Name", "Assigned User", "Last Login", "Location", "Loc Group", "Condition"];
            activeTableKeys = ["id", "canonical_name", "user_assigned", "last_login", "location", "location_group", "condition"];

            const importedKeys = new Set();
            fleetDataset.forEach(dev => {
                if (dev.custom_properties) {
                    for (let key in dev.custom_properties) {
                        importedKeys.add(key);
                    }
                }
            });

            importedKeys.forEach(k => {
                const customKey = `custom:${k}`;
                if (!activeTableKeys.includes(customKey)) {
                    activeTableHeaders.push(k);
                    activeTableKeys.push(customKey);
                }
            });

            currentPage = 1;
            // Switch to the compliance view immediately so user sees the table
            switchNavSection("compliance");
            // Populate table with un-scored rows so the view is not blank during async recalc
            populateFleetTable();
            updateFleetWideMetrics();

            // recalculateAllScores is async (chunked). It calls _doFleetFilter + updateFleetWideMetrics
            // again when done, which will refresh the table with final scored values.
            recalculateAllScores();

            logToTerminal(`[Import] Successfully ingested ${fleetDataset.length} devices from the uploaded spreadsheet. Dynamic headers registered.`, "info");
            alert(`Spreadsheet Ingestion Complete! Loaded ${fleetDataset.length} devices.`);
        }

        function triggerClearFleetData() {
            const confirmPurge = confirm("WARNING: Are you sure you want to clear the entire compliance database? All assets will be deleted.");
            if (!confirmPurge) return;

            fleetDataset = [];
            filteredDataset = [];
            selectedDevice = null;

            // Reset headers
            activeTableHeaders = ["Device ID", "Canonical Name", "Assigned User", "Last Login", "Location", "Loc Group", "Condition"];
            activeTableKeys = ["id", "canonical_name", "user_assigned", "last_login", "location", "location_group", "condition"];

            // Clear spreadsheet reconciler cache and workspace data
            reconcilerSheets = [];
            reconciliationResults = {
                matches: [],
                gaps: [],
                rogues: []
            };
            mergedSoftwareAgents = new Set();

            // Invalidate caches so stale stats don't persist after purge
            invalidatePolicyStatsCache();

            // Clear file input UI elements
            const csvImportFile = document.getElementById("csv-import-file");
            if (csvImportFile) csvImportFile.value = "";
            const reconcilerMultiFiles = document.getElementById("reconciler-multi-files");
            if (reconcilerMultiFiles) reconcilerMultiFiles.value = "";

            // Hide reconciler results sub-panel wrapper
            const reconcilerResultsWrapper = document.getElementById("reconciler-results-wrapper");
            if (reconcilerResultsWrapper) {
                reconcilerResultsWrapper.style.display = "none";
            }

            // Clear selected device details panel
            const detailsDefaultMsg = document.getElementById("details-default-msg");
            if (detailsDefaultMsg) detailsDefaultMsg.style.display = "block";
            const detailsContentBox = document.getElementById("details-content-box");
            if (detailsContentBox) detailsContentBox.style.display = "none";

            // Update all views, metrics, and render states
            renderReconcilerQueue();
            // Guard currentReconTab — may be undefined if reconciler was never opened
            if (currentReconTab) switchReconTab(currentReconTab);
            updateFleetWideMetrics();
            handleFleetQueryChange();

            logToTerminal(`[Database] Fleet ledger purged successfully. Total active assets: 0.`, "warning");
            alert("Database Purged: All assets have been cleared successfully.");
        }

        // Debounce timer for search/filter changes
        let _fleetQueryDebounceTimer = null;

        function handleFleetQueryChange() {
            // Debounce: wait 250ms after the last keystroke before filtering 14k rows
            if (_fleetQueryDebounceTimer) clearTimeout(_fleetQueryDebounceTimer);
            _fleetQueryDebounceTimer = setTimeout(_doFleetFilter, 250);
        }

        function _doFleetFilter() {
            invalidateUploadedSoftwareCache();
            const query = ((document.getElementById("fleet-search-input") || {}).value || "").toLowerCase();
            const riskFilter = "ALL";
            const conditionFilter = (document.getElementById("fleet-filter-condition") || {}).value || "ALL";
            const locGroupFilter = (document.getElementById("fleet-filter-loc-group") || {}).value || "ALL";
            const osPlatformFilter = "ALL";
            const policyFilter = (document.getElementById("fleet-filter-policy") || {}).value || "ALL";

            const hasQuery = query.length > 0;
            const hasFilters = conditionFilter !== "ALL" || locGroupFilter !== "ALL" || policyFilter !== "ALL";

            // Fast path: no search query and no filters — show full dataset instantly
            if (!hasQuery && !hasFilters) {
                filteredDataset = fleetDataset;
                currentPage = 1;
                populateFleetTable();
                // Defer policy comparison to next frame so table renders first
                requestAnimationFrame(() => renderCorePoliciesComparison());
                return;
            }

            filteredDataset = fleetDataset.filter(item => {
                let matchesSearch = true;
                if (hasQuery) {
                    let matchesCustom = false;
                    if (item.custom_properties) {
                        for (let key in item.custom_properties) {
                            if (String(item.custom_properties[key]).toLowerCase().includes(query)) {
                                matchesCustom = true;
                                break;
                            }
                        }
                    }

                    matchesSearch =
                        String(item.id || "").toLowerCase().includes(query) ||
                        String(item.canonical_name || "").toLowerCase().includes(query) ||
                        String(item.serial || "").toLowerCase().includes(query) ||
                        String(item.os || "").toLowerCase().includes(query) ||
                        String(item.condition || "").toLowerCase().includes(query) ||
                        String(item.user_assigned || "").toLowerCase().includes(query) ||
                        String(item.location || "").toLowerCase().includes(query) ||
                        matchesCustom;
                }

                const matchesRisk = (riskFilter === "ALL") || (item.level === riskFilter);
                const matchesCondition = (conditionFilter === "ALL") || (item.condition === conditionFilter);
                const matchesLocGroup = (locGroupFilter === "ALL") || (item.location_group === locGroupFilter);

                // OS family match: check if matches family or if family string is contained
                const matchesOS = (osPlatformFilter === "ALL") ||
                    (item.os_family && String(item.os_family).toLowerCase() === osPlatformFilter.toLowerCase()) ||
                    (item.os && String(item.os).toLowerCase().includes(osPlatformFilter.toLowerCase()));

                let matchesPolicy = true;
                if (policyFilter !== "ALL") {
                    const parts = policyFilter.split(":");
                    const type = parts[0]; // "core" or "custom"
                    const requiredStatus = parts[parts.length - 1]; // "COMPLIANT" or "NON_COMPLIANT"
                    const keyOrName = parts.slice(1, parts.length - 1).join(":");

                    let isCompliant = false;
                    if (type === "core") {
                        const sw = item.software && item.software.find(s => s.key === keyOrName);
                        if (sw) {
                            const isUploaded = isSheetUploadedForSoftware(sw.key);
                            const isEverMerged = typeof mergedSoftwareAgents !== "undefined" && mergedSoftwareAgents.has(sw.key);
                            const alwaysReported = sw.key === "ad";
                            if (!alwaysReported && !isUploaded && !isEverMerged) {
                                isCompliant = true; // Bypassed core agent compliance
                            } else {
                                isCompliant = (sw.status === "COMPLIANT");
                            }
                        } else {
                            isCompliant = false;
                        }
                    } else {
                        const val = (item.custom_properties && item.custom_properties[keyOrName] !== undefined) ? item.custom_properties[keyOrName] : "MISSING";
                        isCompliant = val !== "MISSING" && !["fail", "failed", "inactive", "missing", "no", "disabled"].includes(val.toLowerCase());
                    }
                    matchesPolicy = (isCompliant ? "COMPLIANT" : "NON_COMPLIANT") === requiredStatus;
                }

                return matchesSearch && matchesRisk && matchesCondition && matchesLocGroup && matchesOS && matchesPolicy;
            });

            currentPage = 1;
            populateFleetTable();
            // Defer policy comparison to next frame so table renders first
            requestAnimationFrame(() => renderCorePoliciesComparison());
        }

        function changePage(direction) {
            const maxPage = Math.ceil(filteredDataset.length / pageSize) || 1;
            currentPage += direction;
            if (currentPage < 1) currentPage = 1;
            if (currentPage > maxPage) currentPage = maxPage;
            populateFleetTable();
        }

        function getConditionBadgeClass(state) {
            switch (state) {
                case "IN_USE": return "state-use";
                case "IN_REPAIR": return "state-repair";
                case "BROKEN": return "state-broken";
                case "UNKNOWN": return "state-unknown";
                default: return "state-decom";
            }
        }

        function getRiskBadgeClass(level) {
            return level === "COMPLIANT" ? "risk-low" : "risk-critical";
        }

        function showDeviceAuditDetails(devId) {
            const dev = fleetDataset.find(d => d.id === devId);
            if (!dev) return;

            selectedDevice = devId;

            document.getElementById("details-default-msg").style.display = "none";
            const contentBox = document.getElementById("details-content-box");
            contentBox.style.display = "grid";

            document.getElementById("det-name").innerText = dev.canonical_name.toUpperCase();
            document.getElementById("det-id").innerText = dev.id;
            document.getElementById("det-serial").innerText = dev.serial;

            const condBadge = document.getElementById("det-condition-badge");
            condBadge.innerText = dev.condition.replace("_", " ");
            condBadge.className = `badge ${getConditionBadgeClass(dev.condition)}`;

            const levelBadge = document.getElementById("det-level-badge");
            levelBadge.innerText = dev.level === "COMPLIANT" ? "Compliant" : "Non-Compliant";
            levelBadge.className = `badge ${getRiskBadgeClass(dev.level)}`;

            // Toggle isolation alert banner
            const banner = document.getElementById("det-isolation-banner");
            if (dev.is_isolated) {
                banner.style.display = "block";
            } else {
                banner.style.display = "none";
            }

            // Populate newly requested fields
            document.getElementById("det-user").innerText = dev.user_assigned;
            document.getElementById("det-login").innerText = dev.last_login;
            document.getElementById("det-location").innerText = dev.location;

            const locGrpBadge = document.getElementById("det-loc-group");
            locGrpBadge.innerText = dev.location_group;
            locGrpBadge.className = `badge ${dev.location_group === 'Sift' ? 'group-sift' : 'group-non-sift'}`;

            const tbody = document.getElementById("det-software-tbody");
            tbody.innerHTML = "";
            dev.software.forEach(sw => {
                const tr = document.createElement("tr");
                const statusText = sw.status === "COMPLIANT" ? "Compliant" : "Non-Compliant";
                tr.innerHTML = `
                    <td><strong>${escapeHTML(sw.name)}</strong></td>
                    <td style="font-family: var(--font-mono);">${escapeHTML(sw.installed)}</td>
                    <td style="font-family: var(--font-mono); color: var(--text-secondary);">${escapeHTML(sw.required)}</td>
                    <td><span class="badge ${sw.status === 'COMPLIANT' ? 'risk-low' : 'risk-critical'}">${escapeHTML(statusText)}</span></td>
                `;
                tbody.appendChild(tr);
            });

            // Populate custom dynamic parameters
            const customSection = document.getElementById("det-custom-params-section");
            const customTbody = document.getElementById("det-custom-params-tbody");

            if (dev.custom_properties && Object.keys(dev.custom_properties).length > 0) {
                customSection.style.display = "block";
                customTbody.innerHTML = "";

                Object.entries(dev.custom_properties).forEach(([key, val]) => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td><strong>${escapeHTML(key)}</strong></td>
                        <td style="font-family: var(--font-mono); color: var(--text-primary);">${escapeHTML(val)}</td>
                    `;
                    customTbody.appendChild(tr);
                });
            } else {
                customSection.style.display = "none";
            }

            // Generate deterministic scoring trend sparkline points (6 historical intervals)
            const sparklinePath = document.getElementById("det-sparkline-path");
            if (sparklinePath) {
                const trendScores = [];
                const seed = dev.id.charCodeAt(dev.id.length - 1) || 42;
                for (let k = 0; k < 5; k++) {
                    const modifier = Math.sin(k + seed) * 10;
                    let prevScore = dev.score - (5 - k) * 2.5 + modifier;
                    prevScore = Math.min(100, Math.max(0, parseFloat(prevScore.toFixed(2))));
                    trendScores.push(prevScore);
                }
                trendScores.push(dev.score);

                const mapX = (idx) => 10 + (idx * 46);
                const mapY = (score) => 70 - ((score / 100) * 60);

                let pathD = `M ${mapX(0)},${mapY(trendScores[0])}`;
                for (let k = 1; k < trendScores.length; k++) {
                    pathD += ` L ${mapX(k)},${mapY(trendScores[k])}`;
                }
                sparklinePath.setAttribute("d", pathD);

                const dotsContainer = document.getElementById("det-sparkline-dots");
                if (dotsContainer) {
                    dotsContainer.innerHTML = "";
                    trendScores.forEach((score, idx) => {
                        const cx = mapX(idx);
                        const cy = mapY(score);

                        // Adaptive vertical text offset: if dot near top, render numeric score below it, else above it
                        const textYOffset = cy < 20 ? cy + 12 : cy - 8;

                        dotsContainer.innerHTML += `
                            <circle cx="${cx}" cy="${cy}" r="3" fill="#ffffff" stroke="var(--color-accent)" stroke-width="1.5"></circle>
                            <text x="${cx}" y="${textYOffset}" font-size="8px" fill="var(--text-secondary)" font-family="var(--font-mono)" font-weight="700" text-anchor="middle">${score.toFixed(1)}</text>
                        `;
                    });
                }
            }

            // Update Network Isolation Button state
            const isolateBtn = document.getElementById("btn-isolate-device");
            if (isolateBtn) {
                if (dev.is_isolated) {
                    isolateBtn.innerHTML = `<span>Reconnect Host</span> <span style="font-weight:400; opacity: 0.8;">Active</span>`;
                    isolateBtn.style.background = "var(--status-low)";
                    isolateBtn.style.borderColor = "var(--status-low)";
                } else {
                    isolateBtn.innerHTML = `<span>Isolate Network Host</span> <span style="font-weight:400; opacity: 0.8;">Block</span>`;
                    isolateBtn.style.background = "var(--status-critical)";
                    isolateBtn.style.borderColor = "var(--status-critical)";
                }
            }

            logToTerminal(`[Audit] Loaded software and corporate metadata audits for device ID ${dev.id}`);
            populateFleetTable();
            enforceRoleBasedControls();
        }

        // Unified score calculation algorithm link software table status and dynamic Excel properties dynamically
        function recalculateSingleDeviceScore(dev, policies = null) {
            if (dev.is_isolated) {
                dev.score = 10.00;
                dev.level = "NON_COMPLIANT";
                return;
            }
            if (dev.condition !== "IN_USE" && dev.condition !== "UNKNOWN") {
                dev.score = 0.00;
                dev.level = "NON_COMPLIANT";
                return;
            }
            if (dev.is_rogue) {
                dev.score = 0.00;
                dev.level = "NON_COMPLIANT";
                return;
            }

            let score = 100.00;
            let hasNonCompliant = false;

            const activePolicies = policies || getAvailablePolicies();
            for (let name of activePolicies) {
                const isRequired = enforcedPolicies[name] !== false; // Required by default
                if (!isRequired) continue;

                // Check OS applicability for AD, BitLocker, and SCCM (Windows-only)
                const isWindows = dev.os_family && String(dev.os_family).toLowerCase().includes("win");
                const isApplicable = !["Active Directory (AD) Enrollment", "BitLocker Drive Encryption", "SCCM Management Agent"].includes(name) || isWindows;
                if (!isApplicable) continue;

                if (!name.startsWith('[')) {
                    // Check core software agent compliance
                    const sw = dev.software && dev.software.find(s => s.name === name);
                    if (sw) {
                        const isUploaded = isSheetUploadedForSoftware(sw.key);
                        const isEverMerged = typeof mergedSoftwareAgents !== "undefined" && mergedSoftwareAgents.has(sw.key);
                        const alwaysReported = sw.key === "ad";

                        // If the sheet is NOT uploaded and was NEVER merged, we bypass compliance verification
                        if (!alwaysReported && !isUploaded && !isEverMerged) {
                            continue;
                        }

                        if (sw.status === "NON_COMPLIANT") {
                            hasNonCompliant = true;
                            break;
                        }
                    }
                } else {
                    // Check custom spreadsheet policy compliance
                    const val = (dev.custom_properties && dev.custom_properties[name] !== undefined) ? dev.custom_properties[name] : "MISSING";
                    const isCompliant = val !== "MISSING" && !["fail", "failed", "inactive", "missing", "no", "disabled"].includes(val.toLowerCase());
                    if (!isCompliant) {
                        hasNonCompliant = true;
                        break;
                    }
                }
            }

            if (hasNonCompliant) {
                score = 0.00;
            }

            dev.score = parseFloat(score.toFixed(2));
            dev.level = (dev.score === 100.00) ? "COMPLIANT" : "NON_COMPLIANT";
        }

        // Remediation trigger handler simulation
        function triggerDeviceRemediation(action) {
            if (!selectedDevice) return;
            const dev = fleetDataset.find(d => d.id === selectedDevice);
            if (!dev) return;

            let buttonSelector = "";
            let prefix = "";

            if (action === 'PATCH') {
                buttonSelector = "PATCH";
                prefix = "[SCCM PATCH]";
                logToTerminal(`${prefix} Initiating remote SCCM policy sync & updates installation for host ${dev.canonical_name.toUpperCase()} (ID: ${dev.id})...`);
            } else if (action === 'EDR') {
                buttonSelector = "EDR";
                prefix = "[SentinelOne EDR]";
                logToTerminal(`${prefix} Dispatched remote threat verification scan command...`);
            } else if (action === 'VAULT') {
                buttonSelector = "VAULT";
                prefix = "[HashiCorp Vault]";
                logToTerminal(`${prefix} Initializing secure BitLocker cryptographic recovery escrow session...`);
            }

            // Button feedback loaders
            const buttons = document.querySelectorAll(".btn-secondary");
            let targetBtn = null;
            buttons.forEach(btn => {
                if (btn.getAttribute("onclick") && btn.getAttribute("onclick").includes(action)) {
                    targetBtn = btn;
                }
            });

            if (targetBtn) {
                targetBtn.disabled = true;
                const originalHtml = targetBtn.innerHTML;
                targetBtn.innerHTML = `<span>Processing Remediation...</span> <span style="font-weight:400; color:var(--text-muted);">${action}</span>`;

                setTimeout(() => {
                    targetBtn.disabled = false;
                    targetBtn.innerHTML = originalHtml;

                    if (action === 'PATCH') {
                        let patchesApplied = 0;
                        dev.software.forEach(sw => {
                            if (sw.status === "NON_COMPLIANT" && !sw.name.includes("SentinelOne") && !sw.name.includes("Active Directory")) {
                                sw.installed = "INSTALLED";
                                sw.status = "COMPLIANT";
                                patchesApplied++;
                                logToTerminal(`${prefix} Control agent "${sw.name}" successfully upgraded & verified.`, "info");
                            }
                        });
                        logToTerminal(`${prefix} Patch reconciliation completed. Applied ${patchesApplied} pending security updates.`, "info");
                    } else if (action === 'EDR') {
                        let threatsQuarantined = 0;
                        dev.software.forEach(sw => {
                            if (sw.name.includes("SentinelOne") && sw.status === "NON_COMPLIANT") {
                                sw.installed = "INSTALLED";
                                sw.status = "COMPLIANT";
                                threatsQuarantined++;
                                logToTerminal(`${prefix} SentinelOne agent upgraded and quarantined threat nodes.`, "info");
                            }
                        });
                        logToTerminal(`${prefix} Active threat quarantine verified. Agent operational.`, "info");
                    } else if (action === 'VAULT') {
                        let vaultRestored = 0;
                        dev.software.forEach(sw => {
                            if (sw.name.includes("BitLocker") && sw.status === "NON_COMPLIANT") {
                                sw.installed = "INSTALLED";
                                sw.status = "COMPLIANT";
                                vaultRestored++;
                                logToTerminal(`${prefix} Drive encrypted and keys escrowed to HashiCorp Vault.`, "info");
                            }
                        });
                        logToTerminal(`${prefix} Secure escrow verified. Transported AES-256 BitLocker recovery keys to vault mount "secret/data/tenants/${dev.id}". Key lease lease-id-${Math.random().toString(36).substring(7)} created.`, "info");
                    }

                    recalculateSingleDeviceScore(dev);
                    showDeviceAuditDetails(dev.id);
                    populateFleetTable();
                    updateFleetWideMetrics();
                }, 800);
            }
        }

        // Subnet Isolation Containment control
        function toggleDeviceIsolation() {
            if (!selectedDevice) return;
            const dev = fleetDataset.find(d => d.id === selectedDevice);
            if (!dev) return;

            const prefix = "[EDR Containment]";

            if (dev.is_isolated) {
                dev.is_isolated = false;
                logToTerminal(`${prefix} Restored network routes and unlocked firewall rules for host ${dev.canonical_name.toUpperCase()}. Reconnected.`, "info");
            } else {
                dev.is_isolated = true;
                logToTerminal(`${prefix} WARNING: HOST ISOLATION TRIGGERED for host ${dev.canonical_name.toUpperCase()} (ID: ${dev.id}). Port blocks successfully active.`, "error");
            }

            recalculateSingleDeviceScore(dev);
            showDeviceAuditDetails(dev.id);
            populateFleetTable();
            updateFleetWideMetrics();
        }

        function renderTableHeaders() {
            const head = document.getElementById("fleet-table-head");
            if (!head) return;
            let html = "<tr>";
            activeTableHeaders.forEach(h => {
                html += `<th>${escapeHTML(h)}</th>`;
            });
            html += "</tr>";
            head.innerHTML = html;
        }

        function populateFleetTable() {
            renderTableHeaders(); // Ensure dynamic headers are populated in original order

            const body = document.getElementById("fleet-table-body");
            body.innerHTML = "";

            const total = filteredDataset.length;
            const startIdx = (currentPage - 1) * pageSize;
            const endIdx = Math.min(startIdx + pageSize, total);

            const displaySlice = filteredDataset.slice(startIdx, endIdx);

            if (displaySlice.length === 0) {
                const colSpan = activeTableHeaders.length;
                body.innerHTML = `<tr><td colspan="${colSpan}" style="text-align: center; color: var(--text-secondary); font-style: italic; padding: 2rem;">No matching assets found.</td></tr>`;
            } else {
                displaySlice.forEach(dev => {
                    const isSelected = (dev.id === selectedDevice) ? "selected-row" : "";
                    const tr = document.createElement("tr");
                    tr.className = isSelected;
                    tr.setAttribute("onclick", `showDeviceAuditDetails('${dev.id}')`);

                    let rowHtml = "";
                    activeTableKeys.forEach((key, headerIdx) => {
                        let val = "";
                        let isCustom = key.startsWith("custom:");
                        let isCompliance = key.startsWith("compliance:");
                        let actualKey = (isCustom || isCompliance) ? key.substring(key.indexOf(":") + 1) : key;

                        if (isCustom) {
                            val = (dev.custom_properties && dev.custom_properties[actualKey] !== undefined) ? dev.custom_properties[actualKey] : "-";
                        } else if (isCompliance) {
                            const swAgent = dev.software.find(sw => sw.name === actualKey || sw.key === key);
                            val = swAgent ? swAgent.installed : "MISSING";
                        } else {
                            if (actualKey === "ad" || actualKey === "bitlocker" || actualKey === "zscaler" || actualKey === "nessus" || actualKey === "sentinelone" || actualKey === "sccm") {
                                const swAgent = dev.software.find(sw => sw.key === actualKey);
                                val = swAgent ? swAgent.installed : "MISSING";
                            } else {
                                val = dev[actualKey] !== undefined ? dev[actualKey] : "-";
                            }
                        }

                        // Rich formatting for key columns:
                        if (actualKey === "canonical_name") {
                            const escapedName = escapeHTML(val);
                            let deviceNameMarkup = escapedName;
                            if (dev.is_isolated) {
                                deviceNameMarkup = `<span style="text-decoration: line-through; color: var(--status-critical); font-weight:700;">${escapedName}</span> <span class="badge risk-critical" style="font-size:0.6rem; padding: 0.1rem 0.25rem;">CONTAINED</span>`;
                            } else {
                                deviceNameMarkup = `<strong>${escapedName}</strong>`;
                            }
                            rowHtml += `<td>${deviceNameMarkup}</td>`;
                        } else if (actualKey === "id" || actualKey === "mac" || actualKey === "serial") {
                            rowHtml += `<td style="font-family: var(--font-mono); color: var(--text-secondary); font-size: 0.8rem;">${escapeHTML(String(val))}</td>`;
                        } else if (actualKey === "score") {
                            const numScore = parseFloat(val) || 0;
                            rowHtml += `<td style="font-weight: 700; font-family: var(--font-mono); color: ${getScoreColor(numScore)};">${numScore.toFixed(2)}</td>`;
                        } else if (actualKey === "level") {
                            const displayText = val === "COMPLIANT" ? "Compliant" : "Non-Compliant";
                            rowHtml += `<td><span class="badge ${getRiskBadgeClass(val)}">${escapeHTML(displayText)}</span></td>`;
                        } else if (actualKey === "condition") {
                            rowHtml += `<td><span class="badge ${getConditionBadgeClass(val)}">${escapeHTML(String(val).replace("_", " "))}</span></td>`;
                        } else if (actualKey === "location_group") {
                            rowHtml += `<td><span class="badge ${val === 'Sift' ? 'group-sift' : 'group-non-sift'}">${escapeHTML(String(val))}</span></td>`;
                        } else if (isCompliance || actualKey === "ad" || actualKey === "bitlocker" || actualKey === "zscaler" || actualKey === "nessus" || actualKey === "sentinelone" || actualKey === "sccm") {
                            const swAgent = dev.software.find(sw => sw.name === actualKey || sw.key === key || sw.key === actualKey);
                            const isCompliant = swAgent ? swAgent.status === 'COMPLIANT' : false;
                            rowHtml += `<td><span class="badge ${isCompliant ? 'risk-low' : 'risk-critical'}">${escapeHTML(String(val))}</span></td>`;
                        } else {
                            rowHtml += `<td>${escapeHTML(String(val))}</td>`;
                        }
                    });

                    tr.innerHTML = rowHtml;
                    body.appendChild(tr);
                });
            }

            document.getElementById("pag-start").innerText = total === 0 ? 0 : (startIdx + 1).toLocaleString();
            document.getElementById("pag-end").innerText = endIdx.toLocaleString();
            document.getElementById("pag-total").innerText = total.toLocaleString();

            const btnPrev = document.getElementById("btn-pag-prev");
            const btnNext = document.getElementById("btn-pag-next");

            btnPrev.disabled = (currentPage === 1);
            btnNext.disabled = (endIdx >= total);

            btnPrev.style.opacity = btnPrev.disabled ? 0.4 : 1;
            btnNext.style.opacity = btnNext.disabled ? 0.4 : 1;
            enforceRoleBasedControls();
            // NOTE: renderCorePoliciesComparison is NOT called here intentionally.
            // It is always called via requestAnimationFrame from _doFleetFilter / _finishRecalculate
            // to guarantee the table paints first and avoid double DOM writes.
        }

        function renderCorePoliciesComparison() {
            const grid = document.getElementById("core-policies-comparison-grid");
            if (!grid) return;

            const corePolicies = [
                "Active Directory (AD) Enrollment",
                "BitLocker Drive Encryption",
                "Zscaler Client Connector",
                "Nessus Vulnerability Agent",
                "SentinelOne Endpoint Protection",
                "SCCM Management Agent"
            ];

            const conditionFilter = (document.getElementById("fleet-filter-condition") || {}).value || "ALL";
            let html = "";
            corePolicies.forEach(name => {
                const isRequired = enforcedPolicies[name] !== false;
                const stats = getPolicyStats(name, conditionFilter);
                const isUnreported = stats.isUnreported;
                const showBlank = isUnreported || stats.filteredTotal === 0;

                // Pass rate % and counts scoped to the active condition filter
                const passRate = stats.filteredTotal > 0 ? (stats.filteredCompliant / stats.filteredTotal) * 100 : 0;
                const compliantCount = stats.filteredCompliant;
                const failCount = stats.filteredTotal - stats.filteredCompliant;

                // Color schemes based on compliance and enforcement
                let statusBadgeText = isRequired ? "Enforced" : "Optional";
                let statusBadgeClass = isRequired ? "group-sift" : "group-non-sift";

                let progressColor = "var(--status-low)"; // Compliant (Green)
                if (isRequired && passRate < 100) {
                    progressColor = passRate < 80 ? "var(--status-critical)" : "#eab308"; // Red or Yellow
                } else if (!isRequired) {
                    progressColor = "var(--text-muted)"; // Dimmed if optional
                }

                if (showBlank) {
                    progressColor = "var(--border-clean)";
                    if (isUnreported) {
                        statusBadgeText = "Unreported";
                        statusBadgeClass = "badge"; // default style
                    }
                }

                html += `
                    <div class="metric-widget core-policy-comparison-widget" style="border: 1px solid var(--border-clean); padding: 1.5rem; background: var(--bg-card); border-radius: 6px; display: flex; flex-direction: column; gap: 1rem; transition: transform 0.2s, box-shadow 0.2s; position: relative; overflow: hidden;">
                        <!-- Top status row -->
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 0.5rem;">
                            <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-secondary); font-weight: 700; letter-spacing: 0.05em; line-height: 1.3; max-width: 75%;">${escapeHTML(name)}</span>
                            <span class="badge ${statusBadgeClass}" style="font-size: 0.65rem; padding: 0.15rem 0.4rem; font-weight: 700; text-transform: uppercase;">${statusBadgeText}</span>
                        </div>

                        <!-- Big compliance number -->
                        <div style="display: flex; align-items: baseline; gap: 0.5rem; margin-top: 0.25rem;">
                            <span style="font-size: 1.8rem; font-family: var(--font-mono); font-weight: 800; color: ${progressColor};">${showBlank ? '-' : passRate.toFixed(1) + '%'}</span>
                            <span style="font-size: 0.75rem; color: var(--text-muted);">pass rate</span>
                        </div>

                        <!-- Progress Bar container -->
                        <div style="width: 100%; height: 6px; background: rgba(255, 255, 255, 0.05); border-radius: 3px; overflow: hidden;">
                            <div style="width: ${showBlank ? 0 : passRate}%; height: 100%; background: ${progressColor}; transition: width 0.4s ease-out;"></div>
                        </div>

                        <!-- Bottom detail statistics -->
                        <div style="display: grid; grid-template-columns: 1fr 1fr; grid-template-rows: auto auto; gap: 0.2rem 1rem; margin-top: 0.25rem; font-size: 0.78rem; border-top: 1px solid rgba(255, 255, 255, 0.05); padding-top: 0.75rem;">
                            <span style="color: var(--text-muted); display: block; grid-column: 1; grid-row: 1;">Compliant Assets</span>
                            <span style="color: var(--text-muted); display: block; text-align: right; grid-column: 2; grid-row: 1;">Non-Compliant Assets</span>
                            <strong style="color: var(--text-primary); font-family: var(--font-mono); font-size: 0.85rem; grid-column: 1; grid-row: 2;">${isUnreported ? 0 : compliantCount.toLocaleString()}</strong>
                            <strong style="color: ${failCount > 0 && isRequired ? 'var(--status-critical)' : 'var(--text-secondary)'}; font-family: var(--font-mono); font-size: 0.85rem; text-align: right; grid-column: 2; grid-row: 2;">${isUnreported ? 0 : failCount.toLocaleString()}</strong>
                        </div>
                    </div>
                `;
            });

            grid.innerHTML = html;
        }

        // Dynamic EDR S1 controls
        function calculateFingerprint(serial, mac0, manufacturer) {
            const raw = `${serial.trim().toLowerCase()}:${mac0.trim().toLowerCase()}:${manufacturer.trim().toLowerCase()}`;
            let hash = 0;
            for (let i = 0; i < raw.length; i++) {
                hash = (hash << 5) - hash + raw.charCodeAt(i);
                hash |= 0;
            }
            return "sha256-" + Math.abs(hash).toString(16).repeat(4).substring(0, 64);
        }

        function getLevenshteinDistance(s, t) {
            if (!s.length) return t.length;
            if (!t.length) return s.length;
            const arr = [];
            for (let i = 0; i <= t.length; i++) { arr[i] = [i]; }
            for (let j = 0; j <= s.length; j++) { arr[0][j] = j; }
            for (let i = 1; i <= t.length; i++) {
                for (let j = 1; j <= s.length; j++) {
                    const cost = t[i - 1] === s[j - 1] ? 0 : 1;
                    arr[i][j] = Math.min(
                        arr[i - 1][j] + 1,
                        arr[i][j - 1] + 1,
                        arr[i - 1][j - 1] + cost
                    );
                }
            }
            return arr[t.length][s.length];
        }

        function runReconciliationSimulation() {
            const nameInputEl = document.getElementById("recon-name");
            const serialInputEl = document.getElementById("recon-serial");
            const macInputEl = document.getElementById("recon-mac");
            const manufacturerInputEl = document.getElementById("recon-manufacturer");
            if (!nameInputEl || !serialInputEl || !macInputEl || !manufacturerInputEl) return;

            const nameInput = nameInputEl.value;
            const serialInput = serialInputEl.value;
            const macInput = macInputEl.value;
            const manufacturerInput = manufacturerInputEl.value;

            const normalizedInput = nameInput.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
            const fp = calculateFingerprint(serialInput, macInput, manufacturerInput);
            const outFpEl = document.getElementById("out-fp");
            if (outFpEl) outFpEl.innerText = fp;

            logToTerminal(`[Reconciler] Evaluation triggered for incoming name: "${nameInput}"`);

            const actionBadge = document.getElementById("out-action");

            const subset = fleetDataset.slice(0, 500);
            for (let dev of subset) {
                if (String(dev.canonical_name || "").replace(/[^a-zA-Z0-9]/g, "").toLowerCase() === normalizedInput) {
                    document.getElementById("out-stage").innerText = "Stage 1: Exact Match (Normalized Name)";
                    document.getElementById("out-confidence").innerText = "100.00%";
                    actionBadge.innerText = "AUTO_MERGE";
                    actionBadge.className = "badge risk-low";
                    document.getElementById("out-desc").innerText = `Reconciled perfectly against existing device ID ${dev.id}.`;
                    logToTerminal(`[Reconciler] Stage 1 Exact Match resolved against device ${dev.id} (Confidence 100%). Decision: AUTO_MERGE`, "info");
                    return;
                }
            }

            for (let dev of subset) {
                const devFp = calculateFingerprint(dev.serial, dev.mac, dev.manufacturer);
                if (devFp === fp || dev.serial === serialInput) {
                    document.getElementById("out-stage").innerText = "Stage 2: Hardware Fingerprint Matching";
                    document.getElementById("out-confidence").innerText = "95.00%";
                    actionBadge.innerText = "AUTO_MERGE";
                    actionBadge.className = "badge risk-low";
                    document.getElementById("out-desc").innerText = `Reconciled via hardware cryptographic fingerprint matching device ID ${dev.id}.`;
                    logToTerminal(`[Reconciler] Stage 2 Fingerprint matched device ${dev.id} (Confidence 95%). Decision: AUTO_MERGE`, "info");
                    return;
                }
            }

            let bestDist = 999;
            let matchedDev = null;
            for (let dev of subset) {
                const dist = getLevenshteinDistance(normalizedInput, dev.canonical_name);
                if (dist < bestDist) {
                    bestDist = dist;
                    matchedDev = dev;
                }
            }

            const threshold = Math.max(2, Math.floor(normalizedInput.length / 5));
            if (bestDist <= threshold) {
                const confidence = 100 - (bestDist * 15);
                const action = confidence >= 90 ? "AUTO_MERGE" : "HUMAN_QUEUE";

                document.getElementById("out-stage").innerText = "Stage 3: Levenshtein Edit Distance";
                document.getElementById("out-confidence").innerText = `${confidence.toFixed(2)}%`;
                actionBadge.innerText = action;
                actionBadge.className = action === "AUTO_MERGE" ? "badge risk-low" : "badge";
                document.getElementById("out-desc").innerText = `Name edit distance matched existing record "${matchedDev.canonical_name}" with distance value ${bestDist}.`;

                logToTerminal(`[Reconciler] Stage 3 Levenshtein resolved close match to "${matchedDev.canonical_name}" (Confidence ${confidence}%). Action: ${action}`, action === "AUTO_MERGE" ? "info" : "warn");
                return;
            }

            document.getElementById("out-stage").innerText = "Stage 5: Human Review Queue routing";
            document.getElementById("out-confidence").innerText = "0.00% (No baseline matches)";
            actionBadge.innerText = "HUMAN_QUEUE";
            actionBadge.className = "badge risk-critical";
            document.getElementById("out-desc").innerText = "No automated match met trust boundaries. Programmatically routing record to the verification queue.";
            logToTerminal("[Reconciler] Stage 5 triggered: no cryptographic or edit similarity found. Incident routed to security analyst queue.", "error");
        }

        function recalculateScores() {
            const edrEl = document.getElementById("score-edr");
            const patchEl = document.getElementById("score-patch");
            const encEl = document.getElementById("score-encryption");
            if (!edrEl || !patchEl || !encEl) return;

            const edr = edrEl.value;
            const patch = patchEl.value;
            const enc = encEl.value;

            let edrScore = edr === "compliant" ? 100 : edr === "threats" ? 40 : 0;
            let patchScore = patch === "compliant" ? 100 : patch === "late" ? 40 : 0;
            let encScore = enc === "compliant" ? 100 : 0;

            let criticalCount = 0;
            if (edr === "inactive") criticalCount++;
            if (patch === "eol") criticalCount++;
            if (enc === "disabled") criticalCount++;

            const baseScore = ((edrScore * 0.25) + (patchScore * 0.20) + (encScore * 0.15)) / 0.60;
            const penalty = Math.min(criticalCount * 0.25, 0.75);
            const finalScore = baseScore * (1 - penalty);

            const displayScore = document.getElementById("out-calc-score");
            const displayLevel = document.getElementById("out-calc-level");
            if (displayScore) displayScore.innerText = finalScore.toFixed(2);

            let riskTier = "COMPLIANT";
            let color = "#15803d";
            if (finalScore < 100) { riskTier = "NON-COMPLIANT"; color = "#b91c1c"; }

            if (displayScore) displayScore.style.color = color;
            if (displayLevel) {
                displayLevel.innerText = riskTier;
                displayLevel.style.color = color;
            }

            const penaltyLabel = document.getElementById("out-penalty-label");
            if (penaltyLabel) {
                if (criticalCount > 0) {
                    penaltyLabel.innerText = `Active Failures: ${criticalCount} (${(penalty * 100)}% Drop Applied)`;
                    penaltyLabel.style.color = "#b91c1c";
                } else {
                    penaltyLabel.innerText = "None (0% drop)";
                    penaltyLabel.style.color = "#16a34a";
                }
            }

            const outNistEl = document.getElementById("out-nist");
            if (outNistEl) {
                outNistEl.innerText = finalScore === 100 ? "100% Compliant" : `${finalScore.toFixed(0)}% Compliant`;
                outNistEl.style.color = finalScore === 100 ? "#16a34a" : "#a16207";
            }

            logToTerminal(`[Risk Engine] Compliance recalculated. Base: ${baseScore.toFixed(2)}, Criticals: ${criticalCount}, Final: ${finalScore.toFixed(2)} (${riskTier})`);
        }

        function runDriftSimulation() {
            const scenarioEl = document.getElementById("drift-scenario");
            const d7 = document.getElementById("drift-7");
            const d14 = document.getElementById("drift-14");
            const d30 = document.getElementById("drift-30");
            if (!scenarioEl || !d7 || !d14 || !d30) return;

            const scenario = scenarioEl.value;

            logToTerminal(`[AI Drift] Running 90-day LSTM timeseries projection for "${scenario}" scenario...`);

            if (scenario === "stable") {
                updateDriftDisplays(d7, 98.40, d14, 98.10, d30, 97.80);
            } else if (scenario === "decaying") {
                updateDriftDisplays(d7, 84.10, d14, 76.50, d30, 58.20);
            } else if (scenario === "critical") {
                updateDriftDisplays(d7, 52.00, d14, 38.50, d30, 12.00);
            }
        }

        function updateDriftDisplays(t7, v7, t14, v14, t30, v30) {
            t7.innerText = v7.toFixed(2); t7.style.color = getScoreColor(v7);
            t14.innerText = v14.toFixed(2); t14.style.color = getScoreColor(v14);
            t30.innerText = v30.toFixed(2); t30.style.color = getScoreColor(v30);
            logToTerminal(`[AI Drift] LSTM Forecast completed. 7d: ${v7}, 14d: ${v14}, 30d: ${v30}`);
        }

        function getScoreColor(score) {
            if (score < 40) return "#b91c1c";
            if (score < 65) return "#c2410c";
            if (score < 85) return "#a16207";
            return "#15803d";
        }

        function triggerOutbound(system) {
            logToTerminal(`[Vault] Authenticating and requesting dynamic secret lease for outbound client...`);
            logToTerminal(`[Vault] Generated dynamic session key: "vault-lease-${Math.random().toString(36).substring(7)}"`, "info");
            logToTerminal(`[Kong Gateway] Verified route mapping to outbound endpoints.`);

            const eventPayload = {
                specversion: "1.0",
                id: `evt-${Date.now()}`,
                source: "/compliance/risk-engine",
                type: `eud.integration.${system.toLowerCase()}`,
                subject: "device:dev-f2910a:compliance_audit",
                tenantid: "tenant-xyz",
                deviceid: "dev-f2910a",
                datacontenttype: "application/json",
                data: {
                    severity: "CRITICAL",
                    score: 24.50,
                    remediation: "S1 inactive, BitLocker disabled"
                }
            };

            logToTerminal(`[Event Bus] Dispatched CloudEvent 1.0 to topic "eud.integration.${system.toLowerCase()}"`, "info");
            logToTerminal(`[API POST] Payload: ${JSON.stringify(eventPayload)}`, "info");
        }

        // Fleet stats updater
        function updateFleetWideMetrics() {
            const activeFleet = fleetDataset.filter(d => d.condition === "IN_USE");
            const scaleVal = activeFleet.length;
            const fleetScaleEl = document.getElementById("fleet-scale-val");
            if (fleetScaleEl) fleetScaleEl.innerText = scaleVal.toLocaleString();

            const avg = scaleVal > 0 ? activeFleet.reduce((sum, item) => sum + item.score, 0) / scaleVal : 100;
            const scoreDisplay = document.getElementById("fleet-score-val");
            if (scoreDisplay) {
                scoreDisplay.innerText = avg.toFixed(2);
                scoreDisplay.style.color = getScoreColor(avg);
            }

            const riskLabel = document.getElementById("fleet-risk-label");
            if (riskLabel) {
                if (avg < 100) { riskLabel.innerText = "NON-COMPLIANT FLEET"; riskLabel.style.color = "#b91c1c"; }
                else { riskLabel.innerText = "FULLY COMPLIANT FLEET"; riskLabel.style.color = "#15803d"; }
            }

            // Defer chart renders to next animation frame — avoids blocking the main thread during data load
            requestAnimationFrame(() => {
                renderActiveTrendChart();
                renderActiveRiskChart();
            });
        }

        // SVG Charts and Telemetry Visualizations
        function renderActiveTrendChart() {
            const container = document.getElementById("analytics-trend-chart-container");
            const legend = document.getElementById("analytics-trend-legend");
            if (!container || !legend) return;

            const dimension = document.getElementById("analysis-chart-dimension").value;
            container.innerHTML = "";
            legend.innerHTML = "";

            if (dimension === "trend") {
                // Calculate fleet average compliance score
                const activeFleet = fleetDataset.filter(d => d.condition === "IN_USE");
                const scaleVal = activeFleet.length;
                const avg = scaleVal > 0 ? (activeFleet.reduce((sum, item) => sum + item.score, 0) / scaleVal) : 100;

                // Preceding 5 points + current point
                const months = ["Dec 2025", "Jan 2026", "Feb 2026", "Mar 2026", "Apr 2026", "May (Current)"];
                const points = [
                    Math.min(100, Math.max(0, avg - 4.5)),
                    Math.min(100, Math.max(0, avg - 3.2)),
                    Math.min(100, Math.max(0, avg - 1.8)),
                    Math.min(100, Math.max(0, avg - 2.5)),
                    Math.min(100, Math.max(0, avg - 0.7)),
                    Math.min(100, Math.max(0, avg))
                ];

                const minY = Math.max(0, Math.floor(Math.min(...points) - 5));
                const maxY = 100;
                const ySpan = (maxY - minY) || 1;

                const width = 600;
                const height = 220;
                const padLeft = 45;
                const padRight = 20;
                const padTop = 20;
                const padBottom = 30;

                const plotWidth = width - padLeft - padRight;
                const plotHeight = height - padTop - padBottom;

                const mapX = (idx) => padLeft + (idx * (plotWidth / 5));
                const mapY = (val) => padTop + plotHeight - (((val - minY) / ySpan) * plotHeight);

                let svgContent = `<svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" style="overflow: visible;">`;

                // Define linear gradient for glowing line area
                svgContent += `
                    <defs>
                        <linearGradient id="trend-area-gradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stop-color="var(--color-accent)" stop-opacity="0.15"/>
                            <stop offset="100%" stop-color="var(--color-accent)" stop-opacity="0.0"/>
                        </linearGradient>
                    </defs>
                `;

                // Draw Grid horizontal lines
                const gridTicks = 5;
                for (let i = 0; i <= gridTicks; i++) {
                    const val = minY + (i * (ySpan / gridTicks));
                    const cy = mapY(val);
                    svgContent += `
                        <line x1="${padLeft}" y1="${cy}" x2="${width - padRight}" y2="${cy}" stroke="var(--border-clean)" stroke-width="0.5" stroke-dasharray="3,3" />
                        <text x="${padLeft - 8}" y="${cy + 3}" font-size="9px" font-family="var(--font-mono)" fill="var(--text-muted)" text-anchor="end">${val.toFixed(0)}%</text>
                    `;
                }

                // Draw X-axis month labels
                months.forEach((m, idx) => {
                    const cx = mapX(idx);
                    svgContent += `
                        <text x="${cx}" y="${height - 8}" font-size="9px" font-weight="700" fill="var(--text-muted)" text-anchor="middle">${m}</text>
                    `;
                });

                // Generate path string for trend line
                let pathD = `M ${mapX(0)},${mapY(points[0])}`;
                for (let i = 1; i < points.length; i++) {
                    pathD += ` L ${mapX(i)},${mapY(points[i])}`;
                }

                // Area path for gradient fill
                const areaPathD = `${pathD} L ${mapX(points.length - 1)},${mapY(minY)} L ${mapX(0)},${mapY(minY)} Z`;

                // Render area under line
                svgContent += `<path d="${areaPathD}" fill="url(#trend-area-gradient)" />`;

                // Render active compliance path line
                svgContent += `<path d="${pathD}" stroke="var(--color-accent)" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round" />`;

                // Render Target SLA Threshold Line (85%)
                if (85 >= minY && 85 <= maxY) {
                    const slaY = mapY(85);
                    svgContent += `
                        <line x1="${padLeft}" y1="${slaY}" x2="${width - padRight}" y2="${slaY}" stroke="var(--status-low)" stroke-width="1.2" stroke-dasharray="4,4" />
                        <text x="${width - padRight - 5}" y="${slaY - 4}" font-size="8px" font-weight="700" fill="var(--status-low)" text-anchor="end">SLA Target (85.0%)</text>
                    `;
                }

                // Draw dots and interactive circles
                points.forEach((val, idx) => {
                    const cx = mapX(idx);
                    const cy = mapY(val);
                    svgContent += `
                        <circle cx="${cx}" cy="${cy}" r="4" fill="var(--bg-card)" stroke="var(--color-accent)" stroke-width="2" />
                        <circle cx="${cx}" cy="${cy}" r="12" fill="transparent" style="cursor: pointer;"
                            onmouseover="showTrendTooltip(event, '${months[idx]}', ${val.toFixed(2)})"
                            onmouseout="hideTrendTooltip()" />
                    `;
                });

                svgContent += `</svg>`;
                container.innerHTML = svgContent;

                // Legend
                legend.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem;">
                        <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: var(--color-accent);"></span>
                        <span>Fleet Compliance Average: <strong style="color: var(--text-primary);">${avg.toFixed(2)}%</strong></span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem;">
                        <span style="display: inline-block; width: 10px; height: 2px; border-top: 2px dashed var(--status-low);"></span>
                        <span style="color: var(--text-secondary);">Target Threshold SLA: <strong>85.0%</strong></span>
                    </div>
                `;
            } else if (dimension === "os") {
                // OS breakdown column chart
                let winCount = 0, macCount = 0, linuxCount = 0, otherCount = 0;
                fleetDataset.forEach(d => {
                    if (d.condition !== "IN_USE") return; // Filter active only!
                    const family = (d.os_family || "").toLowerCase();
                    const name = (d.os || "").toLowerCase();
                    if (family === "windows" || name.includes("windows")) winCount++;
                    else if (family === "macos" || name.includes("macos") || name.includes("sonoma")) macCount++;
                    else if (family === "linux" || name.includes("linux") || name.includes("ubuntu")) linuxCount++;
                    else otherCount++;
                });

                const total = winCount + macCount + linuxCount + otherCount;
                const osData = [
                    { name: "Windows", count: winCount, pct: total > 0 ? (winCount / total) * 100 : 0, color: "#334155" },
                    { name: "macOS", count: macCount, pct: total > 0 ? (macCount / total) * 100 : 0, color: "#0f172a" },
                    { name: "Linux", count: linuxCount, pct: total > 0 ? (linuxCount / total) * 100 : 0, color: "var(--color-accent)" },
                    { name: "Other", count: otherCount, pct: total > 0 ? (otherCount / total) * 100 : 0, color: "var(--status-low)" }
                ];

                const width = 600;
                const height = 220;
                const padLeft = 45;
                const padRight = 20;
                const padTop = 30;
                const padBottom = 30;

                const plotWidth = width - padLeft - padRight;
                const plotHeight = height - padTop - padBottom;

                const maxPct = Math.max(...osData.map(o => o.pct), 10);
                const maxVal = Math.ceil(maxPct / 10) * 10; // Round up to nearest 10

                let svgContent = `<svg width="100%" height="100%" viewBox="0 0 ${width} ${height}">`;

                // Horizontal grid lines
                const ticks = 4;
                for (let i = 0; i <= ticks; i++) {
                    const pctVal = (i * (maxVal / ticks));
                    const cy = padTop + plotHeight - ((pctVal / maxVal) * plotHeight);
                    svgContent += `
                        <line x1="${padLeft}" y1="${cy}" x2="${width - padRight}" y2="${cy}" stroke="var(--border-clean)" stroke-width="0.5" stroke-dasharray="3,3" />
                        <text x="${padLeft - 8}" y="${cy + 3}" font-size="9px" font-family="var(--font-mono)" fill="var(--text-muted)" text-anchor="end">${pctVal.toFixed(0)}%</text>
                    `;
                }

                // Render columns
                const colWidth = 60;
                const colGap = (plotWidth - (colWidth * 4)) / 5;

                osData.forEach((os, idx) => {
                    const cx = padLeft + colGap + (idx * (colWidth + colGap));
                    const colHeight = (os.pct / maxVal) * plotHeight;
                    const cy = padTop + plotHeight - colHeight;

                    svgContent += `
                        <rect x="${cx}" y="${cy}" width="${colWidth}" height="${colHeight}" fill="${os.color}" rx="3" ry="3"
                            style="transition: fill 0.2s; cursor: pointer;"
                            onmouseover="showOsTooltip(event, '${os.name}', ${os.count}, ${os.pct.toFixed(1)})"
                            onmouseout="hideTrendTooltip()" />
                        <text x="${cx + (colWidth / 2)}" y="${cy - 6}" font-size="9px" font-weight="700" fill="var(--text-primary)" font-family="var(--font-mono)" text-anchor="middle">${os.pct.toFixed(1)}%</text>
                        <text x="${cx + (colWidth / 2)}" y="${height - 8}" font-size="9px" font-weight="700" fill="var(--text-muted)" text-anchor="middle">${os.name}</text>
                    `;
                });

                svgContent += `</svg>`;
                container.innerHTML = svgContent;

                // Legend
                legend.innerHTML = osData.map(os => `
                    <div style="display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem;">
                        <span style="display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: ${os.color};"></span>
                        <span>${os.name}: <strong>${os.count.toLocaleString()}</strong> (${os.pct.toFixed(1)}%)</span>
                    </div>
                `).join("");

            } else if (dimension === "location") {
                // Location Group Distribution Comparison
                let siftCount = 0, nonSiftCount = 0;
                let siftScoreSum = 0, nonSiftScoreSum = 0;

                fleetDataset.forEach(d => {
                    if (d.condition !== "IN_USE") return; // Filter active only!
                    if (d.location_group === "Sift") {
                        siftCount++;
                        siftScoreSum += d.score;
                    } else {
                        nonSiftCount++;
                        nonSiftScoreSum += d.score;
                    }
                });

                const total = siftCount + nonSiftCount;
                const siftPct = total > 0 ? (siftCount / total) * 100 : 0;
                const nonSiftPct = total > 0 ? (nonSiftCount / total) * 100 : 0;

                const siftAvg = siftCount > 0 ? (siftScoreSum / siftCount) : 0;
                const nonSiftAvg = nonSiftCount > 0 ? (nonSiftScoreSum / nonSiftCount) : 0;

                const width = 600;
                const height = 220;
                const padLeft = 45;
                const padRight = 20;
                const padTop = 30;
                const padBottom = 30;

                const plotWidth = width - padLeft - padRight;
                const plotHeight = height - padTop - padBottom;

                const maxCount = Math.max(siftCount, nonSiftCount, 1);
                const maxVal = Math.ceil(maxCount / 1000) * 1000;

                let svgContent = `<svg width="100%" height="100%" viewBox="0 0 ${width} ${height}">`;

                // Horizontal grid lines
                const ticks = 4;
                for (let i = 0; i <= ticks; i++) {
                    const tickVal = (i * (maxVal / ticks));
                    const cy = padTop + plotHeight - ((tickVal / maxVal) * plotHeight);
                    svgContent += `
                        <line x1="${padLeft}" y1="${cy}" x2="${width - padRight}" y2="${cy}" stroke="var(--border-clean)" stroke-width="0.5" stroke-dasharray="3,3" />
                        <text x="${padLeft - 8}" y="${cy + 3}" font-size="9px" font-family="var(--font-mono)" fill="var(--text-muted)" text-anchor="end">${tickVal.toLocaleString()}</text>
                    `;
                }

                // Render two wide comparison columns
                const colWidth = 80;
                const groups = [
                    { name: "Sift Secure Zone", count: siftCount, pct: siftPct, avg: siftAvg, color: "#1e40af", xIdx: 0 },
                    { name: "Non-Sift Generic", count: nonSiftCount, pct: nonSiftPct, avg: nonSiftAvg, color: "#475569", xIdx: 1 }
                ];

                const space = (plotWidth - (colWidth * 2)) / 3;

                groups.forEach(g => {
                    const cx = padLeft + space + (g.xIdx * (colWidth + space));
                    const colHeight = (g.count / maxVal) * plotHeight;
                    const cy = padTop + plotHeight - colHeight;

                    svgContent += `
                        <rect x="${cx}" y="${cy}" width="${colWidth}" height="${colHeight}" fill="${g.color}" rx="4" ry="4"
                            style="transition: opacity 0.2s; cursor: pointer;"
                            onmouseover="showLocTooltip(event, '${g.name}', ${g.count}, ${g.pct.toFixed(1)}, ${g.avg.toFixed(2)})"
                            onmouseout="hideTrendTooltip()" />
                        
                        <!-- Count overlay -->
                        <text x="${cx + (colWidth / 2)}" y="${cy - 16}" font-size="10px" font-weight="700" fill="var(--text-primary)" font-family="var(--font-mono)" text-anchor="middle">${g.count.toLocaleString()}</text>
                        <text x="${cx + (colWidth / 2)}" y="${cy - 6}" font-size="8px" fill="var(--text-secondary)" font-family="var(--font-sans)" text-anchor="middle">avg score: ${g.avg.toFixed(1)}</text>
                        
                        <!-- Bottom labels -->
                        <text x="${cx + (colWidth / 2)}" y="${height - 8}" font-size="9px" font-weight="700" fill="var(--text-muted)" text-anchor="middle">${g.xIdx === 0 ? 'SIFT SECURE' : 'NON-SIFT'}</text>
                    `;
                });

                svgContent += `</svg>`;
                container.innerHTML = svgContent;

                // Legend
                legend.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem;">
                        <span style="display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: #1e40af;"></span>
                        <span>Sift SECURE Zone: <strong>${siftCount.toLocaleString()}</strong> devices (${siftPct.toFixed(1)}%) | score avg: <strong style="color:#1e40af;">${siftAvg.toFixed(2)}</strong></span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem;">
                        <span style="display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: #475569;"></span>
                        <span>Non-Sift Generic: <strong>${nonSiftCount.toLocaleString()}</strong> devices (${nonSiftPct.toFixed(1)}%) | score avg: <strong style="color:#475569;">${nonSiftAvg.toFixed(2)}</strong></span>
                    </div>
                `;
            }
        }

        function renderActiveRiskChart() {
            const container = document.getElementById("analytics-risk-chart-container");
            if (!container) return;

            const dimension = document.getElementById("analysis-risk-dimension").value;
            container.innerHTML = "";

            if (dimension === "risk") {
                // Count compliance status dynamically
                let compliant = 0, nonCompliant = 0;
                fleetDataset.forEach(d => {
                    if (d.condition !== "IN_USE") return; // Filter active only!
                    if (d.level === "COMPLIANT") compliant++;
                    else nonCompliant++;
                });

                const total = compliant + nonCompliant;
                const data = [
                    { name: "Compliant", count: compliant, pct: total > 0 ? (compliant / total) * 100 : 0, color: "var(--status-low)" },
                    { name: "Non-Compliant", count: nonCompliant, pct: total > 0 ? (nonCompliant / total) * 100 : 0, color: "var(--status-critical)" }
                ];

                // Circumference is exactly 440 (2 * pi * 70 = 439.82)
                const C = 440;
                let currentOffset = 0;

                let donutSvg = `
                    <div style="width: 140px; height: 140px; position: relative; flex-shrink: 0;">
                        <svg width="100%" height="100%" viewBox="0 0 220 220" style="transform: rotate(-90deg);">
                `;

                data.forEach(item => {
                    const arcLength = (item.pct / 100) * C;
                    donutSvg += `
                        <circle cx="110" cy="110" r="70" fill="transparent" stroke="${item.color}" stroke-width="24"
                            stroke-dasharray="${arcLength} ${C}" stroke-dashoffset="${-currentOffset}"
                            style="transition: stroke-width 0.2s; cursor: pointer;"
                            onmouseover="highlightDonutSlice(this); showRiskSliceTooltip(event, '${item.name}', ${item.count}, ${item.pct.toFixed(1)})"
                            onmouseout="restoreDonutSlice(this)" />
                    `;
                    currentOffset += arcLength;
                });

                donutSvg += `
                        </svg>
                        <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; pointer-events: none; text-align: center;">
                            <span style="font-size: 0.65rem; text-transform: uppercase; font-weight: 700; color: var(--text-muted); letter-spacing: 0.05em; margin-bottom: -0.1rem;">Total Fleet</span>
                            <span style="font-family: var(--font-mono); font-size: 1.15rem; font-weight: 800; color: var(--text-primary);">${total.toLocaleString()}</span>
                        </div>
                    </div>
                `;

                // Add Legend on the right side
                let legendContent = `
                    <div style="display: flex; flex-direction: column; gap: 0.65rem; flex-grow: 1; min-width: 160px;">
                `;

                data.forEach(item => {
                    legendContent += `
                        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem; border-bottom: 1px solid var(--border-clean); padding-bottom: 0.35rem;">
                            <div style="display: flex; align-items: center; gap: 0.45rem;">
                                <span style="display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: ${item.color};"></span>
                                <span style="font-weight: 600; color: var(--text-secondary);">${item.name}</span>
                            </div>
                            <span style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary);">${item.count.toLocaleString()} <span style="color: var(--text-muted); font-size: 0.7rem; font-weight: 500;">(${item.pct.toFixed(1)}%)</span></span>
                        </div>
                    `;
                });

                legendContent += `</div>`;

                container.innerHTML = donutSvg + legendContent;
            } else if (dimension === "condition") {
                // Count physical conditions dynamically
                let use = 0, repair = 0, store = 0, expired = 0, disposed = 0, donated = 0, loanable = 0, untraceable = 0, reserved = 0;
                fleetDataset.forEach(d => {
                    if (d.condition === "IN_USE") use++;
                    else if (d.condition === "IN_REPAIR") repair++;
                    else if (d.condition === "IN_STORE") store++;
                    else if (d.condition === "EXPIRED") expired++;
                    else if (d.condition === "DISPOSED") disposed++;
                    else if (d.condition === "DONATED_UNDER_CSR") donated++;
                    else if (d.condition === "LOANABLE_RESERVED") loanable++;
                    else if (d.condition === "NOT_TRACEABLE") untraceable++;
                    else if (d.condition === "RESERVED") reserved++;
                });

                const total = fleetDataset.length;
                const data = [
                    { name: "In Use", count: use, pct: total > 0 ? (use / total) * 100 : 0, color: "#64748b" },
                    { name: "In Repair", count: repair, pct: total > 0 ? (repair / total) * 100 : 0, color: "var(--status-medium)" },
                    { name: "In Store", count: store, pct: total > 0 ? (store / total) * 100 : 0, color: "#475569" },
                    { name: "Expired", count: expired, pct: total > 0 ? (expired / total) * 100 : 0, color: "var(--status-high)" },
                    { name: "Disposed", count: disposed, pct: total > 0 ? (disposed / total) * 100 : 0, color: "#cbd5e1" },
                    { name: "Donated Under CSR", count: donated, pct: total > 0 ? (donated / total) * 100 : 0, color: "#94a3b8" },
                    { name: "Loanable Reserved", count: loanable, pct: total > 0 ? (loanable / total) * 100 : 0, color: "#334155" },
                    { name: "Not Traceable", count: untraceable, pct: total > 0 ? (untraceable / total) * 100 : 0, color: "var(--status-critical)" },
                    { name: "Reserved", count: reserved, pct: total > 0 ? (reserved / total) * 100 : 0, color: "#1e293b" }
                ];

                const C = 440;
                let currentOffset = 0;

                let donutSvg = `
                    <div style="width: 140px; height: 140px; position: relative; flex-shrink: 0;">
                        <svg width="100%" height="100%" viewBox="0 0 220 220" style="transform: rotate(-90deg);">
                `;

                data.forEach(item => {
                    const arcLength = (item.pct / 100) * C;
                    donutSvg += `
                        <circle cx="110" cy="110" r="70" fill="transparent" stroke="${item.color}" stroke-width="24"
                            stroke-dasharray="${arcLength} ${C}" stroke-dashoffset="${-currentOffset}"
                            style="transition: stroke-width 0.2s; cursor: pointer;"
                            onmouseover="highlightDonutSlice(this); showRiskSliceTooltip(event, '${item.name}', ${item.count}, ${item.pct.toFixed(1)})"
                            onmouseout="restoreDonutSlice(this)" />
                    `;
                    currentOffset += arcLength;
                });

                donutSvg += `
                        </svg>
                        <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; pointer-events: none; text-align: center;">
                            <span style="font-size: 0.65rem; text-transform: uppercase; font-weight: 700; color: var(--text-muted); letter-spacing: 0.05em; margin-bottom: -0.1rem;">Asset</span>
                            <span style="font-size: 0.75rem; text-transform: uppercase; font-weight: 800; color: var(--text-primary);">States</span>
                        </div>
                    </div>
                `;

                // Add Legend on the right side
                let legendContent = `
                    <div style="display: flex; flex-direction: column; gap: 0.65rem; flex-grow: 1; min-width: 160px;">
                `;

                data.forEach(item => {
                    legendContent += `
                        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem; border-bottom: 1px solid var(--border-clean); padding-bottom: 0.35rem;">
                            <div style="display: flex; align-items: center; gap: 0.45rem;">
                                <span style="display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: ${item.color};"></span>
                                <span style="font-weight: 600; color: var(--text-secondary);">${item.name}</span>
                            </div>
                            <span style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary);">${item.count.toLocaleString()} <span style="color: var(--text-muted); font-size: 0.7rem; font-weight: 500;">(${item.pct.toFixed(1)}%)</span></span>
                        </div>
                    `;
                });

                legendContent += `</div>`;

                container.innerHTML = donutSvg + legendContent;
            }
        }

        // Custom SVGs Interactive Tooltip Helpers
        function showTrendTooltip(e, label, val) {
            let tooltip = document.getElementById("chart-tooltip");
            if (!tooltip) {
                tooltip = document.createElement("div");
                tooltip.id = "chart-tooltip";
                tooltip.style.position = "absolute";
                tooltip.style.background = "var(--text-primary)";
                tooltip.style.color = "var(--bg-main)";
                tooltip.style.padding = "0.5rem 0.75rem";
                tooltip.style.fontSize = "0.75rem";
                tooltip.style.fontWeight = "700";
                tooltip.style.borderRadius = "4px";
                tooltip.style.pointerEvents = "none";
                tooltip.style.zIndex = "9999";
                tooltip.style.boxShadow = "0 4px 12px rgba(15, 23, 42, 0.15)";
                tooltip.style.border = "1px solid var(--border-clean)";
                tooltip.style.fontFamily = "var(--font-sans)";
                document.body.appendChild(tooltip);
            }
            tooltip.innerHTML = `
                <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.15rem; text-transform: uppercase;">${label}</div>
                <div>Compliance Avg: <span style="color: var(--color-accent); font-family: var(--font-mono);">${val.toFixed(2)}%</span></div>
            `;
            tooltip.style.display = "block";
            tooltip.style.left = (e.pageX + 15) + "px";
            tooltip.style.top = (e.pageY - 35) + "px";
        }

        function showOsTooltip(e, name, count, pct) {
            let tooltip = document.getElementById("chart-tooltip");
            if (!tooltip) {
                showTrendTooltip(e, "", 0);
            }
            tooltip.innerHTML = `
                <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.15rem; text-transform: uppercase;">Platform Footprint</div>
                <div><strong>${name}</strong>: <span style="font-family: var(--font-mono);">${count.toLocaleString()}</span> devices (${pct}%)</div>
            `;
            tooltip.style.display = "block";
            tooltip.style.left = (e.pageX + 15) + "px";
            tooltip.style.top = (e.pageY - 35) + "px";
        }

        function showLocTooltip(e, name, count, pct, avg) {
            let tooltip = document.getElementById("chart-tooltip");
            if (!tooltip) {
                showTrendTooltip(e, "", 0);
            }
            tooltip.innerHTML = `
                <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.15rem; text-transform: uppercase;">${name}</div>
                <div style="margin-bottom: 0.15rem;">Volume: <strong>${count.toLocaleString()}</strong> (${pct}%)</div>
                <div>Avg Compliance: <span style="color: var(--color-accent); font-family: var(--font-mono);">${avg.toFixed(2)}%</span></div>
            `;
            tooltip.style.display = "block";
            tooltip.style.left = (e.pageX + 15) + "px";
            tooltip.style.top = (e.pageY - 45) + "px";
        }

        function showRiskSliceTooltip(e, name, count, pct) {
            let tooltip = document.getElementById("chart-tooltip");
            if (!tooltip) {
                showTrendTooltip(e, "", 0);
            }
            tooltip.innerHTML = `
                <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.15rem; text-transform: uppercase;">distribution sector</div>
                <div><strong>${name}</strong>: <span style="font-family: var(--font-mono);">${count.toLocaleString()}</span> devices (${pct}%)</div>
            `;
            tooltip.style.display = "block";
            tooltip.style.left = (e.pageX + 15) + "px";
            tooltip.style.top = (e.pageY - 35) + "px";
        }

        function hideTrendTooltip() {
            const tooltip = document.getElementById("chart-tooltip");
            if (tooltip) {
                tooltip.style.display = "none";
            }
        }

        function highlightDonutSlice(el) {
            el.setAttribute("stroke-width", "28");
        }

        function restoreDonutSlice(el) {
            el.setAttribute("stroke-width", "24");
            hideTrendTooltip();
        }


        // Initialize aggregate stats
        updateFleetWideMetrics();

        if (fleetDataset.length > 0) {
            showDeviceAuditDetails(fleetDataset[0].id);
        }
        populateFleetTable();
        recalculateAllScores();
        enforceRoleBasedControls();

        // Local Storage virtual DB mock layer for Node VM testing & headless browser environments
        