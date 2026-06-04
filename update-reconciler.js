const fs = require('fs');
const path = require('path');

const targetFilePath = path.join(__dirname, 'frontend', 'index.html');

console.log('Reading file:', targetFilePath);
let content = fs.readFileSync(targetFilePath, 'utf8');

const startToken = '// --- Cross-Sheet Asset Reconciliation Workspace Engine ---';
const scriptCloseToken = '</script>';

const startIndex = content.indexOf(startToken);
if (startIndex === -1) {
    console.error('ERROR: Could not find start token in file!');
    process.exit(1);
}

const closeIndex = content.indexOf(scriptCloseToken, startIndex);
if (closeIndex === -1) {
    console.error('ERROR: Could not find script close tag after reconciler start!');
    process.exit(1);
}

console.log('Found start of reconciler engine at index:', startIndex);
console.log('Found end of reconciler script tag at index:', closeIndex);

const newReconcilerCode = `// --- Cross-Sheet Asset Reconciliation Workspace Engine ---
        
        // reconcilerSheets and reconciliationResults are declared globally at the top of the script block to prevent TDZ ReferenceErrors on page reload
        reconcilerSheets = []; 
        reconciliationResults = {
            matches: [],
            gaps: [],
            rogues: []
        };

        let currentReconTab = "gaps";

        function parseCSVNative(text) {
            const lines = [];
            let row = [""];
            let inQuotes = false;
            
            let sep = ",";
            const firstLine = text.split(/\\r?\\n/)[0] || "";
            let commaCount = (firstLine.match(/,/g) || []).length;
            let semiCount = (firstLine.match(/;/g) || []).length;
            let tabCount = (firstLine.match(/\\t/g) || []).length;
            
            if (semiCount > commaCount && semiCount > tabCount) sep = ";";
            else if (tabCount > commaCount && tabCount > semiCount) sep = "\\t";
            
            for (let i = 0; i < text.length; i++) {
                const c = text[i];
                const next = text[i+1];
                
                if (c === '"') {
                    if (inQuotes && next === '"') {
                        row[row.length - 1] += '"';
                        i++;
                    } else {
                        inQuotes = !inQuotes;
                    }
                } else if (c === sep && !inQuotes) {
                    row.push("");
                } else if ((c === '\\r' || c === '\\n') && !inQuotes) {
                    if (c === '\\r' && next === '\\n') {
                        i++;
                    }
                    lines.push(row);
                    row = [""];
                } else {
                    row[row.length - 1] += c;
                }
            }
            if (row.length > 1 || row[0] !== "") {
                lines.push(row);
            }
            return lines;
        }

        function handleMultiSheetUpload(event) {
            const files = event.target.files;
            if (!files || files.length === 0) return;

            Array.from(files).forEach(file => {
                logToTerminal(\`[Reconciler] Upload request received for source file: "\${file.name}"\`);
                
                const reader = new FileReader();
                const isExcel = file.name.endsWith(".xlsx") || file.name.endsWith(".xls");

                reader.onload = function (e) {
                    try {
                        let data = e.target.result;
                        let rows;

                        if (!isExcel) {
                            // CSV file logic - first attempt native parse, then fallback to SheetJS
                            try {
                                rows = parseCSVNative(data);
                                logToTerminal(\`[Reconciler] Native CSV parser successfully processed "\${file.name}"\`, "info");
                            } catch (csvErr) {
                                logToTerminal(\`[Reconciler] Native CSV parser failed for "\${file.name}": \${csvErr.message}. Trying SheetJS...\`, "warn");
                                if (typeof XLSX !== "undefined") {
                                    let workbook = XLSX.read(data, { type: "string" });
                                    const sheetName = workbook.SheetNames[0];
                                    const worksheet = workbook.Sheets[sheetName];
                                    rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: "" });
                                } else {
                                    throw new Error("SheetJS is not loaded and native CSV parse failed.");
                                }
                            }
                        } else {
                            // Excel files - require SheetJS (XLSX)
                            if (typeof XLSX === "undefined") {
                                const cdnError = "SheetJS library (XLSX) could not be loaded from the network. Please connect to the internet or convert the file to CSV.";
                                logToTerminal(\`[Reconciler] Ingestion failed for "\${file.name}": \${cdnError}\`, "error");
                                alert(\`❌ Excel Ingestion Failed:\\n\\n\${cdnError}\`);
                                return;
                            }

                            const bytes = new Uint8Array(data);
                            let workbook = XLSX.read(bytes, { type: "array" });
                            const sheetName = workbook.SheetNames[0];
                            const worksheet = workbook.Sheets[sheetName];
                            rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: "" });
                        }

                        if (!rows || rows.length < 2) {
                            logToTerminal(\`[Reconciler] Failed: "\${file.name}" contains insufficient rows.\`, "error");
                            alert(\`❌ Ingestion Failed: "\${file.name}" has no data or has too few rows.\`);
                            return;
                        }

                        const headers = rows[0].map(h => String(h).trim());
                        const lowerHeaders = headers.map(h => h.toLowerCase());

                        // Auto-detect the key column (Device Name / Hostname)
                        let keyIdx = -1;
                        const keyKeywords = ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system", "asset"];
                        
                        for (let kw of keyKeywords) {
                            const idx = lowerHeaders.findIndex(h => {
                                if (kw.length <= 3) {
                                    const words = h.split(/[^a-z0-9]+/);
                                    return words.includes(kw);
                                }
                                return h.includes(kw);
                            });
                            if (idx !== -1) {
                                keyIdx = idx;
                                break;
                            }
                        }

                        // Fallback to first column if not auto-detected
                        if (keyIdx === -1) keyIdx = 0;

                        // Default Role classification: First uploaded sheet is primary, subsequent sheets are secondary
                        const role = reconcilerSheets.length === 0 ? "primary" : "secondary";

                        const sheetObj = {
                            id: \`sheet-\${Math.random().toString(36).substring(2, 8)}\`,
                            filename: file.name,
                            rows: rows.slice(1),
                            headers: headers,
                            keyIdx: keyIdx,
                            role: role
                        };

                        reconcilerSheets.push(sheetObj);

                        logToTerminal(\`[Reconciler] Loaded \${rows.length - 1} rows from "\${file.name}". Auto-detected match key: "\${headers[keyIdx]}"\`, "info");

                        renderReconcilerQueue();

                    } catch (err) {
                        logToTerminal(\`[Reconciler] Ingestion failed for "\${file.name}": \${err.message}\`, "error");
                        alert(\`❌ File Import Error: \${err.message}\`);
                    }
                };

                if (isExcel) {
                    reader.readAsArrayBuffer(file);
                } else {
                    reader.readAsText(file);
                }
            });
            event.target.value = "";
        }

        function renderReconcilerQueue() {
            const tbody = document.getElementById("reconciler-queue-tbody");
            const queueCard = document.getElementById("reconciler-queue-card");
            const executeBtn = document.getElementById("btn-execute-reconciliation");
            if (!tbody || !queueCard) return;

            if (reconcilerSheets.length === 0) {
                queueCard.style.display = "none";
                executeBtn.disabled = true;
                executeBtn.style.opacity = 0.6;
                executeBtn.style.cursor = "not-allowed";
                return;
            }

            queueCard.style.display = "block";
            tbody.innerHTML = "";

            reconcilerSheets.forEach(sheet => {
                const tr = document.createElement("tr");

                // Role classification select
                let roleSelectHtml = \`
                    <select style="border: 1px solid var(--border-clean); padding: 0.35rem 0.5rem; font-size: 0.75rem; background: var(--bg-card); color: var(--text-primary); border-radius: 4px; width: 100%; cursor: pointer;" onchange="updateSheetRole('\${sheet.id}', this.value)">
                        <option value="primary" \${sheet.role === 'primary' ? 'selected' : ''}>Corporate Directory (Primary)</option>
                        <option value="secondary" \${sheet.role === 'secondary' ? 'selected' : ''}>Agent Telemetry (Secondary)</option>
                    </select>
                \`;

                // Key column select dropdown
                let keySelectHtml = \`<select style="border: 1px solid var(--border-clean); padding: 0.35rem 0.5rem; font-size: 0.75rem; background: var(--bg-card); color: var(--text-primary); border-radius: 4px; width: 100%; cursor: pointer;" onchange="updateSheetKey('\${sheet.id}', this.value)">\`;
                sheet.headers.forEach((h, idx) => {
                    const selected = idx === sheet.keyIdx ? "selected" : "";
                    keySelectHtml += \`<option value="\${idx}" \${selected}>\${escapeHTML(h)} (Col \${idx + 1})</option>\`;
                });
                keySelectHtml += \`</select>\`;

                // All columns listed
                const allColsHtml = sheet.headers.map((c, idx) => {
                    const isKey = idx === sheet.keyIdx;
                    const badgeClass = isKey ? "badge" : "badge group-sift";
                    const style = isKey ? "font-size:0.65rem; margin-right:0.25rem; display:inline-block; margin-bottom:0.15rem; background:var(--color-accent);" : "font-size:0.65rem; margin-right:0.25rem; display:inline-block; margin-bottom:0.15rem;";
                    return \`<span class="\${badgeClass}" style="\${style}">\${escapeHTML(c)}</span>\`;
                }).join("");

                tr.innerHTML = \`
                    <td><strong style="color:var(--color-accent);">\${sheet.filename}</strong></td>
                    <td style="font-family:var(--font-mono); font-weight:700;">\${sheet.rows.length.toLocaleString()}</td>
                    <td>\${roleSelectHtml}</td>
                    <td>\${keySelectHtml}</td>
                    <td style="max-width:320px; word-break:break-word;">\${allColsHtml}</td>
                    <td style="text-align:right;">
                        <button class="btn" style="background:rgba(220,53,69,0.15); border:1px solid rgba(220,53,69,0.4); color:#ff6b6b; font-size:0.7rem; padding:0.3rem 0.6rem; cursor:pointer;" onclick="deleteSheetFromQueue('\${sheet.id}')">Delete</button>
                    </td>
                \`;
                tbody.appendChild(tr);
            });

            // Enforce role compliance
            const hasPrimary = reconcilerSheets.some(s => s.role === "primary");
            const hasSecondary = reconcilerSheets.some(s => s.role === "secondary");

            if (reconcilerSheets.length >= 2 && hasPrimary && hasSecondary) {
                executeBtn.disabled = false;
                executeBtn.style.opacity = 1;
                executeBtn.style.cursor = "pointer";
            } else {
                executeBtn.disabled = true;
                executeBtn.style.opacity = 0.6;
                executeBtn.style.cursor = "not-allowed";
            }
        }

        function updateSheetRole(id, role) {
            const sheet = reconcilerSheets.find(s => s.id === id);
            if (!sheet) return;
            
            if (role === "primary") {
                reconcilerSheets.forEach(s => {
                    if (s.id !== id && s.role === "primary") {
                        s.role = "secondary";
                    }
                });
            }
            
            sheet.role = role;
            logToTerminal(\`[Reconciler] Role for "\${sheet.filename}" updated to \${role.toUpperCase()}\`);
            renderReconcilerQueue();
        }

        function updateSheetKey(id, val) {
            const sheet = reconcilerSheets.find(s => s.id === id);
            if (!sheet) return;
            sheet.keyIdx = parseInt(val);
            logToTerminal(\`[Reconciler] Match key for "\${sheet.filename}" changed to "\${sheet.headers[sheet.keyIdx]}"\`);
            renderReconcilerQueue();
        }

        function deleteSheetFromQueue(id) {
            const sheet = reconcilerSheets.find(s => s.id === id);
            if (!sheet) return;
            reconcilerSheets = reconcilerSheets.filter(s => s.id !== id);
            logToTerminal(\`[Reconciler] File "\${sheet.filename}" removed from queue.\`);
            
            if (reconcilerSheets.length > 0 && !reconcilerSheets.some(s => s.role === "primary")) {
                reconcilerSheets[0].role = "primary";
            }
            
            renderReconcilerQueue();
        }

        function executeDeepReconciliation() {
            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            const secondarySheets = reconcilerSheets.filter(s => s.role === "secondary");

            if (!primarySheet || secondarySheets.length === 0) {
                alert("Deep reconciliation requires 1 Primary Corporate Directory and at least 1 Secondary Agent Telemetry sheet.");
                return;
            }

            logToTerminal(\`[Reconciler] Executing asset alignment across \${reconcilerSheets.length} spreadsheet inventories...\`);

            const primaryKeyIdx = primarySheet.keyIdx;

            const primaryMap = new Map();
            primarySheet.rows.forEach(row => {
                const nameVal = String(row[primaryKeyIdx] || "").trim();
                if (!nameVal) return;
                const normName = nameVal.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
                primaryMap.set(normName, {
                    rawName: nameVal,
                    row: row
                });
            });

            const secondaryMaps = secondarySheets.map(sheet => {
                const map = new Map();
                sheet.rows.forEach(row => {
                    const nameVal = String(row[sheet.keyIdx] || "").trim();
                    if (!nameVal) return;
                    const normName = nameVal.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
                    map.set(normName, row);
                });
                return {
                    sheetId: sheet.id,
                    filename: sheet.filename,
                    headers: sheet.headers,
                    keyIdx: sheet.keyIdx,
                    map: map
                };
            });

            const matches = [];
            const gaps = [];

            primaryMap.forEach((primaryData, normName) => {
                const presentInSheets = [];
                const missingInSheets = [];
                const mergedProperties = [];

                primarySheet.headers.forEach((h, idx) => {
                    if (idx !== primaryKeyIdx) {
                        mergedProperties.push({
                            source: primarySheet.filename,
                            sheetRole: "Primary",
                            property: h,
                            value: String(primaryData.row[idx] || "").trim() || "-"
                        });
                    }
                });

                secondaryMaps.forEach(sec => {
                    if (sec.map.has(normName)) {
                        presentInSheets.push(sec.filename);
                        const rowData = sec.map.get(normName);
                        
                        sec.headers.forEach((h, idx) => {
                            if (idx !== sec.keyIdx) {
                                mergedProperties.push({
                                    source: sec.filename,
                                    sheetRole: "Secondary",
                                    property: h,
                                    value: String(rowData[idx] || "").trim() || "-"
                                });
                            }
                        });
                    } else {
                        missingInSheets.push(sec.filename);
                    }
                });

                const isMissingAnySecondary = missingInSheets.length > 0;

                if (isMissingAnySecondary) {
                    gaps.push({
                        id: \`dev-gap-\${Math.random().toString(36).substring(2, 6)}\`,
                        name: primaryData.rawName,
                        normalized: normName,
                        primaryRow: primaryData.row,
                        missingInSheets: missingInSheets,
                        presentInSheets: presentInSheets,
                        mergedProperties: mergedProperties,
                        status: "COVERAGE_GAP"
                    });
                } else {
                    matches.push({
                        id: \`dev-rec-\${Math.random().toString(36).substring(2, 6)}\`,
                        name: primaryData.rawName,
                        normalized: normName,
                        primaryRow: primaryData.row,
                        mergedProperties: mergedProperties,
                        status: "MATCHED"
                    });
                }
            });

            const roguesMap = new Map();
            secondaryMaps.forEach(sec => {
                sec.map.forEach((row, normName) => {
                    if (!primaryMap.has(normName)) {
                        if (!roguesMap.has(normName)) {
                            roguesMap.set(normName, {
                                name: String(row[sec.keyIdx] || "").trim(),
                                sheets: []
                            });
                        }
                        const rogueObj = roguesMap.get(normName);
                        rogueObj.sheets.push({
                            filename: sec.filename,
                            row: row,
                            headers: sec.headers,
                            keyIdx: sec.keyIdx
                        });
                    }
                });
            });

            const rogues = [];
            roguesMap.forEach((rogueObj, normName) => {
                rogues.push({
                    id: \`dev-rogue-\${Math.random().toString(36).substring(2, 6)}\`,
                    name: rogueObj.name,
                    normalized: normName,
                    sheets: rogueObj.sheets,
                    status: "ROGUE_UNMANAGED"
                });
            });

            reconciliationResults = { matches, gaps, rogues };

            const totalPrimary = primaryMap.size;
            const matchRate = totalPrimary > 0 ? (matches.length / totalPrimary) * 100 : 0;

            document.getElementById("recon-stat-matches").innerHTML = matches.length.toLocaleString();
            
            const matchesWidget = document.getElementById("recon-stat-matches").parentElement;
            let subtext = matchesWidget.querySelector("p");
            if (subtext) {
                subtext.innerHTML = \`<strong style="color:var(--status-low);">\${matches.length} Matches Aligned</strong>\`;
            }

            document.getElementById("recon-stat-gaps").innerText = gaps.length.toLocaleString();
            document.getElementById("recon-stat-rogues").innerText = rogues.length.toLocaleString();
            
            const matchRateEl = document.getElementById("recon-stat-match-rate");
            matchRateEl.innerText = \`\${matchRate.toFixed(1)}%\`;
            matchRateEl.style.color = matchRate === 100 ? "var(--status-low)" : (matchRate >= 85 ? "var(--status-medium)" : "var(--status-critical)");

            document.getElementById("recon-tab-count-gaps").innerText = gaps.length.toLocaleString();
            document.getElementById("recon-tab-count-rogues").innerText = rogues.length.toLocaleString();
            document.getElementById("recon-tab-count-matches").innerText = matches.length.toLocaleString();

            document.getElementById("reconciler-results-wrapper").style.display = "block";

            logToTerminal(\`[Reconciler] Alignment complete. Aligned Matches: \${matches.length}, Gaps: \${gaps.length}, Rogue Assets: \${rogues.length}. Match Rate: \${matchRate.toFixed(2)}%\`, "info");

            const defaultTab = gaps.length > 0 ? "gaps" : (matches.length > 0 ? "matches" : "rogues");
            switchReconTab(defaultTab);
        }

        function switchReconTab(tabId) {
            currentReconTab = tabId;

            document.querySelectorAll("#section-reconciler .tab-btn").forEach(btn => btn.classList.remove("active"));
            document.getElementById(\`btn-recon-tab-\${tabId}\`).classList.add("active");

            const head = document.getElementById("recon-table-head");
            const body = document.getElementById("recon-table-body");
            if (!head || !body) return;

            head.innerHTML = "";
            body.innerHTML = "";

            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            if (!primarySheet) return;

            const primaryHeaders = primarySheet.headers;
            let rowsToRender = reconciliationResults[tabId];

            if (tabId === "gaps") {
                const headersToRender = ["Device ID", "Hostname", "Missing Sheet Telemetries", "Corporate Detail (Primary)"];
                head.innerHTML = \`<tr>\${headersToRender.map(h => \`<th>\${escapeHTML(h)}</th>\`).join("")}</tr>\`;

                if (rowsToRender.length === 0) {
                    body.innerHTML = \`<tr><td colspan="4" style="text-align: center; color: var(--status-low); font-style: italic; padding: 2rem; font-weight: 700;">🎉 Stellar Alignment! Zero gaps detected.</td></tr>\`;
                } else {
                    rowsToRender.forEach(item => {
                        const tr = document.createElement("tr");
                        const missingBadges = item.missingInSheets.map(s => \`<span class="badge risk-critical" style="font-size:0.65rem; padding: 0.15rem 0.4rem; display: inline-block; margin: 0.1rem 0.2rem 0.1rem 0;">Missing in: \${escapeHTML(s)}</span>\`).join("");
                        const primaryDetails = primaryHeaders.map((h, idx) => \`<strong>\${escapeHTML(h)}:</strong> \${escapeHTML(item.primaryRow[idx] || "-")}\`).join(" | ");
                        
                        tr.innerHTML = \`
                            <td style="font-family: var(--font-mono); color: var(--text-secondary); vertical-align: middle;">\${escapeHTML(item.id)}</td>
                            <td style="vertical-align: middle;"><strong style="color: var(--status-critical);">\${item.name.toUpperCase()}</strong></td>
                            <td style="vertical-align: middle;">\${missingBadges}</td>
                            <td style="vertical-align: middle; font-size: 0.78rem; color: var(--text-secondary);">\${primaryDetails}</td>
                        \`;
                        body.appendChild(tr);
                    });
                }
            } else if (tabId === "rogues") {
                const headersToRender = ["Device ID", "Hostname", "Detected Telemetry Sources", "Agent Properties Details"];
                head.innerHTML = \`<tr>\${headersToRender.map(h => \`<th>\${escapeHTML(h)}</th>\`).join("")}</tr>\`;

                if (rowsToRender.length === 0) {
                    body.innerHTML = \`<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); font-style: italic; padding: 2rem;">No unmanaged rogue assets identified.</td></tr>\`;
                } else {
                    rowsToRender.forEach(item => {
                        const tr = document.createElement("tr");
                        const detectedBadges = item.sheets.map(s => \`<span class="badge risk-medium" style="font-size:0.65rem; padding: 0.15rem 0.4rem; display: inline-block; margin: 0.1rem 0.2rem 0.1rem 0;">Source: \${escapeHTML(s.filename)}</span>\`).join("");
                        
                        const detailsHtml = item.sheets.map(s => {
                            const details = s.headers.slice(0, 4).map((h, idx) => \`<strong>\${escapeHTML(h)}:</strong> \${escapeHTML(s.row[idx] || "-")}\`).join(" | ");
                            return \`<div style="margin-bottom: 0.25rem; font-size: 0.72rem; color: var(--text-secondary);"><strong style="color:var(--text-primary);">\${escapeHTML(s.filename)}:</strong> \${details}</div>\`;
                        }).join("");
                        
                        tr.innerHTML = \`
                            <td style="font-family: var(--font-mono); color: var(--text-secondary); vertical-align: middle;">\${escapeHTML(item.id)}</td>
                            <td style="vertical-align: middle;"><strong style="color: var(--status-medium);">\${item.name.toUpperCase()}</strong> <span class="badge risk-medium" style="font-size:0.6rem; padding: 0.1rem 0.25rem; margin-left: 0.5rem;">UNMANAGED</span></td>
                            <td style="vertical-align: middle;">\${detectedBadges}</td>
                            <td style="vertical-align: middle;">\${detailsHtml}</td>
                        \`;
                        body.appendChild(tr);
                    });
                }
            } else if (tabId === "matches") {
                const headersToRender = ["Device ID", "Hostname", "Alignment", "Merged Excel Sheet Information / Row Details"];
                head.innerHTML = \`<tr>\${headersToRender.map(h => \`<th>\${escapeHTML(h)}</th>\`).join("")}</tr>\`;

                if (rowsToRender.length === 0) {
                    body.innerHTML = \`<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); font-style: italic; padding: 2rem;">No matching assets resolved between directories.</td></tr>\`;
                } else {
                    rowsToRender.forEach(item => {
                        const tr = document.createElement("tr");
                        
                        const propertiesHtml = item.mergedProperties.map(p => {
                            const sourceLabel = p.source.length > 20 ? p.source.substring(0, 17) + "..." : p.source;
                            return \`
                                <div style="display:inline-block; background:rgba(255,255,255,0.02); border:1px solid var(--border-clean); padding: 0.35rem 0.6rem; border-radius: 4px; font-size: 0.72rem; margin: 0.2rem 0.3rem 0.2rem 0; line-height:1.2;">
                                    <span style="font-size:0.6rem; color:var(--color-accent); font-weight:700; text-transform:uppercase; display:block;">\${sourceLabel}</span>
                                    <strong style="color:var(--text-secondary);">\${escapeHTML(p.property)}:</strong> 
                                    <span style="color:var(--text-primary); font-weight:700;">\${escapeHTML(p.value)}</span>
                                </div>
                            \`;
                        }).join("");

                        tr.innerHTML = \`
                            <td style="font-family: var(--font-mono); color: var(--text-secondary); vertical-align: middle;">\${escapeHTML(item.id)}</td>
                            <td style="vertical-align: middle;"><strong style="color: var(--status-low);">\${item.name.toUpperCase()}</strong> <span class="badge risk-low" style="font-size:0.6rem; padding: 0.1rem 0.25rem; margin-left: 0.5rem;">MATCHED</span></td>
                            <td style="vertical-align: middle; color: var(--status-low); font-weight:700;">🟢 Aligned</td>
                            <td style="vertical-align: middle; padding: 0.75rem 0;">
                                <div style="display: flex; flex-wrap: wrap; max-width: 750px;">
                                    \${propertiesHtml}
                                </div>
                            </td>
                        \`;
                        body.appendChild(tr);
                    });
                }
            }
        }

        function mergeReconciliationIntoFleet() {
            const gaps = reconciliationResults.gaps;
            const rogues = reconciliationResults.rogues;
            const matches = reconciliationResults.matches;

            if (gaps.length === 0 && rogues.length === 0 && matches.length === 0) {
                alert("No reconciled assets available to merge. Please execute reconciliation first.");
                return;
            }

            const confirmMerge = confirm(\`⚡ Are you sure you want to merge these reconciled Excel records into the active database?\\n\\n- \${matches.length} Matched devices will have their custom Excel information merged.\\n- \${gaps.length} Coverage Gaps will be marked in the database.\\n- \${rogues.length} Rogue Assets will be appended to the active list.\\n\\nDashboard ledger updates instantly.\`);
            if (!confirmMerge) return;

            let newlyCreated = 0;
            let mergedUpdated = 0;

            matches.forEach(item => {
                const normName = item.normalized;
                let existing = fleetDataset.find(dev => dev.canonical_name === normName || dev.serial.toLowerCase().includes(normName));

                const customProps = { "Reconciliation Match": "SUCCESS" };
                item.mergedProperties.forEach(p => {
                    customProps[\`[\${p.source}] \${p.property}\`] = p.value;
                });

                if (existing) {
                    if (!existing.custom_properties) existing.custom_properties = {};
                    Object.assign(existing.custom_properties, customProps);
                    mergedUpdated++;
                } else {
                    fleetDataset.push({
                        id: \`dev-\${Math.random().toString(36).substring(2, 8)}\`,
                        canonical_name: item.name,
                        serial: \`SN-RECON-\${Math.random().toString(36).substring(2, 8).toUpperCase()}\`,
                        mac: \`00:1A:2B:3C:\${Math.floor(Math.random()*89+10)}:\${Math.floor(Math.random()*89+10)}\`,
                        manufacturer: "Generic Reconciled",
                        os: "Windows 11 Enterprise",
                        os_family: "Windows",
                        score: 100.00,
                        level: "COMPLIANT",
                        condition: "IN_USE",
                        user_assigned: "reconciler.user",
                        last_login: new Date().toISOString().substring(0, 16).replace("T", " "),
                        location: "Corporate Head Office",
                        location_group: "Sift",
                        is_isolated: false,
                        software: sampleSoftwareCatalog.map(sw => ({
                            name: sw.name,
                            key: sw.key,
                            installed: "INSTALLED",
                            required: "REQUIRED",
                            status: "COMPLIANT"
                        })),
                        custom_properties: customProps
                    });
                    newlyCreated++;
                }
            });

            gaps.forEach(item => {
                const normName = item.normalized;
                let existing = fleetDataset.find(dev => dev.canonical_name === normName || dev.serial.toLowerCase().includes(normName));

                const customProps = { 
                    "Reconciliation Match": "COVERAGE_GAP",
                    "Missing Telemetries": item.missingInSheets.join(", ")
                };
                item.mergedProperties.forEach(p => {
                    customProps[\`[\${p.source}] \${p.property}\`] = p.value;
                });

                if (existing) {
                    existing.score = 0.00;
                    existing.level = "NON_COMPLIANT";
                    
                    existing.software.forEach(sw => {
                        const isMissing = item.missingInSheets.some(filename => {
                            const sheet = reconcilerSheets.find(s => s.filename === filename);
                            return sheet && sheet.headers.some(h => h.toLowerCase().includes(sw.key));
                        });
                        if (isMissing) {
                            sw.installed = "MISSING (AGENT UNREPORTED)";
                            sw.status = "NON_COMPLIANT";
                        }
                    });

                    if (!existing.custom_properties) existing.custom_properties = {};
                    Object.assign(existing.custom_properties, customProps);
                    mergedUpdated++;
                } else {
                    fleetDataset.push({
                        id: \`dev-\${Math.random().toString(36).substring(2, 8)}\`,
                        canonical_name: item.name,
                        serial: \`SN-GAP-\${Math.random().toString(36).substring(2, 8).toUpperCase()}\`,
                        mac: \`00:1A:2B:3C:\${Math.floor(Math.random()*89+10)}:\${Math.floor(Math.random()*89+10)}\`,
                        manufacturer: "Generic Reconciled Gap",
                        os: "Unknown Platform",
                        os_family: "Windows",
                        score: 0.00,
                        level: "NON_COMPLIANT",
                        condition: "IN_USE",
                        user_assigned: "unassigned",
                        last_login: "-",
                        location: "Remote - Untrusted",
                        location_group: "Non-Sift",
                        is_isolated: false,
                        software: sampleSoftwareCatalog.map(sw => {
                            const isMissing = item.missingInSheets.some(filename => {
                                const sheet = reconcilerSheets.find(s => s.filename === filename);
                                return sheet && sheet.headers.some(h => h.toLowerCase().includes(sw.key));
                            });
                            return {
                                name: sw.name,
                                key: sw.key,
                                installed: isMissing ? "MISSING (AGENT UNREPORTED)" : "INSTALLED",
                                required: "REQUIRED",
                                status: isMissing ? "NON_COMPLIANT" : "COMPLIANT"
                            };
                        }),
                        custom_properties: customProps
                    });
                    newlyCreated++;
                }
            });

            rogues.forEach(item => {
                const normName = item.normalized;
                let existing = fleetDataset.find(dev => dev.canonical_name === normName || dev.serial.toLowerCase().includes(normName));

                const customProps = { "Reconciliation Match": "ROGUE_UNMANAGED" };
                item.sheets.forEach(s => {
                    s.headers.forEach((h, idx) => {
                        if (idx !== s.keyIdx) {
                            customProps[\`[\${s.filename}] \${h}\`] = String(s.row[idx] || "");
                        }
                    });
                });

                if (existing) {
                    existing.score = 0.00;
                    existing.level = "NON_COMPLIANT";
                    if (!existing.custom_properties) existing.custom_properties = {};
                    Object.assign(existing.custom_properties, customProps);
                    mergedUpdated++;
                } else {
                    fleetDataset.push({
                        id: \`dev-\${Math.random().toString(36).substring(2, 8)}\`,
                        canonical_name: item.name,
                        serial: \`SN-ROGUE-\${Math.random().toString(36).substring(2, 8).toUpperCase()}\`,
                        mac: \`00:1A:2B:3C:\${Math.floor(Math.random()*89+10)}:\${Math.floor(Math.random()*89+10)}\`,
                        manufacturer: "Unmanaged Rogue",
                        os: "Unknown Platform",
                        os_family: "Windows",
                        score: 0.00,
                        level: "NON_COMPLIANT",
                        condition: "IN_USE",
                        user_assigned: "rogue.unmanaged",
                        last_login: "-",
                        location: "Unknown / Network Trace",
                        location_group: "Non-Sift",
                        is_isolated: false,
                        software: sampleSoftwareCatalog.map(sw => ({
                            name: sw.name,
                            key: sw.key,
                            installed: "INSTALLED",
                            required: "REQUIRED",
                            status: "COMPLIANT"
                        })),
                        custom_properties: customProps
                    });
                    newlyCreated++;
                }
            });

            recalculateAllScores();
            switchNavSection("compliance");
            
            const successMsg = \`⚡ Excel Reconciliation Merge Complete! Integrated custom sheet columns. Added \${newlyCreated} new records and updated \${mergedUpdated} existing records.\`;
            logToTerminal(\`[Reconciler] \${successMsg}\`, "info");
            alert(successMsg);
        }

        function exportReconciliationReport() {
            logToTerminal("[Reconciler] Generating detailed CSV export of cross-sheet anomalies report...");
            
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += \`"Recon Device ID","Hostname","Audit Status","Details / Properties"\\n\`;

            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            if (!primarySheet) return;

            reconciliationResults.gaps.forEach(item => {
                const details = item.mergedProperties.map(p => \`[\${p.source}] \${p.property}:\${p.value}\`).join(" | ").replace(/"/g, '""');
                csvContent += \`"\${item.id}","\${item.name}","COVERAGE_GAP","\${details} | Missing: \${item.missingInSheets.join('; ')}"\\n\`;
            });

            reconciliationResults.rogues.forEach(item => {
                const details = item.sheets.map(s => \`\${s.filename}: [\${s.headers.slice(0,4).map((h, idx) => \`\${h}:\${s.row[idx] || "-"}\`).join(', ')}]\`).join(" | ").replace(/"/g, '""');
                csvContent += \`"\${item.id}","\${item.name}","ROGUE_UNMANAGED","\${details}"\\n\`;
            });

            reconciliationResults.matches.forEach(item => {
                const details = item.mergedProperties.map(p => \`[\${p.source}] \${p.property}:\${p.value}\`).join(" | ").replace(/"/g, '""');
                csvContent += \`"\${item.id}","\${item.name}","ALIGNED_MATCH","\${details}"\\n\`;
            });

            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", \`fleet_reconciliation_report_\${Date.now()}.csv\`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            logToTerminal("[Reconciler] Export successful. Dispatched report download stream.", "info");
        }`;

// Assemble the final file content
const finalContent = content.substring(0, startIndex) + newReconcilerCode + '\n' + content.substring(closeIndex);

console.log('Writing updated contents back to file...');
fs.writeFileSync(targetFilePath, finalContent, 'utf8');

console.log('SUCCESS: reconciler engine programmatically updated! 🎉');
