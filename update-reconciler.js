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

        function matchSoftwareKey(header, swKey) {
            if (!header || !swKey) return false;
            const h = header.toLowerCase().trim();
            const k = swKey.toLowerCase().trim();

            if (k === "ad") {
                if (h.includes("active directory") || h.includes("active_directory") || h.includes("domain") || h.includes("enrollment")) {
                    return true;
                }
                const words = h.split(/[^a-z0-9]+/);
                return words.includes("ad");
            }

            if (k === "bitlocker") {
                if (h.includes("bitlocker") || h.includes("bit locker") || h.includes("encryption") || h.includes("drive encryption") || h.includes("drive_encryption") || h.includes("disk encryption")) {
                    return true;
                }
                const words = h.split(/[^a-z0-9]+/);
                return words.includes("bitlocker");
            }

            if (k === "zscaler") {
                if (h.includes("zscaler") || h.includes("zscalar") || h.includes("z-scaler") || h.includes("vpn")) {
                    return true;
                }
                const words = h.split(/[^a-z0-9]+/);
                return words.includes("zscaler") || words.includes("zscalar");
            }

            if (k === "nessus") {
                if (h.includes("nessus") || h.includes("tenable") || h.includes("vulnerability agent") || h.includes("nessus agent") || h.includes("scanner")) {
                    return true;
                }
                const words = h.split(/[^a-z0-9]+/);
                return words.includes("nessus");
            }

            if (k === "sentinelone") {
                if (h.includes("sentinelone") || h.includes("sentinel one") || h.includes("s1") || h.includes("endpoint agent") || h.includes("edr") || h.includes("antivirus")) {
                    return true;
                }
                const words = h.split(/[^a-z0-9]+/);
                return words.includes("sentinelone") || words.includes("s1");
            }

            if (k === "sccm") {
                if (h.includes("sccm") || h.includes("mecm") || h.includes("management agent") || h.includes("patch agent")) {
                    return true;
                }
                const words = h.split(/[^a-z0-9]+/);
                return words.includes("sccm") || words.includes("mecm");
            }

            if (k.length <= 3) {
                const words = h.split(/[^a-z0-9]+/);
                return words.includes(k);
            }
            return h.includes(k);
        }

        function getSheetSoftwareKey(sheet) {
            if (!sheet || !sheet.filename) return null;
            const fn = sheet.filename.toLowerCase();
            const words = fn.split(/[^a-z0-9]+/);
            
            // Check filename matches first
            if (fn.includes("sentinel") || fn.includes("sentiel") || fn.includes("s1") || fn.includes("edr") || fn.includes("antivirus")) {
                return "sentinelone";
            }
            if (fn.includes("bitlocker") || fn.includes("bit locker") || fn.includes("bit_locker") || fn.includes("bit-locker") || fn.includes("encryption") || fn.includes("disk")) {
                return "bitlocker";
            }
            if (fn.includes("zscaler") || fn.includes("zscalar") || fn.includes("z-scaler") || fn.includes("z_scaler") || fn.includes("z scaler") || fn.includes("vpn")) {
                return "zscaler";
            }
            if (fn.includes("nessus") || fn.includes("tenable") || fn.includes("vulnerability") || fn.includes("scanner")) {
                return "nessus";
            }
            if (fn.includes("sccm") || fn.includes("mecm") || fn.includes("patch") || fn.includes("management")) {
                return "sccm";
            }
            
            // "ad" is too short for simple includes, use word list
            if (words.includes("ad") || fn.includes("active directory") || fn.includes("active_directory") || fn.includes("enrollment")) {
                if (sheet.role !== "primary") {
                    return "ad";
                }
            }
            
            // If filename doesn't match any key, fall back to matching headers
            const swKeys = ["sentinelone", "bitlocker", "zscaler", "nessus", "sccm", "ad"];
            for (const k of swKeys) {
                if (k === "ad" && sheet.role === "primary") continue;
                if (sheet.headers && sheet.headers.some(h => matchSoftwareKey(h, k))) {
                    return k;
                }
            }
            
            return null; // unknown classification
        }

        function isSheetUploadedForSoftware(swKey) {
            if (!swKey) return false;
            const k = swKey.toLowerCase();
            return reconcilerSheets.some(sheet => {
                return getSheetSoftwareKey(sheet) === k;
            });
        }

        function evaluateComplianceValue(rawVal) {
            if (rawVal === undefined || rawVal === null) {
                return { installed: "MISSING", status: "NON_COMPLIANT" };
            }
            const val = String(rawVal).trim().toLowerCase();
            if (!val) {
                return { installed: "MISSING", status: "NON_COMPLIANT" };
            }

            // If the value contains a version number, it is installed and compliant
            if (/\b\d+\.\d+/.test(val) || /^v\d+/.test(val)) {
                return { installed: "INSTALLED", status: "COMPLIANT" };
            }

            const compliantKeywords = [
                "compliant", "installed", "yes", "true", "1", "active",
                "enrolled", "active_enrollment", "active enrollment", "success", "ok",
                "pass", "passed", "on", "enabled", "running", "secured", "secure",
                "monitored", "up-to-date", "up to date", "encrypted", "encryption", "protected",
                "connected", "online", "tunnel active", "tunnel_active", "service running", "service_running"
            ];

            const nonCompliantKeywords = [
                "non-compliant", "non_compliant", "non compliant", "failed", "fail",
                "missing", "no", "false", "0", "inactive", "disabled",
                "critical", "error", "offline", "not enrolled", "not_enrolled",
                "unenrolled", "out of date", "out_of_date", "outdated", "vulnerable"
            ];

            if (compliantKeywords.includes(val)) {
                return { installed: "INSTALLED", status: "COMPLIANT" };
            }
            if (nonCompliantKeywords.includes(val)) {
                return { installed: rawVal.trim() || "MISSING", status: "NON_COMPLIANT" };
            }

            for (let kw of compliantKeywords) {
                if (val.includes(kw)) {
                    return { installed: "INSTALLED", status: "COMPLIANT" };
                }
            }
            for (let kw of nonCompliantKeywords) {
                if (val.includes(kw)) {
                    return { installed: rawVal.trim() || "MISSING", status: "NON_COMPLIANT" };
                }
            }

            return { installed: rawVal.trim() || "MISSING", status: "NON_COMPLIANT" };
        }

        function getMergedAgentStatus(item, swKey) {
            const agentKeywords = {
                ad: ["active directory", "ad", "active_directory", "domain"],
                bitlocker: ["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"],
                zscaler: ["zscaler", "zscalar", "z-scaler", "z-scaler", "zscaler client connector", "zscalar client connector", "vpn"],
                nessus: ["nessus", "tenable", "vulnerability agent", "nessus agent", "scanner"],
                sentinelone: ["sentinelone", "sentinel one", "s1", "endpoint agent", "edr", "antivirus"],
                sccm: ["sccm", "sccm agent", "mecm", "management agent", "patch agent"]
            };

            const keywords = agentKeywords[swKey] || [];

            if (item.mergedProperties) {
                const sortedProps = [...item.mergedProperties].sort((a, b) => {
                    const aIsSec = a.sheetRole === "Secondary" ? 1 : 0;
                    const bIsSec = b.sheetRole === "Secondary" ? 1 : 0;
                    return bIsSec - aIsSec;
                });

                for (let p of sortedProps) {
                    const propName = p.property.toLowerCase().trim();
                    const matched = keywords.some(kw => {
                        if (kw.length <= 3) {
                            const words = propName.split(/[^a-z0-9]+/);
                            return words.includes(kw);
                        }
                        return propName.includes(kw);
                    });

                    if (matched) {
                        const valString = String(p.value).trim();
                        if (valString && valString !== "-") {
                            // Specialized logic for AD domain / status values
                            if (swKey === "ad") {
                                const lowerVal = valString.toLowerCase();
                                const nonCompliantAD = ["workgroup", "none", "no", "failed", "false", "0", "not enrolled", "not_enrolled", "unenrolled", "missing", "-", "not joined", "not_joined", "non-joined", "unjoined", "not domain joined", "not domain-joined", "unassociated", "notregistered", "not registered"];
                                if (lowerVal && !nonCompliantAD.includes(lowerVal)) {
                                    return { installed: valString, status: "COMPLIANT" };
                                } else {
                                    return { installed: valString, status: "NON_COMPLIANT" };
                                }
                            }
                            return evaluateComplianceValue(valString);
                        }
                    }
                }
            }

            const isUploaded = isSheetUploadedForSoftware(swKey);
            if (isUploaded) {
                const isMissing = item.missingInSheets && item.missingInSheets.some(filename => {
                    const sheet = reconcilerSheets.find(s => s.filename === filename);
                    return sheet && (getSheetSoftwareKey(sheet) === swKey);
                });

                if (isMissing) {
                    return {
                        installed: swKey === "ad" ? "NOT ENROLLED" : "MISSING (AGENT UNREPORTED)",
                        status: "NON_COMPLIANT"
                    };
                } else {
                    return {
                        installed: "INSTALLED",
                        status: "COMPLIANT"
                    };
                }
            }

            if (swKey === "ad") {
                return {
                    installed: "INSTALLED",
                    status: "COMPLIANT"
                };
            }

            return {
                installed: "MISSING (AGENT UNREPORTED)",
                status: "NON_COMPLIANT"
            };
        }

        function registerMergedSoftwareAgents() {
            reconcilerSheets.forEach(sheet => {
                const key = getSheetSoftwareKey(sheet);
                if (key) {
                    mergedSoftwareAgents.add(key);
                }
            });
        }

        function parseCSVNative(text) {
            if (text.startsWith("\\uFEFF")) {
                text = text.substring(1);
            }
            const rawLines = text.split(/\\r?\\n/);
            const lines = [];
            
            let sep = ",";
            const firstLine = rawLines[0] || "";
            let commaCount = (firstLine.match(/,/g) || []).length;
            let semiCount = (firstLine.match(/;/g) || []).length;
            let tabCount = (firstLine.match(/\\t/g) || []).length;

            if (semiCount > commaCount && semiCount > tabCount) sep = ";";
            else if (tabCount > commaCount && tabCount > semiCount) sep = "\\t";

            for (let lineText of rawLines) {
                lineText = lineText.trim();
                if (!lineText) continue;
                
                const row = [];
                let currentField = "";
                let inQuotes = false;
                
                for (let i = 0; i < lineText.length; i++) {
                    const c = lineText[i];
                    const next = lineText[i + 1];
                    
                    if (c === '"') {
                        if (inQuotes && next === '"') {
                            currentField += '"';
                            i++;
                        } else {
                            inQuotes = !inQuotes;
                        }
                    } else if (c === sep && !inQuotes) {
                        row.push(currentField);
                        currentField = "";
                    } else {
                        currentField += c;
                    }
                }
                row.push(currentField);
                lines.push(row);
            }
            return lines;
        }

        function handleMultiSheetUpload(event) {
            const files = event.target.files;
            if (!files || files.length === 0) return;

            const usePython = (typeof window !== "undefined" && window.location && window.location.protocol && window.location.protocol.startsWith("http"));

            Array.from(files).forEach(file => {
                logToTerminal(\`[Reconciler] Upload request received for source file: "\${file.name}"\`);
                
                const isExcel = file.name.toLowerCase().endsWith(".xlsx") || file.name.toLowerCase().endsWith(".xls");

                if (usePython) {
                    const reader = new FileReader();
                    reader.onload = function (e) {
                        try {
                            const arrayBuffer = e.target.result;
                            const bytes = new Uint8Array(arrayBuffer);
                            let binary = "";
                            for (let i = 0; i < bytes.byteLength; i++) {
                                binary += String.fromCharCode(bytes[i]);
                            }
                            const base64 = btoa(binary);

                            logToTerminal(\`[Reconciler] Uploading "\${file.name}" to Python backend for validation...\`, "info");

                            fetch('/api/validate-sheet', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ filename: file.name, content: base64 })
                            })
                            .then(res => res.json())
                            .then(data => {
                                if (data.success) {
                                    logToTerminal(\`[Reconciler] Python validation completed for "\${file.name}"\`, "info");
                                    if (data.validation_report && data.validation_report.warnings.length > 0) {
                                        data.validation_report.warnings.forEach(warn => {
                                            logToTerminal(\`[Reconciler Validation Warning] \${warn}\`, "warn");
                                        });
                                    }
                                    if (data.validation_report && data.validation_report.errors.length > 0) {
                                        data.validation_report.errors.forEach(err => {
                                            logToTerminal(\`[Reconciler Validation Error] \${err}\`, "error");
                                        });
                                    }

                                    const headers = data.headers;
                                    const lowerHeaders = headers.map(h => String(h).toLowerCase().trim());
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
                                    if (keyIdx === -1) keyIdx = 0;

                                    const role = reconcilerSheets.length === 0 ? "primary" : "secondary";
                                    const sheetObj = {
                                        id: \`sheet-\${Math.random().toString(36).substring(2, 8)}\`,
                                        filename: data.filename,
                                        rows: data.rows.slice(1),
                                        headers: data.headers,
                                        keyIdx: keyIdx,
                                        role: role
                                    };
                                    reconcilerSheets.push(sheetObj);
                                    logToTerminal(\`[Reconciler] Loaded \${data.rows.length - 1} rows from "\${file.name}". Auto-detected match key: "\${headers[keyIdx]}"\`, "info");
                                    renderReconcilerQueue();
                                } else {
                                    logToTerminal(\`[Reconciler] Python validation failed for "\${file.name}": \${data.message}\`, "error");
                                    alert(\`❌ Python Validation Failed: \${data.message}\`);
                                }
                            })
                            .catch(err => {
                                logToTerminal(\`[Reconciler] Python backend connection error: \${err.message}. Falling back to client-side parsing.\`, "warn");
                                runFallbackReconcilerParse(file, isExcel);
                            });
                        } catch (err) {
                            logToTerminal(\`[Reconciler] Error preparing backend upload: \${err.message}. Falling back to client-side parsing.\`, "warn");
                            runFallbackReconcilerParse(file, isExcel);
                        }
                    };
                    reader.readAsArrayBuffer(file);
                } else {
                    runFallbackReconcilerParse(file, isExcel);
                }
            });
            event.target.value = "";
        }

        function runFallbackReconcilerParse(file, isExcel) {
            const reader = new FileReader();
            reader.onload = function (e) {
                try {
                    let data = e.target.result;
                    let rows;

                    if (!isExcel) {
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

                    if (keyIdx === -1) keyIdx = 0;

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

                let roleSelectHtml = \`
                    <select style="border: 1px solid var(--border-clean); padding: 0.35rem 0.5rem; font-size: 0.75rem; background: var(--bg-card); color: var(--text-primary); border-radius: 4px; width: 100%; cursor: pointer;" onchange="updateSheetRole('\${sheet.id}', this.value)">
                        <option value="primary" \${sheet.role === 'primary' ? 'selected' : ''}>Corporate Directory (Primary)</option>
                        <option value="secondary" \${sheet.role === 'secondary' ? 'selected' : ''}>Agent Telemetry (Secondary)</option>
                    </select>
                \`;

                let keySelectHtml = \`<select style="border: 1px solid var(--border-clean); padding: 0.35rem 0.5rem; font-size: 0.75rem; background: var(--bg-card); color: var(--text-primary); border-radius: 4px; width: 100%; cursor: pointer;" onchange="updateSheetKey('\${sheet.id}', this.value)">\`;
                sheet.headers.forEach((h, idx) => {
                    const selected = idx === sheet.keyIdx ? "selected" : "";
                    keySelectHtml += \`<option value="\${idx}" \${selected}>\${escapeHTML(h)} (Col \${idx + 1})</option>\`;
                });
                keySelectHtml += \`</select>\`;

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

            const usePython = (typeof window !== "undefined" && window.location && window.location.protocol && window.location.protocol.startsWith("http"));

            if (usePython) {
                logToTerminal(\`[Reconciler] Offloading deep asset reconciliation alignment to Python backend...\`);
                fetch('/api/reconcile-sheets', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sheets: reconcilerSheets })
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        reconciliationResults = data.results;
                        logToTerminal(\`[Reconciler] Python alignment complete. Matches: \${reconciliationResults.matches.length}, Gaps: \${reconciliationResults.gaps.length}, Rogues: \${reconciliationResults.rogues.length}\`, "info");
                        renderReconciliationUI();
                    } else {
                        logToTerminal(\`[Reconciler] Python Reconciliation failed: \${data.message}\`, "error");
                        alert(\`❌ Reconciliation Failed: \${data.message}\`);
                    }
                })
                .catch(err => {
                    logToTerminal(\`[Reconciler] Python backend connection error: \${err.message}. Falling back to local alignment.\`, "warn");
                    runLocalReconciliation();
                });
            } else {
                runLocalReconciliation();
            }
        }

        function runLocalReconciliation() {
            logToTerminal(\`[Reconciler] Executing local asset alignment...\`);
            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            const secondarySheets = reconcilerSheets.filter(s => s.role === "secondary");
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
            renderReconciliationUI();
        }

        function renderReconciliationUI() {
            const matches = reconciliationResults.matches;
            const gaps = reconciliationResults.gaps;
            const rogues = reconciliationResults.rogues;

            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            if (!primarySheet) return;

            const totalPrimary = primaryMapSizeFallback();
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

            // Verify and align metrics with the active reconciled fleet
            const matchesInFleet = fleetDataset.filter(d => d.custom_properties && d.custom_properties["Reconciliation Match"] === "SUCCESS").length;
            const gapsInFleet = fleetDataset.filter(d => d.custom_properties && d.custom_properties["Reconciliation Match"] === "COVERAGE_GAP").length;
            const roguesInFleet = fleetDataset.filter(d => d.custom_properties && d.custom_properties["Reconciliation Match"] === "ROGUE_UNMANAGED").length;

            const hasMergedData = (matchesInFleet > 0 || gapsInFleet > 0 || roguesInFleet > 0);
            
            if (hasMergedData) {
                logToTerminal(\`[Audit Reconciler] Verification: Matches=\${matches.length} (Fleet: \${matchesInFleet}), Gaps=\${gaps.length} (Fleet: \${gapsInFleet}), Rogues=\${rogues.length} (Fleet: \${roguesInFleet}).\`, "info");
                if (matches.length === matchesInFleet && gaps.length === gapsInFleet && rogues.length === roguesInFleet) {
                    logToTerminal(\`[Audit Reconciler] Verification SUCCESS: Active Reconciled Fleet dataset is in 100% perfect sync with reconciliation metrics.\`, "info");
                } else {
                    logToTerminal(\`[Audit Reconciler] Verification Warning: Active fleet counts have deviated from reconciliation results (possibly due to manual overrides).\`, "warn");
                }
            }

            const activeTab = currentReconTab || (gaps.length > 0 ? "gaps" : (matches.length > 0 ? "matches" : "rogues"));
            switchReconTab(activeTab);
        }

        function primaryMapSizeFallback() {
            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            if (!primarySheet) return 0;
            const keyIdx = primarySheet.keyIdx;
            const nameSet = new Set();
            primarySheet.rows.forEach(r => {
                const val = String(r[keyIdx] || "").trim();
                if (val) nameSet.add(val.replace(/[^a-zA-Z0-9]/g, "").toLowerCase());
            });
            return nameSet.size;
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

        function mergeDistinctProperties(target, source) {
            for (let key in source) {
                if (!source.hasOwnProperty(key)) continue;

                const newValue = source[key];

                // Extract base property name from the source key
                let baseKey = key;
                if (key.startsWith('[') && key.includes('] ')) {
                    baseKey = key.substring(key.indexOf('] ') + 2);
                }

                // Let's check if the target already contains a matching property with the same value
                let hasMatchingInfo = false;
                for (let targetKey in target) {
                    if (!target.hasOwnProperty(targetKey)) continue;

                    let targetBaseKey = targetKey;
                    if (targetKey.startsWith('[') && targetKey.includes('] ')) {
                        targetBaseKey = targetKey.substring(targetKey.indexOf('] ') + 2);
                    }

                    if (targetBaseKey.toLowerCase() === baseKey.toLowerCase()) {
                        if (target[targetKey] === newValue) {
                            hasMatchingInfo = true;
                            break;
                        }
                    }
                }

                // If the target does NOT have matching information, then we merge it!
                if (!hasMatchingInfo) {
                    target[key] = newValue;
                }
            }
        }

        function findExistingDeviceByItem(item, fleetByName = null, fleetBySerial = null, fleetByMac = null) {
            if (!item) return null;

            const nameKeywords = ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system"];
            const serialKeywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "service tag", "servicetag", "tag"];
            const macKeywords = ["macaddress", "mac", "physical", "ethernet", "hardware"];

            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            const primaryHeaders = primarySheet ? primarySheet.headers.map(h => h.toLowerCase().trim()) : [];

            function getPrimaryColValue(row, keywords) {
                if (!primarySheet) return null;
                for (let kw of keywords) {
                    const idx = primaryHeaders.findIndex(h => {
                        if (kw.length <= 3) {
                            const words = h.split(/[^a-z0-9]+/);
                            return words.includes(kw);
                        }
                        return h.includes(kw);
                    });
                    if (idx !== -1 && row[idx] !== undefined) {
                        return String(row[idx]).trim();
                    }
                }
                return null;
            }

            function getMergedPropValue(mergedProperties, keywords) {
                if (!mergedProperties) return null;
                for (let p of mergedProperties) {
                    const propName = p.property.toLowerCase().trim();
                    for (let kw of keywords) {
                        if (kw.length <= 3) {
                            const words = propName.split(/[^a-z0-9]+/);
                            if (words.includes(kw)) {
                                return p.value;
                            }
                        } else if (propName.includes(kw)) {
                            return p.value;
                        }
                    }
                }
                return null;
            }

            let nameVal = null;
            let serialVal = null;
            let macVal = null;

            if (item.primaryRow && primarySheet) {
                nameVal = getPrimaryColValue(item.primaryRow, nameKeywords);
                serialVal = getPrimaryColValue(item.primaryRow, serialKeywords);
                macVal = getPrimaryColValue(item.primaryRow, macKeywords);
            }

            if (item.mergedProperties) {
                if (!nameVal) nameVal = getMergedPropValue(item.mergedProperties, nameKeywords);
                if (!serialVal) serialVal = getMergedPropValue(item.mergedProperties, serialKeywords);
                if (!macVal) macVal = getMergedPropValue(item.mergedProperties, macKeywords);
            }

            if (item.sheets) {
                item.sheets.forEach(s => {
                    const sHeaders = s.headers.map(h => h.toLowerCase().trim());

                    function getSecondaryColValue(row, keywords) {
                        for (let kw of keywords) {
                            const idx = sHeaders.findIndex(h => {
                                if (kw.length <= 3) {
                                    const words = h.split(/[^a-z0-9]+/);
                                    return words.includes(kw);
                                }
                                return h.includes(kw);
                            });
                            if (idx !== -1 && row[idx] !== undefined) {
                                return String(row[idx]).trim();
                            }
                        }
                        return null;
                    }

                    if (!nameVal) nameVal = getSecondaryColValue(s.row, nameKeywords);
                    if (!serialVal) serialVal = getSecondaryColValue(s.row, serialKeywords);
                    if (!macVal) macVal = getSecondaryColValue(s.row, macKeywords);
                });
            }

            if (!nameVal) nameVal = item.name || item.normalized || "";

            const normName = nameVal ? nameVal.replace(/[^a-zA-Z0-9]/g, "").toLowerCase() : "";
            const normSerial = serialVal ? serialVal.replace(/[^a-zA-Z0-9]/g, "").toLowerCase() : "";
            const normMac = macVal ? macVal.replace(/[^a-zA-Z0-9]/g, "").toLowerCase() : "";

            if (!normName && !normSerial && !normMac) return null;

            if (fleetByName && fleetBySerial && fleetByMac) {
                if (normName && fleetByName.has(normName)) return fleetByName.get(normName);
                if (normSerial && fleetBySerial.has(normSerial)) return fleetBySerial.get(normSerial);
                if (normMac && fleetByMac.has(normMac)) return fleetByMac.get(normMac);
                return null;
            }

            return fleetDataset.find(dev => {
                const devName = String(dev.canonical_name || "").replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
                const devSerial = String(dev.serial || "").replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
                const devMac = String(dev.mac || "").replace(/[^a-zA-Z0-9]/g, "").toLowerCase();

                if (normName && devName === normName) return true;
                if (normSerial && devSerial === normSerial) return true;
                if (normMac && devMac === normMac) return true;

                return false;
            });
        }

        function extractDeviceIdentifiers(item) {
            const nameKeywords = ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system"];
            const serialKeywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "service tag", "servicetag", "tag"];
            const macKeywords = ["macaddress", "mac", "physical", "ethernet", "hardware"];

            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            const primaryHeaders = primarySheet ? primarySheet.headers.map(h => h.toLowerCase().trim()) : [];

            function getPrimaryColValue(row, keywords) {
                if (!primarySheet) return null;
                for (let kw of keywords) {
                    const idx = primaryHeaders.findIndex(h => {
                        if (kw.length <= 3) {
                            const words = h.split(/[^a-z0-9]+/);
                            return words.includes(kw);
                        }
                        return h.includes(kw);
                    });
                    if (idx !== -1 && row[idx] !== undefined) {
                        return String(row[idx]).trim();
                    }
                }
                return null;
            }

            function getMergedPropValue(mergedProperties, keywords) {
                if (!mergedProperties) return null;
                for (let p of mergedProperties) {
                    const propName = p.property.toLowerCase().trim();
                    for (let kw of keywords) {
                        if (kw.length <= 3) {
                            const words = propName.split(/[^a-z0-9]+/);
                            if (words.includes(kw)) {
                                return p.value;
                            }
                        } else if (propName.includes(kw)) {
                            return p.value;
                        }
                    }
                }
                return null;
            }

            let nameVal = null;
            let serialVal = null;
            let macVal = null;

            if (item.primaryRow && primarySheet) {
                nameVal = getPrimaryColValue(item.primaryRow, nameKeywords);
                serialVal = getPrimaryColValue(item.primaryRow, serialKeywords);
                macVal = getPrimaryColValue(item.primaryRow, macKeywords);
            }
            if (item.mergedProperties) {
                if (!nameVal) nameVal = getMergedPropValue(item.mergedProperties, nameKeywords);
                if (!serialVal) serialVal = getMergedPropValue(item.mergedProperties, serialKeywords);
                if (!macVal) macVal = getMergedPropValue(item.mergedProperties, macKeywords);
            }
            if (item.sheets) {
                item.sheets.forEach(s => {
                    const sHeaders = s.headers.map(h => h.toLowerCase().trim());

                    function getSecondaryColValue(row, keywords) {
                        for (let kw of keywords) {
                            const idx = sHeaders.findIndex(h => {
                                if (kw.length <= 3) {
                                    const words = h.split(/[^a-z0-9]+/);
                                    return words.includes(kw);
                                }
                                return h.includes(kw);
                            });
                            if (idx !== -1 && row[idx] !== undefined) {
                                return String(row[idx]).trim();
                            }
                        }
                        return null;
                    }

                    if (!nameVal) nameVal = getSecondaryColValue(s.row, nameKeywords);
                    if (!serialVal) serialVal = getSecondaryColValue(s.row, serialKeywords);
                    if (!macVal) macVal = getSecondaryColValue(s.row, macKeywords);
                });
            }

            if (!nameVal) nameVal = item.name || item.normalized || "Unknown Reconciled";
            if (!serialVal) serialVal = \`SN-RECON-\${Math.random().toString(36).substring(2, 8).toUpperCase()}\`;
            if (!macVal) macVal = \`00:1A:2B:3C:\${Math.floor(Math.random() * 89 + 10)}:\${Math.floor(Math.random() * 89 + 10)}\`;

            return { nameVal, serialVal, macVal };
        }

        function extractConditionFromItem(item) {
            const condKeywords = ["condition", "status", "state"];

            function normaliseCondition(raw) {
                const normCond = String(raw).trim().toUpperCase().replace(/[\\s-]+/g, "_").replace(/[^A-Z0-9_]/g, "");
                if (!normCond) return null;
                if (normCond === "IN_USE" || normCond === "USE" || normCond === "ACTIVE") return "IN_USE";
                if (normCond === "IN_REPAIR" || normCond === "REPAIR") return "IN_REPAIR";
                if (normCond === "IN_STORE" || normCond === "STORE") return "IN_STORE";
                if (normCond === "EXPIRED") return "EXPIRED";
                if (normCond === "DISPOSED" || normCond === "DECOMMISSIONED" || normCond === "RETIRED") return "DISPOSED";
                if (normCond === "DONATED_UNDER_CSR" || normCond === "DONATED" || normCond === "CSR") return "DONATED_UNDER_CSR";
                if (normCond === "LOANABLE_RESERVED" || normCond === "LOANABLE") return "LOANABLE_RESERVED";
                if (normCond === "NOT_TRACEABLE" || normCond === "NOTTRACEABLE" || normCond === "UNTRACEABLE") return "NOT_TRACEABLE";
                if (normCond === "RESERVED") return "RESERVED";
                if (normCond === "UNKNOWN") return "UNKNOWN";
                return null;
            }

            // 1) Try primary sheet row
            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            if (primarySheet && item.primaryRow) {
                const pHeaders = primarySheet.headers.map(h => h.toLowerCase().trim());
                for (const kw of condKeywords) {
                    const idx = pHeaders.findIndex(h => {
                        if (kw.length <= 3) {
                            const words = h.split(/[^a-z0-9]+/);
                            return words.includes(kw);
                        }
                        return h.includes(kw);
                    });
                    if (idx !== -1 && item.primaryRow[idx] !== undefined && String(item.primaryRow[idx]).trim()) {
                        const result = normaliseCondition(item.primaryRow[idx]);
                        if (result) return result;
                    }
                }
            }

            // 2) Try mergedProperties
            if (item.mergedProperties) {
                for (const p of item.mergedProperties) {
                    const propName = p.property.toLowerCase().trim();
                    if (condKeywords.some(kw => propName === kw || propName.includes(kw))) {
                        const result = normaliseCondition(p.value);
                        if (result) return result;
                    }
                }
            }

            // 3) Try secondary sheet rows
            if (item.sheets) {
                for (const s of item.sheets) {
                    const sHeaders = s.headers.map(h => h.toLowerCase().trim());
                    for (const kw of condKeywords) {
                        const idx = sHeaders.findIndex(h => {
                            if (kw.length <= 3) {
                                const words = h.split(/[^a-z0-9]+/);
                                return words.includes(kw);
                            }
                            return h.includes(kw);
                        });
                        if (idx !== -1 && s.row[idx] !== undefined && String(s.row[idx]).trim()) {
                            const result = normaliseCondition(s.row[idx]);
                            if (result) return result;
                        }
                    }
                }
            }

            // No condition data in the Excel - default to UNKNOWN for new assets
            return "UNKNOWN";
        }

        function isolateRogueAsset(rogueId) {
            const rogue = reconciliationResults.rogues.find(r => r.id === rogueId);
            if (!rogue) return;

            // Check if already in fleetDataset using robust matching
            let existing = findExistingDeviceByItem(rogue);
            if (existing) {
                existing.is_isolated = true;
                existing.is_rogue = true;
                existing.score = 10.00;
                existing.level = "NON_COMPLIANT";
            } else {
                // Add to fleet as isolated rogue!
                const newCustomProps = { "Reconciliation Match": "ROGUE_UNMANAGED" };
                rogue.sheets.forEach(s => {
                    s.headers.forEach((h, idx) => {
                        if (idx !== s.keyIdx) {
                            newCustomProps[\`[\${s.filename}] \${h}\`] = String(s.row[idx] || "");
                        }
                    });
                });

                const ids = extractDeviceIdentifiers(rogue);
                fleetDataset.push({
                    id: \`dev-\${Math.random().toString(36).substring(2, 8)}\`,
                    canonical_name: rogue.normalized || ids.nameVal,
                    serial: ids.serialVal.startsWith("SN-ROGUE-") ? ids.serialVal : \`SN-ROGUE-\${ids.serialVal.replace(/^SN-/, "")}\`,
                    mac: ids.macVal,
                    manufacturer: "Unmanaged Rogue",
                    os: "Unknown Platform",
                    os_family: "Windows",
                    score: 10.00,
                    level: "NON_COMPLIANT",
                    condition: extractConditionFromItem(rogue),
                    user_assigned: "rogue.unmanaged",
                    last_login: "-",
                    location: "Unknown / Network Trace",
                    location_group: "Non-Sift",
                    is_isolated: true,
                    is_rogue: true,
                    software: sampleSoftwareCatalog.map(sw => ({
                        name: sw.name,
                        key: sw.key,
                        installed: "MISSING",
                        required: "REQUIRED",
                        status: "NON_COMPLIANT"
                    })),
                    custom_properties: newCustomProps
                });
            }

            rogue.is_isolated = true;
            logToTerminal(\`[EDR Containment] Dispatched zero-trust network containment isolation for rogue host \${rogue.name.toUpperCase()} (ID: \${rogue.id}).\`, "error");
            alert(\`Rogue asset \${rogue.name.toUpperCase()} isolated successfully! Firewall rules and network ports contained.\`);

            recalculateAllScores();
            renderReconciliationUI();
        }

        function registerRogueAsset(rogueId) {
            const rogue = reconciliationResults.rogues.find(r => r.id === rogueId);
            if (!rogue) return;

            // Register it! Add it to fleetDataset as a fully compliant managed asset using robust matching
            let existing = findExistingDeviceByItem(rogue);

            const newCustomProps = {
                "Reconciliation Match": "SUCCESS",
                "Authorized Registration": "MANUALLY APPROVED"
            };
            rogue.sheets.forEach(s => {
                s.headers.forEach((h, idx) => {
                    if (idx !== s.keyIdx) {
                        newCustomProps[\`[\${s.filename}] \${h}\`] = String(s.row[idx] || "");
                    }
                });
            });

            if (existing) {
                existing.is_rogue = false;
                existing.is_isolated = false;
                existing.score = 100.00;
                existing.level = "COMPLIANT";
                existing.user_assigned = "authorized.user";
                existing.software.forEach(sw => {
                    sw.installed = "INSTALLED";
                    sw.status = "COMPLIANT";
                });
                if (!existing.custom_properties) existing.custom_properties = {};
                Object.assign(existing.custom_properties, newCustomProps);
            } else {
                const ids = extractDeviceIdentifiers(rogue);
                fleetDataset.push({
                    id: \`dev-\${Math.random().toString(36).substring(2, 8)}\`,
                    canonical_name: rogue.normalized || ids.nameVal,
                    serial: ids.serialVal.startsWith("SN-REGISTERED-") ? ids.serialVal : \`SN-REGISTERED-\${ids.serialVal.replace(/^SN-/, "")}\`,
                    mac: ids.macVal,
                    manufacturer: "Authorized Manually",
                    os: "Windows 11 Enterprise",
                    os_family: "Windows",
                    score: 100.00,
                    level: "COMPLIANT",
                    condition: "IN_USE",
                    user_assigned: "authorized.user",
                    last_login: new Date().toISOString().substring(0, 16).replace("T", " "),
                    location: "Corporate Head Office",
                    location_group: "Sift",
                    is_isolated: false,
                    is_rogue: false,
                    software: sampleSoftwareCatalog.map(sw => {
                        if (sw.key === "ad" || isSheetUploadedForSoftware(sw.key) || mergedSoftwareAgents.has(sw.key)) {
                            return {
                                name: sw.name,
                                key: sw.key,
                                installed: "INSTALLED",
                                required: "REQUIRED",
                                status: "COMPLIANT"
                            };
                        }
                        return {
                            name: sw.name,
                            key: sw.key,
                            installed: "MISSING (AGENT UNREPORTED)",
                            required: "REQUIRED",
                            status: "NON_COMPLIANT"
                        };
                    }),
                    custom_properties: newCustomProps
                });
            }

            // Remove from rogues, add to matches!
            reconciliationResults.rogues = reconciliationResults.rogues.filter(r => r.id !== rogueId);
            reconciliationResults.matches.push({
                id: rogueId,
                name: rogue.name,
                normalized: rogue.normalized,
                mergedProperties: rogue.sheets.flatMap(s =>
                    s.headers.slice(1).map((h, idx) => ({
                        source: s.filename,
                        sheetRole: "Secondary",
                        property: h,
                        value: String(s.row[idx + 1] || "")
                    }))
                ),
                status: "MATCHED"
            });

            recalculateAllScores();
            currentReconTab = "matches";
            renderReconciliationUI();

            logToTerminal(\`[Reconciler] Manually authorized and enrolled rogue asset \${rogue.name.toUpperCase()} into Corporate Directory context.\`, "info");
            alert(\`Rogue asset \${rogue.name.toUpperCase()} authorized and registered in Corporate Directory successfully!\`);
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

            registerMergedSoftwareAgents();

            // Pre-index fleetDataset by normalized canonical name, serial, and MAC address
            const fleetByName = new Map();
            const fleetBySerial = new Map();
            const fleetByMac = new Map();

            fleetDataset.forEach(dev => {
                if (dev.canonical_name) {
                    const normName = String(dev.canonical_name).replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
                    if (normName) fleetByName.set(normName, dev);
                }
                if (dev.serial) {
                    const normSerial = String(dev.serial).replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
                    if (normSerial) fleetBySerial.set(normSerial, dev);
                }
                if (dev.mac) {
                    const normMac = String(dev.mac).replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
                    if (normMac) fleetByMac.set(normMac, dev);
                }
            });

            let newlyCreated = 0;
            let mergedUpdated = 0;

            matches.forEach(item => {
                let existing = findExistingDeviceByItem(item, fleetByName, fleetBySerial, fleetByMac);

                const customProps = { "Reconciliation Match": "SUCCESS" };
                item.mergedProperties.forEach(p => {
                    customProps[\`[\${p.source}] \${p.property}\`] = p.value;
                });

                if (existing) {
                    existing.software.forEach(sw => {
                        const statusObj = getMergedAgentStatus(item, sw.key);
                        const isUploaded = isSheetUploadedForSoftware(sw.key);
                        const hasProp = item.mergedProperties && item.mergedProperties.some(p => {
                            const agentKeywords = {
                                ad: ["active directory", "ad", "active_directory", "domain", "enrollment"],
                                bitlocker: ["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"],
                                zscaler: ["zscaler", "z-scaler", "zscaler client connector", "vpn"],
                                nessus: ["nessus", "tenable", "vulnerability agent", "nessus agent", "scanner"],
                                sentinelone: ["sentinelone", "sentinel one", "s1", "endpoint agent", "edr", "antivirus"],
                                sccm: ["sccm", "sccm agent", "mecm", "management agent", "patch agent"]
                            };
                            const keywords = agentKeywords[sw.key] || [];
                            const propName = p.property.toLowerCase().trim();
                            return keywords.some(kw => {
                                if (kw.length <= 3) {
                                    return propName.split(/[^a-z0-9]+/).includes(kw);
                                }
                                return propName.includes(kw);
                            });
                        });
                        if (isUploaded || hasProp) {
                            sw.installed = statusObj.installed;
                            sw.status = statusObj.status;
                        }
                    });
                    if (!existing.custom_properties) existing.custom_properties = {};
                    mergeDistinctProperties(existing.custom_properties, customProps);
                    mergedUpdated++;
                } else {
                    const newCustomProps = {};
                    mergeDistinctProperties(newCustomProps, customProps);
                    const ids = extractDeviceIdentifiers(item);
                    fleetDataset.push({
                        id: \`dev-\${Math.random().toString(36).substring(2, 8)}\`,
                        canonical_name: ids.nameVal,
                        serial: ids.serialVal,
                        mac: ids.macVal,
                        manufacturer: "Generic Reconciled",
                        os: "Windows 11 Enterprise",
                        os_family: "Windows",
                        score: 100.00,
                        level: "COMPLIANT",
                        condition: extractConditionFromItem(item),
                        user_assigned: "reconciler.user",
                        last_login: new Date().toISOString().substring(0, 16).replace("T", " "),
                        location: "Corporate Head Office",
                        location_group: "Sift",
                        is_isolated: false,
                        software: sampleSoftwareCatalog.map(sw => {
                            const statusObj = getMergedAgentStatus(item, sw.key);
                            return {
                                name: sw.name,
                                key: sw.key,
                                installed: statusObj.installed,
                                required: "REQUIRED",
                                status: statusObj.status
                            };
                        }),
                        custom_properties: newCustomProps
                    });
                    newlyCreated++;
                }
            });

            gaps.forEach(item => {
                let existing = findExistingDeviceByItem(item, fleetByName, fleetBySerial, fleetByMac);

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
                        const statusObj = getMergedAgentStatus(item, sw.key);
                        const isUploaded = isSheetUploadedForSoftware(sw.key);
                        const hasProp = item.mergedProperties && item.mergedProperties.some(p => {
                            const agentKeywords = {
                                ad: ["active directory", "ad", "active_directory", "domain", "enrollment"],
                                bitlocker: ["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"],
                                zscaler: ["zscaler", "z-scaler", "zscaler client connector", "vpn"],
                                nessus: ["nessus", "tenable", "vulnerability agent", "nessus agent", "scanner"],
                                sentinelone: ["sentinelone", "sentinel one", "s1", "endpoint agent", "edr", "antivirus"],
                                sccm: ["sccm", "sccm agent", "mecm", "management agent", "patch agent"]
                            };
                            const keywords = agentKeywords[sw.key] || [];
                            const propName = p.property.toLowerCase().trim();
                            return keywords.some(kw => {
                                if (kw.length <= 3) {
                                    return propName.split(/[^a-z0-9]+/).includes(kw);
                                }
                                return propName.includes(kw);
                            });
                        });
                        if (isUploaded || hasProp) {
                            sw.installed = statusObj.installed;
                            sw.status = statusObj.status;
                        }
                    });

                    if (!existing.custom_properties) existing.custom_properties = {};
                    mergeDistinctProperties(existing.custom_properties, customProps);
                    mergedUpdated++;
                } else {
                    const newCustomProps = {};
                    mergeDistinctProperties(newCustomProps, customProps);
                    const ids = extractDeviceIdentifiers(item);
                    fleetDataset.push({
                        id: \`dev-\${Math.random().toString(36).substring(2, 8)}\`,
                        canonical_name: ids.nameVal,
                        serial: ids.serialVal.startsWith("SN-GAP-") ? ids.serialVal : \`SN-GAP-\${ids.serialVal.replace(/^SN-RECON-/, "").replace(/^SN-/, "")}\`,
                        mac: ids.macVal,
                        manufacturer: "Generic Reconciled Gap",
                        os: "Unknown Platform",
                        os_family: "Windows",
                        score: 0.00,
                        level: "NON_COMPLIANT",
                        condition: extractConditionFromItem(item),
                        user_assigned: "unassigned",
                        last_login: "-",
                        location: "Remote - Untrusted",
                        location_group: "Non-Sift",
                        is_isolated: false,
                        software: sampleSoftwareCatalog.map(sw => {
                            const statusObj = getMergedAgentStatus(item, sw.key);
                            return {
                                name: sw.name,
                                key: sw.key,
                                installed: statusObj.installed,
                                required: "REQUIRED",
                                status: statusObj.status
                            };
                        }),
                        custom_properties: newCustomProps
                    });
                    newlyCreated++;
                }
            });

            rogues.forEach(item => {
                let existing = findExistingDeviceByItem(item, fleetByName, fleetBySerial, fleetByMac);

                const customProps = { "Reconciliation Match": "ROGUE_UNMANAGED" };
                item.sheets.forEach(s => {
                    s.headers.forEach((h, idx) => {
                        if (idx !== s.keyIdx) {
                            customProps[\`[\${s.filename}] \${h}\`] = String(s.row[idx] || "");
                        }
                    });
                });

                if (existing) {
                    existing.score = item.is_isolated ? 10.00 : 0.00;
                    existing.level = "NON_COMPLIANT";
                    existing.is_rogue = true;
                    existing.is_isolated = !!item.is_isolated;
                    if (!existing.custom_properties) existing.custom_properties = {};
                    mergeDistinctProperties(existing.custom_properties, customProps);
                    mergedUpdated++;
                } else {
                    const newCustomProps = {};
                    mergeDistinctProperties(newCustomProps, customProps);
                    const ids = extractDeviceIdentifiers(item);
                    fleetDataset.push({
                        id: \`dev-\${Math.random().toString(36).substring(2, 8)}\`,
                        canonical_name: ids.nameVal,
                        serial: ids.serialVal.startsWith("SN-ROGUE-") ? ids.serialVal : \`SN-ROGUE-\${ids.serialVal.replace(/^SN-RECON-/, "").replace(/^SN-/, "")}\`,
                        mac: ids.macVal,
                        manufacturer: "Unmanaged Rogue",
                        os: "Unknown Platform",
                        os_family: "Windows",
                        score: item.is_isolated ? 10.00 : 0.00,
                        level: "NON_COMPLIANT",
                        condition: extractConditionFromItem(item),
                        user_assigned: "rogue.unmanaged",
                        last_login: "-",
                        location: "Unknown / Network Trace",
                        location_group: "Non-Sift",
                        is_isolated: !!item.is_isolated,
                        is_rogue: true,
                        software: sampleSoftwareCatalog.map(sw => ({
                            name: sw.name,
                            key: sw.key,
                            installed: "MISSING",
                            required: "REQUIRED",
                            status: "NON_COMPLIANT"
                        })),
                        custom_properties: newCustomProps
                    });
                    newlyCreated++;
                }
            });

            // Dynamically expand table headers with newly merged custom Excel property columns
            const mergedKeys = new Set();
            fleetDataset.forEach(dev => {
                if (dev.custom_properties) {
                    for (let key in dev.custom_properties) {
                        if (key.startsWith('[') && key.includes('] ')) {
                            mergedKeys.add(key);
                        }
                    }
                }
            });

            mergedKeys.forEach(k => {
                const customKey = \`custom:\${k}\`;
                if (!activeTableKeys.includes(customKey)) {
                    // Extract clean name and source file for header label
                    const cleanName = k.replace(/^\[.*?\]\s*/, '');
                    const sourceName = k.match(/^\[(.*?)\]/) ? k.match(/^\[(.*?)\]/)[1] : 'Excel';
                    const headerLabel = \`\${cleanName} (\${sourceName})\`;

                    activeTableHeaders.push(headerLabel);
                    activeTableKeys.push(customKey);
                }
            });

            recalculateAllScores();
            renderReconciliationUI();
            switchNavSection("compliance");

            const successMsg = \`Excel Reconciliation Merge Complete! Integrated custom sheet columns. Added \${newlyCreated} new records and updated \${mergedUpdated} existing records.\`;
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
