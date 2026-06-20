// --- Cross-Sheet Asset Reconciliation Workspace Engine ---

        // reconcilerSheets and reconciliationResults are declared globally at the top of the script block to prevent TDZ ReferenceErrors on page reload
        reconcilerSheets = [];
        reconciliationResults = {
            matches: [],
            gaps: [],
            rogues: []
        };

        let currentReconTab = "gaps";

        function autoDetectKeyIdx(headers, rows) {
            if (!headers || headers.length === 0) return 0;
            const lowerHeaders = headers.map(h => String(h).toLowerCase().trim());
            const nameKeywords = ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system"];
            const serialKeywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "service tag", "servicetag", "tag", "asset tag", "assettag"];
            const macKeywords = ["macaddress", "mac", "physical", "ethernet", "hardware"];

            const candidates = [];
            lowerHeaders.forEach((h, idx) => {
                let score = 0;
                let type = "";

                if (nameKeywords.some(kw => kw.length <= 3 ? h.split(/[^a-z0-9]+/).includes(kw) : h.includes(kw))) {
                    score = 3;
                    type = "name";
                } else if (serialKeywords.some(kw => kw.length <= 3 ? h.split(/[^a-z0-9]+/).includes(kw) : h.includes(kw))) {
                    score = 2;
                    type = "serial";
                } else if (macKeywords.some(kw => kw.length <= 3 ? h.split(/[^a-z0-9]+/).includes(kw) : h.includes(kw))) {
                    score = 1;
                    type = "mac";
                }

                if (score > 0) {
                    // Calculate uniqueness
                    const vals = rows.slice(1).map(r => {
                        const cell = r[idx];
                        return cell !== undefined && cell !== null ? String(cell).trim().toLowerCase() : "";
                    }).filter(v => v !== "" && v !== "-" && v !== "disabled" && v !== "unknown" && v !== "not available" && v !== "to be filled by o.e.m.");
                    const uniqueVals = new Set(vals);
                    const uniqueness = vals.length > 0 ? uniqueVals.size / vals.length : 0;

                    candidates.push({
                        idx,
                        score,
                        uniqueness
                    });
                }
            });

            const validCandidates = candidates.filter(c => c.uniqueness > 0.1);
            if (validCandidates.length > 0) {
                validCandidates.sort((a, b) => {
                    if (Math.abs(a.uniqueness - b.uniqueness) > 0.15) {
                        return b.uniqueness - a.uniqueness;
                    }
                    return b.score - a.score;
                });
                return validCandidates[0].idx;
            } else if (candidates.length > 0) {
                candidates.sort((a, b) => b.score - a.score);
                return candidates[0].idx;
            }
            return 0;
        }

        function matchSoftwareKey(header, swKey) {
            if (!header || !swKey) return false;
            const h = header.toLowerCase().trim();
            const k = swKey.toLowerCase().trim();

            if (k !== "ad") {
                const words = h.split(/[^a-z0-9]+/);
                if (words.includes("ad") || words.includes("adcomputers") || h.includes("active directory") || h.includes("active_directory") || h.includes("enrollment")) {
                    return false;
                }
            }

            if (k === "ad") {
                if (h.includes("active directory") || h.includes("active_directory") || h.includes("domain") || h.includes("enrollment") || h.includes("canonicalname") || h.includes("canonical name") || h.includes("distinguishedname") || h.includes("distinguished name")) {
                    return true;
                }
                const words = h.split(/[^a-z0-9]+/);
                return words.includes("ad") || words.includes("adcomputers");
            }

            if (k === "bitlocker") {
                if (h.includes("bitlocker") || h.includes("bit locker") || h.includes("encryption") || h.includes("drive encryption") || h.includes("drive_encryption") || h.includes("disk encryption")) {
                    return true;
                }
                const words = h.split(/[^a-z0-9]+/);
                return words.includes("bitlocker");
            }

            if (k === "zscaler") {
                if (h.includes("zscaler") || h.includes("zscalar") || h.includes("zscalr") || h.includes("z-scaler") || h.includes("z-scalar") || h.includes("z-scalr") || h.includes("vpn")) {
                    return true;
                }
                const words = h.split(/[^a-z0-9]+/);
                return words.includes("zscaler") || words.includes("zscalar") || words.includes("zscalr");
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
            if (sheet.role === "primary") return null; // Primary is the directory baseline, not an agent telemetry sheet
            const fn = sheet.filename.toLowerCase();
            const words = fn.split(/[^a-z0-9]+/);

            // Check filename matches first
            if (fn.includes("sentinel") || fn.includes("sentiel") || fn.includes("s1") || fn.includes("edr") || fn.includes("antivirus")) {
                return "sentinelone";
            }
            if (fn.includes("bitlocker") || fn.includes("bit locker") || fn.includes("bit_locker") || fn.includes("bit-locker") || fn.includes("encryption") || fn.includes("disk")) {
                return "bitlocker";
            }
            if (fn.includes("zscaler") || fn.includes("zscalar") || fn.includes("zscalr") || fn.includes("z-scaler") || fn.includes("z-scalar") || fn.includes("z-scalr") || fn.includes("z_scaler") || fn.includes("z_scalr") || fn.includes("z scaler") || fn.includes("z scalr") || fn.includes("vpn")) {
                return "zscaler";
            }
            if (fn.includes("nessus") || fn.includes("tenable") || fn.includes("vulnerability") || fn.includes("scanner")) {
                return "nessus";
            }
            if (fn.includes("sccm") || fn.includes("mecm") || fn.includes("patch") || fn.includes("management")) {
                return "sccm";
            }

            // "ad" is too short for simple includes, use word list
            if (words.includes("ad") || words.includes("adcomputers") || fn.includes("adcomputers") || fn.includes("ad_computers") || fn.includes("ad-computers") || fn.includes("active directory") || fn.includes("active_directory") || fn.includes("enrollment")) {
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

        // Placeholder — the uploaded software list is stable per session;
        // this is called to pair with cache invalidation patterns in the filter pipeline.
        function invalidateUploadedSoftwareCache() {
            // Invalidate policyStats cache too since uploaded state may affect results
            invalidatePolicyStatsCache();
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

            // 1. Explicit compliant phrases check (overriding general negations)
            const compliantPhrases = [
                "no vulnerabilities", "no vulnerability", "no virus", "no threats", "no threat",
                "not isolated", "tunnel active", "tunnel_active", "service running", "service_running",
                "active enrollment", "active_enrollment", "up to date", "up-to-date",
                "domain joined", "domain_joined", "domain-joined", "machine joined", "machine_joined",
                "trusted network", "trusted_network", "trusted-network"
            ];
            for (let phrase of compliantPhrases) {
                if (val.includes(phrase)) {
                    return { installed: "INSTALLED", status: "COMPLIANT" };
                }
            }

            // 2. Tokenize by splitting on non-alphanumeric characters to match whole words
            const words = val.split(/[^a-z0-9]+/);

            // 3. Check for non-compliant/negation words first
            const nonCompliantWords = [
                "non", "not", "un", "off", "fail", "failed", "inactive", "disconnected",
                "disabled", "outdated", "vulnerable", "error", "critical", "missing",
                "unreported", "offline", "no", "none"
            ];
            for (let w of words) {
                if (nonCompliantWords.includes(w)) {
                    return { installed: rawVal.trim() || "MISSING", status: "NON_COMPLIANT" };
                }
            }

            // 4. Check for compliant words
            const compliantWords = [
                "compliant", "installed", "yes", "true", "active", "enrolled", "success",
                "ok", "pass", "passed", "on", "enabled", "running", "secured", "secure",
                "monitored", "encrypted", "encryption", "protected", "connected", "online",
                "registered", "joined", "trusted", "established", "scanned", "clean", "safe",
                "completed", "healthy", "patched", "updated", "current", "latest", "aes", "xts"
            ];
            for (let w of words) {
                if (compliantWords.includes(w)) {
                    return { installed: "INSTALLED", status: "COMPLIANT" };
                }
            }

            // 5. Fallback exact matches
            const compliantKeywordsFallback = [
                "compliant", "installed", "yes", "true", "1", "active",
                "enrolled", "active_enrollment", "active enrollment", "success", "ok",
                "pass", "passed", "on", "enabled", "running", "secured", "secure",
                "monitored", "up-to-date", "up to date", "encrypted", "encryption", "protected",
                "connected", "online", "tunnel active", "tunnel_active", "service running", "service_running",
                "registered"
            ];
            if (compliantKeywordsFallback.includes(val)) {
                return { installed: "INSTALLED", status: "COMPLIANT" };
            }

            const nonCompliantKeywordsFallback = [
                "non-compliant", "non_compliant", "non compliant", "failed", "fail",
                "missing", "no", "false", "0", "inactive", "disabled",
                "critical", "error", "offline", "not enrolled", "not_enrolled",
                "unenrolled", "out of date", "out_of_date", "outdated", "vulnerable"
            ];
            if (nonCompliantKeywordsFallback.includes(val)) {
                return { installed: rawVal.trim() || "MISSING", status: "NON_COMPLIANT" };
            }

            return { installed: rawVal.trim() || "MISSING", status: "NON_COMPLIANT" };
        }

        function getMergedAgentStatus(item, swKey) {
            const agentKeywords = {
                ad: ["active directory", "ad", "active_directory", "domain", "canonicalname", "canonical name", "distinguishedname", "distinguished name"],
                bitlocker: ["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"],
                zscaler: ["zscaler", "zscalar", "zscalr", "z-scaler", "z-scalar", "z-scalr", "zscaler client connector", "zscalar client connector", "zscalr client connector", "vpn", "vpn state", "vpn_state", "vpn status", "device state", "device_state", "status", "state"],
                nessus: ["nessus", "tenable", "vulnerability agent", "nessus agent", "scanner"],
                sentinelone: ["sentinelone", "sentinel one", "s1", "endpoint agent", "edr", "antivirus", "status", "state", "installed", "compliance", "agent status", "agent_status"],
                sccm: ["sccm", "sccm agent", "mecm", "management agent", "patch agent"]
            };

            const keywords = agentKeywords[swKey] || [];

            if (item.mergedProperties) {
                // Sort properties to prioritize version/connector/client columns over status/state columns
                const sortedProps = [...item.mergedProperties].sort((a, b) => {
                    const aIsSec = a.sheetRole === "Secondary" ? 1 : 0;
                    const bIsSec = b.sheetRole === "Secondary" ? 1 : 0;
                    if (aIsSec !== bIsSec) return bIsSec - aIsSec;

                    const aProp = a.property.toLowerCase();
                    const bProp = b.property.toLowerCase();
                    const aIsVer = (aProp.includes("version") || aProp.includes("connector") || aProp.includes("client")) ? 1 : 0;
                    const bIsVer = (bProp.includes("version") || bProp.includes("connector") || bProp.includes("client")) ? 1 : 0;
                    return bIsVer - aIsVer;
                });

                for (let p of sortedProps) {
                    if (p.sheetRole === "Primary") continue;
                    const propSwKey = getSheetSoftwareKey({ filename: p.source });
                    if (propSwKey && propSwKey !== swKey) {
                        continue;
                    }
                    const propName = p.property.toLowerCase().trim();

                    // Decouple SentinelOne/others from AD enrollment
                    if (swKey !== "ad") {
                        const words = propName.split(/[^a-z0-9]+/);
                        if (words.includes("ad") || words.includes("adcomputers") || propName.includes("active directory") || propName.includes("active_directory") || propName.includes("enrollment")) {
                            continue;
                        }
                    }
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
            if (text.startsWith("\uFEFF")) {
                text = text.substring(1);
            }
            const rawLines = text.split(/\r?\n/);
            const lines = [];

            let sep = ",";
            const firstLine = rawLines[0] || "";
            let commaCount = (firstLine.match(/,/g) || []).length;
            let semiCount = (firstLine.match(/;/g) || []).length;
            let tabCount = (firstLine.match(/\t/g) || []).length;

            if (semiCount > commaCount && semiCount > tabCount) sep = ";";
            else if (tabCount > commaCount && tabCount > semiCount) sep = "\t";

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
                logToTerminal(`[Reconciler] Upload request received for source file: "${file.name}"`);

                const isExcel = file.name.toLowerCase().endsWith(".xlsx") || file.name.toLowerCase().endsWith(".xls");

                if (usePython) {
                    const reader = new FileReader();
                    reader.onload = function (e) {
                        try {
                            const dataUrl = e.target.result;
                            const base64 = dataUrl.substring(dataUrl.indexOf(",") + 1);

                            logToTerminal(`[Reconciler] Uploading "${file.name}" to Python backend for validation...`, "info");

                            fetch('/api/validate-sheet', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ filename: file.name, content: base64 })
                            })
                                .then(res => res.json())
                                .then(data => {
                                    if (data.success) {
                                        logToTerminal(`[Reconciler] Python validation completed for "${file.name}"`, "info");
                                        if (data.validation_report && data.validation_report.warnings.length > 0) {
                                            data.validation_report.warnings.forEach(warn => {
                                                logToTerminal(`[Reconciler Validation Warning] ${warn}`, "warn");
                                            });
                                        }
                                        if (data.validation_report && data.validation_report.errors.length > 0) {
                                            data.validation_report.errors.forEach(err => {
                                                logToTerminal(`[Reconciler Validation Error] ${err}`, "error");
                                            });
                                        }

                                        const headers = data.headers;
                                        let keyIdx = autoDetectKeyIdx(headers, data.rows);

                                        const role = reconcilerSheets.length === 0 ? "primary" : "secondary";
                                        const sheetObj = {
                                            id: `sheet-${Math.random().toString(36).substring(2, 8)}`,
                                            filename: data.filename,
                                            rows: data.rows.slice(1),
                                            headers: data.headers,
                                            keyIdx: keyIdx,
                                            role: role
                                        };
                                        reconcilerSheets.push(sheetObj);
                                        logToTerminal(`[Reconciler] Loaded ${data.rows.length - 1} rows from "${file.name}". Auto-detected match key: "${headers[keyIdx]}"`, "info");
                                        renderReconcilerQueue();
                                    } else {
                                        logToTerminal(`[Reconciler] Python validation failed for "${file.name}": ${data.message}`, "error");
                                        alert(`❌ Python Validation Failed: ${data.message}`);
                                    }
                                })
                                .catch(err => {
                                    logToTerminal(`[Reconciler] Python backend connection error: ${err.message}. Falling back to client-side parsing.`, "warn");
                                    runFallbackReconcilerParse(file, isExcel);
                                });
                        } catch (err) {
                            logToTerminal(`[Reconciler] Error preparing backend upload: ${err.message}. Falling back to client-side parsing.`, "warn");
                            runFallbackReconcilerParse(file, isExcel);
                        }
                    };
                    reader.readAsDataURL(file);
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
                            logToTerminal(`[Reconciler] Native CSV parser successfully processed "${file.name}"`, "info");
                        } catch (csvErr) {
                            logToTerminal(`[Reconciler] Native CSV parser failed for "${file.name}": ${csvErr.message}. Trying SheetJS...`, "warn");
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
                            logToTerminal(`[Reconciler] Ingestion failed for "${file.name}": ${cdnError}`, "error");
                            alert(`❌ Excel Ingestion Failed:\n\n${cdnError}`);
                            return;
                        }

                        const bytes = new Uint8Array(data);
                        let workbook = XLSX.read(bytes, { type: "array" });
                        const sheetName = workbook.SheetNames[0];
                        const worksheet = workbook.Sheets[sheetName];
                        rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: "" });
                    }

                    if (!rows || rows.length < 2) {
                        logToTerminal(`[Reconciler] Failed: "${file.name}" contains insufficient rows.`, "error");
                        alert(`❌ Ingestion Failed: "${file.name}" has no data or has too few rows.`);
                        return;
                    }

                    const headers = rows[0].map(h => String(h).trim());
                    let keyIdx = autoDetectKeyIdx(headers, rows);

                    const role = reconcilerSheets.length === 0 ? "primary" : "secondary";

                    const sheetObj = {
                        id: `sheet-${Math.random().toString(36).substring(2, 8)}`,
                        filename: file.name,
                        rows: rows.slice(1),
                        headers: headers,
                        keyIdx: keyIdx,
                        role: role
                    };

                    reconcilerSheets.push(sheetObj);
                    logToTerminal(`[Reconciler] Loaded ${rows.length - 1} rows from "${file.name}". Auto-detected match key: "${headers[keyIdx]}"`, "info");
                    renderReconcilerQueue();

                } catch (err) {
                    logToTerminal(`[Reconciler] Ingestion failed for "${file.name}": ${err.message}`, "error");
                    alert(`❌ File Import Error: ${err.message}`);
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

                let roleSelectHtml = `
                    <select style="border: 1px solid var(--border-clean); padding: 0.35rem 0.5rem; font-size: 0.75rem; background: var(--bg-card); color: var(--text-primary); border-radius: 4px; width: 100%; cursor: pointer;" onchange="updateSheetRole('${sheet.id}', this.value)">
                        <option value="primary" ${sheet.role === 'primary' ? 'selected' : ''}>Corporate Directory (Primary)</option>
                        <option value="secondary" ${sheet.role === 'secondary' ? 'selected' : ''}>Agent Telemetry (Secondary)</option>
                    </select>
                `;

                let keySelectHtml = `<select style="border: 1px solid var(--border-clean); padding: 0.35rem 0.5rem; font-size: 0.75rem; background: var(--bg-card); color: var(--text-primary); border-radius: 4px; width: 100%; cursor: pointer;" onchange="updateSheetKey('${sheet.id}', this.value)">`;
                sheet.headers.forEach((h, idx) => {
                    const selected = idx === sheet.keyIdx ? "selected" : "";
                    keySelectHtml += `<option value="${idx}" ${selected}>${escapeHTML(h)} (Col ${idx + 1})</option>`;
                });
                keySelectHtml += `</select>`;

                const allColsHtml = sheet.headers.map((c, idx) => {
                    const isKey = idx === sheet.keyIdx;
                    const badgeClass = isKey ? "badge" : "badge group-sift";
                    const style = isKey ? "font-size:0.65rem; margin-right:0.25rem; display:inline-block; margin-bottom:0.15rem; background:var(--color-accent);" : "font-size:0.65rem; margin-right:0.25rem; display:inline-block; margin-bottom:0.15rem;";
                    return `<span class="${badgeClass}" style="${style}">${escapeHTML(c)}</span>`;
                }).join("");

                tr.innerHTML = `
                    <td><strong style="color:var(--color-accent);">${sheet.filename}</strong></td>
                    <td style="font-family:var(--font-mono); font-weight:700;">${sheet.rows.length.toLocaleString()}</td>
                    <td>${roleSelectHtml}</td>
                    <td>${keySelectHtml}</td>
                    <td style="max-width:320px; word-break:break-word;">${allColsHtml}</td>
                    <td style="text-align:right;">
                        <button class="btn" style="background:rgba(220,53,69,0.15); border:1px solid rgba(220,53,69,0.4); color:#ff6b6b; font-size:0.7rem; padding:0.3rem 0.6rem; cursor:pointer;" onclick="deleteSheetFromQueue('${sheet.id}')">Delete</button>
                    </td>
                `;
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
            logToTerminal(`[Reconciler] Role for "${sheet.filename}" updated to ${role.toUpperCase()}`);
            renderReconcilerQueue();
        }

        function updateSheetKey(id, val) {
            const sheet = reconcilerSheets.find(s => s.id === id);
            if (!sheet) return;
            sheet.keyIdx = parseInt(val);
            logToTerminal(`[Reconciler] Match key for "${sheet.filename}" changed to "${sheet.headers[sheet.keyIdx]}"`);
            renderReconcilerQueue();
        }

        function deleteSheetFromQueue(id) {
            const sheet = reconcilerSheets.find(s => s.id === id);
            if (!sheet) return;
            reconcilerSheets = reconcilerSheets.filter(s => s.id !== id);
            logToTerminal(`[Reconciler] File "${sheet.filename}" removed from queue.`);

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
                showLoading("Reconciling assets via backend...");
                logToTerminal(`[Reconciler] Offloading deep asset reconciliation alignment to Python backend...`);
                fetch('/api/reconcile-sheets', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sheets: reconcilerSheets })
                })
                    .then(res => res.json())
                    .then(data => {
                        hideLoading();
                        if (data.success) {
                            reconciliationResults = data.results;
                            logToTerminal(`[Reconciler] Python alignment complete. Matches: ${reconciliationResults.matches.length}, Gaps: ${reconciliationResults.gaps.length}, Rogues: ${reconciliationResults.rogues.length}`, "info");
                            renderReconciliationUI();
                        } else {
                            logToTerminal(`[Reconciler] Python Reconciliation failed: ${data.message}`, "error");
                            alert(`❌ Reconciliation Failed: ${data.message}`);
                        }
                    })
                    .catch(err => {
                        hideLoading();
                        logToTerminal(`[Reconciler] Python backend connection error: ${err.message}. Falling back to local alignment.`, "warn");
                        runProcess(() => {
                            runLocalReconciliation();
                        }, "Reconciling assets locally...");
                    });
            } else {
                runProcess(() => {
                    runLocalReconciliation();
                }, "Reconciling assets locally...");
            }
        }

        function getColIndices(headers, filename) {
            const hLow = headers.map(h => String(h).toLowerCase().trim());
            const nameKeywords = ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system"];

            let isZscaler = false;
            if (filename) {
                const fnLow = String(filename).toLowerCase();
                if (fnLow.includes("zscaler") || fnLow.includes("zscalar") || fnLow.includes("zscalr") || fnLow.includes("vpn")) {
                    isZscaler = true;
                }
            }

            const serialKeywords = isZscaler
                ? ["serialnumber", "serial", "s/n", "sn", "uuid", "udid", "externalid", "external device id", "service tag", "servicetag", "tag", "asset tag", "assettag"]
                : ["serialnumber", "serial", "s/n", "sn", "uuid", "externalid", "external device id", "service tag", "servicetag", "tag", "asset tag", "assettag"];
            const macKeywords = ["macaddress", "mac", "physical", "ethernet", "hardware"];

            function findIndices(keywords) {
                const idxs = [];
                for (let idx = 0; idx < hLow.length; idx++) {
                    const h = hLow[idx];
                    const matched = keywords.some(kw => {
                        if (kw.length <= 3) {
                            const words = h.split(/[^a-z0-9]+/);
                            return words.includes(kw);
                        } else {
                            return h.includes(kw);
                        }
                    });
                    if (matched) {
                        idxs.push(idx);
                    }
                }
                return idxs;
            }
            return {
                nameIndices: findIndices(nameKeywords),
                serialIndices: findIndices(serialKeywords),
                macIndices: findIndices(macKeywords)
            };
        }

        function normMacList(val) {
            if (!val) return [];
            const macs = String(val).match(/[0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}[:.-][0-9a-fA-F]{2}/g);
            if (!macs) return [];
            return macs.map(m => m.toLowerCase().replace(/./g, ':').replace(/-/g, ':'));
        }

        function normalizeValue(val) {
            if (val === undefined || val === null) return "";
            const s = String(val).trim();
            const low = s.toLowerCase();
            if (["disabled", "unknown", "none", "not available", "to be filled by o.e.m.", "-"].includes(low)) {
                return "";
            }
            return s.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
        }

        function rowMatches(primRow, primMeta, secRow, secMeta) {
            const primKeyVal = normalizeValue(primRow[primMeta.key_idx]);
            const secKeyVal = normalizeValue(secRow[secMeta.key_idx]);
            if (primKeyVal && primKeyVal === secKeyVal) {
                return true;
            }

            if (primMeta.name_indices && secMeta.name_indices) {
                for (let pIdx of primMeta.name_indices) {
                    for (let sIdx of secMeta.name_indices) {
                        if (pIdx < primRow.length && sIdx < secRow.length) {
                            const pName = normalizeValue(primRow[pIdx]);
                            const sName = normalizeValue(secRow[sIdx]);
                            if (pName && pName === sName) return true;
                        }
                    }
                }
            }

            if (primMeta.serial_indices && secMeta.serial_indices) {
                for (let pIdx of primMeta.serial_indices) {
                    for (let sIdx of secMeta.serial_indices) {
                        if (pIdx < primRow.length && sIdx < secRow.length) {
                            const pSerial = normalizeValue(primRow[pIdx]);
                            const sSerial = normalizeValue(secRow[sIdx]);
                            if (pSerial && pSerial === sSerial) return true;
                        }
                    }
                }
            }

            if (primMeta.mac_indices && secMeta.mac_indices) {
                for (let pIdx of primMeta.mac_indices) {
                    for (let sIdx of secMeta.mac_indices) {
                        if (pIdx < primRow.length && sIdx < secRow.length) {
                            const pMacVal = primRow[pIdx];
                            const sMacVal = secRow[sIdx];
                            const pMacs = normMacList(pMacVal);
                            const sMacs = normMacList(sMacVal);
                            if (pMacs.length > 0 && sMacs.length > 0) {
                                for (let pm of pMacs) {
                                    if (sMacs.includes(pm)) return true;
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        function runLocalReconciliation() {
            logToTerminal(`[Reconciler] Executing local asset alignment...\n`);
            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            const secondarySheets = reconcilerSheets.filter(s => s.role === "secondary");

            if (!primarySheet || secondarySheets.length === 0) return;

            const primaryHeaders = primarySheet.headers;
            const primaryKeyIdx = primarySheet.keyIdx;

            const primIndices = getColIndices(primaryHeaders, primarySheet.filename);
            const primMeta = {
                key_idx: primaryKeyIdx,
                name_indices: primIndices.nameIndices,
                serial_indices: primIndices.serialIndices,
                mac_indices: primIndices.macIndices
            };

            const secSheetsProcessed = secondarySheets.map(sheet => {
                const secIndices = getColIndices(sheet.headers, sheet.filename);
                const validRows = sheet.rows.filter(r => r && !r.every(cell => String(cell).trim() === ""));

                // Pre-build index maps for fast O(1) lookups
                const keyMap = new Map();
                const nameMap = new Map();
                const serialMap = new Map();
                const macMap = new Map();

                validRows.forEach((sRow, rIdx) => {
                    // 1. Key Value
                    const secKeyVal = normalizeValue(sRow[sheet.keyIdx]);
                    if (secKeyVal) {
                        if (!keyMap.has(secKeyVal)) keyMap.set(secKeyVal, []);
                        keyMap.get(secKeyVal).push(rIdx);
                    }

                    // 2. Name values
                    if (secIndices.nameIndices) {
                        secIndices.nameIndices.forEach(sIdx => {
                            if (sIdx < sRow.length) {
                                const sName = normalizeValue(sRow[sIdx]);
                                if (sName) {
                                    if (!nameMap.has(sName)) nameMap.set(sName, []);
                                    nameMap.get(sName).push(rIdx);
                                }
                            }
                        });
                    }

                    // 3. Serial values
                    if (secIndices.serialIndices) {
                        secIndices.serialIndices.forEach(sIdx => {
                            if (sIdx < sRow.length) {
                                const sSerial = normalizeValue(sRow[sIdx]);
                                if (sSerial) {
                                    if (!serialMap.has(sSerial)) serialMap.set(sSerial, []);
                                    serialMap.get(sSerial).push(rIdx);
                                }
                            }
                        });
                    }

                    // 4. MAC values
                    if (secIndices.macIndices) {
                        secIndices.macIndices.forEach(sIdx => {
                            if (sIdx < sRow.length) {
                                const sMacVal = sRow[sIdx];
                                const sMacs = normMacList(sMacVal);
                                sMacs.forEach(sm => {
                                    if (sm) {
                                        if (!macMap.has(sm)) macMap.set(sm, []);
                                        macMap.get(sm).push(rIdx);
                                    }
                                });
                            }
                        });
                    }
                });

                return {
                    filename: sheet.filename,
                    headers: sheet.headers,
                    rows: validRows,
                    meta: {
                        key_idx: sheet.keyIdx,
                        name_indices: secIndices.nameIndices,
                        serial_indices: secIndices.serialIndices,
                        mac_indices: secIndices.macIndices
                    },
                    keyMap,
                    nameMap,
                    serialMap,
                    macMap,
                    matchedIndices: new Set()
                };
            });

            const matches = [];
            const gaps = [];

            primarySheet.rows.forEach((pRow, pRowIdx) => {
                if (!pRow || pRow.every(cell => String(cell).trim() === "")) return;

                const rawName = String(pRow[primaryKeyIdx] || "").trim() || `Device-${pRowIdx + 1}`;
                const presentInSheets = [];
                const missingInSheets = [];
                const mergedProperties = [];

                primaryHeaders.forEach((h, idx) => {
                    if (idx !== primaryKeyIdx) {
                        const val = String(pRow[idx] || "").trim();
                        mergedProperties.push({
                            source: primarySheet.filename,
                            sheetRole: "Primary",
                            property: h,
                            value: val ? val : "-"
                        });
                    }
                });

                secSheetsProcessed.forEach(sec => {
                    let matchedRow = null;
                    let matchedRIdx = -1;

                    // Try to find match via O(1) lookups

                    // 1. Check key match
                    const primKeyVal = normalizeValue(pRow[primaryKeyIdx]);
                    if (primKeyVal && sec.keyMap.has(primKeyVal)) {
                        const candidates = sec.keyMap.get(primKeyVal);
                        if (candidates.length > 0) {
                            matchedRIdx = candidates[0];
                        }
                    }

                    // 2. Check name match
                    if (matchedRIdx === -1 && primMeta.name_indices) {
                        for (let pIdx of primMeta.name_indices) {
                            if (pIdx < pRow.length) {
                                const pName = normalizeValue(pRow[pIdx]);
                                if (pName && sec.nameMap.has(pName)) {
                                    const candidates = sec.nameMap.get(pName);
                                    if (candidates.length > 0) {
                                        matchedRIdx = candidates[0];
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // 3. Check serial match
                    if (matchedRIdx === -1 && primMeta.serial_indices) {
                        for (let pIdx of primMeta.serial_indices) {
                            if (pIdx < pRow.length) {
                                const pSerial = normalizeValue(pRow[pIdx]);
                                if (pSerial && sec.serialMap.has(pSerial)) {
                                    const candidates = sec.serialMap.get(pSerial);
                                    if (candidates.length > 0) {
                                        matchedRIdx = candidates[0];
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // 4. Check MAC match
                    if (matchedRIdx === -1 && primMeta.mac_indices) {
                        for (let pIdx of primMeta.mac_indices) {
                            if (pIdx < pRow.length) {
                                const pMacVal = pRow[pIdx];
                                const pMacs = normMacList(pMacVal);
                                for (let pm of pMacs) {
                                    if (pm && sec.macMap.has(pm)) {
                                        const candidates = sec.macMap.get(pm);
                                        if (candidates.length > 0) {
                                            matchedRIdx = candidates[0];
                                            break;
                                        }
                                    }
                                }
                            }
                            if (matchedRIdx !== -1) break;
                        }
                    }

                    if (matchedRIdx !== -1) {
                        matchedRow = sec.rows[matchedRIdx];
                        sec.matchedIndices.add(matchedRIdx);
                    }

                    if (matchedRow) {
                        presentInSheets.push(sec.filename);
                        sec.headers.forEach((h, idx) => {
                            if (idx !== sec.meta.key_idx) {
                                const val = String(matchedRow[idx] || "").trim();
                                mergedProperties.push({
                                    source: sec.filename,
                                    sheetRole: "Secondary",
                                    property: h,
                                    value: val ? val : "-"
                                });
                            }
                        });
                    } else {
                        missingInSheets.push(sec.filename);
                    }
                });

                const randomSuffix = Math.random().toString(36).substring(2, 6);

                if (missingInSheets.length > 0) {
                    gaps.push({
                        id: `dev-gap-${randomSuffix}`,
                        name: rawName,
                        normalized: normalizeValue(rawName),
                        primaryRow: pRow,
                        missingInSheets: missingInSheets,
                        presentInSheets: presentInSheets,
                        mergedProperties: mergedProperties,
                        status: "COVERAGE_GAP"
                    });
                } else {
                    matches.push({
                        id: `dev-rec-${randomSuffix}`,
                        name: rawName,
                        normalized: normalizeValue(rawName),
                        primaryRow: pRow,
                        mergedProperties: mergedProperties,
                        status: "MATCHED"
                    });
                }
            });

            // Rogues
            const roguesMap = {};
            secSheetsProcessed.forEach(sec => {
                sec.rows.forEach((sRow, rIdx) => {
                    if (!sec.matchedIndices.has(rIdx)) {
                        const val = String(sRow[sec.meta.key_idx] || "").trim();
                        if (!val) return;
                        const normName = normalizeValue(val);
                        if (!normName) return;
                        if (!roguesMap[normName]) {
                            roguesMap[normName] = {
                                name: val,
                                sheets: []
                            };
                        }
                        roguesMap[normName].sheets.push({
                            filename: sec.filename,
                            row: sRow,
                            headers: sec.headers,
                            keyIdx: sec.meta.key_idx
                        });
                    }
                });
            });

            const rogues = [];
            for (let normName in roguesMap) {
                const randomSuffix = Math.random().toString(36).substring(2, 6);
                rogues.push({
                    id: `dev-rogue-${randomSuffix}`,
                    name: roguesMap[normName].name,
                    normalized: normName,
                    sheets: roguesMap[normName].sheets,
                    status: "ROGUE_UNMANAGED"
                });
            }

            reconciliationResults = { matches: matches, gaps: gaps, rogues: rogues };
            logToTerminal(`[Reconciler] Local alignment complete. Matches: ${matches.length}, Gaps: ${gaps.length}, Rogues: ${rogues.length}`, "info");
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
                subtext.innerHTML = `<strong style="color:var(--status-low);">${matches.length} Matches Aligned</strong>`;
            }

            document.getElementById("recon-stat-gaps").innerText = gaps.length.toLocaleString();
            document.getElementById("recon-stat-rogues").innerText = rogues.length.toLocaleString();

            const matchRateEl = document.getElementById("recon-stat-match-rate");
            matchRateEl.innerText = `${matchRate.toFixed(1)}%`;
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
                logToTerminal(`[Audit Reconciler] Verification: Matches=${matches.length} (Fleet: ${matchesInFleet}), Gaps=${gaps.length} (Fleet: ${gapsInFleet}), Rogues=${rogues.length} (Fleet: ${roguesInFleet}).`, "info");
                if (matches.length === matchesInFleet && gaps.length === gapsInFleet && rogues.length === roguesInFleet) {
                    logToTerminal(`[Audit Reconciler] Verification SUCCESS: Active Reconciled Fleet dataset is in 100% perfect sync with reconciliation metrics.`, "info");
                } else {
                    logToTerminal(`[Audit Reconciler] Verification Warning: Active fleet counts have deviated from reconciliation results (possibly due to manual overrides).`, "warn");
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
            document.getElementById(`btn-recon-tab-${tabId}`).classList.add("active");

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
                head.innerHTML = `<tr>${headersToRender.map(h => `<th>${escapeHTML(h)}</th>`).join("")}</tr>`;

                if (rowsToRender.length === 0) {
                    body.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--status-low); font-style: italic; padding: 2rem; font-weight: 700;">🎉 Stellar Alignment! Zero gaps detected.</td></tr>`;
                } else {
                    rowsToRender.forEach(item => {
                        const tr = document.createElement("tr");
                        const missingBadges = item.missingInSheets.map(s => `<span class="badge risk-critical" style="font-size:0.65rem; padding: 0.15rem 0.4rem; display: inline-block; margin: 0.1rem 0.2rem 0.1rem 0;">Missing in: ${escapeHTML(s)}</span>`).join("");
                        const primaryDetails = primaryHeaders.map((h, idx) => `<strong>${escapeHTML(h)}:</strong> ${escapeHTML(item.primaryRow[idx] || "-")}`).join(" | ");

                        tr.innerHTML = `
                            <td style="font-family: var(--font-mono); color: var(--text-secondary); vertical-align: middle;">${escapeHTML(item.id)}</td>
                            <td style="vertical-align: middle;"><strong style="color: var(--status-critical);">${item.name.toUpperCase()}</strong></td>
                            <td style="vertical-align: middle;">${missingBadges}</td>
                            <td style="vertical-align: middle; font-size: 0.78rem; color: var(--text-secondary);">${primaryDetails}</td>
                        `;
                        body.appendChild(tr);
                    });
                }
            } else if (tabId === "rogues") {
                const headersToRender = ["Device ID", "Hostname", "Detected Telemetry Sources", "Agent Properties Details"];
                head.innerHTML = `<tr>${headersToRender.map(h => `<th>${escapeHTML(h)}</th>`).join("")}</tr>`;

                if (rowsToRender.length === 0) {
                    body.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); font-style: italic; padding: 2rem;">No unmanaged rogue assets identified.</td></tr>`;
                } else {
                    rowsToRender.forEach(item => {
                        const tr = document.createElement("tr");
                        const detectedBadges = item.sheets.map(s => `<span class="badge risk-medium" style="font-size:0.65rem; padding: 0.15rem 0.4rem; display: inline-block; margin: 0.1rem 0.2rem 0.1rem 0;">Source: ${escapeHTML(s.filename)}</span>`).join("");

                        const detailsHtml = item.sheets.map(s => {
                            const details = s.headers.slice(0, 4).map((h, idx) => `<strong>${escapeHTML(h)}:</strong> ${escapeHTML(s.row[idx] || "-")}`).join(" | ");
                            return `<div style="margin-bottom: 0.25rem; font-size: 0.72rem; color: var(--text-secondary);"><strong style="color:var(--text-primary);">${escapeHTML(s.filename)}:</strong> ${details}</div>`;
                        }).join("");

                        tr.innerHTML = `
                            <td style="font-family: var(--font-mono); color: var(--text-secondary); vertical-align: middle;">${escapeHTML(item.id)}</td>
                            <td style="vertical-align: middle;"><strong style="color: var(--status-medium);">${item.name.toUpperCase()}</strong> <span class="badge risk-medium" style="font-size:0.6rem; padding: 0.1rem 0.25rem; margin-left: 0.5rem;">UNMANAGED</span></td>
                            <td style="vertical-align: middle;">${detectedBadges}</td>
                            <td style="vertical-align: middle;">${detailsHtml}</td>
                        `;
                        body.appendChild(tr);
                    });
                }
            } else if (tabId === "matches") {
                const headersToRender = ["Device ID", "Hostname", "Alignment", "Merged Excel Sheet Information / Row Details"];
                head.innerHTML = `<tr>${headersToRender.map(h => `<th>${escapeHTML(h)}</th>`).join("")}</tr>`;

                if (rowsToRender.length === 0) {
                    body.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); font-style: italic; padding: 2rem;">No matching assets resolved between directories.</td></tr>`;
                } else {
                    rowsToRender.forEach(item => {
                        const tr = document.createElement("tr");

                        const propertiesHtml = item.mergedProperties.map(p => {
                            const sourceLabel = p.source.length > 20 ? p.source.substring(0, 17) + "..." : p.source;
                            return `
                                <div style="display:inline-block; background:rgba(255,255,255,0.02); border:1px solid var(--border-clean); padding: 0.35rem 0.6rem; border-radius: 4px; font-size: 0.72rem; margin: 0.2rem 0.3rem 0.2rem 0; line-height:1.2;">
                                    <span style="font-size:0.6rem; color:var(--color-accent); font-weight:700; text-transform:uppercase; display:block;">${sourceLabel}</span>
                                    <strong style="color:var(--text-secondary);">${escapeHTML(p.property)}:</strong> 
                                    <span style="color:var(--text-primary); font-weight:700;">${escapeHTML(p.value)}</span>
                                </div>
                            `;
                        }).join("");

                        tr.innerHTML = `
                            <td style="font-family: var(--font-mono); color: var(--text-secondary); vertical-align: middle;">${escapeHTML(item.id)}</td>
                            <td style="vertical-align: middle;"><strong style="color: var(--status-low);">${item.name.toUpperCase()}</strong> <span class="badge risk-low" style="font-size:0.6rem; padding: 0.1rem 0.25rem; margin-left: 0.5rem;">MATCHED</span></td>
                            <td style="vertical-align: middle; color: var(--status-low); font-weight:700;">🟢 Aligned</td>
                            <td style="vertical-align: middle; padding: 0.75rem 0;">
                                <div style="display: flex; flex-wrap: wrap; max-width: 750px;">
                                    ${propertiesHtml}
                                </div>
                            </td>
                        `;
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
            const serialKeywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "service tag", "servicetag", "tag", "asset tag", "assettag"];
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
            const serialKeywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "service tag", "servicetag", "tag", "asset tag", "assettag"];
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
            if (!serialVal) serialVal = `SN-RECON-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
            if (!macVal) macVal = `00:1A:2B:3C:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}`;

            return { nameVal, serialVal, macVal };
        }

        function extractConditionFromItem(item) {
            const condKeywords = ["condition", "status", "state"];

            function normaliseCondition(raw) {
                const normCond = String(raw).trim().toUpperCase().replace(/[\s-]+/g, "_").replace(/[^A-Z0-9_]/g, "");
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
                            newCustomProps[`[${s.filename}] ${h}`] = String(s.row[idx] || "");
                        }
                    });
                });

                const ids = extractDeviceIdentifiers(rogue);
                fleetDataset.push({
                    id: `dev-${Math.random().toString(36).substring(2, 8)}`,
                    canonical_name: rogue.normalized || ids.nameVal,
                    serial: ids.serialVal.startsWith("SN-ROGUE-") ? ids.serialVal : `SN-ROGUE-${ids.serialVal.replace(/^SN-/, "")}`,
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
            logToTerminal(`[EDR Containment] Dispatched zero-trust network containment isolation for rogue host ${rogue.name.toUpperCase()} (ID: ${rogue.id}).`, "error");
            alert(`Rogue asset ${rogue.name.toUpperCase()} isolated successfully! Firewall rules and network ports contained.`);

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
                        newCustomProps[`[${s.filename}] ${h}`] = String(s.row[idx] || "");
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
                    id: `dev-${Math.random().toString(36).substring(2, 8)}`,
                    canonical_name: rogue.normalized || ids.nameVal,
                    serial: ids.serialVal.startsWith("SN-REGISTERED-") ? ids.serialVal : `SN-REGISTERED-${ids.serialVal.replace(/^SN-/, "")}`,
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

            logToTerminal(`[Reconciler] Manually authorized and enrolled rogue asset ${rogue.name.toUpperCase()} into Corporate Directory context.`, "info");
            alert(`Rogue asset ${rogue.name.toUpperCase()} authorized and registered in Corporate Directory successfully!`);
        }

        function getHeaderClassification(header) {
            if (!header) return "unknown";
            const h = header.toLowerCase().trim();
            const nameKeywords = ["devicename", "hostname", "device", "host", "name", "computer", "machine", "system"];
            const serialKeywords = ["serialnumber", "serial", "s/n", "sn", "uuid", "udid", "externalid", "external device id", "service tag", "servicetag", "tag", "asset tag", "assettag"];
            const macKeywords = ["macaddress", "mac", "physical", "ethernet", "hardware"];

            if (nameKeywords.some(kw => kw.length <= 3 ? h.split(/[^a-z0-9]+/).includes(kw) : h.includes(kw))) {
                return "name";
            }
            if (serialKeywords.some(kw => kw.length <= 3 ? h.split(/[^a-z0-9]+/).includes(kw) : h.includes(kw))) {
                return "serial";
            }
            if (macKeywords.some(kw => kw.length <= 3 ? h.split(/[^a-z0-9]+/).includes(kw) : h.includes(kw))) {
                return "mac";
            }
            return "unknown";
        }

        function mergeReconciliationIntoFleet() {
            const gaps = reconciliationResults.gaps;
            const rogues = reconciliationResults.rogues;
            const matches = reconciliationResults.matches;

            if (gaps.length === 0 && rogues.length === 0 && matches.length === 0) {
                alert("No reconciled assets available to merge. Please execute reconciliation first.");
                return;
            }

            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            let differentKeyUsed = false;
            if (primarySheet) {
                const primaryKeyHeader = primarySheet.headers[primarySheet.keyIdx];
                const primaryKeyClass = getHeaderClassification(primaryKeyHeader);

                const secondarySheets = reconcilerSheets.filter(s => s.role === "secondary");
                for (const sec of secondarySheets) {
                    const secKeyHeader = sec.headers[sec.keyIdx];
                    const secKeyClass = getHeaderClassification(secKeyHeader);
                    if (secKeyClass !== "unknown" && primaryKeyClass !== "unknown" && secKeyClass !== primaryKeyClass) {
                        differentKeyUsed = true;
                        break;
                    }
                }
            }

            const confirmMerge = confirm(`⚡ Are you sure you want to merge these reconciled Excel records into the active database?\n\n- ${matches.length} Matched devices will have their custom Excel information merged.\n- ${gaps.length} Coverage Gaps will be marked in the database.\n- ${rogues.length} Rogue Assets will be appended to the active list.\n\nDashboard ledger updates instantly.`);
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
                    customProps[`[${p.source}] ${p.property}`] = p.value;
                });

                if (existing) {
                    existing.software.forEach(sw => {
                        const statusObj = getMergedAgentStatus(item, sw.key);
                        const isUploaded = isSheetUploadedForSoftware(sw.key);
                        const hasProp = item.mergedProperties && item.mergedProperties.some(p => {
                            if (p.sheetRole === "Primary") return false;
                            const propSwKey = getSheetSoftwareKey({ filename: p.source });
                            if (propSwKey && propSwKey !== sw.key) {
                                return false;
                            }
                            const propName = p.property.toLowerCase().trim();

                            // Decouple SentinelOne/others from AD enrollment
                            if (sw.key !== "ad") {
                                const words = propName.split(/[^a-z0-9]+/);
                                if (words.includes("ad") || words.includes("adcomputers") || propName.includes("active directory") || propName.includes("active_directory") || propName.includes("enrollment")) {
                                    return false;
                                }
                            }

                            const agentKeywords = {
                                ad: ["active directory", "ad", "active_directory", "domain", "enrollment"],
                                bitlocker: ["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"],
                                zscaler: ["zscaler", "zscalar", "zscalr", "z-scaler", "z-scalar", "z-scalr", "zscaler client connector", "zscalar client connector", "zscalr client connector", "vpn"],
                                nessus: ["nessus", "tenable", "vulnerability agent", "nessus agent", "scanner"],
                                sentinelone: ["sentinelone", "sentinel one", "s1", "endpoint agent", "edr", "antivirus", "status", "state", "installed", "compliance", "agent status", "agent_status"],
                                sccm: ["sccm", "sccm agent", "mecm", "management agent", "patch agent"]
                            };
                            const keywords = agentKeywords[sw.key] || [];
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
                        id: `dev-${Math.random().toString(36).substring(2, 8)}`,
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
                    customProps[`[${p.source}] ${p.property}`] = p.value;
                });

                if (existing) {
                    existing.score = 0.00;
                    existing.level = "NON_COMPLIANT";

                    existing.software.forEach(sw => {
                        const statusObj = getMergedAgentStatus(item, sw.key);
                        const isUploaded = isSheetUploadedForSoftware(sw.key);
                        const hasProp = item.mergedProperties && item.mergedProperties.some(p => {
                            const propSwKey = getSheetSoftwareKey({ filename: p.source });
                            if (propSwKey && propSwKey !== sw.key) {
                                return false;
                            }
                            const agentKeywords = {
                                ad: ["active directory", "ad", "active_directory", "domain", "enrollment"],
                                bitlocker: ["bitlocker", "bit locker", "encryption", "drive encryption", "drive_encryption", "disk encryption"],
                                zscaler: ["zscaler", "zscalar", "zscalr", "z-scaler", "z-scalar", "z-scalr", "zscaler client connector", "zscalar client connector", "zscalr client connector", "vpn"],
                                nessus: ["nessus", "tenable", "vulnerability agent", "nessus agent", "scanner"],
                                sentinelone: ["sentinelone", "sentinel one", "s1", "endpoint agent", "edr", "antivirus", "status", "state", "installed", "compliance", "agent status", "agent_status"],
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
                        id: `dev-${Math.random().toString(36).substring(2, 8)}`,
                        canonical_name: ids.nameVal,
                        serial: ids.serialVal.startsWith("SN-GAP-") ? ids.serialVal : `SN-GAP-${ids.serialVal.replace(/^SN-RECON-/, "").replace(/^SN-/, "")}`,
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
                            customProps[`[${s.filename}] ${h}`] = String(s.row[idx] || "");
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
                } else if (false) { // Skip creating new records for Rogues since they do not come from Corporate Directory (Primary)
                    const newCustomProps = {};
                    mergeDistinctProperties(newCustomProps, customProps);
                    const ids = extractDeviceIdentifiers(item);
                    fleetDataset.push({
                        id: `dev-${Math.random().toString(36).substring(2, 8)}`,
                        canonical_name: ids.nameVal,
                        serial: ids.serialVal.startsWith("SN-ROGUE-") ? ids.serialVal : `SN-ROGUE-${ids.serialVal.replace(/^SN-RECON-/, "").replace(/^SN-/, "")}`,
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
                const customKey = `custom:${k}`;
                if (!activeTableKeys.includes(customKey)) {
                    // Extract clean name and source file for header label
                    const cleanName = k.replace(/^[.*?]s*/, '');
                    const sourceName = k.match(/^[(.*?)]/) ? k.match(/^[(.*?)]/)[1] : 'Excel';
                    const headerLabel = `${cleanName} (${sourceName})`;

                    activeTableHeaders.push(headerLabel);
                    activeTableKeys.push(customKey);
                }
            });

            recalculateAllScores();
            renderReconciliationUI();
            switchNavSection("compliance");

            const successMsg = `Excel Reconciliation Merge Complete! Integrated custom sheet columns. Added ${newlyCreated} new records and updated ${mergedUpdated} existing records.`;
            logToTerminal(`[Reconciler] ${successMsg}`, "info");
            alert(successMsg);
        }

        function getColumnValue(item, columnName, sheetRole, filename) {
            if (columnName === 'Device ID') return item.id || '';
            if (columnName === 'Hostname') return item.name || '';
            if (columnName === 'Audit Status') return item.status || '';

            // Check primary/directory sheet if role matches
            if (sheetRole === 'primary') {
                const primarySheet = reconcilerSheets.find(s => s.role === 'primary');
                if (primarySheet && item.primaryRow) {
                    const idx = primarySheet.headers.indexOf(columnName);
                    if (idx !== -1) return item.primaryRow[idx] || '';
                }
                return '';
            }

            // Check mergedProperties first
            if (item.mergedProperties) {
                const prop = item.mergedProperties.find(p => p.property === columnName && p.source === filename);
                if (prop) return prop.value || '';
            }

            // For raw rogues, check their sheets array
            if (item.sheets) {
                const sheetRec = item.sheets.find(s => s.filename === filename);
                if (sheetRec) {
                    const idx = sheetRec.headers.indexOf(columnName);
                    if (idx !== -1) return sheetRec.row[idx] || '';
                }
            }

            return '';
        }

        function exportReconciliationReport() {
            logToTerminal("[Reconciler] Opening custom CSV column selector export config...");

            // Gather all unique headers grouped by sheet/file
            const primarySheet = reconcilerSheets.find(s => s.role === "primary");
            const secondarySheets = reconcilerSheets.filter(s => s.role === "secondary");

            if (!primarySheet && secondarySheets.length === 0) {
                alert("No sheets loaded for reconciliation. Please upload files first.");
                return;
            }

            // Create modal element
            const modal = document.createElement("div");
            modal.id = "export-column-selector-modal";
            modal.style = "position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 100000; font-family: var(--font-sans);";

            let primaryCheckboxes = '';
            if (primarySheet) {
                primaryCheckboxes = `
                    <div style="margin-bottom: 1.5rem;">
                        <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-primary); border-bottom: 1px solid var(--border-clean); padding-bottom: 0.25rem; margin-bottom: 0.75rem;">
                            Primary Directory (${primarySheet.filename})
                        </h4>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
                            ${primarySheet.headers.map(h => `
                                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: var(--text-secondary); cursor: pointer;">
                                    <input type="checkbox" class="export-col-checkbox" data-role="primary" data-filename="${primarySheet.filename}" data-header="${h}" checked>
                                    ${h}
                                </label>
                            `).join('')}
                        </div>
                    </div>
                `;
            }

            let secondaryCheckboxes = '';
            secondarySheets.forEach(sheet => {
                secondaryCheckboxes += `
                    <div style="margin-bottom: 1.5rem;">
                        <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-primary); border-bottom: 1px solid var(--border-clean); padding-bottom: 0.25rem; margin-bottom: 0.75rem;">
                            Secondary Telemetry (${sheet.filename})
                        </h4>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
                            ${sheet.headers.map(h => `
                                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: var(--text-secondary); cursor: pointer;">
                                    <input type="checkbox" class="export-col-checkbox" data-role="secondary" data-filename="${sheet.filename}" data-header="${h}" checked>
                                    ${h}
                                </label>
                            `).join('')}
                        </div>
                    </div>
                `;
            });

            modal.innerHTML = `
                <div class="card" style="width: 580px; max-height: 80vh; overflow-y: auto; background: var(--bg-card); border: 1px solid var(--border-clean); padding: 2rem; border-radius: 4px; box-shadow: 0 10px 25px rgba(0,0,0,0.15); display: flex; flex-direction: column; gap: 1.5rem;">
                    <div>
                        <h3 style="font-size: 1.15rem; font-weight: 700; text-transform: uppercase; margin-bottom: 0.5rem;">
                            Customize Reconciliation Export
                        </h3>
                        <p style="font-size: 0.8rem; color: var(--text-secondary);">
                            Select the columns you want to include in the generated CSV report.
                        </p>
                    </div>

                    <div style="flex-grow: 1; overflow-y: auto; padding-right: 0.5rem;">
                        <!-- Standard Columns Section -->
                        <div style="margin-bottom: 1.5rem;">
                            <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-primary); border-bottom: 1px solid var(--border-clean); padding-bottom: 0.25rem; margin-bottom: 0.75rem;">
                                Standard Attributes
                            </h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.5rem;">
                                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: var(--text-secondary); cursor: pointer;">
                                    <input type="checkbox" class="export-col-checkbox" data-role="standard" data-header="Device ID" checked disabled>
                                    Device ID
                                </label>
                                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: var(--text-secondary); cursor: pointer;">
                                    <input type="checkbox" class="export-col-checkbox" data-role="standard" data-header="Hostname" checked disabled>
                                    Hostname
                                </label>
                                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: var(--text-secondary); cursor: pointer;">
                                    <input type="checkbox" class="export-col-checkbox" data-role="standard" data-header="Audit Status" checked>
                                    Audit Status
                                </label>
                            </div>
                        </div>

                        <!-- Primary Columns Section -->
                        ${primaryCheckboxes}

                        <!-- Secondary Columns Section -->
                        ${secondaryCheckboxes}
                    </div>

                    <!-- Footer Controls -->
                    <div style="display: flex; justify-content: flex-end; gap: 1rem; border-top: 1px solid var(--border-clean); padding-top: 1rem;">
                        <button class="btn btn-secondary" style="font-size: 0.8rem; padding: 0.6rem 1.2rem;" id="btn-export-cancel">Cancel</button>
                        <button class="btn" style="font-size: 0.8rem; padding: 0.6rem 1.2rem;" id="btn-export-download">Download CSV</button>
                    </div>
                </div>
            `;

            document.body.appendChild(modal);

            // Add event listeners (safely guarded)
            const cancelBtn = document.getElementById("btn-export-cancel");
            if (cancelBtn && cancelBtn.addEventListener) {
                cancelBtn.addEventListener("click", () => {
                    document.body.removeChild(modal);
                });
            }

            const downloadBtn = document.getElementById("btn-export-download");
            if (downloadBtn && downloadBtn.addEventListener) {
                downloadBtn.addEventListener("click", () => {
                    // Collect checked checkboxes
                    const checkboxes = modal.querySelectorAll(".export-col-checkbox:checked");
                    const selectedCols = Array.from(checkboxes).map(cb => ({
                        role: cb.getAttribute("data-role"),
                        filename: cb.getAttribute("data-filename"),
                        header: cb.getAttribute("data-header")
                    }));

                    if (selectedCols.length === 0) {
                        alert("Please select at least one column to export.");
                        return;
                    }

                    // Generate CSV content
                    let csvContent = "data:text/csv;charset=utf-8,";

                    // Header row
                    const headerRowStr = selectedCols.map(c => `"${c.header.replace(/"/g, '""')}"`).join(",");
                    csvContent += headerRowStr + "\n";

                    // Rows
                    const allItems = [
                        ...reconciliationResults.gaps,
                        ...reconciliationResults.rogues,
                        ...reconciliationResults.matches
                    ];

                    allItems.forEach(item => {
                        const rowValues = selectedCols.map(c => {
                            const rawVal = getColumnValue(item, c.header, c.role, c.filename);
                            return `"${String(rawVal).replace(/"/g, '""')}"`;
                        });
                        csvContent += rowValues.join(",") + "\n";
                    });

                    // Trigger download
                    const encodedUri = encodeURI(csvContent);
                    const link = document.createElement("a");
                    link.setAttribute("href", encodedUri);
                    link.setAttribute("download", `fleet_reconciliation_report_${Date.now()}.csv`);
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);

                    // Remove modal
                    document.body.removeChild(modal);
                    logToTerminal("[Reconciler] Customized CSV export complete.", "info");
                });
            }
        }

        // Hero Visual Card Slider Logic
        let currentHeroSlideIndex = 0;
        let heroSliderInterval = null;

        function gotoHeroSlide(idx) {
            currentHeroSlideIndex = idx;
            const wrapper = document.getElementById("hero-slider-wrapper");
            if (wrapper) {
                wrapper.style.transform = `translateX(-${idx * 33.333}%)`;
            }

            // Update dots
            const dots = document.querySelectorAll(".slide-dot");
            dots.forEach((dot, index) => {
                if (index === idx) {
                    dot.classList.add("active");
                } else {
                    dot.classList.remove("active");
                }
            });
        }

        function nextHeroSlide() {
            let nextIdx = (currentHeroSlideIndex + 1) % 3;
            gotoHeroSlide(nextIdx);
        }

        function startHeroSlider() {
            if (heroSliderInterval) clearInterval(heroSliderInterval);
            heroSliderInterval = setInterval(nextHeroSlide, 5000);
        }

        function stopHeroSlider() {
            if (heroSliderInterval) clearInterval(heroSliderInterval);
        }

        // Initialize slider auto-play and event listeners
        const sliderCard = document.getElementById("hero-interactive-card");
        if (sliderCard && typeof sliderCard.addEventListener === "function") {
            sliderCard.addEventListener("mouseenter", stopHeroSlider);
            sliderCard.addEventListener("mouseleave", startHeroSlider);
        }
        startHeroSlider();

        // Slide 3 SIEM Log Stream Simulator
        const sampleIngestLogs = [
            { text: "INGEST: asset_reconciliation_report.csv processed successfully (1,042 assets matched)", color: "#4ade80" },
            { text: "ALERT: Cryptographic encryption audit gap on node 'DELL-EUD-2041'", color: "#fb7185" },
            { text: "SEC: Identity Assertion token leased to corporate analyst", color: "#38bdf8" },
            { text: "INGEST: Tenable Nessus check-in received for host 'DELL-EUD-1002'", color: "#4ade80" },
            { text: "ALERT: SentinelOne EDR service disabled on client 'dev-7463'", color: "#fb7185" },
            { text: "SEC: LDAP directories synchronization cycle completed", color: "#38bdf8" },
            { text: "INGEST: active_directory_ledger.csv updated by administrator", color: "#4ade80" },
            { text: "VAULT: secrets engine lease renewed at 'secret/data/tenants'", color: "#38bdf8" }
        ];

        setInterval(() => {
            const terminal = document.getElementById("hero-mini-terminal");
            if (terminal && typeof terminal.appendChild === "function") {
                const log = sampleIngestLogs[Math.floor(Math.random() * sampleIngestLogs.length)];
                const logEl = document.createElement("div");
                logEl.style.color = log.color;
                const time = new Date().toLocaleTimeString();
                logEl.innerText = `[${time}] ${log.text}`;

                // Add and scroll
                terminal.appendChild(logEl);
                if (terminal.children && terminal.children.length > 20 && typeof terminal.removeChild === "function") {
                    terminal.removeChild(terminal.firstChild);
                }
                terminal.scrollTop = terminal.scrollHeight;
            }
        }, 3000);

        // Fluctuate Slide 1, Slide 2, and Slide 3 calculations in real time for dynamic interactivity
        function updateHeroLiveMetrics() {
            // Slide 1 Elements
            const scaleEl = document.getElementById("hero-fleet-scale");
            const complianceEl = document.getElementById("hero-avg-compliance");
            const adValEl = document.getElementById("hero-ad-val");
            const adBarEl = document.getElementById("hero-ad-bar");
            const bitlockerValEl = document.getElementById("hero-bitlocker-val");
            const bitlockerBarEl = document.getElementById("hero-bitlocker-bar");
            const s1ValEl = document.getElementById("hero-s1-val");
            const s1BarEl = document.getElementById("hero-s1-bar");

            // Slide 2 Elements
            const riskClassEl = document.getElementById("hero-risk-class");
            const mandatesEl = document.getElementById("hero-mandates-val");
            const zscalerValEl = document.getElementById("hero-zscaler-val");
            const zscalerBarEl = document.getElementById("hero-zscaler-bar");
            const nessusValEl = document.getElementById("hero-nessus-val");
            const nessusBarEl = document.getElementById("hero-nessus-bar");
            const sccmValEl = document.getElementById("hero-sccm-val");
            const sccmBarEl = document.getElementById("hero-sccm-bar");

            // Slide 3 Elements
            const keysEl = document.getElementById("hero-active-keys");
            const throughputEl = document.getElementById("hero-throughput");

            if (!scaleEl) return; // safety guard for headless tests

            // Helper to get color code based on percentage
            function getMetricColor(pct) {
                if (pct < 80) return "var(--status-critical)";
                if (pct < 90) return "var(--status-medium)";
                return "var(--status-low)";
            }

            // --- Slide 1 Fluctuations ---
            // Fluctuate Fleet Scale wildly between 8,000 and 12,000
            const fleetScale = 8000 + Math.floor(Math.random() * 4001);
            scaleEl.innerText = fleetScale.toLocaleString();

            // Fluctuate individual agent metrics widely
            const adPct = (70.0 + Math.random() * 30.0).toFixed(1);
            const bitPct = (60.0 + Math.random() * 40.0).toFixed(1);
            const s1Pct = (75.0 + Math.random() * 25.0).toFixed(1);

            if (adValEl) {
                adValEl.innerText = `${adPct}% Compliant`;
                adValEl.style.color = getMetricColor(parseFloat(adPct));
            }
            if (adBarEl && adBarEl.style) {
                adBarEl.style.width = `${adPct}%`;
                adBarEl.style.backgroundColor = getMetricColor(parseFloat(adPct));
            }

            if (bitlockerValEl) {
                bitlockerValEl.innerText = `${bitPct}% Audited`;
                bitlockerValEl.style.color = getMetricColor(parseFloat(bitPct));
            }
            if (bitlockerBarEl && bitlockerBarEl.style) {
                bitlockerBarEl.style.width = `${bitPct}%`;
                bitlockerBarEl.style.backgroundColor = getMetricColor(parseFloat(bitPct));
            }

            if (s1ValEl) {
                s1ValEl.innerText = `${s1Pct}% Active`;
                s1ValEl.style.color = getMetricColor(parseFloat(s1Pct));
            }
            if (s1BarEl && s1BarEl.style) {
                s1BarEl.style.width = `${s1Pct}%`;
                s1BarEl.style.backgroundColor = getMetricColor(parseFloat(s1Pct));
            }

            // Calculate and display average compliance
            const avgCompliance = ((parseFloat(adPct) + parseFloat(bitPct) + parseFloat(s1Pct)) / 3).toFixed(1);
            if (complianceEl) {
                complianceEl.innerText = `${avgCompliance}%`;
                if (complianceEl.style) {
                    complianceEl.style.color = getMetricColor(parseFloat(avgCompliance));
                }
            }

            // --- Slide 2 Fluctuations ---
            if (riskClassEl) {
                const rVal = Math.random();
                let riskText = "LOW";
                let riskColor = "var(--status-low)";
                if (rVal < 0.25) {
                    riskText = "CRITICAL";
                    riskColor = "var(--status-critical)";
                } else if (rVal < 0.5) {
                    riskText = "HIGH";
                    riskColor = "var(--status-high)";
                } else if (rVal < 0.75) {
                    riskText = "MEDIUM";
                    riskColor = "var(--status-medium)";
                }
                riskClassEl.innerText = riskText;
                if (riskClassEl.style) riskClassEl.style.color = riskColor;
            }

            if (mandatesEl) {
                const activeMandates = 2 + Math.floor(Math.random() * 5); // 2 to 6
                mandatesEl.innerText = `${activeMandates} / 6`;
                if (mandatesEl.style) {
                    mandatesEl.style.color = activeMandates === 6 ? "var(--text-primary)" : "var(--status-medium)";
                }
            }

            const zPct = (55.0 + Math.random() * 45.0).toFixed(1);
            if (zscalerValEl) {
                zscalerValEl.innerText = `${zPct}% Encrypted`;
                zscalerValEl.style.color = getMetricColor(parseFloat(zPct));
            }
            if (zscalerBarEl && zscalerBarEl.style) {
                zscalerBarEl.style.width = `${zPct}%`;
                zscalerBarEl.style.backgroundColor = getMetricColor(parseFloat(zPct));
            }

            const nPct = (65.0 + Math.random() * 35.0).toFixed(1);
            if (nessusValEl) {
                nessusValEl.innerText = `${nPct}% Inspected`;
                nessusValEl.style.color = getMetricColor(parseFloat(nPct));
            }
            if (nessusBarEl && nessusBarEl.style) {
                nessusBarEl.style.width = `${nPct}%`;
                nessusBarEl.style.backgroundColor = getMetricColor(parseFloat(nPct));
            }

            const sccmPct = (70.0 + Math.random() * 30.0).toFixed(1);
            if (sccmValEl) {
                sccmValEl.innerText = `${sccmPct}% Active`;
                sccmValEl.style.color = getMetricColor(parseFloat(sccmPct));
            }
            if (sccmBarEl && sccmBarEl.style) {
                sccmBarEl.style.width = `${sccmPct}%`;
                sccmBarEl.style.backgroundColor = getMetricColor(parseFloat(sccmPct));
            }

            // --- Slide 3 Fluctuations ---
            if (keysEl) {
                keysEl.innerText = (10 + Math.floor(Math.random() * 41)).toString(); // 10 to 50
            }

            if (throughputEl) {
                const tp = 450 + Math.floor(Math.random() * 3351); // 450 to 3800
                throughputEl.innerText = `${tp.toLocaleString()} ev/s`;
            }
        }
        setInterval(updateHeroLiveMetrics, 3000);
        updateHeroLiveMetrics();

    