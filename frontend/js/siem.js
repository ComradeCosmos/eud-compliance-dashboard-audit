const siemTemplates = {
            AD: JSON.stringify({
                "event_id": 4724,
                "target_username": "operator",
                "changed_by": "admin",
                "domain": "COSMOS.LOCAL",
                "status": "success",
                "details": "An attempt was made to reset an account's password."
            }, null, 4),
            Nessus: JSON.stringify({
                "plugin_id": 104631,
                "plugin_name": "HTTP Strict Transport Security (HSTS) Detection",
                "severity": "HIGH",
                "port": 443,
                "protocol": "tcp",
                "plugin_output": "The remote HTTPS server does not send the HTTP Strict Transport Security header.",
                "cve": ["CVE-2015-2808"]
            }, null, 4),
            EDR: JSON.stringify({
                "agent_id": "eud-agent-88a",
                "hostname": "DELL-EUD-1003",
                "os": "Windows 11 Enterprise",
                "last_checkin": "2026-06-18T10:00:00Z",
                "malware_status": "Clean",
                "threats_blocked": 0,
                "tamper_protection": "Enabled"
            }, null, 4),
            Zscaler: JSON.stringify({
                "transaction_id": 9847192,
                "user": "alkes@cosmos.local",
                "action": "Blocked",
                "url": "http://malicious-command-and-control.com/payload.exe",
                "category": "Malware/Spyware",
                "threat_name": "Win32.Trojan.Downloader"
            }, null, 4)
        };

        function handleSiemSourceChange() {
            const source = document.getElementById("siem-source-select").value;
            loadSiemSample(source);
        }

        function loadSiemDefaultTemplate() {
            const source = document.getElementById("siem-source-select").value;
            loadSiemSample(source);
        }

        function loadSiemSample(source) {
            const textarea = document.getElementById("siem-payload-input");
            if (textarea && siemTemplates[source]) {
                textarea.value = siemTemplates[source];
                logToTerminal(`[SIEM Ingest] Template loaded for source: "${source}"`);
            }
        }

        async function executeManualSiemIngest() {
            const source = document.getElementById("siem-source-select").value;
            const payload = document.getElementById("siem-payload-input").value;
            if (!payload || !payload.trim()) {
                alert("Please enter a valid log payload.");
                return;
            }

            logToTerminal(`[SIEM Ingest] Dispatching manual log ingestion event for source: "${source}"...`);
            const res = await apiPost('/api/siem/ingest', {
                source: source,
                raw_log: payload,
                collected_at: new Date().toISOString()
            });

            if (res && res.id) {
                logToTerminal(`[SIEM Ingest] Ingestion complete: Evidence ID #${res.id} registered successfully.`, "info");
                logToTerminal(`[SIEM Ingest] Hash Signature: ${res.hash_signature}`, "info");
                logToTerminal(`[SIEM Ingest] Verification Status: ${res.is_verified ? "SECURE" : "TAMPERED"}`, res.is_verified ? "info" : "error");
            } else {
                logToTerminal(`[SIEM Ingest Error] Failed to ingest log payload: ${res ? res.message : "Unknown error"}`, "error");
            }
        }

        async function verifyAllSiemEvidence() {
            logToTerminal("[SIEM Ingest] Initiating cryptographic hash integrity check for all registered evidence...");
            const evidenceList = await apiGet('/api/evidence');
            if (!evidenceList || evidenceList.length === 0) {
                logToTerminal("[SIEM Ingest] No evidence records found in the cryptographic database to verify.", "warn");
                return;
            }

            logToTerminal(`[SIEM Ingest] Found ${evidenceList.length} evidence records. Querying validation keys...`, "info");
            let verifiedCount = 0;
            let compromisedCount = 0;

            for (const ev of evidenceList) {
                const res = await apiGet(`/api/evidence/${ev.id}/verify`);
                if (res && res.is_verified) {
                    logToTerminal(`[SECURE] ID #${ev.id} (${ev.source}): Hash matches registry value. [Signature: ${res.expected_hash.substring(0, 16)}...]`, "info");
                    verifiedCount++;
                } else {
                    logToTerminal(`[TAMPERED] ID #${ev.id} (${ev.source}): CRYPTOGRAPHIC SIGNATURE MISMATCH OR EVIDENCE CORRUPTED!`, "error");
                    compromisedCount++;
                }
            }

            if (compromisedCount > 0) {
                logToTerminal(`[INTEGRITY AUDIT COMPLETE] Result: COMPROMISED. Verified: ${verifiedCount}, Tampered/Failed: ${compromisedCount}`, "error");
                alert(`WARNING: Integrity audit failed! Detected ${compromisedCount} tampered evidence record(s).`);
            } else {
                logToTerminal(`[INTEGRITY AUDIT COMPLETE] Result: SECURE. All ${verifiedCount} records passed signature validation.`, "info");
                alert("Integrity check complete: All evidence logs verified secure. Non-repudiation integrity intact.");
            }
        }

        let siemSimulationInterval = null;

        function toggleSiemSimulation(event) {
            const btn = document.getElementById("btn-siem-simulate");
            if (!btn) return;

            if (siemSimulationInterval) {
                clearInterval(siemSimulationInterval);
                siemSimulationInterval = null;
                btn.innerText = "Start Simulation";
                btn.style.background = "#15803d";
                btn.style.borderColor = "#15803d";
                logToTerminal("[SIEM Ingest] Background log stream simulation stopped.");
            } else {
                btn.innerText = "Stop Simulation";
                btn.style.background = "#b91c1c";
                btn.style.borderColor = "#b91c1c";
                logToTerminal("[SIEM Ingest] Background log stream simulation started.");

                siemSimulationInterval = setInterval(async () => {
                    const sources = ["AD", "Nessus", "EDR", "Zscaler"];
                    const randomSource = sources[Math.floor(Math.random() * sources.length)];
                    let templateStr = siemTemplates[randomSource];

                    let payload = JSON.parse(templateStr);
                    if (randomSource === "AD") {
                        const users = ["operator", "admin", "alkes", "analyst", "developer"];
                        payload.target_username = users[Math.floor(Math.random() * users.length)];
                        payload.event_id = Math.random() > 0.5 ? 4724 : 4624;
                        payload.details = payload.event_id === 4724 ? "An attempt was made to reset an account's password." : "An account was successfully logged on.";
                    } else if (randomSource === "Nessus") {
                        const severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
                        payload.severity = severities[Math.floor(Math.random() * severities.length)];
                        payload.port = Math.random() > 0.5 ? 443 : 80;
                    } else if (randomSource === "EDR") {
                        const hosts = ["DELL-EUD-1001", "DELL-EUD-1002", "DELL-EUD-1003", "DELL-EUD-9999"];
                        payload.hostname = hosts[Math.floor(Math.random() * hosts.length)];
                        payload.threats_blocked = Math.floor(Math.random() * 3);
                    } else if (randomSource === "Zscaler") {
                        const urls = [
                            "http://malicious-command-and-control.com/payload.exe",
                            "http://phishing-site-domain.org/login",
                            "http://trusted-internal-dns.net/api",
                            "https://external-file-sharing.com/doc.pdf"
                        ];
                        payload.url = urls[Math.floor(Math.random() * urls.length)];
                        payload.action = payload.url.includes("malicious") || payload.url.includes("phishing") ? "Blocked" : "Allowed";
                    }

                    const randomizedPayloadStr = JSON.stringify(payload, null, 4);
                    logToTerminal(`[Simulation Stream] Generated simulated event for source: "${randomSource}"`);

                    const res = await apiPost('/api/siem/ingest', {
                        source: randomSource,
                        raw_log: randomizedPayloadStr,
                        collected_at: new Date().toISOString()
                    });
                    if (res && res.id) {
                        logToTerminal(`[Simulation Stream Error] Failed to ingest simulated event.`, "error");
                    }
                }, 3000);
            }
        }

        async function exportSiemLogs() {
            logToTerminal("[SIEM Ingest] Fetching evidence database records for export...");
            const evidenceList = await apiGet('/api/evidence');
            if (!evidenceList || evidenceList.length === 0) {
                logToTerminal("[SIEM Ingest] No evidence records found to export.", "warn");
                alert("No evidence records found to export.");
                return;
            }
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(evidenceList, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", "siem_logs_export.json");
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
            logToTerminal("[SIEM Ingest] SIEM evidence logs exported successfully.", "info");
        }

        function importSiemLogs(event) {
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = async function (e) {
                try {
                    const logs = JSON.parse(e.target.result);
                    if (!Array.isArray(logs)) {
                        alert("Invalid file format. Expected a JSON array of logs.");
                        return;
                    }
                    logToTerminal(`[SIEM Ingest] Importing ${logs.length} logs from file...`);
                    let successCount = 0;
                    for (const item of logs) {
                        const rawLog = item.raw_log || item.raw_data || JSON.stringify(item);
                        const res = await apiPost('/api/siem/ingest', {
                            source: item.source || "AD",
                            raw_log: typeof rawLog === 'string' ? rawLog : JSON.stringify(rawLog),
                            collected_at: item.collected_at || new Date().toISOString()
                        });
                        if (res && res.id) {
                            successCount++;
                        }
                    }
                    logToTerminal(`[SIEM Ingest] Successfully imported ${successCount} / ${logs.length} logs.`, "info");
                    alert(`Successfully imported ${successCount} logs.`);
                    event.target.value = "";
                } catch (err) {
                    console.error(err);
                    logToTerminal(`[SIEM Ingest] Failed to parse import file: ${err.message}`, "error");
                    alert("Failed to parse import file. Ensure it is a valid JSON array.");
                }
            };
            reader.readAsText(file);
        }

        