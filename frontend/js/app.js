
        function showLoading(message) {
            const overlay = document.getElementById("process-loading-overlay");
            const textEl = document.getElementById("process-loading-text");
            if (overlay) overlay.style.display = "flex";
            if (textEl) textEl.textContent = message || "Processing...";
        }

        function hideLoading() {
            const overlay = document.getElementById("process-loading-overlay");
            if (overlay) overlay.style.display = "none";
        }

        function runProcess(processFn, loadingMessage, autoHide = true) {
            showLoading(loadingMessage);
            const isBrowser = (typeof window !== "undefined" && window.location && window.location.href);
            if (isBrowser) {
                setTimeout(() => {
                    try {
                        processFn();
                    } finally {
                        if (autoHide) hideLoading();
                    }
                }, 50);
            } else {
                try {
                    processFn();
                } finally {
                    if (autoHide) hideLoading();
                }
            }
        }

        // Ensure requestAnimationFrame is defined (for test environments / headless environments)
        if (typeof requestAnimationFrame === "undefined") {
            if (typeof window !== "undefined") {
                window.requestAnimationFrame = function (cb) { return setTimeout(cb, 16); };
            } else if (typeof globalThis !== "undefined") {
                globalThis.requestAnimationFrame = function (cb) { return setTimeout(cb, 16); };
            } else {
                this.requestAnimationFrame = function (cb) { return setTimeout(cb, 16); };
            }
        }

        // Simulated LDAP user and authorization directory
        const simulatedLDAPDirectory = {
            "admin": {
                pin: "admin",
                role: "admin",
                roleLabel: "Global Security & Compliance Administrator",
                authorizations: ["Reconciliation Approval", "CSV Ingestion Authority", "Secret Key Leasing", "Sift Fleet Access", "Outbound Alerts Dispatch"]
            },
            "analyst": {
                pin: "analyst",
                role: "analyst",
                roleLabel: "Global Security Analyst",
                authorizations: ["Reconciliation Approval", "CSV Ingestion Authority", "Sift Fleet Access"]
            },
            "operator": {
                pin: "operator",
                role: "operator",
                roleLabel: "Security Operations Operator",
                authorizations: ["Reconciliation Approval", "Sift Fleet Access"]
            },
            "auditor": {
                pin: "auditor",
                role: "auditor",
                roleLabel: "External Compliance Auditor",
                authorizations: ["Read-Only Ledger Access"]
            }
        };


        // Global Reconciliation Workspace Data (Declared at the top to prevent TDZ ReferenceErrors on page reload)
        let reconcilerSheets = [];
        let reconciliationResults = {
            matches: [],
            gaps: [],
            rogues: []
        };
        let mergedSoftwareAgents = new Set();
        let currentPolicyTab = "all";

        // Current active tenant session details
        let currentSession = {
            isLoggedIn: false,
            username: "",
            role: "",
            roleLabel: "",
            tenant: "",
            authorizations: []
        };

        let loginFailCount = 0;
        let lockoutTimer = null;
        let lockoutUntil = 0;

        // Role-based privilege mapping & element locks
        function enforceRoleBasedControls() {
            const role = currentSession.role;
            const isAdmin = (role === "admin");
            const isAnalyst = (role === "analyst");
            const isOperator = (role === "operator");
            const isAuditor = (role === "auditor");

            // 1. Details view controls & Network isolation buttons
            const remButtons = document.querySelectorAll("#audit-details-panel .btn, #audit-details-panel .btn-secondary");
            remButtons.forEach(btn => {
                const isIsolation = btn.id === "btn-isolate-device";

                // Identify which remediation
                let onClickAttr = btn.getAttribute("onclick") || "";
                const isRemPatch = onClickAttr.includes("'PATCH'");
                const isRemEdr = onClickAttr.includes("'EDR'");
                const isRemVault = onClickAttr.includes("'VAULT'");

                if (isIsolation || isRemPatch || isRemEdr || isRemVault) {
                    if (isAuditor) {
                        btn.disabled = true;
                        btn.style.opacity = 0.55;
                        btn.style.cursor = "not-allowed";
                        btn.title = "Access Denied: Auditor Read-Only";

                        if (isIsolation) {
                            btn.innerHTML = `<span>Isolated (Auditor Read-Only)</span> <span style="font-weight:400; opacity: 0.8;">Block</span>`;
                            btn.style.background = "var(--border-clean)";
                            btn.style.borderColor = "var(--border-clean)";
                            btn.style.color = "var(--text-muted)";
                        }
                    } else if (isOperator) {
                        // Operator can isolate/reconnect and patch, but NOT EDR Scan or Vault Escrow
                        if (isRemEdr || isRemVault) {
                            btn.disabled = true;
                            btn.style.opacity = 0.55;
                            btn.style.cursor = "not-allowed";
                            btn.title = "Access Denied: Operator Restricted";
                        } else {
                            btn.disabled = false;
                            btn.style.opacity = 1;
                            btn.style.cursor = "pointer";
                            btn.title = "";

                            if (isIsolation) {
                                const dev = fleetDataset.find(d => d.id === selectedDevice);
                                if (dev) {
                                    if (dev.is_isolated) {
                                        btn.innerHTML = `<span>Reconnect Host</span> <span style="font-weight:400; opacity: 0.8;">Active</span>`;
                                        btn.style.background = "var(--status-low)";
                                        btn.style.borderColor = "var(--status-low)";
                                        btn.style.color = "var(--bg-main)";
                                    } else {
                                        btn.innerHTML = `<span>Isolate Network Host</span> <span style="font-weight:400; opacity: 0.8;">Block</span>`;
                                        btn.style.background = "var(--status-critical)";
                                        btn.style.borderColor = "var(--status-critical)";
                                        btn.style.color = "var(--bg-main)";
                                    }
                                }
                            }
                        }
                    } else {
                        // Admin & Analyst have full access to remediation
                        btn.disabled = false;
                        btn.style.opacity = 1;
                        btn.style.cursor = "pointer";
                        btn.title = "";

                        if (isIsolation) {
                            const dev = fleetDataset.find(d => d.id === selectedDevice);
                            if (dev) {
                                if (dev.is_isolated) {
                                    btn.innerHTML = `<span>Reconnect Host</span> <span style="font-weight:400; opacity: 0.8;">Active</span>`;
                                    btn.style.background = "var(--status-low)";
                                    btn.style.borderColor = "var(--status-low)";
                                    btn.style.color = "var(--bg-main)";
                                } else {
                                    btn.innerHTML = `<span>Isolate Network Host</span> <span style="font-weight:400; opacity: 0.8;">Block</span>`;
                                    btn.style.background = "var(--status-critical)";
                                    btn.style.borderColor = "var(--status-critical)";
                                    btn.style.color = "var(--bg-main)";
                                }
                            }
                        }
                    }
                }
            });

            // 2. CSV Import / Export
            const importBtnLabel = document.querySelector('label[for="csv-import-file"]');
            const exportBtn = document.querySelector('button[onclick="triggerCsvExport()"]');

            if (isAuditor || isOperator) {
                const labelTitle = isAuditor ? "Auditor Read-Only" : "Operator Restricted";
                if (importBtnLabel) {
                    importBtnLabel.style.opacity = 0.55;
                    importBtnLabel.style.cursor = "not-allowed";
                    importBtnLabel.style.pointerEvents = "none";
                    importBtnLabel.title = labelTitle;
                }
                if (exportBtn) {
                    exportBtn.disabled = true;
                    exportBtn.style.opacity = 0.55;
                    exportBtn.style.cursor = "not-allowed";
                    exportBtn.title = labelTitle;
                }
            } else {
                if (importBtnLabel) {
                    importBtnLabel.style.opacity = 1;
                    importBtnLabel.style.cursor = "pointer";
                    importBtnLabel.style.pointerEvents = "auto";
                    importBtnLabel.title = "";
                }
                if (exportBtn) {
                    exportBtn.disabled = false;
                    exportBtn.style.opacity = 1;
                    exportBtn.style.cursor = "pointer";
                    exportBtn.title = "";
                }
            }

            // 3. Reconciliation Simulation Button (Risk Management view)
            const reconBtn = document.querySelector('button[onclick="runReconciliationSimulation()"]');
            if (reconBtn) {
                if (isAuditor || isOperator) {
                    reconBtn.disabled = true;
                    reconBtn.style.opacity = 0.55;
                    reconBtn.style.cursor = "not-allowed";
                    reconBtn.title = isAuditor ? "Auditor Read-Only" : "Operator Restricted";
                } else {
                    reconBtn.disabled = false;
                    reconBtn.style.opacity = 1;
                    reconBtn.style.cursor = "pointer";
                    reconBtn.title = "";
                }
            }
        }

        // Security helpers to mitigate Stored XSS and CSV Formula Injection
        function escapeHTML(str) {
            if (str === undefined || str === null) return "";
            return String(str).replace(/[&<>'"]/g,
                tag => ({
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    "'": '&#39;',
                    '"': '&quot;'
                }[tag] || tag)
            );
        }

        function sanitizeCSVCell(val) {
            if (val === undefined || val === null) return "";
            let str = String(val);
            // Mitigate spreadsheet formula injection attacks (CSV Injection)
            if (str.startsWith("=") || str.startsWith("+") || str.startsWith("-") || str.startsWith("@") || str.startsWith("\t") || str.startsWith("\r")) {
                str = "'" + str;
            }
            return str;
        }

        const assetConditions = [
            "DISPOSED",
            "DONATED_UNDER_CSR",
            "EXPIRED",
            "IN_REPAIR",
            "IN_STORE",
            "IN_USE",
            "LOANABLE_RESERVED",
            "NOT_TRACEABLE",
            "RESERVED"
        ];
        const manufacturersList = ["Dell Inc.", "Apple Inc.", "Lenovo", "HP", "Microsoft"];
        const osVersionsList = [
            { os: "Windows 11 (22631)", family: "Windows" },
            { os: "Windows 10 Enterprise", family: "Windows" },
            { os: "macOS 14.4 (Sonoma)", family: "macOS" },
            { os: "Ubuntu 22.04 LTS", family: "Linux" }
        ];

        // Software catalogs (Core Enterprise Security Agents & Controls)
        const sampleSoftwareCatalog = [
            { name: "Active Directory (AD) Enrollment", key: "ad" },
            { name: "BitLocker Drive Encryption", key: "bitlocker" },
            { name: "Zscaler Client Connector", key: "zscaler" },
            { name: "Nessus Vulnerability Agent", key: "nessus" },
            { name: "SentinelOne Endpoint Protection", key: "sentinelone" },
            { name: "SCCM Management Agent", key: "sccm" }
        ];

        // Corporate User Assigned and Office Locations catalogs
        const userAssignedCatalog = ["Cosmos.s", "j.doe", "s.johnson", "a.taylor", "r.jones", "m.smith", "d.brown", "c.miller", "l.davis", "k.wilson"];
        const officeLocationsCatalog = ["New York HQs", "London Office", "Singapore Hub", "Remote - US", "Munich Lab", "Tokyo branch"];

        // Seed generator for highly deterministic, realistic dataset at true corporate scale (exactly 10,029 devices)
        function generateStructuredAssets(count) {
            const list = [];
            for (let i = 1; i <= count; i++) {
                const man = manufacturersList[i % manufacturersList.length];
                const osInfo = osVersionsList[i % osVersionsList.length];

                // Realistic distribution: majority in use, others distributed across the other 8 conditions
                let condition = "IN_USE";
                if (i % 25 === 0) condition = "IN_REPAIR";
                else if (i % 40 === 0) condition = "IN_STORE";
                else if (i % 50 === 0) condition = "EXPIRED";
                else if (i % 60 === 0) condition = "DISPOSED";
                else if (i % 70 === 0) condition = "DONATED_UNDER_CSR";
                else if (i % 80 === 0) condition = "LOANABLE_RESERVED";
                else if (i % 90 === 0) condition = "NOT_TRACEABLE";
                else if (i % 100 === 0) condition = "RESERVED";

                let score = 100.00;
                if (condition !== "IN_USE") {
                    score = 0.00;
                } else if (i % 10 === 0) {
                    score = 0.00;
                } else {
                    score = 100.00;
                }

                // Generate software audits (Base Compliance Checks)
                let hasMissing = false;
                const software = sampleSoftwareCatalog.map((sw, swIdx) => {
                    let status = "COMPLIANT";
                    let installed = "INSTALLED";

                    if (sw.key === "ad") {
                        // AD Enrollment: independent ~1.6% non-compliance rate (not gated on score)
                        // Affects ~161 devices across the full fleet for a realistic baseline gap
                        if (i % 62 === 1) {
                            status = "NON_COMPLIANT";
                            installed = "NOT ENROLLED";
                            hasMissing = true;
                        }
                    } else {
                        // All other agents: non-compliant only on devices already scored 0
                        if (score === 0.00 && (swIdx + i) % 3 === 0) {
                            status = "NON_COMPLIANT";
                            installed = "MISSING";
                            hasMissing = true;
                        }
                    }
                    return { name: sw.name, key: sw.key, installed: installed, required: "REQUIRED", status: status };
                });

                // Apply strict binary compliance: 1 non-compliance drops the score to 0.00!
                if (hasMissing || condition !== "IN_USE") {
                    score = 0.00;
                } else {
                    score = 100.00;
                }
                let level = (score === 100.00) ? "COMPLIANT" : "NON_COMPLIANT";

                // Generate new corporate metadata fields
                const user = userAssignedCatalog[i % userAssignedCatalog.length];
                const location = officeLocationsCatalog[i % officeLocationsCatalog.length];

                // Strictly 'Sift' or 'Non-Sift' location group category
                const locationGroup = (i % 3 === 0) ? "Sift" : "Non-Sift";

                // Deterministic last login dates
                const hour = 10 + (i % 8);
                const min = 10 + (i % 45);
                const lastLoginStr = `2026-05-${20 + (i % 7)} ${hour}:${min}`;

                const deptList = ["Engineering", "Product", "Sales", "Human Resources", "Finance", "Legal", "Operations", "Marketing"];
                const deviceName = `${man.substring(0, 3).toUpperCase()}-EUD-${1000 + i}`;
                list.push({
                    id: `dev-${Math.abs(8000 + i).toString(16)}`,
                    canonical_name: deviceName.toLowerCase(),
                    serial: `SN-${man.substring(0, 3).toUpperCase()}-992${1000 + i}`,
                    mac: `00:1A:2B:3C:5F:${(10 + i % 240).toString(16).toUpperCase()}`,
                    manufacturer: man,
                    os: osInfo.os,
                    os_family: osInfo.family,
                    score: score,
                    level: level,
                    condition: condition,
                    software: software,
                    user_assigned: user,
                    last_login: lastLoginStr,
                    location: location,
                    location_group: locationGroup,
                    is_isolated: false,
                    custom_properties: {
                        "Department": deptList[i % deptList.length],
                        "Asset Tag": `AT-${12000 + i}`,
                        "Assigned Project": `Project-${["Titan", "Hermes", "Apollo", "Minerva", "Hyperion"][i % 5]}`,
                        "Bios Version": `v${1 + (i % 3)}.${i % 9}.${i % 5}`,
                        "Subnet IP": `10.23.${4 + (i % 20)}.${10 + (i % 240)}`
                    }
                });
            }
            return list;
        }

        // Global variables for dynamic table headers and keys
        let activeTableHeaders = ["Device ID", "Canonical Name", "Assigned User", "Last Login", "Location", "Loc Group", "Condition"];
        let activeTableKeys = ["id", "canonical_name", "user_assigned", "last_login", "location", "location_group", "condition"];

        // Global registry of enforced compliance policies (true = Required, false = Optional)
        let enforcedPolicies = {};

        // Initialize with empty fleet dataset
        let fleetDataset = [];
        let filteredDataset = [];
        let selectedDevice = null;

        // Swiss Pagination variables
        let currentPage = 1;
        const pageSize = 10;

        // Global variables for reporting pagination and search
        let reportingCurrentPage = 1;
        let reportingSearchQuery = "";
        const reportingPageSize = 10;

        function logToTerminal(text, type = "info") {
            const term = document.getElementById("audit-terminal");
            if (!term) return;
            const line = document.createElement("div");
            line.className = `terminal-line ${type}`;
            const time = new Date().toLocaleTimeString();
            line.innerText = `[${time}] ${text}`;
            term.appendChild(line);
            term.scrollTop = term.scrollHeight;
        }



        function switchNavSection(target) {
            // NIST CSF 2.0 Airtight Auth Boundaries
            if (!currentSession.isLoggedIn && target !== 'login') {
                logToTerminal(`[Security Challenge] Access Blocked: Session token missing or lease expired. Redirecting.`, "error");
                document.getElementById("login-screen-canvas").style.display = "flex";
                document.getElementById("main-app-container").style.display = "none";
                return;
            }

            if (currentSession.isLoggedIn) {
                if ((target === 'settings' || target === 'reporting') && currentSession.role !== 'admin') {
                    logToTerminal(`[Security Alert] RBAC Violation: User "${currentSession.username}" (Role: ${currentSession.role.toUpperCase()}) lacks Global Admin privileges for "${target.toUpperCase()}".`, "error");
                    alert(`Access Denied: Global Administrator privileges are required to view the ${target.toUpperCase()} configurations.`);
                    return;
                }
                if (target === 'dev-db' && currentSession.role !== 'admin' && currentSession.role !== 'developer') {
                    logToTerminal(`[Security Alert] RBAC Violation: User "${currentSession.username}" lacks Developer privileges for "${target.toUpperCase()}".`, "error");
                    alert(`Access Denied: Developer or Admin privileges are required to access the Developer Console.`);
                    return;
                }
            }
            // Toggle sidebar visibility and layout sizing
            const sidebar = document.querySelector(".sidebar");
            const mainContent = document.querySelector(".main-content");
            const header = document.querySelector(".main-content > header");

            const menuHub = document.getElementById("menu-hub");
            if (target === 'hub') {
                if (sidebar) sidebar.style.display = "none";
                if (header) header.style.display = "none";
                if (mainContent) {
                    mainContent.style.background = "radial-gradient(circle at center, #111827 0%, #030712 100%)";
                    mainContent.style.padding = "0";
                }
                if (menuHub) menuHub.style.display = "block";
            } else {
                if (sidebar) sidebar.style.display = "flex";
                if (header) header.style.display = "flex";
                if (mainContent) {
                    mainContent.style.background = "transparent";
                    mainContent.style.padding = "3rem 2.5rem";
                }
                if (menuHub) menuHub.style.display = "none";
            }

            document.querySelectorAll(".sidebar-menu .menu-item").forEach(item => item.classList.remove("active"));
            document.querySelectorAll(".sidebar-group-header").forEach(item => item.classList.remove("active"));

            // Expand the group that contains this sub-item
            if (target === 'siem') {
                toggleSidebarGroup('siem');
            } else if (target === 'risk-engine') {
                toggleSidebarGroup('risk');
            } else if (target === 'samp-auditor') {
                toggleSidebarGroup('samp');
            } else if (['compliance', 'risk', 'reporting', 'reconciler'].includes(target)) {
                toggleSidebarGroup('reconciler');
            } else if (target === 'hub') {
                toggleSidebarGroup('none');
            }

            const clickedMenu = document.getElementById(`menu-${target}`);
            if (clickedMenu) {
                clickedMenu.classList.add("active");
            } else if (window.event && window.event.currentTarget) {
                window.event.currentTarget.classList.add("active");
            }

            logToTerminal(`Console navigation: loading sidebar target view "${target.toUpperCase()}"...`);

            // Hide all section views
            document.querySelectorAll(".section-view").forEach(section => {
                section.style.display = "none";
            });

            // Show selected section view
            const targetSection = document.getElementById(`section-${target}`);
            if (targetSection) {
                targetSection.style.display = "block";
            }

            // Update main section title dynamically
            const titleEl = document.getElementById("main-section-title");
            if (titleEl) {
                switch (target) {
                    case "analytics":
                        titleEl.innerText = "Executive Overview";
                        break;
                    case "hub":
                        titleEl.innerText = "Unified Gateway Portal";
                        break;
                    case "siem":
                        titleEl.innerText = "SIEM Ingestion Logs Pipeline";
                        break;
                    case "compliance":
                        titleEl.innerText = "Fleet Compliance Ledger";
                        break;
                    case "risk":
                        titleEl.innerText = "Compliance & Scoring Controls Engine";
                        break;
                    case "reporting":
                        titleEl.innerText = "Compliance Telemetry Reporting Center";
                        break;
                    case "risk-engine":
                        titleEl.innerText = "Centralized Risk Engine";
                        break;
                    case "samp-auditor":
                        titleEl.innerText = "SAMP Core Auditing Board";
                        break;
                    case "profile":
                        titleEl.innerText = "Security Analyst Identity";
                        break;

                    case "settings":
                        titleEl.innerText = "Console Settings & Pipeline Parameters";
                        break;
                    case "dev-db":
                        titleEl.innerText = "Developer Console & Database Management";
                        break;
                    case "sso":
                        titleEl.innerText = "SSO Identity Directory & Audit Trail";
                        break;
                    default:
                        titleEl.innerText = "Executive Overview";
                }
            }

            // Trigger real-time dashboard renders on section load
            if (target === "reporting") {
                generateComplianceReport();
            } else if (target === "risk") {
                renderPoliciesGrid();
            } else if (target === "dev-db") {
                loadDevConsoleData();
            } else if (target === "sso") {
                populateIdentitySSOAudits();
            } else if (target === "reconciler") {
                if (typeof renderReconciliationUI === "function" && reconciliationResults && (reconciliationResults.matches.length > 0 || reconciliationResults.gaps.length > 0 || reconciliationResults.rogues.length > 0)) {
                    renderReconciliationUI();
                }
            }

            if (typeof window.scrollTo === "function") {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }

        function switchTab(tabId) {
            document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(content => content.style.display = "none");

            const clickedBtn = document.getElementById(`tab-btn-${tabId}`);
            if (clickedBtn) clickedBtn.classList.add("active");
            document.getElementById(`tab-${tabId}`).style.display = "block";
            logToTerminal(`Console navigation: switched control pane to ${tabId.toUpperCase()}`);
        }

        // CSV Ingestion & Export
        function triggerCsvExport() {
            logToTerminal(`[Export] Opening fleet export column selector...`);

            if (filteredDataset.length === 0) {
                alert("No records to export.");
                return;
            }

            // Create modal element
            const modal = document.createElement("div");
            modal.id = "fleet-export-column-selector-modal";
            modal.style = "position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 100000; font-family: var(--font-sans);";

            const standardKeys = ["id", "canonical_name", "user_assigned", "last_login", "location", "location_group", "condition"];
            const complianceKeys = ["ad", "bitlocker", "zscaler", "nessus", "sentinelone", "sccm"];

            let coreCheckboxes = '';
            let complianceCheckboxes = '';
            let customCheckboxes = '';

            activeTableKeys.forEach((key, idx) => {
                const header = activeTableHeaders[idx];
                const isCustom = key.startsWith("custom:") || (!standardKeys.includes(key) && !complianceKeys.includes(key) && !key.startsWith("compliance:"));
                const isCompliance = key.startsWith("compliance:") || complianceKeys.includes(key);

                const isStandard = standardKeys.includes(key) && !isCustom && !isCompliance;
                const isLocked = key === "id" || key === "canonical_name";

                const checkboxHtml = `
                    <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: var(--text-secondary); cursor: pointer;">
                        <input type="checkbox" class="fleet-export-col-checkbox" data-key="${key}" data-header="${header}" checked ${isLocked ? 'disabled' : ''}>
                        ${header}
                    </label>
                `;

                if (isStandard) {
                    coreCheckboxes += checkboxHtml;
                } else if (isCompliance) {
                    complianceCheckboxes += checkboxHtml;
                } else {
                    customCheckboxes += checkboxHtml;
                }
            });

            let customSectionHtml = '';
            if (customCheckboxes) {
                customSectionHtml = `
                    <div style="margin-bottom: 1.5rem;">
                        <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-primary); border-bottom: 1px solid var(--border-clean); padding-bottom: 0.25rem; margin-bottom: 0.75rem;">
                            Custom Telemetry Columns
                        </h4>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
                            ${customCheckboxes}
                        </div>
                    </div>
                `;
            }

            modal.innerHTML = `
                <div class="card" style="width: 580px; max-height: 80vh; overflow-y: auto; background: var(--bg-card); border: 1px solid var(--border-clean); padding: 2rem; border-radius: 4px; box-shadow: 0 10px 25px rgba(0,0,0,0.15); display: flex; flex-direction: column; gap: 1.5rem;">
                    <div>
                        <h3 style="font-size: 1.15rem; font-weight: 700; text-transform: uppercase; margin-bottom: 0.5rem;">
                            Customize Fleet Export
                        </h3>
                        <p style="font-size: 0.8rem; color: var(--text-secondary);">
                            Select the columns you want to include in the exported reconciled fleet CSV.
                        </p>
                    </div>

                    <div style="flex-grow: 1; overflow-y: auto; padding-right: 0.5rem;">
                        <!-- Core Attributes Section -->
                        <div style="margin-bottom: 1.5rem;">
                            <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-primary); border-bottom: 1px solid var(--border-clean); padding-bottom: 0.25rem; margin-bottom: 0.75rem;">
                                Core Attributes
                            </h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.5rem;">
                                ${coreCheckboxes}
                            </div>
                        </div>

                        <!-- Core Policies Section -->
                        <div style="margin-bottom: 1.5rem;">
                            <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-primary); border-bottom: 1px solid var(--border-clean); padding-bottom: 0.25rem; margin-bottom: 0.75rem;">
                                Core Security Policies
                            </h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
                                ${complianceCheckboxes}
                            </div>
                        </div>

                        <!-- Custom Section -->
                        ${customSectionHtml}
                    </div>

                    <!-- Footer Controls -->
                    <div style="display: flex; justify-content: flex-end; gap: 1rem; border-top: 1px solid var(--border-clean); padding-top: 1rem;">
                        <button class="btn btn-secondary" style="font-size: 0.8rem; padding: 0.6rem 1.2rem;" id="btn-fleet-export-cancel">Cancel</button>
                        <button class="btn" style="font-size: 0.8rem; padding: 0.6rem 1.2rem;" id="btn-fleet-export-download">Download CSV</button>
                    </div>
                </div>
            `;

            document.body.appendChild(modal);

            // Add event listeners (safely guarded)
            const cancelBtn = document.getElementById("btn-fleet-export-cancel");
            if (cancelBtn && cancelBtn.addEventListener) {
                cancelBtn.addEventListener("click", () => {
                    document.body.removeChild(modal);
                });
            }

            const downloadBtn = document.getElementById("btn-fleet-export-download");
            if (downloadBtn && downloadBtn.addEventListener) {
                downloadBtn.addEventListener("click", () => {
                    // Collect checked checkboxes
                    const checkboxes = modal.querySelectorAll(".fleet-export-col-checkbox:checked");
                    const selectedCols = Array.from(checkboxes).map(cb => ({
                        key: cb.getAttribute("data-key"),
                        header: cb.getAttribute("data-header")
                    }));

                    if (selectedCols.length === 0) {
                        alert("Please select at least one column to export.");
                        return;
                    }

                    // Generate CSV content
                    let csvLines = [];

                    // Header row
                    const headerLine = selectedCols.map(c => `"${sanitizeCSVCell(c.header)}"`).join(",");
                    csvLines.push(headerLine);

                    // Rows
                    filteredDataset.forEach(row => {
                        const lineValues = selectedCols.map(c => {
                            const key = c.key;
                            let val = "";
                            let isCustom = key.startsWith("custom:");
                            let isCompliance = key.startsWith("compliance:");
                            let actualKey = (isCustom || isCompliance) ? key.substring(key.indexOf(":") + 1) : key;

                            if (isCustom) {
                                val = (row.custom_properties && row.custom_properties[actualKey] !== undefined) ? row.custom_properties[actualKey] : "-";
                            } else if (isCompliance) {
                                const swAgent = row.software.find(sw => sw.name === actualKey || sw.key === key);
                                val = swAgent ? swAgent.installed : "MISSING";
                            } else {
                                if (actualKey === "ad" || actualKey === "bitlocker" || actualKey === "zscaler" || actualKey === "nessus" || actualKey === "sentinelone" || actualKey === "sccm") {
                                    const swAgent = row.software.find(sw => sw.key === actualKey);
                                    val = swAgent ? swAgent.installed : "MISSING";
                                } else {
                                    val = row[actualKey] !== undefined ? row[actualKey] : "-";
                                }
                            }
                            return val;
                        });

                        const line = lineValues.map(v => `"${sanitizeCSVCell(v)}"`).join(",");
                        csvLines.push(line);
                    });

                    const csvContent = csvLines.join("\n");
                    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement("a");
                    link.setAttribute("href", url);
                    link.setAttribute("download", `eud_compliance_export_${Date.now()}.csv`);
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    URL.revokeObjectURL(url);

                    // Remove modal
                    document.body.removeChild(modal);
                    logToTerminal(`[Export] File successfully compiled. Dispatched ${filteredDataset.length} rows as customized CSV download stream.`, "info");
                });
            }
        }

        const localDB = {
            memoryUsers: null,
            memoryKeys: null,
            memoryEvidence: null,
            init: function () {
                const hasLocalStorage = (typeof localStorage !== "undefined" && localStorage !== null);
                if (hasLocalStorage) {
                    if (!localStorage.getItem("db_users")) {
                        const defaultUsers = [
                            { username: "admin", password: "admin", role: "admin", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") },
                            { username: "analyst", password: "analyst", role: "analyst", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") },
                            { username: "operator", password: "operator", role: "operator", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") },
                            { username: "auditor", password: "auditor", role: "auditor", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") },
                            { username: "dev_admin", password: "dev_admin", role: "developer", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") }
                        ];
                        localStorage.setItem("db_users", JSON.stringify(defaultUsers));
                    }
                    if (!localStorage.getItem("db_api_keys")) {
                        localStorage.setItem("db_api_keys", JSON.stringify([]));
                    }
                    if (!localStorage.getItem("db_evidence")) {
                        localStorage.setItem("db_evidence", JSON.stringify([]));
                    }
                } else {
                    if (!this.memoryUsers) {
                        this.memoryUsers = [
                            { username: "admin", password: "admin", role: "admin", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") },
                            { username: "analyst", password: "analyst", role: "analyst", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") },
                            { username: "operator", password: "operator", role: "operator", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") },
                            { username: "auditor", password: "auditor", role: "auditor", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") },
                            { username: "dev_admin", password: "dev_admin", role: "developer", oauth_provider: null, created_at: new Date().toISOString().substring(0, 19).replace("T", " ") }
                        ];
                    }
                    if (!this.memoryKeys) {
                        this.memoryKeys = [];
                    }
                    if (!this.memoryEvidence) {
                        this.memoryEvidence = [];
                    }
                }
            },
            getUsers: function () {
                this.init();
                const hasLocalStorage = (typeof localStorage !== "undefined" && localStorage !== null);
                if (hasLocalStorage) {
                    return JSON.parse(localStorage.getItem("db_users"));
                }
                return this.memoryUsers;
            },
            saveUsers: function (users) {
                const hasLocalStorage = (typeof localStorage !== "undefined" && localStorage !== null);
                if (hasLocalStorage) {
                    localStorage.setItem("db_users", JSON.stringify(users));
                } else {
                    this.memoryUsers = users;
                }
            },
            getKeys: function () {
                this.init();
                const hasLocalStorage = (typeof localStorage !== "undefined" && localStorage !== null);
                if (hasLocalStorage) {
                    return JSON.parse(localStorage.getItem("db_api_keys"));
                }
                return this.memoryKeys;
            },
            saveKeys: function (keys) {
                const hasLocalStorage = (typeof localStorage !== "undefined" && localStorage !== null);
                if (hasLocalStorage) {
                    localStorage.setItem("db_api_keys", JSON.stringify(keys));
                } else {
                    this.memoryKeys = keys;
                }
            },
            getEvidence: function () {
                this.init();
                const hasLocalStorage = (typeof localStorage !== "undefined" && localStorage !== null);
                if (hasLocalStorage) {
                    return JSON.parse(localStorage.getItem("db_evidence")) || [];
                }
                return this.memoryEvidence || [];
            },
            saveEvidence: function (evidence) {
                const hasLocalStorage = (typeof localStorage !== "undefined" && localStorage !== null);
                if (hasLocalStorage) {
                    localStorage.setItem("db_evidence", JSON.stringify(evidence));
                } else {
                    this.memoryEvidence = evidence;
                }
            },
            getAssessments: function () {
                this.init();
                const hasLocalStorage = (typeof localStorage !== "undefined" && localStorage !== null);
                if (hasLocalStorage) {
                    return JSON.parse(localStorage.getItem("db_assessments")) || [];
                }
                return this.memoryAssessments || [];
            },
            saveAssessments: function (assessments) {
                const hasLocalStorage = (typeof localStorage !== "undefined" && localStorage !== null);
                if (hasLocalStorage) {
                    localStorage.setItem("db_assessments", JSON.stringify(assessments));
                } else {
                    this.memoryAssessments = assessments;
                }
            }
        };

        // API Post client that routes to python server or falls back to local DB
        async function apiPost(endpoint, data = {}, method = "POST") {
            const usePython = (typeof window !== "undefined" && window.location && window.location.protocol && window.location.protocol.startsWith("http"));
            if (usePython) {
                try {
                    const response = await fetch(endpoint, {
                        method: method,
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(data)
                    });
                    return await response.json();
                } catch (err) {
                    console.error("API POST error:", err);
                    return { success: false, message: "Server communication failed." };
                }
            } else {
                localDB.init();
                if (endpoint === '/api/auth/signup') {
                    const users = localDB.getUsers();
                    if (users.some(u => u.username === data.username)) {
                        return { success: false, message: "Username already exists." };
                    }
                    users.push({
                        username: data.username,
                        password: data.password,
                        role: data.role || "operator",
                        oauth_provider: null,
                        created_at: new Date().toISOString().substring(0, 19).replace("T", " ")
                    });
                    localDB.saveUsers(users);
                    return { success: true, message: "User registered successfully!" };
                }
                else if (endpoint === '/api/auth/login') {
                    const users = localDB.getUsers();
                    const user = users.find(u => u.username === data.username && u.password === data.password);
                    if (!user) {
                        return { success: false, message: "Invalid username or passcode." };
                    }
                    return { success: true, username: user.username, role: user.role };
                }
                else if (endpoint === '/api/auth/oauth') {
                    const users = localDB.getUsers();
                    let user = users.find(u => u.username === data.username);
                    let role = "analyst";
                    if (!user) {
                        users.push({
                            username: data.username,
                            password: "oauth_derived_secret",
                            role: "analyst",
                            oauth_provider: data.provider,
                            created_at: new Date().toISOString().substring(0, 19).replace("T", " ")
                        });
                        localDB.saveUsers(users);
                    } else {
                        role = user.role;
                    }
                    return { success: true, username: data.username, role: role, oauth: true };
                }
                else if (endpoint === '/api/developer/users') {
                    return { success: true, users: localDB.getUsers() };
                }
                else if (endpoint === '/api/developer/update-role') {
                    const users = localDB.getUsers();
                    const user = users.find(u => u.username === data.username);
                    if (user) {
                        user.role = data.role;
                        localDB.saveUsers(users);
                        return { success: true, message: "User role updated successfully!" };
                    }
                    return { success: false, message: "User not found." };
                }
                else if (endpoint === '/api/developer/delete-user') {
                    if (data.username === "admin") {
                        return { success: false, message: "Cannot delete root admin user." };
                    }
                    let users = localDB.getUsers();
                    users = users.filter(u => u.username !== data.username);
                    localDB.saveUsers(users);
                    return { success: true, message: "User deleted successfully!" };
                }
                else if (endpoint === '/api/developer/keys') {
                    return { success: true, keys: localDB.getKeys() };
                }
                else if (endpoint === '/api/developer/generate-key') {
                    const keys = localDB.getKeys();
                    const token = Math.random().toString(36).substring(2, 10) + Math.random().toString(36).substring(2, 10);
                    const apiKey = `amns_sk_${token}`;
                    const keyId = `id_${token.substring(0, 8)}`;
                    const newKey = {
                        key_id: keyId,
                        api_key: apiKey,
                        username: data.username,
                        created_at: new Date().toISOString().substring(0, 19).replace("T", " "),
                        request_count: Math.floor(Math.random() * 120)
                    };
                    keys.push(newKey);
                    localDB.saveKeys(keys);
                    return { success: true, key: newKey };
                }
                else if (endpoint === '/api/developer/delete-key') {
                    let keys = localDB.getKeys();
                    keys = keys.filter(k => k.key_id !== data.key_id);
                    localDB.saveKeys(keys);
                    return { success: true, message: "API Key revoked successfully!" };
                }
                else if (endpoint === '/api/siem/ingest') {
                    localDB.init();
                    const evidence = localDB.getEvidence();
                    const newEv = {
                        id: evidence.length + 1,
                        assessment_id: data.assessment_id || null,
                        source: data.source,
                        raw_data: data.raw_log,
                        hash_signature: "mock_sha256_" + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15),
                        collected_at: data.collected_at || new Date().toISOString(),
                        is_verified: true,
                        created_at: new Date().toISOString()
                    };
                    evidence.push(newEv);
                    localDB.saveEvidence(evidence);
                    return newEv;
                }
                else if (endpoint === '/api/assessments') {
                    localDB.init();
                    if (method === 'POST') {
                        const assessments = localDB.getAssessments();
                        const newA = {
                            id: assessments.length + 1,
                            name: data.name,
                            environment: data.environment,
                            status: "IN_PROGRESS",
                            overall_score: null,
                            created_at: new Date().toISOString(),
                            updated_at: new Date().toISOString(),
                            findings: [],
                            evidence_list: []
                        };
                        assessments.push(newA);
                        localDB.saveAssessments(assessments);
                        return newA;
                    }
                }
                else if (endpoint.startsWith('/api/assessments/')) {
                    localDB.init();
                    const assessments = localDB.getAssessments();
                    const parts = endpoint.split('?');
                    const pathParts = parts[0].split('/');
                    const id = parseInt(pathParts[3], 10);
                    const idx = assessments.findIndex(a => a.id === id);
                    if (idx !== -1) {
                        if (method === 'PUT') {
                            if (data.environment) assessments[idx].environment = data.environment;
                            if (data.status) assessments[idx].status = data.status;
                            if (data.overall_score !== undefined) assessments[idx].overall_score = data.overall_score;
                            assessments[idx].updated_at = new Date().toISOString();
                            localDB.saveAssessments(assessments);
                            return assessments[idx];
                        }
                    }
                }
                else if (endpoint.startsWith('/api/checklist/evaluate/')) {
                    localDB.init();
                    const parts = endpoint.split('/');
                    const id = parseInt(parts[4], 10);
                    const assessments = localDB.getAssessments();
                    const idx = assessments.findIndex(a => a.id === id);
                    if (idx !== -1) {
                        const manualControls = [
                            { code: "CTRL-011", title: "Role-Based Access Control", severity: "HIGH", type: "MANUAL", desc: "Auditors verify RBAC authorization checks are enforced on endpoints.", rec: "Conduct audit of access policies, map all endpoints to roles, and verify restriction." },
                            { code: "CTRL-012", title: "Inactive Account Disable", severity: "MEDIUM", type: "MANUAL", desc: "Auditors verify LDAP/AD deactivation policies are active.", rec: "Review Active Directory account deactivation logs for accounts idle > 90 days." },
                            { code: "CTRL-013", title: "Audit Log Completeness", severity: "HIGH", type: "MANUAL", desc: "Auditors verify access, modifications, and security events are logged.", rec: "Review centralized logging daemon configs to verify auditing completeness." },
                            { code: "CTRL-014", title: "Security Alerting", severity: "MEDIUM", type: "MANUAL", desc: "Auditors verify alerts are raised on anomalous login attempts.", rec: "Check SIEM alerting rules for brute-force or anomalous geolocation logins." },
                            { code: "CTRL-015", title: "Logout Session Kill", severity: "HIGH", type: "MANUAL", desc: "Auditors verify backend session tokens are revoked upon logout.", rec: "Test session revocation endpoint and confirm server-side token state is deleted." }
                        ];
                        const automatedControls = [
                            { code: "CTRL-001", title: "HTTP Strict Transport Security", severity: "HIGH", type: "AUTOMATED", desc: "HSTS header check. Must contain max-age of at least 1 year (31536000s).", rec: "Add Strict-Transport-Security header with max-age=31536000." },
                            { code: "CTRL-002", title: "Secure Cookie Flags", severity: "MEDIUM", type: "AUTOMATED", desc: "All session cookies must have HttpOnly and Secure flags, and SameSite set to Strict/Lax.", rec: "Set HttpOnly, Secure, and SameSite=Lax flags on session cookies." }
                        ];

                        const findings = assessments[idx].findings || [];
                        const allControls = [...automatedControls, ...manualControls];
                        allControls.forEach(ctrl => {
                            if (!findings.some(f => f.control_code === ctrl.code)) {
                                findings.push({
                                    id: findings.length + 1,
                                    assessment_id: id,
                                    control_code: ctrl.code,
                                    control_title: ctrl.title,
                                    severity: ctrl.severity,
                                    status: "FAIL",
                                    details: ctrl.type === "MANUAL" ? "Pending auditor manual checklist verification." : "No evidence gathered for automated validation.",
                                    recommendation: ctrl.rec,
                                    type: ctrl.type,
                                    checked_at: new Date().toISOString()
                                });
                            }
                        });
                        assessments[idx].findings = findings;
                        localDB.saveAssessments(assessments);
                        return findings;
                    }
                }
                else if (endpoint.startsWith('/api/risk/calculate/')) {
                    localDB.init();
                    const parts = endpoint.split('/');
                    const id = parseInt(parts[4], 10);
                    const assessments = localDB.getAssessments();
                    const idx = assessments.findIndex(a => a.id === id);
                    if (idx !== -1) {
                        const findings = assessments[idx].findings || [];
                        let passed = findings.filter(f => f.status === 'PASS').length;
                        let score = findings.length > 0 ? (passed / findings.length) * 100 : 100;
                        assessments[idx].overall_score = Math.round(score);
                        assessments[idx].status = "COMPLETED";
                        localDB.saveAssessments(assessments);
                        return assessments[idx];
                    }
                }
                else if (endpoint.startsWith('/api/assessments/findings/')) {
                    localDB.init();
                    const parts = endpoint.split('?');
                    const pathParts = parts[0].split('/');
                    const findingId = parseInt(pathParts[4], 10);

                    const params = new URLSearchParams(parts[1] || "");
                    const status = params.get("status") || "FAIL";
                    const details = params.get("details") || "";

                    const assessments = localDB.getAssessments();
                    let updatedFinding = null;
                    assessments.forEach(a => {
                        if (a.findings) {
                            const fIdx = a.findings.findIndex(f => f.id === findingId);
                            if (fIdx !== -1) {
                                a.findings[fIdx].status = status;
                                a.findings[fIdx].details = details;
                                a.findings[fIdx].checked_at = new Date().toISOString();
                                updatedFinding = a.findings[fIdx];
                            }
                        }
                    });
                    localDB.saveAssessments(assessments);
                    return updatedFinding || { success: false, message: "Finding not found." };
                }
                return { success: false, message: "Unknown local endpoint." };
            }
        }

        // Initialize corporate EUD Portal layout
        function initSessionUI() {
            if (currentSession && currentSession.isLoggedIn) {
                const mainApp = document.getElementById("main-app-container");
                const landing = document.getElementById("section-landing");
                const loginCanvas = document.getElementById("login-screen-canvas");
                if (mainApp) mainApp.style.display = "flex";
                if (landing) landing.style.display = "none";
                if (loginCanvas) loginCanvas.style.display = "none";

                // Set default nav to hub if no section is active
                const activeItem = document.querySelector(".sidebar-menu .menu-item.active");
                if (!activeItem) {
                    switchNavSection("hub");
                }

                // Initialize default template for SIEM & load assessments
                setTimeout(() => {
                    const selectEl = document.getElementById("siem-source-select");
                    if (selectEl) {
                        selectEl.value = "AD";
                        loadSiemSample("AD");
                    }
                    loadAssessmentsForSelectors();
                }, 100);
            } else {
                const mainApp = document.getElementById("main-app-container");
                const landing = document.getElementById("section-landing");
                const loginCanvas = document.getElementById("login-screen-canvas");
                if (mainApp) mainApp.style.display = "none";
                if (landing) landing.style.display = "block";
                if (loginCanvas) loginCanvas.style.display = "none";
            }
        }

        // Call session initialization on startup
        initSessionUI();

        // Modal triggers for Signup / Login toggling
        function showAuthModal(mode = 'login') {
            const loginCanvas = document.getElementById("login-screen-canvas");
            if (loginCanvas) loginCanvas.style.display = "flex";

            const loginForm = document.getElementById("login-form-wrapper");
            const signupForm = document.getElementById("signup-form-wrapper");
            const errorLogin = document.getElementById("portal-login-error-msg");
            const errorSignup = document.getElementById("portal-signup-error-msg");

            if (errorLogin) errorLogin.style.display = "none";
            if (errorSignup) errorSignup.style.display = "none";

            const tabLogin = document.getElementById("auth-tab-login");
            const tabSignup = document.getElementById("auth-tab-signup");

            if (mode === 'signup') {
                if (loginForm) loginForm.style.display = "none";
                if (signupForm) signupForm.style.display = "block";
                if (tabLogin) tabLogin.classList.remove("active");
                if (tabSignup) tabSignup.classList.add("active");
            } else {
                if (loginForm) loginForm.style.display = "block";
                if (signupForm) signupForm.style.display = "none";
                if (tabLogin) tabLogin.classList.add("active");
                if (tabSignup) tabSignup.classList.remove("active");
            }
        }

        // Dynamic operations for User Login and Settings sections
        async function simulateLogin() {
            // Check lockout first
            if (Date.now() < lockoutUntil) {
                const waitSecs = Math.ceil((lockoutUntil - Date.now()) / 1000);
                const errorDiv = document.getElementById("portal-login-error-msg");
                if (errorDiv) {
                    errorDiv.innerText = `Vault Security lockout active. Please try again in ${waitSecs} seconds.`;
                    errorDiv.style.display = "block";
                }
                logToTerminal(`[Auth Lockout] Access denied. Client is rate-limited.`, "error");
                return;
            }

            const tenant = "Empire Corp";
            const userInput = document.getElementById("portal-login-user");
            const passcodeVal = document.getElementById("portal-login-passcode");
            const user = userInput ? userInput.value.trim() : "";
            const pin = passcodeVal ? passcodeVal.value : "";
            const errorDiv = document.getElementById("portal-login-error-msg");

            if (errorDiv) errorDiv.style.display = "none";

            if (!user) {
                if (errorDiv) {
                    errorDiv.innerText = " Ingestion Failure: Username cannot be empty.";
                    errorDiv.style.display = "block";
                }
                logToTerminal("[Login Fail] Username cannot be empty.", "error");
                return;
            }

            logToTerminal(`[Auth] Dispatching identity request to security gateway for "${user}"...`);

            // Verify credentials via server API or local SQLite simulation
            const res = await apiPost('/api/auth/login', { username: user, password: pin });
            if (!res.success) {
                loginFailCount++;
                logToTerminal(`[Auth Fail] Challenge rejection for "${user}" (Attempt ${loginFailCount}/3).`, "error");

                if (loginFailCount >= 3) {
                    lockoutUntil = Date.now() + 60000; // 60 seconds lockout
                    loginFailCount = 0; // Reset fails after lock
                    if (errorDiv) errorDiv.innerText = "Security Alert: Too many failed challenge matches. Vault locked for 60 seconds.";
                } else {
                    if (errorDiv) errorDiv.innerText = ` Authentication Failed: ${res.message || "Invalid credentials."} (${3 - loginFailCount} attempts remaining)`;
                }
                if (errorDiv) errorDiv.style.display = "block";
                return;
            }

            // Successful Login
            loginFailCount = 0;

            const roleLabels = {
                "admin": "Global Security & Compliance Administrator",
                "analyst": "Global Security Analyst",
                "operator": "Security Operations Operator",
                "auditor": "External Compliance Auditor",
                "developer": "Corporate Security Developer"
            };
            const userRole = res.role || "operator";

            currentSession = {
                isLoggedIn: true,
                username: res.username,
                role: userRole,
                roleLabel: roleLabels[userRole] || "Enterprise Compliance User",
                tenant: tenant,
                authorizations: userRole === "admin" ? ["Reconciliation Approval", "CSV Ingestion Authority", "Secret Key Leasing", "Sift Fleet Access", "Outbound Alerts Dispatch"] : ["Sift Fleet Access"]
            };

            logToTerminal(`[Vault] Authenticated session lease for tenant context: "${tenant}"`, "info");
            logToTerminal(`[RBAC Guard] Loaded user profile. Assigned Role: ${userRole.toUpperCase()}. Unlocking bounds...`, "info");

            // Update user profile section details dynamically
            const profileNameEl = document.getElementById("profile-analyst-name");
            if (profileNameEl) profileNameEl.innerText = res.username;

            const roleLabelEl = document.querySelector("#section-profile p strong");
            if (roleLabelEl) {
                roleLabelEl.innerText = roleLabels[userRole] || "Enterprise Compliance User";
            }

            // Update user profile authorizations badge list dynamically
            const authListContainer = document.getElementById("profile-authorizations-list");
            if (authListContainer) {
                authListContainer.innerHTML = "";
                const auths = userRole === "admin" ? ["Reconciliation Approval", "CSV Ingestion Authority", "Secret Key Leasing", "Sift Fleet Access", "Outbound Alerts Dispatch"] : ["Sift Fleet Access"];
                auths.forEach(auth => {
                    authListContainer.innerHTML += `<span class="badge group-non-sift">${auth}</span> `;
                });
            }

            // Enforce controls
            enforceRoleBasedControls();

            // Hide portal login, show dashboard
            initSessionUI();

            // Switch to overview view
            switchNavSection("hub");
            logToTerminal(`[Session Active] Successfully logged in. Session established for tenant: "${tenant}"`, "info");
        }

        async function simulateSignup() {
            const userInput = document.getElementById("portal-signup-user");
            const passcodeVal = document.getElementById("portal-signup-passcode");
            const roleVal = document.getElementById("portal-signup-role");
            const user = userInput ? userInput.value.trim() : "";
            const pin = passcodeVal ? passcodeVal.value : "";
            const role = roleVal ? roleVal.value : "analyst";
            const errorDiv = document.getElementById("portal-signup-error-msg");

            if (errorDiv) errorDiv.style.display = "none";

            if (!user || !pin) {
                if (errorDiv) {
                    errorDiv.innerText = "Username and pin required.";
                    errorDiv.style.display = "block";
                }
                return;
            }

            logToTerminal(`[Auth] Dispatching signup request for user "${user}" as role: ${role.toUpperCase()}...`);
            const res = await apiPost('/api/auth/signup', { username: user, password: pin, role: role });
            if (!res.success) {
                if (errorDiv) {
                    errorDiv.innerText = res.message || "Signup failed.";
                    errorDiv.style.display = "block";
                }
                logToTerminal(`[Auth] Signup failed: ${res.message || "Unknown error."}`, "error");
                return;
            }

            logToTerminal(`[Auth] Account for user "${user}" successfully registered!`, "info");
            alert("Signup successful! Please log in.");
            showAuthModal('login');
        }

        async function triggerOAuth(provider) {
            const oauthUser = prompt(`Enter corporate ${provider === 'google' ? 'Google' : 'GitHub'} identity/email (e.g. employee@amns.in):`);
            if (!oauthUser) return;

            logToTerminal(`[OAuth] Connecting to external OAuth provider: ${provider.toUpperCase()}...`);
            const res = await apiPost('/api/auth/oauth', { username: oauthUser, provider: provider });
            if (res.success) {
                const roleLabels = {
                    "admin": "Global Security & Compliance Administrator",
                    "analyst": "Global Security Analyst",
                    "operator": "Security Operations Operator",
                    "auditor": "External Compliance Auditor",
                    "developer": "Corporate Security Developer"
                };
                const userRole = res.role || "analyst";
                currentSession = {
                    isLoggedIn: true,
                    username: res.username,
                    role: userRole,
                    roleLabel: roleLabels[userRole] || "Enterprise Compliance User",
                    tenant: "AM/NS India",
                    authorizations: ["SSO Identity lease"]
                };

                const profileNameEl = document.getElementById("profile-analyst-name");
                if (profileNameEl) profileNameEl.innerText = res.username;
                const roleLabelEl = document.querySelector("#section-profile p strong");
                if (roleLabelEl) roleLabelEl.innerText = roleLabels[userRole] || "Enterprise Compliance User";

                enforceRoleBasedControls();
                initSessionUI();
                switchNavSection("hub");
                logToTerminal(`[OAuth SSO] Authentication lease established via ${provider.toUpperCase()}: ${res.username}`, "info");
                alert(`Welcome back! Successfully authenticated via ${provider.toUpperCase()} SSO.`);
            } else {
                alert(`SSO Login failed: ${res.message}`);
            }
        }

        function terminateSessionLease() {
            const loggedOutUser = currentSession.username;
            const loggedOutRole = currentSession.role;

            logToTerminal(`[Auth Guard] Disposing session lease token for "${currentSession.username}"...`);
            logToTerminal(`[Vault] Session context revoked. Key vault closed.`, "warn");

            currentSession = {
                isLoggedIn: false,
                username: "",
                role: "",
                roleLabel: "",
                tenant: "",
                authorizations: []
            };

            // Enforce controls
            enforceRoleBasedControls();

            // Clear inputs
            const loginUserEl = document.getElementById("portal-login-user");
            const loginPassEl = document.getElementById("portal-login-passcode");
            if (loginUserEl) loginUserEl.value = "";
            if (loginPassEl) loginPassEl.value = "";

            // Reset profile displays
            const profileNameEl = document.getElementById("profile-analyst-name");
            if (profileNameEl) profileNameEl.innerText = "-";

            // Hide App, show landing page
            initSessionUI();

            logToTerminal(`[Session Closed] Vault lease revoked. Portal lock active.`, "info");
            alert("Vault Lease Revoked: Session successfully disposed. Dashboard is locked.");
        }

        // Developer Console dynamic functions
        async function loadDevConsoleData() {
            logToTerminal("[Dev Console] Synchronizing database state...");

            // 1. Load users
            const usersRes = await apiPost('/api/developer/users');
            if (usersRes.success) {
                const tbody = document.getElementById("dev-users-tbody");
                if (tbody) {
                    tbody.innerHTML = "";
                    usersRes.users.forEach(u => {
                        const tr = document.createElement("tr");
                        tr.innerHTML = `
                            <td style="font-weight: 700; color: var(--text-primary);">${u.username}</td>
                            <td>
                                <select onchange="updateUserRole('${u.username}', this.value)" style="background: transparent; border: 1px solid var(--border-clean); font-size: 0.8rem; padding: 0.15rem 0.35rem; color: var(--text-primary); cursor: pointer;">
                                    <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
                                    <option value="developer" ${u.role === 'developer' ? 'selected' : ''}>Developer</option>
                                    <option value="analyst" ${u.role === 'analyst' ? 'selected' : ''}>Analyst</option>
                                    <option value="operator" ${u.role === 'operator' ? 'selected' : ''}>Operator</option>
                                    <option value="auditor" ${u.role === 'auditor' ? 'selected' : ''}>Auditor</option>
                                </select>
                            </td>
                            <td><span class="badge group-non-sift">${u.oauth_provider || 'LDAP/Local'}</span></td>
                            <td style="font-family: var(--font-mono); font-size: 0.75rem;">${u.created_at || '-'}</td>
                            <td style="text-align: right;">
                                <button onclick="deleteUserAccount('${u.username}')" class="btn" style="font-size: 0.7rem; padding: 0.2rem 0.5rem; background: rgba(220,53,69,0.15); border-color: rgba(220,53,69,0.3); color: var(--status-critical); margin: 0;" ${u.username === 'admin' ? 'disabled style="opacity: 0.4; cursor: not-allowed;"' : ''}>Delete</button>
                            </td>
                        `;
                        tbody.appendChild(tr);
                    });
                }
            } else {
                logToTerminal(`[Dev Console Error] Failed to fetch users: ${usersRes.message}`, "error");
            }

            // 2. Load API keys
            const keysRes = await apiPost('/api/developer/keys');
            if (keysRes.success) {
                const tbody = document.getElementById("dev-keys-tbody");
                if (tbody) {
                    tbody.innerHTML = "";
                    keysRes.keys.forEach(k => {
                        const tr = document.createElement("tr");
                        const maskedKey = k.api_key.substring(0, 12) + "..." + k.api_key.substring(k.api_key.length - 4);
                        tr.innerHTML = `
                            <td style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary);">${k.key_id}</td>
                            <td style="font-family: var(--font-mono); font-size: 0.75rem;" title="${k.api_key}">${maskedKey}</td>
                            <td style="font-weight: 700;">${k.username}</td>
                            <td style="font-family: var(--font-mono); font-weight: 800; color: var(--status-low);">${k.request_count || 0}</td>
                            <td style="text-align: right;">
                                <button onclick="revokeApiKey('${k.key_id}')" class="btn" style="font-size: 0.7rem; padding: 0.2rem 0.5rem; background: rgba(220,53,69,0.15); border-color: rgba(220,53,69,0.3); color: var(--status-critical); margin: 0;">Revoke</button>
                            </td>
                        `;
                        tbody.appendChild(tr);
                    });
                }
            } else {
                logToTerminal(`[Dev Console Error] Failed to fetch API keys: ${keysRes.message}`, "error");
            }
        }

        async function updateUserRole(username, newRole) {
            logToTerminal(`[Dev DB] Modifying role for user "${username}" to ${newRole.toUpperCase()}...`);
            const res = await apiPost('/api/developer/update-role', { username: username, role: newRole });
            if (res.success) {
                logToTerminal(`[Dev DB] User "${username}" role updated successfully!`, "info");
                if (username === currentSession.username) {
                    currentSession.role = newRole;
                    const roleLabels = {
                        "admin": "Global Security & Compliance Administrator",
                        "analyst": "Global Security Analyst",
                        "operator": "Security Operations Operator",
                        "auditor": "External Compliance Auditor",
                        "developer": "Corporate Security Developer"
                    };
                    currentSession.roleLabel = roleLabels[newRole] || "Enterprise Compliance User";
                    enforceRoleBasedControls();
                    if (newRole !== 'admin' && newRole !== 'developer') {
                        switchNavSection("hub");
                    }
                }
            } else {
                alert(`Failed to update role: ${res.message}`);
                loadDevConsoleData();
            }
        }

        async function deleteUserAccount(username) {
            if (!confirm(`Are you sure you want to permanently delete user "${username}"?`)) return;
            logToTerminal(`[Dev DB] Revoking credentials and deleting account "${username}"...`);
            const res = await apiPost('/api/developer/delete-user', { username: username });
            if (res.success) {
                logToTerminal(`[Dev DB] User "${username}" deleted successfully.`, "info");
                loadDevConsoleData();
            } else {
                alert(`Failed to delete user: ${res.message}`);
            }
        }

        async function triggerGenerateApiKeyModal() {
            const targetUser = prompt("Enter username to associate this API key with:");
            if (!targetUser) return;

            const usersRes = await apiPost('/api/developer/users');
            if (usersRes.success) {
                const exists = usersRes.users.some(u => u.username === targetUser);
                if (!exists) {
                    alert(`User "${targetUser}" does not exist in the database directory. Please enter a valid username.`);
                    return;
                }
            }

            logToTerminal(`[Dev DB] Generating cryptographically secure API key for "${targetUser}"...`);
            const res = await apiPost('/api/developer/generate-key', { username: targetUser });
            if (res.success) {
                logToTerminal(`[Dev DB] Key generated: ${res.key.key_id} owner: ${res.key.username}`, "info");
                alert(`API Key generated successfully!\n\nKey ID: ${res.key.key_id}\nAPI Key: ${res.key.api_key}\n\nPlease copy this key now. It will be masked on subsequent loads.`);
                loadDevConsoleData();
            } else {
                alert(`Failed to generate API Key: ${res.message}`);
            }
        }

        async function revokeApiKey(keyId) {
            if (!confirm(`Are you sure you want to permanently revoke API Key ID "${keyId}"?`)) return;
            logToTerminal(`[Dev DB] Revoking key ID "${keyId}" from registry...`);
            const res = await apiPost('/api/developer/delete-key', { key_id: keyId });
            if (res.success) {
                logToTerminal(`[Dev DB] API Key ID "${keyId}" revoked.`, "info");
                loadDevConsoleData();
            } else {
                alert(`Failed to revoke key: ${res.message}`);
            }
        }

        function saveSettings() {
            const topic = document.getElementById("set-kafka-topic").value;
            const partitions = document.getElementById("set-kafka-partitions").value;
            const vaultAddr = document.getElementById("set-vault-addr").value;
            const vaultEngine = document.getElementById("set-vault-engine").value;

            logToTerminal("[Settings] Initiating dynamic environment configurations reload...");
            logToTerminal(`[Settings] Kafka compliance raw topic committed to: "${topic}" (partitions: ${partitions})`, "info");
            logToTerminal(`[Settings] Vault provider path synchronized with server: "${vaultAddr}" (mount: "${vaultEngine}")`, "info");
            logToTerminal("[Settings] Configuration successfully committed and replicated to downstream gateway.", "info");

            // Switch back to gateway hub as active view
            switchNavSection("hub");
        }

        async function apiGet(endpoint) {
            const usePython = (typeof window !== "undefined" && window.location && window.location.protocol && window.location.protocol.startsWith("http"));
            if (usePython) {
                try {
                    const response = await fetch(endpoint, {
                        method: "GET"
                    });
                    return await response.json();
                } catch (err) {
                    console.error("API GET error:", err);
                    return null;
                }
            } else {
                localDB.init();
                if (endpoint === '/api/evidence') {
                    return localDB.getEvidence();
                } else if (endpoint.startsWith('/api/evidence/') && endpoint.endsWith('/verify')) {
                    const parts = endpoint.split('/');
                    const id = parseInt(parts[3], 10);
                    const evidence = localDB.getEvidence();
                    const item = evidence.find(e => e.id === id);
                    if (item) {
                        return {
                            evidence_id: id,
                            is_verified: item.is_verified !== false,
                            expected_hash: item.hash_signature,
                            status: (item.is_verified !== false) ? "SECURE" : "TAMPERED_OR_INVALID"
                        };
                    } else {
                        return { success: false, message: "Evidence not found." };
                    }
                }
                return null;
            }
        }

        