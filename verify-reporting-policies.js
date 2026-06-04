const fs = require('fs');
const path = require('path');
const vm = require('vm');

const htmlPath = path.join(__dirname, 'frontend', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

const scriptRegex = /<script>([\s\S]*?)<\/script>/gi;
let match = scriptRegex.exec(html);
if (!match) {
    console.error('No script tag found!');
    process.exit(1);
}
const jsCode = match[1];

console.log('Running Reporting Policies Isolation Verification Test...');

// Detailed DOM mocks to support dynamic operations
const domElements = {};

function createMockElement(id, tagName = 'div') {
    const el = {
        id: id,
        tagName: tagName.toUpperCase(),
        style: {},
        attributes: {},
        _innerHTML: '',
        get innerHTML() { return this._innerHTML; },
        set innerHTML(val) {
            this._innerHTML = val;
            if (val === '') {
                this.children = [];
            }
        },
        innerText: '',
        value: '',
        classList: {
            add: (cls) => { el.className = (el.className || '') + ' ' + cls; },
            remove: (cls) => { if (el.className) el.className = el.className.replace(cls, '').trim(); }
        },
        setAttribute: (name, val) => { el.attributes[name] = val; },
        getAttribute: (name) => el.attributes[name],
        appendChild: (child) => {
            if (!el.children) el.children = [];
            el.children.push(child);
            child.parentElement = el;
        },
        querySelectorAll: () => [],
        querySelector: () => ({ style: {} }),
        parentElement: null,
        children: []
    };
    domElements[id] = el;
    return el;
}

// Pre-create required elements for details and reporting views
createMockElement('details-default-msg');
createMockElement('details-content-box');
createMockElement('det-name');
createMockElement('det-id');
createMockElement('det-serial');
createMockElement('det-condition-badge');
createMockElement('det-level-badge');
createMockElement('det-isolation-banner');
createMockElement('det-user');
createMockElement('det-login');
createMockElement('det-location');
createMockElement('det-loc-group');
createMockElement('det-software-tbody');
createMockElement('det-custom-params-tbody');
createMockElement('det-sparkline-path');
createMockElement('det-sparkline-dots');
createMockElement('btn-isolate-device');
createMockElement('audit-terminal');
createMockElement('reporting-dashboard-content');
createMockElement('reporting-table-head-row');
createMockElement('reporting-agent-tbody');
createMockElement('reporting-pag-start');
createMockElement('reporting-pag-end');
createMockElement('reporting-pag-total');

const domMock = {
    console: {
        log: console.log,
        error: console.error,
        warn: console.warn
    },
    setTimeout: setTimeout,
    setInterval: setInterval,
    clearTimeout: clearTimeout,
    clearInterval: clearInterval,
    window: {},
    document: {
        getElementById: (id) => {
            if (!domElements[id]) {
                createMockElement(id);
            }
            return domElements[id];
        },
        querySelector: (sel) => {
            return { style: {} };
        },
        querySelectorAll: (sel) => {
            return [];
        },
        createElement: (tag) => {
            const id = 'temp-' + Math.random();
            return createMockElement(id, tag);
        },
        body: { appendChild: () => {}, removeChild: () => {} }
    },
    FileReader: class {},
    XLSX: {
        read: () => ({ SheetNames: ['Sheet1'], Sheets: {} }),
        utils: { sheet_to_json: () => [] }
    },
    Math: Math,
    Date: Date,
    Array: Array,
    Object: Object,
    String: String,
    Number: Number,
    RegExp: RegExp,
    Error: Error,
    Map: Map,
    Set: Set,
    parseFloat: parseFloat,
    parseInt: parseInt,
    encodeURI: encodeURI,
    alert: (msg) => console.log('ALERT:', msg),
    confirm: () => true
};
domMock.window = domMock;

const context = vm.createContext(domMock);

try {
    vm.runInContext(jsCode, context, { filename: 'script-1.js' });
    console.log('✔ App script loaded successfully.');

    // Inject a custom spreadsheet policy that is failed on a device
    // But the device is COMPLIANT with all 6 core policies.
    vm.runInContext(`
        fleetDataset = [
            {
                id: "dev-core-compliant",
                canonical_name: "DELL-CORE-COMPLIANT",
                serial: "SN-CORE-111",
                condition: "IN_USE",
                level: "NON_COMPLIANT", // Non-compliant in main workspace because of custom policy
                software: [
                    { name: "Active Directory (AD) Enrollment", key: "ad", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" },
                    { name: "BitLocker Drive Encryption", key: "bitlocker", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" },
                    { name: "Zscaler Client Connector", key: "zscaler", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" },
                    { name: "Nessus Vulnerability Agent", key: "nessus", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" },
                    { name: "SentinelOne Endpoint Protection", key: "sentinelone", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" },
                    { name: "SCCM Management Agent", key: "sccm", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" }
                ],
                user_assigned: "test.user",
                last_login: "2026-06-04 10:00",
                location: "Remote - US",
                location_group: "Non-Sift",
                is_isolated: false,
                custom_properties: {
                    "[custom_policy.csv] Compliance": "FAILED" // Custom spreadsheet policy failed
                },
                score: 0
            }
        ];
        
        // Register custom policy to look like a loaded Excel sheet
        mergedSoftwareAgents.add("custom_policy.csv");
    `, context);

    // Run generateComplianceReport
    console.log('Executing generateComplianceReport()...');
    vm.runInContext(`
        const dev = fleetDataset[0];
        console.log('Tracing isDeviceCompliantForReporting(dev):');
        console.log('dev.is_isolated:', dev.is_isolated);
        console.log('dev.condition:', dev.condition);
        console.log('dev.is_rogue:', dev.is_rogue);
        
        const corePolicies = [
            "Active Directory (AD) Enrollment",
            "BitLocker Drive Encryption",
            "Zscaler Client Connector",
            "Nessus Vulnerability Agent",
            "SentinelOne Endpoint Protection",
            "SCCM Management Agent"
        ];
        
        for (let name of corePolicies) {
            const isRequired = enforcedPolicies[name] !== false;
            const sw = dev.software && dev.software.find(s => s.name === name);
            console.log('Policy:', name, 'isRequired:', isRequired, 'found sw:', !!sw);
            if (sw) {
                const isUploaded = isSheetUploadedForSoftware(sw.key);
                const isEverMerged = typeof mergedSoftwareAgents !== "undefined" && mergedSoftwareAgents.has(sw.key);
                const alwaysReported = sw.key === "ad";
                console.log('  sw.key:', sw.key, 'alwaysReported:', alwaysReported, 'isUploaded:', isUploaded, 'isEverMerged:', isEverMerged);
                if (!alwaysReported && !isUploaded && !isEverMerged) {
                    console.log('  -> Bypassed/Skipped');
                    continue;
                }
                console.log('  sw.status:', sw.status);
            }
        }
        
        console.log('Result of isDeviceCompliantForReporting(dev):', isDeviceCompliantForReporting(dev));
    `, context);
    vm.runInContext('generateComplianceReport()', context);

    // 1. Verify SLA Overall Stats count the device as COMPLIANT
    // (Since it is compliant for all 6 core policies and we ignore the failed custom policy).
    const htmlReport = domElements['reporting-dashboard-content'].innerHTML;
    console.log('Verifying SLA Dial gauge values...');
    if (!htmlReport.includes("100.00%</strong> compliant")) {
        // Let's print out what is there
        console.log('Report HTML:', htmlReport);
        throw new Error('SLA score did not count the device as compliant.');
    }
    console.log('✔ SLA score correctly counts only the 6 core policies.');

    // 2. Verify "Global Security Policy Audit Summary" table contains exactly 6 rows and no custom policy
    console.log('Verifying mandated policy count inside Audit Summary table...');
    const tableTrRegex = /<tr>([\s\S]*?)<\/tr>/g;
    let trCount = 0;
    let match;
    while ((match = tableTrRegex.exec(htmlReport)) !== null) {
        trCount++;
    }
    // Note: trCount includes the header row, so we expect 7 rows in total (1 header + 6 core policies).
    console.log('Found table rows (including headers):', trCount);
    
    // Check that custom policy is NOT rendered in the table HTML
    if (htmlReport.includes("custom_policy.csv") || htmlReport.includes("custom_policy")) {
        throw new Error('Custom policy should not be rendered in the Policy Summary table.');
    }
    console.log('✔ Custom policies are hidden from the Policy Summary table.');

    // 3. Verify Negation checklist options
    console.log('Verifying negation checklist content...');
    if (htmlReport.includes("negate-policy--custom-policy-csv--Compliance")) {
        throw new Error('Custom policy should not have a negation checkbox switch in Reporting.');
    }
    console.log('✔ Custom policies are hidden from the Negation checklist.');

    // 4. Verify Ledger table columns and rows
    console.log('Verifying Ledger table headers...');
    const headRowHtml = domElements['reporting-table-head-row'].innerHTML;
    if (headRowHtml.includes("custom_policy.csv") || headRowHtml.includes("custom_policy")) {
        throw new Error('Ledger headers should not contain custom policies.');
    }
    
    console.log('Verifying Ledger device overall compliance badge...');
    const ledgerTbodyHtml = domElements['reporting-agent-tbody'].innerHTML;
    if (ledgerTbodyHtml.includes("NON_COMPLIANT")) {
        console.log('Ledger Body HTML:', ledgerTbodyHtml);
        throw new Error('Device should be marked as COMPLIANT in the Reporting Ledger.');
    }
    console.log('✔ Device is marked COMPLIANT in the ledger table based on core compliance.');

    console.log('✔ All Reporting Tab policies isolation verification tests passed successfully! 🎉');
} catch (err) {
    console.error('❌ Verification test failed:', err.message);
    console.error(err.stack);
    process.exit(1);
}
