const fs = require('fs');
const path = require('path');
const vm = require('vm');

const htmlPath = path.join(__dirname, '..', 'frontend', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

const scriptRegex = /<script>([\s\S]*?)<\/script>/gi;
let match = scriptRegex.exec(html);
const jsCode = match[1];

// Detailed DOM mocks to support dynamic operations
const domElements = {};

function createMockElement(id, tagName = 'div') {
    const el = {
        id: id,
        tagName: tagName.toUpperCase(),
        style: {},
        attributes: {},
        innerHTML: '',
        innerText: '',
        value: id.includes('filter') ? 'ALL' : '',
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
        parentElement: null
    };
    domElements[id] = el;
    return el;
}

// Pre-create required elements
createMockElement('policies-governance-grid');
createMockElement('policy-admin-alert');
createMockElement('reporting-dashboard-content');
createMockElement('policy-count-all');
createMockElement('policy-count-core');
createMockElement('policy-count-excel');
createMockElement('fleet-scale-val');
createMockElement('fleet-score-val');
createMockElement('fleet-risk-label');
createMockElement('analytics-trend-chart-container');
createMockElement('analytics-trend-legend');
createMockElement('analytics-risk-chart-container');
createMockElement('analysis-chart-dimension');
createMockElement('analysis-risk-dimension');

// Reconciler elements
createMockElement('reconciler-queue-card');
createMockElement('reconciler-queue-tbody');
createMockElement('btn-execute-reconciliation');
const matchesWidget = createMockElement('recon-stat-matches');
const matchesParent = createMockElement('recon-stat-matches-parent');
matchesParent.appendChild(matchesWidget); // links parentElement

createMockElement('recon-stat-gaps');
createMockElement('recon-stat-rogues');
createMockElement('recon-stat-match-rate');
createMockElement('recon-tab-count-gaps');
createMockElement('recon-tab-count-rogues');
createMockElement('recon-tab-count-matches');
createMockElement('reconciler-results-wrapper');
createMockElement('btn-recon-tab-gaps');
createMockElement('btn-recon-tab-rogues');
createMockElement('btn-recon-tab-matches');
createMockElement('recon-table-head');
createMockElement('recon-table-body');

// Set values
domElements['analysis-chart-dimension'].value = 'trend';
domElements['analysis-risk-dimension'].value = 'risk';

const domMock = {
    console: {
        log: console.log,
        error: console.error,
        warn: console.warn
    },
    setTimeout: setTimeout,
    setInterval: () => {},
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
            if (sel.includes('label[for="csv-import-file"]')) return { style: {} };
            if (sel.includes('button[onclick="triggerCsvExport()"]')) return { style: {} };
            if (sel.includes('button[onclick="runReconciliationSimulation()"]')) return { style: {} };
            if (sel.includes('#recon-stat-matches')) return domElements['recon-stat-matches'];
            return { style: {} };
        },
        querySelectorAll: (sel) => {
            if (sel.includes('#section-risk .tab-btn')) {
                return [
                    domElements['policy-filter-btn-all'] || createMockElement('policy-filter-btn-all'),
                    domElements['policy-filter-btn-core'] || createMockElement('policy-filter-btn-core'),
                    domElements['policy-filter-btn-excel'] || createMockElement('policy-filter-btn-excel')
                ];
            }
            if (sel.includes('#section-reconciler .tab-btn')) {
                return [
                    domElements['btn-recon-tab-gaps'] || createMockElement('btn-recon-tab-gaps'),
                    domElements['btn-recon-tab-rogues'] || createMockElement('btn-recon-tab-rogues'),
                    domElements['btn-recon-tab-matches'] || createMockElement('btn-recon-tab-matches')
                ];
            }
            return [];
        },
        createElement: (tag) => createMockElement('temp-' + Math.random(), tag),
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
vm.runInContext(jsCode, context);

vm.runInContext(`
    // 1. Seed initial fleetDataset
    fleetDataset = [
        {
            id: "dev-test-1",
            canonical_name: "dell-eud-1001",
            serial: "SN-DELL-1001",
            mac: "00:1A:2B:3C:4D:5E",
            manufacturer: "Dell Inc.",
            os: "Windows 11 Enterprise",
            os_family: "Windows",
            score: 100.00,
            level: "COMPLIANT",
            condition: "IN_USE",
            software: [
                { name: "Active Directory", key: "ad", installed: "INSTALLED", status: "COMPLIANT" },
                { name: "BitLocker", key: "bitlocker", installed: "INSTALLED", status: "COMPLIANT" },
                { name: "Zscaler", key: "zscaler", installed: "INSTALLED", status: "COMPLIANT" },
                { name: "Nessus", key: "nessus", installed: "INSTALLED", status: "COMPLIANT" },
                { name: "SentinelOne", key: "sentinelone", installed: "INSTALLED", status: "COMPLIANT" },
                { name: "SCCM", key: "sccm", installed: "INSTALLED", status: "COMPLIANT" }
            ],
            custom_properties: {}
        }
    ];
    
    // 2. Set up reconcilerSheets
    // Use 'telemetry.csv' so getSheetSoftwareKey returns null.
    // The sheet only has Zscaler columns, but it has 'Connection Status' which has 'Status' in it.
    reconcilerSheets = [
        {
            id: 'sheet-primary',
            filename: 'corporate_directory.csv',
            headers: ['Device Name', 'Asset Tag', 'Department', 'Condition'],
            rows: [
                ['DELL-EUD-1001', 'AT-12001', 'Engineering', 'IN_USE']
            ],
            keyIdx: 0,
            role: 'primary'
        },
        {
            id: 'sheet-secondary',
            filename: 'telemetry.csv',
            headers: ['Hostname', 'Client Version', 'Connection Status'],
            rows: [
                ['DELL-EUD-1001', 'v2026.1', 'DISCONNECTED']
            ],
            keyIdx: 0,
            role: 'secondary'
        }
    ];

    console.log("Running reconciliation...");
    runLocalReconciliation();

    console.log("Merging reconciliation...");
    mergeReconciliationIntoFleet();

    const dev = fleetDataset[0];
    console.log("\\n--- Post-Merge Software Status ---");
    dev.software.forEach(sw => {
        console.log(sw.name + ": installed=" + sw.installed + ", status=" + sw.status);
    });
`, context);
