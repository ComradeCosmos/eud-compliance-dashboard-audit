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

// Setup Dom elements
const elementsToMock = [
    'policies-governance-grid', 'policy-admin-alert', 'reporting-dashboard-content',
    'policy-count-all', 'policy-count-core', 'policy-count-excel',
    'fleet-scale-val', 'fleet-score-val', 'fleet-risk-label',
    'analytics-trend-chart-container', 'analytics-trend-legend', 'analytics-risk-chart-container',
    'analysis-chart-dimension', 'analysis-risk-dimension', 'audit-terminal',
    'fleet-table-head', 'fleet-table-body', 'pag-start', 'pag-end', 'pag-total',
    'btn-pag-prev', 'btn-pag-next', 'reconciler-queue-card', 'reconciler-queue-tbody',
    'btn-execute-reconciliation', 'recon-stat-matches', 'recon-stat-gaps', 'recon-stat-rogues',
    'recon-stat-match-rate', 'recon-tab-count-gaps', 'recon-tab-count-rogues', 'recon-tab-count-matches',
    'recon-table-head', 'recon-table-body'
];
elementsToMock.forEach(id => createMockElement(id));

const matchesWidget = domElements['recon-stat-matches'];
const matchesParent = createMockElement('recon-stat-matches-parent');
matchesParent.appendChild(matchesWidget);

const domMock = {
    console: console,
    setTimeout: setTimeout,
    setInterval: setInterval,
    clearTimeout: clearTimeout,
    clearInterval: clearInterval,
    window: {},
    document: {
        getElementById: (id) => {
            if (!domElements[id]) createMockElement(id);
            return domElements[id];
        },
        querySelector: (sel) => {
            return { style: {} };
        },
        querySelectorAll: () => [],
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

try {
    vm.runInContext(jsCode, context, { filename: 'script-1.js' });
    vm.runInContext(`
        currentSession.isLoggedIn = true;
        currentSession.username = "admin.security";
        currentSession.role = "admin";
        
        fleetDataset = [
            {
                id: "dev-exist-matched",
                canonical_name: "dell-eud-1001",
                serial: "SN-DELL-EXIST",
                mac: "00:1A:2B:3C:4D:5E",
                manufacturer: "Dell Inc.",
                os: "Windows 11 Enterprise",
                os_family: "Windows",
                score: 100.00,
                level: "COMPLIANT",
                condition: "IN_USE",
                user_assigned: "test.user",
                last_login: "2026-05-27 10:00",
                location: "Corporate Head Office",
                location_group: "Sift",
                is_isolated: false,
                software: [
                    { name: "Active Directory (AD) Enrollment", key: "ad", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" },
                    { name: "BitLocker Drive Encryption", key: "bitlocker", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" },
                    { name: "Zscaler Client Connector", key: "zscaler", installed: "MISSING", required: "REQUIRED", status: "NON_COMPLIANT" },
                    { name: "Nessus Vulnerability Agent", key: "nessus", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" },
                    { name: "SentinelOne Endpoint Protection", key: "sentinelone", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" },
                    { name: "SCCM Management Agent", key: "sccm", installed: "INSTALLED", required: "REQUIRED", status: "COMPLIANT" }
                ],
                custom_properties: {}
            }
        ];
        
        reconcilerSheets = [
            {
                id: 'sheet-primary',
                filename: 'corporate_directory.csv',
                headers: ['Device Name', 'Asset Tag', 'Department'],
                rows: [
                    ['DELL-EUD-1001', 'AT-12001', 'Engineering'],
                    ['DELL-EUD-1002', 'AT-12002', 'Product']
                ],
                keyIdx: 0,
                role: 'primary'
            },
            {
                id: 'sheet-secondary',
                filename: 'zscaler_telemetry.csv',
                headers: ['Hostname', 'Client Version', 'Connection Status'],
                rows: [
                    ['DELL-EUD-1001', 'v2026.1', 'CONNECTED'],
                    ['DELL-EUD-1002', 'v2026.1', 'CONNECTED']
                ],
                keyIdx: 0,
                role: 'secondary'
            }
        ];
        executeDeepReconciliation();
        mergeReconciliationIntoFleet();
        
        const newDev = fleetDataset.find(d => d.canonical_name.toLowerCase() === 'dell-eud-1002');
        console.log('--- newDev inspection ---');
        console.log(JSON.stringify(newDev, null, 2));
        
        console.log('--- running single score calculation manually ---');
        const policies = getAvailablePolicies();
        recalculateSingleDeviceScore(newDev, policies);
        console.log('newDev score after recalculate:', newDev.score, newDev.level);
        
        console.log('--- checking failing controls ---');
        const failed = getFailedControlsForDevice(newDev);
        console.log('failed controls:', failed);
    `, context);
} catch (err) {
    console.error('Error:', err.message);
    console.error(err.stack);
}
