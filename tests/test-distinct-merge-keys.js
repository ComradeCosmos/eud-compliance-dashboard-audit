const fs = require('fs');
const path = require('path');
const vm = require('vm');

const htmlPath = path.join(__dirname, '..', 'frontend', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

const scriptRegex = /<script>([\s\S]*?)<\/script>/gi;
let match = scriptRegex.exec(html);
if (!match) {
    console.error('No script tag found!');
    process.exit(1);
}
const jsCode = match[1];

// Detailed DOM mocks to support boot operations
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
createMockElement('audit-terminal');
createMockElement('fleet-table-head');
createMockElement('fleet-table-body');
createMockElement('pag-start');
createMockElement('pag-end');
createMockElement('pag-total');
createMockElement('btn-pag-prev');
createMockElement('btn-pag-next');
createMockElement('recon-table-head');
createMockElement('recon-table-body');
createMockElement('recon-tab-count-rogues');
createMockElement('recon-tab-count-matches');
createMockElement('recon-pag-start');
createMockElement('recon-pag-end');
createMockElement('recon-pag-total');
createMockElement('btn-recon-pag-prev');
createMockElement('btn-recon-pag-next');

const domMock = {
    console: console,
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
            if (sel.includes('label[for="csv-import-file"]')) return { style: {} };
            if (sel.includes('button[onclick="triggerCsvExport()"]')) return { style: {} };
            if (sel.includes('button[onclick="runReconciliationSimulation()"]')) return { style: {} };
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

// Run script code in VM to define EUD environment
vm.runInContext(jsCode, context);

console.log('Verifying Multi-Attribute Matching with Distinct Reconciliation Keys...');

vm.runInContext(`
    // 1. Reset fleet dataset with explicit serial numbers and MACs
    fleetDataset.length = 0;
    fleetDataset.push({
        id: "dev-primary-1002",
        canonical_name: "DELL-EUD-1002",
        serial: "SN-999-ABC",
        mac: "00:1A:2B:3C:4D:5E",
        manufacturer: "Dell",
        os: "Windows 11 Enterprise",
        os_family: "Windows",
        score: 100.00,
        level: "COMPLIANT",
        condition: "IN_USE",
        user_assigned: "test.user",
        last_login: "2026-06-01 12:00",
        location: "Corporate Office",
        location_group: "Sift",
        is_isolated: false,
        software: sampleSoftwareCatalog.map(sw => ({
            name: sw.name,
            key: sw.key,
            installed: "MISSING",
            required: "REQUIRED",
            status: "NON_COMPLIANT"
        }))
    });

    const initialFleetSize = fleetDataset.length;

    // 2. Setup mock sheets in reconciler
    reconcilerSheets.length = 0;
    reconcilerSheets.push({
        filename: "zscaler_report.csv",
        role: "secondary",
        headers: ["Serial Number", "Zscaler Status", "Client Version"],
        keyIdx: 0,
        data: [["SN-999-ABC", "ACTIVE", "5.2.1"]]
    });

    // 3. Populate matches in reconciliationResults targeting Serial Number
    reconciliationResults.matches = [
        {
            id: "match-s1",
            name: "SN-999-ABC",
            normalized: "sn999abc",
            mergedProperties: [
                { source: "zscaler_report.csv", sheetRole: "Secondary", property: "Zscaler Status", value: "ACTIVE" },
                { source: "zscaler_report.csv", sheetRole: "Secondary", property: "Client Version", value: "5.2.1" }
            ],
            sheets: [
                {
                    filename: "zscaler_report.csv",
                    row: ["SN-999-ABC", "ACTIVE", "5.2.1"],
                    headers: ["Serial Number", "Zscaler Status", "Client Version"],
                    keyIdx: 0
                }
            ],
            status: "MATCHED"
        }
    ];
    reconciliationResults.gaps = [];
    reconciliationResults.rogues = [];

    console.log('Initial Fleet Size:', initialFleetSize);
    console.log('Matches Count:', reconciliationResults.matches.length);

    // 4. Run mergeReconciliationIntoFleet
    console.log('Merging reconciliation with Serial Number key...');
    mergeReconciliationIntoFleet();

    console.log('Post-Merge Fleet Size:', fleetDataset.length);

    // 5. Verification checks
    if (fleetDataset.length !== initialFleetSize) {
        throw new Error("FAIL: Database duplicated entry instead of matching by Serial Number!");
    }

    const device = fleetDataset[0];
    console.log('Merged custom properties:', device.custom_properties);

    if (!device.custom_properties || device.custom_properties["[zscaler_report.csv] Zscaler Status"] !== "ACTIVE") {
        throw new Error("FAIL: Custom properties from secondary sheet were not successfully merged!");
    }

    console.log("✔ Multi-attribute identity resolution test passed cleanly! No duplicate entries created. 🎉");
`, context);
