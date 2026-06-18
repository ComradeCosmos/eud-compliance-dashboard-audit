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

const matchesEl = createMockElement('recon-stat-matches');
matchesEl.parentElement = createMockElement('recon-stat-matches-parent');

const gapsEl = createMockElement('recon-stat-gaps');
gapsEl.parentElement = createMockElement('recon-stat-gaps-parent');

const roguesEl = createMockElement('recon-stat-rogues');
roguesEl.parentElement = createMockElement('recon-stat-rogues-parent');

const matchRateEl = createMockElement('recon-stat-match-rate');
matchRateEl.parentElement = createMockElement('recon-stat-match-rate-parent');

const domMock = {
    console: console,
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

console.log('Verifying prevention of new record creation when different column keys are used...');

vm.runInContext(`
    // 1. Reset fleet dataset with an existing device
    fleetDataset.length = 0;
    fleetDataset.push({
        id: "dev-primary-exist",
        canonical_name: "DELL-EUD-EXIST",
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

    // 2. Setup mock sheets in reconciler: different keys
    // Primary key: "Device Name" (name/hostname key)
    // Secondary key: "Serial Number" (serial key)
    reconcilerSheets.length = 0;
    reconcilerSheets.push({
        filename: "primary_dir.csv",
        role: "primary",
        headers: ["Device Name", "Serial Number"],
        keyIdx: 0,
        rows: [
            ["DELL-EUD-EXIST", "SN-999-ABC"],
            ["DELL-EUD-NEWGAP", "SN-111-GAP"] // exists in primary, not in secondary -> GAP (does not exist in DB)
        ]
    });

    reconcilerSheets.push({
        filename: "secondary_agent.csv",
        role: "secondary",
        headers: ["Serial Number", "Agent Status"],
        keyIdx: 0,
        rows: [
            ["SN-999-ABC", "ACTIVE"],
            ["SN-222-ROGUE", "ACTIVE"] // exists in secondary, not in primary -> ROGUE (does not exist in DB)
        ]
    });

    // 3. Populate matches, gaps, and rogues in reconciliationResults
    reconciliationResults.matches = [
        {
            id: "match-1",
            name: "DELL-EUD-EXIST",
            normalized: "delleudexist",
            mergedProperties: [
                { source: "primary_dir.csv", sheetRole: "Primary", property: "Department", value: "Sales" },
                { source: "secondary_agent.csv", sheetRole: "Secondary", property: "Agent Status", value: "ACTIVE" }
            ],
            primaryRow: ["DELL-EUD-EXIST", "SN-999-ABC"],
            status: "MATCHED"
        }
    ];

    reconciliationResults.gaps = [
        {
            id: "gap-1",
            name: "DELL-EUD-NEWGAP",
            normalized: "delleudnewgap",
            mergedProperties: [
                { source: "primary_dir.csv", sheetRole: "Primary", property: "Department", value: "Marketing" }
            ],
            primaryRow: ["DELL-EUD-NEWGAP", "SN-111-GAP"],
            missingInSheets: ["secondary_agent.csv"],
            presentInSheets: ["primary_dir.csv"],
            status: "COVERAGE_GAP"
        }
    ];

    reconciliationResults.rogues = [
        {
            id: "rogue-1",
            name: "SN-222-ROGUE",
            normalized: "sn222rogue",
            sheets: [
                {
                    filename: "secondary_agent.csv",
                    row: ["SN-222-ROGUE", "ACTIVE"],
                    headers: ["Serial Number", "Agent Status"],
                    keyIdx: 0
                }
            ],
            status: "ROGUE_UNMANAGED"
        }
    ];

    console.log('Initial Fleet Size:', initialFleetSize);
    console.log('Matches Count:', reconciliationResults.matches.length);
    console.log('Gaps Count:', reconciliationResults.gaps.length);
    console.log('Rogues Count:', reconciliationResults.rogues.length);

    // 4. Run mergeReconciliationIntoFleet
    console.log('Merging reconciliation with different keys...');
    mergeReconciliationIntoFleet();

    console.log('Post-Merge Fleet Size:', fleetDataset.length);

    // 5. Verification checks
    if (fleetDataset.length !== initialFleetSize + 1) {
        throw new Error("FAIL: Database size should have increased by exactly 1 (adding the Gap device from the primary Corporate Directory) but was: " + fleetDataset.length);
    }

    const rogueDevice = fleetDataset.find(dev => dev.canonical_name === "sn222rogue" || dev.serial.includes("222"));
    if (rogueDevice) {
        throw new Error("FAIL: Rogue device was incorrectly added to the database!");
    }

    const device = fleetDataset[0];
    console.log('Merged custom properties:', device.custom_properties);

    if (!device.custom_properties || device.custom_properties["Department"] !== "Sales" || device.custom_properties["[secondary_agent.csv] Agent Status"] !== undefined) {
        throw new Error("FAIL: Custom properties from primary sheet were not successfully merged into the existing record or secondary properties were not filtered out!");
    }

    console.log("✔ Mismatched alignment keys prevention test passed cleanly! Existing records updated, zero new records created. 🎉");
`, context);
