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

console.log('Verifying Rogue Assets Management flows...');

vm.runInContext(`
    // 1. Setup simulated rogue asset in reconciliation results
    reconciliationResults.rogues = [
        {
            id: "dev-rogue-t1",
            name: "ROGUE-DEVICE-999",
            normalized: "roguedevice999",
            sheets: [
                {
                    filename: "edr_report.csv",
                    row: ["ROGUE-DEVICE-999", "ACTIVE", "2026-05-27"],
                    headers: ["Hostname", "EDR Status", "Scan Date"],
                    keyIdx: 0
                }
            ],
            status: "ROGUE_UNMANAGED",
            is_isolated: false
        }
    ];

    console.log('Initial Rogue count:', reconciliationResults.rogues.length);
    console.log('Initial Matches count:', reconciliationResults.matches.length);

    // 2. Test isolateRogueAsset
    console.log('Executing isolateRogueAsset("dev-rogue-t1")...');
    isolateRogueAsset("dev-rogue-t1");

    const isolatedRogue = fleetDataset.find(dev => dev.canonical_name === "roguedevice999");
    if (!isolatedRogue) throw new Error("FAIL: Rogue device not merged to fleetDataset upon isolation!");
    if (!isolatedRogue.is_isolated) throw new Error("FAIL: Rogue device was not isolated!");
    if (!isolatedRogue.is_rogue) throw new Error("FAIL: Rogue device is_rogue flag was not set!");
    if (isolatedRogue.score !== 10.00) throw new Error("FAIL: Isolated rogue device did not receive isolated score of 10.00! Got: " + isolatedRogue.score);

    console.log("✔ Rogue Asset Isolation verified successfully! Score: " + isolatedRogue.score);

    // 3. Test registerRogueAsset
    console.log('Executing registerRogueAsset("dev-rogue-t1")...');
    registerRogueAsset("dev-rogue-t1");

    const registeredRogue = fleetDataset.find(dev => dev.canonical_name === "roguedevice999");
    if (registeredRogue.is_rogue) throw new Error("FAIL: Registered rogue device is_rogue flag was not cleared!");
    if (registeredRogue.is_isolated) throw new Error("FAIL: Registered rogue device remained isolated!");
    if (registeredRogue.score !== 100.00) throw new Error("FAIL: Registered rogue did not receive compliant score of 100.00! Got: " + registeredRogue.score);

    // Check counts updated in tab header
    if (reconciliationResults.rogues.length !== 0) throw new Error("FAIL: Rogue was not removed from rogues list!");
    if (reconciliationResults.matches.length !== 1) throw new Error("FAIL: Rogue was not moved to matches list!");

    console.log("✔ Rogue Asset Manual Authorized Registration verified successfully! Score: " + registeredRogue.score);
    console.log("✔ All Rogue Assets management flows passed perfectly! 🎉");
`, context);
