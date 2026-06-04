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

// Run script code in VM to define the helper
vm.runInContext(jsCode, context);

console.log('Verifying mergeDistinctProperties logic...');

vm.runInContext(`
    const target = {
        "Department": "Engineering",
        "Asset Tag": "AT-12001",
        "[reconciliation_1.csv] Status": "ACTIVE"
    };

    const source = {
        // Matching identical property value in active database (even if key has different reconciliation file source)
        "[reconciliation_2.csv] Department": "Engineering",
        
        // Distinct/Different property value (should be merged!)
        "[reconciliation_2.csv] Asset Tag": "AT-99999",
        
        // Matching identical property value from a different reconciliation
        "[reconciliation_2.csv] Status": "ACTIVE",
        
        // Brand new distinct property (should be merged!)
        "[reconciliation_2.csv] Project": "Minerva"
    };

    mergeDistinctProperties(target, source);

    console.log('Resulting target properties:', target);

    // Assertions
    if (target["[reconciliation_2.csv] Department"] !== undefined) {
        throw new Error("FAIL: Identical matching information was merged!");
    }
    if (target["[reconciliation_2.csv] Asset Tag"] !== "AT-99999") {
        throw new Error("FAIL: Distinct different property was not merged!");
    }
    if (target["[reconciliation_2.csv] Status"] !== undefined) {
        throw new Error("FAIL: Identical matching information from different reconciliations was merged!");
    }
    if (target["[reconciliation_2.csv] Project"] !== "Minerva") {
        throw new Error("FAIL: New distinct property was not merged!");
    }

    console.log("✔ Distinct properties merging logic verified perfectly! 🎉");
`, context);
