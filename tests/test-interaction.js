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

console.log('Running robust DOM and interaction test...');

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
        log: () => {}, // suppress logs to keep output clean unless we want them
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
            // Basic selector matches
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
    confirm: () => true // automatically confirm dialogs
};
domMock.window = domMock;

const context = vm.createContext(domMock);

try {
    vm.runInContext(jsCode, context, { filename: 'script-1.js' });
    console.log('✔ Phase 1: Clean boot successful.');

    // Simulate login
    console.log('Simulating login as admin...');
    vm.runInContext(`
        currentSession.isLoggedIn = true;
        currentSession.username = "admin";
        currentSession.role = "admin";
        currentSession.roleLabel = "Global Security & Compliance Administrator";
    `, context);

    // Simulate uploader populating files
    console.log('Simulating spreadsheet upload queue...');
    vm.runInContext(`
        reconcilerSheets = [
            {
                id: 'sheet-primary',
                filename: 'corporate_directory.csv',
                headers: ['Device Name', 'Asset Tag', 'Department'],
                rows: [
                    ['DELL-EUD-1001', 'AT-12001', 'Engineering'],
                    ['DELL-EUD-1002', 'AT-12002', 'Product'],
                    ['DELL-EUD-1003', 'AT-12003', 'Sales']
                ],
                keyIdx: 0,
                role: 'primary'
            },
            {
                id: 'sheet-secondary',
                filename: 'edr_agent_report.csv',
                headers: ['Hostname', 'EDR Status', 'Scan Date'],
                rows: [
                    ['DELL-EUD-1001', 'ACTIVE', '2026-05-27'],
                    ['DELL-EUD-1002', 'OFFLINE', '2026-05-26'],
                    ['DELL-EUD-9999', 'ACTIVE', '2026-05-27'] // rogue device (not in directory)
                ],
                keyIdx: 0,
                role: 'secondary'
            }
        ];
    `, context);

    // Execute deep reconciliation
    console.log('Executing executeDeepReconciliation()...');
    vm.runInContext('executeDeepReconciliation()', context);
    console.log('✔ Phase 2: Reconciliation executed cleanly.');

    // Verify reconciliationResults
    console.log('Verifying matches, gaps, and rogues...');
    vm.runInContext(`
        console.log('Matches length:', reconciliationResults.matches.length);
        console.log('Gaps length:', reconciliationResults.gaps.length);
        console.log('Rogues length:', reconciliationResults.rogues.length);
        
        if (reconciliationResults.matches.length !== 2) throw new Error('Expected 2 matches (DELL-EUD-1001, DELL-EUD-1002)');
        if (reconciliationResults.gaps.length !== 1) throw new Error('Expected 1 gap (DELL-EUD-1003)');
        if (reconciliationResults.rogues.length !== 1) throw new Error('Expected 1 rogue (DELL-EUD-9999)');
    `, context);
    console.log('✔ Phase 3: Matching counts verified correctly.');

    // Execute tab switching
    console.log('Testing switchReconTab()...');
    vm.runInContext('switchReconTab("gaps")', context);
    vm.runInContext('switchReconTab("rogues")', context);
    vm.runInContext('switchReconTab("matches")', context);
    console.log('✔ Phase 4: switchReconTab() executed cleanly.');

    // Execute merge
    console.log('Executing mergeReconciliationIntoFleet()...');
    vm.runInContext('mergeReconciliationIntoFleet()', context);
    console.log('✔ Phase 5: mergeReconciliationIntoFleet() executed cleanly.');

    // Call renderPoliciesGrid
    console.log('Executing renderPoliciesGrid()...');
    vm.runInContext('renderPoliciesGrid()', context);
    console.log('✔ Phase 6: renderPoliciesGrid() executed cleanly.');

    // Generate compliance report
    console.log('Executing generateComplianceReport()...');
    vm.runInContext('generateComplianceReport()', context);
    console.log('✔ Phase 7: generateComplianceReport() executed cleanly.');

    console.log('All detailed reconciliation integration tests passed successfully! 🎉');
} catch (err) {
    console.error('❌ Detailed Integration Test failed:', err.message);
    console.error(err.stack);
    process.exit(1);
}
