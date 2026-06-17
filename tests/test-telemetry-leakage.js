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

console.log('Testing single-agent uploader (Zscaler only) telemetry mapping & leakage fix...');

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
createMockElement('reconciler-queue-card');
createMockElement('reconciler-queue-tbody');
createMockElement('btn-execute-reconciliation');
const matchesWidget = createMockElement('recon-stat-matches');
const matchesParent = createMockElement('recon-stat-matches-parent');
matchesParent.appendChild(matchesWidget);
createMockElement('recon-stat-gaps');
createMockElement('recon-stat-rogues');
createMockElement('recon-stat-match-rate');
createMockElement('recon-tab-count-gaps');
createMockElement('recon-tab-count-rogues');
createMockElement('recon-tab-count-matches');
createMockElement('recon-table-head');
createMockElement('recon-table-body');

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

try {
    vm.runInContext(jsCode, context, { filename: 'script-1.js' });
    console.log('✔ Phase 1: Environment boot successful.');

    // Enforce role and load test queue
    vm.runInContext(`
        currentSession.isLoggedIn = true;
        currentSession.username = "admin";
        currentSession.role = "admin";
        
        // Seed some custom test devices in the fleet to verify existing device preservation rules
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
        
        // ONLY primary (directory) and ONE secondary sheet (Zscaler connector status) uploaded!
        reconcilerSheets = [
            {
                id: 'sheet-primary',
                filename: 'corporate_directory.csv',
                headers: ['Device Name', 'Asset Tag', 'Department'],
                rows: [
                    ['DELL-EUD-1001', 'AT-12001', 'Engineering'], // existing device
                    ['DELL-EUD-1002', 'AT-12002', 'Product']       // new device
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
    `, context);

    // Run reconciliation
    vm.runInContext('executeDeepReconciliation()', context);
    console.log('✔ Phase 2: Deep Reconciliation executed with Zscaler only.');

    // Assert matches / gaps counts
    vm.runInContext(`
        if (reconciliationResults.matches.length !== 2) {
            throw new Error('Expected 2 matches, got ' + reconciliationResults.matches.length);
        }
    `, context);
    console.log('✔ Phase 3: Match counts verified.');

    // Run merge
    console.log('Merging reconciliation into fleet...');
    vm.runInContext('mergeReconciliationIntoFleet()', context);
    console.log('✔ Phase 4: Integration merge completed.');

    // Validate the software states
    vm.runInContext(`
        // Find the existing device in the fleet
        const existingDev = fleetDataset.find(d => d.id === 'dev-exist-matched');
        if (!existingDev) throw new Error('Existing device "dev-exist-matched" was lost!');

        // Existing device must preserve its compliance states for unreported sheets!
        // BitLocker, Nessus, SentinelOne, SCCM were not part of the active upload queue, so their status must remain COMPLIANT.
        // Zscaler WAS part of the upload queue, so its status should be updated to CONNECTED / COMPLIANT!
        const existBitLocker = existingDev.software.find(sw => sw.key === 'bitlocker');
        const existZscaler = existingDev.software.find(sw => sw.key === 'zscaler');
        
        console.log('Existing Device BitLocker Installed:', existBitLocker.installed);
        console.log('Existing Device Zscaler Installed:', existZscaler.installed);
        console.log('Existing Device Overall Score:', existingDev.score, existingDev.level);
        
        if (existBitLocker.installed !== 'INSTALLED' || existBitLocker.status !== 'COMPLIANT') {
            throw new Error('FAIL: Existing device BitLocker status was overwritten by unreported default!');
        }
        if (existZscaler.installed !== 'INSTALLED' || existZscaler.status !== 'COMPLIANT') {
            throw new Error('FAIL: Existing device Zscaler status was not updated!');
        }
        
        // Since BitLocker is unreported, its NON_COMPLIANT status should NOT drag down the overall score of the device!
        if (existingDev.score !== 100.00 || existingDev.level !== 'COMPLIANT') {
            throw new Error('FAIL: Existing device score was failed by unreported telemetry!');
        }
        
        // Find the newly created matched device 'DELL-EUD-1002'
        const newDev = fleetDataset.find(d => d.canonical_name.toLowerCase() === 'dell-eud-1002');
        if (!newDev) throw new Error('New matched device "DELL-EUD-1002" was not created!');

        // New device: AD and Zscaler must be COMPLIANT/INSTALLED, while BitLocker, Nessus, SentinelOne, and SCCM must be MISSING (AGENT UNREPORTED) / NON_COMPLIANT!
        const newAD = newDev.software.find(sw => sw.key === 'ad');
        const newZscaler = newDev.software.find(sw => sw.key === 'zscaler');
        const newBitLocker = newDev.software.find(sw => sw.key === 'bitlocker');
        const newNessus = newDev.software.find(sw => sw.key === 'nessus');
        const newSentinelOne = newDev.software.find(sw => sw.key === 'sentinelone');
        const newSCCM = newDev.software.find(sw => sw.key === 'sccm');

        console.log('New Device AD:', newAD.installed, newAD.status);
        console.log('New Device Zscaler:', newZscaler.installed, newZscaler.status);
        console.log('New Device BitLocker:', newBitLocker.installed, newBitLocker.status);
        console.log('New Device Nessus:', newNessus.installed, newNessus.status);
        console.log('New Device SentinelOne:', newSentinelOne.installed, newSentinelOne.status);
        console.log('New Device SCCM:', newSCCM.installed, newSCCM.status);
        console.log('New Device Overall Score:', newDev.score, newDev.level);

        if (newAD.installed !== 'INSTALLED' || newAD.status !== 'COMPLIANT') {
            throw new Error('FAIL: AD Enrollment was not verified/compliant for directory asset!');
        }
        if (newZscaler.installed !== 'INSTALLED' || newZscaler.status !== 'COMPLIANT') {
            throw new Error('FAIL: Zscaler agent was not marked compliant for matched asset!');
        }
        if (newBitLocker.installed !== 'MISSING (AGENT UNREPORTED)' || newBitLocker.status !== 'NON_COMPLIANT') {
            throw new Error('FAIL: BitLocker was not marked as unreported/non-compliant!');
        }
        if (newNessus.installed !== 'MISSING (AGENT UNREPORTED)' || newNessus.status !== 'NON_COMPLIANT') {
            throw new Error('FAIL: Nessus was not marked as unreported/non-compliant!');
        }
        if (newSentinelOne.installed !== 'MISSING (AGENT UNREPORTED)' || newSentinelOne.status !== 'NON_COMPLIANT') {
            throw new Error('FAIL: SentinelOne was not marked as unreported/non-compliant!');
        }
        if (newSCCM.installed !== 'MISSING (AGENT UNREPORTED)' || newSCCM.status !== 'NON_COMPLIANT') {
            throw new Error('FAIL: SCCM was not marked as unreported/non-compliant!');
        }
        
        // Since BitLocker, Nessus, SentinelOne, and SCCM are unreported, they must be ignored from new matched device scoring!
        if (newDev.score !== 100.00 || newDev.level !== 'COMPLIANT') {
            throw new Error('FAIL: New matched device score was failed by unreported telemetries!');
        }
        
        // Check policy statistics unreported states
        const bitlockerStats = getPolicyStats("BitLocker Drive Encryption");
        const zscalerStats = getPolicyStats("Zscaler Client Connector");
        
        console.log('BitLocker Stats isUnreported:', bitlockerStats.isUnreported);
        console.log('Zscaler Stats isUnreported:', zscalerStats.isUnreported);
        
        if (!bitlockerStats.isUnreported) {
            throw new Error('FAIL: BitLocker stats did not register as unreported!');
        }
        if (zscalerStats.isUnreported) {
            throw new Error('FAIL: Zscaler stats registered as unreported!');
        }
    `, context);
    console.log('✔ Phase 5: Compliance mapping verification succeeded flawlessly!');

    // Phase 6: Simulate a successive merge of a different agent (BitLocker)
    console.log('\nRunning successive merge check (Phase 6: merging BitLocker telemetry after Zscaler)...');
    vm.runInContext(`
        // Simulating the user uploading ONLY a BitLocker telemetry sheet next (Zscaler is no longer in the queue)
        reconcilerSheets = [
            {
                id: 'sheet-primary',
                filename: 'corporate_directory.csv',
                headers: ['Device Name', 'Asset Tag', 'Department'],
                rows: [
                    ['DELL-EUD-1001', 'AT-12001', 'Engineering'], // existing device
                    ['DELL-EUD-1002', 'AT-12002', 'Product']       // our new device
                ],
                keyIdx: 0,
                role: 'primary'
            },
            {
                id: 'sheet-secondary-bitlocker',
                filename: 'bitlocker_telemetry.csv',
                headers: ['Computer', 'Drive Encryption State'],
                rows: [
                    ['DELL-EUD-1001', 'ENCRYPTED'],
                    ['DELL-EUD-1002', 'ENCRYPTED']
                ],
                keyIdx: 0,
                role: 'secondary'
            }
        ];
        
        // Execute reconciliation with BitLocker
        executeDeepReconciliation();
        
        // Merge BitLocker reconciliation into the active fleet
        mergeReconciliationIntoFleet();
        
        // Now, BOTH 'zscaler' and 'bitlocker' should be in the permanently merged software agents list
        console.log('mergedSoftwareAgents has zscaler:', mergedSoftwareAgents.has("zscaler"));
        console.log('mergedSoftwareAgents has bitlocker:', mergedSoftwareAgents.has("bitlocker"));
        
        if (!mergedSoftwareAgents.has("zscaler") || !mergedSoftwareAgents.has("bitlocker")) {
            throw new Error('FAIL: Successive merged software agents tracking failed!');
        }
        
        // Let's check our device 'DELL-EUD-1002' again
        const devCheck = fleetDataset.find(d => d.canonical_name.toLowerCase() === 'dell-eud-1002');
        if (!devCheck) throw new Error('Device DELL-EUD-1002 was lost!');
        
        const checkAD = devCheck.software.find(sw => sw.key === 'ad');
        const checkZscaler = devCheck.software.find(sw => sw.key === 'zscaler');
        const checkBitLocker = devCheck.software.find(sw => sw.key === 'bitlocker');
        const checkNessus = devCheck.software.find(sw => sw.key === 'nessus');
        
        console.log('DELL-EUD-1002 Zscaler after second merge:', checkZscaler.installed, checkZscaler.status);
        console.log('DELL-EUD-1002 BitLocker after second merge:', checkBitLocker.installed, checkBitLocker.status);
        console.log('DELL-EUD-1002 Compliance Score after second merge:', devCheck.score, devCheck.level);
        
        // AD must stay INSTALLED and COMPLIANT
        if (checkAD.installed !== 'INSTALLED' || checkAD.status !== 'COMPLIANT') {
            throw new Error('FAIL: AD Enrollment was overwritten!');
        }
        // Zscaler must stay INSTALLED and COMPLIANT from the first merge, and NOT get deleted/removed!
        if (checkZscaler.installed !== 'INSTALLED' || checkZscaler.status !== 'COMPLIANT') {
            throw new Error('FAIL: Zscaler status was wiped or removed during successive merge!');
        }
        // BitLocker must now be INSTALLED and COMPLIANT from the second merge!
        if (checkBitLocker.installed !== 'INSTALLED' || checkBitLocker.status !== 'COMPLIANT') {
            throw new Error('FAIL: BitLocker was not successfully updated during successive merge!');
        }
        // Nessus was never merged, so it should still be MISSING (AGENT UNREPORTED) and ignored in the score!
        if (checkNessus.installed !== 'MISSING (AGENT UNREPORTED)' || checkNessus.status !== 'NON_COMPLIANT') {
            throw new Error('FAIL: Nessus was improperly modified or evaluated!');
        }
        
        // Composite score of the device must still be 100.00 (since AD, Zscaler, BitLocker are compliant, and Nessus is ignored)
        if (devCheck.score !== 100.00 || devCheck.level !== 'COMPLIANT') {
            throw new Error('FAIL: Device overall compliance score failed after successive merge!');
        }
        
        // Verify stats for both policies are active and evaluated!
        const checkZscalerStats = getPolicyStats("Zscaler Client Connector");
        const checkBitLockerStats = getPolicyStats("BitLocker Drive Encryption");
        
        console.log('Zscaler Stats isUnreported after second merge:', checkZscalerStats.isUnreported, checkZscalerStats.compliantCount, '/', checkZscalerStats.totalCount);
        console.log('BitLocker Stats isUnreported after second merge:', checkBitLockerStats.isUnreported, checkBitLockerStats.compliantCount, '/', checkBitLockerStats.totalCount);
        
        if (checkZscalerStats.isUnreported || checkBitLockerStats.isUnreported) {
            throw new Error('FAIL: Merged policy statistics are registered as unreported!');
        }
        
        if (checkZscalerStats.compliantCount !== 2 || checkBitLockerStats.compliantCount !== 2) {
            throw new Error('FAIL: Successive merge calculations are incorrect!');
        }
    `, context);
    console.log('✔ Phase 6: Successive multi-agent merge verification succeeded flawlessly!');

    console.log('\nRunning Phase 7: evaluateComplianceValue version patterns & negation verification...');
    vm.runInContext(`
        const v1 = evaluateComplianceValue('6.2.1');
        const v2 = evaluateComplianceValue('v5.0');
        const v3 = evaluateComplianceValue('10.241.13');
        const v4 = evaluateComplianceValue('v4.15');
        const v5 = evaluateComplianceValue('non-compliant');
        
        // Negation / Substring checks
        const v6 = evaluateComplianceValue('agent non-compliant');
        const v7 = evaluateComplianceValue('not active');
        const v8 = evaluateComplianceValue('disconnected');
        const v9 = evaluateComplianceValue('agent inactive');
        
        // Complex compliant phrases
        const v10 = evaluateComplianceValue('trusted network');
        const v11 = evaluateComplianceValue('domain joined');
        const v12 = evaluateComplianceValue('aes-256');
        const v13 = evaluateComplianceValue('no vulnerabilities');
        
        console.log('6.2.1 compliance result:', JSON.stringify(v1));
        console.log('v5.0 compliance result:', JSON.stringify(v2));
        console.log('10.241.13 compliance result:', JSON.stringify(v3));
        console.log('v4.15 compliance result:', JSON.stringify(v4));
        console.log('non-compliant compliance result:', JSON.stringify(v5));
        console.log('agent non-compliant compliance result:', JSON.stringify(v6));
        console.log('not active compliance result:', JSON.stringify(v7));
        console.log('disconnected compliance result:', JSON.stringify(v8));
        console.log('agent inactive compliance result:', JSON.stringify(v9));
        console.log('trusted network compliance result:', JSON.stringify(v10));
        console.log('domain joined compliance result:', JSON.stringify(v11));
        console.log('aes-256 compliance result:', JSON.stringify(v12));
        console.log('no vulnerabilities compliance result:', JSON.stringify(v13));
        
        if (v1.status !== 'COMPLIANT' || v1.installed !== 'INSTALLED') throw new Error('FAIL: 6.2.1 version string did not resolve to COMPLIANT/INSTALLED');
        if (v2.status !== 'COMPLIANT' || v2.installed !== 'INSTALLED') throw new Error('FAIL: v5.0 version string did not resolve to COMPLIANT/INSTALLED');
        if (v3.status !== 'COMPLIANT' || v3.installed !== 'INSTALLED') throw new Error('FAIL: 10.241.13 version string did not resolve to COMPLIANT/INSTALLED');
        if (v4.status !== 'COMPLIANT' || v4.installed !== 'INSTALLED') throw new Error('FAIL: v4.15 version string did not resolve to COMPLIANT/INSTALLED');
        if (v5.status !== 'NON_COMPLIANT') throw new Error('FAIL: non-compliant string did not resolve to NON_COMPLIANT');
        
        if (v6.status !== 'NON_COMPLIANT') throw new Error('FAIL: agent non-compliant should be NON_COMPLIANT');
        if (v7.status !== 'NON_COMPLIANT') throw new Error('FAIL: not active should be NON_COMPLIANT');
        if (v8.status !== 'NON_COMPLIANT') throw new Error('FAIL: disconnected should be NON_COMPLIANT');
        if (v9.status !== 'NON_COMPLIANT') throw new Error('FAIL: agent inactive should be NON_COMPLIANT');
        
        if (v10.status !== 'COMPLIANT' || v10.installed !== 'INSTALLED') throw new Error('FAIL: trusted network should be COMPLIANT/INSTALLED');
        if (v11.status !== 'COMPLIANT' || v11.installed !== 'INSTALLED') throw new Error('FAIL: domain joined should be COMPLIANT/INSTALLED');
        if (v12.status !== 'COMPLIANT' || v12.installed !== 'INSTALLED') throw new Error('FAIL: aes-256 should be COMPLIANT/INSTALLED');
        if (v13.status !== 'COMPLIANT' || v13.installed !== 'INSTALLED') throw new Error('FAIL: no vulnerabilities should be COMPLIANT/INSTALLED');
    `, context);
    console.log('✔ Phase 7: evaluateComplianceValue version patterns & negation verification succeeded flawlessly!');

    console.log('\nAll single-agent uploader mapping leakage & successive merge tracking verification tests passed successfully! 🎉');
} catch (err) {
    console.error('❌ Integration Test failed:', err.message);
    console.error(err.stack);
    process.exit(1);
}
