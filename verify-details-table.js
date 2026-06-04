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

console.log('Running Custom Telemetry Table Verification Test...');

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

// Pre-create required elements for details view
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
createMockElement('det-custom-params-section');
createMockElement('det-custom-params-tbody');
createMockElement('det-sparkline-path');
createMockElement('det-sparkline-dots');
createMockElement('btn-isolate-device');
createMockElement('audit-terminal');

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
            // Create a mock element representing the created tag
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

    // Inject a mock device with custom properties to fleetDataset
    vm.runInContext(`
        fleetDataset = [
            {
                id: "dev-custom-test",
                canonical_name: "DELL-CUSTOM-TEST",
                serial: "SN-CUSTOM-111",
                condition: "IN_USE",
                level: "COMPLIANT",
                software: [],
                user_assigned: "test.user",
                last_login: "2026-06-04 10:00",
                location: "Remote - US",
                location_group: "Non-Sift",
                is_isolated: false,
                custom_properties: {
                    "Department": "Product Engineering",
                    "Asset Tag": "AT-99999",
                    "Assigned Project": "Project-Omega",
                    "Bios Version": "v1.2.3",
                    "Subnet IP": "10.23.45.67"
                },
                score: 100
            }
        ];
    `, context);

    // Run showDeviceAuditDetails
    console.log('Executing showDeviceAuditDetails("dev-custom-test")...');
    vm.runInContext('showDeviceAuditDetails("dev-custom-test")', context);

    // Retrieve and verify the populated custom parameters tbody element
    const customSection = domElements['det-custom-params-section'];
    const customTbody = domElements['det-custom-params-tbody'];

    console.log('Verifying Custom Telemetry & Asset Properties section visibility...');
    if (customSection.style.display !== 'block') {
        throw new Error('det-custom-params-section style.display should be "block" when custom properties are present');
    }

    console.log('Verifying child table row elements count...');
    console.log('Found children rows:', customTbody.children.length);
    if (customTbody.children.length !== 5) {
        throw new Error(`Expected exactly 5 child rows, but found ${customTbody.children.length}`);
    }

    // Inspect the generated table rows content
    const expectedProperties = {
        "Department": "Product Engineering",
        "Asset Tag": "AT-99999",
        "Assigned Project": "Project-Omega",
        "Bios Version": "v1.2.3",
        "Subnet IP": "10.23.45.67"
    };

    customTbody.children.forEach(row => {
        if (row.tagName !== 'TR') {
            throw new Error(`Expected child tag to be "TR", got "${row.tagName}"`);
        }
        
        const htmlContent = row.innerHTML;
        // Verify key and value exist in the innerHTML of the row
        let matchFound = false;
        for (const [key, val] of Object.entries(expectedProperties)) {
            if (htmlContent.includes(key) && htmlContent.includes(val)) {
                console.log(`✔ Verified row for key "${key}" matches value "${val}"`);
                matchFound = true;
                break;
            }
        }
        if (!matchFound) {
            throw new Error(`Row HTML content did not match any expected properties: "${htmlContent}"`);
        }
    });

    console.log('✔ All verification assertions passed successfully! 🎉');
} catch (err) {
    console.error('❌ Verification test failed:', err.message);
    console.error(err.stack);
    process.exit(1);
}
