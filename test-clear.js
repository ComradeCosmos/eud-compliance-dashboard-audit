const fs = require('fs');
const path = require('path');
const vm = require('vm');

const htmlPath = path.join(__dirname, 'frontend', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

const scriptRegex = /<script>([\s\S]*?)<\/script>/gi;
const match = scriptRegex.exec(html);
const jsCode = match[1];

// Robust DOM Mocks
const domElements = {};
function createMockElement(id, tagName = 'div') {
    const el = {
        id: id,
        tagName: tagName.toUpperCase(),
        style: {},
        attributes: {},
        innerHTML: '',
        innerText: '',
        value: '',
        classList: {
            add: () => {},
            remove: () => {}
        },
        setAttribute: () => {},
        getAttribute: () => '',
        appendChild: () => {},
        querySelectorAll: () => [],
        querySelector: () => ({ style: {} }),
        parentElement: null
    };
    domElements[id] = el;
    return el;
}

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
        querySelector: () => ({ style: {}, querySelector: () => ({}), setAttribute: () => {} }),
        querySelectorAll: () => [],
        createElement: () => ({ setAttribute: () => {}, style: {} }),
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
    confirm: () => true // automatically click OK in confirm prompt
};
domMock.window = domMock;

const context = vm.createContext(domMock);
vm.runInContext(jsCode, context);

console.log('Testing triggerClearFleetData()...');
try {
    vm.runInContext('triggerClearFleetData()', context);
    console.log('✔ triggerClearFleetData executed successfully without errors!');
} catch (err) {
    console.error('❌ Error executing triggerClearFleetData:', err);
    process.exit(1);
}
