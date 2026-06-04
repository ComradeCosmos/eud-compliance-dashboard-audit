const fs = require('fs');
const path = require('path');
const vm = require('vm');

const htmlPath = path.join(__dirname, 'frontend', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

const scriptRegex = /<script>([\s\S]*?)<\/script>/gi;
let match;
let count = 0;

console.log('Testing JS runtime execution on boot...');

// Mock browser globals
const domMock = {
    console: console,
    setTimeout: setTimeout,
    setInterval: setInterval,
    clearTimeout: clearTimeout,
    clearInterval: clearInterval,
    window: {},
    document: {
        getElementById: () => ({
            style: {},
            setAttribute: () => {},
            addEventListener: () => {},
            appendChild: () => {},
            querySelector: () => ({ style: {}, querySelector: () => ({}) }),
            querySelectorAll: () => []
        }),
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
    alert: (msg) => console.log('ALERT:', msg)
};
domMock.window = domMock;

const context = vm.createContext(domMock);

while ((match = scriptRegex.exec(html)) !== null) {
    count++;
    const jsCode = match[1];
    try {
        vm.runInContext(jsCode, context, { filename: `script-${count}.js` });
        console.log(`Script tag #${count} executed on boot successfully.`);
    } catch (err) {
        console.error(`❌ Runtime Error in script tag #${count} on boot:`, err.message);
        console.error(err.stack);
        process.exit(1);
    }
}

console.log('All script tags executed successfully on boot! 🎉');
