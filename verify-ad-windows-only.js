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
vm.runInContext(jsCode, context);

console.log('Testing AD Enrollment stats with Windows-only applicability filter...');

vm.runInContext(`
    const allStats = getPolicyStats("Active Directory (AD) Enrollment", "ALL");
    console.log("conditionFilter=ALL:");
    console.log("  Compliant Count:  ", allStats.compliantCount);
    console.log("  Total Count:      ", allStats.totalCount);
    console.log("  Pass Rate:        ", (allStats.totalCount > 0 ? (allStats.compliantCount / allStats.totalCount * 100).toFixed(2) : 0) + "%");

    const inUseStats = getPolicyStats("Active Directory (AD) Enrollment", "IN_USE");
    console.log("conditionFilter=IN_USE:");
    console.log("  Compliant Count:  ", inUseStats.compliantCount);
    console.log("  Total Count:      ", inUseStats.totalCount);
    console.log("  Pass Rate:        ", (inUseStats.totalCount > 0 ? (inUseStats.compliantCount / inUseStats.totalCount * 100).toFixed(2) : 0) + "%");
`, context);
