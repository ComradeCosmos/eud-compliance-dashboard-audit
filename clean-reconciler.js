const fs = require('fs');
const path = require('path');

const targetFilePath = path.join(__dirname, 'update-reconciler.js');
console.log('Reading file:', targetFilePath);
let content = fs.readFileSync(targetFilePath, 'utf8');

// Replace any occurrences of \text{\${...}} with just \${...}
// Also replace any occurrences of \text{\\\${...}} with \\\${...}
// and \text{details} or \text{h} or \text{sourceLabel} or \text{p.property} or \text{p.value} or \text{Date.now()}
const cleaned = content
    .replace(/\\text{\\(\$?{.+?})}/g, '\\$1')
    .replace(/\\text{\\\\(\$?{.+?})}/g, '\\\\$1')
    .replace(/\\text{\\(\w+?)}/g, '\\$1')
    .replace(/\\text{\\\\(\w+?)}/g, '\\\\$1')
    .replace(/\\text{\\(.+?)}/g, '\\$1')
    .replace(/\\text{\\\\(.+?)}/g, '\\\\$1')
    .replace(/\\text{(\$.+?)}/g, '$1')
    .replace(/\\text{(\w+?)}/g, '$1')
    .replace(/\\text{(.+?)}/g, '$1');

console.log('Writing cleaned contents back...');
fs.writeFileSync(targetFilePath, cleaned, 'utf8');
console.log('SUCCESS: update-reconciler.js cleaned! 🎉');
