const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'frontend', 'index.html');
const content = fs.readFileSync(filePath, 'utf8');
const lines = content.split('\n');

console.log('Searching for dynamic policy logic...');
lines.forEach((line, idx) => {
    if (line.includes('excel') && line.includes('policy') || line.includes('startsWith(\'[\')') || line.includes('startsWith("["') || line.includes('getAvailablePolicies')) {
        console.log(`${idx + 1}: ${line.trim()}`);
    }
});
