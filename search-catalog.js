const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'frontend', 'index.html');
const content = fs.readFileSync(filePath, 'utf8');
const lines = content.split('\n');

console.log('Searching for sampleSoftwareCatalog...');
lines.forEach((line, idx) => {
    if (line.includes('sampleSoftwareCatalog')) {
        console.log(`${idx + 1}: ${line.trim().substring(0, 120)}`);
    }
});
