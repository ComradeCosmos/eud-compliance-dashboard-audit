const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'frontend', 'index.html');
const lines = fs.readFileSync(filePath, 'utf8').split('\n');

lines.forEach((line, index) => {
    if (line.includes('function executeDeepReconciliation')) {
        console.log(`Found function at line: ${index + 1}`);
        for (let i = index; i < index + 175 && i < lines.length; i++) {
            console.log(`${i + 1}: ${lines[i]}`);
        }
    }
});
