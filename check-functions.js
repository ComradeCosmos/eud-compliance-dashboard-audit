const fs = require('fs');
const path = require('path');

const htmlPath = path.join(__dirname, 'frontend', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

const functions = [
    'runReconciliationSimulation',
    'recalculateScores',
    'runDriftSimulation'
];

functions.forEach(fn => {
    console.log(`--- Searching for ${fn} ---`);
    let pos = -1;
    while ((pos = html.indexOf(fn, pos + 1)) !== -1) {
        const start = Math.max(0, pos - 50);
        const end = Math.min(html.length, pos + 50);
        console.log(`Found at index ${pos}: "${html.substring(start, end).replace(/\n/g, ' ')}"`);
    }
});
