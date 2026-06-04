const fs = require('fs');
const path = require('path');

const htmlPath = path.join(__dirname, 'frontend', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

const elements = [
    'score-edr',
    'score-patch',
    'score-encryption',
    'recon-name',
    'recon-serial',
    'recon-mac',
    'recon-manufacturer',
    'drift-scenario',
    'drift-7',
    'drift-14',
    'drift-30',
    'out-calc-score',
    'out-calc-level',
    'out-penalty-label',
    'out-nist',
    'out-fp',
    'out-action',
    'out-desc'
];

elements.forEach(el => {
    const hasInHtml = html.includes(`id="${el}"`) || html.includes(`id='${el}'`);
    console.log(`${el} in HTML:`, hasInHtml);
});
