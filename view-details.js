const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'frontend', 'index.html');
const lines = fs.readFileSync(filePath, 'utf8').split('\n');

for (let i = 3924; i < 3985 && i < lines.length; i++) {
    console.log(`${i + 1}: ${lines[i]}`);
}
