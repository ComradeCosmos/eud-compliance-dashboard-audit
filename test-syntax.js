const fs = require('fs');
const path = require('path');
const vm = require('vm');

const htmlPath = path.join(__dirname, 'frontend', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

const scriptRegex = /<script>([\s\S]*?)<\/script>/gi;
let match;
let count = 0;

console.log('Testing JS syntax inside index.html script tags...');

while ((match = scriptRegex.exec(html)) !== null) {
    count++;
    const jsCode = match[1];
    try {
        new vm.Script(jsCode, { filename: `script-${count}.js`, lineOffset: 0 });
        console.log(`Script tag #${count} parsed successfully.`);
    } catch (err) {
        console.error(`❌ Syntax Error in script tag #${count}:`, err.message);
        console.error(err.stack);
        
        // Find line number in original file
        const index = match.index;
        const lineNum = html.substring(0, index).split('\n').length;
        console.error(`Starts near line: ${lineNum}`);
        
        // Split script into lines and show lines around the error
        const lines = jsCode.split('\n');
        // If the error message has a line number like "script-1.js:123"
        const lineMatch = err.stack.match(/script-\d+\.js:(\d+)/);
        if (lineMatch) {
            const errLine = parseInt(lineMatch[1], 10);
            console.error(`Error is at script-relative line: ${errLine}`);
            console.error(`Error is at original file line: ${lineNum + errLine - 1}`);
            
            console.error('\nCode Snippet around the error:');
            const start = Math.max(0, errLine - 5);
            const end = Math.min(lines.length, errLine + 5);
            for (let i = start; i < end; i++) {
                const marker = (i + 1 === errLine) ? '>>> ' : '    ';
                console.error(`${marker}${lineNum + i}: ${lines[i]}`);
            }
        }
        process.exit(1);
    }
}

console.log('All scripts are valid! 🎉');
