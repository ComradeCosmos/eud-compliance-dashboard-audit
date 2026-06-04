const XLSX = require('xlsx');
const path = require('path');

const filePath = path.join(__dirname, 'i-desk Inventory.xlsx');
try {
    const workbook = XLSX.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: "" });
    
    console.log('Headers in i-desk Inventory:');
    console.log(rows[0]);
    console.log('\nRow 1:');
    console.log(rows[1]);
    console.log('\nRow 2:');
    console.log(rows[2]);
    console.log('\nTotal rows:', rows.length);
} catch (err) {
    console.error('Error reading i-desk Inventory:', err);
}
