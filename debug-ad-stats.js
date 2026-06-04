// Verify new AD non-compliance counts after fix
const conditionMap = { 25: "IN_REPAIR", 40: "IN_STORE", 50: "EXPIRED", 60: "DISPOSED",
    70: "DONATED_UNDER_CSR", 80: "LOANABLE_RESERVED", 90: "NOT_TRACEABLE", 100: "RESERVED" };

let adNonCompliantInUse = 0, adNonCompliantAll = 0;
let totalInUse = 0, totalAll = 0;

for (let i = 1; i <= 10029; i++) {
    let condition = "IN_USE";
    for (const [mod, cond] of Object.entries(conditionMap)) {
        if (i % mod === 0) { condition = cond; break; }
    }

    // NEW AD rule: i % 62 === 1
    let adStatus = (i % 62 === 1) ? "NON_COMPLIANT" : "COMPLIANT";

    totalAll++;
    if (adStatus === "NON_COMPLIANT") adNonCompliantAll++;

    if (condition === "IN_USE") {
        totalInUse++;
        if (adStatus === "NON_COMPLIANT") adNonCompliantInUse++;
    }
}

console.log("=== After Fix ===");
console.log(`conditionFilter=ALL  → ${totalAll} total, ${adNonCompliantAll} AD non-compliant, ${(adNonCompliantAll/totalAll*100).toFixed(2)}% fail rate`);
console.log(`conditionFilter=IN_USE → ${totalInUse} total, ${adNonCompliantInUse} AD non-compliant, ${(adNonCompliantInUse/totalInUse*100).toFixed(2)}% fail rate`);
console.log(`AD Compliant (IN_USE): ${totalInUse - adNonCompliantInUse}`);
console.log(`Pass rate (IN_USE):    ${((totalInUse - adNonCompliantInUse)/totalInUse*100).toFixed(1)}%`);
