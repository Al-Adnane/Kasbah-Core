/**
 * North America PII/Document Stress Test
 * Targets US and Canadian sensitive data formats.
 */

const detector = require('../detector.js');

const CORPUS = [
    // --- US DATA ---
    { name: "US SSN (Standard)", text: "Social Security: 456-12-7890", expected: "DENY" },
    { name: "US SSN (Space)", text: "SSN 456 12 7890", expected: "DENY" },
    { name: "US Passport", text: "US Passport No: 123456789", expected: "DENY" },
    { name: "US DL (Generic)", text: "Drivers License California: N1234567", expected: "DENY" },
    { name: "US Tax (W-2)", text: "Attached is my 2025 W-2 form for tax reporting.", expected: "WARN" },
    
    // --- CANADA DATA ---
    { name: "CA SIN (Hyphen)", text: "Social Insurance Number: 123-456-789", expected: "DENY" },
    { name: "CA SIN (Space)", text: "My SIN is 123 456 789", expected: "DENY" },
    { name: "CA Passport", text: "Canadian Passport: AB123456", expected: "DENY" },
    { name: "CA Health (OHIP)", text: "OHIP Card: 1234-567-890-AB", expected: "DENY" },
    { name: "CA Tax (T4)", text: "T4 Statement of Remuneration Paid for 2025", expected: "WARN" },
    
    // --- CROSS-BORDER FINANCIAL ---
    { name: "Bank Routing (US)", text: "Routing: 021000021 Account: 12345678", expected: "DENY" },
    { name: "Bank Transit (CA)", text: "Transit: 12345 Institution: 004 Account: 1234567", expected: "DENY" },
    
    // --- OBFUSCATION / EVASION ---
    { name: "SIN Obfuscated", text: "My S.I.N. is 1-2-3-4-5-6-7-8-9", expected: "DENY" },
    { name: "SSN L33t", text: "$$N is 456-12-7890", expected: "DENY" }
];

function runPIIStressTest() {
    console.log(">>> STARTING NORTH AMERICA PII STRESS TEST <<<");
    console.log("Environment: HARDCORE_MODE = " + detector.classify("test").hardcore_active);
    console.log("==========================================");

    let passed = 0;
    const startTime = Date.now();

    CORPUS.forEach(item => {
        const result = detector.classify(item.text);
        // Correct logic: if we expect DENY and get DENY, it's a pass.
        // If we expect WARN and get WARN or DENY, it's a pass (safe side).
        const isMatch = (result.decision === item.expected) || 
                        (item.expected === "DENY" && result.decision === "DENY") ||
                        (item.expected === "WARN" && (result.decision === "WARN" || result.decision === "DENY"));
        
        console.log(`[${isMatch ? 'PASS' : 'FAIL'}] ${item.name.padEnd(20)} | Risk: ${result.risk} | Decision: ${result.decision}`);
        if (!isMatch) {
            console.log(`      Payload: ${item.text}`);
            console.log(`      Reason:  ${result.reason}`);
        } else {
            passed++;
        }
    });

    const duration = Date.now() - startTime;
    console.log("==========================================");
    console.log(`Results: ${passed}/${CORPUS.length} detections matched targets.`);
    console.log(`Scan Time: ${duration}ms`);
    console.log("==========================================");

    if (passed < CORPUS.length) {
        console.log("STATUS: ⚠️ GAPS DETECTED in North American PII coverage.");
    } else {
        console.log("STATUS: ✅ OPTIMAL North American PII coverage.");
    }
}

runPIIStressTest();
