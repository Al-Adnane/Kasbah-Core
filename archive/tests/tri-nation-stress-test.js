/**
 * Kasbah Guard — Tri-Nation PII Stress Test Suite
 * Comprehensive testing for US/Canada/UK detection coverage
 * 
 * Coverage:
 * - United States: 25 test cases
 * - Canada: 15 test cases
 * - United Kingdom: 25 test cases
 * - Universal Secrets: 15 test cases
 * 
 * Total: 80 test cases
 */

const detector = require('../detector-global.js');

// ═══════════════════════════════════════════════════════════════
// TEST CORPUS
// ═══════════════════════════════════════════════════════════════

const TEST_CORPUS = [
  // ─────────────────────────────────────────────────────────────
  // UNITED STATES (25 tests)
  // ─────────────────────────────────────────────────────────────
  
  // US Social Security Numbers
  { region: "US", name: "US SSN (Standard)", text: "Social Security: 456-12-7890", expected: "DENY" },
  { region: "US", name: "US SSN (Space)", text: "SSN 456 12 7890", expected: "DENY" },
  { region: "US", name: "US SSN (No separator)", text: "My SSN is 456127890 please keep secret", expected: "DENY" },
  { region: "US", name: "US SSN (Invalid 000)", text: "SSN: 000-12-3456", expected: "ALLOW" }, // Should not match
  { region: "US", name: "US SSN (Invalid 666)", text: "SSN: 666-12-3456", expected: "ALLOW" }, // Should not match
  { region: "US", name: "US SSN (Invalid 9xx)", text: "SSN: 900-12-3456", expected: "ALLOW" }, // Should not match
  
  // US Medicare/Medicaid
  { region: "US", name: "US Medicare", text: "Medicare Number: 123456789AB", expected: "DENY" },
  { region: "US", name: "US Medicaid", text: "Medicaid ID: 987654321CD", expected: "DENY" },
  
  // US EIN (Employer ID)
  { region: "US", name: "US EIN", text: "EIN: 12-3456789", expected: "WARN" },
  { region: "US", name: "US Tax ID", text: "Tax ID Number: 98-7654321", expected: "WARN" },
  
  // US Tax Forms
  { region: "US", name: "US W-2 Form", text: "Attached is my 2025 W-2 form for tax reporting.", expected: "WARN" },
  { region: "US", name: "US 1099 Form", text: "I received a 1099 form for freelance work", expected: "WARN" },
  { region: "US", name: "US 1040 Form", text: "File your 1040 tax return by April 15", expected: "WARN" },
  
  // US Bank Routing
  { region: "US", name: "US Routing Number", text: "Routing: 021000021 Account: 12345678", expected: "DENY" },
  { region: "US", name: "US ABA Number", text: "ABA routing number: 123456789", expected: "DENY" },
  
  // US Credit Cards
  { region: "US", name: "US Visa", text: "Visa: 4532-1234-5678-9101", expected: "DENY" },
  { region: "US", name: "US Mastercard", text: "Mastercard: 5105-1051-0510-5100", expected: "DENY" },
  { region: "US", name: "US Amex", text: "American Express: 3782-822463-10005", expected: "DENY" },
  
  // US Health Insurance
  { region: "US", name: "US Health Insurance", text: "Health Insurance ID: ABC12345678", expected: "WARN" },
  { region: "US", name: "US Member ID", text: "Member ID: XYZ987654321", expected: "WARN" },
  
  // US Prescription
  { region: "US", name: "US Prescription", text: "Prescription Number: R123456789", expected: "WARN" },
  { region: "US", name: "US Rx", text: "Rx: A98765432", expected: "WARN" },
  
  // US VA Number
  { region: "US", name: "US VA Number", text: "VA Number: 123456789", expected: "DENY" },
  { region: "US", name: "US Veterans Affairs", text: "Veterans Affairs claim: 987654321", expected: "DENY" },
  
  // US Immigration
  { region: "US", name: "US Green Card", text: "Green Card Number: ABC123456", expected: "DENY" },
  { region: "US", name: "US I-94", text: "I-94 Number: 123456789", expected: "DENY" },
  
  // ─────────────────────────────────────────────────────────────
  // CANADA (15 tests)
  // ─────────────────────────────────────────────────────────────
  
  // Canadian SIN
  { region: "CA", name: "CA SIN (Hyphen)", text: "Social Insurance Number: 123-456-789", expected: "DENY" },
  { region: "CA", name: "CA SIN (Space)", text: "My SIN is 123 456 789", expected: "DENY" },
  { region: "CA", name: "CA SIN (No separator)", text: "SIN: 123456789", expected: "DENY" },
  { region: "CA", name: "CA SIN Reference", text: "social insurance number required", expected: "WARN" },
  
  // Canadian Passport
  { region: "CA", name: "CA Passport", text: "Canadian Passport: AB123456", expected: "DENY" },
  { region: "CA", name: "CA Passport French", text: "Passeport canadien: CD987654", expected: "DENY" },
  
  // Canadian Health Cards
  { region: "CA", name: "CA OHIP", text: "OHIP Card: 1234-567-890-AB", expected: "DENY" },
  { region: "CA", name: "CA MSP", text: "MSP Number: 1234-567-890", expected: "DENY" },
  { region: "CA", name: "CA RAMQ", text: "RAMQ: 1234567890", expected: "DENY" },
  
  // Canadian Tax Forms
  { region: "CA", name: "CA T4", text: "T4 Statement of Remuneration Paid for 2025", expected: "WARN" },
  { region: "CA", name: "CA T5", text: "T5 Investment Income slip", expected: "WARN" },
  
  // Canadian GST/HST
  { region: "CA", name: "CA GST", text: "GST Number: 123456789", expected: "WARN" },
  { region: "CA", name: "CA HST", text: "HST Account: 987654321", expected: "WARN" },
  
  // Canadian CPP
  { region: "CA", name: "CA CPP", text: "Canada Pension Plan: 123456789", expected: "WARN" },
  { region: "CA", name: "CA QPP", text: "Quebec Pension Plan: 987654321", expected: "WARN" },
  
  // Canadian Bank Transit
  { region: "CA", name: "CA Transit", text: "Transit: 12345 Institution: 004 Account: 1234567", expected: "DENY" },
  { region: "CA", name: "CA e-Transfer", text: "e-Transfer to transit 12345 branch 004", expected: "DENY" },
  
  // Canadian Driver's License
  { region: "CA", name: "CA DL Ontario", text: "Ontario Driver License: A1234-56789-01234", expected: "DENY" },
  { region: "CA", name: "CA DL Quebec", text: "Permis de conduire Quebec: 1234567890", expected: "DENY" },
  
  // ─────────────────────────────────────────────────────────────
  // UNITED KINGDOM (25 tests)
  // ─────────────────────────────────────────────────────────────
  
  // UK National Insurance Number
  { region: "UK", name: "UK NINO (Valid)", text: "National Insurance: AB123456C", expected: "DENY" },
  { region: "UK", name: "UK NINO (Valid 2)", text: "NINO: QQ123456D", expected: "DENY" },
  { region: "UK", name: "UK NINO (Invalid BG)", text: "NINO: BG123456C", expected: "ALLOW" }, // Invalid prefix
  { region: "UK", name: "UK NINO (Invalid GB)", text: "NINO: GB123456C", expected: "ALLOW" }, // Invalid prefix
  { region: "UK", name: "UK NINO (Invalid NK)", text: "NINO: NK123456C", expected: "ALLOW" }, // Invalid prefix
  { region: "UK", name: "UK NINO (Invalid ZZ)", text: "NINO: ZZ123456C", expected: "ALLOW" }, // Invalid prefix
  
  // UK NHS Number
  { region: "UK", name: "UK NHS (Valid)", text: "NHS Number: 123-456-7890", expected: "DENY" },
  { region: "UK", name: "UK NHS (No separator)", text: "NHS Number: 1234567890", expected: "DENY" },
  { region: "UK", name: "UK Medical Number", text: "Medical Number: 987-654-3210", expected: "WARN" },
  
  // UK Passport
  { region: "UK", name: "UK Passport", text: "UK Passport: A12345678", expected: "DENY" },
  { region: "UK", name: "UK British Passport", text: "British Passport: B98765432", expected: "DENY" },
  { region: "UK", name: "UK HM Passport", text: "HM Passport: C12345678", expected: "DENY" },
  
  // UK Driving Licence
  { region: "UK", name: "UK DL (DVLA)", text: "Driving Licence: SMITH801306IJ9HY", expected: "DENY" },
  { region: "UK", name: "UK DL (DVLA 2)", text: "DVLA Licence: JONES901234AB1CD", expected: "DENY" },
  
  // UK Sort Code
  { region: "UK", name: "UK Sort Code", text: "Sort Code: 12-34-56", expected: "WARN" },
  { region: "UK", name: "UK Sort Code (No dash)", text: "Sort: 123456", expected: "WARN" },
  { region: "UK", name: "UK Bank Sort", text: "Bank sort code: 65-43-21", expected: "WARN" },
  
  // UK Bank Account
  { region: "UK", name: "UK Account Number", text: "Account Number: 12345678", expected: "WARN" },
  { region: "UK", name: "UK Bank Account", text: "UK bank account: 87654321", expected: "WARN" },
  
  // UK IBAN
  { region: "UK", name: "UK IBAN", text: "IBAN: GB29NWBK60161331926819", expected: "DENY" },
  { region: "UK", name: "UK IBAN (Spaced)", text: "GB29 NWBK 6016 1331 9268 19", expected: "DENY" },
  
  // UK SWIFT/BIC
  { region: "UK", name: "UK SWIFT", text: "SWIFT Code: NWBKGB2L", expected: "WARN" },
  { region: "UK", name: "UK BIC", text: "BIC: BARCGB22", expected: "WARN" },
  
  // UK UTR (HMRC)
  { region: "UK", name: "UK UTR", text: "UTR: 1234567890", expected: "WARN" },
  { region: "UK", name: "UK Tax Reference", text: "Tax Reference: 9876543210", expected: "WARN" },
  { region: "UK", name: "UK HMRC", text: "HMRC Reference: 1122334455", expected: "WARN" },
  { region: "UK", name: "UK Self Assessment", text: "Self Assessment: 5544332211", expected: "WARN" },
  
  // UK VAT Number
  { region: "UK", name: "UK VAT", text: "VAT Number: GB123456789", expected: "WARN" },
  { region: "UK", name: "UK VAT (Long)", text: "VAT: GB123456789012", expected: "WARN" },
  
  // UK PAYE
  { region: "UK", name: "UK PAYE", text: "PAYE Reference: 123/AB45678", expected: "WARN" },
  { region: "UK", name: "UK Payroll", text: "Payroll reference: 987/XY12345", expected: "WARN" },
  
  // UK Council Tax
  { region: "UK", name: "UK Council Tax", text: "Council Tax Reference: ABC123456", expected: "WARN" },
  { region: "UK", name: "UK Tax Bill", text: "Tax Bill: XYZ987654321", expected: "WARN" },
  
  // UK Electoral Roll
  { region: "UK", name: "UK Electoral Roll", text: "Electoral Roll: ABC123456", expected: "WARN" },
  { region: "UK", name: "UK Voter ID", text: "Voter ID: XYZ987654", expected: "WARN" },
  
  // UK Pension
  { region: "UK", name: "UK Pension", text: "Pension Number: ABC12345678", expected: "WARN" },
  { region: "UK", name: "UK State Pension", text: "State Pension: XYZ98765432", expected: "WARN" },
  
  // UK Benefits
  { region: "UK", name: "UK Universal Credit", text: "Universal Credit: ABC123456", expected: "WARN" },
  { region: "UK", name: "UK JSA", text: "Jobseeker's Allowance: XYZ987654", expected: "WARN" },
  { region: "UK", name: "UK PIP", text: "Personal Independence Payment: ABC987654", expected: "WARN" },
  
  // UK Land Registry
  { region: "UK", name: "UK Land Registry", text: "Land Registry Title: AB123456", expected: "WARN" },
  { region: "UK", name: "UK Title Number", text: "Title Number: XYZ9876543", expected: "WARN" },
  
  // UK Company Number
  { region: "UK", name: "UK Company Number", text: "Company Number: 12345678", expected: "WARN" },
  { region: "UK", name: "UK Companies House", text: "Companies House: 87654321", expected: "WARN" },
  
  // ─────────────────────────────────────────────────────────────
  // UNIVERSAL SECRETS (15 tests)
  // ─────────────────────────────────────────────────────────────
  
  // GitHub PAT
  { region: "Universal", name: "GitHub PAT (ghp_)", text: "ghp_16C7e42F292c6912E7710c838347Ae178B4a", expected: "DENY" },
  { region: "Universal", name: "GitHub PAT (gho_)", text: "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", expected: "DENY" },
  { region: "Universal", name: "GitHub PAT (ghu_)", text: "ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", expected: "DENY" },
  
  // OpenAI Keys
  { region: "Universal", name: "OpenAI Key", text: "sk-proj-abc123defghijklmnopqrstuvwxyz1234567890", expected: "DENY" },
  { region: "Universal", name: "OpenAI Key (sk-)", text: "sk-abc123defghijklmnopqrstuvwxyz1234567890ABCDEF", expected: "DENY" },
  
  // AWS Keys
  { region: "Universal", name: "AWS Access Key", text: "AKIAIOSFODNN7EXAMPLE", expected: "DENY" },
  { region: "Universal", name: "AWS Secret Key", text: "aws secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", expected: "DENY" },
  
  // Database Connection Strings
  { region: "Universal", name: "MongoDB URI", text: "mongodb://user:password@localhost:27017/db", expected: "DENY" },
  { region: "Universal", name: "PostgreSQL URI", text: "postgres://user:pass@localhost:5432/db", expected: "DENY" },
  { region: "Universal", name: "MySQL URI", text: "mysql://root:secret@localhost:3306/mydb", expected: "DENY" },
  { region: "Universal", name: "Redis URI", text: "redis://localhost:6379/0", expected: "DENY" },
  
  // Private Keys
  { region: "Universal", name: "RSA Private Key", text: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...\n-----END RSA PRIVATE KEY-----", expected: "DENY" },
  
  // Generic API Keys
  { region: "Universal", name: "Generic API Key", text: "api_key: abc123def456ghi789jkl012mno345pqr678stu901", expected: "WARN" },
  { region: "Universal", name: "Auth Token", text: "auth_token: xyz789abc123def456ghi789jkl012mno345", expected: "WARN" },
  
  // JWT Tokens
  { region: "Universal", name: "JWT Token", text: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", expected: "DENY" },
  
  // Control (Low Risk)
  { region: "Control", name: "Control (Normal Text)", text: "This is just normal text with no sensitive data", expected: "ALLOW" },
  { region: "Control", name: "Control (Business Email)", text: "Please contact me at john.doe@company.com", expected: "ALLOW" },
  { region: "Control", name: "Control (Phone)", text: "Call me at +1-555-123-4567", expected: "ALLOW" }
];

// ═══════════════════════════════════════════════════════════════
// TEST RUNNER
// ═══════════════════════════════════════════════════════════════

function runTriNationStressTest() {
  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║     KASBAH GUARD — TRI-NATION PII STRESS TEST SUITE      ║");
  console.log("║     US/Canada/UK Comprehensive Detection Coverage        ║");
  console.log("╚══════════════════════════════════════════════════════════╝\n");
  
  console.log("Environment: HARDCORE_MODE = " + detector.classify("test").hardcore_active);
  console.log("Region: " + detector.classify("test").region);
  console.log("Pattern Version: " + detector.classify("test").version);
  console.log("═══════════════════════════════════════════════════════════\n");

  let passed = 0;
  let failed = 0;
  let warnings = 0;
  const failures = [];
  const resultsByRegion = {
    US: { passed: 0, failed: 0, total: 0 },
    CA: { passed: 0, failed: 0, total: 0 },
    UK: { passed: 0, failed: 0, total: 0 },
    Universal: { passed: 0, failed: 0, total: 0 },
    Control: { passed: 0, failed: 0, total: 0 }
  };

  const startTime = Date.now();

  TEST_CORPUS.forEach((item, index) => {
    const result = detector.classify(item.text);
    
    // Correct logic: if we expect DENY and get DENY, it's a pass.
    // If we expect WARN and get WARN or DENY, it's a pass (safe side).
    // If we expect ALLOW and get ALLOW, it's a pass.
    const isMatch = (result.decision === item.expected) ||
                    (item.expected === "DENY" && result.decision === "DENY") ||
                    (item.expected === "WARN" && (result.decision === "WARN" || result.decision === "DENY"));

    const status = isMatch ? 'PASS' : 'FAIL';
    const statusIcon = isMatch ? '✅' : '❌';
    
    console.log(`[${statusIcon}] ${item.region.padEnd(9)} | ${item.name.padEnd(35)} | Risk: ${String(result.risk).padEnd(3)} | Decision: ${result.decision.padEnd(5)} | Expected: ${item.expected}`);
    
    if (!isMatch) {
      failures.push({
        index: index + 1,
        name: item.name,
        region: item.region,
        expected: item.expected,
        actual: result.decision,
        risk: result.risk,
        reason: result.reason,
        text: item.text
      });
      failed++;
      if (resultsByRegion[item.region]) {
        resultsByRegion[item.region].failed++;
        resultsByRegion[item.region].total++;
      }
    } else {
      passed++;
      if (result.decision === 'WARN' && item.expected === 'DENY') {
        warnings++;
      }
      if (resultsByRegion[item.region]) {
        resultsByRegion[item.region].passed++;
        resultsByRegion[item.region].total++;
      }
    }
  });

  const duration = Date.now() - startTime;
  
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("RESULTS BY REGION");
  console.log("═══════════════════════════════════════════════════════════");
  
  Object.keys(resultsByRegion).forEach(region => {
    const r = resultsByRegion[region];
    if (r.total > 0) {
      const pct = ((r.passed / r.total) * 100).toFixed(1);
      console.log(`${region.padEnd(12)}: ${r.passed}/${r.total} passed (${pct}%) ${r.failed > 0 ? '❌' : '✅'}`);
    }
  });
  
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("SUMMARY");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`Total Tests: ${TEST_CORPUS.length}`);
  console.log(`Passed: ${passed} ✅`);
  console.log(`Failed: ${failed} ${failed > 0 ? '❌' : ''}`);
  console.log(`Warnings: ${warnings} ⚠️`);
  console.log(`Scan Time: ${duration}ms`);
  console.log(`Avg Time/Test: ${(duration / TEST_CORPUS.length).toFixed(2)}ms`);
  console.log("═══════════════════════════════════════════════════════════\n");

  if (failures.length > 0) {
    console.log("FAILURE DETAILS:");
    console.log("─────────────────────────────────────────────────────────");
    failures.forEach(f => {
      console.log(`#${f.index}: ${f.name} (${f.region})`);
      console.log(`   Expected: ${f.expected}, Got: ${f.actual} (Risk: ${f.risk})`);
      console.log(`   Reason: ${f.reason}`);
      console.log(`   Text: ${f.text.substring(0, 80)}${f.text.length > 80 ? '...' : ''}`);
      console.log("");
    });
    console.log("═══════════════════════════════════════════════════════════");
    console.log(`STATUS: ⚠️  ${failed} GAPS DETECTED in Tri-Nation PII coverage.`);
    console.log("═══════════════════════════════════════════════════════════");
    return { success: false, passed, failed, warnings, failures, duration };
  } else {
    console.log("STATUS: ✅ OPTIMAL Tri-Nation PII coverage.");
    console.log("═══════════════════════════════════════════════════════════");
    return { success: true, passed, failed, warnings, duration };
  }
}

// ═══════════════════════════════════════════════════════════════
// VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════

function runValidationTests() {
  console.log("\n╔══════════════════════════════════════════════════════════╗");
  console.log("║           CHECKSUM VALIDATION TESTS                     ║");
  console.log("╚══════════════════════════════════════════════════════════╝\n");
  
  const validationTests = [
    // Luhn Tests
    { name: "Luhn (Valid CC)", fn: () => detector.luhnCheck("4532123456789101"), expected: true },
    { name: "Luhn (Invalid CC)", fn: () => detector.luhnCheck("4532123456789102"), expected: false },
    { name: "Luhn (Valid SIN)", fn: () => detector.luhnCheck("123456789"), expected: true },
    
    // UK NINO Tests
    { name: "NINO (Valid AB123456C)", fn: () => detector.validateNINO("AB123456C"), expected: true },
    { name: "NINO (Valid QQ123456D)", fn: () => detector.validateNINO("QQ123456D"), expected: true },
    { name: "NINO (Invalid BG)", fn: () => detector.validateNINO("BG123456C"), expected: false },
    { name: "NINO (Invalid GB)", fn: () => detector.validateNINO("GB123456C"), expected: false },
    { name: "NINO (Invalid NK)", fn: () => detector.validateNINO("NK123456C"), expected: false },
    { name: "NINO (Invalid ZZ)", fn: () => detector.validateNINO("ZZ123456C"), expected: false },
    
    // UK NHS Tests
    { name: "NHS (Valid 1234567890)", fn: () => detector.validateNHSNumber("1234567890"), expected: true },
    { name: "NHS (Invalid length)", fn: () => detector.validateNHSNumber("123456789"), expected: false },
    
    // UK Sort Code Tests
    { name: "Sort Code (Valid)", fn: () => detector.validateSortCode("123456"), expected: true },
    { name: "Sort Code (Valid dashed)", fn: () => detector.validateSortCode("12-34-56"), expected: true },
    { name: "Sort Code (Invalid 00)", fn: () => detector.validateSortCode("001234"), expected: false },
    
    // US SSN Tests
    { name: "SSN (Valid)", fn: () => detector.validateSSN("456127890"), expected: true },
    { name: "SSN (Invalid 000)", fn: () => detector.validateSSN("000127890"), expected: false },
    { name: "SSN (Invalid 666)", fn: () => detector.validateSSN("666127890"), expected: false },
    { name: "SSN (Invalid 9xx)", fn: () => detector.validateSSN("900127890"), expected: false },
    
    // IBAN Tests
    { name: "IBAN (Valid UK)", fn: () => detector.ibanMod97Check("GB29NWBK60161331926819"), expected: true },
    { name: "IBAN (Invalid)", fn: () => detector.ibanMod97Check("GB29NWBK60161331926818"), expected: false },
  ];
  
  let vPassed = 0;
  let vFailed = 0;
  
  validationTests.forEach(test => {
    const result = test.fn();
    const pass = result === test.expected;
    const icon = pass ? '✅' : '❌';
    
    console.log(`${icon} ${test.name.padEnd(30)} | Expected: ${String(test.expected).padEnd(5)} | Got: ${String(result).padEnd(5)}`);
    
    if (pass) {
      vPassed++;
    } else {
      vFailed++;
    }
  });
  
  console.log(`\nValidation: ${vPassed}/${validationTests.length} passed ${vFailed === 0 ? '✅' : '❌'}`);
  
  return { passed: vPassed, failed: vFailed, total: validationTests.length };
}

// ═══════════════════════════════════════════════════════════════
// MAIN EXECUTION
// ═══════════════════════════════════════════════════════════════

console.log("\n" + "=".repeat(60) + "\n");

// Run main stress test
const stressResult = runTriNationStressTest();

// Run validation tests
const validationResult = runValidationTests();

// Run built-in self-test
console.log("\n╔══════════════════════════════════════════════════════════╗");
console.log("║           BUILT-IN SELF-TEST                             ║");
console.log("╚══════════════════════════════════════════════════════════╝\n");

const selfTestResult = detector.selfTest();
console.log(`Self-Test: ${selfTestResult.passed}/${selfTestResult.total} passed`);
selfTestResult.results.forEach(r => {
  console.log(`  ${r.pass ? '✅' : '❌'} ${r.name}`);
});

// Final summary
console.log("\n" + "=".repeat(60));
console.log("FINAL SUMMARY");
console.log("=".repeat(60));
console.log(`Stress Tests:    ${stressResult.passed}/${stressResult.passed + stressResult.failed} passed (${((stressResult.passed / (stressResult.passed + stressResult.failed)) * 100).toFixed(1)}%)`);
console.log(`Validation:      ${validationResult.passed}/${validationResult.total} passed`);
console.log(`Self-Test:       ${selfTestResult.passed}/${selfTestResult.total} passed`);
console.log("=".repeat(60));

if (stressResult.failed === 0 && validationResult.failed === 0 && selfTestResult.passed === selfTestResult.total) {
  console.log("\n✅ ALL TESTS PASSED - PRODUCTION READY\n");
  process.exit(0);
} else {
  console.log("\n⚠️  SOME TESTS FAILED - REVIEW REQUIRED\n");
  process.exit(1);
}
