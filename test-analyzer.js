/**
 * Automated Verification Script for ScamShield Analysis Engine
 */
const { analyzeMessage, analyzeLink, analyzeWebsite, analyzeQRCode, DEMO_SAMPLES } = require('./js/rules/analyzer.js');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ PASS: ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    failed++;
  }
}

console.log('=== TEST 1: MESSAGE ANALYSIS ===');
// 1. Bank fraud suspension message
const bankMsg = analyzeMessage(DEMO_SAMPLES.messages[0].text);
assert(bankMsg.score >= 61, `Bank fraud should be High Risk (got ${bankMsg.score})`);
assert(bankMsg.category === 'High Risk', `Category should be High Risk (got ${bankMsg.category})`);
assert(bankMsg.issues.some(i => i.tag === 'Account Fraud Bait' || i.tag === 'Psychological Coercion'), 'Detected urgency or suspension');

// 2. Safe chat
const safeMsg = analyzeMessage(DEMO_SAMPLES.messages[3].text);
assert(safeMsg.score <= 30, `Safe chat should score <= 30 (got ${safeMsg.score})`);
assert(safeMsg.category === 'Looks Safe', `Category should be Looks Safe (got ${safeMsg.category})`);

console.log('\n=== TEST 2: LINK ANALYSIS ===');
// 1. Fake Login with .xyz TLD
const fakeLink = analyzeLink('http://secure-login.bank-update.xyz/verify-identity?account=locked');
assert(fakeLink.score >= 61, `Fake login should be High Risk (got ${fakeLink.score})`);
assert(fakeLink.issues.some(i => i.title.includes('HTTP')), 'Detected insecure HTTP protocol');
assert(fakeLink.issues.some(i => i.title.includes('Extension') || i.title.includes('TLD')), 'Detected suspicious TLD');
assert(fakeLink.issues.some(i => i.title.includes('Keywords')), 'Detected sensitive keywords');

// 2. IP Hostname
const ipLink = analyzeLink('http://192.168.1.105:8080/portal/update-billing');
assert(ipLink.issues.some(i => i.title.includes('IP Address')), 'Detected raw numeric IP address');
assert(ipLink.issues.some(i => i.title.includes('Port')), 'Detected non-standard port');

// 3. Official Safe URL
const safeLink = analyzeLink('https://www.amazon.com/gp/help/customer/display.html');
assert(safeLink.score <= 30, `Amazon should be safe (got ${safeLink.score})`);
assert(safeLink.category === 'Looks Safe', `Category should be Looks Safe (got ${safeLink.category})`);

console.log('\n=== TEST 3: WEBSITE ANALYSIS ===');
const fakeWeb = analyzeWebsite('http://paypa1-account-secure-verify.top');
assert(fakeWeb.score >= 61, `Typosquatting website should be High Risk (got ${fakeWeb.score})`);
assert(fakeWeb.disclaimer !== undefined, 'Contains client-side disclaimer');

const safeWeb = analyzeWebsite('https://www.wikipedia.org');
assert(safeWeb.score <= 30, `Wikipedia should be Looks Safe (got ${safeWeb.score})`);

console.log('\n=== TEST 4: QR CODE ANALYSIS ===');
// 1. Unsecured WiFi QR
const wifiQR = analyzeQRCode('WIFI:T:nopass;S:Free_Airport_WiFi_Unsecured;P:;;');
assert(wifiQR.qrType === 'WiFi Network', `QR Type detected as WiFi Network (got ${wifiQR.qrType})`);
assert(wifiQR.score >= 60, `Unsecured WiFi QR should be high risk (got ${wifiQR.score})`);

// 2. Phishing URL in QR
const linkQR = analyzeQRCode('http://secure-login.bank-update.xyz/verify');
assert(linkQR.qrType === 'URL', `QR Type detected as URL (got ${linkQR.qrType})`);
assert(linkQR.score >= 60, `Phishing URL in QR should be high risk (got ${linkQR.score})`);

// 3. Contact vCard
const contactQR = analyzeQRCode('BEGIN:VCARD\nVERSION:3.0\nFN:Alice Smith\nTEL:+123456789\nEND:VCARD');
assert(contactQR.qrType === 'Contact Card', `QR Type detected as Contact Card (got ${contactQR.qrType})`);
assert(contactQR.score <= 30, 'Contact QR should be low risk');

console.log('\n=== TEST 5: QUIZ DATA INTEGRITY ===');
assert(DEMO_SAMPLES.quiz.length >= 5, `Quiz contains 5+ scenarios (got ${DEMO_SAMPLES.quiz.length})`);
DEMO_SAMPLES.quiz.forEach((q, idx) => {
  assert(q.options.length >= 3, `Quiz ${idx + 1} has >= 3 options`);
  assert(q.correctIndex >= 0 && q.correctIndex < q.options.length, `Quiz ${idx + 1} has valid correctIndex`);
  assert(q.explanation.length > 20, `Quiz ${idx + 1} has thorough explanation`);
});

console.log(`\nRESULTS: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
