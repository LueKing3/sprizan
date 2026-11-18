process.env.NODE_ENV = 'test';
delete process.env.URLHAUS_AUTH_KEY;

import { app } from '../server/index.js';
import { inspectUrl, extractRegisteredDomain } from '../server/analyzer.js';
import { isRecognizedTopDomain } from '../server/top-domains.js';
import { EventEmitter } from 'node:events';

console.log('=====================================================');
console.log('SPRIZAN VERIFICATION SUITE — COMPREHENSIVE TESTS');
console.log('=====================================================\n');

let passCount = 0;
let failCount = 0;

function assert(condition, testName, detail = '') {
  if (condition) {
    console.log(`[PASS] ${testName}`);
    passCount++;
  } else {
    console.error(`[FAIL] ${testName} - ${detail}`);
    failCount++;
  }
}

// In-memory simulation of Express request/response
function simulate(appInstance, { method = 'GET', url = '/', body = null, ip = '127.0.0.1' } = {}) {
  return new Promise((resolve) => {
    const req = new EventEmitter();
    req.method = method;
    req.url = url;
    req.originalUrl = url;
    req.headers = { 'content-type': 'application/json' };
    req.ip = ip;
    req.connection = { remoteAddress: ip };
    req.socket = { remoteAddress: ip };
    req.body = body;

    const res = new EventEmitter();
    const resHeaders = {};
    res.statusCode = 200;

    res.setHeader = (k, v) => { resHeaders[k.toLowerCase()] = v; };
    res.getHeader = (k) => resHeaders[k.toLowerCase()];
    res.removeHeader = (k) => { delete resHeaders[k.toLowerCase()]; };
    res.hasHeader = (k) => Object.prototype.hasOwnProperty.call(resHeaders, k.toLowerCase());

    res.status = function(code) {
      this.statusCode = code;
      return this;
    };

    res.json = function(json) {
      resolve({ statusCode: this.statusCode, data: json });
      return this;
    };

    appInstance.handle(req, res);
  });
}

async function runTests() {
  console.log('--- SUITE 1: REGISTERED DOMAIN EXTRACTION & TOP DOMAINS ---');
  assert(extractRegisteredDomain('www.amazon.in') === 'amazon.in', 'amazon.in recognized as registered domain');
  assert(extractRegisteredDomain('amazon.co.uk') === 'amazon.co.uk', 'amazon.co.uk recognized across multi-part TLD');
  assert(extractRegisteredDomain('www.google.co.in') === 'google.co.in', 'google.co.in recognized across multi-part TLD');
  assert(extractRegisteredDomain('colab.research.google.com') === 'google.com', 'google.com extracted from deep subdomain');
  assert(extractRegisteredDomain('en.wikipedia.org') === 'wikipedia.org', 'wikipedia.org extracted correctly');
  assert(extractRegisteredDomain('news.bbc.co.uk') === 'bbc.co.uk', 'bbc.co.uk extracted correctly');

  assert(isRecognizedTopDomain('amazon.in').isTopDomain === true, 'amazon.in is verified in top domains');
  assert(isRecognizedTopDomain('amazon.com').isTopDomain === true, 'amazon.com is verified in top domains');
  assert(isRecognizedTopDomain('google.co.in').isTopDomain === true, 'google.co.in is verified in top domains');
  assert(isRecognizedTopDomain('google.com').isTopDomain === true, 'google.com is verified in top domains');
  assert(isRecognizedTopDomain('microsoft.com').isTopDomain === true, 'microsoft.com is verified in top domains');
  assert(isRecognizedTopDomain('apple.com').isTopDomain === true, 'apple.com is verified in top domains');
  assert(isRecognizedTopDomain('github.com').isTopDomain === true, 'github.com is verified in top domains');
  assert(isRecognizedTopDomain('youtube.com').isTopDomain === true, 'youtube.com is verified in top domains');
  assert(isRecognizedTopDomain('wikipedia.org').isTopDomain === true, 'wikipedia.org is verified in top domains');
  assert(isRecognizedTopDomain('phishing-site.xyz').isTopDomain === false, 'Unknown domain is NOT marked as top domain');

  console.log('\n--- SUITE 2: POPULAR LEGITIMATE WEBSITES SCAN ACCURACY ---');
  const legitimateSites = [
    { url: 'https://www.amazon.in/', expectedDomain: 'amazon.in', label: 'Amazon India' },
    { url: 'https://amazon.in/dp/B08N5WRWNW', expectedDomain: 'amazon.in', label: 'Amazon India Product Page' },
    { url: 'https://www.google.co.in/', expectedDomain: 'google.co.in', label: 'Google India' },
    { url: 'https://colab.research.google.com/', expectedDomain: 'google.com', label: 'Google Colab' },
    { url: 'https://www.microsoft.com/en-in', expectedDomain: 'microsoft.com', label: 'Microsoft' },
    { url: 'https://apple.com/iphone', expectedDomain: 'apple.com', label: 'Apple' },
    { url: 'https://github.com/torvalds/linux', expectedDomain: 'github.com', label: 'GitHub' },
    { url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ', expectedDomain: 'youtube.com', label: 'YouTube' },
    { url: 'https://en.wikipedia.org/wiki/Computer_security', expectedDomain: 'wikipedia.org', label: 'Wikipedia' }
  ];

  for (const site of legitimateSites) {
    const res = await simulate(app, {
      method: 'POST',
      url: '/api/scan',
      body: { url: site.url },
      ip: `10.1.1.${Math.floor(Math.random() * 200)}`
    });

    assert(res.statusCode === 200, `${site.label} returns 200 OK`);
    assert(res.data.verdict === 'NOT FLAGGED BY LOCAL ANALYSIS', `${site.label} receives NOT FLAGGED BY LOCAL ANALYSIS`, `Verdict was ${res.data.verdict}`);
    assert(res.data.isPopularDomain === true, `${site.label} recognized as popular domain`);
    assert(res.data.registeredDomain === site.expectedDomain, `${site.label} registeredDomain matches ${site.expectedDomain}`);
    assert(res.data.score === 0, `${site.label} has 0 severity score`);
    assert(res.data.findings.length === 0, `${site.label} has 0 structural findings`);
    assert(res.data.riskLevel === 'Low', `${site.label} risk level is Low`);
  }

  console.log('\n--- SUITE 3: DECEPTIVE & THREAT DOMAIN DETECTION ---');
  // A. Misleading brand subdomain
  const brandSpoof = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://amazon.in.phishing-fake.xyz/login' },
    ip: '10.2.1.1'
  });
  assert(brandSpoof.data.verdict === 'SUSPICIOUS', 'amazon.in.phishing-fake.xyz flagged as SUSPICIOUS');
  assert(brandSpoof.data.isPopularDomain === false, 'amazon.in.phishing-fake.xyz is NOT marked popular');
  assert(brandSpoof.data.registeredDomain === 'phishing-fake.xyz', 'Registered domain is correctly phishing-fake.xyz');
  assert(brandSpoof.data.findings.some(f => f.title.includes('Misleading brand')), 'Flags Misleading brand in subdomain');

  // B. Typosquatting (amazn.in)
  const typo = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://amazn.in/login' },
    ip: '10.2.1.2'
  });
  assert(typo.data.verdict === 'SUSPICIOUS', 'amazn.in flagged as SUSPICIOUS');
  assert(typo.data.findings.some(f => f.title.includes('Typosquatting')), 'Flags Typosquatting for amazn.in');

  // C. Leetspeak / Character Substitution (paypa1.com)
  const leet = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://paypa1.com/account' },
    ip: '10.2.1.3'
  });
  assert(leet.data.verdict === 'SUSPICIOUS', 'paypa1.com flagged as SUSPICIOUS');
  assert(leet.data.findings.some(f => f.title.includes('Character Substitution')), 'Flags Character Substitution for paypa1.com');

  // D. Combosquatting (amazon-security-update.com)
  const combo = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://amazon-security-update.com/signin' },
    ip: '10.2.1.4'
  });
  assert(combo.data.verdict === 'SUSPICIOUS', 'amazon-security-update.com flagged as SUSPICIOUS');
  assert(combo.data.findings.some(f => f.title.includes('Combosquatting')), 'Flags Combosquatting');

  // E. Direct IP Host & Obfuscated IP
  const ipScan = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'http://192.168.1.1/setup' },
    ip: '10.2.1.5'
  });
  assert(ipScan.data.verdict === 'SUSPICIOUS', '192.168.1.1 flagged as SUSPICIOUS');
  assert(ipScan.data.findings.some(f => f.title.includes('Internal') || f.title.includes('Private')), 'Flags Internal IP');

  const hexScan = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'http://0x7f000001/malware' },
    ip: '10.2.1.6'
  });
  assert(hexScan.data.verdict === 'SUSPICIOUS', '0x7f000001 flagged as SUSPICIOUS');
  assert(hexScan.data.findings.some(f => f.title.includes('numeric IP')), 'Flags Obfuscated numeric IP');

  // F. Punycode
  const puny = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://xn--pple-43d.com/login' },
    ip: '10.2.1.7'
  });
  assert(puny.data.verdict === 'SUSPICIOUS', 'xn--pple-43d.com flagged as SUSPICIOUS');
  assert(puny.data.findings.some(f => f.title.includes('Punycode')), 'Flags Punycode IDN');

  // G. Double File Extension (.pdf.exe)
  const dblExt = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://example.com/invoice.pdf.exe' },
    ip: '10.2.1.8'
  });
  assert(dblExt.data.verdict === 'SUSPICIOUS', 'invoice.pdf.exe flagged as SUSPICIOUS');
  assert(dblExt.data.findings.some(f => f.title.includes('double file extension')), 'Flags double file extension');

  // H. Open Redirect
  const openRedir = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://example.com/login?redirect=https://evil.com' },
    ip: '10.2.1.9'
  });
  assert(openRedir.data.verdict === 'SUSPICIOUS', 'Open redirect flagged as SUSPICIOUS');
  assert(openRedir.data.findings.some(f => f.title.includes('open redirect')), 'Flags open redirect');

  // I. Suspicious Service Port
  const portScan = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'http://example.com:1337/backdoor' },
    ip: '10.2.1.10'
  });
  assert(portScan.data.verdict === 'SUSPICIOUS', 'Port 1337 flagged as SUSPICIOUS');
  assert(portScan.data.findings.some(f => f.title.includes('Unusual service port')), 'Flags service port 1337');

  console.log('\n--- SUITE 4: DELIBERATELY MALFORMED & INVALID URLS ---');
  const malformed = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'not_a_valid_url' },
    ip: '10.3.1.1'
  });
  assert(malformed.statusCode === 400, 'not_a_valid_url returns 400');
  assert(malformed.data.verdict === 'UNABLE TO VERIFY', 'Verdict is UNABLE TO VERIFY for not_a_valid_url');

  const ftpScan = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'ftp://files.example.com' },
    ip: '10.3.1.2'
  });
  assert(ftpScan.statusCode === 400, 'ftp:// returns 400');
  assert(ftpScan.data.verdict === 'UNABLE TO VERIFY', 'Verdict is UNABLE TO VERIFY for ftp://');

  const jsScan = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'javascript:alert(1)' },
    ip: '10.3.1.3'
  });
  assert(jsScan.statusCode === 400, 'javascript: returns 400');
  assert(jsScan.data.verdict === 'UNABLE TO VERIFY', 'Verdict is UNABLE TO VERIFY for javascript:');

  const emptyScan = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: '' },
    ip: '10.3.1.4'
  });
  assert(emptyScan.statusCode === 400, 'Empty string returns 400');
  assert(emptyScan.data.verdict === 'UNABLE TO VERIFY', 'Verdict is UNABLE TO VERIFY for empty string');

  console.log('\n--- SUITE 5: VERDICT MATRIX COMPLETENESS ---');
  // Test Mock URLhaus CONFIRMED MALWARE
  const originalFetch = global.fetch;
  process.env.URLHAUS_AUTH_KEY = 'test_key';

  global.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      query_status: 'ok',
      threat: 'malware_download',
      url_status: 'online',
      date_added: '2026-03-01',
      tags: ['trojan']
    })
  });

  const malwareRes = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://malicious-distribution.xyz/trojan.bin' },
    ip: '10.4.1.1'
  });
  assert(malwareRes.data.verdict === 'CONFIRMED MALWARE', 'Verdict is CONFIRMED MALWARE on URLhaus match');
  assert(malwareRes.data.score >= 95, 'Score is >= 95');

  // Test Mock URLhaus NO KNOWN THREATS DETECTED
  global.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ query_status: 'no_results' })
  });

  const cleanExtRes = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://www.amazon.in/' },
    ip: '10.4.1.2'
  });
  assert(cleanExtRes.data.verdict === 'NO KNOWN THREATS DETECTED', 'Verdict is NO KNOWN THREATS DETECTED when URLhaus is clean');

  // Test Mock URLhaus Error -> PARTIALLY VERIFIED
  global.fetch = async () => {
    throw new Error('Connection timeout');
  };

  const errExtRes = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://www.amazon.in/' },
    ip: '10.4.1.3'
  });
  assert(errExtRes.data.verdict === 'PARTIALLY VERIFIED', 'Verdict is PARTIALLY VERIFIED when external feed errors on clean URL');

  // Cleanup
  global.fetch = originalFetch;
  delete process.env.URLHAUS_AUTH_KEY;

  console.log('\n--- SUITE 6: RATE LIMITER ---');
  const rateLimitIp = '192.0.2.99';
  let lastResponse;
  for (let i = 0; i < 61; i++) {
    lastResponse = await simulate(app, {
      method: 'POST',
      url: '/api/scan',
      body: { url: 'https://www.amazon.in/' },
      ip: rateLimitIp
    });
  }
  assert(lastResponse.statusCode === 429, '61st request triggers HTTP 429');
  assert(lastResponse.data.verdict === 'UNABLE TO VERIFY', 'Rate limited verdict is UNABLE TO VERIFY');

  console.log(`\n=====================================================`);
  console.log(`FINAL RESULTS: ${passCount} Passed, ${failCount} Failed.`);
  console.log(`=====================================================\n`);
  process.exit(failCount > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
