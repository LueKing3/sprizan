process.env.NODE_ENV = 'test';
delete process.env.URLHAUS_AUTH_KEY;

import { app } from '../server/index.js';
import { inspectUrl, extractRegisteredDomain } from '../server/analyzer.js';
import { isRecognizedTopDomain } from '../server/top-domains.js';
import { EventEmitter } from 'node:events';

console.log('=====================================================');
console.log('SPRIZAN VERIFICATION SUITE — COMPREHENSIVE SECURITY AUDIT');
console.log('=====================================================\n');

let passCount = 0;
let failCount = 0;

function assert(condition, testName, detail = '') {
  if (condition) {
    console.log(`[PASS] ${testName}`);
    passCount++;
  } else {
    console.error(`[FAIL] ${testName}${detail ? ' — ' + detail : ''}`);
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
  let totalCleanTested = 0;
  let cleanFalsePositives = 0;
  let totalThreatsTested = 0;
  let threatsDetected = 0;

  // ---------------------------------------------------------------------------
  // SUITE 1: REGISTERED DOMAIN EXTRACTION & TOP DOMAINS
  // ---------------------------------------------------------------------------
  console.log('--- SUITE 1: REGISTERED DOMAIN EXTRACTION & TOP DOMAINS ---');
  assert(extractRegisteredDomain('www.amazon.in') === 'amazon.in', 'amazon.in recognized as registered domain');
  assert(extractRegisteredDomain('amazon.co.uk') === 'amazon.co.uk', 'amazon.co.uk recognized across multi-part TLD');
  assert(extractRegisteredDomain('www.google.co.in') === 'google.co.in', 'google.co.in recognized across multi-part TLD');
  assert(extractRegisteredDomain('colab.research.google.com') === 'google.com', 'google.com extracted from deep subdomain');
  assert(extractRegisteredDomain('en.wikipedia.org') === 'wikipedia.org', 'wikipedia.org extracted correctly');
  assert(extractRegisteredDomain('news.bbc.co.uk') === 'bbc.co.uk', 'bbc.co.uk extracted correctly');
  assert(extractRegisteredDomain('portal.sbi.co.in') === 'sbi.co.in', 'sbi.co.in extracted correctly');

  // Managed Hosting Platforms: subdomains must NOT collapse into root platform domain
  assert(extractRegisteredDomain('attacker.github.io') === 'attacker.github.io', 'Managed platform attacker.github.io retains user tenant boundary');
  assert(extractRegisteredDomain('phish.firebaseapp.com') === 'phish.firebaseapp.com', 'Managed platform phish.firebaseapp.com retains user tenant boundary');

  assert(isRecognizedTopDomain('amazon.in').isTopDomain === true, 'amazon.in is verified in top domains');
  assert(isRecognizedTopDomain('amazon.com').isTopDomain === true, 'amazon.com is verified in top domains');
  assert(isRecognizedTopDomain('google.co.in').isTopDomain === true, 'google.co.in is verified in top domains');
  assert(isRecognizedTopDomain('google.com').isTopDomain === true, 'google.com is verified in top domains');
  assert(isRecognizedTopDomain('microsoft.com').isTopDomain === true, 'microsoft.com is verified in top domains');
  assert(isRecognizedTopDomain('apple.com').isTopDomain === true, 'apple.com is verified in top domains');
  assert(isRecognizedTopDomain('github.com').isTopDomain === true, 'github.com is verified in top domains');
  assert(isRecognizedTopDomain('youtube.com').isTopDomain === true, 'youtube.com is verified in top domains');
  assert(isRecognizedTopDomain('wikipedia.org').isTopDomain === true, 'wikipedia.org is verified in top domains');
  assert(isRecognizedTopDomain('onlinesbi.sbi').isTopDomain === true, 'onlinesbi.sbi is verified in top domains');
  assert(isRecognizedTopDomain('phishing-site.xyz').isTopDomain === false, 'Unknown domain is NOT marked as top domain');

  // ---------------------------------------------------------------------------
  // SUITE 2: POPULAR LEGITIMATE WEBSITES SCAN ACCURACY (ZERO FALSE POSITIVES)
  // ---------------------------------------------------------------------------
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
    { url: 'https://en.wikipedia.org/wiki/Computer_security', expectedDomain: 'wikipedia.org', label: 'Wikipedia' },
    { url: 'https://www.linkedin.com/feed/', expectedDomain: 'linkedin.com', label: 'LinkedIn' },
    { url: 'https://stackoverflow.com/questions/tagged/javascript', expectedDomain: 'stackoverflow.com', label: 'StackOverflow' },
    { url: 'https://www.onlinesbi.sbi/', expectedDomain: 'onlinesbi.sbi', label: 'State Bank of India' }
  ];

  for (const site of legitimateSites) {
    totalCleanTested++;
    const res = await simulate(app, {
      method: 'POST',
      url: '/api/scan',
      body: { url: site.url },
      ip: `10.1.1.${Math.floor(Math.random() * 200)}`
    });

    const isClean = res.data.verdict === 'NO SUSPICIOUS INDICATORS FOUND — LOCAL ANALYSIS ONLY' ||
                    res.data.verdict === 'NOT FLAGGED BY LOCAL ANALYSIS' ||
                    res.data.verdict === 'NO THREAT INDICATORS DETECTED';

    if (!isClean) cleanFalsePositives++;

    assert(res.statusCode === 200, `${site.label} returns 200 OK`);
    assert(isClean, `${site.label} receives clean verdict`, `Verdict was ${res.data.verdict}`);
    assert(res.data.isPopularDomain === true, `${site.label} recognized as popular domain`);
    assert(res.data.score === 0, `${site.label} has 0 severity score`);
    assert(res.data.findings.length === 0, `${site.label} has 0 structural findings`);
    assert(res.data.riskLevel === 'Low', `${site.label} risk level is Low`);
  }

  // ---------------------------------------------------------------------------
  // SUITE 3: UNFAMILIAR / UNRANKED LEGITIMATE WEBSITES (NO FALSE POSITIVES)
  // SPRIZAN must NOT classify unknown websites as suspicious without evidence.
  // ---------------------------------------------------------------------------
  console.log('\n--- SUITE 3: UNFAMILIAR / UNRANKED CLEAN WEBSITES (NO FALSE POSITIVES) ---');
  const unfamiliarCleanSites = [
    {
      url: 'https://local-art-bakery-shop.org/our-menu?category=pastries&page=2',
      label: 'Niche Bakery Website with Query Parameters'
    },
    {
      url: 'https://researcher-portfolio.io/publications/2026/quantum-algorithms-draft.pdf',
      label: 'Academic Portfolio with PDF Document Link'
    },
    {
      url: 'https://my-community-sports-club.net/schedule?team=under14&season=winter_2026&ref=newsletter',
      label: 'Sports Club with Multiple Normal Query Parameters'
    },
    {
      url: 'https://independent-bookstore-blog.org/reviews/sci-fi/dune-messiah-analysis/?utm_source=twitter&utm_medium=social&utm_campaign=spring_reads&fbclid=IwAR29182371923',
      label: 'Long Blog URL with Standard UTM and Social Tracking Parameters'
    },
    {
      url: 'https://docs.api.small-saas-tool.dev/v1/endpoints/get-user-profile?fields=id,name,email',
      label: 'Developer Documentation on Multi-Level Domain with Deep Path'
    }
  ];

  for (const site of unfamiliarCleanSites) {
    totalCleanTested++;
    const res = await simulate(app, {
      method: 'POST',
      url: '/api/scan',
      body: { url: site.url },
      ip: `10.1.2.${Math.floor(Math.random() * 200)}`
    });

    const isClean = res.data.verdict === 'NO SUSPICIOUS INDICATORS FOUND — LOCAL ANALYSIS ONLY' ||
                    res.data.verdict === 'NOT FLAGGED BY LOCAL ANALYSIS' ||
                    res.data.verdict === 'NO THREAT INDICATORS DETECTED';

    if (!isClean) cleanFalsePositives++;

    assert(res.statusCode === 200, `${site.label} returns 200 OK`);
    assert(isClean, `${site.label} NOT flagged as suspicious`, `Verdict was ${res.data.verdict}`);
    assert(res.data.isPopularDomain === false, `${site.label} correctly identified as unranked`);
    assert(res.data.findings.filter(f => f.severity === 'high').length === 0, `${site.label} has 0 high severity findings`);
    assert(res.data.score <= 15, `${site.label} has low severity score (<= 15)`);
  }

  // ---------------------------------------------------------------------------
  // SUITE 4: LEGITIMATE OAUTH / FEDERATED REDIRECTS (NO FALSE POSITIVES)
  // Legitimate redirect_uri on trusted identity providers must NOT be flagged.
  // ---------------------------------------------------------------------------
  console.log('\n--- SUITE 4: LEGITIMATE OAUTH / FEDERATED REDIRECTS ---');
  const legitimateOAuth = [
    {
      url: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=123.apps.googleusercontent.com&redirect_uri=https://my-saas-app.com/auth/callback&response_type=code&scope=openid%20profile%20email',
      label: 'Google OAuth 2.0 Authorization Endpoint'
    },
    {
      url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc-123&response_type=code&redirect_uri=https://app.workplace.com/login',
      label: 'Microsoft Azure Entra OAuth Endpoint'
    },
    {
      url: 'https://github.com/login/oauth/authorize?client_id=gh123&redirect_uri=https://my-developer-tool.io/callback',
      label: 'GitHub OAuth Authorization Endpoint'
    }
  ];

  for (const oauth of legitimateOAuth) {
    totalCleanTested++;
    const res = await simulate(app, {
      method: 'POST',
      url: '/api/scan',
      body: { url: oauth.url },
      ip: `10.1.3.${Math.floor(Math.random() * 200)}`
    });

    const isClean = res.data.verdict === 'NO SUSPICIOUS INDICATORS FOUND — LOCAL ANALYSIS ONLY' ||
                    res.data.verdict === 'NOT FLAGGED BY LOCAL ANALYSIS' ||
                    res.data.verdict === 'NO THREAT INDICATORS DETECTED';

    if (!isClean) cleanFalsePositives++;

    assert(isClean, `${oauth.label} NOT flagged as open redirect`, `Verdict was ${res.data.verdict}`);
    assert(!res.data.findings.some(f => f.title.toLowerCase().includes('open redirect')), `${oauth.label} contains no open redirect finding`);
  }

  // ---------------------------------------------------------------------------
  // SUITE 5: DECEPTIVE & THREAT DOMAIN DETECTION (100% TRUE POSITIVES)
  // ---------------------------------------------------------------------------
  console.log('\n--- SUITE 5: DECEPTIVE & THREAT DOMAIN DETECTION ---');

  // A. Misleading brand subdomain
  totalThreatsTested++;
  const brandSpoof = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://amazon.in.phishing-fake.xyz/login' },
    ip: '10.2.1.1'
  });
  if (brandSpoof.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(brandSpoof.data.verdict === 'SUSPICIOUS', 'amazon.in.phishing-fake.xyz flagged as SUSPICIOUS');
  assert(brandSpoof.data.isPopularDomain === false, 'amazon.in.phishing-fake.xyz is NOT marked popular');
  assert(brandSpoof.data.registeredDomain === 'phishing-fake.xyz', 'Registered domain is correctly phishing-fake.xyz');
  assert(brandSpoof.data.findings.some(f => f.title.includes('Misleading brand')), 'Flags Misleading brand in subdomain');

  // B. Typosquatting (amazn.in)
  totalThreatsTested++;
  const typo = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://amazn.in/login' },
    ip: '10.2.1.2'
  });
  if (typo.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(typo.data.verdict === 'SUSPICIOUS', 'amazn.in flagged as SUSPICIOUS');
  assert(typo.data.findings.some(f => f.title.includes('Typosquatting')), 'Flags Typosquatting for amazn.in');

  // C. Leetspeak / Character Substitution (paypa1.com)
  totalThreatsTested++;
  const leet = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://paypa1.com/account' },
    ip: '10.2.1.3'
  });
  if (leet.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(leet.data.verdict === 'SUSPICIOUS', 'paypa1.com flagged as SUSPICIOUS');
  assert(leet.data.findings.some(f => f.title.includes('Character Substitution')), 'Flags Character Substitution for paypa1.com');

  // D. Combosquatting (amazon-security-update.com)
  totalThreatsTested++;
  const combo = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://amazon-security-update.com/signin' },
    ip: '10.2.1.4'
  });
  if (combo.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(combo.data.verdict === 'SUSPICIOUS', 'amazon-security-update.com flagged as SUSPICIOUS');
  assert(combo.data.findings.some(f => f.title.includes('Combosquatting')), 'Flags Combosquatting');

  // E. Punycode IDN Homograph
  totalThreatsTested++;
  const puny = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://xn--pple-43d.com/login' },
    ip: '10.2.1.5'
  });
  if (puny.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(puny.data.verdict === 'SUSPICIOUS', 'xn--pple-43d.com flagged as SUSPICIOUS');
  assert(puny.data.findings.some(f => f.title.includes('Punycode')), 'Flags Punycode IDN');

  // F. Double File Extension (.pdf.exe)
  totalThreatsTested++;
  const dblExt = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://example-file-host.org/urgent-invoice.pdf.exe' },
    ip: '10.2.1.6'
  });
  if (dblExt.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(dblExt.data.verdict === 'SUSPICIOUS', 'invoice.pdf.exe flagged as SUSPICIOUS');
  assert(dblExt.data.findings.some(f => f.title.includes('double file extension')), 'Flags double file extension');

  // G. Open Redirect on Unranked Site
  totalThreatsTested++;
  const openRedir = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://random-forum-site.org/redirect.php?url=https://attacker-stealer.xyz' },
    ip: '10.2.1.7'
  });
  if (openRedir.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(openRedir.data.verdict === 'SUSPICIOUS', 'Open redirect on unranked site flagged as SUSPICIOUS');
  assert(openRedir.data.findings.some(f => f.title.includes('open redirect')), 'Flags open redirect');

  // H. Suspicious Service Port
  totalThreatsTested++;
  const portScan = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'http://example-node.org:1337/backdoor' },
    ip: '10.2.1.8'
  });
  if (portScan.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(portScan.data.verdict === 'SUSPICIOUS', 'Port 1337 flagged as SUSPICIOUS');
  assert(portScan.data.findings.some(f => f.title.includes('Unusual service port')), 'Flags service port 1337');

  // I. Cryptocurrency Seed Phrase Lure
  totalThreatsTested++;
  const cryptoLure = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://metamask-security-vault.net/wallet/enter-secret-recovery-phrase.html' },
    ip: '10.2.1.9'
  });
  if (cryptoLure.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(cryptoLure.data.verdict === 'SUSPICIOUS', 'Crypto seed phrase lure flagged as SUSPICIOUS');
  assert(cryptoLure.data.findings.some(f => f.title.toLowerCase().includes('seed phrase')), 'Flags seed phrase harvest attempt');

  // J. Embedded Basic Auth Credentials
  totalThreatsTested++;
  const credsScan = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://root:supersecret123@suspicious-bank-node.com/admin' },
    ip: '10.2.1.10'
  });
  if (credsScan.data.verdict === 'SUSPICIOUS') threatsDetected++;
  assert(credsScan.data.verdict === 'SUSPICIOUS', 'Embedded credentials flagged as SUSPICIOUS');
  assert(credsScan.data.findings.some(f => f.title.toLowerCase().includes('credentials')), 'Flags embedded credentials');

  // ---------------------------------------------------------------------------
  // SUITE 6: SSRF DEFENSE & OBFUSCATED IP HOSTS
  // ---------------------------------------------------------------------------
  console.log('\n--- SUITE 6: SSRF DEFENSE & OBFUSCATED IP HOSTS ---');
  const ssrfCases = [
    { url: 'http://169.254.169.254/latest/meta-data/', label: 'AWS/GCP Cloud Metadata 169.254.169.254' },
    { url: 'http://127.0.0.1:8080/actuator/env', label: 'Localhost IPv4 127.0.0.1' },
    { url: 'http://localhost:3000/api/keys', label: 'Localhost Hostname' },
    { url: 'http://10.0.0.1/network-status', label: 'RFC 1918 Private Class A (10.0.0.0/8)' },
    { url: 'http://172.16.0.1/docker', label: 'RFC 1918 Private Class B (172.16.0.0/12)' },
    { url: 'http://192.168.1.254/router', label: 'RFC 1918 Private Class C (192.168.0.0/16)' },
    { url: 'http://[::1]:9090/metrics', label: 'IPv6 Loopback ::1' },
    { url: 'http://0x7f000001/shell', label: 'Hex-Encoded IP (0x7f000001)' },
    { url: 'http://2130706433/admin', label: 'Dword-Encoded IP (2130706433)' }
  ];

  for (const ssrf of ssrfCases) {
    totalThreatsTested++;
    const res = await simulate(app, {
      method: 'POST',
      url: '/api/scan',
      body: { url: ssrf.url },
      ip: `10.2.2.${Math.floor(Math.random() * 200)}`
    });

    if (res.data.verdict === 'SUSPICIOUS') threatsDetected++;
    assert(res.data.verdict === 'SUSPICIOUS', `${ssrf.label} flagged as SUSPICIOUS`);
    assert(res.data.findings.some(f => f.title.includes('Internal') || f.title.includes('numeric IP') || f.title.includes('Private')), `${ssrf.label} has SSRF / Obfuscated finding`);
    // Verify external reputation check was safely skipped for internal destinations
    const urlhausSource = (res.data.sources || []).find(s => s.name === 'URLhaus Community Threat Database');
    if (urlhausSource) {
      assert(urlhausSource.status === 'not_applicable', `${ssrf.label} bypassed external API check (SSRF Safe)`);
    }
  }

  // ---------------------------------------------------------------------------
  // SUITE 7: INPUT VALIDATION & SANITIZATION
  // ---------------------------------------------------------------------------
  console.log('\n--- SUITE 7: INPUT VALIDATION & SANITIZATION ---');
  const malformedInputs = [
    { url: 'not_a_valid_url', label: 'Plain text string' },
    { url: 'ftp://files.example.com/bin', label: 'FTP scheme' },
    { url: 'javascript:alert(1)', label: 'JavaScript pseudoprotocol' },
    { url: 'data:text/html,<script>alert(1)</script>', label: 'Data URI' },
    { url: 'file:///etc/passwd', label: 'File URI scheme' },
    { url: '', label: 'Empty string' },
    { url: 'https://example.com/path\x00withnull', label: 'Null byte injection' },
    { url: 'https://example.com/' + 'a'.repeat(2100), label: 'Oversized URL (> 2048 chars)' }
  ];

  for (const item of malformedInputs) {
    const res = await simulate(app, {
      method: 'POST',
      url: '/api/scan',
      body: { url: item.url },
      ip: `10.3.1.${Math.floor(Math.random() * 200)}`
    });
    assert(res.statusCode === 400, `${item.label} rejected with HTTP 400`);
    assert(res.data.verdict === 'UNABLE TO VERIFY', `${item.label} returns UNABLE TO VERIFY`);
  }

  // ---------------------------------------------------------------------------
  // SUITE 8: EXTERNAL THREAT INTELLIGENCE (URLhaus Community Feed)
  // ---------------------------------------------------------------------------
  console.log('\n--- SUITE 8: EXTERNAL THREAT INTELLIGENCE INTEGRATION ---');
  const originalFetch = global.fetch;
  process.env.URLHAUS_AUTH_KEY = 'mock_community_auth_key';

  // Scenario 1: Confirmed Threat Intel Match
  totalThreatsTested++;
  global.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      query_status: 'ok',
      threat: 'malware_download',
      url_status: 'online',
      date_added: '2026-03-01',
      tags: ['trojan', 'redline']
    })
  });

  const malwareRes = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://verified-threat-distribution.xyz/payload.exe' },
    ip: '10.4.1.1'
  });

  const isConfirmed = malwareRes.data.verdict === 'CONFIRMED MALICIOUS' || malwareRes.data.verdict === 'CONFIRMED MALWARE';
  if (isConfirmed) threatsDetected++;
  assert(isConfirmed, 'Threat intel match results in CONFIRMED MALICIOUS verdict');
  assert(malwareRes.data.score >= 95, 'Confirmed threat score is >= 95');
  assert(malwareRes.data.riskLevel === 'Critical', 'Confirmed threat risk level is Critical');

  // Scenario 2: External Intel Checked and Clean
  global.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ query_status: 'no_results' })
  });

  totalCleanTested++;
  const cleanExtRes = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://www.amazon.in/' },
    ip: '10.4.1.2'
  });

  const isIntelClean = cleanExtRes.data.verdict === 'NO THREAT INDICATORS DETECTED' || cleanExtRes.data.verdict === 'NO KNOWN THREATS DETECTED';
  if (!isIntelClean) cleanFalsePositives++;
  assert(isIntelClean, 'Verdict is NO THREAT INDICATORS DETECTED when URLhaus completed clean', `Verdict: ${cleanExtRes.data.verdict}`);

  // Scenario 3: External Intel Service Error / Timeout
  global.fetch = async () => {
    throw new Error('Connection timeout');
  };

  const errExtRes = await simulate(app, {
    method: 'POST',
    url: '/api/scan',
    body: { url: 'https://www.amazon.in/' },
    ip: '10.4.1.3'
  });
  assert(errExtRes.data.verdict === 'PARTIALLY VERIFIED', 'Verdict is PARTIALLY VERIFIED when external feed errors on otherwise clean URL');

  // Teardown
  global.fetch = originalFetch;
  delete process.env.URLHAUS_AUTH_KEY;

  // ---------------------------------------------------------------------------
  // SUITE 9: RATE LIMITER & CONCURRENCY PROTECTION
  // ---------------------------------------------------------------------------
  console.log('\n--- SUITE 9: RATE LIMITER & RESOURCE EXHAUSTION DEFENSE ---');
  const rateLimitIp = '198.51.100.42';
  let lastResponse;
  for (let i = 0; i < 61; i++) {
    lastResponse = await simulate(app, {
      method: 'POST',
      url: '/api/scan',
      body: { url: 'https://www.amazon.in/' },
      ip: rateLimitIp
    });
  }
  assert(lastResponse.statusCode === 429, '61st request from same IP triggers HTTP 429');
  assert(lastResponse.data.verdict === 'UNABLE TO VERIFY', 'Rate limited response returns UNABLE TO VERIFY');

  // ---------------------------------------------------------------------------
  // FINAL METRICS & SUMMARY
  // ---------------------------------------------------------------------------
  const fpRate = ((cleanFalsePositives / totalCleanTested) * 100).toFixed(2);
  const tpRate = ((threatsDetected / totalThreatsTested) * 100).toFixed(2);

  console.log(`\n=====================================================`);
  console.log(`SPRIZAN VERIFICATION AUDIT METRICS`);
  console.log(`=====================================================`);
  console.log(`Total Clean URLs Evaluated:      ${totalCleanTested}`);
  console.log(`Clean False Positives:           ${cleanFalsePositives}`);
  console.log(`False Positive Rate:             ${fpRate}% (TARGET: 0.00%)`);
  console.log(`Total Threat Samples Evaluated:  ${totalThreatsTested}`);
  console.log(`Threats Successfully Detected:   ${threatsDetected}`);
  console.log(`Detection True Positive Rate:    ${tpRate}% (TARGET: 100.00%)`);
  console.log(`-----------------------------------------------------`);
  console.log(`Assertions Passed: ${passCount}`);
  console.log(`Assertions Failed: ${failCount}`);
  console.log(`=====================================================\n`);

  assert(cleanFalsePositives === 0, 'False positive rate on legitimate and unfamiliar clean sites is strictly 0.00%');
  assert(threatsDetected === totalThreatsTested, 'True positive detection rate on malicious/deceptive samples is 100.00%');

  process.exit(failCount > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
