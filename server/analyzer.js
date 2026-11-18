import { URL } from 'node:url';
import { TOP_LEGITIMATE_DOMAINS, TARGET_BRANDS, isRecognizedTopDomain } from './top-domains.js';

/**
 * Comprehensive multi-part public suffixes (2-level and 3-level ccTLDs).
 * Ensures accurate registered domain extraction for global and regional sites.
 */
const MULTI_PART_TLDS = new Set([
  // India
  'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'mil.in', 'gen.in', 'ind.in',
  // United Kingdom
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'police.uk', 'net.uk', 'sch.uk',
  // Australia
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  // New Zealand
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'geek.nz', 'school.nz',
  // Japan
  'co.jp', 'ne.jp', 'ac.jp', 'go.jp', 'or.jp', 'ed.jp', 'lg.jp',
  // Brazil
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'art.br',
  // China
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  // Singapore
  'com.sg', 'edu.sg', 'gov.sg', 'org.sg', 'net.sg',
  // South Africa
  'co.za', 'org.za', 'gov.za', 'ac.za', 'net.za',
  // Mexico
  'com.mx', 'org.mx', 'gob.mx', 'edu.mx', 'net.mx',
  // South Korea
  'co.kr', 'ne.kr', 're.kr', 'or.kr', 'go.kr', 'ac.kr',
  // Taiwan
  'com.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw',
  // Hong Kong
  'com.hk', 'org.hk', 'gov.hk', 'edu.hk', 'idv.hk',
  // Turkey
  'com.tr', 'edu.tr', 'gov.tr', 'org.tr', 'net.tr',
  // Argentina
  'com.ar', 'org.ar', 'gov.ar', 'edu.ar', 'net.ar',
  // Colombia
  'com.co', 'co.co', 'edu.co', 'org.co', 'gov.co',
  // Malaysia
  'com.my', 'edu.my', 'gov.my', 'org.my', 'net.my',
  // Indonesia
  'co.id', 'web.id', 'go.id', 'ac.id', 'sch.id', 'or.id',
  // Vietnam
  'com.vn', 'edu.vn', 'gov.vn', 'org.vn', 'net.vn',
  // Pakistan
  'com.pk', 'org.pk', 'gov.pk', 'edu.pk', 'net.pk',
  // Nigeria
  'com.ng', 'org.ng', 'gov.ng', 'edu.ng', 'net.ng',
  // Philippines
  'com.ph', 'org.ph', 'gov.ph', 'edu.ph', 'net.ph',
  // Bangladesh
  'com.bd', 'org.bd', 'gov.bd', 'edu.bd',
  // Thailand
  'co.th', 'ac.th', 'go.th', 'or.th',
  // Egypt, Saudi, UAE
  'com.eg', 'edu.eg', 'gov.eg',
  'com.sa', 'edu.sa', 'gov.sa',
  'com.ae', 'gov.ae', 'ac.ae',
  // Canada
  'gc.ca', 'gov.bc.ca', 'on.ca', 'qc.ca'
]);

/**
 * TLDs with historically high abuse or disposable registration volumes.
 */
const HIGH_ABUSE_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'work', 'click', 'buzz',
  'rest', 'country', 'surf', 'tokyo', 'gdn', 'kim', 'loan', 'racing'
]);

/**
 * Suspicious non-web service ports.
 */
const SUSPICIOUS_PORTS = {
  21: 'FTP (File Transfer Protocol)',
  22: 'SSH (Secure Shell)',
  23: 'Telnet (Unencrypted remote terminal)',
  25: 'SMTP (Mail routing)',
  110: 'POP3 (Mail access)',
  143: 'IMAP (Mail access)',
  445: 'SMB (File sharing - frequently abused)',
  1337: 'Common backdoor / exploit port',
  3389: 'RDP (Remote Desktop)',
  6667: 'IRC (Internet Relay Chat / Botnet C2)'
};

/**
 * Damerau-Levenshtein distance algorithm for typosquatting detection.
 */
function damerauLevenshtein(a, b) {
  if (a === b) return 0;
  const la = a.length;
  const lb = b.length;
  if (!la) return lb;
  if (!lb) return la;

  const d = Array.from({ length: la + 1 }, () => new Array(lb + 1).fill(0));
  for (let i = 0; i <= la; i++) d[i][0] = i;
  for (let j = 0; j <= lb; j++) d[0][j] = j;

  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1,       // deletion
        d[i][j - 1] + 1,       // insertion
        d[i - 1][j - 1] + cost // substitution
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); // transposition
      }
    }
  }
  return d[la][lb];
}

/**
 * Extract the true registered domain (e.g., "amazon.in" from "www.amazon.in",
 * "google.co.in" from "mail.google.co.in", or "bbc.co.uk" from "news.bbc.co.uk").
 */
export function extractRegisteredDomain(hostname) {
  const clean = hostname.toLowerCase().replace(/^www\./, '');
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;

  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Check if an IP address is in a private, loopback, or reserved range.
 */
function isPrivateOrReservedIP(ip) {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) return false;

  const [o1, o2] = octets;
  if (o1 === 127) return { type: 'Loopback', range: '127.0.0.0/8' };
  if (o1 === 10) return { type: 'Private RFC 1918', range: '10.0.0.0/8' };
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return { type: 'Private RFC 1918', range: '172.16.0.0/12' };
  if (o1 === 192 && o2 === 168) return { type: 'Private RFC 1918', range: '192.168.0.0/16' };
  if (o1 === 169 && o2 === 254) return { type: 'Link-Local', range: '169.254.0.0/16' };
  if (o1 === 0) return { type: 'Current Network', range: '0.0.0.0/8' };

  return false;
}

/**
 * Check registered domain against target brands for typosquatting, combosquatting,
 * and visual leetspeak lookalikes.
 *
 * @param {string} registeredDomain
 * @returns {object|null} Typosquatting alert or null
 */
function detectTyposquatting(registeredDomain) {
  const domainLabel = registeredDomain.split('.')[0].toLowerCase();

  // Normalize leetspeak lookalikes
  const normalizedLabel = domainLabel
    .replace(/1/g, 'l')
    .replace(/0/g, 'o')
    .replace(/5/g, 's')
    .replace(/3/g, 'e')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm');

  for (const [brandKey, meta] of Object.entries(TARGET_BRANDS)) {
    // If it is an authorized canonical domain for the brand, do not flag
    if (meta.canonical.includes(registeredDomain)) {
      continue;
    }

    const brandName = meta.name;

    // 1. Combosquatting: brand hyphenated with lure keywords (e.g. amazon-security, login-paypal)
    const brandHyphenRegex = new RegExp(`(^|-)${brandKey}-(security|update|login|verify|account|support|service|portal|wallet|pay|auth|online|signin|checkout)($|-)`, 'i');
    const lureHyphenRegex = new RegExp(`^(security|update|login|verify|account|support|service|portal|wallet|pay|auth|online|signin|checkout)-${brandKey}($|-)`, 'i');

    if (brandHyphenRegex.test(domainLabel) || lureHyphenRegex.test(domainLabel)) {
      return {
        type: 'Combosquatting / Hyphenated Brand Lure',
        brand: brandName,
        detail: `The registered domain "${registeredDomain}" attaches an account lure keyword to popular brand "${brandName}". Combosquatting is frequently used to manufacture a deceptive sense of legitimacy.`
      };
    }

    // 2. Character substitution / Leetspeak: e.g. paypa1.com, g00gle.com
    if (normalizedLabel === brandKey && domainLabel !== brandKey) {
      return {
        type: 'Character Substitution / Lookalike Domain',
        brand: brandName,
        detail: `The registered domain "${registeredDomain}" substitutes characters (e.g. "1" for "l" or "0" for "o") to visually mimic brand "${brandName}".`
      };
    }

    // 3. Typosquatting / Damerau-Levenshtein edit distance: e.g. amazn, amzon, goolge
    // Only check if length is reasonably close
    if (Math.abs(domainLabel.length - brandKey.length) <= 2) {
      const dist = damerauLevenshtein(domainLabel, brandKey);
      // Distance of 1 (omission, insertion, transposition) is high-confidence typosquatting
      if (dist === 1 && domainLabel !== brandKey) {
        return {
          type: 'Potential Typosquatting / Lookalike Variation',
          brand: brandName,
          detail: `The registered domain "${registeredDomain}" varies by only 1 character from popular brand "${brandName}" (edit distance: 1). Typosquatting domains exploit typographical errors to deceive visitors.`
        };
      }
    }
  }

  return null;
}

/**
 * Inspect a URL and return detailed structural findings and severity score.
 * Never executes or fetches the URL.
 *
 * @param {string} raw
 * @returns {object} Analysis report object
 */
export function inspectUrl(raw) {
  const trimmed = String(raw || '').trim();
  if (!trimmed) {
    throw new Error('Please enter a URL to inspect.');
  }
  if (trimmed.length > 2048) {
    throw new Error('URL exceeds the maximum length limit of 2,048 characters.');
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
      throw new Error('Enter a valid URL including protocol (e.g. https://example.com).');
    }
    throw new Error('Invalid URL format. Please enter a syntactically valid URL.');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Protocol "${parsed.protocol}" is not supported. Only HTTP and HTTPS URLs can be analyzed.`);
  }

  const rawHost = parsed.hostname;
  if (!rawHost) {
    throw new Error('URL does not specify a valid host domain.');
  }

  const host = rawHost.toLowerCase().replace(/^www\./, '');
  const full = parsed.href;
  const findings = [];
  const add = (severity, title, detail, points, category = 'structural') => {
    findings.push({ severity, title, detail, points, category });
  };

  const registeredDomain = extractRegisteredDomain(host);
  const topDomainCheck = isRecognizedTopDomain(registeredDomain);
  const isTopDomain = topDomainCheck.isTopDomain;

  let isIP = false;
  let domainPoints = 0;
  let transportPoints = 0;
  let structuralPoints = 0;
  let contentPoints = 0;

  // 1. Embedded Credentials check (user:pass@host)
  if (parsed.username || parsed.password) {
    add(
      'high',
      'Embedded credentials in URL',
      'The URL contains user credentials before the hostname. This is frequently used in phishing attacks to mislead victims regarding the actual target server.',
      24,
      'domain'
    );
  } else if (/@/.test(trimmed)) {
    add(
      'high',
      'At-sign (@) in URL string',
      'An at-sign was detected in the URL. Characters before the "@" symbol can visually disguise the true destination domain that appears after it.',
      20,
      'domain'
    );
  }

  // 2. Protocol / Transport Security
  if (parsed.protocol === 'http:') {
    add(
      'medium',
      'Unencrypted HTTP connection',
      'The URL uses plain HTTP without TLS encryption. Traffic can be monitored or modified in transit. While not proof of malice, modern legitimate sites default to HTTPS.',
      12,
      'transport'
    );
  }

  // 3. Port Inspection
  if (parsed.port) {
    const portNum = Number(parsed.port);
    if (SUSPICIOUS_PORTS[portNum]) {
      add(
        'high',
        `Unusual service port (${portNum})`,
        `The URL connects to port ${portNum} (${SUSPICIOUS_PORTS[portNum]}). Legitimate web applications rarely run on internal or administrative service ports.`,
        22,
        'transport'
      );
    } else if (![80, 443].includes(portNum)) {
      add(
        'low',
        `Non-standard web port (${portNum})`,
        `The URL specifies custom port ${portNum}. Legitimate web services normally run on standard ports (80 for HTTP, 443 for HTTPS).`,
        8,
        'transport'
      );
    }
  }

  // 4. IP-Based Hostname & Obfuscation
  const rawHostBeforeCanonical = (trimmed.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/:?#]+)/) || [])[1] || '';
  const isHexOrDwordIP = /^0x[0-9a-fA-F]+$/i.test(rawHostBeforeCanonical) ||
    /^\d{8,10}$/.test(rawHostBeforeCanonical) ||
    /^(0x[0-9a-fA-F]+\.){3}0x[0-9a-fA-F]+$/i.test(rawHostBeforeCanonical);

  const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  const isIPv6 = /^\[.*\]$/.test(rawHost);

  if (isHexOrDwordIP) {
    isIP = true;
    add(
      'high',
      'Obfuscated numeric IP representation',
      `The hostname uses hexadecimal or integer notation ("${rawHostBeforeCanonical}") to disguise an IP destination from URL string filters.`,
      25,
      'domain'
    );
  }

  if (isIPv4) {
    isIP = true;
    const reserved = isPrivateOrReservedIP(host);
    if (reserved) {
      add(
        'high',
        `Internal / ${reserved.type} IP address`,
        `The URL targets a private or internal network IP address (${reserved.range}). Legitimate public internet links do not target internal addresses.`,
        25,
        'domain'
      );
    } else if (!isHexOrDwordIP) {
      add(
        'high',
        'Direct IPv4 address used as host',
        'The link points directly to a numeric IP address rather than a domain name. This is commonly used in malware C2 servers and phishing to evade domain-based reputation filters.',
        22,
        'domain'
      );
    }
  } else if (isIPv6) {
    isIP = true;
    add(
      'high',
      'Direct IPv6 address used as host',
      'The link targets an explicit IPv6 address instead of a standard registered domain name.',
      20,
      'domain'
    );
  }

  // 5. Homograph & Punycode (IDN) Indicators
  if (host.startsWith('xn--') || host.includes('.xn--')) {
    add(
      'high',
      'Internationalized domain name (Punycode)',
      'The domain contains Punycode ("xn--"). While legitimate for non-Latin writing systems, attackers frequently use it in homograph attacks to imitate well-known Latin brand domains with visually identical foreign glyphs.',
      22,
      'structural'
    );
  }

  // Hidden / bidirectional / zero-width characters in URL
  if (/[\u200B\u200C\u200D\uFEFF\u00AD\u202E\u202A\u202B\u202C\u202D]/.test(raw)) {
    add(
      'high',
      'Invisible or bidirectional unicode characters',
      'The URL contains zero-width, soft-hyphen, or direction-reversing unicode characters. These are malicious obfuscation techniques used to trick the human eye or bypass regex filters.',
      25,
      'structural'
    );
  }

  // 6. Domain Structure, Brand Impersonation & Typosquatting
  let detectedBrandSpoof = false;
  if (!isIP) {
    const hostLabels = host.split('.');
    const registeredParts = registeredDomain.split('.');
    const subdomains = hostLabels.slice(0, hostLabels.length - registeredParts.length);

    // Excessive subdomain depth
    if (hostLabels.length >= 5) {
      add(
        'medium',
        'Excessive subdomain depth',
        `The hostname contains ${hostLabels.length} subdomain labels. Deeply nested subdomains are often deployed to push the real registered domain out of view on mobile screens.`,
        12,
        'structural'
      );
    }

    // Check Typosquatting & Combosquatting on the registered domain
    const typoAlert = detectTyposquatting(registeredDomain);
    if (typoAlert) {
      detectedBrandSpoof = true;
      add(
        'high',
        `${typoAlert.type} (${typoAlert.brand.toUpperCase()})`,
        typoAlert.detail,
        25,
        'domain'
      );
    }

    // Check Misleading Brand in Subdomains
    if (!detectedBrandSpoof) {
      for (const [brandKey, meta] of Object.entries(TARGET_BRANDS)) {
        // If the registered domain is canonical for this brand, it is legitimate
        if (meta.canonical.includes(registeredDomain)) {
          continue;
        }

        const subString = subdomains.join('.');
        const brandRegex = new RegExp(`(^|[-._])${brandKey}([-._]|$)`, 'i');
        if (brandRegex.test(subString) || brandRegex.test(host.replace(registeredDomain, ''))) {
          detectedBrandSpoof = true;
          add(
            'high',
            `Misleading brand in subdomain (${meta.name.toUpperCase()})`,
            `The URL displays brand keyword "${brandKey}" in its subdomain, but the actual registered destination is "${registeredDomain}". This is a primary indicator of brand impersonation phishing.`,
            25,
            'domain'
          );
          break;
        }
      }
    }

    // High-abuse TLDs with credential lures
    const tld = hostLabels[hostLabels.length - 1];
    if (HIGH_ABUSE_TLDS.has(tld)) {
      if (/(login|verify|secure|account|update|wallet|banking|auth|recovery|password)/i.test(host) ||
          /(login|verify|secure|account|update|wallet|banking|auth|recovery|password)/i.test(parsed.pathname)) {
        add(
          'medium',
          `High-risk TLD (.${tld}) with account lure`,
          `The domain uses a top-level domain frequently associated with disposable registrations (.${tld}) combined with sensitive account keywords.`,
          16,
          'domain'
        );
      } else {
        add(
          'low',
          `Elevated-risk top-level domain (.${tld})`,
          `The domain uses an extension (.${tld}) with elevated prevalence in disposable and abusive infrastructure.`,
          6,
          'domain'
        );
      }
    }
  }

  // 7. Contextual Path & Query Deceptions
  const pathAndSearch = (parsed.pathname + parsed.search).toLowerCase();

  // Deceptive double file extension in path (e.g. statement.pdf.exe)
  const doubleExtMatch = parsed.pathname.match(/\.(pdf|doc|docx|xls|xlsx|jpg|png|zip|rar|tar)\.(exe|scr|bat|cmd|vbs|js|ps1|apk|msi|iso|hta)$/i);
  if (doubleExtMatch) {
    add(
      'high',
      'Deceptive double file extension',
      `The URL path contains a deceptive double extension "${doubleExtMatch[0]}". Attackers use this to trick users into downloading executable malware disguised as a document or image.`,
      25,
      'content'
    );
  }

  // Crypto / seed phrase lure in path or host
  if (/(seed[-_]?phrase|recovery[-_]?phrase|private[-_]?key|keystore[-_]?json|secret[-_]?recovery)/i.test(pathAndSearch) ||
      /(seed[-_]?phrase|recovery[-_]?phrase|private[-_]?key)/i.test(host)) {
    add(
      'high',
      'Cryptocurrency credential / seed phrase lure',
      'The URL targets cryptocurrency private keys, seed phrases, or wallet recovery files. Legitimate services never request secret recovery phrases via web links.',
      25,
      'content'
    );
  }

  // Potential Open Redirect parameters
  for (const [param, val] of parsed.searchParams.entries()) {
    if (['url', 'redirect', 'redirect_uri', 'next', 'dest', 'destination', 'return', 'goto', 'rurl', 'target', 'link'].includes(param.toLowerCase())) {
      if (/^https?:\/\//i.test(val) || val.startsWith('//')) {
        add(
          'high',
          `Potential open redirect parameter ("${param}")`,
          `The query parameter "${param}" points directly to an external destination ("${val.slice(0, 50)}..."). Open redirects are exploited in phishing campaigns to route victims to unvetted external sites.`,
          22,
          'content'
        );
        break;
      }
    }
  }

  // 8. Obfuscation & Encoding
  if (/(%[0-9a-fA-F]{2}){4,}/i.test(full)) {
    add(
      'medium',
      'Repeated percent-encoding in URL',
      'The URL contains four or more consecutive percent-encoded sequences, often employed to obscure the true path or parameters from casual inspection.',
      8,
      'structural'
    );
  }

  if (/%25[0-9a-fA-F]{2}/i.test(full)) {
    add(
      'medium',
      'Double percent-encoding detected',
      'The URL contains double-encoded character sequences (%25..), which can bypass certain web application firewalls and security filters.',
      12,
      'structural'
    );
  }

  // 9. Host and URL Length (Low-severity structural signals)
  if (host.length > 50) {
    add(
      'low',
      'Unusually long hostname',
      `The hostname is ${host.length} characters long. While some legitimate CDNs use long hosts, attackers also generate long hostnames to avoid collisions.`,
      5,
      'structural'
    );
  }

  if (full.length > 250) {
    add(
      'low',
      'Unusually long URL string',
      `The full URL is ${full.length} characters long. Long URLs can be legitimate but may also harbor large tracking or payload delivery parameters.`,
      4,
      'structural'
    );
  }

  // 10. Sensitive keywords on UNVERIFIED domains only (avoid false positives on top domains)
  if (!isTopDomain && !detectedBrandSpoof && !isIP) {
    if (/(login|verify|secure|account|update|wallet|password|confirm|banking|authentication)/i.test(host)) {
      add(
        'low',
        'Account or authentication keywords in unranked host',
        'The hostname on an unverified domain contains terms commonly associated with account or banking portals. On unverified domains, this can be an indicator of credential harvesting.',
        6,
        'domain'
      );
    }
  }

  // Calculate component scores with anti-double-counting caps
  for (const f of findings) {
    if (f.category === 'domain') domainPoints += f.points;
    else if (f.category === 'transport') transportPoints += f.points;
    else if (f.category === 'structural') structuralPoints += f.points;
    else if (f.category === 'content') contentPoints += f.points;
  }

  const domainScore = Math.min(25, domainPoints);
  const transportScore = Math.min(25, transportPoints);
  const structuralScore = Math.min(25, structuralPoints);
  const contentScore = Math.min(25, contentPoints);

  const highPoints = findings.filter(f => f.severity === 'high').reduce((acc, f) => acc + f.points, 0);
  const medPoints = findings.filter(f => f.severity === 'medium').reduce((acc, f) => acc + f.points, 0);
  const lowPoints = Math.min(15, findings.filter(f => f.severity === 'low').reduce((acc, f) => acc + f.points, 0));

  let score = Math.min(100, highPoints + medPoints + lowPoints);
  const hasHighSeverity = findings.some(f => f.severity === 'high');

  return {
    normalizedUrl: full,
    host,
    registeredDomain,
    isPopularDomain: isTopDomain,
    brandRecognized: topDomainCheck.brand || null,
    domainReputationNote: isTopDomain
      ? `Recognized Global Top Domain (${topDomainCheck.brand ? topDomainCheck.brand + ' — ' : ''}${registeredDomain})`
      : 'Unranked / General Domain',
    findings,
    score,
    hasHighSeverity,
    componentScores: {
      domain: domainScore,
      transport: transportScore,
      structural: structuralScore,
      content: contentScore
    }
  };
}
