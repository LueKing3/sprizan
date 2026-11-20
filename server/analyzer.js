import { URL } from 'node:url';
import {
  TOP_LEGITIMATE_DOMAINS,
  TARGET_BRANDS,
  MULTI_PART_SUFFIXES,
  MANAGED_HOSTING_PLATFORMS,
  extractRegisteredDomain,
  isRecognizedTopDomain
} from './top-domains.js';

export { extractRegisteredDomain, isRecognizedTopDomain };

/**
 * TLDs with historically high prevalence in disposable and abusive infrastructure.
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
  445: 'SMB (Direct host file sharing - heavily abused)',
  1337: 'Common backdoor / exploit port',
  3389: 'RDP (Remote Desktop Protocol)',
  6667: 'IRC (Internet Relay Chat / Botnet C2)'
};

/**
 * Damerau-Levenshtein distance algorithm for typosquatting detection.
 * Accounts for insertions, deletions, substitutions, and adjacent transpositions.
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
 * Check if an IP address is private, loopback, carrier-grade NAT, or cloud metadata.
 * Strict SSRF mitigation: prevents internal network reconnaissance.
 */
export function isPrivateOrReservedIP(ip) {
  if (!ip) return false;
  const clean = ip.replace(/^\[|\]$/g, '').trim().toLowerCase();

  // IPv6 checks
  if (clean === '::1' || clean === '0:0:0:0:0:0:0:1') return { type: 'IPv6 Loopback', range: '::1/128' };
  if (clean === '::' || clean === '0:0:0:0:0:0:0:0') return { type: 'IPv6 Unspecified', range: '::/128' };
  if (clean.startsWith('fe80:')) return { type: 'IPv6 Link-Local', range: 'fe80::/10' };
  if (clean.startsWith('fc00:') || clean.startsWith('fd00:')) return { type: 'IPv6 Unique Local', range: 'fc00::/7' };

  // IPv4 checks
  const octets = clean.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) return false;

  const [o1, o2] = octets;
  if (o1 === 127) return { type: 'Loopback', range: '127.0.0.0/8' };
  if (o1 === 10) return { type: 'Private RFC 1918', range: '10.0.0.0/8' };
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return { type: 'Private RFC 1918', range: '172.16.0.0/12' };
  if (o1 === 192 && o2 === 168) return { type: 'Private RFC 1918', range: '192.168.0.0/16' };
  if (o1 === 169 && o2 === 254) return { type: 'Cloud Metadata / Link-Local', range: '169.254.0.0/16' };
  if (o1 === 100 && o2 >= 64 && o2 <= 127) return { type: 'Carrier-Grade NAT', range: '100.64.0.0/10' };
  if (o1 === 0) return { type: 'Current Network', range: '0.0.0.0/8' };

  return false;
}

/**
 * Check registered domain against target brands for typosquatting, combosquatting,
 * and visual character substitutions.
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
        detail: `The registered domain "${registeredDomain}" pairs a popular brand name ("${brandName}") with an account/security lure keyword. Combosquatting is a known phishing tactic to deceive users.`
      };
    }

    // 2. Character substitution / Leetspeak (e.g. paypa1.com, g00gle.com, rnicrosoft.com)
    if (normalizedLabel === brandKey && domainLabel !== brandKey) {
      return {
        type: 'Character Substitution / Lookalike Domain',
        brand: brandName,
        detail: `The registered domain "${registeredDomain}" substitutes characters (e.g. "1" for "l" or "0" for "o") to visually imitate brand "${brandName}".`
      };
    }

    // 3. Typosquatting / Edit distance (e.g. amazn.in, goolge.com)
    if (Math.abs(domainLabel.length - brandKey.length) <= 2) {
      const dist = damerauLevenshtein(domainLabel, brandKey);
      if (dist === 1 && domainLabel !== brandKey) {
        return {
          type: 'Potential Typosquatting / Lookalike Variation',
          brand: brandName,
          detail: `The registered domain "${registeredDomain}" varies by only 1 character from popular brand "${brandName}" (edit distance: 1). Typosquatting exploits typographical mistakes to hijack traffic.`
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

  // Reject dangerous non-web schemes and control characters
  if (/[\x00-\x1F\x7F]/.test(trimmed)) {
    throw new Error('URL contains illegal control characters or null bytes.');
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

  const host = rawHost.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  const full = parsed.href;
  const findings = [];
  const add = (severity, title, detail, points, category = 'structural') => {
    findings.push({ severity, title, detail, points, category });
  };

  const registeredDomain = extractRegisteredDomain(host);
  const topDomainCheck = isRecognizedTopDomain(registeredDomain);
  const isTopDomain = topDomainCheck.isTopDomain;

  let isIP = false;
  let isInternalIP = false;

  // 1. Embedded Credentials check (user:pass@host)
  if (parsed.username || parsed.password) {
    add(
      'high',
      'Embedded credentials in URL authority',
      'The URL contains user credentials before the hostname. This is frequently used in phishing attacks to mislead victims regarding the actual target destination.',
      35,
      'domain'
    );
  } else if (/@/.test(trimmed.split('?')[0].split('#')[0])) {
    add(
      'high',
      'At-sign (@) in URL authority',
      'An at-sign was detected in the URL authority section. Browsers interpret text before the "@" as userinfo, while the actual destination server appears after it.',
      30,
      'domain'
    );
  }

  // 2. Protocol / Transport Security
  // Plain HTTP is noted as an informational/low signal, NOT treated as fraud by itself
  if (parsed.protocol === 'http:') {
    add(
      'low',
      'Unencrypted HTTP connection',
      'The URL uses plain HTTP without TLS encryption. Traffic can be monitored or modified in transit. While not evidence of fraud by itself, modern web services default to HTTPS.',
      5,
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
        `The URL connects to port ${portNum} (${SUSPICIOUS_PORTS[portNum]}). Legitimate web applications rarely run on internal or non-web service ports.`,
        30,
        'transport'
      );
    } else if (![80, 443, 8080, 8443, 3000, 5000, 8000].includes(portNum)) {
      add(
        'low',
        `Non-standard web port (${portNum})`,
        `The URL specifies custom port ${portNum}. Standard public web services typically operate on standard ports 80 (HTTP) or 443 (HTTPS).`,
        6,
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
  const isIPv6 = /^\[.*\]$/.test(rawHost) || /^[0-9a-fA-F:]+$/.test(host) && host.includes(':');

  if (isHexOrDwordIP) {
    isIP = true;
    add(
      'high',
      'Obfuscated numeric IP representation',
      `The hostname uses hexadecimal, octal, or integer notation ("${rawHostBeforeCanonical}") to disguise an IP destination from URL string filters.`,
      35,
      'domain'
    );
  }

  if (isIPv4 || isIPv6) {
    isIP = true;
    const reserved = isPrivateOrReservedIP(host);
    if (reserved) {
      isInternalIP = true;
      add(
        'high',
        `Internal / ${reserved.type} IP address (SSRF Risk)`,
        `The URL targets a private, internal, or loopback network address (${reserved.range}). Legitimate public internet links do not target internal host infrastructure.`,
        35,
        'domain'
      );
    } else if (!isHexOrDwordIP) {
      add(
        'high',
        'Direct numeric IP address used as host',
        'The link points directly to a numeric IP address rather than a domain name. Direct IP hosts are commonly used in malware C2 servers and phishing to evade domain-based reputation lists.',
        25,
        'domain'
      );
    }
  }

  // Localhost keyword check
  if (host === 'localhost' || host.endsWith('.localhost')) {
    isInternalIP = true;
    add(
      'high',
      'Internal / Localhost destination targeted (SSRF Risk)',
      'The URL targets the local loopback host (localhost). Legitimate public internet links do not target localhost.',
      35,
      'domain'
    );
  }

  // 5. Homograph & Punycode (IDN) Indicators
  if (host.startsWith('xn--') || host.includes('.xn--')) {
    add(
      'high',
      'Internationalized domain name (Punycode)',
      'The domain contains Punycode ("xn--"). While legitimate for non-Latin writing systems, attackers frequently deploy Punycode homographs to visually impersonate popular Latin brand domains.',
      25,
      'structural'
    );
  }

  // Hidden / bidirectional / zero-width characters in URL
  if (/[\u200B\u200C\u200D\uFEFF\u00AD\u202E\u202A\u202B\u202C\u202D]/.test(raw)) {
    add(
      'high',
      'Invisible or bidirectional unicode characters',
      'The URL contains zero-width, soft-hyphen, or direction-reversing unicode characters used to obscure true URLs or bypass security filters.',
      35,
      'structural'
    );
  }

  // 6. Domain Structure, Brand Impersonation & Typosquatting
  let detectedBrandSpoof = false;
  if (!isIP && !isInternalIP) {
    const hostLabels = host.split('.');
    const registeredParts = registeredDomain.split('.');
    const subdomains = hostLabels.slice(0, hostLabels.length - registeredParts.length);

    // Deep subdomain nesting (only flagged if >= 5 labels and NOT on a recognized top domain)
    if (hostLabels.length >= 5 && !isTopDomain) {
      add(
        'medium',
        'Excessive subdomain depth',
        `The hostname contains ${hostLabels.length} subdomain labels. Deeply nested subdomains on unranked domains are often used in phishing to push the real domain off-screen on mobile devices.`,
        15,
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
        35,
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
            35,
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
          20,
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
      `The URL path contains a deceptive double extension "${doubleExtMatch[0]}". Attackers use this to trick users into executing malware disguised as a document or image.`,
      35,
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
      35,
      'content'
    );
  }

  // Potential Open Redirect parameters:
  // Only evaluate on non-top domains or when target is suspicious, preventing false positives on legitimate OAuth flows
  if (!isTopDomain) {
    for (const [param, val] of parsed.searchParams.entries()) {
      if (['url', 'redirect', 'redirect_uri', 'next', 'dest', 'destination', 'return', 'goto', 'rurl', 'target', 'link'].includes(param.toLowerCase())) {
        if (/^https?:\/\//i.test(val) || val.startsWith('//')) {
          try {
            const destUrl = new URL(val.startsWith('//') ? 'https:' + val : val);
            const destRegistered = extractRegisteredDomain(destUrl.hostname);
            // Only flag if redirecting to a completely different external domain
            if (destRegistered && destRegistered !== registeredDomain) {
              add(
                'high',
                `Potential open redirect parameter ("${param}")`,
                `The query parameter "${param}" points to an external destination ("${val.slice(0, 50)}..."). Open redirects are exploited in phishing to route victims from trusted links to unvetted external sites.`,
                25,
                'content'
              );
              break;
            }
          } catch {}
        }
      }
    }
  }

  // 8. Dangerous Obfuscation & Encoding
  if (/%00|%0d%0a/i.test(full)) {
    add(
      'high',
      'Null byte or CRLF injection sequence detected',
      'The URL contains null bytes (%00) or CRLF characters (%0D%0A) designed to exploit parser vulnerabilities or HTTP response splitting.',
      35,
      'structural'
    );
  }

  if (/%25[0-9a-fA-F]{2}/i.test(full)) {
    add(
      'medium',
      'Double percent-encoding detected',
      'The URL contains double-encoded character sequences (%25..), which can bypass certain web application firewalls and security filters.',
      15,
      'structural'
    );
  }

  // Calculate component scores with anti-double-counting caps
  let domainPoints = 0;
  let transportPoints = 0;
  let structuralPoints = 0;
  let contentPoints = 0;

  for (const f of findings) {
    if (f.category === 'domain') domainPoints += f.points;
    else if (f.category === 'transport') transportPoints += f.points;
    else if (f.category === 'structural') structuralPoints += f.points;
    else if (f.category === 'content') contentPoints += f.points;
  }

  const domainScore = Math.min(35, domainPoints);
  const transportScore = Math.min(25, transportPoints);
  const structuralScore = Math.min(30, structuralPoints);
  const contentScore = Math.min(35, contentPoints);

  const highCount = findings.filter(f => f.severity === 'high').length;
  const medCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;

  const highPoints = findings.filter(f => f.severity === 'high').reduce((acc, f) => acc + f.points, 0);
  const medPoints = findings.filter(f => f.severity === 'medium').reduce((acc, f) => acc + f.points, 0);
  const lowPoints = Math.min(10, findings.filter(f => f.severity === 'low').reduce((acc, f) => acc + f.points, 0));

  let score = Math.min(100, highPoints + medPoints + lowPoints);
  const hasHighSeverity = highCount > 0;

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
    isInternalIP,
    findingCounts: {
      high: highCount,
      medium: medCount,
      low: lowCount,
      total: findings.length
    },
    componentScores: {
      domain: domainScore,
      transport: transportScore,
      structural: structuralScore,
      content: contentScore
    }
  };
}
