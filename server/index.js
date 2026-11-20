import express from 'express';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectUrl } from './analyzer.js';

dotenv.config();

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

// Basic security middleware & body size limits
app.use(express.json({ limit: '12kb' }));
app.use(express.static(path.join(root, 'public')));

// Memory-bounded in-memory rate limiting to prevent abuse & memory exhaustion
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 60;
const MAX_RATE_LIMIT_ENTRIES = 10000;

// Periodic cleanup of expired rate limit entries
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of rateLimitMap.entries()) {
    if (now - data.resetTime > RATE_LIMIT_WINDOW_MS) {
      rateLimitMap.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS);

function rateLimiter(req, res, next) {
  const clientIp = String(req.ip || req.headers['x-forwarded-for'] || '127.0.0.1').split(',')[0].trim();
  const now = Date.now();
  const entry = rateLimitMap.get(clientIp);

  if (!entry || now - entry.resetTime > RATE_LIMIT_WINDOW_MS) {
    if (rateLimitMap.size >= MAX_RATE_LIMIT_ENTRIES) {
      // Evict oldest entry if map exceeds memory limit
      const oldestKey = rateLimitMap.keys().next().value;
      if (oldestKey) rateLimitMap.delete(oldestKey);
    }
    rateLimitMap.set(clientIp, { count: 1, resetTime: now });
    return next();
  }

  if (entry.count >= RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({
      error: 'Rate limit exceeded (60 requests/minute). Please wait a moment before submitting more scans.',
      verdict: 'UNABLE TO VERIFY'
    });
  }

  entry.count++;
  next();
}

/**
 * Fetch wrapper with timeout and AbortController.
 * Strictly queries trusted threat-intel endpoints, NEVER the user-submitted URL.
 */
const timeoutFetch = async (url, options = {}, ms = 3500) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Free URLhaus Community API (abuse.ch)
 * URLhaus provides free community threat intelligence.
 * Official API documentation: https://urlhaus.abuse.ch/api/
 * Requires zero payment, zero credit card, and zero Google Cloud billing.
 */
async function checkUrlhaus(targetUrl, isInternalTarget = false) {
  if (isInternalTarget) {
    return {
      source: 'URLhaus Community Threat Feed',
      status: 'not_applicable',
      matches: [],
      note: 'Target resolves to private or internal network infrastructure. External threat intelligence query skipped for security (OWASP SSRF protection).'
    };
  }

  const key = process.env.URLHAUS_AUTH_KEY;
  if (!key) {
    return {
      source: 'URLhaus Community Threat Feed',
      status: 'not_configured',
      matches: [],
      note: 'Free URLhaus Auth-Key not configured. Obtain a free key from https://urlhaus.abuse.ch/api/ (no credit card or billing required).'
    };
  }

  try {
    const startTime = Date.now();
    const body = new URLSearchParams({ url: targetUrl });
    const response = await timeoutFetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: {
        'Auth-Key': key.trim(),
        'content-type': 'application/x-www-form-urlencoded'
      },
      body
    });

    const elapsed = Date.now() - startTime;

    if (response.status === 401 || response.status === 403) {
      return {
        source: 'URLhaus Community Threat Feed',
        status: 'error',
        matches: [],
        latencyMs: elapsed,
        note: 'URLhaus authentication failed. Verify your free Auth-Key from abuse.ch.'
      };
    }

    if (!response.ok) {
      return {
        source: 'URLhaus Community Threat Feed',
        status: 'error',
        matches: [],
        latencyMs: elapsed,
        note: `URLhaus service returned HTTP ${response.status}.`
      };
    }

    const data = await response.json();
    const hit = data.query_status === 'ok';

    return {
      source: 'URLhaus Community Threat Feed',
      status: 'checked',
      latencyMs: elapsed,
      matches: hit ? [{
        threat: data.threat,
        urlStatus: data.url_status,
        dateAdded: data.date_added,
        tags: data.tags || [],
        reporter: data.reporter || 'community'
      }] : [],
      note: hit
        ? `URL confirmed in URLhaus malware database (Threat: ${data.threat || 'Malware'}).`
        : `No active malware records found in URLhaus (${data.query_status || 'clean'}).`
    };
  } catch (err) {
    const isTimeout = err.name === 'AbortError';
    return {
      source: 'URLhaus Community Threat Feed',
      status: 'error',
      matches: [],
      note: isTimeout ? 'URLhaus request timed out (3.5s).' : (err.message || 'URLhaus service unavailable.')
    };
  }
}

/**
 * Health check endpoint - reports free mode status and source configuration.
 * Never leaks API keys.
 */
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'SPRIZAN Threat Intelligence',
    edition: '100% Free Community Edition',
    billingRequired: false,
    topDomainsLoaded: true,
    configured: {
      urlhaus: Boolean(process.env.URLHAUS_AUTH_KEY)
    }
  });
});

/**
 * Scan endpoint - safe inspection without visiting target URL.
 */
app.post('/api/scan', rateLimiter, async (req, res) => {
  try {
    const raw = String(req.body?.url || '').trim();
    if (!raw) {
      return res.status(400).json({
        error: 'Please enter a URL to inspect.',
        verdict: 'UNABLE TO VERIFY'
      });
    }

    const scanStartTime = Date.now();

    // 1. Safe local structural inspection (never fetches target URL)
    const local = inspectUrl(raw);

    // 2. Query free URLhaus community database (SSRF guarded: skips internal IPs)
    const urlhausResult = await checkUrlhaus(local.normalizedUrl, local.isInternalIP);
    const sources = [urlhausResult];

    // 3. Evidence-Based Verdict Determination (Three Clear Categories)
    const isConfirmedMalware = urlhausResult.status === 'checked' && urlhausResult.matches.length > 0;
    let score = local.score;
    let verdict;
    let verdictDetail;
    const reputationStatus = urlhausResult.status;

    if (isConfirmedMalware) {
      // Category A: CONFIRMED MALICIOUS
      score = Math.max(score, 95);
      verdict = 'CONFIRMED MALICIOUS';
      verdictDetail = `The URL was positively verified in the URLhaus community malware database as an active threat (${urlhausResult.matches[0]?.threat || 'Malware Distribution'}).`;
    } else if (local.hasHighSeverity || score >= 30) {
      // Category B: SUSPICIOUS
      verdict = 'SUSPICIOUS';
      const highFindings = local.findings.filter(f => f.severity === 'high');
      const reasons = highFindings.length > 0
        ? highFindings.map(f => f.title).join(', ')
        : `${local.findings.length} warning indicators detected`;
      verdictDetail = local.isInternalIP
        ? `The target resolves to internal, private, or loopback network infrastructure (${local.host}). Flagged as a security restriction (OWASP SSRF protection) rather than fraudulent external web content.`
        : `Local analysis identified meaningful risk indicators: ${reasons}. Review individual evidence items below.`;
      score = Math.max(score, local.hasHighSeverity ? 50 : 35);
    } else if (urlhausResult.status === 'checked') {
      // Category C1: NO THREAT INDICATORS DETECTED (external threat intel verified clean)
      verdict = 'NO THREAT INDICATORS DETECTED';
      verdictDetail = local.isPopularDomain
        ? `Local analysis identified this as a recognized top domain (${local.registeredDomain}) with no structural anomalies. External threat intelligence (URLhaus) completed with no matching malware records.`
        : 'Local structural analysis identified no warning indicators, and external threat intelligence (URLhaus) completed with no active malware records.';
    } else if (urlhausResult.status === 'not_configured' || urlhausResult.status === 'not_applicable') {
      // Category C2: NO SUSPICIOUS INDICATORS FOUND — LOCAL ANALYSIS ONLY
      verdict = 'NO SUSPICIOUS INDICATORS FOUND — LOCAL ANALYSIS ONLY';
      verdictDetail = local.isPopularDomain
        ? `Local analysis identified this as a recognized top domain (${local.registeredDomain}) with zero warning indicators. External community threat database was not configured.`
        : 'No structural or heuristic warning indicators were found by local analysis. External community threat database was not configured.';
    } else {
      // Category C3: PARTIALLY VERIFIED (local passed, external errored/timed out)
      verdict = 'PARTIALLY VERIFIED';
      verdictDetail = `Local structural analysis completed with zero warnings, but external threat intelligence check failed or timed out (${urlhausResult.note}).`;
    }

    score = Math.min(100, Math.max(0, score));

    const riskLevel = isConfirmedMalware || score >= 70
      ? 'Critical'
      : score >= 40
        ? 'High'
        : score >= 20
          ? 'Elevated'
          : 'Low';

    const completedCount = sources.filter(s => s.status === 'checked').length;
    const configuredCount = sources.filter(s => s.status !== 'not_configured').length;
    const totalLatency = Date.now() - scanStartTime;

    res.json({
      id: `SPZ-${Date.now().toString(36).toUpperCase()}`,
      scannedAt: new Date().toISOString(),
      scanLatencyMs: totalLatency,
      normalizedUrl: local.normalizedUrl,
      host: local.host,
      registeredDomain: local.registeredDomain,
      isPopularDomain: local.isPopularDomain,
      brandRecognized: local.brandRecognized,
      domainReputationNote: local.domainReputationNote,
      componentScores: local.componentScores,
      score,
      verdict,
      verdictDetail,
      riskLevel,
      reputationStatus,
      findings: local.findings,
      findingCounts: local.findingCounts,
      sources,
      sourcesChecked: completedCount,
      sourcesConfigured: configuredCount,
      disclaimer: 'This investigation is based on explainable heuristic structural inspection and available community threat intelligence. A clean or unflagged result is not a guarantee of safety: newly registered domains or zero-day phishing sites may not yet be recorded in threat feeds. SPRIZAN never executes or visits submitted links.'
    });
  } catch (error) {
    res.status(400).json({
      error: error.message || 'Unable to analyze this URL.',
      verdict: 'UNABLE TO VERIFY'
    });
  }
});

// Single Page Application routing
app.get('*', (_req, res) => {
  res.sendFile(path.join(root, 'public', 'index.html'));
});

const port = Number(process.env.PORT || 3000);
if (process.env.NODE_ENV !== 'test') {
  app.listen(port, () => {
    console.log(`SPRIZAN (100% Free Community Edition) running at http://localhost:${port}`);
  });
}

export { app };
