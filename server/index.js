import express from 'express';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectUrl } from './analyzer.js';

dotenv.config();

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

// Basic security middleware
app.use(express.json({ limit: '12kb' }));
app.use(express.static(path.join(root, 'public')));

// In-memory rate limiting to prevent abuse (60 requests per minute per IP)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 60;

// Periodic cleanup of rate limit cache
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of rateLimitMap.entries()) {
    if (now - data.resetTime > RATE_LIMIT_WINDOW_MS) {
      rateLimitMap.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS);

function rateLimiter(req, res, next) {
  const clientIp = req.ip || req.headers['x-forwarded-for'] || '127.0.0.1';
  const now = Date.now();
  const entry = rateLimitMap.get(clientIp);

  if (!entry || now - entry.resetTime > RATE_LIMIT_WINDOW_MS) {
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
const timeoutFetch = async (url, options = {}, ms = 8500) => {
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
 * Requires a free Auth-Key from abuse.ch (zero billing, no credit card required).
 */
async function checkUrlhaus(targetUrl) {
  const key = process.env.URLHAUS_AUTH_KEY;
  if (!key) {
    return {
      source: 'URLhaus Community Feed',
      status: 'not_configured',
      matches: [],
      note: 'Free Auth-Key not configured. Obtain a free key from https://urlhaus.abuse.ch/api/ (no credit card or payment required).'
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
        source: 'URLhaus Community Feed',
        status: 'error',
        matches: [],
        latencyMs: elapsed,
        note: 'URLhaus authentication failed. Verify your free Auth-Key from abuse.ch.'
      };
    }

    if (!response.ok) {
      return {
        source: 'URLhaus Community Feed',
        status: 'error',
        matches: [],
        latencyMs: elapsed,
        note: `URLhaus service returned HTTP ${response.status}.`
      };
    }

    const data = await response.json();
    const hit = data.query_status === 'ok';

    return {
      source: 'URLhaus Community Feed',
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
      source: 'URLhaus Community Feed',
      status: 'error',
      matches: [],
      note: isTimeout ? 'URLhaus request timed out (8.5s).' : (err.message || 'URLhaus service unavailable.')
    };
  }
}

/**
 * Health check endpoint - reports 100% free mode status and source configuration.
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

    // 2. Query free URLhaus community database
    const urlhausResult = await checkUrlhaus(local.normalizedUrl);
    const sources = [urlhausResult];

    // 3. Correlate findings into the 6 distinct verdicts
    const isConfirmedMalware = urlhausResult.status === 'checked' && urlhausResult.matches.length > 0;
    let score = local.score;
    let verdict;
    let verdictDetail;
    const reputationStatus = urlhausResult.status;

    if (isConfirmedMalware) {
      score = Math.max(score, 95);
      verdict = 'CONFIRMED MALWARE';
      verdictDetail = 'The URL was positively identified in the URLhaus community malware database as an active threat.';
    } else if (local.hasHighSeverity || score >= 25) {
      verdict = 'SUSPICIOUS';
      verdictDetail = local.findings.length > 0
        ? `Local structural analysis detected ${local.findings.length} warning indicator(s), including ${local.hasHighSeverity ? 'high-severity deception risks' : 'elevated risk patterns'}.`
        : 'Local heuristic analysis detected significant warning indicators or deceptive patterns.';
      score = Math.max(score, local.hasHighSeverity ? 50 : 35);
    } else if (urlhausResult.status === 'checked') {
      verdict = 'NO KNOWN THREATS DETECTED';
      verdictDetail = local.isPopularDomain
        ? `Local analysis identified this as a recognized top domain (${local.registeredDomain}) with no structural anomalies. External threat intelligence (URLhaus) completed and found no active malware records.`
        : 'Local structural analysis identified no red flags, and external threat intelligence (URLhaus) completed with no matching malware records.';
    } else if (urlhausResult.status === 'not_configured') {
      verdict = 'NOT FLAGGED BY LOCAL ANALYSIS';
      verdictDetail = local.isPopularDomain
        ? `Local analysis identified this as a recognized top domain (${local.registeredDomain}) and found no structural warning indicators. External community threat database check was not configured.`
        : 'No structural or heuristic warning indicators were found by local analysis. External community threat database check was not configured.';
    } else {
      // urlhausResult.status === 'error' (some checks succeeded, others failed)
      verdict = 'PARTIALLY VERIFIED';
      verdictDetail = `Local structural analysis completed with no warnings, but external threat intelligence check failed or timed out (${urlhausResult.note}).`;
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
