const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const STORAGE_KEY = 'sprizan-investigations-v3';

let records = loadRecords();
let health = { configured: {} };
let toastTimer;

function loadRecords() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch {
    return [];
  }
}

function saveRecords() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(records.slice(0, 60)));
  } catch (e) {
    console.warn('Could not save records to localStorage', e);
  }
}

function esc(value = '') {
  return String(value).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

function timeLabel(value) {
  return new Date(value).toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function toast(message, type = 'info', actionText = null, actionFn = null) {
  const el = $('#toast');
  el.innerHTML = '';

  const msgSpan = document.createElement('span');
  msgSpan.textContent = message;
  el.appendChild(msgSpan);

  if (actionText && typeof actionFn === 'function') {
    const btn = document.createElement('button');
    btn.className = 'toast-action-btn';
    btn.textContent = actionText;
    btn.onclick = (e) => {
      e.stopPropagation();
      actionFn();
      el.classList.remove('show');
    };
    el.appendChild(btn);
  }

  el.className = `toast show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 4200);
}

function showView(name) {
  $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${name}`));
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  const labels = {
    overview: 'Command Center',
    scanner: 'URL Intelligence',
    history: 'Investigation History',
    sources: 'Intelligence Sources'
  };
  $('#page-title').textContent = labels[name] || 'Command Center';
  $('#crumb').textContent = (name || 'OVERVIEW').toUpperCase();
  if (name === 'history') renderHistory();
  if (name === 'sources') renderSources();
}

$$('.nav-item').forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));
$$('[data-go]').forEach(b => b.addEventListener('click', () => showView(b.dataset.go)));

function verdictClass(v) {
  if (v === 'CONFIRMED MALWARE') return 'danger';
  if (v === 'SUSPICIOUS') return 'warn';
  if (v === 'NO KNOWN THREATS DETECTED') return 'success';
  if (v === 'NOT FLAGGED BY LOCAL ANALYSIS') return 'notice';
  if (v === 'PARTIALLY VERIFIED') return 'info';
  return 'muted';
}

function verdictColor(v) {
  if (v === 'CONFIRMED MALWARE') return '#f0444b'; // crimson red
  if (v === 'SUSPICIOUS') return '#eab65d';        // toxic amber
  if (v === 'NO KNOWN THREATS DETECTED') return '#43d18b'; // tactical emerald green
  if (v === 'NOT FLAGGED BY LOCAL ANALYSIS') return '#4ca8e8'; // electric cyan / steel blue
  if (v === 'PARTIALLY VERIFIED') return '#818cf8'; // indigo
  return '#87939a';                               // slate gray
}

function verdictIcon(v) {
  if (v === 'CONFIRMED MALWARE') return '▲';
  if (v === 'SUSPICIOUS') return '⚠';
  if (v === 'NO KNOWN THREATS DETECTED') return '🛡';
  if (v === 'NOT FLAGGED BY LOCAL ANALYSIS') return '◎';
  if (v === 'PARTIALLY VERIFIED') return '◈';
  return '⌁';
}

function coverageBadgeHtml(status) {
  if (status === 'checked') {
    return '<span class="coverage-label coverage-checked">COMMUNITY REPUTATION CHECK COMPLETED</span>';
  }
  if (status === 'not_configured') {
    return '<span class="coverage-label coverage-unverified">EXTERNAL REPUTATION NOT CONFIGURED (LOCAL ONLY)</span>';
  }
  if (status === 'error') {
    return '<span class="coverage-label coverage-partial">EXTERNAL REPUTATION SERVICE UNAVAILABLE</span>';
  }
  return '<span class="coverage-label coverage-unverified">EXTERNAL REPUTATION NOT VERIFIED</span>';
}

function renderActivity(target, items) {
  if (!items.length) {
    target.innerHTML = '<div class="empty-state">No investigations recorded yet. Submit a URL in the Scanner to begin.</div>';
    return;
  }
  target.innerHTML = items.map(item => `
    <div class="activity-row">
      <div class="activity-main">
        <b title="${esc(item.normalizedUrl)}">${esc(item.registeredDomain || item.host || item.normalizedUrl)}</b>
        <small>${esc(timeLabel(item.scannedAt))} · ${esc(item.id || 'LOCAL')} ${item.isPopularDomain ? '· <span class="popular-tag">TOP DOMAIN</span>' : ''}</small>
      </div>
      <span class="verdict-pill ${verdictClass(item.verdict)}">${esc(item.verdict)}</span>
    </div>
  `).join('');
}

function updateOverview() {
  const confirmed = records.filter(r => r.verdict === 'CONFIRMED MALWARE').length;
  const suspicious = records.filter(r => r.verdict === 'SUSPICIOUS').length;
  const unflagged = records.filter(r => r.verdict === 'NOT FLAGGED BY LOCAL ANALYSIS' || r.verdict === 'NO KNOWN THREATS DETECTED').length;

  $('#metric-total').textContent = records.length;
  $('#metric-threats').textContent = confirmed;
  $('#metric-suspicious').textContent = suspicious;
  $('#metric-clean').textContent = unflagged;

  renderActivity($('#recent-list'), records.slice(0, 5));
  renderSourceMini();
}

function renderSourceMini() {
  const isUrlhaus = Boolean(health.configured?.urlhaus);
  $('#source-mini').innerHTML = `
    <div class="source-row">
      <span>Local Heuristic Engine</span>
      <b style="color:var(--cyan)">ACTIVE (1,000 TOP DOMAINS)</b>
    </div>
    <div class="source-row">
      <span>URLhaus Community Feed</span>
      <b style="color:${isUrlhaus ? 'var(--green)' : '#7f8c92'}">${isUrlhaus ? 'CONNECTED (100% FREE)' : 'NOT CONFIGURED'}</b>
    </div>
    <div class="source-row">
      <span>VirusTotal Feed</span>
      <b style="color:#606e75">DISABLED (ZERO-BILLING)</b>
    </div>
  `;
}

async function checkHealth() {
  try {
    const r = await fetch('/api/health');
    health = await r.json();
    $('#engine-status').textContent = health.configured?.urlhaus
      ? 'URLhaus Community Feed Connected'
      : 'Local Engine Active (1,000 Top Domains Indexed)';
  } catch {
    $('#engine-status').textContent = 'API Offline';
  }
  updateOverview();
}

function renderHistory() {
  renderActivity($('#history-list'), records);
}

function renderSources() {
  const isUrlhaus = Boolean(health.configured?.urlhaus);
  const list = [
    {
      name: 'Local Heuristic & Structural Engine',
      provider: 'SPRIZAN Core (Native / Offline Capable)',
      desc: 'Self-sufficient in-memory engine featuring a local database of top 1,000 legitimate domains (including Amazon India, Google, Microsoft, Apple, GitHub, YouTube, Wikipedia, and Indian utilities). Performs Levenshtein typosquatting detection, homograph inspection, and port analysis with zero external network dependencies.',
      authNote: 'Built-in. Completely free, offline capable, and always active.',
      url: '#',
      status: 'checked',
      statusText: 'ACTIVE (1,000 TOP DOMAINS INDEXED)'
    },
    {
      name: 'URLhaus Community Threat Feed',
      provider: 'abuse.ch (100% Free Community Intelligence)',
      desc: 'Free community-driven database of active malware URLs operated by the abuse.ch research team. Provides crowd-sourced threat signatures with zero billing or payment requirements.',
      authNote: isUrlhaus
        ? 'Connected with your free abuse.ch Auth-Key.'
        : 'Free Auth-Key missing. Register for free at https://urlhaus.abuse.ch/api/ and add URLHAUS_AUTH_KEY to .env.',
      url: 'https://urlhaus.abuse.ch/api/',
      status: isUrlhaus ? 'checked' : 'not_configured',
      statusText: isUrlhaus ? 'CONNECTED (FREE)' : 'FREE AUTH-KEY REQUIRED'
    },
    {
      name: 'VirusTotal Integration',
      provider: 'VirusTotal (Intentionally Disabled)',
      desc: 'Disabled to guarantee 100% free operation without paid API subscriptions, credit cards, or cloud billing accounts.',
      authNote: 'No paid account or billing required.',
      url: 'https://virustotal.com',
      status: 'not_configured',
      statusText: 'DISABLED IN ZERO-BILLING TIER'
    }
  ];

  $('#source-cards').innerHTML = list.map(s => `
    <article class="source-detail">
      <div class="eyebrow">${esc(s.provider)}</div>
      <h3>${esc(s.name)}</h3>
      <p>${esc(s.desc)}</p>
      <small style="display:block;margin:6px 0 10px;color:#8fa0a8;font-size:10px">${esc(s.authNote)}</small>
      ${s.url !== '#' ? `<a href="${esc(s.url)}" target="_blank" rel="noreferrer">DOCUMENTATION ↗</a>` : ''}
      <div class="source-status ${esc(s.status)}">${esc(s.statusText)}</div>
    </article>
  `).join('');
}

/**
 * Laser Scanning Animation Engine
 * Coordinates horizontal laser beam, progress bar, and stage titles.
 */
function stageProgress() {
  const stages = [
    { phase: 'PHASE 1: SYNTAX CHECK', title: 'PARSING URL STRUCTURE & SPECIFICATION', sub: 'Inspecting scheme, domain boundaries, and character encoding' },
    { phase: 'PHASE 2: TOP DOMAINS', title: 'CHECKING 1,000 LEGITIMATE TOP DOMAINS', sub: 'Evaluating registered domain and typosquatting edit distance' },
    { phase: 'PHASE 3: COMMUNITY FEED', title: 'CROSS-CHECKING THREAT REPUTATION', sub: 'Querying free community URLhaus malware signatures' },
    { phase: 'PHASE 4: CORRELATION', title: 'COMPILING TELEMETRY & VERDICT', sub: 'Finalizing severity index and explainable security report' }
  ];

  let currentIdx = 0;
  const phaseIndicator = $('#scan-phase-indicator');
  const title = $('#scan-stage-title');
  const sub = $('#scan-stage-sub');
  const fill = $('#progress-fill');
  const steps = $$('.progress-steps .step');

  const updateUI = () => {
    if (currentIdx < stages.length) {
      const s = stages[currentIdx];
      if (phaseIndicator) phaseIndicator.textContent = s.phase;
      if (title) title.textContent = s.title;
      if (sub) sub.textContent = s.sub;
      if (fill) fill.style.width = ((currentIdx + 1) * 25) + '%';
      steps.forEach((stepEl, n) => stepEl.classList.toggle('active', n <= currentIdx));
      currentIdx++;
    }
  };

  updateUI();
  const timer = setInterval(() => {
    if (currentIdx < stages.length) updateUI();
    else clearInterval(timer);
  }, 650);

  return () => {
    clearInterval(timer);
  };
}

function copyToClipboard(text, msg = 'Copied to clipboard!') {
  navigator.clipboard.writeText(text).then(() => {
    toast(msg, 'success');
  }).catch(() => {
    toast('Unable to copy text.', 'warn');
  });
}

/**
 * Reliable smooth scrolling to analysis results.
 * Works across desktop, laptop, mobile, and accounts for sticky headers & reduced motion.
 */
function scrollToResult() {
  const resultEl = $('#result');
  if (!resultEl) return;

  const prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const behavior = prefersReducedMotion ? 'auto' : 'smooth';

  // Double requestAnimationFrame ensures browser has completed DOM layout & geometry calculation
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      // Offset by topbar navigation height (approx 85px) so the verdict header sits clearly in view
      const navOffset = 84;
      const targetY = resultEl.getBoundingClientRect().top + window.pageYOffset - navOffset;
      window.scrollTo({
        top: Math.max(0, targetY),
        behavior
      });
    });
  });
}

function renderResult(data) {
  const color = verdictColor(data.verdict);
  const icon = verdictIcon(data.verdict);
  const comp = data.componentScores || { domain: 0, transport: 0, structural: 0, content: 0 };

  // Format findings HTML
  let findingsHtml = '';
  if (data.findings && data.findings.length > 0) {
    findingsHtml = data.findings.map(f => `
      <div class="finding-item finding-${esc(f.severity)}">
        <div class="finding-header">
          <span class="finding-pill finding-pill-${esc(f.severity)}">[${esc(f.severity.toUpperCase())}]</span>
          <b class="finding-title">${esc(f.title)}</b>
          <span class="finding-points">+${f.points} pts</span>
        </div>
        <p class="finding-detail">${esc(f.detail)}</p>
      </div>
    `).join('');
  } else {
    findingsHtml = `
      <div class="clean-verification-card">
        <div class="clean-header">
          <span class="clean-check-icon">✓</span>
          <div>
            <b>NO STRUCTURAL RED FLAGS IDENTIFIED</b>
            <small>Local heuristic analysis completed with zero security warnings.</small>
          </div>
        </div>
        <div class="clean-check-grid">
          <div class="clean-check-item"><span>✓</span> Standard Protocol (${data.normalizedUrl.startsWith('https:') ? 'HTTPS' : 'HTTP'})</div>
          <div class="clean-check-item"><span>✓</span> Valid Host Syntax & Domain Boundaries</div>
          <div class="clean-check-item"><span>✓</span> No Typosquatting / Combosquatting Detected</div>
          <div class="clean-check-item"><span>✓</span> No Obfuscated IP or Punycode Deceptions</div>
          <div class="clean-check-item"><span>✓</span> No Suspicious Service Ports or Extensions</div>
          <div class="clean-check-item"><span>✓</span> No Credential Harvesting Parameters</div>
        </div>
      </div>
    `;
  }

  // Format sources HTML
  const sourcesHtml = data.sources && data.sources.length > 0
    ? data.sources.map(s => `
      <div class="source-card">
        <div class="source-card-top">
          <b>${esc(s.source)}</b>
          <span class="source-status-pill status-${esc(s.status)}">${esc((s.status || '').replace('_', ' ').toUpperCase())}</span>
        </div>
        <p class="source-note-text">${esc(s.note)}</p>
        ${s.matches && s.matches.length > 0 ? `
          <div class="threat-evidence-box">
            <span class="evidence-tag">CONFIRMED MATCH</span>
            <code>${esc(JSON.stringify(s.matches, null, 2))}</code>
          </div>
        ` : ''}
        ${s.latencyMs ? `<div class="source-latency mono">Response Latency: ${s.latencyMs}ms</div>` : ''}
      </div>
    `).join('')
    : '<div class="empty-state">No external threat sources configured.</div>';

  // SVG Gauge calculation
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const scorePercent = Math.min(100, Math.max(0, data.score));
  const strokeDashoffset = circumference - (scorePercent / 100) * circumference;

  // Render comprehensive console
  $('#result').innerHTML = `
    <!-- 1. Tactical Verdict Header -->
    <div class="result-hero border-${verdictClass(data.verdict)}" id="investigation-result-header">
      <div class="hero-left">
        <div class="hero-eyebrow">
          <span class="investigation-id mono">CASE: ${esc(data.id)}</span>
          <span class="scan-time mono">ANALYSIS LATENCY: ${data.scanLatencyMs || 12}ms</span>
          <span class="scan-time mono">${esc(timeLabel(data.scannedAt))}</span>
        </div>
        <div class="verdict-banner-wrap">
          <span class="verdict-beacon" style="background:${color};box-shadow:0 0 16px ${color}"></span>
          <h2 class="verdict-display" style="color:${color}">${icon} ${esc(data.verdict)}</h2>
          <span class="risk-badge risk-${esc(data.riskLevel.toLowerCase())}">${esc(data.riskLevel.toUpperCase())} RISK</span>
        </div>
        <p class="verdict-explanation-text">${esc(data.verdictDetail || 'Review source findings and structural indicators below.')}</p>
        <div class="target-chip">
          <span class="chip-label">TARGET:</span>
          <code class="target-url" title="${esc(data.normalizedUrl)}">${esc(data.normalizedUrl)}</code>
          <button class="copy-url-btn" id="copy-target-btn" title="Copy Target URL">COPY</button>
        </div>
      </div>
      <div class="hero-right">
        <div class="gauge-card">
          <svg class="score-svg" viewBox="0 0 100 100">
            <circle class="score-bg" cx="50" cy="50" r="${radius}" />
            <circle class="score-progress" cx="50" cy="50" r="${radius}"
              stroke="${color}"
              stroke-dasharray="${circumference}"
              stroke-dashoffset="${strokeDashoffset}"
            />
          </svg>
          <div class="gauge-center">
            <span class="gauge-score" style="color:${color}">${data.score}</span>
            <small class="gauge-label">SEVERITY INDEX</small>
          </div>
        </div>
      </div>
    </div>

    <!-- 2. Technical Telemetry & Domain Intelligence Grid -->
    <div class="console-grid">
      <!-- Domain Identity & Recognition Card -->
      <article class="console-card">
        <div class="card-head">
          <div class="card-title">◈ DOMAIN IDENTITY & VERIFICATION</div>
          <span class="card-tag mono">${esc(data.registeredDomain)}</span>
        </div>
        <div class="telemetry-list">
          <div class="telemetry-row">
            <span>Registered Domain</span>
            <strong class="mono">${esc(data.registeredDomain)}</strong>
          </div>
          <div class="telemetry-row">
            <span>Domain Reputation Index</span>
            <span>
              ${data.isPopularDomain
                ? `<span class="badge-verified-top">✓ VERIFIED GLOBAL TOP DOMAIN</span>`
                : `<span class="badge-unranked">UNRANKED / GENERAL DOMAIN</span>`}
            </span>
          </div>
          <div class="telemetry-row">
            <span>Transport Security</span>
            <strong class="mono" style="color:${data.normalizedUrl.startsWith('https:') ? 'var(--green)' : 'var(--amber)'}">
              ${data.normalizedUrl.startsWith('https:') ? 'HTTPS (TLS Encrypted)' : 'HTTP (Plaintext Unencrypted)'}
            </strong>
          </div>
          <div class="telemetry-row">
            <span>Host Structure</span>
            <span class="mono">${esc(data.host)}</span>
          </div>
          <div class="telemetry-row">
            <span>Reputation Coverage</span>
            <span>${coverageBadgeHtml(data.reputationStatus)}</span>
          </div>
        </div>
      </article>

      <!-- Component Risk Score Breakdown Chart -->
      <article class="console-card">
        <div class="card-head">
          <div class="card-title">◎ COMPONENT RISK TELEMETRY</div>
          <span class="card-tag mono">MAX 25 PTS / BAND</span>
        </div>
        <div class="bar-chart-wrap">
          <div class="chart-bar-item">
            <div class="bar-label-row">
              <span>Domain & Typosquatting Risk</span>
              <b class="mono">${comp.domain}/25</b>
            </div>
            <div class="bar-track">
              <i class="bar-fill" style="width:${(comp.domain / 25) * 100}%;background:${comp.domain > 10 ? 'var(--red)' : comp.domain > 0 ? 'var(--amber)' : 'var(--green)'}"></i>
            </div>
          </div>
          <div class="chart-bar-item">
            <div class="bar-label-row">
              <span>Transport & Port Risk</span>
              <b class="mono">${comp.transport}/25</b>
            </div>
            <div class="bar-track">
              <i class="bar-fill" style="width:${(comp.transport / 25) * 100}%;background:${comp.transport > 10 ? 'var(--red)' : comp.transport > 0 ? 'var(--amber)' : 'var(--green)'}"></i>
            </div>
          </div>
          <div class="chart-bar-item">
            <div class="bar-label-row">
              <span>Syntax & Structural Risk</span>
              <b class="mono">${comp.structural}/25</b>
            </div>
            <div class="bar-track">
              <i class="bar-fill" style="width:${(comp.structural / 25) * 100}%;background:${comp.structural > 10 ? 'var(--red)' : comp.structural > 0 ? 'var(--amber)' : 'var(--green)'}"></i>
            </div>
          </div>
          <div class="chart-bar-item">
            <div class="bar-label-row">
              <span>Deception & Lure Risk</span>
              <b class="mono">${comp.content}/25</b>
            </div>
            <div class="bar-track">
              <i class="bar-fill" style="width:${(comp.content / 25) * 100}%;background:${comp.content > 10 ? 'var(--red)' : comp.content > 0 ? 'var(--amber)' : 'var(--green)'}"></i>
            </div>
          </div>
        </div>
      </article>
    </div>

    <!-- 3. Structural Findings & Threat Intelligence Cards -->
    <div class="console-grid">
      <article class="console-card">
        <div class="card-head">
          <div class="card-title">◈ STRUCTURAL HEURISTICS & WARNINGS</div>
          <span class="card-tag mono">${data.findings ? data.findings.length : 0} FINDINGS</span>
        </div>
        <div class="findings-container">
          ${findingsHtml}
        </div>
      </article>

      <article class="console-card">
        <div class="card-head">
          <div class="card-title">◎ EXTERNAL THREAT INTELLIGENCE</div>
          <span class="card-tag mono">${data.sourcesChecked}/${data.sourcesConfigured} CHECKED</span>
        </div>
        <div class="sources-container">
          ${sourcesHtml}
          <div class="source-card local-engine-card">
            <div class="source-card-top">
              <b>Local Threat Intelligence Engine</b>
              <span class="source-status-pill status-checked">ACTIVE</span>
            </div>
            <p class="source-note-text">1,000 legitimate top domains indexed. Typosquatting, Punycode homographs, and combosquatting algorithms operating locally with zero third-party dependencies.</p>
          </div>
        </div>
      </article>
    </div>

    <!-- 4. Investigation Action Toolbar & Disclaimer -->
    <div class="console-footer-card">
      <div class="footer-actions">
        <button class="action-btn" id="btn-copy-report">📋 COPY INVESTIGATION SUMMARY</button>
        <button class="action-btn text-action" id="btn-rescan">↺ RE-ANALYZE TARGET</button>
      </div>
      <div class="disclaimer-text">
        ${esc(data.disclaimer)}
      </div>
    </div>
  `;

  // Attach button events
  $('#copy-target-btn')?.addEventListener('click', () => copyToClipboard(data.normalizedUrl, 'Target URL copied!'));
  $('#btn-rescan')?.addEventListener('click', () => {
    $('#url-input').focus();
    scan();
  });
  $('#btn-copy-report')?.addEventListener('click', () => {
    const reportText = [
      `SPRIZAN CYBERSECURITY INVESTIGATION REPORT`,
      `==========================================`,
      `Investigation ID : ${data.id}`,
      `Scanned At       : ${data.scannedAt}`,
      `Target URL       : ${data.normalizedUrl}`,
      `Registered Domain: ${data.registeredDomain}`,
      `Domain Status    : ${data.isPopularDomain ? 'Verified Global Top Domain' : 'Unranked / General Domain'}`,
      `Final Verdict    : ${data.verdict}`,
      `Risk Severity    : ${data.riskLevel.toUpperCase()} (Index: ${data.score}/100)`,
      `Reputation Status: ${data.reputationStatus.toUpperCase()}`,
      `------------------------------------------`,
      `Findings (${data.findings ? data.findings.length : 0}):`,
      ...(data.findings && data.findings.length
        ? data.findings.map(f => ` - [${f.severity.toUpperCase()}] ${f.title}: ${f.detail}`)
        : [' - None (Structure matches verified baseline)']),
      `==========================================`,
      `Notice: A clean verdict is not an absolute guarantee of safety.`
    ].join('\n');
    copyToClipboard(reportText, 'Investigation report copied to clipboard!');
  });

  $('#result').classList.remove('hidden');
}

async function scan() {
  const input = $('#url-input');
  const raw = input.value.trim();
  if (!raw) {
    toast('Please enter a target URL to analyze.', 'warn');
    input.focus();
    return;
  }

  $('#scan-btn').disabled = true;
  $('#scan-btn').textContent = 'ANALYZING…';
  $('#result').classList.add('hidden');
  $('#scan-stage').classList.remove('hidden');
  $('#scan-target').textContent = raw;

  const stopProgress = stageProgress();

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: raw })
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Analysis failed.');
    }

    // Stop laser progress animation immediately when response arrives
    stopProgress();
    $('#progress-fill').style.width = '100%';
    $$('.progress-steps .step').forEach(s => s.classList.add('active'));
    $('#scan-stage-title').textContent = 'ANALYSIS COMPLETE';
    $('#scan-stage-sub').textContent = 'Evidence compiled. Transferring telemetry to investigation console…';

    // Brief pause to allow laser sweep to conclude gracefully
    await new Promise(r => setTimeout(r, 260));
    $('#scan-stage').classList.add('hidden');

    renderResult(data);
    records.unshift(data);
    records = records.slice(0, 60);
    saveRecords();
    updateOverview();

    // Automatic smooth scroll to the results section
    scrollToResult();

    toast(`Analysis complete: ${data.verdict}`, 'success', 'VIEW RESULTS', () => scrollToResult());
  } catch (error) {
    stopProgress();
    $('#scan-stage').classList.add('hidden');
    toast(error.message || 'Unable to complete scan.', 'danger');
  } finally {
    $('#scan-btn').disabled = false;
    $('#scan-btn').innerHTML = 'ANALYSE TARGET <span>→</span>';
  }
}

$('#scan-btn').addEventListener('click', scan);
$('#url-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') scan();
});

$('#clear-history').addEventListener('click', () => {
  if (!records.length) return;
  if (confirm('Delete all SPRIZAN investigation records stored in this browser?')) {
    records = [];
    saveRecords();
    updateOverview();
    renderHistory();
    toast('Local investigation history cleared.', 'info');
  }
});

function clock() {
  const now = new Date();
  $('#current-time').textContent = now.toISOString().slice(11, 19) + ' UTC';
}

clock();
setInterval(clock, 1000);
checkHealth();
