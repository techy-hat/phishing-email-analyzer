/**
 * PhishGuard — Application Logic
 *
 * Components:
 *  [1] State
 *  [2] DOM references
 *  [3] Navbar
 *  [4] Email input (tabs, char counter)
 *  [5] Upload area (drag-drop, file selection)
 *  [6] Scan loader animation
 *  [7] Results rendering
 *  [8] Analyzer orchestration
 *  [9] Init
 */

'use strict';

// ─── [0] API BASE URL ────────────────────────────────────────────────────────
// The FastAPI backend runs on http://localhost:8000 (see backend/start_server.bat).
// When the frontend is served from the API's own origin (deployed on Vercel, or
// opened directly on port 8000) the relative /api/* paths work as-is. When the
// page is served elsewhere (Live Server, python -m http.server, or file://) we
// must point at the local backend explicitly.
const isLocalHost = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
const API_BASE = (isLocalHost && location.port !== '8000')
  ? 'http://localhost:8000'
  : '';

// ─── [1] STATE ────────────────────────────────────────────────────────────────
const state = {
  activeTab: 'paste',
  selectedFile: null,
  isAnalyzing: false
};

// ─── [2] DOM ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

const dom = {
  navbar: $('navbar'),
  navToggle: $('navToggle'),
  navLinks: $('navLinks'),
  tabPaste: $('tab-paste'),
  tabUpload: $('tab-upload'),
  panelPaste: $('panel-paste'),
  panelUpload: $('panel-upload'),
  emailInput: $('emailInput'),
  charCounter: $('charCounter'),
  uploadArea: $('uploadArea'),
  uploadIdle: $('uploadIdle'),
  uploadSelected: $('uploadSelected'),
  fileInput: $('fileInput'),
  browseBtn: $('browseBtn'),
  fileName: $('fileName'),
  fileSize: $('fileSize'),
  fileRemove: $('fileRemove'),
  dragOverlay: $('dragOverlay'),
  analyzeBtn: $('analyzeBtn'),
  clearBtn: $('clearBtn'),
  analyzerCard: $('analyzerCard'),
  scanLoader: $('scanLoader'),
  resultsDashboard: $('resultsDashboard'),
  newAnalysisBtn: $('newAnalysisBtn'),
  analysisTimestamp: $('analysisTimestamp'),
  scoreNumber: $('scoreNumber'),
  riskLabel: $('riskLabel'),
  verdictStrip: $('verdictStrip'),
  verdictDot: $('verdictDot'),
  barSender: $('bar-sender'),
  barLinks: $('bar-links'),
  barContent: $('bar-content'),
  barAttachment: $('bar-attachment'),
  barHeader: $('bar-header'),
  pctSender: $('pct-sender'),
  pctLinks: $('pct-links'),
  pctContent: $('pct-content'),
  pctAttachment: $('pct-attachment'),
  pctHeader: $('pct-header'),
  classificationLabel: $('classificationLabel'),
  confidenceValue: $('confidenceValue'),
  authSpf: $('auth-spf'),
  authDkim: $('auth-dkim'),
  authDmarc: $('auth-dmarc'),
  threatCards: $('threatCards'),
  findingsList: $('findingsList'),
  findingsCount: $('findingsCount'),
  evidenceSummary: $('evidenceSummary'),
  evidenceList: $('evidenceList'),
  recommendationText: $('recommendationText'),
  recommendationCard: $('recommendationCard')
};

// ─── [3] NAVBAR ───────────────────────────────────────────────────────────────
function initNavbar() {
  window.addEventListener('scroll', () => {
    // Subtle: just keep border visible on scroll (it's always visible now)
  }, { passive: true });

  dom.navToggle.addEventListener('click', () => {
    const open = dom.navLinks.classList.toggle('open');
    dom.navToggle.setAttribute('aria-expanded', String(open));
  });

  dom.navLinks.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', () => {
      dom.navLinks.classList.remove('open');
      dom.navToggle.setAttribute('aria-expanded', 'false');
    });
  });

  document.addEventListener('click', e => {
    if (!dom.navbar.contains(e.target)) {
      dom.navLinks.classList.remove('open');
      dom.navToggle.setAttribute('aria-expanded', 'false');
    }
  });
}

// ─── [4] EMAIL INPUT ──────────────────────────────────────────────────────────
function initEmailInput() {
  // Tab switching
  [dom.tabPaste, dom.tabUpload].forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      if (tab === state.activeTab) return;
      state.activeTab = tab;

      dom.tabPaste.setAttribute('aria-selected', String(tab === 'paste'));
      dom.tabUpload.setAttribute('aria-selected', String(tab === 'upload'));
      dom.panelPaste.classList.toggle('hidden', tab !== 'paste');
      dom.panelUpload.classList.toggle('hidden', tab !== 'upload');
    });
  });

  // Character counter
  dom.emailInput.addEventListener('input', () => {
    const len = dom.emailInput.value.length;
    dom.charCounter.textContent = `${len.toLocaleString()} / 50,000`;
    dom.charCounter.classList.toggle('warn', len > 42500);
  });
}

// ─── [5] UPLOAD AREA ─────────────────────────────────────────────────────────
function initUploadArea() {
  const area = dom.uploadArea;

  area.addEventListener('click', e => {
    if (dom.fileRemove.contains(e.target)) return;
    if (!dom.uploadSelected.classList.contains('hidden')) return;
    dom.fileInput.click();
  });

  dom.browseBtn.addEventListener('click', e => {
    e.stopPropagation();
    dom.fileInput.click();
  });

  area.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      dom.fileInput.click();
    }
  });

  dom.fileInput.addEventListener('change', e => {
    const f = e.target.files[0];
    if (f) handleFile(f);
  });

  ['dragenter', 'dragover'].forEach(ev => {
    area.addEventListener(ev, e => {
      e.preventDefault();
      area.classList.add('drag-over');
      dom.dragOverlay.classList.remove('hidden');
    });
  });

  ['dragleave', 'dragend'].forEach(ev => {
    area.addEventListener(ev, e => {
      if (!area.contains(e.relatedTarget)) {
        area.classList.remove('drag-over');
        dom.dragOverlay.classList.add('hidden');
      }
    });
  });

  area.addEventListener('drop', e => {
    e.preventDefault();
    area.classList.remove('drag-over');
    dom.dragOverlay.classList.add('hidden');
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  });

  dom.fileRemove.addEventListener('click', e => {
    e.stopPropagation();
    clearFile();
  });
}

function handleFile(file) {
  const ext = '.' + file.name.split('.').pop().toLowerCase();
  if (!['.eml', '.txt'].includes(ext)) return;
  if (file.size > 10 * 1024 * 1024) return;

  state.selectedFile = file;
  dom.fileName.textContent = file.name;
  dom.fileSize.textContent = fmtSize(file.size);
  dom.uploadIdle.classList.add('hidden');
  dom.uploadSelected.classList.remove('hidden');
  dom.fileInput.value = '';
}

function clearFile() {
  state.selectedFile = null;
  dom.uploadIdle.classList.remove('hidden');
  dom.uploadSelected.classList.add('hidden');
}

function fmtSize(b) {
  if (b < 1024) return b + ' B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
  return (b / (1024 * 1024)).toFixed(2) + ' MB';
}

// ─── [6] SCAN LOADER ─────────────────────────────────────────────────────────
const STEPS = ['step-1', 'step-2', 'step-3', 'step-4', 'step-5'];

function runLoader() {
  // Reset
  STEPS.forEach(id => {
    const el = $(id);
    el.className = 'lstep';
    el.querySelector('.lstep-dot').className = 'lstep-dot';
  });

  let idx = 0;
  let timer = null;

  function tick() {
    if (idx >= STEPS.length) return;

    // Mark previous done
    if (idx > 0) {
      const prev = $(STEPS[idx - 1]);
      prev.classList.remove('active');
      prev.classList.add('done');
    }

    // Mark current active
    const cur = $(STEPS[idx]);
    cur.classList.add('active');
    idx++;

    if (idx < STEPS.length) {
      timer = setTimeout(tick, 380 + Math.random() * 240);
    }
  }

  timer = setTimeout(tick, 100);

  return () => {
    // Cancel any pending step so a finished analysis can never be mutated
    // by a stale timer while a new analysis is already running.
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
    STEPS.forEach(id => {
      const el = $(id);
      el.classList.remove('active');
      el.classList.add('done');
    });
  };
}

// ─── [7] RESULTS RENDERING ───────────────────────────────────────────────────

function renderResults(result) {
  const { score, level, breakdown, threats, findings, recommendation,
    confidence, classification, authentication, evidence } = result;
  const lvl = level.toLowerCase();

  // Timestamp
  const now = new Date();
  dom.analysisTimestamp.textContent =
    now.toLocaleDateString() + ' ' + now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  // Verdict strip
  dom.verdictStrip.className = 'verdict-strip ' + lvl;
  dom.riskLabel.textContent = level + ' RISK';

  // Classification + confidence
  const classLabel = ({ likely_phishing: 'Phishing', suspicious: 'Suspicious', likely_benign: 'Likely benign' }[classification] || classification);
  dom.classificationLabel.textContent = classLabel;
  dom.classificationLabel.className = 'vs-class ' + lvl;
  dom.confidenceValue.textContent = '~' + Math.round((confidence ?? 0) * 100) + '%';

  // Animate score number
  animateNum(dom.scoreNumber, 0, score, 1200);

  // Breakdown bars (include new header category if present)
  setTimeout(() => {
    setBar(dom.barSender, dom.pctSender, breakdown.sender, lvl);
    setBar(dom.barLinks, dom.pctLinks, breakdown.links, lvl);
    setBar(dom.barContent, dom.pctContent, breakdown.content, lvl);
    setBar(dom.barAttachment, dom.pctAttachment, breakdown.attachment, lvl);
    if (dom.barHeader) setBar(dom.barHeader, dom.pctHeader, breakdown.header, lvl);
  }, 300);

  // Authentication grid
  setAuth('spf', authentication);
  setAuth('dkim', authentication);
  setAuth('dmarc', authentication);

  // Threat table
  dom.threatCards.innerHTML = '';
  threats.forEach(t => {
    const sev = t.severity.toLowerCase();
    const row = document.createElement('div');
    row.className = 'threat-row';
    row.setAttribute('role', 'listitem');
    row.innerHTML = `
      <div class="threat-name">
        <span class="threat-name-dot" style="background:${sevColor(sev)}" aria-hidden="true"></span>
        ${esc(t.title)}
      </div>
      <div class="threat-desc">${esc(t.description)}</div>
      <span class="sev-badge ${sev}" aria-label="Severity: ${t.severity}">${t.severity}</span>
    `;
    dom.threatCards.appendChild(row);
  });

  // Findings
  dom.findingsList.innerHTML = '';
  dom.findingsCount.textContent = findings.length + ' findings';
  findings.forEach(f => {
    const sev = f.severity.toLowerCase();
    const row = document.createElement('div');
    row.className = 'finding-row';
    row.setAttribute('role', 'listitem');
    row.innerHTML = `
      <span class="finding-sev ${sev}" aria-label="Severity: ${f.severity}">${f.severity}</span>
      <div class="finding-body">
        <div class="finding-label">${esc(f.label)}</div>
        <div class="finding-text">${esc(f.text)}</div>
      </div>
    `;
    dom.findingsList.appendChild(row);
  });

  // Evidence ("why this email was flagged")
  const evidenceItems = Array.isArray(evidence) ? evidence : [];
  if (evidenceItems.length > 1) {
    // Last item is the methodological caveat; keep it as a footer note.
    const caveat = evidenceItems[evidenceItems.length - 1];
    const bullets = evidenceItems.slice(0, -1);
    dom.evidenceSummary.textContent = bullets.length
      ? 'This email was flagged for the following reason(s):'
      : 'No high-confidence suspicious indicators were detected.';
    dom.evidenceList.innerHTML = '';
    bullets.forEach(b => {
      const li = document.createElement('li');
      li.className = 'evidence-item';
      li.textContent = b;
      dom.evidenceList.appendChild(li);
    });
  } else {
    dom.evidenceSummary.textContent = 'No high-confidence suspicious indicators were detected.';
    dom.evidenceList.innerHTML = '';
  }

  // Recommendation
  dom.recommendationText.textContent = recommendation;
  dom.recommendationCard.className = 'rec-block ' + lvl;

  // Show results
  dom.resultsDashboard.classList.remove('hidden');
  setTimeout(() => {
    dom.resultsDashboard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 80);
}

function setAuth(mech, authentication) {
  const stateEl = mech === 'spf' ? dom.authSpf : mech === 'dkim' ? dom.authDkim : dom.authDmarc;
  if (!stateEl) return;
  const val = (authentication && authentication[mech]) || null;
  const item = stateEl.closest('.auth-item');
  if (val === 'pass') {
    stateEl.textContent = 'PASS';
    stateEl.className = 'auth-state pass';
    item && item.setAttribute('data-sev', 'pass');
  } else if (['fail', 'softfail', 'neutral', 'none', 'hardfail'].includes(val)) {
    stateEl.textContent = val.toUpperCase();
    stateEl.className = 'auth-state fail';
    item && item.setAttribute('data-sev', 'fail');
  } else {
    stateEl.textContent = 'NOT PROVIDED';
    stateEl.className = 'auth-state na';
    item && item.setAttribute('data-sev', 'na');
  }
}

function setBar(barEl, pctEl, value, levelClass) {
  // Color bar based on subscore magnitude
  const c = value >= 70 ? 'var(--danger)' : value >= 40 ? 'var(--warn)' : 'var(--ok)';
  barEl.style.width = value + '%';
  barEl.style.background = c;
  pctEl.textContent = value + '%';
  pctEl.style.color = c;
}

function sevColor(sev) {
  if (sev === 'high') return 'var(--danger)';
  if (sev === 'medium') return 'var(--warn)';
  if (sev === 'not_analyzed') return 'var(--text-3)';
  if (sev === 'unknown') return 'var(--text-3)';
  return 'var(--ok)';
}

function animateNum(el, from, to, duration) {
  const start = performance.now();
  const ease = t => 1 - Math.pow(1 - t, 3);
  const tick = now => {
    const p = Math.min((now - start) / duration, 1);
    el.textContent = Math.round(from + (to - from) * ease(p));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function esc(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}

// ─── [8] ORCHESTRATION ───────────────────────────────────────────────────────
function hasInput() {
  return state.activeTab === 'paste'
    ? dom.emailInput.value.trim().length > 0
    : state.selectedFile !== null;
}

function setAnalyzing(on) {
  state.isAnalyzing = on;
  dom.analyzeBtn.disabled = on;
  if (on) {
    dom.analyzeBtn.innerHTML = `
      <svg class="spin-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13" aria-hidden="true"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
      Analyzing…
    `;
  } else {
    dom.analyzeBtn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      Run Analysis
    `;
  }
}

async function handleAnalyze() {
  if (state.isAnalyzing) return;

  if (!hasInput()) {
    if (state.activeTab === 'paste') {
      dom.emailInput.focus();
      dom.emailInput.style.outline = '2px solid var(--danger)';
      setTimeout(() => { dom.emailInput.style.outline = ''; }, 1600);
    }
    return;
  }

  hideError();
  dom.resultsDashboard.classList.add('hidden');
  dom.analyzerCard.style.opacity = '0.6';
  dom.analyzerCard.style.pointerEvents = 'none';
  setAnalyzing(true);

  const finishLoader = runLoader();
  dom.scanLoader.classList.remove('hidden');
  dom.scanLoader.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    // ── API call to FastAPI backend ─────────────────────────────────────────
    let response;
    const isEml = state.activeTab === 'upload' &&
      state.selectedFile &&
      state.selectedFile.name.toLowerCase().endsWith('.eml');

    try {
      if (isEml) {
        // Send the .eml file as a proper multipart upload so the backend can
        // parse the full header block (SPF/DKIM/DMARC, Reply-To, Return-Path).
        const fd = new FormData();
        fd.append('file', state.selectedFile, state.selectedFile.name);
        response = await fetch(API_BASE + '/api/analyze-eml', {
          method: 'POST',
          body: fd
        });
      } else {
        // Paste (or .txt upload) — send raw text to the JSON endpoint.
        let content;
        if (state.activeTab === 'paste') {
          content = dom.emailInput.value;
        } else {
          content = await readFileAsText(state.selectedFile);
        }
        response = await fetch(API_BASE + '/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: content })
        });
      }
    } catch (networkErr) {
      // Network-level failure (server not running, CORS pre-flight refused, etc.)
      throw new ApiError(
        'Unable to connect to the analysis server. ' +
        'Please make sure the backend is running (uvicorn main:app --port 8000).'
      );
    }

    if (!response.ok) {
      let detail = `Server returned ${response.status}`;
      try { detail = (await response.json()).detail || detail; } catch (_) { /* ignore */ }
      throw new ApiError(`Analysis failed: ${detail}`);
    }

    const body = await response.json();
    // The .eml endpoint wraps the result in { detail, result }; unwrap it.
    const result = body && body.result ? body.result : body;
    // ─────────────────────────────────────────────────────────────────────────

    finishLoader();
    await sleep(500);
    dom.scanLoader.classList.add('hidden');
    await sleep(120);

    renderResults(result);

  } catch (err) {
    console.error('[PhishGuard] Error:', err);
    finishLoader();
    dom.scanLoader.classList.add('hidden');

    const msg = err instanceof ApiError
      ? err.message
      : 'An unexpected error occurred during analysis. Please try again.';
    showError(msg);

    // Reset button label so user can retry immediately
    setAnalyzing(false);
    dom.analyzeBtn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      Run Analysis
    `;
  } finally {
    setAnalyzing(false);
    dom.analyzerCard.style.opacity = '';
    dom.analyzerCard.style.pointerEvents = '';
  }
}

function handleClear() {
  dom.emailInput.value = '';
  dom.charCounter.textContent = '0 / 50,000';
  dom.charCounter.classList.remove('warn');
  clearFile();
  hideError();
  dom.resultsDashboard.classList.add('hidden');
  dom.scanLoader.classList.add('hidden');
  dom.tabPaste.click();
  dom.emailInput.focus();
}

function handleNewAnalysis() {
  dom.resultsDashboard.classList.add('hidden');
  dom.analyzerCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  setTimeout(() => {
    if (state.activeTab === 'paste') dom.emailInput.focus();
  }, 400);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/** Custom error class to distinguish API/network errors from programming errors. */
class ApiError extends Error {
  constructor(msg) { super(msg); this.name = 'ApiError'; }
}

/**
 * Read a File object as plain text, returning a Promise<string>.
 * Used so .eml files can be sent to the backend as raw text.
 */
function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error('Could not read the selected file.'));
    reader.readAsText(file);
  });
}

// ─── Error banner ─────────────────────────────────────────────────────────────
let _errorBanner = null;

function _ensureErrorBanner() {
  if (_errorBanner) return;
  _errorBanner = document.createElement('div');
  _errorBanner.id = 'apiErrorBanner';
  _errorBanner.setAttribute('role', 'alert');
  _errorBanner.style.cssText = [
    'display:none',
    'margin-top:12px',
    'padding:12px 16px',
    'background:color-mix(in srgb,var(--danger) 12%,var(--bg-raised))',
    'border:1px solid color-mix(in srgb,var(--danger) 35%,transparent)',
    'border-radius:var(--radius)',
    'color:var(--text-1)',
    'font-size:13px',
    'line-height:1.5',
    'display:none'
  ].join(';');
  // Insert immediately after the analyzerCard
  dom.analyzerCard.insertAdjacentElement('afterend', _errorBanner);
}

function showError(msg) {
  _ensureErrorBanner();
  _errorBanner.textContent = '⚠ ' + msg;
  _errorBanner.style.display = 'block';
  _errorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideError() {
  if (_errorBanner) _errorBanner.style.display = 'none';
}
// Inject spinner style
function injectStyles() {
  const s = document.createElement('style');
  s.textContent = `.spin-icon { animation: _spin 0.7s linear infinite; }
@keyframes _spin { to { transform: rotate(360deg); } }`;
  document.head.appendChild(s);
}

// ─── [9] INIT ─────────────────────────────────────────────────────────────────
function init() {
  injectStyles();
  initNavbar();
  initEmailInput();
  initUploadArea();

  dom.analyzeBtn.addEventListener('click', handleAnalyze);
  dom.clearBtn.addEventListener('click', handleClear);
  dom.newAnalysisBtn.addEventListener('click', handleNewAnalysis);

  // Ctrl/Cmd+Enter shortcut
  dom.emailInput.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      handleAnalyze();
    }
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
