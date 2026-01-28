/**
 * DKIM Validator - Main Module
 * Entry point that ties all modules together
 */

import { THEMES } from './constants.js';
import { log, clearLogs, esc } from './utils.js';
import { fetchDmarcRecord, fetchBimiRecord, fetchMtaStsRecord, fetchSpfRecord } from './dns.js';
import { parseEmail, parseRelayChain, extractMailDomain, extractSenderIP, parseArcHeaders } from './parsing.js';
import { evaluateSpf } from './spf.js';
import { verifyDkim } from './dkim.js';
import {
    renderHeaders, renderOverallSummary, renderAuthenticationResults, renderSig,
    renderSpfEvaluation, renderDmarc, renderArc, renderRelayChain,
    renderBimi, renderMtaSts, renderDebug, renderSummary
} from './render.js';

// ============================================================================
// State
// ============================================================================

let validateTimeout;

// ============================================================================
// Theme Management
// ============================================================================

function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('theme', theme);

    // Update active button state
    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.theme === theme);
    });

    // Update legacy toggle button if present
    const btn = document.getElementById('themeBtn');
    if (btn) {
        const isDark = theme.startsWith('dark');
        btn.textContent = isDark ? '\uD83C\uDF19' : '\u2600\uFE0F';
    }
}

function toggleTheme() {
    const current = document.documentElement.dataset.theme || 'dark-cyber';
    const isDark = current.startsWith('dark');

    // Toggle between first dark and first light theme
    const newTheme = isDark ? 'light-classic' : 'dark-cyber';
    setTheme(newTheme);
}

function initTheme() {
    const saved = localStorage.getItem('theme') || 'dark-cyber';
    setTheme(saved);
}

// ============================================================================
// Help Modal
// ============================================================================

function openHelp() {
    document.getElementById('helpModal').classList.add('visible');
    document.body.style.overflow = 'hidden';
}

function closeHelp() {
    document.getElementById('helpModal').classList.remove('visible');
    document.body.style.overflow = '';
}

// ============================================================================
// UI Helpers
// ============================================================================

function showToast(msg) {
    const t = document.getElementById('toast');
    document.getElementById('toastMsg').textContent = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2000);
}

function copy(btn, val) {
    navigator.clipboard.writeText(val);
    btn.classList.add('copied');
    const orig = btn.textContent;
    btn.textContent = '\u2713';
    setTimeout(() => { btn.classList.remove('copied'); btn.textContent = orig; }, 1500);
    showToast('Copied!');
}

function copyFlattenedSpf(btn) {
    const preview = document.getElementById('spfFlattenedPreview');
    if (preview) {
        copy(btn, preview.textContent);
    }
}

function clearAll() {
    document.getElementById('input').value = '';
    document.getElementById('results').classList.remove('visible');
    document.getElementById('status').innerHTML = '';
}

function toggleCard(el) {
    el.closest('.sig-card, .spf-card, .dmarc-card, .arc-card, .relay-card, .bimi-card, .mta-sts-card, .auth-results-card').classList.toggle('expanded');
}

// ============================================================================
// Tooltip Manager
// ============================================================================

const RFC_LINKS = {
    6376: { title: 'DKIM Signatures', url: 'https://datatracker.ietf.org/doc/html/rfc6376' },
    7208: { title: 'SPF', url: 'https://datatracker.ietf.org/doc/html/rfc7208' },
    7489: { title: 'DMARC', url: 'https://datatracker.ietf.org/doc/html/rfc7489' },
    8601: { title: 'Authentication-Results', url: 'https://datatracker.ietf.org/doc/html/rfc8601' },
    8617: { title: 'ARC', url: 'https://datatracker.ietf.org/doc/html/rfc8617' },
    8461: { title: 'MTA-STS', url: 'https://datatracker.ietf.org/doc/html/rfc8461' }
};

const Tooltip = {
    el: null,
    hideTimer: null,
    activeTag: null,

    init() {
        this.el = document.getElementById('tooltip');
        this.el.addEventListener('mouseenter', () => this.cancelHide());
        this.el.addEventListener('mouseleave', () => this.scheduleHide());
    },

    show(tag) {
        this.cancelHide();
        this.activeTag = tag;

        const { tag: name, tagName, tagDesc, tagValue, rfc, section } = tag.dataset;
        document.getElementById('tooltipTitle').textContent =
            tag.classList.contains('header') ? tagName : `${tagName} (${name}=)`;
        document.getElementById('tooltipDesc').textContent = tagDesc;
        document.getElementById('tooltipValue').textContent = tagValue;

        // Add RFC link if present
        const rfcEl = document.getElementById('tooltipRfc');
        if (rfcEl) {
            if (rfc && RFC_LINKS[rfc]) {
                const rfcInfo = RFC_LINKS[rfc];
                const url = section ? `${rfcInfo.url}#section-${section}` : rfcInfo.url;
                rfcEl.innerHTML = `<a href="${esc(url)}" target="_blank" rel="noopener" class="rfc-link">RFC ${rfc}${section ? ' §' + section : ''} - ${esc(rfcInfo.title)}</a>`;
                rfcEl.style.display = 'block';
            } else {
                rfcEl.innerHTML = '';
                rfcEl.style.display = 'none';
            }
        }

        const r = tag.getBoundingClientRect();
        let left = r.left;
        let top = r.bottom + 10;

        if (left + 300 > window.innerWidth) {
            left = window.innerWidth - 320;
        }
        if (left < 10) left = 10;

        if (top + 150 > window.innerHeight) {
            top = r.top - 160;
        }

        this.el.style.left = left + 'px';
        this.el.style.top = top + 'px';
        this.el.classList.add('visible');
    },

    hide() {
        this.el.classList.remove('visible');
        this.activeTag = null;
    },

    cancelHide() {
        if (this.hideTimer) {
            clearTimeout(this.hideTimer);
            this.hideTimer = null;
        }
    },

    scheduleHide() {
        this.cancelHide();
        this.hideTimer = setTimeout(() => this.hide(), 250);
    },

    attachToTag(tag) {
        tag.addEventListener('mouseenter', (e) => {
            if (!e.target.closest('.copy-btn')) {
                this.show(tag);
            }
        });
        tag.addEventListener('mouseleave', () => {
            this.scheduleHide();
        });
    }
};

// ============================================================================
// Initialize Tooltips
// ============================================================================

function initTooltips() {
    document.querySelectorAll('#results .tag').forEach(tag => {
        Tooltip.attachToTag(tag);
    });
}

// ============================================================================
// Main Validation Function
// ============================================================================

async function validate() {
    clearLogs();
    const input = document.getElementById('input').value.trim();
    if (!input) return;

    log('info', 'Starting validation');
    const { headers, body, dkimSigs, authResults, errors, warnings } = parseEmail(input);

    let parsingIssuesHtml = '';
    if (errors && errors.length > 0) {
        const errorsHtml = errors.map(e => `<div class="error-msg">${esc(e.message)}${e.suggestion ? `<span class="suggestion">\uD83D\uDCA1 ${esc(e.suggestion)}</span>` : ''}</div>`).join('');
        parsingIssuesHtml += errorsHtml;
        errors.forEach(e => log('error', e.message));
    }
    if (warnings && warnings.length > 0) {
        const warningsHtml = warnings.map(w => `<div class="warning-msg">${esc(w.message)}${w.suggestion ? `<span class="suggestion">\uD83D\uDCA1 ${esc(w.suggestion)}</span>` : ''}</div>`).join('');
        parsingIssuesHtml += warningsHtml;
        warnings.forEach(w => log('warn', w.message));
    }

    if (parsingIssuesHtml) {
        const issueClass = errors?.length > 0 ? 'has-errors' : 'has-warnings';
        document.getElementById('parsingIssuesEl').innerHTML = `<div class="parsing-issues ${issueClass}">
            <div class="section-header">\u26A0\uFE0F Parsing Issues</div>
            ${parsingIssuesHtml}
        </div>`;
    } else {
        document.getElementById('parsingIssuesEl').innerHTML = '';
    }

    if (errors && errors.length > 0 && headers.length === 0) {
        document.getElementById('overallSummaryEl').innerHTML = '';
        document.getElementById('authResultsEl').innerHTML = '';
        document.getElementById('headersEl').innerHTML = '';
        document.getElementById('summaryEl').innerHTML = '';
        document.getElementById('relayEl').innerHTML = '';
        document.getElementById('spfEl').innerHTML = '';
        document.getElementById('dmarcEl').innerHTML = '';
        document.getElementById('bimiEl').innerHTML = '';
        document.getElementById('mtaStsEl').innerHTML = '';
        document.getElementById('arcEl').innerHTML = '';
        document.getElementById('sigsEl').innerHTML = '';
        document.getElementById('debugLog').innerHTML = renderDebug();
        document.getElementById('results').classList.add('visible');
        document.getElementById('status').innerHTML = '';
        return;
    }

    const signed = new Set();
    dkimSigs.forEach(s => s.parsed?.h?.split(':').forEach(h => signed.add(h.trim().toLowerCase())));

    document.getElementById('headersEl').innerHTML = renderHeaders(headers, signed);

    const relayHops = parseRelayChain(headers);
    document.getElementById('relayEl').innerHTML = renderRelayChain(relayHops);
    log('info', `Found ${relayHops.length} relay hops`);

    const mailDomain = extractMailDomain(headers);
    const senderIP = extractSenderIP(headers);
    let spfEvalResult = null;
    if (mailDomain && senderIP) {
        spfEvalResult = await evaluateSpf(senderIP, mailDomain);
        spfEvalResult.senderIP = senderIP;
        spfEvalResult.domain = mailDomain;
    } else if (mailDomain) {
        const spfRecord = await fetchSpfRecord(mailDomain);
        spfEvalResult = {
            result: 'none',
            reason: 'Could not extract sender IP from headers',
            record: spfRecord.ok ? spfRecord.record : null,
            domain: mailDomain,
            senderIP: null
        };
        log('warn', 'Could not extract sender IP for SPF evaluation');
    } else {
        log('warn', 'Could not extract mail domain for SPF check');
    }
    document.getElementById('spfEl').innerHTML = spfEvalResult ? renderSpfEvaluation(spfEvalResult) : '<div class="error-msg">Could not determine sender domain for SPF lookup</div>';

    let dmarcResult = null;
    if (mailDomain) {
        dmarcResult = await fetchDmarcRecord(mailDomain);
    }
    document.getElementById('dmarcEl').innerHTML = dmarcResult ? renderDmarc(dmarcResult) : '';

    // BIMI lookup
    let bimiResult = null;
    if (mailDomain) {
        bimiResult = await fetchBimiRecord(mailDomain);
    }
    document.getElementById('bimiEl').innerHTML = bimiResult ? renderBimi(bimiResult) : '';

    // MTA-STS lookup
    let mtaStsResult = null;
    if (mailDomain) {
        mtaStsResult = await fetchMtaStsRecord(mailDomain);
    }
    document.getElementById('mtaStsEl').innerHTML = mtaStsResult ? renderMtaSts(mtaStsResult) : '';

    const arcSets = parseArcHeaders(headers);
    document.getElementById('arcEl').innerHTML = renderArc(arcSets);
    if (arcSets.length > 0) {
        log('info', `Found ${arcSets.length} ARC set(s) in chain`);
    }

    // Verify DKIM signatures
    const dkimResults = [];
    for (const sig of dkimSigs) {
        dkimResults.push(await verifyDkim(sig, headers, body));
    }

    const valid = dkimResults.filter(r => r.status === 'valid').length;
    const invalid = dkimResults.length - valid;

    // Render Authentication-Results header (from receiving server)
    document.getElementById('authResultsEl').innerHTML = renderAuthenticationResults(authResults);

    // Render overall summary card
    document.getElementById('overallSummaryEl').innerHTML = renderOverallSummary({
        dkimResults,
        spfResult: spfEvalResult,
        dmarcResult,
        authResults
    });

    document.getElementById('summaryEl').innerHTML = renderSummary({
        spfResult: spfEvalResult,
        dkimResults
    });

    if (!dkimSigs.length) {
        document.getElementById('sigsEl').innerHTML = '<div class="error-msg">No DKIM-Signature headers found</div>';
    } else {
        document.getElementById('sigsEl').innerHTML = dkimResults.map((r, i) => renderSig(r, i + 1)).join('');
    }

    document.getElementById('debugLog').innerHTML = renderDebug();
    document.getElementById('results').classList.add('visible');
    document.getElementById('status').innerHTML = '';
    initTooltips();
}

// ============================================================================
// Event Listeners and Initialization
// ============================================================================

// Only run DOM initialization in browser environment
if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        initTheme();
        Tooltip.init();

        // Close help modal on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && document.getElementById('helpModal').classList.contains('visible')) {
                closeHelp();
            }
        });

        // Auto-validate on input
        document.getElementById('input').addEventListener('input', () => {
            clearTimeout(validateTimeout);
            const val = document.getElementById('input').value.trim();
            if (!val || val.length < 50) {
                document.getElementById('results').classList.remove('visible');
                document.getElementById('status').innerHTML = '';
                return;
            }
            document.getElementById('status').innerHTML = '<div class="spinner"></div> Validating...';
            validateTimeout = setTimeout(validate, 400);
        });

        // Drag & Drop support for .eml files
        const inputSection = document.querySelector('.input-section');
        const textarea = document.getElementById('input');

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            inputSection.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            inputSection.addEventListener(eventName, () => {
                inputSection.classList.add('drag-over');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            inputSection.addEventListener(eventName, () => {
                inputSection.classList.remove('drag-over');
            }, false);
        });

        inputSection.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;

            if (files.length > 0) {
                handleFiles(files);
            }
        }

        function handleFiles(files) {
            const file = files[0];
            const validExtensions = ['.eml', '.txt', '.msg'];
            const fileName = file.name.toLowerCase();
            const isValidExt = validExtensions.some(ext => fileName.endsWith(ext));

            if (!isValidExt && !file.type.includes('text') && !file.type.includes('message')) {
                showToast('Please drop an email file (.eml, .txt)');
                return;
            }

            document.getElementById('status').innerHTML = '<div class="spinner"></div> Reading file...';

            const reader = new FileReader();
            reader.onload = function(e) {
                textarea.value = e.target.result;
                document.getElementById('status').innerHTML = '<div class="spinner"></div> Validating...';
                clearTimeout(validateTimeout);
                validateTimeout = setTimeout(validate, 100);
                showToast(`Loaded: ${file.name}`);
            };
            reader.onerror = function() {
                document.getElementById('status').innerHTML = '';
                showToast('Error reading file');
            };
            reader.readAsText(file);
        }
    });
}

// ============================================================================
// Global Exports (for onclick handlers in HTML)
// ============================================================================

// Make functions available globally for HTML onclick handlers
if (typeof window !== 'undefined') {
    window.setTheme = setTheme;
    window.toggleTheme = toggleTheme;
    window.openHelp = openHelp;
    window.closeHelp = closeHelp;
    window.copy = copy;
    window.copyFlattenedSpf = copyFlattenedSpf;
    window.clearAll = clearAll;
    window.toggleCard = toggleCard;
}

// ============================================================================
// Module Exports for Testing
// ============================================================================

export {
    validate,
    setTheme,
    toggleTheme,
    openHelp,
    closeHelp,
    copy,
    clearAll,
    toggleCard,
    Tooltip
};
