/**
 * DKIM Signature Validator - JavaScript
 * Separated from dkimsignaturevalidator.html
 *
 * This module handles email authentication validation including:
 * - DKIM signature verification
 * - SPF record evaluation
 * - DMARC policy checking
 * - ARC chain validation
 */

// ============================================================================
// Constants - Tag descriptions with RFC references
// ============================================================================

// RFC Links for clickable references
const RFC_LINKS = {
    6376: { title: 'DKIM Signatures', url: 'https://datatracker.ietf.org/doc/html/rfc6376' },
    7208: { title: 'SPF', url: 'https://datatracker.ietf.org/doc/html/rfc7208' },
    7489: { title: 'DMARC', url: 'https://datatracker.ietf.org/doc/html/rfc7489' },
    8601: { title: 'Authentication-Results', url: 'https://datatracker.ietf.org/doc/html/rfc8601' },
    8617: { title: 'ARC', url: 'https://datatracker.ietf.org/doc/html/rfc8617' },
    8461: { title: 'MTA-STS', url: 'https://datatracker.ietf.org/doc/html/rfc8461' }
};

// Security implications for authentication results
const SECURITY_IMPLICATIONS = {
    dkim: {
        pass: { level: 'good', message: 'Email content has not been modified since it was signed by the sender\'s domain.' },
        fail: { level: 'bad', message: 'Email may have been tampered with, or the signature is invalid. Treat with caution.' },
        none: { level: 'neutral', message: 'No DKIM signature present. Cannot verify message integrity.' }
    },
    spf: {
        pass: { level: 'good', message: 'Sending server is authorized to send mail for this domain.' },
        fail: { level: 'bad', message: 'Sending server is NOT authorized. This could be a spoofed email.' },
        softfail: { level: 'warning', message: 'Sender is probably not authorized. Domain is transitioning to stricter policy.' },
        neutral: { level: 'neutral', message: 'Domain makes no assertion about the sender\'s authorization.' },
        none: { level: 'neutral', message: 'No SPF record found. Domain has not configured sender authorization.' },
        permerror: { level: 'bad', message: 'SPF record has errors. Domain configuration is broken.' },
        temperror: { level: 'warning', message: 'Temporary DNS error. Try again later.' }
    },
    dmarc: {
        pass: { level: 'good', message: 'Email passes DMARC alignment. Both authentication and domain alignment verified.' },
        fail: { level: 'bad', message: 'DMARC check failed. Email may be forged or misconfigured.' },
        none: { level: 'neutral', message: 'No DMARC policy. Domain owner has not set up anti-spoofing protection.' },
        reject: { level: 'good', message: 'Domain uses strict policy - unauthorized emails are rejected.' },
        quarantine: { level: 'warning', message: 'Domain uses moderate policy - suspicious emails go to spam.' },
        policy_none: { level: 'warning', message: 'Domain is only monitoring - no action taken on failures.' }
    },
    overall: {
        pass: { level: 'good', title: 'Email Authentication: \u2713 Fully Authenticated', message: 'All authentication checks passed. This email can be trusted as legitimately from the claimed sender.' },
        partial: { level: 'warning', title: 'Email Authentication: \u26A0 Partial Issues', message: 'Some authentication checks passed, but there are issues. Review the specific failures below.' },
        fail: { level: 'bad', title: 'Email Authentication: \u2717 Authentication Failed', message: 'Critical authentication failures detected. This email may be forged or spoofed.' },
        unknown: { level: 'neutral', title: 'Email Authentication: ? Unknown', message: 'Could not determine authentication status.' }
    }
};

const DKIM_TAGS = {
    v: { name: 'Version', desc: 'DKIM signature version (must be "1")', rfc: '6376', section: '3.5' },
    a: { name: 'Algorithm', desc: 'Signing algorithm: rsa-sha256 or rsa-sha1', rfc: '6376', section: '3.5' },
    b: { name: 'Signature', desc: 'Base64-encoded cryptographic signature', rfc: '6376', section: '3.5' },
    bh: { name: 'Body Hash', desc: 'Hash of canonicalized message body', rfc: '6376', section: '3.5' },
    c: { name: 'Canonicalization', desc: 'Header/body normalization: simple or relaxed', rfc: '6376', section: '3.4' },
    d: { name: 'Domain', desc: 'Signing domain identifier (SDID)', rfc: '6376', section: '3.5' },
    s: { name: 'Selector', desc: 'DNS selector for public key lookup', rfc: '6376', section: '3.5' },
    h: { name: 'Signed Headers', desc: 'Headers included in signature', rfc: '6376', section: '3.5' },
    t: { name: 'Timestamp', desc: 'Signature creation time (Unix epoch)', rfc: '6376', section: '3.5' },
    x: { name: 'Expiration', desc: 'Signature expiration time (Unix epoch)', rfc: '6376', section: '3.5' },
    l: { name: 'Body Length', desc: 'Number of body bytes signed (security risk!)', rfc: '6376', section: '3.5' },
    i: { name: 'Identity', desc: 'Agent/user identifier (AUID)', rfc: '6376', section: '3.5' }
};

const DNS_TAGS = {
    v: { name: 'Version', desc: 'DKIM key record version (must be "DKIM1") [RFC 6376 §3.6.1]' },
    k: { name: 'Key Type', desc: 'Type of key: rsa (default) or ed25519 [RFC 6376 §3.6.1]' },
    p: { name: 'Public Key', desc: 'Base64-encoded public key data [RFC 6376 §3.6.1]' },
    h: { name: 'Hash Algorithms', desc: 'Acceptable hash algorithms [RFC 6376 §3.6.1]' },
    t: { name: 'Flags', desc: 'Flags: y=testing mode, s=strict [RFC 6376 §3.6.1]' }
};

const SPF_MECHANISMS = {
    all: { name: 'All', desc: 'Matches all senders (catchall) [RFC 7208 §5.1]' },
    ip4: { name: 'IPv4', desc: 'Match if sender IP is in this IPv4 range [RFC 7208 §5.6]' },
    ip6: { name: 'IPv6', desc: 'Match if sender IP is in this IPv6 range [RFC 7208 §5.6]' },
    a: { name: 'A Record', desc: 'Match if sender IP matches domain A record [RFC 7208 §5.3]' },
    mx: { name: 'MX Record', desc: 'Match if sender IP matches domain MX hosts [RFC 7208 §5.4]' },
    include: { name: 'Include', desc: 'Include SPF policy from another domain [RFC 7208 §5.2]' },
    redirect: { name: 'Redirect', desc: 'Use SPF policy from another domain instead [RFC 7208 §6.1]' },
    exists: { name: 'Exists', desc: 'Match if domain exists (has any A record) [RFC 7208 §5.7]' },
    ptr: { name: 'PTR', desc: 'Match via reverse DNS (deprecated) [RFC 7208 §5.5]' }
};

const SPF_QUALIFIERS = {
    '+': { name: 'Pass', desc: 'IP is authorized', color: 'success' },
    '-': { name: 'Fail', desc: 'IP is not authorized', color: 'error' },
    '~': { name: 'SoftFail', desc: 'IP is probably not authorized', color: 'warning' },
    '?': { name: 'Neutral', desc: 'No assertion about IP', color: 'neutral' }
};

const SPF_RESULTS = {
    pass: { name: 'Pass', desc: 'Sender IP is authorized', color: 'success', icon: '\u2713' },
    fail: { name: 'Fail', desc: 'Sender IP is NOT authorized', color: 'error', icon: '\u2717' },
    softfail: { name: 'SoftFail', desc: 'Sender IP is probably not authorized', color: 'warning', icon: '~' },
    neutral: { name: 'Neutral', desc: 'No assertion about sender IP', color: 'neutral', icon: '?' },
    none: { name: 'None', desc: 'No SPF record found', color: 'neutral', icon: '\u2212' },
    permerror: { name: 'PermError', desc: 'Permanent error in SPF evaluation', color: 'error', icon: '!' },
    temperror: { name: 'TempError', desc: 'Temporary error (DNS timeout)', color: 'warning', icon: '\u26A0' }
};

const DMARC_TAGS = {
    v: { name: 'Version', desc: 'DMARC version (must be "DMARC1") [RFC 7489 §6.3]' },
    p: { name: 'Policy', desc: 'Policy for the domain: none, quarantine, reject [RFC 7489 §6.3]' },
    sp: { name: 'Subdomain Policy', desc: 'Policy for subdomains (defaults to p=) [RFC 7489 §6.3]' },
    pct: { name: 'Percentage', desc: 'Percentage of messages to apply policy (default: 100) [RFC 7489 §6.3]' },
    rua: { name: 'Aggregate Reports', desc: 'URI(s) for aggregate reports [RFC 7489 §6.3]' },
    ruf: { name: 'Forensic Reports', desc: 'URI(s) for forensic/failure reports [RFC 7489 §6.3]' },
    adkim: { name: 'DKIM Alignment', desc: 'DKIM alignment mode: r=relaxed, s=strict [RFC 7489 §6.3]' },
    aspf: { name: 'SPF Alignment', desc: 'SPF alignment mode: r=relaxed, s=strict [RFC 7489 §6.3]' },
    fo: { name: 'Failure Options', desc: 'When to generate failure reports: 0, 1, d, s [RFC 7489 §6.3]' },
    rf: { name: 'Report Format', desc: 'Format for failure reports (afrf) [RFC 7489 §6.3]' },
    ri: { name: 'Report Interval', desc: 'Interval between aggregate reports in seconds [RFC 7489 §6.3]' }
};

const DMARC_POLICIES = {
    none: { name: 'None', desc: 'No action taken, monitor only [RFC 7489 §6.3]', color: 'warning', icon: '?' },
    quarantine: { name: 'Quarantine', desc: 'Treat as suspicious (spam folder) [RFC 7489 §6.3]', color: 'warning', icon: '\u26A0' },
    reject: { name: 'Reject', desc: 'Reject the message outright [RFC 7489 §6.3]', color: 'success', icon: '\u2713' }
};

// ARC (Authenticated Received Chain) tags - RFC 8617
const ARC_SEAL_TAGS = {
    i: { name: 'Instance', desc: 'ARC chain instance number (1, 2, 3...) [RFC 8617 §4.1]' },
    a: { name: 'Algorithm', desc: 'Signing algorithm (rsa-sha256) [RFC 8617 §4.1]' },
    b: { name: 'Signature', desc: 'Base64-encoded signature of ARC headers [RFC 8617 §4.1]' },
    cv: { name: 'Chain Validation', desc: 'Validation status: none, fail, pass [RFC 8617 §4.1]' },
    d: { name: 'Domain', desc: 'Signing domain [RFC 8617 §4.1]' },
    s: { name: 'Selector', desc: 'DNS selector for public key [RFC 8617 §4.1]' },
    t: { name: 'Timestamp', desc: 'Signature creation time (Unix epoch) [RFC 8617 §4.1]' }
};

const ARC_MESSAGE_TAGS = {
    i: { name: 'Instance', desc: 'ARC chain instance number [RFC 8617 §4.1]' },
    a: { name: 'Algorithm', desc: 'Signing algorithm [RFC 8617 §4.1]' },
    b: { name: 'Signature', desc: 'Base64-encoded signature [RFC 8617 §4.1]' },
    bh: { name: 'Body Hash', desc: 'Hash of canonicalized body [RFC 8617 §4.1]' },
    c: { name: 'Canonicalization', desc: 'Header/body normalization method [RFC 8617 §4.1]' },
    d: { name: 'Domain', desc: 'Signing domain [RFC 8617 §4.1]' },
    h: { name: 'Signed Headers', desc: 'Headers included in signature [RFC 8617 §4.1]' },
    s: { name: 'Selector', desc: 'DNS selector for public key [RFC 8617 §4.1]' },
    t: { name: 'Timestamp', desc: 'Signature creation time [RFC 8617 §4.1]' }
};

const ARC_AUTH_TAGS = {
    i: { name: 'Instance', desc: 'ARC chain instance number [RFC 8617 §4.1]' },
    dkim: { name: 'DKIM Result', desc: 'DKIM authentication result [RFC 8617 §4.1]' },
    spf: { name: 'SPF Result', desc: 'SPF authentication result [RFC 8617 §4.1]' },
    dmarc: { name: 'DMARC Result', desc: 'DMARC authentication result [RFC 8617 §4.1]' },
    arc: { name: 'ARC Result', desc: 'Previous ARC validation result [RFC 8617 §4.1]' }
};

const ARC_CV_STATUS = {
    none: { name: 'None', desc: 'No previous ARC sets in chain [RFC 8617 §4.1]', color: 'neutral', icon: '\u2212' },
    pass: { name: 'Pass', desc: 'Previous ARC sets validated successfully [RFC 8617 §4.1]', color: 'success', icon: '\u2713' },
    fail: { name: 'Fail', desc: 'Previous ARC set validation failed [RFC 8617 §4.1]', color: 'error', icon: '\u2717' }
};

// BIMI (Brand Indicators for Message Identification) - draft-brand-indicators-for-message-identification
const BIMI_TAGS = {
    v: { name: 'Version', desc: 'BIMI version (must be "BIMI1") [BIMI spec]' },
    l: { name: 'Logo Location', desc: 'HTTPS URL to SVG logo file [BIMI spec]' },
    a: { name: 'Authority', desc: 'URL to Verified Mark Certificate (VMC) [BIMI spec]' }
};

// MTA-STS (Mail Transfer Agent Strict Transport Security) - RFC 8461
const MTA_STS_MODES = {
    enforce: { name: 'Enforce', desc: 'Require TLS; reject on failure [RFC 8461 §5]', color: 'success', icon: '\u2713' },
    testing: { name: 'Testing', desc: 'Report TLS failures but deliver anyway [RFC 8461 §5]', color: 'warning', icon: '~' },
    none: { name: 'None', desc: 'MTA-STS is disabled [RFC 8461 §5]', color: 'neutral', icon: '\u2212' }
};

// Authentication-Results result codes (RFC 8601)
const AUTH_RESULTS = {
    pass: { name: 'Pass', desc: 'Authentication passed', color: 'success', icon: '\u2713' },
    fail: { name: 'Fail', desc: 'Authentication failed', color: 'error', icon: '\u2717' },
    softfail: { name: 'SoftFail', desc: 'Soft failure', color: 'warning', icon: '~' },
    neutral: { name: 'Neutral', desc: 'No assertion', color: 'neutral', icon: '?' },
    none: { name: 'None', desc: 'No authentication performed', color: 'neutral', icon: '\u2212' },
    temperror: { name: 'TempError', desc: 'Temporary error', color: 'warning', icon: '\u26A0' },
    permerror: { name: 'PermError', desc: 'Permanent error', color: 'error', icon: '!' },
    policy: { name: 'Policy', desc: 'Policy decision', color: 'neutral', icon: 'P' },
    hardfail: { name: 'HardFail', desc: 'Hard failure', color: 'error', icon: '\u2717' },
    bestguesspass: { name: 'BestGuessPass', desc: 'Best guess pass', color: 'warning', icon: '~' }
};

// ============================================================================
// State
// ============================================================================

const logs = [];
let validateTimeout;

// ============================================================================
// Theme Management
// ============================================================================

// Available themes
const THEMES = {
    dark: ['dark-cyber', 'dark-dracula', 'dark-nord', 'dark-monokai', 'dark-ocean'],
    light: ['light-classic', 'light-solarized', 'light-github', 'light-rose', 'light-mint']
};

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
// Utility Functions
// ============================================================================

function esc(s) {
    if (typeof document !== 'undefined') {
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }
    // Node.js fallback for testing
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function log(type, msg) {
    logs.push({ time: new Date().toISOString().split('T')[1].split('.')[0], type, msg });
}

/**
 * Clean DNS TXT record data by removing quotes and joining split strings
 * @param {string} data - Raw DNS TXT record data
 * @returns {string} Cleaned record string
 */
function cleanDnsRecord(data) {
    return data.replace(/^"|"$/g, '').replace(/" "/g, '');
}

/**
 * Parse tag=value pairs from a record string (used by DKIM, DMARC, ARC)
 * @param {string} record - Record string with tag=value; format
 * @param {string[]} stripWhitespace - Tags that should have whitespace removed
 * @returns {Object} Object with tag names as keys
 */
function parseTagValuePairs(record, stripWhitespace = []) {
    const tags = {};
    const re = /([a-z]+)\s*=\s*([^;]+)/gi;
    let m;
    while ((m = re.exec(record))) {
        let val = m[2].trim();
        if (stripWhitespace.includes(m[1].toLowerCase())) {
            val = val.replace(/\s+/g, '');
        }
        tags[m[1].toLowerCase()] = val;
    }
    return tags;
}

/**
 * Get badge style and text for validation results
 * @param {string} result - Result type (pass, fail, etc.)
 * @param {string} type - Context type (spf, dmarc, arc)
 * @returns {{badgeStyle: string, badgeText: string}}
 */
function getBadgeForResult(result, type = 'generic') {
    const styles = {
        pass: { style: 'background:rgba(0,255,136,0.15);color:var(--success)', text: '\u2713 PASS' },
        fail: { style: 'background:rgba(255,107,122,0.15);color:var(--error)', text: '\u2717 FAIL' },
        softfail: { style: 'background:rgba(255,179,71,0.15);color:var(--warning)', text: '~ SOFTFAIL' },
        neutral: { style: 'background:rgba(139,148,158,0.15);color:var(--text-secondary)', text: '? NEUTRAL' },
        none: { style: 'background:rgba(139,148,158,0.15);color:var(--text-secondary)', text: '\u2212 NONE' },
        permerror: { style: 'background:rgba(255,107,122,0.15);color:var(--error)', text: '! ERROR' },
        temperror: { style: 'background:rgba(255,107,122,0.15);color:var(--error)', text: '! ERROR' },
        reject: { style: 'background:rgba(0,255,136,0.15);color:var(--success)', text: '\u2713 REJECT' },
        quarantine: { style: 'background:rgba(255,179,71,0.15);color:var(--warning)', text: '\u26A0 QUARANTINE' },
        notfound: { style: 'background:rgba(255,107,122,0.15);color:var(--error)', text: 'NOT FOUND' }
    };
    const config = styles[result] || styles.none;
    return { badgeStyle: config.style, badgeText: config.text };
}

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
                rfcEl.innerHTML = `<a href="${esc(url)}" target="_blank" rel="noopener" class="rfc-link">RFC ${rfc}${section ? ' \u00A7' + section : ''} - ${esc(rfcInfo.title)}</a>`;
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
// Email Parsing
// ============================================================================

function parseEmail(raw) {
    const errors = [];
    const warnings = [];

    if (!raw || raw.trim().length === 0) {
        errors.push({ type: 'empty', message: 'No email content provided', suggestion: 'Paste the raw email source including headers and body' });
        return { headers: [], body: '', dkimSigs: [], errors, warnings };
    }

    if (!raw.includes(':') || raw.indexOf(':') > 100) {
        errors.push({ type: 'no_headers', message: 'No email headers detected', suggestion: 'Make sure to include the full raw email source, not just the body. In most email clients, look for "Show Original" or "View Source"' });
    }

    let headerSection, body;
    let idx = raw.indexOf('\r\n\r\n');
    if (idx !== -1) {
        headerSection = raw.slice(0, idx);
        body = raw.slice(idx + 4);
    } else {
        idx = raw.indexOf('\n\n');
        if (idx !== -1) {
            headerSection = raw.slice(0, idx);
            body = raw.slice(idx + 2);
        } else {
            headerSection = raw;
            body = '';
            warnings.push({ type: 'no_body', message: 'No message body found', suggestion: 'The email appears to have no body section. This may be normal for some emails, or the header/body separator (blank line) may be missing' });
        }
    }

    headerSection = headerSection.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
    const headers = [];
    let cur = null;
    let invalidLines = 0;

    for (const line of headerSection.split('\r\n')) {
        if (/^[ \t]/.test(line) && cur) {
            cur.raw += '\r\n' + line;
            cur.value += '\r\n' + line;
        } else {
            if (cur) headers.push({ name: cur.name, value: cur.value, raw: cur.raw });
            const i = line.indexOf(':');
            if (i > 0) {
                cur = {
                    name: line.slice(0, i),
                    value: line.slice(i + 1),
                    raw: line
                };
            } else if (line.trim().length > 0) {
                invalidLines++;
                cur = null;
            } else {
                cur = null;
            }
        }
    }
    if (cur) headers.push({ name: cur.name, value: cur.value, raw: cur.raw });

    if (invalidLines > 3) {
        warnings.push({ type: 'malformed_headers', message: `Found ${invalidLines} lines that don't look like headers`, suggestion: 'Some header lines may be malformed. Ensure you\'re pasting the raw email source without modifications' });
    }

    const headerNames = headers.map(h => h.name.toLowerCase());
    if (!headerNames.includes('from')) {
        warnings.push({ type: 'missing_from', message: 'No "From" header found', suggestion: 'The From header is required in valid emails. The email may be truncated or malformed' });
    }
    if (!headerNames.includes('date')) {
        warnings.push({ type: 'missing_date', message: 'No "Date" header found', suggestion: 'Most emails have a Date header. The email may be incomplete' });
    }

    if (raw.includes('&lt;') || raw.includes('&gt;') || raw.includes('&amp;')) {
        warnings.push({ type: 'html_encoded', message: 'Content appears to be HTML-encoded', suggestion: 'The email may have been copied from an HTML view. Try using "View Source" or "Show Original" in your email client' });
    }

    if (/^[A-Za-z0-9+/=\s]+$/.test(raw.trim()) && raw.length > 200) {
        warnings.push({ type: 'possibly_base64', message: 'Content looks like base64-encoded data', suggestion: 'This might be an encoded attachment rather than the email source. Look for "Show Original" to get the raw headers' });
    }

    const dkimSigs = headers.filter(h => h.name.toLowerCase() === 'dkim-signature').map(h => ({
        raw: h.raw,
        parsed: parseDkimTags(h.raw)
    }));

    // Parse Authentication-Results headers
    const authResults = headers
        .filter(h => h.name.toLowerCase() === 'authentication-results')
        .map(h => parseAuthenticationResults(h.value));

    return { headers, body, dkimSigs, authResults, errors, warnings };
}

function parseDkimTags(raw) {
    const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
    const match = unfolded.match(/DKIM-Signature:\s*(.+)/i);
    if (!match) return null;
    return parseTagValuePairs(match[1], ['b', 'bh']);
}

function parseDnsTags(record) {
    return parseTagValuePairs(record, ['p']);
}

// ============================================================================
// Authentication-Results Header Parsing (RFC 8601)
// ============================================================================

function parseAuthenticationResults(value) {
    const unfolded = value.replace(/\r?\n[ \t]+/g, ' ').trim();
    const result = {
        authserv_id: null,
        version: null,
        results: []
    };

    const firstSemicolon = unfolded.indexOf(';');
    if (firstSemicolon === -1) {
        result.authserv_id = unfolded.trim();
        return result;
    }

    const authservPart = unfolded.slice(0, firstSemicolon).trim();
    const versionMatch = authservPart.match(/^(.+?)\s+(\d+)$/);
    if (versionMatch) {
        result.authserv_id = versionMatch[1].trim();
        result.version = parseInt(versionMatch[2], 10);
    } else {
        result.authserv_id = authservPart;
    }

    const resultsPart = unfolded.slice(firstSemicolon + 1);
    const resultEntries = splitAuthResults(resultsPart);

    for (const entry of resultEntries) {
        const parsed = parseAuthResultEntry(entry.trim());
        if (parsed) {
            result.results.push(parsed);
        }
    }

    return result;
}

function splitAuthResults(str) {
    const results = [];
    let current = '';
    let inQuotes = false;
    let parenDepth = 0;

    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        if (char === '"' && str[i - 1] !== '\\') {
            inQuotes = !inQuotes;
            current += char;
        } else if (char === '(' && !inQuotes) {
            parenDepth++;
            current += char;
        } else if (char === ')' && !inQuotes) {
            parenDepth--;
            current += char;
        } else if (char === ';' && !inQuotes && parenDepth === 0) {
            if (current.trim()) {
                results.push(current);
            }
            current = '';
        } else {
            current += char;
        }
    }
    if (current.trim()) {
        results.push(current);
    }
    return results;
}

function parseAuthResultEntry(entry) {
    if (!entry) return null;

    const methodMatch = entry.match(/^(\w+)\s*=\s*(\w+)/);
    if (!methodMatch) return null;

    const method = methodMatch[1].toLowerCase();
    const resultCode = methodMatch[2].toLowerCase();

    const parsed = {
        method,
        result: resultCode,
        resultInfo: AUTH_RESULTS[resultCode] || { name: resultCode.toUpperCase(), desc: 'Unknown result', color: 'neutral', icon: '?' },
        properties: {},
        reason: null
    };

    const reasonMatch = entry.match(/\(\s*([^)]+)\s*\)/);
    if (reasonMatch) {
        parsed.reason = reasonMatch[1].trim();
    }

    const propRegex = /([\w.]+)\s*=\s*(?:"([^"]+)"|([^\s;]+))/g;
    let match;
    let skipFirst = true;

    while ((match = propRegex.exec(entry)) !== null) {
        if (skipFirst) {
            skipFirst = false;
            continue;
        }
        const propName = match[1];
        const propValue = match[2] || match[3];
        parsed.properties[propName] = propValue;
    }

    return parsed;
}

// ============================================================================
// Canonicalization (RFC 6376)
// ============================================================================

function canonHeaderRelaxed(name, value) {
    let v = value.replace(/\r?\n[ \t]+/g, ' ').replace(/[ \t]+/g, ' ').trim();
    return name.toLowerCase() + ':' + v;
}

function canonBodyRelaxed(body) {
    if (!body) return '\r\n';
    let c = body.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
    c = c.split('\r\n').map(l => l.replace(/[ \t]+/g, ' ').replace(/ +$/, '')).join('\r\n');
    c = c.replace(/(\r\n)+$/, '') || '';
    return c + '\r\n';
}

function canonBodySimple(body) {
    if (!body) return '\r\n';
    let c = body.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
    c = c.replace(/(\r\n)+$/, '') || '';
    return c + '\r\n';
}

// ============================================================================
// Email Domain/IP Extraction
// ============================================================================

function extractMailDomain(headers) {
    const returnPath = headers.find(h => h.name.toLowerCase() === 'return-path');
    if (returnPath) {
        const match = returnPath.value.match(/<([^>]+)>|([^\s<>]+@[^\s<>]+)/);
        if (match) {
            const email = match[1] || match[2];
            const domain = email.split('@')[1];
            if (domain) return domain.toLowerCase().trim();
        }
    }
    const from = headers.find(h => h.name.toLowerCase() === 'from');
    if (from) {
        const match = from.value.match(/<([^>]+)>|([^\s<>]+@[^\s<>]+)/);
        if (match) {
            const email = match[1] || match[2];
            const domain = email.split('@')[1];
            if (domain) return domain.toLowerCase().trim();
        }
    }
    return null;
}

function extractSenderIP(headers) {
    const receivedHeaders = headers.filter(h => h.name.toLowerCase() === 'received');

    for (let i = receivedHeaders.length - 1; i >= 0; i--) {
        const val = receivedHeaders[i].value;

        let match = val.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
        if (match && !isPrivateIP(match[1])) {
            log('info', `Extracted sender IP: ${match[1]} from Received header`);
            return { ip: match[1], version: 4 };
        }

        match = val.match(/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/);
        if (match && !isPrivateIP(match[1])) {
            log('info', `Extracted sender IP: ${match[1]} from Received header`);
            return { ip: match[1], version: 4 };
        }

        match = val.match(/from\s+\S+\s+\((?:[^)]*\s)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
        if (match && !isPrivateIP(match[1])) {
            log('info', `Extracted sender IP: ${match[1]} from Received header`);
            return { ip: match[1], version: 4 };
        }

        match = val.match(/\[([0-9a-fA-F:]+:[0-9a-fA-F:]+)\]/);
        if (match && match[1].includes(':')) {
            log('info', `Extracted sender IPv6: ${match[1]} from Received header`);
            return { ip: match[1], version: 6 };
        }
    }

    log('warn', 'Could not extract sender IP from Received headers');
    return null;
}

function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    return false;
}

// ============================================================================
// Relay Chain Parsing
// ============================================================================

function parseRelayChain(headers) {
    const receivedHeaders = headers.filter(h => h.name.toLowerCase() === 'received');
    const hops = [];

    for (const hdr of receivedHeaders) {
        const val = hdr.value.replace(/\r?\n[ \t]+/g, ' ');
        const hop = { raw: val, type: 'received' };

        const fromMatch = val.match(/from\s+([^\s(]+)/i);
        if (fromMatch) hop.from = fromMatch[1];

        const byMatch = val.match(/by\s+([^\s(]+)/i);
        if (byMatch) hop.by = byMatch[1];

        const ipMatch = val.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
        if (ipMatch) hop.ip = ipMatch[1];

        const ipv6Match = val.match(/\[([0-9a-fA-F:]+:[0-9a-fA-F:]+)\]/);
        if (ipv6Match && ipv6Match[1].includes(':')) hop.ip = ipv6Match[1];

        const dateMatch = val.match(/;\s*([A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*[+-]?\d{0,4})/);
        if (dateMatch) {
            try {
                hop.timestamp = new Date(dateMatch[1]);
                if (isNaN(hop.timestamp.getTime())) hop.timestamp = null;
            } catch { hop.timestamp = null; }
        }

        if (!hop.timestamp) {
            const altDateMatch = val.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/);
            if (altDateMatch) {
                try {
                    hop.timestamp = new Date(altDateMatch[1]);
                    if (isNaN(hop.timestamp.getTime())) hop.timestamp = null;
                } catch { hop.timestamp = null; }
            }
        }

        const protoMatch = val.match(/with\s+(E?SMTPS?A?)/i);
        if (protoMatch) hop.protocol = protoMatch[1].toUpperCase();

        if (val.match(/\(.*TLS.*\)/i) || val.match(/ESMTPS/i)) hop.tls = true;

        hops.push(hop);
    }

    // Parse X-Received headers (Google/Gmail internal headers)
    const xReceivedHeaders = headers.filter(h => h.name.toLowerCase() === 'x-received');
    for (const hdr of xReceivedHeaders) {
        const val = hdr.value.replace(/\r?\n[ \t]+/g, ' ');
        const hop = { raw: val, type: 'x-received', isInternal: true };

        const byMatch = val.match(/by\s+([^\s;]+)/i);
        if (byMatch) hop.by = byMatch[1];

        const withMatch = val.match(/with\s+(\w+)/i);
        if (withMatch) hop.protocol = withMatch[1].toUpperCase();

        const dateMatch = val.match(/;\s*([A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*[+-]?\d{0,4})/);
        if (dateMatch) {
            try {
                hop.timestamp = new Date(dateMatch[1]);
                if (isNaN(hop.timestamp.getTime())) hop.timestamp = null;
            } catch { hop.timestamp = null; }
        }

        const idMatch = val.match(/id\s+([^\s;]+)/i);
        if (idMatch) hop.smtpId = idMatch[1];

        hops.push(hop);
    }

    // Sort by timestamp if available
    hops.sort((a, b) => {
        if (a.timestamp && b.timestamp) {
            return a.timestamp.getTime() - b.timestamp.getTime();
        }
        return 0;
    });

    // Calculate latencies
    for (let i = 1; i < hops.length; i++) {
        if (hops[i].timestamp && hops[i-1].timestamp) {
            hops[i].latency = hops[i].timestamp.getTime() - hops[i-1].timestamp.getTime();
        }
    }

    return hops;
}

function formatLatency(ms) {
    if (ms === undefined || ms === null) return null;
    if (ms < 0) ms = 0;
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    if (ms < 3600000) return `${(ms / 60000).toFixed(1)}m`;
    return `${(ms / 3600000).toFixed(1)}h`;
}

function getLatencyClass(ms) {
    if (ms === undefined || ms === null) return '';
    if (ms < 1000) return 'fast';
    if (ms < 10000) return 'medium';
    return 'slow';
}

// ============================================================================
// IP Address Utilities
// ============================================================================

function ipv4ToInt(ip) {
    const parts = ip.split('.').map(Number);
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function ipv4MatchesCIDR(ip, cidr) {
    let [network, prefixStr] = cidr.split('/');
    const prefix = prefixStr ? parseInt(prefixStr, 10) : 32;

    const ipInt = ipv4ToInt(ip);
    const networkInt = ipv4ToInt(network);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;

    return (ipInt & mask) === (networkInt & mask);
}

function expandIPv6(ip) {
    let parts = ip.split(':');
    const emptyIndex = parts.indexOf('');

    if (emptyIndex !== -1) {
        const before = parts.slice(0, emptyIndex).filter(p => p);
        const after = parts.slice(emptyIndex + 1).filter(p => p);
        const missing = 8 - before.length - after.length;
        parts = [...before, ...Array(missing).fill('0'), ...after];
    }

    return parts.map(p => p.padStart(4, '0')).join(':');
}

function ipv6ToBigInt(ip) {
    const expanded = expandIPv6(ip);
    const hex = expanded.replace(/:/g, '');
    return BigInt('0x' + hex);
}

function ipv6MatchesCIDR(ip, cidr) {
    let [network, prefixStr] = cidr.split('/');
    const prefix = prefixStr ? parseInt(prefixStr, 10) : 128;

    const ipBig = ipv6ToBigInt(ip);
    const networkBig = ipv6ToBigInt(network);
    const mask = prefix === 0 ? 0n : (~0n << BigInt(128 - prefix));

    return (ipBig & mask) === (networkBig & mask);
}

// ============================================================================
// DNS Lookups
// ============================================================================

/**
 * Generic DNS query helper
 * @param {string} domain - Domain to query
 * @param {string} type - DNS record type (A, AAAA, MX, TXT)
 * @param {number} typeCode - DNS type code for filtering answers
 * @param {function} extractor - Function to extract data from answer record
 * @returns {Promise<Array>} Array of extracted values
 */
async function fetchDnsRecords(domain, type, typeCode, extractor) {
    try {
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
            headers: { Accept: 'application/dns-json' }
        });
        const data = await res.json();
        const results = [];
        if (data.Answer) {
            for (const a of data.Answer) {
                if (a.type === typeCode) {
                    const value = extractor(a);
                    if (value) results.push(value);
                }
            }
        }
        return results;
    } catch (e) {
        log('error', `${type} record lookup failed for ${domain}: ${e.message}`);
        return [];
    }
}

async function fetchARecords(domain) {
    return fetchDnsRecords(domain, 'A', 1, a => a.data);
}

async function fetchAAAARecords(domain) {
    return fetchDnsRecords(domain, 'AAAA', 28, a => a.data);
}

async function fetchMXRecords(domain) {
    return fetchDnsRecords(domain, 'MX', 15, a => {
        const parts = a.data.split(' ');
        return parts.length >= 2 ? parts[1].replace(/\.$/, '') : null;
    });
}

async function fetchDns(domain, selector) {
    const name = `${selector}._domainkey.${domain}`;
    log('info', `DNS lookup: ${name}`);
    try {
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`, {
            headers: { Accept: 'application/dns-json' }
        });
        const data = await res.json();
        if (data.Answer) {
            for (const a of data.Answer) {
                if (a.type === 16) {
                    const record = cleanDnsRecord(a.data);
                    if (record.match(/^v\s*=\s*DKIM1/i) || record.match(/[;]?\s*p\s*=/)) {
                        log('success', `DNS found: ${record.slice(0, 80)}...`);
                        return { ok: true, record, name };
                    }
                }
            }
            for (const a of data.Answer) {
                if (a.type === 16) {
                    const record = cleanDnsRecord(a.data);
                    log('warn', `DNS found non-DKIM TXT: ${record.slice(0, 80)}...`);
                    return { ok: true, record, name };
                }
            }
        }
        return { ok: false, error: 'No TXT record', name };
    } catch (e) {
        log('error', `DNS error: ${e.message}`);
        return { ok: false, error: e.message, name };
    }
}

// ============================================================================
// SPF Evaluation
// ============================================================================

async function fetchSpfRecord(domain) {
    log('info', `SPF lookup: ${domain}`);
    try {
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=TXT`, {
            headers: { Accept: 'application/dns-json' }
        });
        const data = await res.json();
        if (data.Answer) {
            for (const a of data.Answer) {
                if (a.type === 16) {
                    const record = cleanDnsRecord(a.data);
                    if (record.startsWith('v=spf1')) {
                        log('success', `SPF found: ${record.slice(0, 80)}...`);
                        return { ok: true, record, domain };
                    }
                }
            }
        }
        log('warn', `No SPF record found for ${domain}`);
        return { ok: false, error: 'No SPF record found', domain };
    } catch (e) {
        log('error', `SPF DNS error: ${e.message}`);
        return { ok: false, error: e.message, domain };
    }
}

function parseSpfRecord(record) {
    const mechanisms = [];
    const parts = record.split(/\s+/).filter(p => p && p !== 'v=spf1');

    for (const part of parts) {
        let qualifier = '+';
        let term = part;

        if (['+', '-', '~', '?'].includes(part[0])) {
            qualifier = part[0];
            term = part.slice(1);
        }

        const colonIdx = term.indexOf(':');
        const eqIdx = term.indexOf('=');
        let mechanism, value;

        if (colonIdx !== -1) {
            mechanism = term.slice(0, colonIdx).toLowerCase();
            value = term.slice(colonIdx + 1);
        } else if (eqIdx !== -1) {
            mechanism = term.slice(0, eqIdx).toLowerCase();
            value = term.slice(eqIdx + 1);
        } else {
            mechanism = term.toLowerCase();
            value = '';
        }

        mechanisms.push({ qualifier, mechanism, value, raw: part });
    }

    return mechanisms;
}

async function evaluateSpf(senderIP, domain, depth = 0, lookupCount = { count: 0 }, trace = null) {
    const MAX_DEPTH = 10;
    const MAX_LOOKUPS = 10;

    if (trace === null) {
        trace = { domains: [], matchPath: [] };
    }

    const domainTrace = {
        domain,
        depth,
        record: null,
        mechanisms: [],
        matched: null
    };
    trace.domains.push(domainTrace);

    if (depth > MAX_DEPTH) {
        log('error', `SPF evaluation exceeded max depth (${MAX_DEPTH})`);
        return { result: 'permerror', reason: 'Too many nested includes', lookups: lookupCount.count, trace };
    }

    if (lookupCount.count >= MAX_LOOKUPS) {
        log('error', `SPF evaluation exceeded max DNS lookups (${MAX_LOOKUPS})`);
        return { result: 'permerror', reason: 'Too many DNS lookups', lookups: lookupCount.count, trace };
    }

    log('info', `Evaluating SPF for ${domain} (depth=${depth}, lookups=${lookupCount.count})`);

    const spfResult = await fetchSpfRecord(domain);
    if (!spfResult.ok) {
        domainTrace.error = spfResult.error;
        return { result: 'none', reason: spfResult.error, lookups: lookupCount.count, record: null, trace };
    }

    domainTrace.record = spfResult.record;
    const mechanisms = parseSpfRecord(spfResult.record);
    const ipVersion = senderIP.version;
    const ip = senderIP.ip;

    for (const mech of mechanisms) {
        let matched = false;
        let mechTrace = { mechanism: mech.raw, type: mech.mechanism, qualifier: mech.qualifier, matched: false, details: null };
        domainTrace.mechanisms.push(mechTrace);

        switch (mech.mechanism) {
            case 'all':
                matched = true;
                mechTrace.details = 'Matches all';
                break;

            case 'ip4':
                if (ipVersion === 4) {
                    matched = ipv4MatchesCIDR(ip, mech.value);
                    mechTrace.details = `Checking ${ip} against ${mech.value}`;
                } else {
                    mechTrace.details = 'Skipped (sender is IPv6)';
                }
                break;

            case 'ip6':
                if (ipVersion === 6) {
                    matched = ipv6MatchesCIDR(ip, mech.value);
                    mechTrace.details = `Checking ${ip} against ${mech.value}`;
                } else {
                    mechTrace.details = 'Skipped (sender is IPv4)';
                }
                break;

            case 'a':
                lookupCount.count++;
                if (lookupCount.count > MAX_LOOKUPS) {
                    return { result: 'permerror', reason: 'Too many DNS lookups', lookups: lookupCount.count, trace };
                }
                const aDomain = mech.value || domain;
                const aRecords = ipVersion === 4 ? await fetchARecords(aDomain) : await fetchAAAARecords(aDomain);
                mechTrace.details = `${aDomain} \u2192 ${aRecords.join(', ') || 'none'}`;
                log('info', `SPF 'a' mechanism: ${aDomain} resolved to ${aRecords.join(', ') || 'none'}`);
                for (const aIP of aRecords) {
                    if (ipVersion === 4 && ipv4MatchesCIDR(ip, aIP + '/32')) {
                        matched = true;
                        break;
                    } else if (ipVersion === 6 && ipv6MatchesCIDR(ip, aIP + '/128')) {
                        matched = true;
                        break;
                    }
                }
                break;

            case 'mx':
                lookupCount.count++;
                if (lookupCount.count > MAX_LOOKUPS) {
                    return { result: 'permerror', reason: 'Too many DNS lookups', lookups: lookupCount.count, trace };
                }
                const mxDomain = mech.value || domain;
                const mxHosts = await fetchMXRecords(mxDomain);
                mechTrace.details = `MX: ${mxHosts.join(', ') || 'none'}`;
                log('info', `SPF 'mx' mechanism: ${mxDomain} MX hosts: ${mxHosts.join(', ') || 'none'}`);
                for (const mxHost of mxHosts) {
                    lookupCount.count++;
                    if (lookupCount.count > MAX_LOOKUPS) {
                        return { result: 'permerror', reason: 'Too many DNS lookups', lookups: lookupCount.count, trace };
                    }
                    const mxIPs = ipVersion === 4 ? await fetchARecords(mxHost) : await fetchAAAARecords(mxHost);
                    for (const mxIP of mxIPs) {
                        if (ipVersion === 4 && ipv4MatchesCIDR(ip, mxIP + '/32')) {
                            matched = true;
                            break;
                        } else if (ipVersion === 6 && ipv6MatchesCIDR(ip, mxIP + '/128')) {
                            matched = true;
                            break;
                        }
                    }
                    if (matched) break;
                }
                break;

            case 'include':
                lookupCount.count++;
                if (lookupCount.count > MAX_LOOKUPS) {
                    return { result: 'permerror', reason: 'Too many DNS lookups', lookups: lookupCount.count, trace };
                }
                log('info', `SPF 'include' mechanism: checking ${mech.value}`);
                mechTrace.details = `\u2192 ${mech.value}`;
                const includeResult = await evaluateSpf(senderIP, mech.value, depth + 1, lookupCount, trace);
                if (includeResult.result === 'pass') {
                    matched = true;
                    mechTrace.includeResult = 'pass';
                } else if (includeResult.result === 'permerror' || includeResult.result === 'temperror') {
                    mechTrace.includeResult = includeResult.result;
                    return includeResult;
                } else {
                    mechTrace.includeResult = includeResult.result;
                }
                break;

            case 'redirect':
                lookupCount.count++;
                if (lookupCount.count > MAX_LOOKUPS) {
                    return { result: 'permerror', reason: 'Too many DNS lookups', lookups: lookupCount.count, trace };
                }
                log('info', `SPF 'redirect' mechanism: redirecting to ${mech.value}`);
                mechTrace.details = `\u2192 ${mech.value}`;
                const redirectResult = await evaluateSpf(senderIP, mech.value, depth + 1, lookupCount, trace);
                redirectResult.trace = trace;
                return redirectResult;

            case 'exists':
                lookupCount.count++;
                if (lookupCount.count > MAX_LOOKUPS) {
                    return { result: 'permerror', reason: 'Too many DNS lookups', lookups: lookupCount.count, trace };
                }
                const existsIPs = await fetchARecords(mech.value);
                matched = existsIPs.length > 0;
                mechTrace.details = `${mech.value} ${matched ? 'exists' : 'not found'}`;
                break;

            case 'ptr':
                log('warn', 'PTR mechanism is deprecated and not evaluated');
                mechTrace.details = 'Deprecated, not evaluated';
                break;
        }

        mechTrace.matched = matched;

        if (matched) {
            const qualResult = {
                '+': 'pass',
                '-': 'fail',
                '~': 'softfail',
                '?': 'neutral'
            }[mech.qualifier] || 'neutral';

            domainTrace.matched = mech.raw;
            trace.matchPath.push({ domain, mechanism: mech.raw, result: qualResult });

            log('success', `SPF matched: ${mech.raw} -> ${qualResult}`);
            return {
                result: qualResult,
                mechanism: mech.raw,
                lookups: lookupCount.count,
                record: spfResult.record,
                trace
            };
        }
    }

    log('info', 'SPF: No mechanism matched, defaulting to neutral');
    return { result: 'neutral', reason: 'No mechanism matched', lookups: lookupCount.count, record: spfResult.record, trace };
}

// ============================================================================
// DMARC
// ============================================================================

async function fetchDmarcRecord(domain) {
    const dmarcDomain = `_dmarc.${domain}`;
    log('info', `DMARC lookup: ${dmarcDomain}`);
    try {
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(dmarcDomain)}&type=TXT`, {
            headers: { Accept: 'application/dns-json' }
        });
        const data = await res.json();
        if (data.Answer) {
            for (const a of data.Answer) {
                if (a.type === 16) {
                    const record = cleanDnsRecord(a.data);
                    if (record.startsWith('v=DMARC1')) {
                        log('success', `DMARC found: ${record.slice(0, 80)}...`);
                        return { ok: true, record, domain, dmarcDomain };
                    }
                }
            }
        }
        log('warn', `No DMARC record found for ${domain}`);
        return { ok: false, error: 'No DMARC record found', domain, dmarcDomain };
    } catch (e) {
        log('error', `DMARC DNS error: ${e.message}`);
        return { ok: false, error: e.message, domain, dmarcDomain };
    }
}

function parseDmarcRecord(record) {
    return parseTagValuePairs(record);
}

/**
 * Check DKIM alignment for DMARC
 * @param {string} fromDomain - Domain from the From header
 * @param {string} dkimDomain - Domain from DKIM d= tag
 * @param {string} mode - Alignment mode: 'r' (relaxed) or 's' (strict)
 * @returns {{aligned: boolean, mode: string, fromDomain: string, dkimDomain: string}}
 */
function checkDkimAlignment(fromDomain, dkimDomain, mode = 'r') {
    if (!fromDomain || !dkimDomain) {
        return { aligned: false, mode, fromDomain, dkimDomain, reason: 'Missing domain' };
    }

    const from = fromDomain.toLowerCase();
    const dkim = dkimDomain.toLowerCase();

    if (mode === 's') {
        // Strict: exact match required
        const aligned = from === dkim;
        return { aligned, mode: 'strict', fromDomain: from, dkimDomain: dkim };
    } else {
        // Relaxed: organizational domain match (same root domain)
        const fromOrg = getOrganizationalDomain(from);
        const dkimOrg = getOrganizationalDomain(dkim);
        const aligned = fromOrg === dkimOrg;
        return { aligned, mode: 'relaxed', fromDomain: from, dkimDomain: dkim, fromOrg, dkimOrg };
    }
}

/**
 * Check SPF alignment for DMARC
 * @param {string} fromDomain - Domain from the From header
 * @param {string} mailFromDomain - Domain from Return-Path/envelope sender
 * @param {string} mode - Alignment mode: 'r' (relaxed) or 's' (strict)
 * @returns {{aligned: boolean, mode: string, fromDomain: string, mailFromDomain: string}}
 */
function checkSpfAlignment(fromDomain, mailFromDomain, mode = 'r') {
    if (!fromDomain || !mailFromDomain) {
        return { aligned: false, mode, fromDomain, mailFromDomain, reason: 'Missing domain' };
    }

    const from = fromDomain.toLowerCase();
    const mailFrom = mailFromDomain.toLowerCase();

    if (mode === 's') {
        // Strict: exact match required
        const aligned = from === mailFrom;
        return { aligned, mode: 'strict', fromDomain: from, mailFromDomain: mailFrom };
    } else {
        // Relaxed: organizational domain match
        const fromOrg = getOrganizationalDomain(from);
        const mailFromOrg = getOrganizationalDomain(mailFrom);
        const aligned = fromOrg === mailFromOrg;
        return { aligned, mode: 'relaxed', fromDomain: from, mailFromDomain: mailFrom, fromOrg, mailFromOrg };
    }
}

/**
 * Get the organizational domain (registrable domain) from a hostname
 * This is a simplified implementation - production would use Public Suffix List
 * @param {string} domain - Full domain name
 * @returns {string} Organizational domain
 */
function getOrganizationalDomain(domain) {
    const parts = domain.split('.');
    if (parts.length <= 2) return domain;

    // Handle common multi-part TLDs
    const multiPartTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.za', 'org.uk', 'net.au'];
    const lastTwo = parts.slice(-2).join('.');

    if (multiPartTlds.includes(lastTwo)) {
        return parts.slice(-3).join('.');
    }

    return parts.slice(-2).join('.');
}

/**
 * Evaluate DMARC policy based on DKIM and SPF results
 * @param {Object} params - Evaluation parameters
 * @returns {Object} DMARC evaluation result
 */
function evaluateDmarc(params) {
    const { fromDomain, dkimResults, spfResult, dmarcRecord } = params;

    if (!dmarcRecord || !dmarcRecord.ok) {
        return { result: 'none', reason: 'No DMARC record found' };
    }

    const tags = parseDmarcRecord(dmarcRecord.record);
    const adkim = tags.adkim || 'r';
    const aspf = tags.aspf || 'r';
    const policy = tags.p || 'none';

    // Check DKIM alignment
    let dkimAligned = false;
    const dkimAlignments = [];
    for (const dkim of (dkimResults || [])) {
        if (dkim.status === 'valid') {
            const alignment = checkDkimAlignment(fromDomain, dkim.domain, adkim);
            dkimAlignments.push(alignment);
            if (alignment.aligned) {
                dkimAligned = true;
            }
        }
    }

    // Check SPF alignment
    const spfAligned = spfResult?.result === 'pass' &&
        checkSpfAlignment(fromDomain, spfResult.domain, aspf).aligned;

    // DMARC passes if either DKIM or SPF is aligned
    const pass = dkimAligned || spfAligned;

    return {
        result: pass ? 'pass' : 'fail',
        policy,
        dkimAligned,
        spfAligned,
        dkimAlignments,
        adkim,
        aspf,
        reason: pass
            ? `${dkimAligned ? 'DKIM' : ''}${dkimAligned && spfAligned ? ' and ' : ''}${spfAligned ? 'SPF' : ''} aligned`
            : 'Neither DKIM nor SPF aligned with From domain'
    };
}

// ============================================================================
// BIMI (Brand Indicators for Message Identification)
// ============================================================================

/**
 * Fetch BIMI record for a domain
 * @param {string} domain - Domain to lookup
 * @returns {Promise<{ok: boolean, record?: string, l?: string, a?: string, error?: string}>}
 */
async function fetchBimiRecord(domain) {
    const bimiDomain = `default._bimi.${domain}`;
    log('info', `BIMI lookup: ${bimiDomain}`);

    try {
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(bimiDomain)}&type=TXT`, {
            headers: { Accept: 'application/dns-json' }
        });
        const data = await res.json();
        if (data.Answer) {
            for (const a of data.Answer) {
                if (a.type === 16) {
                    const record = cleanDnsRecord(a.data);
                    if (record.startsWith('v=BIMI1')) {
                        log('success', `BIMI found: ${record.slice(0, 80)}...`);
                        const tags = parseTagValuePairs(record);
                        return { ok: true, record, domain, l: tags.l, a: tags.a };
                    }
                }
            }
        }
        log('info', `No BIMI record found for ${domain}`);
        return { ok: false, error: 'No BIMI record found', domain };
    } catch (e) {
        log('error', `BIMI DNS error: ${e.message}`);
        return { ok: false, error: e.message, domain };
    }
}

/**
 * Render BIMI section
 * @param {Object} bimiResult - BIMI lookup result
 * @returns {string} HTML string
 */
function renderBimi(bimiResult) {
    if (!bimiResult) return '';

    const dnsCmd = `dig TXT default._bimi.${bimiResult.domain}`;

    if (!bimiResult.ok) {
        return `<div class="bimi-card notfound">
            <div class="sig-header" onclick="toggleCard(this)">
                <div class="sig-title">
                    <span class="sig-num">\uD83C\uDFF7\uFE0F</span>
                    <span class="sig-domain">BIMI (Brand Logo)</span>
                    <span class="badge" style="background:rgba(139,148,158,0.15);color:var(--text-secondary)">\u2212 NONE</span>
                </div>
                <span class="expand-icon">\u25BC</span>
            </div>
            <div class="sig-content"><div class="sig-body">
                <div class="info-msg">No BIMI record found for ${esc(bimiResult.domain)}</div>
                <div class="sig-section">
                    <div class="sig-section-title">\uD83C\uDF10 DNS Lookup</div>
                    <div class="dns-cmd">
                        <code>${esc(dnsCmd)}</code>
                        <button class="copy-btn" style="opacity:1" onclick="event.stopPropagation();copy(this,'${esc(dnsCmd)}')">&#x29C9;</button>
                    </div>
                </div>
            </div></div>
        </div>`;
    }

    const logoUrl = bimiResult.l || '';
    const vmcUrl = bimiResult.a || '';

    return `<div class="bimi-card pass expanded">
        <div class="sig-header" onclick="toggleCard(this)">
            <div class="sig-title">
                <span class="sig-num">\uD83C\uDFF7\uFE0F</span>
                <span class="sig-domain">BIMI (Brand Logo)</span>
                <span class="badge" style="background:rgba(0,255,136,0.15);color:var(--success)">\u2713 FOUND</span>
            </div>
            <span class="expand-icon">\u25BC</span>
        </div>
        <div class="sig-content"><div class="sig-body">
            <div class="sig-section">
                <div class="sig-section-title">\uD83D\uDCCA BIMI Details</div>
                <div class="details">
                    <div class="detail-row"><span class="detail-label">Logo URL</span><span class="detail-value" style="word-break:break-all">${logoUrl ? `<a href="${esc(logoUrl)}" target="_blank" style="color:var(--accent)">${esc(logoUrl)}</a>` : '<span style="color:var(--text-dim)">Not specified</span>'}</span></div>
                    <div class="detail-row"><span class="detail-label">VMC (Certificate)</span><span class="detail-value" style="word-break:break-all">${vmcUrl ? `<a href="${esc(vmcUrl)}" target="_blank" style="color:var(--accent)">${esc(vmcUrl)}</a>` : '<span style="color:var(--text-dim)">Not specified</span>'}</span></div>
                </div>
            </div>
            ${logoUrl ? `<div class="sig-section">
                <div class="sig-section-title">\uD83D\uDDBC\uFE0F Logo Preview</div>
                <div class="bimi-logo-preview">
                    <img src="${esc(logoUrl)}" alt="BIMI Logo" onerror="this.parentElement.innerHTML='<span class=\\'error-msg\\'>Could not load logo</span>'" style="max-width:100px;max-height:100px;background:white;padding:8px;border-radius:8px;">
                </div>
            </div>` : ''}
            <div class="sig-section">
                <div class="sig-section-title">\uD83C\uDF10 DNS Record</div>
                <div class="dns-cmd">
                    <code>${esc(dnsCmd)}</code>
                    <button class="copy-btn" style="opacity:1" onclick="event.stopPropagation();copy(this,'${esc(dnsCmd)}')">&#x29C9;</button>
                </div>
                <div class="raw-record">${esc(bimiResult.record)}</div>
            </div>
        </div></div>
    </div>`;
}

// ============================================================================
// MTA-STS (Mail Transfer Agent Strict Transport Security)
// ============================================================================

/**
 * Fetch MTA-STS record and policy for a domain
 * @param {string} domain - Domain to lookup
 * @returns {Promise<{ok: boolean, record?: string, policy?: Object, error?: string}>}
 */
async function fetchMtaStsRecord(domain) {
    const stsDomain = `_mta-sts.${domain}`;
    log('info', `MTA-STS lookup: ${stsDomain}`);

    try {
        // First, fetch the DNS TXT record
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(stsDomain)}&type=TXT`, {
            headers: { Accept: 'application/dns-json' }
        });
        const data = await res.json();

        let stsRecord = null;
        if (data.Answer) {
            for (const a of data.Answer) {
                if (a.type === 16) {
                    const record = cleanDnsRecord(a.data);
                    if (record.startsWith('v=STSv1')) {
                        stsRecord = record;
                        log('success', `MTA-STS record found: ${record}`);
                        break;
                    }
                }
            }
        }

        if (!stsRecord) {
            log('info', `No MTA-STS record found for ${domain}`);
            return { ok: false, error: 'No MTA-STS record found', domain };
        }

        // Parse the record
        const tags = parseTagValuePairs(stsRecord);

        // Try to fetch the policy file
        let policy = null;
        try {
            const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
            log('info', `Fetching MTA-STS policy: ${policyUrl}`);
            const policyRes = await fetch(policyUrl);
            if (policyRes.ok) {
                const policyText = await policyRes.text();
                policy = parseMtaStsPolicy(policyText);
                log('success', `MTA-STS policy fetched: mode=${policy.mode}`);
            } else {
                log('warn', `Could not fetch MTA-STS policy: ${policyRes.status}`);
            }
        } catch (e) {
            log('warn', `MTA-STS policy fetch error: ${e.message}`);
        }

        return { ok: true, record: stsRecord, domain, id: tags.id, policy };
    } catch (e) {
        log('error', `MTA-STS DNS error: ${e.message}`);
        return { ok: false, error: e.message, domain };
    }
}

/**
 * Parse MTA-STS policy file
 * @param {string} policyText - Raw policy text
 * @returns {Object} Parsed policy
 */
function parseMtaStsPolicy(policyText) {
    const policy = { mode: 'none', mx: [], max_age: 0 };
    const lines = policyText.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('version:')) {
            policy.version = trimmed.split(':')[1]?.trim();
        } else if (trimmed.startsWith('mode:')) {
            policy.mode = trimmed.split(':')[1]?.trim().toLowerCase();
        } else if (trimmed.startsWith('mx:')) {
            policy.mx.push(trimmed.split(':')[1]?.trim());
        } else if (trimmed.startsWith('max_age:')) {
            policy.max_age = parseInt(trimmed.split(':')[1]?.trim(), 10) || 0;
        }
    }

    return policy;
}

/**
 * Render MTA-STS section
 * @param {Object} stsResult - MTA-STS lookup result
 * @returns {string} HTML string
 */
function renderMtaSts(stsResult) {
    if (!stsResult) return '';

    const dnsCmd = `dig TXT _mta-sts.${stsResult.domain}`;

    if (!stsResult.ok) {
        return `<div class="mta-sts-card notfound">
            <div class="sig-header" onclick="toggleCard(this)">
                <div class="sig-title">
                    <span class="sig-num">\uD83D\uDD12</span>
                    <span class="sig-domain">MTA-STS (TLS Policy)</span>
                    <span class="badge" style="background:rgba(139,148,158,0.15);color:var(--text-secondary)">\u2212 NONE</span>
                </div>
                <span class="expand-icon">\u25BC</span>
            </div>
            <div class="sig-content"><div class="sig-body">
                <div class="info-msg">No MTA-STS record found for ${esc(stsResult.domain)}</div>
                <div class="sig-section">
                    <div class="sig-section-title">\uD83C\uDF10 DNS Lookup</div>
                    <div class="dns-cmd">
                        <code>${esc(dnsCmd)}</code>
                        <button class="copy-btn" style="opacity:1" onclick="event.stopPropagation();copy(this,'${esc(dnsCmd)}')">&#x29C9;</button>
                    </div>
                </div>
            </div></div>
        </div>`;
    }

    const policy = stsResult.policy;
    const mode = policy?.mode || 'unknown';
    const modeInfo = MTA_STS_MODES[mode] || MTA_STS_MODES.none;

    let badgeStyle, badgeText;
    if (mode === 'enforce') {
        badgeStyle = 'background:rgba(0,255,136,0.15);color:var(--success)';
        badgeText = '\u2713 ENFORCE';
    } else if (mode === 'testing') {
        badgeStyle = 'background:rgba(255,179,71,0.15);color:var(--warning)';
        badgeText = '~ TESTING';
    } else {
        badgeStyle = 'background:rgba(139,148,158,0.15);color:var(--text-secondary)';
        badgeText = '? ' + mode.toUpperCase();
    }

    const maxAgeDays = policy?.max_age ? Math.round(policy.max_age / 86400) : 0;

    return `<div class="mta-sts-card ${mode} expanded">
        <div class="sig-header" onclick="toggleCard(this)">
            <div class="sig-title">
                <span class="sig-num">\uD83D\uDD12</span>
                <span class="sig-domain">MTA-STS (TLS Policy)</span>
                <span class="badge" style="${badgeStyle}">${badgeText}</span>
            </div>
            <span class="expand-icon">\u25BC</span>
        </div>
        <div class="sig-content"><div class="sig-body">
            <div class="sig-section">
                <div class="sig-section-title">\uD83D\uDCCA Policy Details</div>
                <div class="details">
                    <div class="detail-row"><span class="detail-label">Mode</span><span class="detail-value ${modeInfo.color}">${modeInfo.icon} ${modeInfo.name}</span></div>
                    <div class="detail-row"><span class="detail-label">Description</span><span class="detail-value">${esc(modeInfo.desc)}</span></div>
                    ${policy?.max_age ? `<div class="detail-row"><span class="detail-label">Max Age</span><span class="detail-value">${policy.max_age}s (${maxAgeDays} days)</span></div>` : ''}
                    ${stsResult.id ? `<div class="detail-row"><span class="detail-label">Policy ID</span><span class="detail-value">${esc(stsResult.id)}</span></div>` : ''}
                </div>
            </div>
            ${policy?.mx?.length ? `<div class="sig-section">
                <div class="sig-section-title">\uD83D\uDCE7 Authorized MX Hosts</div>
                <div class="details">
                    ${policy.mx.map(mx => `<div class="detail-row"><span class="detail-label">MX</span><span class="detail-value" style="color:var(--accent)">${esc(mx)}</span></div>`).join('')}
                </div>
            </div>` : ''}
            <div class="sig-section">
                <div class="sig-section-title">\uD83C\uDF10 DNS Record</div>
                <div class="dns-cmd">
                    <code>${esc(dnsCmd)}</code>
                    <button class="copy-btn" style="opacity:1" onclick="event.stopPropagation();copy(this,'${esc(dnsCmd)}')">&#x29C9;</button>
                </div>
                <div class="raw-record">${esc(stsResult.record)}</div>
            </div>
        </div></div>
    </div>`;
}

// ============================================================================
// ARC (Authenticated Received Chain)
// ============================================================================

function parseArcHeaders(headers) {
    const arcSets = {};

    const arcSeals = headers.filter(h => h.name.toLowerCase() === 'arc-seal');
    const arcMsgs = headers.filter(h => h.name.toLowerCase() === 'arc-message-signature');
    const arcAuths = headers.filter(h => h.name.toLowerCase() === 'arc-authentication-results');

    for (const seal of arcSeals) {
        const tags = parseArcTags(seal.value);
        const instance = parseInt(tags.i, 10);
        if (!isNaN(instance)) {
            if (!arcSets[instance]) arcSets[instance] = {};
            arcSets[instance].seal = { raw: seal.value, tags };
        }
    }

    for (const msg of arcMsgs) {
        const tags = parseArcTags(msg.value);
        const instance = parseInt(tags.i, 10);
        if (!isNaN(instance)) {
            if (!arcSets[instance]) arcSets[instance] = {};
            arcSets[instance].message = { raw: msg.value, tags };
        }
    }

    for (const auth of arcAuths) {
        const parsed = parseArcAuthResults(auth.value);
        const instance = parsed.instance;
        if (instance) {
            if (!arcSets[instance]) arcSets[instance] = {};
            arcSets[instance].auth = { raw: auth.value, parsed };
        }
    }

    const sets = Object.entries(arcSets)
        .map(([i, set]) => ({ instance: parseInt(i, 10), ...set }))
        .sort((a, b) => a.instance - b.instance);

    return sets;
}

function parseArcTags(value) {
    const unfolded = value.replace(/\r?\n[ \t]+/g, ' ');
    return parseTagValuePairs(unfolded, ['b', 'bh']);
}

function parseArcAuthResults(value) {
    const unfolded = value.replace(/\r?\n[ \t]+/g, ' ');
    const result = { results: [] };

    const instanceMatch = unfolded.match(/^\s*i\s*=\s*(\d+)\s*;/);
    if (instanceMatch) {
        result.instance = parseInt(instanceMatch[1], 10);
    }

    const authservMatch = unfolded.match(/;\s*([^;]+?)\s*;/);
    if (authservMatch) {
        result.authserv = authservMatch[1].trim();
    }

    const dkimMatch = unfolded.match(/dkim\s*=\s*(\w+)/i);
    if (dkimMatch) result.results.push({ method: 'dkim', result: dkimMatch[1].toLowerCase() });

    const spfMatch = unfolded.match(/spf\s*=\s*(\w+)/i);
    if (spfMatch) result.results.push({ method: 'spf', result: spfMatch[1].toLowerCase() });

    const dmarcMatch = unfolded.match(/dmarc\s*=\s*(\w+)/i);
    if (dmarcMatch) result.results.push({ method: 'dmarc', result: dmarcMatch[1].toLowerCase() });

    const arcMatch = unfolded.match(/arc\s*=\s*(\w+)/i);
    if (arcMatch) result.results.push({ method: 'arc', result: arcMatch[1].toLowerCase() });

    return result;
}

// ============================================================================
// Cryptographic Functions
// ============================================================================

function b64ToBuffer(b64) {
    let cleaned = b64.replace(/\s+/g, '');
    const invalidMatch = cleaned.match(/[^A-Za-z0-9+/=]/);
    if (invalidMatch) {
        log('warn', `Base64 contains invalid character: '${invalidMatch[0]}' (charCode ${invalidMatch[0].charCodeAt(0)})`);
        cleaned = cleaned.replace(/[^A-Za-z0-9+/=]/g, '');
    }
    const bin = atob(cleaned);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
}

async function importKey(b64, algorithm = 'rsa-sha256') {
    const keyData = b64ToBuffer(b64);
    const hashAlg = algorithm === 'rsa-sha1' ? 'SHA-1' : 'SHA-256';
    try {
        return await crypto.subtle.importKey('spki', keyData, { name: 'RSASSA-PKCS1-v1_5', hash: hashAlg }, false, ['verify']);
    } catch {
        const spki = convertPkcs1ToSpki(new Uint8Array(keyData));
        return await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: hashAlg }, false, ['verify']);
    }
}

function convertPkcs1ToSpki(pkcs1) {
    const oid = new Uint8Array([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
    const bitStr = new Uint8Array(pkcs1.length + 1);
    bitStr[0] = 0x00;
    bitStr.set(pkcs1, 1);
    const bsHeader = asn1Len(0x03, bitStr.length);
    const innerLen = oid.length + bsHeader.length + bitStr.length;
    const seqHeader = asn1Len(0x30, innerLen);
    const spki = new Uint8Array(seqHeader.length + oid.length + bsHeader.length + bitStr.length);
    let o = 0;
    spki.set(seqHeader, o); o += seqHeader.length;
    spki.set(oid, o); o += oid.length;
    spki.set(bsHeader, o); o += bsHeader.length;
    spki.set(bitStr, o);
    return spki.buffer;
}

function asn1Len(tag, len) {
    if (len < 128) return new Uint8Array([tag, len]);
    if (len < 256) return new Uint8Array([tag, 0x81, len]);
    return new Uint8Array([tag, 0x82, (len >> 8) & 0xff, len & 0xff]);
}

async function computeBodyHash(body, canon, limit, algorithm = 'rsa-sha256') {
    let c = canon === 'relaxed' ? canonBodyRelaxed(body) : canonBodySimple(body);
    if (limit !== undefined && limit !== '') {
        const n = parseInt(limit, 10);
        if (!isNaN(n) && n >= 0) {
            const bytes = new TextEncoder().encode(c);
            if (bytes.length > n) c = new TextDecoder().decode(bytes.slice(0, n));
        }
    }
    const hashAlg = algorithm === 'rsa-sha1' ? 'SHA-1' : 'SHA-256';
    const hash = await crypto.subtle.digest(hashAlg, new TextEncoder().encode(c));
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

function buildSigningInput(headers, tags, rawDkim, headerCanon) {
    const signed = tags.h.split(':').map(h => h.trim().toLowerCase());
    const headerMap = new Map();
    for (const hdr of headers) {
        const ln = hdr.name.toLowerCase();
        if (!headerMap.has(ln)) headerMap.set(ln, []);
        headerMap.get(ln).push(hdr);
    }
    const lines = [];
    for (const h of signed) {
        const stack = headerMap.get(h);
        if (stack?.length) {
            const hdr = stack.pop();
            if (headerCanon === 'relaxed') {
                lines.push(canonHeaderRelaxed(hdr.name, hdr.value));
            } else {
                lines.push(hdr.raw);
            }
        }
    }
    if (headerCanon === 'relaxed') {
        let dkimUnfolded = rawDkim.replace(/\r?\n[ \t]+/g, ' ');
        dkimUnfolded = dkimUnfolded.replace(/(;\s*b\s*=\s*)[A-Za-z0-9+/=\s]+/i, '$1');
        lines.push(canonHeaderRelaxed('DKIM-Signature', dkimUnfolded.replace(/^DKIM-Signature:\s*/i, '')));
    } else {
        let dkimSimple = rawDkim.replace(/(;\s*b\s*=\s*)[A-Za-z0-9+/=\r\n\t ]+/i, '$1');
        lines.push(dkimSimple);
    }
    return lines.join('\r\n');
}

async function verifySig(input, sig, key) {
    try {
        return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64ToBuffer(sig), new TextEncoder().encode(input));
    } catch { return false; }
}

// ============================================================================
// DKIM Verification
// ============================================================================

async function verifyDkim(sig, headers, body) {
    const tags = sig.parsed;
    const result = { domain: tags.d || '?', selector: tags.s || '?', tags, raw: sig.raw, status: 'invalid', errors: [], warnings: [], details: {} };

    const required = ['v', 'a', 'b', 'bh', 'd', 'h', 's'];
    for (const t of required) if (!tags[t]) result.errors.push(`Missing tag: ${t}`);
    if (result.errors.length) return result;
    if (tags.v !== '1') { result.errors.push(`Unsupported version: ${tags.v}`); return result; }
    if (tags.a !== 'rsa-sha256' && tags.a !== 'rsa-sha1') { result.errors.push(`Unsupported algorithm: ${tags.a}`); return result; }

    if (tags.l !== undefined && tags.l !== '') {
        const bodyLen = parseInt(tags.l, 10);
        result.warnings.push({
            type: 'body_length_limit',
            message: `Body length limit (l=${bodyLen}) is set`,
            detail: 'Only the first ' + bodyLen + ' bytes of the body are signed. Content after this limit is NOT authenticated and could be malicious.'
        });
        log('warn', `Security: DKIM signature uses l=${bodyLen} tag - body content after ${bodyLen} bytes is unsigned`);
    }

    if (tags.x !== undefined && tags.x !== '') {
        const expireTime = parseInt(tags.x, 10);
        const now = Math.floor(Date.now() / 1000);
        result.details.expireTime = expireTime;
        result.details.expireDate = new Date(expireTime * 1000).toISOString();

        if (expireTime < now) {
            const expiredAgo = now - expireTime;
            const expiredDays = Math.floor(expiredAgo / 86400);
            const expiredHours = Math.floor((expiredAgo % 86400) / 3600);
            let expiredStr = '';
            if (expiredDays > 0) expiredStr = `${expiredDays} day${expiredDays > 1 ? 's' : ''}`;
            else if (expiredHours > 0) expiredStr = `${expiredHours} hour${expiredHours > 1 ? 's' : ''}`;
            else expiredStr = `${expiredAgo} second${expiredAgo > 1 ? 's' : ''}`;

            result.warnings.push({
                type: 'signature_expired',
                message: `Signature expired ${expiredStr} ago`,
                detail: `This signature expired on ${new Date(expireTime * 1000).toLocaleString()}. Expired signatures may still technically verify but should be treated with caution.`
            });
            log('warn', `DKIM signature expired: ${new Date(expireTime * 1000).toISOString()}`);
        } else {
            const expiresIn = expireTime - now;
            const expiresDays = Math.floor(expiresIn / 86400);
            if (expiresDays < 7) {
                result.warnings.push({
                    type: 'signature_expiring_soon',
                    message: `Signature expires in ${expiresDays} day${expiresDays !== 1 ? 's' : ''}`,
                    detail: `This signature will expire on ${new Date(expireTime * 1000).toLocaleString()}.`
                });
            }
        }
    }

    if (tags.t !== undefined && tags.t !== '') {
        result.details.signTime = parseInt(tags.t, 10);
        result.details.signDate = new Date(result.details.signTime * 1000).toISOString();
    }

    const [hCanon, bCanon] = (tags.c || 'simple/simple').split('/');
    result.details.headerCanon = hCanon || 'simple';
    result.details.bodyCanon = bCanon || hCanon || 'simple';

    const dns = await fetchDns(tags.d, tags.s);
    result.dns = dns;
    if (!dns.ok) { result.errors.push(`DNS failed: ${dns.error}`); return result; }

    result.dnsTags = parseDnsTags(dns.record);
    if (!result.dnsTags.p) { result.errors.push('No public key in DNS'); return result; }

    const computedBh = await computeBodyHash(body, result.details.bodyCanon, tags.l, tags.a);
    result.details.computedBh = computedBh;
    result.details.declaredBh = tags.bh;
    result.details.bhMatch = computedBh === tags.bh;
    if (!result.details.bhMatch) result.errors.push('Body hash mismatch');

    try {
        const key = await importKey(result.dnsTags.p, tags.a);
        const input = buildSigningInput(headers, tags, sig.raw, result.details.headerCanon);
        result.details.sigValid = await verifySig(input, tags.b, key);
        if (!result.details.sigValid) result.errors.push('Signature verification failed');
    } catch (e) {
        result.errors.push(`Crypto error: ${e.message}`);
        result.details.sigValid = false;
    }

    result.status = result.details.bhMatch && result.details.sigValid ? 'valid' : 'invalid';
    log(result.status === 'valid' ? 'success' : 'error', `${tags.d}: ${result.status.toUpperCase()}`);
    return result;
}

// ============================================================================
// Rendering Functions
// ============================================================================

function renderTag(name, value, info, classes = '') {
    const short = value.length > 25 ? value.slice(0, 25) + '\u2026' : value;
    return `<div class="tag ${classes}" data-tag="${esc(name)}" data-tag-name="${esc(info.name)}" data-tag-desc="${esc(info.desc)}" data-tag-value="${esc(value)}">
        <span class="dot"></span>
        <span class="tag-name">${esc(name)}</span>
        <span class="tag-value">${esc(short)}</span>
        <button class="copy-btn" onclick="event.stopPropagation();copy(this,\`${esc(value.replace(/`/g, ''))}\`)">&#x29C9;</button>
    </div>`;
}

function renderHeaders(headers, signed) {
    const tags = headers.map(hdr => {
        const isSigned = signed.has(hdr.name.toLowerCase());
        const displayValue = hdr.value.replace(/\r?\n[ \t]+/g, ' ').trim();
        return renderTag(hdr.name, displayValue, { name: hdr.name, desc: isSigned ? 'Included in DKIM signature' : 'Not signed' }, `header ${isSigned ? 'signed' : ''}`);
    }).join('');
    return `<div class="headers-section">
        <div class="section-header">\uD83D\uDCE8 Email Headers</div>
        <div class="tags-grid">${tags}</div>
        <div class="legend">
            <div class="legend-item"><span class="dot" style="background:linear-gradient(135deg,var(--success),var(--accent));width:6px;height:6px;border-radius:50%"></span> Signed</div>
            <div class="legend-item"><span class="dot" style="background:var(--text-dim);width:6px;height:6px;border-radius:50%"></span> Not signed</div>
        </div>
    </div>`;
}

function renderSig(r, i) {
    const errHtml = r.errors.map(e => `<div class="error-msg">${esc(e)}</div>`).join('');
    const warnHtml = (r.warnings || []).map(w => `<div class="warning-msg">\u26A0\uFE0F <strong>Security Warning:</strong> ${esc(w.message)}<span class="suggestion">${esc(w.detail)}</span></div>`).join('');
    const dkimTags = Object.entries(r.tags).map(([k, v]) => renderTag(k, v, DKIM_TAGS[k] || { name: k.toUpperCase(), desc: 'DKIM tag' }, 'signed')).join('');
    const dnsTags = r.dnsTags ? Object.entries(r.dnsTags).map(([k, v]) => renderTag(k, v, DNS_TAGS[k] || { name: k.toUpperCase(), desc: 'DNS tag' }, 'dns')).join('') : '';
    const dnsCmd = `dig TXT ${r.dns?.name || r.selector + '._domainkey.' + r.domain}`;
    const hasWarnings = r.warnings && r.warnings.length > 0;

    return `<div class="sig-card ${r.status} expanded">
        <div class="sig-header" onclick="toggleCard(this)">
            <div class="sig-title">
                <span class="sig-dkim">\uD83D\uDCE7 DKIM Signature #</span>
                <span class="sig-num">${i}</span>
                <span class="sig-domain">${esc(r.domain)}</span>
                <span class="badge ${r.status}">${r.status === 'valid' ? '\u2713 PASS' : '\u2717 FAIL'}</span>
                ${hasWarnings ? '<span class="badge" style="background:rgba(255,179,71,0.15);color:var(--warning);margin-left:0.5rem">\u26A0\uFE0F WARNING</span>' : ''}
            </div>
            <span class="expand-icon">\u25BC</span>
        </div>
        <div class="sig-content"><div class="sig-body">
            ${errHtml}
            ${warnHtml}
            <div class="sig-section">
                <div class="sig-section-title">\uD83C\uDFF7\uFE0F DKIM Tags</div>
                <div class="tags-grid">${dkimTags}</div>
            </div>
            <div class="sig-section">
                <div class="sig-section-title">\uD83C\uDF10 DNS Record</div>
                <div class="dns-cmd">
                    <code>${esc(dnsCmd)}</code>
                    <button class="copy-btn" style="opacity:1" onclick="event.stopPropagation();copy(this,'${esc(dnsCmd)}')">&#x29C9;</button>
                </div>
                ${r.dns?.ok ? `<div class="tags-grid">${dnsTags}</div><div class="dns-raw">${esc(r.dns.record)}</div>` : `<div class="error-msg">${esc(r.dns?.error || 'DNS lookup failed')}</div>`}
            </div>
            <div class="sig-section">
                <div class="sig-section-title">\uD83D\uDD10 Verification</div>
                <div class="details">
                    <div class="detail-row"><span class="detail-label">Algorithm</span><span class="detail-value">${esc(r.tags.a || 'N/A')}</span></div>
                    <div class="detail-row"><span class="detail-label">Canonicalization</span><span class="detail-value">${r.details.headerCanon}/${r.details.bodyCanon}</span></div>
                    <div class="detail-row"><span class="detail-label">Body Hash</span><span class="detail-value ${r.details.bhMatch ? 'success' : 'error'}">${r.details.bhMatch ? '\u2713 Match' : '\u2717 Mismatch'}</span></div>
                    <div class="detail-row"><span class="detail-label">Signature</span><span class="detail-value ${r.details.sigValid ? 'success' : 'error'}">${r.details.sigValid ? '\u2713 Valid' : '\u2717 Invalid'}</span></div>
                    ${r.details.signDate ? `<div class="detail-row"><span class="detail-label">Signed</span><span class="detail-value">${new Date(r.details.signTime * 1000).toLocaleString()}</span></div>` : ''}
                    ${r.details.expireDate ? `<div class="detail-row"><span class="detail-label">Expires</span><span class="detail-value ${r.details.expireTime < Math.floor(Date.now() / 1000) ? 'error' : ''}">${new Date(r.details.expireTime * 1000).toLocaleString()}${r.details.expireTime < Math.floor(Date.now() / 1000) ? ' (EXPIRED)' : ''}</span></div>` : ''}
                </div>
            </div>
        </div></div>
    </div>`;
}

function renderDebug() {
    return logs.map(l => `<div class="log-entry"><span class="log-time">${l.time}</span><span class="log-type ${l.type}">${l.type.toUpperCase()}</span><span class="log-msg">${esc(l.msg)}</span></div>`).join('');
}

function renderSpfMechanism(mech) {
    const qualInfo = SPF_QUALIFIERS[mech.qualifier] || { name: 'Unknown', desc: 'Unknown qualifier', color: 'neutral' };
    const mechInfo = SPF_MECHANISMS[mech.mechanism] || { name: mech.mechanism.toUpperCase(), desc: 'SPF mechanism' };
    const displayValue = mech.value || (mech.mechanism === 'all' ? '' : '(domain)');
    const tagClass = `spf-${qualInfo.color === 'success' ? 'pass' : qualInfo.color === 'error' ? 'fail' : qualInfo.color === 'warning' ? 'softfail' : 'neutral'}`;

    return `<div class="tag ${tagClass}" data-tag="${esc(mech.raw)}" data-tag-name="${esc(qualInfo.name + ' ' + mechInfo.name)}" data-tag-desc="${esc(mechInfo.desc + '. Qualifier: ' + qualInfo.desc)}" data-tag-value="${esc(mech.raw)}">
        <span class="dot"></span>
        <span class="tag-name">${esc(mech.qualifier)}${esc(mech.mechanism)}</span>
        ${displayValue ? `<span class="tag-value">${esc(displayValue)}</span>` : ''}
        <button class="copy-btn" onclick="event.stopPropagation();copy(this,\`${esc(mech.raw)}\`)">&#x29C9;</button>
    </div>`;
}

function getDefaultPolicy(mechanisms) {
    const allMech = mechanisms.find(m => m.mechanism === 'all');
    if (!allMech) return 'None (default: neutral)';
    const qual = SPF_QUALIFIERS[allMech.qualifier];
    return qual ? qual.name : 'Unknown';
}

function getDefaultPolicyClass(mechanisms) {
    const allMech = mechanisms.find(m => m.mechanism === 'all');
    if (!allMech) return 'neutral';
    const qual = SPF_QUALIFIERS[allMech.qualifier];
    return qual ? qual.color : 'neutral';
}

function renderSpfEvaluation(evalResult) {
    if (!evalResult) return '';

    const resultInfo = SPF_RESULTS[evalResult.result] || SPF_RESULTS.none;
    const dnsCmd = `dig TXT ${evalResult.domain}`;

    const { badgeStyle, badgeText } = getBadgeForResult(evalResult.result);

    let content = '';

    content += `
        <div class="sig-section">
            <div class="sig-section-title">\uD83D\uDCCA SPF Evaluation Result</div>
            ${renderSecurityHint('spf', evalResult.result)}
            <div class="details">
                <div class="detail-row"><span class="detail-label">Result</span><span class="detail-value ${resultInfo.color}">${resultInfo.icon} ${resultInfo.name}</span></div>
                <div class="detail-row"><span class="detail-label">Description</span><span class="detail-value">${esc(resultInfo.desc)}</span></div>
                ${evalResult.senderIP ? `<div class="detail-row"><span class="detail-label">Sender IP</span><span class="detail-value">${esc(evalResult.senderIP.ip)} (IPv${evalResult.senderIP.version})</span></div>` : ''}
                ${evalResult.mechanism ? `<div class="detail-row"><span class="detail-label">Matched Mechanism</span><span class="detail-value" style="color:var(--accent)">${esc(evalResult.mechanism)}</span></div>` : ''}
                ${evalResult.reason ? `<div class="detail-row"><span class="detail-label">Reason</span><span class="detail-value">${esc(evalResult.reason)}</span></div>` : ''}
                ${evalResult.lookups !== undefined ? `<div class="detail-row"><span class="detail-label">DNS Lookups</span><span class="detail-value">${evalResult.lookups}/10</span></div>` : ''}
            </div>
        </div>
    `;

    if (evalResult.record) {
        const mechanisms = parseSpfRecord(evalResult.record);
        const mechTags = mechanisms.map(m => renderSpfMechanism(m)).join('');

        content += `
            <div class="sig-section">
                <div class="sig-section-title">\uD83D\uDEE1\uFE0F SPF Mechanisms</div>
                <div class="tags-grid">${mechTags}</div>
            </div>
            <div class="sig-section">
                <div class="sig-section-title">\uD83C\uDF10 DNS Record</div>
                <div class="dns-cmd">
                    <code>${esc(dnsCmd)}</code>
                    <button class="copy-btn" style="opacity:1" onclick="event.stopPropagation();copy(this,'${esc(dnsCmd)}')">&#x29C9;</button>
                </div>
                <div class="dns-raw">${esc(evalResult.record)}</div>
            </div>
            <div class="sig-section">
                <div class="sig-section-title">\uD83D\uDCCB Policy Summary</div>
                <div class="details">
                    <div class="detail-row"><span class="detail-label">Domain</span><span class="detail-value">${esc(evalResult.domain)}</span></div>
                    <div class="detail-row"><span class="detail-label">Mechanisms</span><span class="detail-value">${mechanisms.length}</span></div>
                    <div class="detail-row"><span class="detail-label">Default Policy</span><span class="detail-value ${getDefaultPolicyClass(mechanisms)}">${getDefaultPolicy(mechanisms)}</span></div>
                </div>
            </div>
        `;
    }

    if (evalResult.trace && evalResult.trace.domains && evalResult.trace.domains.length > 0) {
        // Build flattened SPF visualization
        const flattenedMechanisms = [];
        for (const domainTrace of evalResult.trace.domains) {
            if (domainTrace.mechanisms) {
                for (const mech of domainTrace.mechanisms) {
                    if (mech.type === 'ip4' || mech.type === 'ip6') {
                        flattenedMechanisms.push({
                            type: mech.type,
                            value: mech.mechanism,
                            source: domainTrace.domain,
                            depth: domainTrace.depth
                        });
                    }
                }
            }
        }

        content += `
            <div class="spf-trace">
                <div class="spf-trace-title">\uD83D\uDD0D Recursive SPF Trace (${evalResult.trace.domains.length} domain${evalResult.trace.domains.length > 1 ? 's' : ''} evaluated)</div>
        `;

        // SPF Flattening Visualization
        if (flattenedMechanisms.length > 0) {
            content += `
                <div class="spf-flattened">
                    <div class="spf-flattened-header">
                        <span class="spf-flattened-title">\uD83D\uDCCB Flattened SPF (${flattenedMechanisms.length} IP mechanisms)</span>
                        <button class="copy-btn" style="opacity:1" onclick="event.stopPropagation();copyFlattenedSpf(this)">Copy Flattened</button>
                    </div>
                    <div class="spf-flattened-preview" id="spfFlattenedPreview">v=spf1 ${flattenedMechanisms.map(m => m.value).join(' ')} ~all</div>
                    <div class="spf-flattened-sources">
                        ${flattenedMechanisms.slice(0, 10).map(m => `<span class="spf-source-tag" title="From ${esc(m.source)}">${esc(m.value.split(':')[0] === 'ip4' || m.value.split(':')[0] === 'ip6' ? m.value : m.type + ':' + m.value)}</span>`).join('')}
                        ${flattenedMechanisms.length > 10 ? `<span class="spf-source-tag more">+${flattenedMechanisms.length - 10} more</span>` : ''}
                    </div>
                </div>
            `;
        }

        for (const domainTrace of evalResult.trace.domains) {
            const depthClass = `depth-${Math.min(domainTrace.depth, 3)}`;
            content += `
                <div class="spf-domain-trace ${depthClass}">
                    <div class="spf-domain-header">
                        <span class="spf-domain-name">${esc(domainTrace.domain)}</span>
                        <span class="spf-domain-depth">Depth ${domainTrace.depth}</span>
                    </div>
            `;

            if (domainTrace.record) {
                content += `<div class="spf-record-preview">${esc(domainTrace.record)}</div>`;
            }

            if (domainTrace.mechanisms && domainTrace.mechanisms.length > 0) {
                content += `<div class="spf-mechanisms-list">`;
                for (const mech of domainTrace.mechanisms) {
                    const matchClass = mech.matched ? 'matched' : 'not-matched';
                    const detailsStr = mech.details ? ` \u2192 ${mech.details}` : '';
                    content += `
                        <div class="spf-mech ${matchClass}">
                            <span class="spf-mech-indicator"></span>
                            <span class="spf-mech-text">${esc(mech.mechanism)}</span>
                            ${detailsStr ? `<span class="spf-mech-details">${esc(detailsStr)}</span>` : ''}
                        </div>
                    `;
                }
                content += `</div>`;
            }

            content += `</div>`;
        }

        if (evalResult.trace.matchPath && evalResult.trace.matchPath.length > 0) {
            content += `
                <div class="spf-match-path">
                    <div class="spf-match-path-title">\u2713 Match Path</div>
                    <div class="spf-match-path-chain">
            `;
            evalResult.trace.matchPath.forEach((item, idx) => {
                if (idx > 0) {
                    content += `<span class="spf-match-path-arrow">\u2192</span>`;
                }
                content += `<span class="spf-match-path-item">${esc(item.domain)}: ${esc(item.mechanism)}</span>`;
            });
            content += `
                    </div>
                </div>
            `;
        }

        content += `</div>`;
    }

    const cardClass = evalResult.result === 'pass' ? 'found' : (evalResult.result === 'fail' || evalResult.result === 'permerror' ? 'notfound' : '');

    return `<div class="spf-card ${cardClass} expanded">
        <div class="sig-header" onclick="toggleCard(this)">
            <div class="sig-title">
                <span class="sig-num">\uD83D\uDEE1\uFE0F</span>
                <span class="sig-domain">${esc(evalResult.domain)}</span>
                <span class="badge" style="${badgeStyle}">${badgeText}</span>
            </div>
            <span class="expand-icon">\u25BC</span>
        </div>
        <div class="sig-content"><div class="sig-body">
            ${content}
        </div></div>
    </div>`;
}

function renderDmarcTag(name, value) {
    const info = DMARC_TAGS[name] || { name: name.toUpperCase(), desc: 'DMARC tag' };
    let tagClass = '';
    if (name === 'p' || name === 'sp') {
        tagClass = `dmarc-${value.toLowerCase()}`;
    }
    const short = value.length > 30 ? value.slice(0, 30) + '\u2026' : value;
    return `<div class="tag ${tagClass}" data-tag="${esc(name)}" data-tag-name="${esc(info.name)}" data-tag-desc="${esc(info.desc)}" data-tag-value="${esc(value)}">
        <span class="dot"></span>
        <span class="tag-name">${esc(name)}</span>
        <span class="tag-value">${esc(short)}</span>
        <button class="copy-btn" onclick="event.stopPropagation();copy(this,\`${esc(value.replace(/`/g, ''))}\`)">&#x29C9;</button>
    </div>`;
}

function renderDmarc(dmarcResult) {
    if (!dmarcResult) return '';

    const dnsCmd = `dig TXT _dmarc.${dmarcResult.domain}`;

    if (!dmarcResult.ok) {
        const { badgeStyle, badgeText } = getBadgeForResult('notfound');
        return `<div class="dmarc-card notfound expanded">
            <div class="sig-header" onclick="toggleCard(this)">
                <div class="sig-title">
                    <span class="sig-num">\uD83D\uDCCB</span>
                    <span class="sig-domain">DMARC Policy</span>
                    <span class="badge" style="${badgeStyle}">${badgeText}</span>
                </div>
                <span class="expand-icon">\u25BC</span>
            </div>
            <div class="sig-content"><div class="sig-body">
                <div class="error-msg">${esc(dmarcResult.error)} for ${esc(dmarcResult.domain)}</div>
                <div class="sig-section">
                    <div class="sig-section-title">\uD83C\uDF10 DNS Lookup</div>
                    <div class="dns-cmd">
                        <code>${esc(dnsCmd)}</code>
                        <button class="copy-btn" style="opacity:1" onclick="event.stopPropagation();copy(this,'${esc(dnsCmd)}')">&#x29C9;</button>
                    </div>
                </div>
            </div></div>
        </div>`;
    }

    const tags = parseDmarcRecord(dmarcResult.record);
    const policy = tags.p?.toLowerCase() || 'none';
    const policyInfo = DMARC_POLICIES[policy] || DMARC_POLICIES.none;

    const { badgeStyle, badgeText } = getBadgeForResult(policy);

    const dmarcTags = Object.entries(tags).map(([k, v]) => renderDmarcTag(k, v)).join('');

    return `<div class="dmarc-card ${policy} expanded">
        <div class="sig-header" onclick="toggleCard(this)">
            <div class="sig-title">
                <span class="sig-num">\uD83D\uDCCB</span>
                <span class="sig-domain">DMARC Policy</span>
                <span class="badge" style="${badgeStyle}">${badgeText}</span>
            </div>
            <span class="expand-icon">\u25BC</span>
        </div>
        <div class="sig-content"><div class="sig-body">
            <div class="sig-section">
                <div class="sig-section-title">\uD83D\uDCCA Policy Details</div>
                <div class="details">
                    <div class="detail-row"><span class="detail-label">Policy</span><span class="detail-value ${policyInfo.color}">${policyInfo.icon} ${policyInfo.name}</span></div>
                    <div class="detail-row"><span class="detail-label">Description</span><span class="detail-value">${esc(policyInfo.desc)}</span></div>
                    ${tags.sp ? `<div class="detail-row"><span class="detail-label">Subdomain Policy</span><span class="detail-value">${esc(tags.sp)}</span></div>` : ''}
                    <div class="detail-row"><span class="detail-label">DKIM Alignment</span><span class="detail-value">${tags.adkim === 's' ? 'Strict' : 'Relaxed'}</span></div>
                    <div class="detail-row"><span class="detail-label">SPF Alignment</span><span class="detail-value">${tags.aspf === 's' ? 'Strict' : 'Relaxed'}</span></div>
                    ${tags.pct ? `<div class="detail-row"><span class="detail-label">Percentage Applied</span><span class="detail-value">${esc(tags.pct)}%</span></div>` : ''}
                </div>
            </div>
            <div class="sig-section">
                <div class="sig-section-title">\uD83C\uDFF7\uFE0F DMARC Tags</div>
                <div class="tags-grid">${dmarcTags}</div>
            </div>
            ${tags.rua || tags.ruf ? `<div class="sig-section">
                <div class="sig-section-title">\uD83D\uDCEC Reporting</div>
                <div class="details">
                    ${tags.rua ? `<div class="detail-row"><span class="detail-label">Aggregate Reports</span><span class="detail-value" style="word-break:break-all">${esc(tags.rua)}</span></div>` : ''}
                    ${tags.ruf ? `<div class="detail-row"><span class="detail-label">Forensic Reports</span><span class="detail-value" style="word-break:break-all">${esc(tags.ruf)}</span></div>` : ''}
                    ${tags.ri ? `<div class="detail-row"><span class="detail-label">Report Interval</span><span class="detail-value">${esc(tags.ri)} seconds</span></div>` : ''}
                </div>
            </div>` : ''}
            <div class="sig-section">
                <div class="sig-section-title">\uD83C\uDF10 DNS Record</div>
                <div class="dns-cmd">
                    <code>${esc(dnsCmd)}</code>
                    <button class="copy-btn" style="opacity:1" onclick="event.stopPropagation();copy(this,'${esc(dnsCmd)}')">&#x29C9;</button>
                </div>
                <div class="dns-raw">${esc(dmarcResult.record)}</div>
            </div>
        </div></div>
    </div>`;
}

function renderArc(arcSets) {
    if (!arcSets || arcSets.length === 0) {
        return '';
    }

    const latestSet = arcSets[arcSets.length - 1];
    const chainStatus = latestSet?.seal?.tags?.cv?.toLowerCase() || 'none';
    const statusInfo = ARC_CV_STATUS[chainStatus] || ARC_CV_STATUS.none;

    const { badgeStyle, badgeText } = getBadgeForResult(chainStatus);

    const setsHtml = arcSets.map(set => {
        const sealTags = set.seal?.tags || {};
        const msgTags = set.message?.tags || {};
        const authResults = set.auth?.parsed?.results || [];
        const domain = sealTags.d || msgTags.d || 'unknown';

        const authHtml = authResults.map(r => {
            const resultClass = r.result === 'pass' ? 'success' : (r.result === 'fail' ? 'error' : 'warning');
            return `<span class="relay-hop-detail">${r.method}: <span style="color:var(--${resultClass})">${r.result}</span></span>`;
        }).join('');

        const sealTagsHtml = Object.entries(sealTags)
            .filter(([k]) => k !== 'b')
            .map(([k, v]) => {
                const info = ARC_SEAL_TAGS[k] || { name: k.toUpperCase(), desc: 'ARC tag' };
                const short = v.length > 20 ? v.slice(0, 20) + '\u2026' : v;
                return `<div class="tag" data-tag="${esc(k)}" data-tag-name="${esc(info.name)}" data-tag-desc="${esc(info.desc)}" data-tag-value="${esc(v)}">
                    <span class="dot"></span>
                    <span class="tag-name">${esc(k)}</span>
                    <span class="tag-value">${esc(short)}</span>
                </div>`;
            }).join('');

        const cvStatus = sealTags.cv?.toLowerCase() || 'none';
        const cvInfo = ARC_CV_STATUS[cvStatus] || ARC_CV_STATUS.none;

        return `
            <div class="arc-set">
                <div class="arc-set-header">
                    <span class="arc-set-title">ARC Set #${set.instance}</span>
                    <span class="arc-set-domain">${esc(domain)}</span>
                </div>
                <div class="arc-component">
                    <div class="arc-component-label">Chain Validation (cv=)</div>
                    <span class="detail-value ${cvInfo.color}">${cvInfo.icon} ${cvInfo.name}</span>
                </div>
                ${authResults.length > 0 ? `<div class="arc-component">
                    <div class="arc-component-label">Authentication Results</div>
                    <div class="relay-hop-details">${authHtml}</div>
                </div>` : ''}
                <div class="arc-component">
                    <div class="arc-component-label">ARC-Seal Tags</div>
                    <div class="tags-grid">${sealTagsHtml}</div>
                </div>
            </div>
        `;
    }).join('');

    return `<div class="arc-card ${chainStatus} expanded">
        <div class="sig-header" onclick="toggleCard(this)">
            <div class="sig-title">
                <span class="sig-num">\uD83D\uDD17</span>
                <span class="sig-domain">ARC Chain</span>
                <span class="badge" style="${badgeStyle}">${badgeText}</span>
                <span class="badge" style="background:var(--glass);color:var(--text-secondary);margin-left:0.5rem">${arcSets.length} SET${arcSets.length > 1 ? 'S' : ''}</span>
            </div>
            <span class="expand-icon">\u25BC</span>
        </div>
        <div class="sig-content"><div class="sig-body">
            <div class="sig-section">
                <div class="sig-section-title">\uD83D\uDCCA Chain Status</div>
                <div class="details">
                    <div class="detail-row"><span class="detail-label">Chain Validation</span><span class="detail-value ${statusInfo.color}">${statusInfo.icon} ${statusInfo.name}</span></div>
                    <div class="detail-row"><span class="detail-label">Description</span><span class="detail-value">${esc(statusInfo.desc)}</span></div>
                    <div class="detail-row"><span class="detail-label">Total Sets</span><span class="detail-value">${arcSets.length}</span></div>
                </div>
            </div>
            <div class="sig-section">
                <div class="sig-section-title">\uD83D\uDD17 ARC Sets (oldest first)</div>
                ${setsHtml}
            </div>
        </div></div>
    </div>`;
}

function renderRelayChain(hops) {
    if (!hops || hops.length === 0) {
        return '<div class="error-msg">No Received headers found to trace email path</div>';
    }

    let totalLatency = 0;
    let validLatencies = 0;
    for (const hop of hops) {
        if (hop.latency && hop.latency > 0) {
            totalLatency += hop.latency;
            validLatencies++;
        }
    }

    const summaryHtml = `
        <div class="relay-summary-row">
            <div class="relay-stat">
                <span>Hops:</span>
                <span class="relay-stat-value">${hops.length}</span>
            </div>
            ${totalLatency > 0 ? `<div class="relay-stat">
                <span>Total Transit:</span>
                <span class="relay-stat-value">${formatLatency(totalLatency)}</span>
            </div>` : ''}
            ${validLatencies > 0 ? `<div class="relay-stat">
                <span>Avg per Hop:</span>
                <span class="relay-stat-value">${formatLatency(Math.round(totalLatency / validLatencies))}</span>
            </div>` : ''}
        </div>
    `;

    const hopsHtml = hops.map((hop, i) => {
        const isOrigin = i === 0;
        const server = hop.by || hop.from || 'Unknown server';
        const timeStr = hop.timestamp ? hop.timestamp.toLocaleString() : '';
        const latencyHtml = hop.latency !== undefined ?
            `<span class="relay-latency ${getLatencyClass(hop.latency)}">+${formatLatency(hop.latency)}</span>` : '';
        const isXReceived = hop.type === 'x-received';
        const hopTypeLabel = isXReceived ? '<span class="hop-type-badge internal">X-Received</span>' : '';

        return `
            <div class="relay-hop ${isOrigin ? 'origin' : ''} ${isXReceived ? 'x-received' : ''}">
                <div class="relay-hop-header">
                    <span class="relay-hop-server">${esc(server)} ${hopTypeLabel}</span>
                    <span class="relay-hop-time">${esc(timeStr)} ${latencyHtml}</span>
                </div>
                <div class="relay-hop-details">
                    ${hop.from ? `<span class="relay-hop-detail">from <span>${esc(hop.from)}</span></span>` : ''}
                    ${hop.ip ? `<span class="relay-hop-detail">IP <span>${esc(hop.ip)}</span></span>` : ''}
                    ${hop.protocol ? `<span class="relay-hop-detail">via <span>${esc(hop.protocol)}</span></span>` : ''}
                    ${hop.tls ? `<span class="relay-hop-detail" style="color:var(--success)">TLS</span>` : ''}
                    ${hop.smtpId ? `<span class="relay-hop-detail">ID <span>${esc(hop.smtpId)}</span></span>` : ''}
                    ${hop.isInternal ? `<span class="relay-hop-detail" style="color:var(--text-dim)">Internal</span>` : ''}
                </div>
            </div>
        `;
    }).join('');

    return `
        <div class="relay-card expanded">
            <div class="sig-header" onclick="toggleCard(this)">
                <div class="sig-title">
                    <span class="sig-num">\uD83D\uDCEC</span>
                    <span class="sig-domain">Email Relay Path</span>
                    <span class="badge" style="background:rgba(0,212,255,0.15);color:var(--accent-secondary)">${hops.length} HOPS</span>
                </div>
                <span class="expand-icon">\u25BC</span>
            </div>
            <div class="sig-content">
                <div class="sig-body">
                    ${summaryHtml}
                    <div class="sig-section">
                        <div class="sig-section-title">\uD83D\uDCE1 Relay Timeline</div>
                        <div class="relay-timeline">${hopsHtml}</div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// ============================================================================
// Initialize Tooltips
// ============================================================================

// ============================================================================
// Security Hint Rendering
// ============================================================================

function renderSecurityHint(type, result) {
    const implications = SECURITY_IMPLICATIONS[type];
    if (!implications) return '';
    const info = implications[result];
    if (!info) return '';

    const levelClass = info.level === 'good' ? 'success' : (info.level === 'bad' ? 'error' : (info.level === 'warning' ? 'warning' : 'neutral'));
    return `<div class="security-hint ${levelClass}">
        <span class="security-hint-icon">${info.level === 'good' ? '\u2713' : (info.level === 'bad' ? '\u26A0' : '\u2139')}</span>
        <span class="security-hint-text">${esc(info.message)}</span>
    </div>`;
}

// ============================================================================
// Overall Authentication Summary
// ============================================================================

function computeOverallStatus(results) {
    const { dkimResults, spfResult, dmarcResult, authResults } = results;

    let level = 'unknown';
    const issues = [];
    const passes = [];
    let score = 0;
    const scoreBreakdown = { dkim: 0, spf: 0, dmarc: 0 };

    // Check DKIM (40% of score)
    const validDkim = dkimResults?.filter(r => r.status === 'valid').length || 0;
    const totalDkim = dkimResults?.length || 0;
    if (totalDkim === 0) {
        issues.push({ text: 'No DKIM signatures', type: 'dkim', severity: 'warning' });
        scoreBreakdown.dkim = 0;
    } else if (validDkim === 0) {
        issues.push({ text: 'All DKIM signatures failed', type: 'dkim', severity: 'error' });
        scoreBreakdown.dkim = 0;
    } else if (validDkim < totalDkim) {
        passes.push({ text: `DKIM (${validDkim}/${totalDkim} valid)`, type: 'dkim' });
        scoreBreakdown.dkim = Math.round((validDkim / totalDkim) * 40);
    } else {
        passes.push({ text: 'DKIM', type: 'dkim' });
        scoreBreakdown.dkim = 40;
    }

    // Check SPF (30% of score)
    if (!spfResult || spfResult.result === 'none') {
        issues.push({ text: 'No SPF record', type: 'spf', severity: 'warning' });
        scoreBreakdown.spf = 0;
    } else if (spfResult.result === 'pass') {
        passes.push({ text: 'SPF', type: 'spf' });
        scoreBreakdown.spf = 30;
    } else if (spfResult.result === 'fail' || spfResult.result === 'permerror') {
        issues.push({ text: `SPF ${spfResult.result}`, type: 'spf', severity: 'error' });
        scoreBreakdown.spf = 0;
    } else if (spfResult.result === 'softfail') {
        issues.push({ text: 'SPF softfail', type: 'spf', severity: 'warning' });
        scoreBreakdown.spf = 10;
    } else {
        issues.push({ text: `SPF ${spfResult.result}`, type: 'spf', severity: 'warning' });
        scoreBreakdown.spf = 5;
    }

    // Check DMARC (30% of score)
    if (!dmarcResult || !dmarcResult.ok) {
        issues.push({ text: 'No DMARC policy', type: 'dmarc', severity: 'warning' });
        scoreBreakdown.dmarc = 0;
    } else {
        const policy = parseDmarcRecord(dmarcResult.record).p || 'none';
        if (policy === 'reject') {
            passes.push({ text: 'DMARC (reject)', type: 'dmarc' });
            scoreBreakdown.dmarc = 30;
        } else if (policy === 'quarantine') {
            passes.push({ text: 'DMARC (quarantine)', type: 'dmarc' });
            scoreBreakdown.dmarc = 20;
        } else {
            issues.push({ text: 'DMARC policy=none', type: 'dmarc', severity: 'warning' });
            scoreBreakdown.dmarc = 5;
        }
    }

    score = scoreBreakdown.dkim + scoreBreakdown.spf + scoreBreakdown.dmarc;

    // Determine overall level
    if (issues.filter(i => i.severity === 'error').length > 0) {
        level = 'fail';
    } else if (issues.length === 0) {
        level = 'pass';
    } else if (passes.length > 0 && issues.length > 0) {
        level = 'partial';
    } else if (passes.length === 0) {
        level = 'fail';
    } else {
        level = 'partial';
    }

    const securityInfo = SECURITY_IMPLICATIONS.overall[level] || SECURITY_IMPLICATIONS.overall.unknown;
    let message, icon, colorClass;
    switch (level) {
        case 'pass':
            message = 'Fully Authenticated';
            icon = '\u2713';
            colorClass = 'success';
            break;
        case 'partial':
            message = 'Partially Authenticated';
            icon = '\u26A0';
            colorClass = 'warning';
            break;
        case 'fail':
            message = 'Authentication Failed';
            icon = '\u2717';
            colorClass = 'error';
            break;
        default:
            message = 'Unknown Status';
            icon = '?';
            colorClass = 'neutral';
    }

    return { level, message, icon, colorClass, passes, issues, score, scoreBreakdown, securityInfo };
}

function renderOverallSummary(results) {
    const status = computeOverallStatus(results);

    const passesHtml = status.passes.map(p =>
        `<span class="auth-check pass" data-type="${p.type}">\u2713 ${esc(p.text)}</span>`
    ).join('');

    const issuesHtml = status.issues.map(i =>
        `<span class="auth-check ${i.severity === 'error' ? 'fail' : 'warn'}" data-type="${i.type}">${i.severity === 'error' ? '\u2717' : '\u26A0'} ${esc(i.text)}</span>`
    ).join('');

    const scoreColor = status.score >= 80 ? 'var(--success)' : (status.score >= 50 ? 'var(--warning)' : 'var(--error)');
    const scorePercent = (status.score / 100) * 283;
    const scoreGrade = status.score >= 90 ? 'A' : (status.score >= 80 ? 'B' : (status.score >= 60 ? 'C' : (status.score >= 40 ? 'D' : 'F')));

    return `<div class="overall-summary-card ${status.level}">
        <div class="overall-summary-header">
            <div class="overall-score-ring">
                <svg viewBox="0 0 100 100" class="score-svg">
                    <circle cx="50" cy="50" r="45" fill="none" stroke="var(--border)" stroke-width="6"/>
                    <circle cx="50" cy="50" r="45" fill="none" stroke="${scoreColor}" stroke-width="6"
                        stroke-dasharray="${scorePercent} 283"
                        stroke-linecap="round" transform="rotate(-90 50 50)"/>
                </svg>
                <div class="score-text">
                    <div class="score-value">${status.score}</div>
                    <div class="score-grade">${scoreGrade}</div>
                </div>
            </div>
            <div class="overall-summary-main">
                <div class="overall-title-row">
                    <span class="overall-icon ${status.colorClass}">${status.icon}</span>
                    <span class="overall-title">${status.securityInfo.title}</span>
                </div>
                <div class="overall-description">${esc(status.securityInfo.message)}</div>
                <div class="overall-checks">
                    ${passesHtml}${issuesHtml}
                </div>
            </div>
        </div>
        <div class="score-breakdown">
            <div class="score-breakdown-title">Score Breakdown</div>
            <div class="score-breakdown-items">
                <div class="score-item">
                    <span class="score-item-label">DKIM (40%)</span>
                    <div class="score-item-bar">
                        <div class="score-item-fill" style="width:${(status.scoreBreakdown.dkim / 40) * 100}%;background:${status.scoreBreakdown.dkim >= 30 ? 'var(--success)' : (status.scoreBreakdown.dkim > 0 ? 'var(--warning)' : 'var(--error)')}"></div>
                    </div>
                    <span class="score-item-value">${status.scoreBreakdown.dkim}/40</span>
                </div>
                <div class="score-item">
                    <span class="score-item-label">SPF (30%)</span>
                    <div class="score-item-bar">
                        <div class="score-item-fill" style="width:${(status.scoreBreakdown.spf / 30) * 100}%;background:${status.scoreBreakdown.spf >= 20 ? 'var(--success)' : (status.scoreBreakdown.spf > 0 ? 'var(--warning)' : 'var(--error)')}"></div>
                    </div>
                    <span class="score-item-value">${status.scoreBreakdown.spf}/30</span>
                </div>
                <div class="score-item">
                    <span class="score-item-label">DMARC (30%)</span>
                    <div class="score-item-bar">
                        <div class="score-item-fill" style="width:${(status.scoreBreakdown.dmarc / 30) * 100}%;background:${status.scoreBreakdown.dmarc >= 20 ? 'var(--success)' : (status.scoreBreakdown.dmarc > 0 ? 'var(--warning)' : 'var(--error)')}"></div>
                    </div>
                    <span class="score-item-value">${status.scoreBreakdown.dmarc}/30</span>
                </div>
            </div>
        </div>
    </div>`;
}

// ============================================================================
// Authentication-Results Header Rendering
// ============================================================================

function renderAuthenticationResults(authResults) {
    if (!authResults || authResults.length === 0) {
        return '';
    }

    const resultsHtml = authResults.map((ar, idx) => {
        const serverName = ar.authserv_id || 'Unknown Server';

        const methodsHtml = ar.results.map(r => {
            const resultInfo = r.resultInfo || AUTH_RESULTS[r.result] || AUTH_RESULTS.none;
            const propsHtml = Object.entries(r.properties || {})
                .map(([k, v]) => `<span class="auth-prop">${esc(k)}=${esc(v)}</span>`)
                .join('');

            return `<div class="auth-result-item">
                <span class="auth-method">${esc(r.method.toUpperCase())}</span>
                <span class="auth-result-badge ${resultInfo.color}">${resultInfo.icon} ${esc(r.result)}</span>
                ${r.reason ? `<span class="auth-reason">(${esc(r.reason)})</span>` : ''}
                ${propsHtml ? `<div class="auth-props">${propsHtml}</div>` : ''}
            </div>`;
        }).join('');

        return `<div class="auth-results-entry">
            <div class="auth-server">
                <span class="auth-server-icon">\uD83D\uDDA5\uFE0F</span>
                <span class="auth-server-name">${esc(serverName)}</span>
                ${ar.version ? `<span class="auth-version">v${ar.version}</span>` : ''}
            </div>
            <div class="auth-methods">${methodsHtml}</div>
        </div>`;
    }).join('');

    return `<div class="auth-results-card expanded">
        <div class="sig-header" onclick="toggleCard(this)">
            <div class="sig-title">
                <span class="sig-num">\uD83D\uDCDD</span>
                <span class="sig-domain">Server Authentication Results</span>
                <span class="badge" style="background:rgba(0,212,255,0.15);color:var(--accent-secondary)">${authResults.length} SERVER${authResults.length > 1 ? 'S' : ''}</span>
            </div>
            <span class="expand-icon">\u25BC</span>
        </div>
        <div class="sig-content"><div class="sig-body">
            <div class="info-msg">These are the authentication results reported by receiving mail servers in the Authentication-Results header.</div>
            <div class="auth-results-list">
                ${resultsHtml}
            </div>
        </div></div>
    </div>`;
}

function initTooltips() {
    document.querySelectorAll('#results .tag').forEach(tag => {
        Tooltip.attachToTag(tag);
    });
}

// ============================================================================
// Main Validation Function
// ============================================================================

async function validate() {
    logs.length = 0;
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

    const spfSummaryClass = spfEvalResult?.result === 'pass' ? 'success' : (spfEvalResult?.result === 'fail' || spfEvalResult?.result === 'permerror' ? 'error' : 'warning');
    const spfSummaryIcon = spfEvalResult?.result === 'pass' ? '\u2713' : (spfEvalResult?.result === 'fail' || spfEvalResult?.result === 'permerror' ? '\u2717' : '?');
    const spfSummaryLabel = spfEvalResult ? (SPF_RESULTS[spfEvalResult.result]?.name || 'Unknown') : 'N/A';

    if (!dkimSigs.length) {
        // Render Authentication-Results header (from receiving server)
        document.getElementById('authResultsEl').innerHTML = renderAuthenticationResults(authResults);

        // Render overall summary card (with no DKIM)
        document.getElementById('overallSummaryEl').innerHTML = renderOverallSummary({
            dkimResults: [],
            spfResult: spfEvalResult,
            dmarcResult,
            authResults
        });

        document.getElementById('summaryEl').innerHTML = `
            <div class="summary-item"><div class="summary-icon">\uD83D\uDEE1\uFE0F</div><div><span class="summary-value ${spfSummaryClass}">${spfSummaryIcon}</span><div class="summary-label">SPF ${spfSummaryLabel}</div></div></div>
            <div class="summary-item"><div class="summary-icon">\uD83D\uDCE7</div><div><span class="summary-value">0</span><div class="summary-label">DKIM Signatures</div></div></div>
        `;
        document.getElementById('sigsEl').innerHTML = '<div class="error-msg">No DKIM-Signature headers found</div>';
        document.getElementById('debugLog').innerHTML = renderDebug();
        document.getElementById('results').classList.add('visible');
        document.getElementById('status').innerHTML = '';
        initTooltips();
        return;
    }

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

    document.getElementById('summaryEl').innerHTML = `
        <div class="summary-item"><div class="summary-icon">\uD83D\uDEE1\uFE0F</div><div><span class="summary-value ${spfSummaryClass}">${spfSummaryIcon}</span><div class="summary-label">SPF ${spfSummaryLabel}</div></div></div>
        <div class="summary-item"><div class="summary-icon">\uD83D\uDCE7</div><div><span class="summary-value">${dkimResults.length}</span><div class="summary-label">DKIM Signatures</div></div></div>
        <div class="summary-item"><div class="summary-icon">\u2713</div><div><span class="summary-value success">${valid}</span><div class="summary-label">Valid</div></div></div>
        <div class="summary-item"><div class="summary-icon">\u2717</div><div><span class="summary-value error">${invalid}</span><div class="summary-label">Invalid</div></div></div>
    `;

    document.getElementById('sigsEl').innerHTML = dkimResults.map((r, i) => renderSig(r, i + 1)).join('');
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
// Exports for Testing
// ============================================================================

// Export functions for unit testing (when running in Node.js environment)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        // Parsing
        parseEmail,
        parseDkimTags,
        parseDnsTags,
        parseSpfRecord,
        parseDmarcRecord,
        parseArcHeaders,
        parseArcTags,
        parseArcAuthResults,
        parseRelayChain,
        parseMtaStsPolicy,

        // Canonicalization
        canonHeaderRelaxed,
        canonBodyRelaxed,
        canonBodySimple,

        // IP utilities
        ipv4ToInt,
        ipv4MatchesCIDR,
        expandIPv6,
        ipv6ToBigInt,
        ipv6MatchesCIDR,
        isPrivateIP,

        // Extraction
        extractMailDomain,
        extractSenderIP,

        // DMARC Alignment
        checkDkimAlignment,
        checkSpfAlignment,
        getOrganizationalDomain,
        evaluateDmarc,

        // Utilities
        esc,
        formatLatency,
        getLatencyClass,

        // Constants
        DKIM_TAGS,
        DNS_TAGS,
        SPF_MECHANISMS,
        SPF_QUALIFIERS,
        SPF_RESULTS,
        DMARC_TAGS,
        DMARC_POLICIES,
        ARC_SEAL_TAGS,
        ARC_MESSAGE_TAGS,
        ARC_AUTH_TAGS,
        ARC_CV_STATUS,
        BIMI_TAGS,
        MTA_STS_MODES
    };
}
