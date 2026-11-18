// --- UI Logic ---

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const errorMsg = document.getElementById('error-msg');
const resultsDiv = document.getElementById('results');
const headersOutput = document.getElementById('headers-output');
const headersSignedToggle = document.getElementById('headers-signed-toggle');
const summaryOutput = document.getElementById('summary-output');
const dkimOutput = document.getElementById('dkim-output');
const spfOutput = document.getElementById('spf-output');
const dmarcOutput = document.getElementById('dmarc-output');
const themeSelector = document.getElementById('theme-selector');
const copyToast = document.getElementById('copy-status');

const htmlEntities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => htmlEntities[character]);
}

function verdictClass(result) {
    if (result === 'pass') return 'status-pass';
    if (result === 'fail' || result === 'softfail' || result === 'permerror') return 'status-fail';
    return 'status-pending';
}

function formatUnixTime(seconds) {
    return new Date(parseInt(seconds, 10) * 1000).toLocaleString();
}

function verdictLabel(result) {
    return { pending: 'Checking…', none: 'None', unavailable: 'Not verified',
        temperror: 'Temporary error', permerror: 'Policy error' }[result] || result.toUpperCase();
}

// Define all themes
const allThemes = [
    { id: 'theme-auto', title: 'Match system (Ayu Light / Ayu Mirage)', type: 'system' },

    // Light Themes
    { id: 'theme-light-nord', title: 'Nord Light', type: 'light' },
    { id: 'theme-light-github', title: 'GitHub Light', type: 'light' },
    { id: 'theme-light-github-default', title: 'GitHub Light Default', type: 'light' },
    { id: 'theme-light-atom-one', title: 'Atom One Light', type: 'light' },
    { id: 'theme-light-quiet', title: 'Quiet Light', type: 'light' },
    { id: 'theme-light-ayu', title: 'Ayu Light', type: 'light' },
    { id: 'theme-light-bluloco', title: 'Bluloco Light', type: 'light' },
    { id: 'theme-light-catppuccin-latte', title: 'Catppuccin Latte', type: 'light' },
    { id: 'theme-light-horizon', title: 'Horizon Light', type: 'light' },
    { id: 'theme-light-soft-era', title: 'Soft Era', type: 'light' },
    { id: 'theme-light-gentle-sepia', title: 'Gentle Sepia', type: 'light' },
    
    // Dark Themes
    { id: 'theme-dark-ayu-mirage', title: 'Ayu Mirage', type: 'dark' },
    { id: 'theme-dark-solarized', title: 'Solarized Dark', type: 'dark' },
    { id: 'theme-dark-dracula', title: 'Dracula', type: 'dark' },
    { id: 'theme-dark-monokai', title: 'Monokai', type: 'dark' },
    { id: 'theme-dark-gruvbox', title: 'Gruvbox Dark', type: 'dark' },
    { id: 'theme-dark-catppuccin', title: 'Catppuccin Macchiato', type: 'dark' },
    { id: 'theme-dark-kiwi', title: 'Minimal Kiwi', type: 'dark' },
    { id: 'theme-dark-onedark', title: 'One Dark Pro', type: 'dark' }
];

const themeMenuButton = document.getElementById('theme-menu-btn');
const themeSwatch = themeMenuButton.querySelector('.theme-swatch');
themeSelector.replaceChildren();
for (const [type, label] of [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']]) {
    const heading = document.createElement('div');
    heading.className = 'theme-panel-label';
    heading.textContent = label;
    const group = document.createElement('div');
    group.className = 'theme-group';
    for (const theme of allThemes.filter(theme => theme.type === type)) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'theme-btn';
        button.dataset.theme = theme.id;
        button.title = theme.title;
        button.setAttribute('aria-label', theme.title);
        group.appendChild(button);
    }
    themeSelector.append(heading, group);
}

function closeThemeMenu(returnFocus) {
    if (themeSelector.classList.contains('hidden')) return;
    themeSelector.classList.add('hidden');
    themeMenuButton.setAttribute('aria-expanded', 'false');
    if (returnFocus) themeMenuButton.focus();
}
document.addEventListener('click', event => {
    if (!event.target.closest('.theme-menu')) closeThemeMenu(false);
});
document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeThemeMenu(true);
});

// Inject Paste Area into Drop Zone
const pasteContainer = document.createElement('div');
pasteContainer.className = 'paste-container';
pasteContainer.innerHTML = `
    <div class="divider"><span>or</span></div>
    <textarea id="paste-input" class="paste-area" aria-label="Raw email content" placeholder="Paste the raw email source here. It's analyzed as you type…"></textarea>
`;
dropZone.appendChild(pasteContainer);

const pasteInput = document.getElementById('paste-input');
let pasteTimeout;
let latestRun = 0;
pasteInput.addEventListener('input', () => {
    const run = startRun();
    const text = pasteInput.value;
    if (text.trim()) pasteTimeout = setTimeout(() => processRawEmail(text, run), 800);
});

const iconAttrs = 'aria-hidden="true" focusable="false" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
const copiedIcon = `<svg width="16" height="16" ${iconAttrs}><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>`;
const copyFailedIcon = `<svg width="16" height="16" ${iconAttrs}><path d="M6 6l12 12M18 6 6 18"/></svg>`;
const clockIcon = `<svg width="18" height="18" ${iconAttrs}><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`;

// Filled status dot shared by header badges and DKIM check cards.
const statusMarks = { pass: 'm4.75 8.25 2.1 2.1 4.4-4.6', fail: 'M5.6 5.6l4.8 4.8m0-4.8-4.8 4.8', warn: 'M8 4.5V8l2.25 1.5',
    unknown: 'M6.2 6.2a1.9 1.9 0 1 1 2.6 1.75c-.5.2-.8.6-.8 1.1v.35M8 11.3v.05' };
// "ring" draws the pass mark in an outline circle, for "verifies, with a caveat".
function statusIcon(kind, size = 16) {
    const ring = kind === 'ring';
    const mark = statusMarks[ring ? 'pass' : kind];
    return `<svg class="status-icon ${kind}" aria-hidden="true" focusable="false" width="${size}" height="${size}" viewBox="0 0 16 16">
        ${ring ? '<circle cx="8" cy="8" r="7.1" fill="none" stroke="currentColor" stroke-width="1.6"/>' : '<circle cx="8" cy="8" r="8" fill="currentColor"/>'}
        <path class="status-icon-mark${ring ? ' on-ring' : ''}" d="${mark}"/></svg>`;
}

function plusMinusIcon(circled = false) {
    return `<svg class="disclosure-icon" aria-hidden="true" focusable="false" width="24" height="24"
        viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
        ${circled ? '<circle cx="12" cy="12" r="10"/>' : ''}
        <path d="${circled ? 'M8 12h8' : 'M5 12h14'}"/>
        <path class="disclosure-plus" d="${circled ? 'M12 8v8' : 'M12 5v14'}"/>
    </svg>`;
}

const sectionDisclosureIcon = plusMinusIcon(true);
const detailDisclosureIcon = plusMinusIcon();
const bulkDisclosureIcon = `<svg aria-hidden="true" focusable="false" width="16" height="16"
    viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M4 12h16" stroke-dasharray="2 3"/>
    <path class="trace-expand-icon" d="M12 9V3m-3 3 3-3 3 3M12 15v6m-3-3 3 3 3-3"/>
    <path class="trace-collapse-icon" d="M12 3v6m-3-3 3 3 3-3M12 21v-6m-3 3 3-3 3 3"/>
</svg>`;

// One lock with both shackles; aria-pressed on the button picks which one shows.
const lockIcon = `<svg class="lock-icon" aria-hidden="true" focusable="false" width="18" height="18"
    viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <rect x="4.5" y="11" width="15" height="10" rx="2.5"/>
    <path class="lock-shackle-closed" d="M8 11V7.5a4 4 0 0 1 8 0V11"/>
    <path class="lock-shackle-open" d="M8 11V7.5a4 4 0 0 1 7.76-1.37"/>
    <path d="M12 15v2"/>
</svg>`;

// How a header is covered by DKIM, best first; each header shows the best signature that lists it.
const signatureBadges = {
    verified: { rank: 5, label: 'Covered by a verified DKIM signature', short: 'Verified', icon: statusIcon('pass') },
    headers: { rank: 4, label: 'Covered by a DKIM signature whose headers verify; the body changed after signing', short: 'Headers verify, body changed', icon: statusIcon('ring') },
    expired: { rank: 3, label: 'Covered by an expired DKIM signature that still verifies', short: 'Expired', icon: statusIcon('warn') },
    unchecked: { rank: 2, label: 'Listed in a DKIM signature that couldn\'t be checked', short: 'Not checked', icon: statusIcon('unknown') },
    failed: { rank: 1, label: 'Listed in a DKIM signature that doesn\'t verify', short: 'Doesn\'t verify', icon: statusIcon('fail') }
};

let currentEmail = null;

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('hover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('hover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('hover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
});

dropZone.addEventListener('click', (event) => {
    if (!event.target.closest('.paste-container')) fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    const files = e.target.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
    // Reset value to allow re-selecting the same file
    fileInput.value = '';
});

headersSignedToggle.innerHTML = lockIcon + '<span>Signed only</span>';
headersSignedToggle.addEventListener('click', () => {
    const signedOnly = headersSignedToggle.getAttribute('aria-pressed') !== 'true';
    headersSignedToggle.setAttribute('aria-pressed', String(signedOnly));
    headersSignedToggle.title = signedOnly ? 'Show all headers' : 'Show only signed headers';
    displayHeaders();
});

// Load saved theme
let savedTheme;
try {
    savedTheme = localStorage.getItem('emailParserTheme');
} catch {
    // The theme switcher still works when the browser blocks local storage.
}
applyTheme(allThemes.some(theme => theme.id === savedTheme) ? savedTheme : 'theme-auto');
themeSelector.addEventListener('click', (event) => {
    const button = event.target.closest('.theme-btn');
    if (!button) return;
    const theme = button.dataset.theme;
    applyTheme(theme);
    try {
        localStorage.setItem('emailParserTheme', theme);
    } catch {
        // Only persistence is optional.
    }
});

function applyTheme(theme) {
    document.body.className = theme;
    themeSwatch.dataset.theme = theme;
    themeMenuButton.title = 'Theme: ' + allThemes.find(entry => entry.id === theme).title;
    for (const button of themeSelector.querySelectorAll('.theme-btn')) {
        const active = button.dataset.theme === theme;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', String(active));
    }
}

document.querySelectorAll('.toggle-section-btn').forEach(button => {
    button.innerHTML = sectionDisclosureIcon;
});

document.addEventListener('click', (event) => {
    const button = event.target.closest('button[aria-expanded][aria-controls]');
    if (!button) return;
    const panel = document.getElementById(button.getAttribute('aria-controls'));
    if (!panel) return;
    const expanded = !panel.classList.toggle('hidden');
    button.setAttribute('aria-expanded', String(expanded));
    if (button.classList.contains('toggle-section-btn')) {
        button.title = expanded ? 'Collapse section' : 'Expand section';
    } else if (button.classList.contains('toggle-all-spf')) {
        button.querySelector('span').textContent = expanded ? 'Collapse all' : 'Expand all';
    }
});

// Every value field copies itself on click (or Enter/Space when focused) and confirms with a toast.
const copyableSelector = [
    '.data-card', '.subject-text', '.facts dd.mono', '.relay-details dd', '.route-host', '.route-ip', '.route-embedded', '.route-from', '.dmarc-domain', '.dmarc-address', '.spf-token', '.spf-ptr-name', '.dkim-domain',
    '.dkim-check-value', '.tech-value', '.spf-trace-record', '.spf-dns-cmd'
].join(', ');

function markCopyable(root) {
    for (const element of root.querySelectorAll(copyableSelector)) {
        if (element.classList.contains('is-copyable')) continue;
        element.classList.add('is-copyable');
        element.tabIndex = 0;
        element.setAttribute('role', 'button');
        if (!element.title) element.title = 'Click to copy';
    }
}
new MutationObserver(() => markCopyable(resultsDiv)).observe(resultsDiv, { childList: true, subtree: true });

function copyText(element) {
    const source = element.classList.contains('data-card') ? element.querySelector('.data-value') : element;
    const text = element.dataset.copy ?? source.dataset.copy ?? source.textContent;
    return source.tagName === 'PRE' ? text : text.trim();
}

async function writeClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        // Some browsers withhold the async clipboard from file:// pages; fall back to a selection copy.
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
        document.body.appendChild(area);
        area.select();
        try {
            return document.execCommand('copy');
        } catch {
            return false;
        } finally {
            area.remove();
        }
    }
}

let toastTimer;
function showCopyToast(copied, text) {
    const flat = text.replace(/\s+/g, ' ').trim();
    const preview = flat.length > 48 ? flat.slice(0, 47) + '…' : flat;
    copyToast.innerHTML = copied
        ? `${copiedIcon}<span>Copied</span>${preview ? ` <code>${escapeHtml(preview)}</code>` : ''}`
        : `${copyFailedIcon}<span>Couldn't copy to the clipboard</span>`;
    copyToast.classList.toggle('is-error', !copied);
    copyToast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => copyToast.classList.remove('visible'), 1800);
}

const flashTimers = new WeakMap();
async function copyField(element) {
    const text = copyText(element);
    const copied = await writeClipboard(text);
    clearTimeout(flashTimers.get(element));
    element.classList.remove('just-copied', 'copy-failed');
    void element.offsetWidth; // Restart the flash when the same field is clicked again.
    element.classList.add(copied ? 'just-copied' : 'copy-failed');
    flashTimers.set(element, setTimeout(() => element.classList.remove('just-copied', 'copy-failed'), 700));
    showCopyToast(copied, text);
}

resultsDiv.addEventListener('click', event => {
    const element = event.target.closest('.is-copyable');
    if (!element) return;
    // Let people select part of a value without copying the whole field.
    const selection = window.getSelection();
    if (selection && !selection.isCollapsed && element.contains(selection.anchorNode)) return;
    copyField(element);
});

resultsDiv.addEventListener('keydown', event => {
    if ((event.key !== 'Enter' && event.key !== ' ') || !event.target.classList?.contains('is-copyable')) return;
    event.preventDefault();
    copyField(event.target);
});


async function processFile(file) {
    const run = startRun();
    try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        if (run === latestRun) await processRawEmail(bytes, run);
    } catch (error) {
        showError(run, 'Could not read the file', error);
    }
}

function startRun() {
    clearTimeout(pasteTimeout);
    currentEmail = null;
    errorMsg.classList.add('hidden');
    errorMsg.textContent = '';
    resultsDiv.classList.add('hidden');
    return ++latestRun;
}

function showError(run, message, error) {
    if (run !== latestRun) return;
    errorMsg.textContent = message + ': ' + error.message;
    errorMsg.classList.remove('hidden');
    console.error(error);
}

async function processRawEmail(input, run) {
    if (run !== latestRun) return;
    try {
        const parser = new EmailParser();
        const email = typeof input === 'string' ? parser.parse(input) : parser.parseBytes(input);
        currentEmail = email;
        const dkimParser = new DkimParser();
        email.dkim = new DkimValidator().getRawHeaderFields(email.rawHeaders)
            .filter(field => field.key === 'dkim-signature')
            .map((field, index) => dkimParser.parse(field.raw.slice(field.raw.indexOf(':') + 1), index));

        displaySummary(getHeaderValue(email.headers, 'Subject'));
        displayHeaders();
        displayRelay(traceHeaders(email), getHeaderValue(email.headers, 'Date'), relayHints(email));
        displayServerValidation(getHeaderValue(email.headers, 'Authentication-Results'));
        displayDkim(email.dkim);
        displaySpfLoading();
        displayDmarcLoading();
        
        resultsDiv.classList.remove('hidden');
        await runVerification(email, run);
    } catch (err) {
        showError(run, 'Could not analyze the email', err);
    }
}

function displaySummary(subject, results = {}) {
    const subj = Array.isArray(subject) ? subject[0] : subject;
    const safeSubject = escapeHtml(subj ? decodeMimeWords(subj) : '(No Subject)');
    const checks = ['DKIM', 'SPF', 'DMARC'].map(label => {
        const result = results[label.toLowerCase()] || 'pending';
        return `<div class="summary-group">
            <div class="summary-label">${label}</div>
            <div><span class="${verdictClass(result)} summary-pill">${escapeHtml(verdictLabel(result))}</span></div>
        </div>`;
    }).join('');
    
    summaryOutput.innerHTML = `
        <div class="summary-layout">
            <div class="summary-group">
                <div class="summary-label">Subject</div>
                <div class="summary-value subject-text" title="${safeSubject}">${safeSubject}</div>
            </div>
            <div class="summary-checks">${checks}</div>
        </div>
    `;
}

// What a signature's result says about the headers it lists.
function headerCoverage(dkim, result) {
    if (!result.details?.signedHeaders?.length) return null;
    const headers = dkimHeadersVerified(result);
    if (result.valid) return 'verified';
    if (headers === true) return dkimExpired(dkim) ? 'expired' : 'headers';
    return headers === false ? 'failed' : 'unchecked';
}

function displayHeaders() {
    if (!currentEmail) return;
    const headers = currentEmail.headers;
    const showSignedOnly = headersSignedToggle.getAttribute('aria-pressed') === 'true';

    const coverageByHeader = new Map();
    for (const { dkim, result } of currentEmail.dkimResults || []) {
        const coverage = headerCoverage(dkim, result);
        if (!coverage) continue;
        for (const { key, instance } of result.details.signedHeaders) {
            const id = key + ':' + instance;
            const current = coverageByHeader.get(id);
            if (!current || signatureBadges[coverage].rank > signatureBadges[current].rank) coverageByHeader.set(id, coverage);
        }
    }
    if (showSignedOnly && !coverageByHeader.size) {
        const checking = !currentEmail.dkimResults && currentEmail.dkim.length > 0;
        headersOutput.innerHTML = '<p class="note">' + (checking ? 'Checking DKIM signatures…'
            : currentEmail.dkim.length ? 'No DKIM signature lists any of these headers.' : 'This message has no DKIM signature.') + '</p>';
        return;
    }

    const kinds = Object.keys(signatureBadges).filter(kind => [...coverageByHeader.values()].includes(kind));
    let html = kinds.length ? `<div class="header-legend">${kinds.map(kind =>
        `<span class="header-legend-item signature-badge ${kind}">${signatureBadges[kind].icon}${escapeHtml(signatureBadges[kind].short)}</span>`).join('')}</div>` : '';
    html += '<div class="headers-grid">';
    for (const [key, value] of Object.entries(headers)) {
        const values = Array.isArray(value) ? value : [value];
        for (const [instance, rawValue] of values.entries()) {
            const coverage = coverageByHeader.get(key.toLowerCase() + ':' + instance);
            if (showSignedOnly && !coverage) continue;
            const badge = signatureBadges[coverage];
            const displayValue = escapeHtml(rawValue);
            html += `
                <div class="data-card${coverage ? ' coverage-' + coverage : ''}"${badge ? ` aria-label="${escapeHtml(key)}, ${badge.label}: ${displayValue}"` : ''}>
                    <div class="data-key">
                        ${badge ? `<span class="signature-badge ${coverage}" role="img" aria-label="${badge.label}" title="${badge.label}">${badge.icon}</span>` : ''}
                        <span>${escapeHtml(key)}</span>
                    </div>
                    <div class="data-value" title="${displayValue}">${displayValue}</div>
                </div>`;
        }
    }
    html += '</div>';
    headersOutput.innerHTML = html;
}

// Received and X-Received fields in header order (newest first), so internal steps
// such as Gmail's X-Received land between the hops around them.
function traceHeaders(email) {
    return new DkimValidator().getRawHeaderFields(email.rawHeaders)
        .filter(field => field.key === 'received' || field.key === 'x-received')
        .map(field => ({ name: field.key === 'received' ? 'Received' : 'X-Received', value: field.raw.slice(field.raw.indexOf(':') + 1).trim() }));
}

// Facts from other headers that place the hops: the client IP your provider checked SPF against
// (where it took the message from outside), and Microsoft's delayed-delivery flag.
function relayHints(email) {
    const values = name => [getHeaderValue(email.headers, name)].flat().filter(value => typeof value === 'string');
    const clientIp = values('Received-SPF').map(value => value.match(/\bclient-ip\s*=\s*([0-9a-fA-F:.]+)/i)?.[1]).find(Boolean) ||
        values('Authentication-Results').map(value => value.match(/\bsender IP is ([0-9a-fA-F:.]+)/i)?.[1] ||
            value.match(/\bsmtp\.remote-ip\s*=\s*([0-9a-fA-F:.]+)/i)?.[1]).find(Boolean) || null;
    const delayedDelivery = values('X-MS-DelayedDelivery').some(value => /^\s*true\b/i.test(value));
    return { clientIp, delayedDelivery };
}

function displayRelay(trace, dateHeader, hints = {}) {
    // Ensure container exists
    let container = document.getElementById('relay-output');
    if (!container) {
        const section = document.createElement('section');
        section.className = 'section';
        section.innerHTML = `
            <h2 class="section-heading">
                <span>Email Hops <span class="header-stats hidden"></span></span>
                <span class="header-controls">
                    <button type="button" class="toggle-section-btn" aria-controls="relay-output" aria-expanded="true" title="Collapse section">${sectionDisclosureIcon}</button>
                </span>
            </h2>
            <div id="relay-output"></div>
        `;
        // Insert after summary section
        const summarySection = summaryOutput.closest('.section');
        if (summarySection) {
            summarySection.after(section);
        } else {
            resultsDiv.insertBefore(section, headersOutput.closest('.section'));
        }
        container = document.getElementById('relay-output');
    }

    const stats = container.closest('.section').querySelector('.header-stats');
    stats.classList.add('hidden');
    stats.textContent = '';
    relayState.route = null;
    if (!trace.some(header => header.name === 'Received')) {
        container.innerHTML = '<p class="note">No Received headers found.</p>';
        return;
    }

    if (typeof RelayParser === 'undefined') {
        container.innerHTML = '<div class="error">RelayParser library not loaded.</div>';
        return;
    }

    let dto;
    try {
        const parser = new RelayParser();
        dto = parser.parse(trace.map(header => header.value));
        dto.hops.forEach((hop, position) => { hop.source = trace[position].name; });
    } catch (e) {
        container.innerHTML = `<div class="error">Error parsing relay: ${escapeHtml(e.message)}</div>`;
        return;
    }

    relayState.route = buildRoute(dto.hops, Array.isArray(dateHeader) ? dateHeader[0] : dateHeader, hints);
    relayState.spfIp = null;
    const { steps, total } = relayState.route;
    relayState.selected = (relayState.route.groups.length > 1 ? relayState.route.groups.at(-1).steps[0] : steps.at(-1))?.index;
    const hops = steps.filter(step => step.source === 'Received').length;
    const count = hops === 1 ? '1 hop' : hops + ' hops';
    stats.textContent = total === null ? count : count + ' · ' + formatDuration(total, false);
    stats.classList.toggle('hidden', !steps.length);
    renderRelay();
}

// --- Relay views ---
// Both views read one route model: Received headers oldest first, grouped by the
// registrable domain of the server that wrote each one.
const relayState = { route: null, spfIp: null, selected: null, view: storedRelayView() };
const relayViews = [
    { id: 'route', label: 'Route', icon: `<svg width="15" height="15" ${iconAttrs}><circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><path d="M6 7v10M11 5h9M11 12h6M11 19h9"/></svg>` },
    { id: 'map', label: 'Path map', icon: `<svg width="15" height="15" ${iconAttrs}><rect x="2" y="8" width="7" height="8" rx="1.5"/><rect x="15" y="8" width="7" height="8" rx="1.5"/><path d="M9 12h6"/></svg>` }
];
const smallLockIcon = `<svg width="11" height="11" ${iconAttrs}><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7.5a4 4 0 0 1 8 0V11"/></svg>`;
const arrowRightIcon = `<svg width="14" height="14" ${iconAttrs}><path d="M5 12h14m-5-5 5 5-5 5"/></svg>`;
// Domains one provider uses for its own servers, shown under one name.
const organizationAliases = {
    'office365.com': 'outlook.com', 'exchangelabs.com': 'outlook.com', 'office.com': 'outlook.com', 'hotmail.com': 'outlook.com',
    'live.com': 'outlook.com', 'gmail.com': 'google.com', 'googlemail.com': 'google.com'
};
const twoLevelSuffixes = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp',
    'com.br', 'com.cn', 'com.mx', 'co.in', 'co.za', 'com.tr', 'co.kr', 'com.sg', 'com.hk', 'com.tw', 'com.ar', 'co.il']);

function storedRelayView() {
    try {
        return localStorage.getItem('emailParserRelayView') === 'map' ? 'map' : 'route';
    } catch {
        return 'route';
    }
}

function normalizeIp(ip) {
    return ip ? ip.replace(/^IPv6:/i, '').toLowerCase() : null;
}

function ipScope(ip) {
    const value = normalizeIp(ip);
    if (!value) return null;
    if (value === '::1' || /^127\./.test(value)) return 'loopback';
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|f[cd][0-9a-f]{0,2}:|fe[89ab][0-9a-f]?:)/.test(value)) return 'private';
    return 'public';
}

function registrableDomain(host) {
    const name = (host || '').replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
    if (!name.includes('.') || name.includes(':') || /^[\d.]+$/.test(name)) return null;
    // Names inside private networks (eaas-34.….svc.cluster.local) say nothing about the company.
    if (/\.(local|localdomain|internal|lan|intranet|corp|home|arpa)$/.test(name)) return null;
    const labels = name.split('.');
    const size = twoLevelSuffixes.has(labels.slice(-2).join('.')) ? 3 : 2;
    return labels.length >= size ? labels.slice(-size).join('.') : null;
}

function organizationOf(host) {
    const domain = registrableDomain(host);
    return organizationAliases[domain] || domain;
}

function buildRoute(hops, dateHeader, hints = {}) {
    const recorded = [...hops].reverse().map(hop => ({
        host: hop.by || 'Unknown server', org: organizationOf(hop.by), source: hop.source || 'Received',
        from: hop.from, ip: hop.ip, helo: hop.helo, protocol: hop.with, tls: hop.tls, cipher: hop.cipher,
        timestamp: hop.timestamp || null, date: hop.date, raw: hop.fullHeader, delay: null
    }));
    // A server without a domain (an ID or internal name) is usually the one the next server names
    // as its sender; otherwise it belongs to the network around it.
    recorded.forEach((step, position) => {
        const next = recorded[position + 1];
        if (!step.org && next) step.org = [next.from, next.helo].map(organizationOf).find(Boolean) || null;
    });
    let known = null;
    for (const step of recorded) step.org ? known = step.org : step.org = known;
    known = null;
    for (const step of [...recorded].reverse()) step.org ? known = step.org : step.org = known;

    // Some senders (Amazon SES, for one) add no Received header of their own. They still appear
    // as the "from" of the first header, so show that server as the first step.
    const first = recorded[0];
    const senderHost = first && [first.from, first.helo]
        .map(name => name?.replace(/^\[|\]$/g, '').replace(/\.$/, ''))
        .find(name => organizationOf(name));
    const steps = senderHost && organizationOf(senderHost) !== first.org
        ? [{ host: senderHost, org: organizationOf(senderHost), source: 'Reported', reportedBy: first.host,
            ip: first.ip, helo: first.helo, raw: first.raw, timestamp: null, date: null, delay: null }, ...recorded]
        : recorded;
    steps.forEach((step, position) => { step.index = position + 1; });
    if (first) first.firstRecorded = true;

    // The Date header is set by the sender's software when it marks the message ready to send.
    // Each gap is measured from the step before it; the first recorded step from the Date header.
    const sentAt = Date.parse(dateHeader || '');
    const sent = Number.isNaN(sentAt) ? null : { timestamp: sentAt, date: dateHeader };
    let previous = sent;
    for (const step of recorded) {
        if (previous?.timestamp && step.timestamp) step.delay = (step.timestamp - previous.timestamp) / 1000;
        previous = step;
    }

    // Your provider took the message from outside at the hop whose IP it checked SPF against. Start a
    // new group there even when both sides are the same company (Microsoft mail to an Outlook.com box).
    const entry = hints.clientIp && [...steps].reverse().find(step => step.ip && normalizeIp(step.ip) === normalizeIp(hints.clientIp));
    const groups = [];
    for (const step of steps) {
        if (!groups.length || groups.at(-1).org !== step.org || step === entry) groups.push({ org: step.org, steps: [] });
        groups.at(-1).steps.push(step);
    }
    if (hints.delayedDelivery) {
        const slowest = recorded.filter(step => step.delay !== null).sort((a, b) => b.delay - a.delay)[0];
        if (slowest) slowest.delayedDelivery = true;
    }
    const dated = steps.filter(step => step.timestamp);
    const days = new Set([...dated, ...(sent ? [sent] : [])].map(step => new Date(step.timestamp).toDateString()));
    return {
        steps, groups, sent, multiDay: days.size > 1,
        total: dated.length > 1 ? (dated.at(-1).timestamp - dated[0].timestamp) / 1000 : null,
        zone: dated.length ? new Date(dated[0].timestamp).toLocaleTimeString([], { timeZoneName: 'short' }).split(' ').pop() : null
    };
}

function formatDuration(seconds, signed = true) {
    let rest = Math.round(Math.abs(seconds));
    // Sub-second clock differences round to "+0 s", never "−0 s".
    const sign = signed ? (seconds < 0 && rest > 0 ? '−' : '+') : '';
    if (rest < 60) return `${sign}${rest} s`;
    const hours = Math.floor(rest / 3600), minutes = Math.floor(rest % 3600 / 60);
    rest %= 60;
    return sign + [hours && `${hours} h`, minutes && `${minutes} min`, rest && `${rest} s`].filter(Boolean).join(' ');
}

function stepNote(step, route) {
    if (step.delayedDelivery) {
        return 'Microsoft held this message before this step (X-MS-DelayedDelivery: true)' +
            (step.index === route.steps.length ? '. Last server to record the message' : '');
    }
    if (step.source === 'Reported') return `Sending server, as named by ${escapeHtml(step.reportedBy)}. It added no Received header of its own.`;
    if (step.source === 'X-Received') return 'Internal processing step (X-Received header)';
    return step.index === route.steps.length ? 'Last server to record the message' : '';
}

function hopTime(step, route) {
    if (step.source === 'Reported') return '';
    if (!step.timestamp) return 'No date';
    const options = { hour: '2-digit', minute: '2-digit', second: '2-digit' };
    return route.multiDay ? new Date(step.timestamp).toLocaleString([], { month: 'short', day: 'numeric', ...options })
        : new Date(step.timestamp).toLocaleTimeString([], options);
}

function orgRole(groupIndex, route) {
    if (route.groups.length < 2) return '';
    return groupIndex === 0 ? 'sender' : groupIndex === route.groups.length - 1 ? 'your provider' : 'relay';
}

function orgLabel(group, groupIndex, route) {
    const role = orgRole(groupIndex, route);
    return `<span class="route-org-name">${escapeHtml(group.org || 'Unnamed servers')}</span>${role ? `<span class="route-org-role">${role}</span>` : ''}`;
}

function delayBadge(step) {
    if (step.firstRecorded && step.delay === null) return '<span class="route-delay">Start</span>';
    if (step.delay === null) return '<span class="route-delay is-unknown" title="One of these headers has no readable date">—</span>';
    const warn = step.delay <= -1 ? 'Earlier than the previous step: the two servers\' clocks disagree' : step.delay > 60 ? 'Slow handoff' : '';
    return `<span class="route-delay${warn ? ' is-warn' : ''}"${warn ? ` title="${warn}"` : ''}>${formatDuration(step.delay)}</span>`;
}

// Names and IPs in IPv6 form that carry an IPv4 (6to4, IPv4-mapped, NAT64, Teredo) get it shown alongside.
function embeddedChip(value) {
    const found = IpAddress.embeddedIpv4(value);
    if (!found) return '';
    const scope = ipScope(found.ipv4);
    return `<span class="route-chip is-mono route-embedded" data-copy="${found.ipv4}" title="IPv4 carried inside this ${found.kind} IPv6 address">`
        + `<span class="route-ip-scope">IPv4</span>${found.ipv4}${scope === 'public' ? '' : `<span class="route-ip-scope">${scope}</span>`}</span>`;
}

function embeddedNote(value) {
    const found = IpAddress.embeddedIpv4(value);
    return found ? `carries IPv4 ${found.ipv4} (${found.kind})` : '';
}

function hopChips(step) {
    const scope = ipScope(step.ip);
    return [
        step.protocol ? `<span class="route-chip">${escapeHtml(step.protocol)}</span>` : '',
        step.tls ? `<span class="route-chip is-secure" title="${escapeHtml(step.cipher || 'Encrypted in transit')}">${smallLockIcon}${escapeHtml(step.tls)}</span>` : '',
        step.ip ? `<span class="route-chip is-mono route-ip" data-copy="${escapeHtml(normalizeIp(step.ip))}">${scope === 'public' ? '' : `<span class="route-ip-scope">${scope}</span>`}${escapeHtml(normalizeIp(step.ip))}</span>` : '',
        step.ip ? embeddedChip(step.ip) : '',
        step.ip && normalizeIp(step.ip) === relayState.spfIp
            ? `<span class="route-spf">${copiedIcon}SPF checked this IP</span>` : ''
    ].join('');
}

function senderNames(step, previous) {
    const from = step.from && step.from.replace(/^\[|\]$/g, '');
    const names = [];
    if (from && from !== normalizeIp(step.ip) && from !== previous?.host) names.push(['from', step.from]);
    if (step.helo && step.helo !== step.from && step.helo !== previous?.host) names.push(['HELO', step.helo]);
    return names.map(([label, value]) => `<span class="route-edge-line">${label} <span class="route-from">${escapeHtml(value)}</span></span>`).join('');
}

function renderRouteView(route) {
    let html = `<p class="relay-caption">Oldest first${route.zone ? ` · times in your time zone (${escapeHtml(route.zone)})` : ''}</p><ol class="route">`;
    route.groups.forEach((group, groupIndex) => {
        if (groupIndex && groupIndex === route.groups.length - 1) {
            html += `<li class="route-boundary"><span>Your provider recorded the steps below this line. The ones above were written by earlier servers and can't be checked.</span></li>`;
        }
        html += `<li class="route-org">${orgLabel(group, groupIndex, route)}</li>`;
        if (!groupIndex && route.sent) {
            html += `
                <li class="route-step is-sent">
                    <span class="route-time" title="${escapeHtml(route.sent.date)}">${escapeHtml(hopTime(route.sent, route))}</span>
                    <span class="route-dot" aria-hidden="true"></span>
                    <div class="route-body"><span class="route-sent">Sent</span><span class="route-note">Date header: when the sender marked it ready to send</span></div>
                </li>`;
        }
        for (const step of group.steps) {
            const previous = route.steps[step.index - 2];
            if (step.source !== 'Reported') {
                html += `<li class="route-edge"><div class="route-edge-body">${delayBadge(step)}${hopChips(step)}${senderNames(step, previous)}</div></li>`;
            }
            html += `
                <li class="route-step${step.index === route.steps.length ? ' is-last' : ''}${step.source === 'X-Received' ? ' is-internal' : ''}${step.source === 'Reported' ? ' is-reported' : ''}">
                    <span class="route-time" title="${escapeHtml(step.date || (step.source === 'Reported' ? 'No header records when this server sent it' : 'This header has no readable date'))}">${escapeHtml(hopTime(step, route))}</span>
                    <span class="route-dot" aria-hidden="true"></span>
                    <div class="route-body">
                        <div class="route-host-line"><span class="route-host">${escapeHtml(step.host)}</span>${embeddedChip(step.host)}</div>
                        ${stepNote(step, route) ? `<span class="route-note">${stepNote(step, route)}</span>` : ''}
                    </div>
                </li>`;
        }
    });
    return html + '</ol>';
}

// Inside a lane the network is already named, so long hosts drop that suffix
// and leave a single ellipsis to CSS.
function shortHost(host, org) {
    return org && host.length > 18 && host.endsWith('.' + org) ? host.slice(0, -org.length - 1) : host;
}

// Arrows in the map have little room, so long gaps use a compact form ("+14m 47s").
function arrowLabel(step) {
    if (step.delay === null) return '';
    const full = formatDuration(step.delay);
    return `<span title="${full}">${full.replace(/ (h|min|s)\b/g, (match, unit) => unit === 'min' ? 'm' : unit)}</span>`;
}

function renderPathMap(route) {
    const internal = route.steps.some(step => step.source === 'X-Received');
    let html = `<p class="relay-caption">Select a server to see its header${internal ? ' · dashed: internal step' : ''}${route.zone ? ` · times in ${escapeHtml(route.zone)}` : ''}</p><div class="map-lanes">`;
    route.groups.forEach((group, groupIndex) => {
        const first = group.steps[0];
        if (groupIndex) html += `<span class="map-arrow map-handoff" aria-hidden="true">${arrowLabel(first)}${arrowRightIcon}</span>`;
        const sent = !groupIndex && route.sent ? `
            <div class="map-node map-sent" title="Sent (Date header): ${escapeHtml(route.sent.date)}">
                <span class="map-host">Sent</span>
                <span class="map-time">${escapeHtml(hopTime(route.sent, route))}</span>
            </div>` : '';
        const nodes = sent + group.steps.map((step, position) => `
            ${position || sent ? `<span class="map-arrow" aria-hidden="true">${arrowLabel(step)}${arrowRightIcon}</span>` : ''}
            <button type="button" class="map-node${step.source === 'X-Received' ? ' is-internal' : ''}${step.source === 'Reported' ? ' is-reported' : ''}" data-step="${step.index}" aria-pressed="${step.index === relayState.selected}"
                title="${escapeHtml(step.host)}${embeddedNote(step.host) ? ', ' + embeddedNote(step.host) : ''}${step.source === 'X-Received' ? ' (internal processing step)' : step.source === 'Reported' ? ` (named by ${escapeHtml(step.reportedBy)})` : ''}">
                <span class="map-host">${escapeHtml(shortHost(step.host, step.org))}</span>
                <span class="map-time">${step.source === 'Reported' ? 'no timestamp' : escapeHtml(hopTime(step, route))}</span>
            </button>`).join('');
        html += `<section class="map-lane${route.groups.length > 1 && groupIndex === route.groups.length - 1 ? ' is-provider' : ''}" style="flex-grow: ${group.steps.length + (sent ? 0.5 : 0)}">
            <div class="map-lane-label">${orgLabel(group, groupIndex, route)}</div>
            <div class="map-nodes">${nodes}</div>
        </section>`;
    });
    html += '</div>';
    if (route.groups.length > 1) {
        html += `<div class="map-handoffs">${route.groups.slice(1).map((group, position) => `
            <div class="map-handoff-row">
                <span class="map-handoff-title">${escapeHtml(route.groups[position].org || 'Unnamed servers')}${arrowRightIcon}${escapeHtml(group.org || 'Unnamed servers')}</span>
                ${delayBadge(group.steps[0])}${hopChips(group.steps[0])}
            </div>`).join('')}</div>`;
    }
    return html + `<div class="map-detail">${renderMapDetail(route)}</div>`;
}

function renderMapDetail(route) {
    const step = route.steps[relayState.selected - 1];
    if (!step) return '';
    const ip = step.ip && normalizeIp(step.ip) + (ipScope(step.ip) === 'public' ? '' : ` (${ipScope(step.ip)})`)
        + (embeddedNote(step.ip) ? `, ${embeddedNote(step.ip)}` : '');
    const reported = step.source === 'Reported';
    const fields = (reported ? [['Named by', step.reportedBy], ['IP', ip], ['HELO', step.helo]] : [
        ['Received', step.timestamp ? new Date(step.timestamp).toLocaleString() : 'No readable date'],
        ['Gap', step.delay !== null ? formatDuration(step.delay) + (step.firstRecorded ? ' after the Date header' : '') : step.firstRecorded ? 'First step' : 'Unknown'],
        ['From', step.from], ['IP', ip], ['HELO', step.helo], ['Protocol', step.protocol],
        ['TLS', step.tls && step.tls + (step.cipher ? ', ' + step.cipher : '')],
        ['Note', step.delayedDelivery && 'Microsoft held this message before this step (X-MS-DelayedDelivery: true)']
    ]).filter(([, value]) => value);
    const note = reported ? 'Sending server · no Received header of its own' : step.source === 'X-Received' ? 'internal processing' : '';
    return `
        <div class="map-detail-head"><span class="route-host">${escapeHtml(step.host)}</span>${embeddedChip(step.host)}<span class="route-note">Step ${step.index} of ${route.steps.length}${note ? ' · ' + note : ''}</span></div>
        <dl class="relay-details">${fields.map(([label, value]) => `<dt>${label}</dt><dd>${escapeHtml(value)}</dd>`).join('')}</dl>
        <div class="dns-command-label">Raw header</div>
        <pre class="tech-value code">${reported ? 'Received' : step.source}: ${escapeHtml(step.raw)}</pre>`;
}

function renderRelay() {
    const container = document.getElementById('relay-output');
    const route = relayState.route;
    if (!container || !route) return;
    if (!route.steps.length) {
        container.innerHTML = '<p class="note">No Received headers could be read.</p>';
        return;
    }
    const view = relayState.view;
    container.innerHTML = `
        <div class="relay-tabs" role="tablist" aria-label="Relay view">
            ${relayViews.map(({ id, label, icon }) => `<button type="button" role="tab" class="relay-tab" id="relay-tab-${id}" data-view="${id}"
                aria-controls="relay-panel-${id}" aria-selected="${id === view}" tabindex="${id === view ? 0 : -1}">${icon}<span>${label}</span></button>`).join('')}
        </div>
        <div class="relay-panel" id="relay-panel-route" role="tabpanel" aria-labelledby="relay-tab-route"${view === 'route' ? '' : ' hidden'}>${renderRouteView(route)}</div>
        <div class="relay-panel" id="relay-panel-map" role="tabpanel" aria-labelledby="relay-tab-map"${view === 'map' ? '' : ' hidden'}>${renderPathMap(route)}</div>`;
}

function selectRelayView(view, focus) {
    relayState.view = view;
    try {
        localStorage.setItem('emailParserRelayView', view);
    } catch {
        // The view still switches; only the preference isn't kept.
    }
    for (const tab of document.querySelectorAll('.relay-tab')) {
        const active = tab.dataset.view === view;
        tab.setAttribute('aria-selected', String(active));
        tab.tabIndex = active ? 0 : -1;
        if (active && focus) tab.focus();
    }
    for (const panel of document.querySelectorAll('.relay-panel')) panel.hidden = panel.id !== 'relay-panel-' + view;
}

function selectMapStep(index) {
    relayState.selected = index;
    for (const node of document.querySelectorAll('.map-node')) node.setAttribute('aria-pressed', String(Number(node.dataset.step) === index));
    const detail = document.querySelector('.map-detail');
    if (detail) detail.innerHTML = renderMapDetail(relayState.route);
}

function markRelaySpfIp(ip) {
    relayState.spfIp = normalizeIp(ip);
    if (relayState.spfIp) renderRelay();
}

resultsDiv.addEventListener('click', event => {
    const tab = event.target.closest('.relay-tab');
    if (tab) selectRelayView(tab.dataset.view, false);
    const node = event.target.closest('.map-node');
    if (node) selectMapStep(Number(node.dataset.step));
});

resultsDiv.addEventListener('keydown', event => {
    if (!event.target.classList?.contains('relay-tab') || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const ids = relayViews.map(view => view.id);
    const current = ids.indexOf(event.target.dataset.view);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? ids.length - 1
        : (current + (event.key === 'ArrowRight' ? 1 : ids.length - 1)) % ids.length;
    selectRelayView(ids[next], true);
});

function displayServerValidation(headerValue) {
    let container = document.getElementById('server-validation-output');
    if (!container) {
        const section = document.createElement('section');
        section.className = 'section';
        section.innerHTML = `
            <h2 class="section-heading">
                <span>Reported Authentication Results</span>
                <span class="header-controls">
                    <button type="button" class="toggle-section-btn" aria-controls="server-validation-output" aria-expanded="true" title="Collapse section">${sectionDisclosureIcon}</button>
                </span>
            </h2>
            <div id="server-validation-output"></div>
        `;
        
        // Insert after summary section to ensure it appears right after summary
        // Note: displayRelay also inserts after summary. If called in order (Relay then ServerValidation),
        // ServerValidation will be inserted immediately after summary, pushing Relay down.
        // Result: Summary -> ServerValidation -> Relay
        const summarySection = summaryOutput.closest('.section');
        if (summarySection) {
            summarySection.after(section);
        } else {
            resultsDiv.insertBefore(section, headersOutput.closest('.section'));
        }
        container = document.getElementById('server-validation-output');
    }

    if (!headerValue) {
        container.innerHTML = '<p class="note">No Authentication-Results header found.</p>';
        return;
    }

    const parser = new ServerValidationParser();
    const dto = parser.parse(headerValue);

    let html = `
        <div class="auth-results-container">
            <div class="auth-results-grid">
    `;

    dto.results.forEach(res => {
        const statusClass = res.result === 'pass' ? 'status-pass' : 
                          (res.result === 'fail' ? 'status-fail' : 'status-pending');
        html += `
            <div class="auth-result-card">
                <div class="auth-method">${escapeHtml(res.method.toUpperCase())}</div>
                <div class="auth-status ${statusClass}">${escapeHtml(res.result.toUpperCase())}</div>
            </div>
        `;
    });

    html += `
            </div>
            <div class="mt-15">
                <div class="dns-command-label">Raw header</div>
                <div class="data-card">
                    <div class="data-value">${escapeHtml(dto.fullHeader)}</div>
                </div>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

function displayDkim(dkimList) {
    if (!dkimList || dkimList.length === 0) {
        dkimOutput.innerHTML = '<p class="note">No DKIM signatures found.</p>';
        return;
    }
    dkimOutput.innerHTML = dkimList.map((dkim, index) => `
        <div class="dkim-signature-card">
            <div class="dkim-card-header">
                <div class="dkim-header-info">
                    <span class="dkim-domain">${escapeHtml(dkim.tags.d || 'unknown')}</span>
                    <span class="dkim-selector">selector ${escapeHtml(dkim.tags.s || 'unknown')}</span>
                </div>
                <div id="dkim-status-${index}" class="dkim-status-badge status-pending">Verifying…</div>
            </div>
            <div id="dkim-verification-${index}"><p class="note">Checking the signature…</p></div>
        </div>`).join('');
}

function displaySpfLoading() {
    spfOutput.innerHTML = '<div class="spf-record-card"><span class="status-pending">Checking SPF…</span></div>';
}

function renderSpfTrace(node, depth = 0) {
    if (!node) return '';
    
    const statusClass = node.result === 'Pass' ? 'status-pass' : 
                       (node.result === 'Fail' || node.result === 'SoftFail' ? 'status-fail' : 'status-pending');
    const isMatch = node.matchMechanism ? true : false;
    const matchClass = isMatch ? ' match' : '';
    const hasChildren = node.children && node.children.length > 0;
    
    let html = `
        <div class="spf-trace-node${matchClass}" style="--depth: ${depth}">
            <div class="spf-trace-header">
                <strong>${escapeHtml(node.domain)}</strong>
                <span class="${statusClass} spf-trace-status">${escapeHtml(node.result)}</span>
            </div>
            <div class="spf-trace-record">
                ${escapeHtml(node.record || 'No Record')}
            </div>
            ${node.reason ? `<div class="spf-trace-reason">${escapeHtml(node.reason)}</div>` : ''}
            
            ${node.dnsCommand ? `
            <div class="spf-trace-dns">
                <span class="spf-dns-cmd">${escapeHtml(node.dnsCommand)}</span>
            </div>` : ''}
        </div>
    `;

    if (hasChildren) {
        html += depth === 0 ? '<div id="spf-trace-branches" class="hidden">' : '<div>';
        node.children.forEach(child => {
            html += renderSpfTrace(child.trace, depth + 1);
        });
        html += '</div>';
    }

    return html;
}

// --- SPF ---
// Common senders' SPF includes, by domain or parent domain. Unknown includes show their domain.
const spfProviders = [
    ['spf.protection.outlook.com', 'Microsoft 365'], ['_spf.google.com', 'Google Workspace'], ['_netblocks.google.com', 'Google'],
    ['mailgun.org', 'Mailgun'], ['sendgrid.net', 'SendGrid'], ['amazonses.com', 'Amazon SES'], ['mcsv.net', 'Mailchimp'],
    ['mandrillapp.com', 'Mailchimp Transactional'], ['exacttarget.com', 'Salesforce Marketing Cloud'], ['salesforce.com', 'Salesforce'],
    ['mtasv.net', 'Postmark'], ['zendesk.com', 'Zendesk'], ['sparkpostmail.com', 'SparkPost'], ['mailjet.com', 'Mailjet'],
    ['mlsend.com', 'MailerLite'], ['createsend.com', 'Campaign Monitor'], ['hubspotemail.net', 'HubSpot'], ['klaviyomail.com', 'Klaviyo'],
    ['helpscoutemail.com', 'Help Scout'], ['freshdesk.com', 'Freshdesk'], ['zoho.com', 'Zoho Mail'], ['zohomail.com', 'Zoho Mail'],
    ['icloud.com', 'iCloud Mail'], ['yahoo.com', 'Yahoo'], ['secureserver.net', 'GoDaddy'], ['pphosted.com', 'Proofpoint'],
    ['mimecast.com', 'Mimecast'], ['messagelabs.com', 'Broadcom Email Security'], ['msft.net', 'Microsoft'], ['microsoft.com', 'Microsoft'],
    ['outlook.com', 'Microsoft'], ['google.com', 'Google']
];
const allQualifiers = {
    '-': ['status-fail', 'Fail', 'Everything else is rejected (strict)'],
    '~': ['status-pending', 'Softfail', 'Everything else is accepted but marked as suspicious'],
    '?': ['status-neutral', 'Neutral', 'No opinion about everything else'],
    '+': ['status-fail', 'Pass', 'Anyone may send for this domain, which makes SPF meaningless']
};

// Escaped text that may wrap only after separators (".", "@", ":", "=", "+", "/").
function breakable(text) {
    return escapeHtml(text).replace(/([.@:=+\/])/g, '$1<wbr>');
}

function spfProvider(domain) {
    const name = (domain || '').toLowerCase();
    return spfProviders.find(([key]) => name === key || name.endsWith('.' + key))?.[1] || null;
}

function spfTerm(token) {
    const qualifier = /^[-~?+]/.test(token) ? token[0] : '+';
    const body = token.replace(/^[-~?+]/, '');
    const [type, ...rest] = body.split(/[:=/]/);
    return { token, qualifier, type: type.toLowerCase(), target: body.includes(':') ? body.slice(body.indexOf(':') + 1) : body.includes('=') ? body.slice(body.indexOf('=') + 1) : null };
}

function spfTermLabel(term, domain) {
    switch (term.type) {
        case 'include': return spfProvider(term.target) || term.target.replace(/\/.*$/, '');
        case 'redirect': return `Policy of ${spfProvider(term.target) || term.target}`;
        case 'ip4': case 'ip6': return 'Listed addresses';
        case 'a': return term.target ? `Servers of ${term.target}` : 'The domain\'s own servers';
        case 'mx': return term.target ? `Mail servers of ${term.target}` : 'The domain\'s mail servers';
        case 'ptr': return 'Reverse DNS match (deprecated)';
        case 'exists': return 'Custom DNS check';
        case 'all': return 'Everyone else';
        default: return term.type;
    }
}

// The matched include's path below this domain, e.g. "_spf.mailgun.org → ip4:204.220.168.0/21".
function spfMatchPath(spfDto) {
    const chain = spfDto.matchChain || [];
    return chain.slice(1).map(step => step.mechanism && /^[+]?(include:|redirect=)/i.test(step.mechanism)
        ? step.mechanism.replace(/^[+]?(include:|redirect=)/i, '') : step.mechanism).filter(Boolean);
}

function spfRules(spfDto) {
    const outcomes = spfDto.trace?.terms || [];
    const matchedAt = outcomes.findIndex(entry => entry.outcome === 'matched');
    const path = spfMatchPath(spfDto);
    const rows = (spfDto.mechanisms || []).filter(token => !/^exp=/i.test(token)).map((token, position) => {
        const recorded = outcomes.find(entry => entry.token.replace(/^\+/, '') === token.replace(/^\+/, ''));
        const outcome = recorded?.outcome || 'not-reached';
        return { term: spfTerm(token), outcome, afterMatch: matchedAt >= 0 && !recorded };
    });
    // Consecutive IP ranges read as one rule ("13 IP ranges") instead of a row each.
    const merged = [];
    for (const row of rows) {
        const previous = merged.at(-1);
        const isRange = ['ip4', 'ip6'].includes(row.term.type);
        if (isRange && previous?.ranges && previous.term.qualifier === row.term.qualifier) {
            previous.ranges.push(row);
        } else {
            merged.push(isRange ? { ...row, ranges: [row] } : row);
        }
    }
    return merged.map(row => {
        const { term } = row;
        const ranges = row.ranges;
        const hit = ranges ? ranges.find(range => range.outcome === 'matched') : null;
        const outcome = ranges ? (hit ? 'matched' : ranges.some(range => range.outcome === 'no-match') ? 'no-match' : 'not-reached') : row.outcome;
        const tokens = ranges ? ranges.map(range => range.term.token) : [term.token];
        let detail;
        if (term.type === 'all') {
            const [cls, label, meaning] = allQualifiers[term.qualifier];
            detail = `<span class="${cls}">${label}</span><span class="check-note">${meaning}${outcome === 'matched' ? '. This rule decided the result.' : ''}</span>`;
        } else if (outcome === 'matched') {
            const via = hit ? [hit.term.token] : path;
            detail = `<span class="spf-rule-hit">${copiedIcon}Matched</span>${via.length ? checkNote(`${hit ? '' : 'via '}<code>${via.map(escapeHtml).join(' → ')}</code>`) : ''}`;
        } else if (outcome === 'no-match') {
            detail = '<span class="check-note">Checked, no match</span>';
        } else if (outcome === 'error') {
            detail = `<span class="status-fail">Error</span>${checkNote(escapeHtml(spfDto.trace?.reason || ''))}`;
        } else {
            detail = `<span class="check-note">${row.afterMatch || (ranges && ranges[0].afterMatch) ? 'Not checked, already matched' : 'Not checked'}</span>`;
        }
        const qualifier = term.type !== 'all' && term.qualifier !== '+' ? ` <span class="${allQualifiers[term.qualifier][0]}">${allQualifiers[term.qualifier][1]}</span>` : '';
        const label = ranges && ranges.length > 1 ? `${ranges.length} IP ranges` : spfTermLabel(term, spfDto.domain);
        const tokenCell = tokens.length > 1
            ? `<span class="spf-token" title="${escapeHtml(tokens.join(' '))}" data-copy="${escapeHtml(tokens.join(' '))}">${escapeHtml(tokens[0])} … ${escapeHtml(tokens.at(-1))}</span>`
            : `<span class="spf-token">${breakable(tokens[0])}</span>`;
        return `<tr class="${outcome === 'matched' ? 'counts' : ''}">
            <td class="spf-rule-mark">${outcome === 'matched' ? copiedIcon : outcome === 'no-match' ? '<span aria-label="No match">×</span>' : ''}</td>
            <th scope="row">${escapeHtml(label)}${qualifier}</th>
            <td>${tokenCell}</td>
            <td>${detail}</td>
        </tr>`;
    }).join('');
}

function spfSummary(spfDto) {
    const ip = `<code>${escapeHtml(normalizeIp(spfDto.senderIp) || '')}</code>`;
    const domain = `<code>${escapeHtml(spfDto.domain || '')}</code>`;
    const matched = spfDto.trace?.matchMechanism ? spfTerm(spfDto.trace.matchMechanism) : null;
    const allToken = (spfDto.mechanisms || []).find(token => /^[-~?+]?all$/i.test(token));
    switch (spfDto.result) {
        case 'pass': {
            const provider = matched?.type === 'include' || matched?.type === 'redirect' ? spfProvider(matched.target) : null;
            const why = provider ? ` It's one of ${escapeHtml(provider)}'s addresses.`
                : ['ip4', 'ip6'].includes(matched?.type) ? ' It\'s listed directly in the record.'
                : ['a', 'mx'].includes(matched?.type) ? ' It\'s one of the domain\'s own servers.' : '';
            return `${ip} is allowed to send for ${domain}.${why}`;
        }
        case 'fail': return `${ip} is not allowed to send for ${domain}${allToken ? `. The record ends with <code>${escapeHtml(allToken)}</code>, which rejects everyone else` : ''}.`;
        case 'softfail': return `${ip} isn't listed for ${domain}. Its <code>${escapeHtml(allToken || '~all')}</code> rule marks such mail as suspicious without rejecting it.`;
        case 'neutral': return `${domain}'s record takes no position on ${ip}.`;
        case 'none': return `${domain} publishes no SPF record.`;
        case 'permerror': return `${domain}'s SPF record can't be evaluated: ${escapeHtml(spfDto.trace?.reason || spfDto.error || 'it is invalid')}.`;
        case 'temperror': return 'A DNS lookup failed, so SPF could not be checked. Try again later.';
        default: return escapeHtml(spfDto.error || 'SPF could not be checked.');
    }
}

function spfFromNote(spfDto) {
    const from = currentEmail && EmailAddress.parseMailboxes(getHeaderValue(currentEmail.headers, 'From'));
    const fromDomain = from?.length === 1 ? from[0].domain : null;
    const envelope = (spfDto.domain || '').toLowerCase();
    if (!fromDomain || !envelope) return { chip: '', note: '' };
    if (envelope === fromDomain.toLowerCase()) return { chip: '<span class="status-pass">Matches From</span>', note: '' };
    if (registrableDomain(envelope) && registrableDomain(envelope) === registrableDomain(fromDomain)) {
        return { chip: '<span class="status-pass">Same organization as From</span>', note: '' };
    }
    return {
        chip: '<span class="status-neutral">Different from From</span>',
        note: `<div class="notice">The envelope sender's domain <code>${escapeHtml(envelope)}</code> isn't <code>${escapeHtml(fromDomain)}</code>, `
            + `so this SPF result doesn't count toward DMARC for the From address.</div>`
    };
}

function countTraceRecords(node) {
    return node ? 1 + (node.children || []).reduce((sum, child) => sum + countTraceRecords(child.trace), 0) : 0;
}

function displaySpf(spfDto) {
    const dnsOutput = spfDto.rawDns || 'No record';
    const dnsOutputDisplay = escapeHtml(dnsOutput.length > 255 ? dnsOutput.substring(0, 255) + '…' : dnsOutput);
    const reported = spfDto.headerResult;
    const agrees = reported && reported === spfDto.result;
    const from = spfFromNote(spfDto);
    const ip = spfDto.senderIp ? normalizeIp(spfDto.senderIp) : null;
    const ipSources = { 'Received-SPF': 'the Received-SPF header', 'Authentication-Results': 'the Authentication-Results header', Received: 'a Received header' };
    const lookups = spfDto.lookups;
    const records = countTraceRecords(spfDto.trace);
    const rules = spfDto.record ? spfRules(spfDto) : '';
    const warnings = [];
    if ((spfDto.mechanisms || []).some(token => /^\+?all$/i.test(token))) warnings.push('The record ends with <code>+all</code>, so anyone may send for this domain.');
    if ((spfDto.mechanisms || []).some(token => /^[-~?+]?ptr\b/i.test(token))) warnings.push('The record uses <code>ptr</code>, which is deprecated and slow.');
    if (spfDto.record && !(spfDto.mechanisms || []).some(token => /^[-~?+]?all$|^redirect=/i.test(token))) {
        warnings.push('The record has no <code>all</code> rule, so unlisted senders get a neutral result.');
    }
    if (lookups >= 9) warnings.push(`This check used ${lookups} of the 10 DNS lookups SPF allows; one more include would break it.`);

    spfOutput.innerHTML = `
        <div class="spf-record-card">
            <div class="dmarc-verdict">
                <span class="${verdictClass(spfDto.result)} summary-pill">${escapeHtml(verdictLabel(spfDto.result))}</span>
                <span class="dmarc-verdict-text">${spfSummary(spfDto)}</span>
            </div>
            <div class="dmarc-reported">
                ${reported ? `${agrees ? 'Same result' : 'Today\'s result differs from what'} <code>${escapeHtml(spfDto.reportedBy || 'the receiving server')}</code> recorded at delivery
                    ${agrees ? '' : `(<span class="${verdictClass(reported)}">${escapeHtml(verdictLabel(reported))}</span>); the record may have changed since`}`
                    : 'No SPF result was recorded at delivery'}${spfDto.trace ? ' · rechecked against today\'s DNS' : ''}
            </div>
            ${from.note}
            ${warnings.map(text => `<div class="notice">${text}</div>`).join('')}

            <dl class="facts spf-facts">
                <div><dt>Envelope sender</dt>
                    <dd class="mono spf-mailbox">${breakable(spfDto.mailbox || spfDto.domain || 'Unknown')}</dd>
                    <dd class="fact-note">Return-Path ${from.chip}</dd></div>
                <div><dt>Sending server</dt>
                    <dd class="mono">${ip ? escapeHtml(ip) : 'Unknown'}${ip ? embeddedChip(ip) : ''}</dd>
                    ${ip ? `<dd class="fact-note spf-ptr" data-ip="${escapeHtml(ip)}">Looking up its name…</dd>` : ''}
                    ${spfDto.ipSource ? `<dd class="fact-note">Taken from ${ipSources[spfDto.ipSource] || escapeHtml(spfDto.ipSource)}</dd>` : ''}</div>
                ${lookups !== null && lookups !== undefined ? `<div><dt>DNS lookups</dt>
                    <dd${lookups >= 9 ? ' class="spf-lookups-high"' : ''}>${lookups} of 10 used</dd>
                    <dd class="fact-note">SPF fails if a check needs more than 10${spfDto.voidLookups ? ` · ${spfDto.voidLookups} returned nothing` : ''}</dd></div>` : ''}
            </dl>
            ${spfDto.error && spfDto.result !== 'permerror' ? `<div class="error">${escapeHtml(spfDto.error)}</div>` : ''}

            ${rules ? `
            <h4>Allowed to send for ${escapeHtml(spfDto.domain)}</h4>
            <table class="spf-rules"><tbody>${rules}</tbody></table>` : ''}

            ${spfDto.trace ? `
            <button type="button" class="dkim-advanced-toggle" aria-controls="spf-evaluation" aria-expanded="false">
                ${detailDisclosureIcon}<span>Full evaluation</span><span class="toggle-meta">${records} ${records === 1 ? 'record' : 'records'}</span>
            </button>
            <div id="spf-evaluation" class="hidden">
                <div class="spf-trace-header-container">
                    <h4>Evaluation trace</h4>
                    ${spfDto.trace.children?.length ? `<button type="button" class="toggle-all-spf spf-trace-toggle-btn" aria-controls="spf-trace-branches" aria-expanded="false">${bulkDisclosureIcon}<span>Expand all</span></button>` : ''}
                </div>
                <div class="spf-trace-container">${renderSpfTrace(spfDto.trace)}</div>
            </div>` : ''}

            ${spfDto.dnsCommand ? `
            <button type="button" class="dkim-advanced-toggle" aria-controls="spf-dns" aria-expanded="false">
                ${detailDisclosureIcon}<span>DNS record</span><span class="toggle-meta">${escapeHtml(spfDto.dnsCommand.replace(/^dig TXT /, ''))}</span>
            </button>
            <div id="spf-dns" class="hidden">
                <div class="dns-command-card">
                    <div class="dns-command-label">Lookup command</div>
                    <div class="data-card"><div class="data-value">${escapeHtml(spfDto.dnsCommand)}</div></div>
                    <div class="dns-command-label">Raw SPF record</div>
                    <div class="data-card"><div class="data-value" data-copy="${escapeHtml(dnsOutput)}">${dnsOutputDisplay}</div></div>
                </div>
            </div>` : ''}
        </div>`;

    // Reverse DNS is only for display, so it loads after the panel and never blocks it.
    const ptr = spfOutput.querySelector('.spf-ptr');
    if (ptr) {
        new SpfValidator().reverseName(ptr.dataset.ip)
            .then(name => { if (ptr.isConnected) ptr.innerHTML = name ? `<span class="spf-ptr-name">${escapeHtml(name)}</span> (reverse DNS)` : 'No reverse DNS name'; })
            .catch(() => { if (ptr.isConnected) ptr.textContent = 'Reverse DNS lookup failed'; });
    }
}

function displayDmarcLoading() {
    dmarcOutput.innerHTML = '<div class="dmarc-record-card"><span class="status-pending">Checking DMARC…</span></div>';
}

// --- DMARC ---
const policyActions = { none: 'Take no action (monitoring only)', quarantine: 'Treat as suspicious, usually the spam folder', reject: 'Reject it' };
const matchLabels = {
    exact: ['status-pass', 'Exact'], relaxed: ['status-pass', 'Relaxed'], strict: ['status-fail', 'Needs exact match'],
    none: ['status-neutral', 'Different domain'], unknown: ['status-neutral', 'Unknown']
};
const failureOptions = { 0: 'all checks fail', 1: 'any check fails', d: 'DKIM fails', s: 'SPF fails' };

function pill(cls, label) {
    return `<span class="${cls}">${escapeHtml(label)}</span>`;
}

function checkNote(text) {
    return text ? `<span class="check-note">${text}</span>` : '';
}

function dmarcMatchCell(check, dto) {
    const [cls, label] = matchLabels[check.match] || matchLabels.unknown;
    const mode = check.kind === 'DKIM' ? 'adkim=s' : 'aspf=s';
    const note = check.match === 'relaxed' ? `Same organization as <code>${escapeHtml(dto.domain)}</code>`
        : check.match === 'strict' ? `Same organization, but the policy requires an exact match (${mode})` : '';
    return pill(cls, label) + checkNote(note);
}

function dmarcAuthCell(check) {
    const { auth } = check;
    if (check.kind === 'SPF') {
        const ip = auth.ip ? `IP <code>${escapeHtml(normalizeIp(auth.ip))}</code>` : '';
        if (auth.state === 'unconfirmed') return pill('status-pending', 'Pass, unconfirmed') + checkNote(`${ip || 'The sending IP'} comes from the message's own headers`);
        return pill(verdictClass(auth.state), auth.state === 'pass' ? 'Pass' : verdictLabel(auth.state)) + checkNote(auth.reason ? escapeHtml(auth.reason) : ip);
    }
    const expiry = auth.expires ? escapeHtml(formatUnixTime(auth.expires)) : '';
    switch (auth.state) {
        case 'pass': return pill('status-pass', 'Verified');
        case 'body-changed': return pill('status-fail', 'Body changed') + checkNote('Headers still verify; the body was changed after signing');
        case 'expired': return pill('status-pending', 'Expired') + checkNote(auth.signatureValid === true ? `Still verifies, but expired on ${expiry}`
            : auth.signatureValid === false ? `Expired on ${expiry} and no longer verifies` : `Expired on ${expiry}`);
        case 'temperror': return pill('status-pending', 'DNS error') + checkNote(escapeHtml(auth.reason || ''));
        case 'unavailable': return pill('status-pending', 'Not checked') + checkNote(escapeHtml(auth.reason || ''));
        default: return pill('status-fail', 'Failed') + checkNote(escapeHtml(auth.reason || ''));
    }
}

function dmarcSummary(dto) {
    const domain = `<code>${escapeHtml(dto.domain)}</code>`;
    const winner = dto.checks.find(check => check.counts);
    switch (dto.result) {
        case 'pass':
            return winner ? `${winner.kind} passed for <code>${escapeHtml(winner.domain)}</code>, ${winner.match === 'exact' ? 'the From domain' : `which matches ${domain}`}.`
                : `DMARC passed for ${domain}.`;
        case 'fail': return `Neither DKIM nor SPF passed for a domain matching ${domain}.`;
        case 'unavailable': return `DMARC needs DKIM or SPF to pass for a domain matching ${domain}. Neither can be confirmed from this email.`;
        case 'temperror': return 'A DNS lookup failed, so DMARC could not be decided. Try again later.';
        default: return dto.error ? escapeHtml(dto.error) : `${domain} publishes no DMARC policy, so there is nothing to check this message against.`;
    }
}

function addressList(value) {
    return (value || '').split(',').map(entry => entry.trim().replace(/^mailto:/i, '')).filter(Boolean)
        .map(entry => `<span class="dmarc-address">${escapeHtml(entry)}</span>`).join('');
}

function dmarcPolicyRows(dto) {
    const tags = dto.tags;
    const action = value => policyActions[(value || '').toLowerCase()] || value;
    const mode = value => (value || 'r').toLowerCase() === 's' ? 'strict (exact domain)' : 'relaxed (same organization)';
    const subdomainApplies = dto.fetchedDomain && dto.fetchedDomain !== dto.domain;
    const applies = '<span class="policy-applies">applies to this message</span>';
    const rows = [
        ['If mail fails DMARC', escapeHtml(action(tags.p)) + (subdomainApplies ? '' : applies), `p=${tags.p}`],
        ['Subdomains', escapeHtml(tags.sp ? action(tags.sp) : `${action(tags.p)} (same as above)`) + (subdomainApplies ? applies : ''), tags.sp ? `sp=${tags.sp}` : 'sp not set']
    ];
    if (tags.np) rows.push(['Subdomains that don\'t exist', escapeHtml(action(tags.np)), `np=${tags.np}`]);
    rows.push(['Applies to', !tags.pct || tags.pct === '100' ? 'All failing mail' : `${escapeHtml(tags.pct)}% of failing mail`, tags.pct ? `pct=${tags.pct}` : 'pct not set (100)']);
    rows.push(['Domain matching', (tags.adkim || 'r').toLowerCase() === (tags.aspf || 'r').toLowerCase()
        ? `${mode(tags.adkim).replace(/^./, letter => letter.toUpperCase())} for DKIM and SPF` : `DKIM ${mode(tags.adkim)}, SPF ${mode(tags.aspf)}`,
        tags.adkim || tags.aspf ? [tags.adkim && `adkim=${tags.adkim}`, tags.aspf && `aspf=${tags.aspf}`].filter(Boolean).join(', ') : 'adkim, aspf not set (relaxed)']);
    if (tags.rua) rows.push(['Summary reports to', addressList(tags.rua), 'rua']);
    if (tags.ruf) rows.push(['Failure reports to', addressList(tags.ruf), 'ruf']);
    if (tags.fo) rows.push(['Failure reports when', escapeHtml(tags.fo.split(':').map(option => failureOptions[option.trim()] || option).join(', ')), `fo=${tags.fo}`]);
    if (tags.ri) rows.push(['Report interval', `Every ${escapeHtml(formatDuration(Number(tags.ri), false).replace(/ 0 s$/, ''))}`, `ri=${tags.ri}`]);
    const known = new Set(['v', 'p', 'sp', 'np', 'pct', 'adkim', 'aspf', 'rua', 'ruf', 'fo', 'ri']);
    for (const [key, value] of Object.entries(tags)) {
        if (!known.has(key)) rows.push([`Tag ${escapeHtml(key)}`, `<span class="mono">${escapeHtml(value)}</span>`, `${key}=${value}`]);
    }
    return rows.map(([label, value, tag]) => `<dt>${label}</dt><dd>${value}</dd><dd class="policy-tag">${escapeHtml(tag)}</dd>`).join('');
}

function displayDmarc(dmarcDto) {
    const dto = dmarcDto;
    const dnsOutput = dto.rawDns || 'No record';
    const dnsOutputDisplay = escapeHtml(dnsOutput.length > 255 ? dnsOutput.substring(0, 255) + '…' : dnsOutput);
    const checks = dto.checks || [];
    const policyDomain = dto.fetchedDomain || dto.domain;

    dmarcOutput.innerHTML = `
        <div class="dmarc-record-card">
            <div class="dmarc-verdict">
                <span class="${verdictClass(dto.result)} summary-pill">${escapeHtml(verdictLabel(dto.result))}</span>
                <span class="dmarc-verdict-text">${dto.domain ? dmarcSummary({ ...dto, checks }) : escapeHtml(dto.error || 'No From domain to check.')}</span>
            </div>
            ${dto.reported ? `<div class="dmarc-reported">At delivery <code>${escapeHtml(dto.reported.authServId)}</code> reported
                <span class="${verdictClass(dto.reported.result)}">${escapeHtml(verdictLabel(dto.reported.result))}</span></div>` : ''}

            ${checks.length ? `
            <h4>How it was decided</h4>
            <table class="dmarc-checks">
                <thead><tr><th scope="col">Check</th><th scope="col">Domain</th><th scope="col">Matches From</th><th scope="col">Authenticated</th><th scope="col">Counts</th></tr></thead>
                <tbody>
                    ${checks.map(check => `
                    <tr${check.counts ? ' class="counts"' : ''}>
                        <th scope="row">${check.kind}</th>
                        <td data-label="Domain">${check.domain ? `<span class="dmarc-domain">${escapeHtml(check.domain).replace(/\./g, '.<wbr>')}</span>` : '<span class="check-note">Unknown</span>'}
                            ${check.selector ? checkNote(`selector <code>${escapeHtml(check.selector)}</code>`) : ''}</td>
                        <td data-label="Matches From">${dmarcMatchCell(check, dto)}</td>
                        <td data-label="Authenticated">${dmarcAuthCell(check)}</td>
                        <td data-label="Counts">${check.counts ? `<span class="dmarc-counts is-yes">${copiedIcon}Yes</span>` : '<span class="dmarc-counts">No</span>'}</td>
                    </tr>`).join('')}
                </tbody>
            </table>` : ''}

            ${dto.record ? `
            <h4>Policy for ${escapeHtml(policyDomain)}</h4>
            ${dto.fetchedDomain && dto.fetchedDomain !== dto.domain
                ? `<p class="note"><code>${escapeHtml(dto.domain)}</code> has no record of its own, so the policy of its organization domain applies.</p>` : ''}
            <dl class="dmarc-policy">${dmarcPolicyRows(dto)}</dl>` : ''}

            ${dto.dnsCommand ? `
            <button type="button" class="dkim-advanced-toggle" aria-controls="dmarc-dns" aria-expanded="false">
                ${detailDisclosureIcon}<span>DNS record</span><span class="toggle-meta">${escapeHtml(dto.dnsCommand.replace(/^dig TXT /, ''))}</span>
            </button>
            <div id="dmarc-dns" class="hidden">
                <div class="dns-command-card">
                    <div class="dns-command-label">Lookup command</div>
                    <div class="data-card"><div class="data-value">${escapeHtml(dto.dnsCommand)}</div></div>
                    <div class="dns-command-label">Raw DMARC record</div>
                    <div class="data-card"><div class="data-value" data-copy="${escapeHtml(dnsOutput)}">${dnsOutputDisplay}</div></div>
                </div>
            </div>` : ''}
        </div>`;
}

async function runVerification(email, run) {
    const validator = new DkimValidator();
    const summary = {};
    const subject = getHeaderValue(email.headers, 'Subject');
    const updateSummary = (check, result) => {
        summary[check] = result;
        displaySummary(subject, summary);
    };
    const spfCheck = new SpfValidator().verify(email)
        .catch(error => ({ result: 'unavailable', error: error.message }))
        .then(result => {
            if (run === latestRun) {
                displaySpf(result);
                updateSummary('spf', result.result);
                markRelaySpfIp(result.senderIp);
            }
            return result;
        });
    const dkimResults = [];

    for (const [index, dkim] of email.dkim.entries()) {
        let result;
        try {
            result = await validator.verify(email, dkim);
        } catch (error) {
            result = { valid: false, status: 'unavailable', error: error.message };
        }
        if (run !== latestRun) return;
        dkimResults.push({ result, dkim });
        displayDkimResult(index, dkim, result);
    }
    email.dkimResults = dkimResults;
    displayHeaders();
    const dkimStatuses = dkimResults.map(({ result }) => result.valid ? 'pass' : result.status || 'fail');
    const dkim = ['pass', 'temperror', 'unavailable', 'fail', 'expired'].find(status => dkimStatuses.includes(status)) || 'none';
    updateSummary('dkim', dkim);

    const spf = await spfCheck;
    if (run !== latestRun) return;

    const dmarc = await new DmarcValidator().verify(email, spf, dkimResults);
    if (run !== latestRun) return;
    displayDmarc(dmarc);

    updateSummary('dmarc', dmarc.result);
}

// Headers worth knowing about when a signature leaves them out.
const importantHeaders = ['from', 'to', 'cc', 'subject', 'date', 'reply-to', 'sender', 'message-id', 'content-type',
    'mime-version', 'list-unsubscribe', 'list-unsubscribe-post'];

function dkimExpired(dkim) {
    return dkim.tags.x !== undefined && Number(dkim.tags.x) < Date.now() / 1000;
}

// The header signature on its own: true (verifies), false (doesn't), or null (couldn't be checked).
function dkimHeadersVerified(result) {
    if (result.valid) return true;
    if (result.headersVerified !== undefined) return result.headersVerified;
    if (result.status === 'expired') return result.signatureValid ?? null;
    if (!result.details || result.keyError || ['temperror', 'unavailable'].includes(result.status)) return null;
    return false;
}

function dkimVerdict(dkim, result) {
    const domain = `<code>${escapeHtml(dkim.tags.d || 'unknown')}</code>`;
    const expiry = dkim.tags.x ? escapeHtml(formatUnixTime(dkim.tags.x)) : '';
    const headers = dkimHeadersVerified(result);
    if (result.valid) return { cls: 'dkim-verdict', text: `Verified: the signed headers and body are exactly as ${domain} signed them.` };
    if (result.headersVerified === true) {
        return { cls: 'notice', text: 'The body no longer matches what was signed, but the signed headers still verify against the current key, '
            + 'so the body was changed after signing. Messages saved or exported from Outlook or Exchange often look like this, '
            + 'because the body is rebuilt when the file is created.' + (dkimExpired(dkim) ? ` The signature had also expired on ${expiry}.` : '') };
    }
    if (result.status === 'expired') {
        return headers === true ? { cls: 'dkim-verdict', text: `${domain} signed this message and the signature still verifies, but it expired on ${expiry}, so it no longer counts toward DMARC.` }
            : headers === false ? { cls: 'error', text: `The signature expired on ${expiry} and no longer verifies against the current key.` }
            : { cls: 'dkim-verdict', text: `The signature expired on ${expiry}, and its key could not be checked.` };
    }
    if (result.headersVerified === false) return { cls: 'error', text: 'Neither the body nor the signed headers match this signature.' };
    if (result.keyError) return { cls: 'error', text: `The key ${escapeHtml(dkim.tags.s || '')}._domainkey.${escapeHtml(dkim.tags.d || '')} could not be used: ${escapeHtml(result.keyError)}.` };
    return { cls: 'error', text: escapeHtml(result.error || 'The signature does not verify.') };
}

function fromRelation(domain) {
    const from = currentEmail && EmailAddress.parseMailboxes(getHeaderValue(currentEmail.headers, 'From'));
    const fromDomain = from?.length === 1 ? from[0].domain.toLowerCase() : null;
    const value = (domain || '').toLowerCase();
    if (!fromDomain || !value) return '';
    if (value === fromDomain) return '<span class="status-pass">Matches From</span>';
    if (registrableDomain(value) && registrableDomain(value) === registrableDomain(fromDomain)) return '<span class="status-pass">Same organization as From</span>';
    return '<span class="status-neutral">Different from From</span>';
}

function dkimCheckRow(state, label, detail) {
    const icon = state === true ? statusIcon('pass', 18) : state === false ? statusIcon('fail', 18)
        : state === 'warn' ? statusIcon('warn', 18) : statusIcon('unknown', 18);
    return `<li>${icon}<div><span class="dkim-check-title">${label}</span>${detail ? `<span class="check-note">${detail}</span>` : ''}</div></li>`;
}

function dkimCoverage(dkim, result) {
    const listed = dkim.signedHeaders.map(name => name.toLowerCase());
    const counts = new Map();
    for (const name of listed) counts.set(name, (counts.get(name) || 0) + 1);
    const present = new Map(Object.keys(currentEmail?.headers || {}).map(key => [key.toLowerCase(), key]));
    const chips = [...counts].map(([name, count]) => {
        const shown = present.get(name) || name;
        const extra = count > 1 ? `<span class="dkim-header-count" title="Listed ${count} times: extra copies of this header can't be added without breaking the signature">×${count}</span>` : '';
        return `<span class="dkim-header-chip${present.has(name) ? '' : ' is-absent'}"${present.has(name) ? '' : ' title="Not present in this message; signed as absent"'}>${escapeHtml(shown)}${extra}</span>`;
    }).join('');
    const unsigned = importantHeaders.filter(name => present.has(name) && !counts.has(name)).map(name => present.get(name));
    const body = result.bodyHash || {};
    const bodyText = body.signedBytes !== undefined && body.signedBytes < body.totalBytes
        ? `Only the first ${body.signedBytes} of ${body.totalBytes} bytes (l=${escapeHtml(dkim.tags.l)}), so content added after that isn't protected`
        : 'The whole body';
    return `
        <div class="dkim-coverage">
            <div class="dkim-coverage-row"><span class="dkim-coverage-label">Signed headers</span><div class="dkim-header-chips">${chips}</div></div>
            ${unsigned.length ? `<div class="dkim-coverage-row"><span class="dkim-coverage-label">Not signed</span><div class="dkim-header-chips">${unsigned.map(name => `<span class="dkim-header-chip is-unsigned">${escapeHtml(name)}</span>`).join('')}</div></div>` : ''}
            <div class="dkim-coverage-row"><span class="dkim-coverage-label">Body</span><span>${bodyText}</span></div>
        </div>`;
}

function displayDkimResult(i, dkim, result) {
    const statusDiv = document.getElementById(`dkim-status-${i}`);
    const verificationDiv = document.getElementById(`dkim-verification-${i}`);
    const status = result.valid ? 'pass' : result.status || 'fail';
    const bhResult = result.bodyHash || {};
    statusDiv.className = `dkim-status-badge ${verdictClass(status)}`;
    statusDiv.textContent = verdictLabel(status);

    const verdict = dkimVerdict(dkim, result);
    const headers = dkimHeadersVerified(result);
    const expired = dkimExpired(dkim);
    const keyName = `${dkim.tags.s || ''}._domainkey.${dkim.tags.d || ''}`;
    const key = result.key;
    const keyText = key ? (key.type === 'rsa' ? `RSA, ${key.bits}-bit` : 'Ed25519') : dkim.publicKey ? 'Published' : 'Not found';
    const weakKey = key?.type === 'rsa' && key.bits < 2048;
    const identity = dkim.tags.i && dkim.tags.i !== '@' + dkim.tags.d ? dkim.tags.i : null;

    const checks = [
        bhResult.valid === undefined ? dkimCheckRow(null, 'Body not checked', escapeHtml(result.error || ''))
            : bhResult.valid ? dkimCheckRow(true, 'Body matches what was signed', '')
            : dkimCheckRow(false, 'Body changed after signing', 'Its hash differs from the one in the signature'),
        headers === true ? dkimCheckRow(true, 'Signed headers verify', 'Checked against the key published today')
            : headers === false ? dkimCheckRow(false, 'Signed headers don\'t verify', 'The signature doesn\'t match them with the key published today')
            : dkimCheckRow(null, 'Signed headers not checked', escapeHtml(result.keyError || (result.status === 'unavailable' ? result.error : '') || '')),
        expired ? dkimCheckRow('warn', `Expired on ${escapeHtml(formatUnixTime(dkim.tags.x))}`, 'Receivers ignore signatures past their expiry')
            : dkimCheckRow(true, dkim.tags.x ? `Valid until ${escapeHtml(formatUnixTime(dkim.tags.x))}` : 'No expiry set', ''),
        key ? dkimCheckRow(weakKey ? 'warn' : true, `Key found: ${keyText}`, weakKey ? '2048-bit keys are recommended; 1024-bit keys are considered weak' : `<code>${escapeHtml(keyName)}</code>`)
            : dkimCheckRow(dkim.publicKey ? null : false, dkim.publicKey ? 'Key published' : 'Key not found', `<code>${escapeHtml(keyName)}</code>${result.keyError ? ' · ' + escapeHtml(result.keyError) : ''}`)
    ].join('');

    const dataToVerify = result.details?.dataToVerify || 'Not available.';
    const dnsOutput = dkim.dnsRaw || 'No record';
    const dnsOutputDisplay = escapeHtml(dnsOutput.length > 255 ? dnsOutput.substring(0, 255) + '…' : dnsOutput);

    verificationDiv.innerHTML = `
        <div class="${verdict.cls}">${verdict.text}</div>
        <dl class="facts dkim-facts">
            <div><dt>Signed by</dt><dd class="mono">${escapeHtml(dkim.tags.d || 'unknown')}</dd>
                <dd class="fact-note">${fromRelation(dkim.tags.d)}</dd>
                ${identity ? `<dd class="fact-note">Identity <code>${escapeHtml(identity)}</code></dd>` : ''}</div>
            <div><dt>Signed at</dt><dd>${dkim.tags.t ? escapeHtml(formatUnixTime(dkim.tags.t)) : 'Not stated'}</dd></div>
            <div><dt>Expires</dt><dd${expired ? ' class="dkim-expired"' : ''}>${dkim.tags.x ? escapeHtml(formatUnixTime(dkim.tags.x)) : 'No expiry'}</dd>
                ${expired ? '<dd class="fact-note">Already expired</dd>' : ''}</div>
            <div><dt>Key</dt><dd>${escapeHtml(keyText)}</dd><dd class="fact-note">${escapeHtml(dkim.tags.a || '')}</dd></div>
        </dl>
        <ul class="dkim-checklist">${checks}</ul>
        ${dkimCoverage(dkim, result)}

        <button type="button" class="dkim-advanced-toggle" aria-controls="dkim-tech-${i}" aria-expanded="false">
            ${detailDisclosureIcon}<span>Technical details</span><span class="toggle-meta">hashes, signed data, key</span>
        </button>
        <div id="dkim-tech-${i}" class="hidden">
            <div class="tech-details-grid">
                <div class="tech-detail-card"><span class="tech-label">Body hash (expected)</span><div class="tech-value code">${escapeHtml(bhResult.expected || 'N/A')}</div></div>
                <div class="tech-detail-card"><span class="tech-label">Body hash (calculated)</span><div class="tech-value code">${escapeHtml(bhResult.calculated || 'N/A')}</div></div>
                <div class="tech-detail-card full-width"><span class="tech-label">Canonicalized headers (data signed)</span><pre class="tech-value code scrollable-pre">${escapeHtml(dataToVerify)}</pre></div>
                <div class="tech-detail-card full-width"><span class="tech-label">Public key (p=) in current DNS</span><div class="tech-value code">${escapeHtml(dkim.dnsTags?.p || result.keyError || 'Not available.')}</div></div>
                <div class="tech-detail-card full-width"><span class="tech-label">Signature (b=)</span><div class="tech-value code">${escapeHtml(dkim.tags.b || 'Not available.')}</div></div>
            </div>
        </div>

        <button type="button" class="dkim-advanced-toggle" aria-controls="dkim-raw-${i}" aria-expanded="false">
            ${detailDisclosureIcon}<span>Signature tags</span><span class="toggle-meta">${Object.keys(dkim.tags).length} tags</span>
        </button>
        <div id="dkim-raw-${i}" class="hidden mt-10">
            <div class="tags-grid">${Object.entries(dkim.tags).map(([tag, value]) => `
                <div class="data-card"><div class="data-key">${escapeHtml(tag)}</div><div class="data-value" title="${escapeHtml(value)}">${escapeHtml(value)}</div></div>`).join('')}
            </div>
        </div>

        <button type="button" class="dkim-advanced-toggle" aria-controls="dkim-dns-${i}" aria-expanded="false">
            ${detailDisclosureIcon}<span>Key record</span><span class="toggle-meta">${escapeHtml(keyName)}</span>
        </button>
        <div id="dkim-dns-${i}" class="hidden">
            <div class="dns-command-card">
                <div class="dns-command-label">Key lookup command</div>
                <div class="data-card"><div class="data-value">${escapeHtml(dkim.dnsCommand || 'dig TXT ' + keyName)}</div></div>
                ${dkim.dnsTags ? `
                <div class="dns-command-label">Key record tags</div>
                <div class="tags-grid">${Object.entries(dkim.dnsTags).map(([tag, value]) => `
                    <div class="data-card"><div class="data-key">${escapeHtml(tag)}</div><div class="data-value" title="${escapeHtml(value)}">${escapeHtml(value)}</div></div>`).join('')}
                </div>` : ''}
                <div class="dns-command-label">Raw key record</div>
                <div class="data-card"><div class="data-value" data-copy="${escapeHtml(dnsOutput)}">${dnsOutputDisplay}</div></div>
            </div>
        </div>`;
}

function getHeaderValue(headers, key) {
    return EmailAddress.getHeader(headers, key);
}
