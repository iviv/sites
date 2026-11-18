// --- UI Logic ---

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const errorMsg = document.getElementById('error-msg');
const resultsDiv = document.getElementById('results');
const headersOutput = document.getElementById('headers-output');
const headersSignedToggle = document.getElementById('headers-signed-toggle');
const headersSearch = document.getElementById('headers-search');
const headersRawToggle = document.getElementById('headers-raw-toggle');
const headersCount = document.getElementById('headers-count');
const summaryOutput = document.getElementById('summary-output');
const dkimOutput = document.getElementById('dkim-output');
const spfOutput = document.getElementById('spf-output');
const dmarcOutput = document.getElementById('dmarc-output');
const contentOutput = document.getElementById('content-output');
const domainOutput = document.getElementById('domain-output');
const arcOutput = document.getElementById('arc-output');
const themeSelector = document.getElementById('theme-selector');
const copyToast = document.getElementById('copy-status');

const htmlEntities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => htmlEntities[character]);
}

function verdictClass(result) {
    if (result === 'pass') return 'status-pass';
    if (result === 'offline') return 'status-neutral';
    if (result === 'fail' || result === 'softfail' || result === 'permerror') return 'status-fail';
    return 'status-pending';
}

function formatUnixTime(seconds) {
    return new Date(parseInt(seconds, 10) * 1000).toLocaleString();
}

function verdictLabel(result) {
    return { pending: 'Checking…', none: 'None', unavailable: 'Not verified', offline: 'Offline',
        temperror: 'Temporary error', permerror: 'Policy error' }[result] || result.toUpperCase();
}

// --- Network: every request the page makes goes through fetch, so this one place logs them and offline mode blocks them ---
const offlineMessage = 'offline mode is on';
const network = { offline: false, requests: [] };
try {
    network.offline = localStorage.getItem('emailParserOffline') === '1';
} catch {
    // Without storage the setting lasts until the page is closed.
}
const nativeFetch = window.fetch.bind(window);
window.fetch = (input, init) => {
    if (network.offline) return Promise.reject(new Error(offlineMessage));
    try {
        logRequest(new URL(input instanceof Request ? input.url : String(input), location.href));
    } catch {
        // Logging never stops a request.
    }
    return nativeFetch(input, init);
};

const networkDestinations = [
    { id: 'dns', name: 'Cloudflare DNS', host: 'cloudflare-dns.com',
        sends: 'Domain names: DKIM keys and the SPF, DMARC, MX, BIMI, MTA-STS and TLS reporting records, plus reverse DNS for the sending IP' },
    { id: 'cymru', name: 'Team Cymru, through Cloudflare DNS', host: 'asn.cymru.com', sends: 'Relay IP addresses, to find the network that routes them' },
    { id: 'rir', name: 'IP address registries', host: 'ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC', sends: 'Relay IP addresses, to find who the network is registered to' },
    { id: 'rdap', name: 'rdap.org', host: 'rdap.org', sends: 'The sender\'s domain, to find when it was registered' },
    { id: 'logo', name: 'Brand logo host', host: '', sends: 'A request for the sender\'s logo image, the same for every recipient, when the Summary shows it or you click Show logo' }
];

function logRequest(url, kind = null) {
    let dest = 'other';
    let label = url.host;
    if (kind) {
        dest = kind;
        label = url.href;
    } else if (url.host === 'cloudflare-dns.com') {
        const name = url.searchParams.get('name') || '';
        dest = /\.asn\.cymru\.com$/i.test(name) ? 'cymru' : 'dns';
        label = `${url.searchParams.get('type') || ''} ${name}`;
    } else if (url.host === 'rdap.org') {
        dest = 'rdap';
        label = decodeURIComponent(url.pathname.replace(/^\/domain\//, ''));
    } else if (/^rdap\.|\.rdap\./.test(url.host)) {
        dest = 'rir';
        label = `${url.host} · ${decodeURIComponent(url.pathname.split('/').pop())}`;
    }
    network.requests.push({ dest, label });
    scheduleNetworkUpdate();
}

const networkMenuButton = document.getElementById('network-menu-btn');
const networkPanel = document.getElementById('network-panel');
let offlineSwitch;
function buildNetworkPanel() {
    networkPanel.innerHTML = `
    <div class="network-switch-row">
        <div>
            <div class="network-title" id="offline-title">Offline mode</div>
            <p class="network-help">Blocks every lookup. Checks then use only what's in the email, and what the receiving server recorded is still shown.</p>
        </div>
        <button type="button" class="switch" role="switch" aria-checked="false" aria-labelledby="offline-title"><span class="switch-thumb"></span></button>
    </div>
    <div class="theme-panel-label">What leaves your browser</div>
    <ul class="network-dests">${networkDestinations.map(dest => `
        <li data-dest="${dest.id}">
            <span class="network-dest-name">${escapeHtml(dest.name)}</span>
            <span class="network-count"></span>
            <span class="network-dest-sends">${escapeHtml(dest.sends)}</span>
        </li>`).join('')}
    </ul>
    <p class="network-foot">The email itself never leaves your browser.</p>
    <div class="network-actions">
        <button type="button" class="dkim-advanced-toggle network-log-toggle" aria-controls="network-log" aria-expanded="false">
            ${detailDisclosureIcon}<span>Requests for this email</span><span class="toggle-meta network-log-count"></span>
        </button>
        <ol id="network-log" class="network-log hidden"></ol>
        <button type="button" class="btn btn-secondary network-recheck" title="Run every lookup again for this email">Recheck</button>
    </div>`;
    offlineSwitch = networkPanel.querySelector('.switch');
    offlineSwitch.addEventListener('click', () => setOffline(!network.offline));
    networkPanel.querySelector('.network-recheck').addEventListener('click', () => recheck());
    updateNetworkControls();
}

let networkUpdatePending = false;
function scheduleNetworkUpdate() {
    if (networkUpdatePending) return;
    networkUpdatePending = true;
    requestAnimationFrame(() => {
        networkUpdatePending = false;
        updateNetworkControls();
    });
}

function updateNetworkControls() {
    if (!offlineSwitch) return;
    const offline = network.offline;
    networkMenuButton.classList.toggle('is-offline', offline);
    networkMenuButton.querySelector('.network-label').textContent = offline ? 'Offline' : 'Online';
    networkMenuButton.title = offline ? 'Offline mode: no lookups are made' : 'Network: see what this page looks up';
    networkMenuButton.setAttribute('aria-label', offline ? 'Network: offline mode is on' : 'Network: online');
    offlineSwitch.setAttribute('aria-checked', String(offline));
    const counts = {};
    for (const request of network.requests) counts[request.dest] = (counts[request.dest] || 0) + 1;
    for (const item of networkPanel.querySelectorAll('[data-dest]')) {
        const count = counts[item.dataset.dest] || 0;
        item.querySelector('.network-count').textContent = offline ? 'Blocked' : currentEmail ? `${count} ${count === 1 ? 'request' : 'requests'}` : '';
        item.classList.toggle('is-idle', offline || !count);
    }
    const total = network.requests.length;
    networkPanel.querySelector('.network-log-count').textContent = offline ? 'none, offline' : String(total);
    networkPanel.querySelector('.network-log').innerHTML = network.requests.map(request =>
        `<li><span class="network-log-dest">${escapeHtml(networkDestinations.find(dest => dest.id === request.dest)?.name.split(',')[0] || 'Other')}</span>${escapeHtml(request.label)}</li>`).join('')
        || `<li class="network-log-empty">${offline ? 'Nothing is sent while offline mode is on.' : currentEmail ? 'No requests yet.' : 'Load an email to see its lookups.'}</li>`;
    const recheck = networkPanel.querySelector('.network-recheck');
    recheck.disabled = !lastInput || offline;
    const offlineChip = document.querySelector('.jump-offline');
    if (offlineChip) offlineChip.hidden = !offline;
}

function setOffline(offline) {
    network.offline = offline;
    try {
        localStorage.setItem('emailParserOffline', offline ? '1' : '0');
    } catch {
        // Only persistence is optional.
    }
    updateNetworkControls();
    recheck();
}

function closeNetworkMenu(returnFocus) {
    if (networkPanel.classList.contains('hidden')) return;
    networkPanel.classList.add('hidden');
    networkMenuButton.setAttribute('aria-expanded', 'false');
    if (returnFocus) networkMenuButton.focus();
}

document.addEventListener('click', event => {
    if (!event.target.closest('.network-menu')) closeNetworkMenu(false);
    if (event.target.closest('.go-online-btn')) setOffline(false);
    if (event.target.closest('.recheck-btn')) recheck();
});
document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeNetworkMenu(true);
});

// While offline, a lookup that couldn't run reads as Offline rather than as an error.
function offlineStatus(status) {
    return network.offline && (status === 'temperror' || status === 'unavailable') ? 'offline' : status;
}

function offlineVerdict(text) {
    return `${text} Offline mode is on. <button type="button" class="link-toggle go-online-btn">Turn it off and recheck</button>`;
}

// Run the current email again, keeping the reader's place on the page.
let lastInput = null;
function recheck() {
    if (!lastInput) return;
    const top = scrollY;
    const { input, source } = lastInput;
    IpAddress.clearCache();
    processRawEmail(input, startRun(), source);
    scrollTo({ top, behavior: 'instant' });
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
const fileIcon = `<svg width="20" height="20" ${iconAttrs}><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/></svg>`;
const pasteKey = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent) ? '⌘V' : 'Ctrl+V';

// Once an email is loaded the drop zone shrinks to one line, so results start near the top.
const loadedBar = document.createElement('div');
loadedBar.className = 'loaded-info';
loadedBar.innerHTML = `
    <span class="loaded-icon" aria-hidden="true">${fileIcon}</span>
    <span class="loaded-text"><span class="loaded-name"></span><span class="loaded-meta"></span></span>
    <span class="loaded-actions">
        <button type="button" class="btn btn-secondary loaded-paste">Paste text</button>
        <button type="button" class="btn btn-primary loaded-choose">Choose file</button>
    </span>`;
dropZone.appendChild(loadedBar);
document.querySelector('.drop-hint').textContent = `or press ${pasteKey} anywhere on the page to paste one`;

function formatBytes(bytes) {
    return bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1048576).toFixed(1)} MB`;
}

function showLoaded(source) {
    loadedBar.querySelector('.loaded-name').textContent = source.name;
    loadedBar.querySelector('.loaded-meta').textContent = `${formatBytes(source.size)} · drop or paste (${pasteKey}) another email anywhere`;
    dropZone.classList.add('is-compact');
}

function expandDropZone(focusPaste) {
    dropZone.classList.remove('is-compact');
    if (focusPaste) {
        pasteInput.value = '';
        pasteInput.focus();
    }
}

loadedBar.querySelector('.loaded-paste').addEventListener('click', event => {
    event.stopPropagation();
    expandDropZone(true);
});
loadedBar.querySelector('.loaded-choose').addEventListener('click', event => {
    event.stopPropagation();
    fileInput.click();
});

// Files can be dropped anywhere on the page, not only on the drop zone.
document.addEventListener('dragover', event => {
    if (![...(event.dataTransfer?.types || [])].includes('Files')) return;
    event.preventDefault();
    dropZone.classList.add('hover');
});
document.addEventListener('dragleave', event => {
    if (!event.relatedTarget) dropZone.classList.remove('hover');
});
document.addEventListener('drop', event => {
    if (event.defaultPrevented || !event.dataTransfer?.files.length) return;
    event.preventDefault();
    dropZone.classList.remove('hover');
    processFile(event.dataTransfer.files[0]);
});

// Pasting an email anywhere (outside text fields) analyzes it straight away.
function looksLikeEmail(text) {
    return (text.match(/^[A-Za-z][A-Za-z0-9-]*:[ \t]*\S/gm) || []).length >= 2;
}

document.addEventListener('paste', event => {
    if (event.target instanceof Element && event.target.closest('input, textarea, [contenteditable]')) return;
    const file = [...(event.clipboardData?.files || [])][0];
    if (file) {
        event.preventDefault();
        processFile(file);
        return;
    }
    const text = event.clipboardData?.getData('text/plain') || '';
    if (!text.trim()) return;
    event.preventDefault();
    if (!looksLikeEmail(text)) {
        showToast(false, 'That doesn\'t look like an email. Paste the full message source, starting with its headers.');
        return;
    }
    pasteInput.value = text;
    processRawEmail(text, startRun(), { name: 'Pasted email', size: new Blob([text]).size });
});
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
    headers: { rank: 4, label: 'Covered by a DKIM signature whose headers verify; its body changed after signing or wasn\'t included', short: 'Headers verify, body doesn\'t', icon: statusIcon('ring') },
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
    if (!event.target.closest('.paste-container, .loaded-actions')) fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    const files = e.target.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
    // Reset value to allow re-selecting the same file
    fileInput.value = '';
});

let headersSearchTimer;
headersSearch.addEventListener('input', () => {
    clearTimeout(headersSearchTimer);
    headersSearchTimer = setTimeout(displayHeaders, 120);
});
headersRawToggle.addEventListener('click', () => {
    headersRawToggle.setAttribute('aria-pressed', String(headersRawToggle.getAttribute('aria-pressed') !== 'true'));
    displayHeaders();
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
buildNetworkPanel();
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
    } else if (button.classList.contains('link-toggle')) {
        button.textContent = expanded ? 'Hide links' : 'Show links';
    } else if (button.classList.contains('toggle-all-spf')) {
        button.querySelector('span').textContent = expanded ? 'Collapse all' : 'Expand all';
    }
});

// Every value field copies itself on click (or Enter/Space when focused) and confirms with a toast.
const copyableSelector = [
    '.data-card', '.subject-text', '.facts dd.mono', '.relay-details dd', '.route-host', '.route-ip', '.route-embedded', '.route-from', '.dmarc-domain', '.dmarc-address', '.spf-token', '.spf-ptr-name', '.net-owner-name', '.link-url', '.link-domain', '.dkim-domain',
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
function showToast(ok, message) {
    copyToast.innerHTML = `${ok ? copiedIcon : copyFailedIcon}<span>${escapeHtml(message)}</span>`;
    copyToast.classList.toggle('is-error', !ok);
    copyToast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => copyToast.classList.remove('visible'), 2600);
}

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
        if (run === latestRun) await processRawEmail(bytes, run, { name: file.name, size: file.size });
    } catch (error) {
        showError(run, 'Could not read the file', error);
    }
}

function startRun() {
    clearTimeout(pasteTimeout);
    currentEmail = null;
    bimiCache.clear();
    network.requests = [];
    scheduleNetworkUpdate();
    errorMsg.classList.add('hidden');
    errorMsg.textContent = '';
    resultsDiv.classList.add('hidden');
    return ++latestRun;
}

function showError(run, message, error) {
    if (run !== latestRun) return;
    errorMsg.textContent = message + ': ' + error.message;
    errorMsg.classList.remove('hidden');
    expandDropZone(false);
    console.error(error);
}

// source names a file or a page-wide paste; typing in the text box passes none, so the box stays open.
async function processRawEmail(input, run, source = null) {
    if (run !== latestRun) return;
    try {
        const parser = new EmailParser();
        const email = typeof input === 'string' ? parser.parse(input) : parser.parseBytes(input);
        currentEmail = email;
        lastInput = { input, source };
        const dkimParser = new DkimParser();
        email.dkim = new DkimValidator().getRawHeaderFields(email.rawHeaders)
            .filter(field => field.key === 'dkim-signature')
            .map((field, index) => dkimParser.parse(field.raw.slice(field.raw.indexOf(':') + 1), index));

        summaryState.checks = {};
        summaryState.arc = null;
        summaryState.reported = reportedAtDelivery(email);
        summaryState.spam = HeaderInsights.spamVerdicts(headerFieldList(email));
        Object.assign(summaryState, { bimi: null, dmarcDto: null, logoImg: null, logoFailed: false });
        for (const id of Object.keys(jumpState)) delete jumpState[id];
        for (const id of ['dkim', 'spf', 'dmarc', 'arc']) jumpState['section-' + id] = { result: 'pending', note: 'checking' };
        jumpActive = null;
        headersSearch.value = '';
        displaySummary();
        displayContent(email);
        displayDomain(email, run);
        displayHeaders();
        displayRelay(traceHeaders(email), getHeaderValue(email.headers, 'Date'), relayHints(email));
        displayDkim(email.dkim);
        displaySpfLoading();
        displayDmarcLoading();
        arcOutput.innerHTML = '<p class="note">Checking the ARC chain…</p>';
        renderJumpBar();
        const senderDomain = fromDomainOf(email);
        if (senderDomain && !network.offline) {
            bimiLookup(senderDomain).then(result => {
                if (run !== latestRun) return;
                summaryState.bimi = { ...result, domain: senderDomain };
                displaySummary();
                updateBimiNote();
            });
        }

        resultsDiv.classList.remove('hidden');
        if (source) showLoaded(source);
        scheduleJumpUpdate();
        await runVerification(email, run);
    } catch (err) {
        showError(run, 'Could not analyze the email', err);
    }
}

// --- Jump bar: section links that stay at the top while scrolling, each with its section's status ---
const jumpBar = document.getElementById('jump-bar');
const jumpLabels = { 'section-summary': 'Summary', 'section-relay': 'Hops', 'section-content': 'Content', 'section-dmarc': 'DMARC',
    'section-spf': 'SPF', 'section-dkim': 'DKIM', 'section-arc': 'ARC', 'section-domain': 'Domain', 'section-headers': 'Headers' };
const jumpState = {};
let jumpActive = null;

function jumpTone(result) {
    if (!result) return null;
    if (result === 'pending' || result === 'pass') return result;
    if (['fail', 'softfail', 'permerror'].includes(result)) return 'fail';
    if (['temperror', 'unavailable', 'expired', 'warn'].includes(result)) return 'warn';
    return 'neutral';
}

function setJumpStatus(id, result, note = null) {
    const next = result ? { result, note } : null;
    if (JSON.stringify(jumpState[id] ?? null) === JSON.stringify(next)) return;
    if (next) jumpState[id] = next;
    else delete jumpState[id];
    renderJumpBar();
}

function jumpSections() {
    return [...resultsDiv.querySelectorAll(':scope > section.section[id]')];
}

function renderJumpBar() {
    jumpBar.innerHTML = jumpSections().map(section => {
        const label = jumpLabels[section.id] || section.id;
        const state = jumpState[section.id];
        const tone = jumpTone(state?.result);
        const said = state ? state.note || verdictLabel(state.result).toLowerCase() : '';
        return `<a class="jump-link" href="#${section.id}" data-target="${section.id}"${section.id === jumpActive ? ' aria-current="location"' : ''}
            ${said ? ` aria-label="${label}, ${escapeHtml(said)}" title="${label}: ${escapeHtml(said)}"` : ''}>${tone ? `<span class="jump-dot is-${tone}" aria-hidden="true"></span>` : ''}${label}</a>`;
    }).join('') + `<button type="button" class="jump-offline"${network.offline ? '' : ' hidden'} title="Offline mode is on. Open the network settings">
        <span class="network-dot" aria-hidden="true"></span>Offline</button>`;
}

function updateJumpActive() {
    if (resultsDiv.classList.contains('hidden')) return;
    const bar = jumpBar.getBoundingClientRect();
    jumpBar.classList.toggle('is-stuck', bar.top <= 0.5 && scrollY > 0);
    const sections = jumpSections().filter(section => section.offsetParent);
    let active = null;
    for (const section of sections) {
        if (section.getBoundingClientRect().top <= bar.bottom + 24) active = section.id;
        else break;
    }
    if (innerHeight + scrollY >= document.documentElement.scrollHeight - 2 && sections.length) active = sections.at(-1).id;
    if (active === jumpActive) return;
    jumpActive = active;
    for (const link of jumpBar.querySelectorAll('.jump-link')) {
        if (link.dataset.target === active) link.setAttribute('aria-current', 'location');
        else link.removeAttribute('aria-current');
    }
    // On narrow screens the bar scrolls sideways; keep the current section's link in view.
    const link = jumpBar.querySelector('[aria-current]');
    if (link && (link.offsetLeft < jumpBar.scrollLeft || link.offsetLeft + link.offsetWidth > jumpBar.scrollLeft + jumpBar.clientWidth)) {
        jumpBar.scrollTo({ left: link.offsetLeft - 12, behavior: 'smooth' });
    }
}

let jumpFrame = 0;
function scheduleJumpUpdate() {
    if (!jumpFrame) jumpFrame = requestAnimationFrame(() => {
        jumpFrame = 0;
        updateJumpActive();
    });
}
addEventListener('scroll', scheduleJumpUpdate, { passive: true });
addEventListener('resize', scheduleJumpUpdate);

jumpBar.addEventListener('click', event => {
    if (event.target.closest('.jump-offline')) {
        // Keep the page-level handler from closing the menu this opens.
        event.stopPropagation();
        scrollTo({ top: 0, behavior: 'instant' });
        if (networkPanel.classList.contains('hidden')) networkMenuButton.click();
        return;
    }
    const link = event.target.closest('.jump-link');
    if (!link) return;
    event.preventDefault();
    const section = document.getElementById(link.dataset.target);
    if (!section) return;
    section.querySelector('.toggle-section-btn[aria-expanded="false"]')?.click();
    const motion = matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth';
    section.scrollIntoView({ behavior: motion, block: 'start' });
    section.setAttribute('tabindex', '-1');
    section.focus({ preventScroll: true });
});

// --- Summary: the message at a glance, its verdict, and each check now vs at delivery ---
const summaryState = { checks: {}, reported: null };

function firstHeader(email, name) {
    const value = getHeaderValue(email.headers, name);
    return Array.isArray(value) ? value[0] : value;
}

// What the receiving server recorded, from the topmost (most recent) Authentication-Results header.
function reportedAtDelivery(email) {
    const dto = new ServerValidationParser().parse(getHeaderValue(email.headers, 'Authentication-Results'));
    const top = dto.headers[0] || null;
    const byMethod = {};
    for (const method of ['dkim', 'spf', 'dmarc']) {
        const entries = top ? top.results.filter(entry => entry.method === method) : [];
        if (!entries.length) continue;
        const passed = entries.filter(entry => entry.result === 'pass').length;
        const [first] = entries;
        const note = method === 'dkim'
            ? (entries.length > 1 ? `${passed} of ${entries.length} signatures passed` : first.props['header.d'] || (first.props['header.i'] || '').replace(/^.*@/, ''))
            : method === 'spf' ? (first.props['smtp.mailfrom'] || '').replace(/^.*@/, '')
            : (first.comment?.match(/\bp=(\w+)/i)?.[1] ? 'policy ' + first.comment.match(/\bp=(\w+)/i)[1].toLowerCase() : '');
        byMethod[method] = { result: passed ? 'pass' : first.result, note };
    }
    return { dto, top, byMethod };
}

function fromDomainOf(email) {
    const from = firstHeader(email, 'From');
    const mailboxes = from ? EmailAddress.parseMailboxes(from) : [];
    return mailboxes.length === 1 ? mailboxes[0].domain.toLowerCase() : null;
}

// BIMI: the From domain's record, or its organization's. One lookup per run, shared by the Summary and Sender Domain.
const bimiCache = new Map();
function bimiLookup(domain) {
    if (!bimiCache.has(domain)) {
        const org = registrableDomain(domain) || domain;
        bimiCache.set(domain, Promise.all([txtRecords('default._bimi.' + domain), org !== domain ? txtRecords('default._bimi.' + org) : Promise.resolve([])])
            .then(([own, parent]) => {
                if (own === null && parent === null) return { error: true, record: null };
                const record = (own || []).find(value => /^v=BIMI1/i.test(value)) || (parent || []).find(value => /^v=BIMI1/i.test(value)) || null;
                if (!record) return { record: null };
                const { tags } = EmailDns.parseTags(record);
                return { record, tags, logo: tags.l && /^https:\/\//i.test(tags.l) ? tags.l : null, authority: tags.a && /^https:\/\//i.test(tags.a) ? tags.a : null };
            }));
    }
    return bimiCache.get(domain);
}

// Mail clients show a BIMI logo only when DMARC passes under a policy that quarantines or rejects all failing mail.
function bimiStatus() {
    const bimi = summaryState.bimi;
    const dmarc = summaryState.dmarcDto;
    if (!bimi?.logo || !dmarc) return null;
    const subdomain = dmarc.fetchedDomain && dmarc.fetchedDomain !== dmarc.domain;
    const policy = String((subdomain ? dmarc.tags.sp || dmarc.tags.p : dmarc.tags.p) || '').toLowerCase();
    const partial = dmarc.tags.pct && dmarc.tags.pct !== '100';
    const enforced = ['quarantine', 'reject'].includes(policy) && !partial;
    const then = summaryState.reported?.byMethod.dmarc?.result;
    const passed = dmarc.result === 'pass' || then === 'pass';
    const failed = !passed && (dmarc.result === 'fail' || then === 'fail');
    return { bimi, policy, partial, enforced, passed, failed, show: enforced && passed && !network.offline };
}

function updateBimiNote() {
    const slot = document.getElementById('bimi-eligibility');
    if (!slot) return;
    const status = bimiStatus();
    slot.textContent = !status ? ''
        : status.show ? 'This message qualifies: DMARC passed under a policy that blocks failures, so mail clients that support BIMI can show the logo.'
        : status.failed ? 'This message failed DMARC, so mail clients won\'t show the logo.'
        : !status.enforced ? `Mail clients won't show it: the DMARC policy is ${status.policy ? `p=${status.policy}` : 'missing'}${status.partial ? ` and covers only ${summaryState.dmarcDto.tags.pct}% of mail` : ''}, and BIMI needs quarantine or reject for all mail.`
        : 'Mail clients won\'t show it, because DMARC couldn\'t be confirmed for this message.';
    slot.hidden = !slot.textContent;
}

function attachSummaryLogo(url) {
    const slot = summaryOutput.querySelector('[data-logo-slot]');
    if (!slot || network.offline) return;
    if (summaryState.logoImg?.dataset.src !== url) {
        const image = new Image(48, 48);
        image.alt = 'Brand logo';
        image.decoding = 'async';
        image.referrerPolicy = 'no-referrer';
        image.dataset.src = url;
        // An <img> never runs scripts inside an SVG, so the logo is safe to show.
        image.addEventListener('error', () => {
            summaryState.logoFailed = true;
            displaySummary();
        });
        image.src = url;
        logRequest(new URL(url), 'logo');
        summaryState.logoImg = image;
    }
    slot.appendChild(summaryState.logoImg);
}

const spamTones = { pass: 'status-pass', fail: 'status-fail', warn: 'status-pending', neutral: 'status-neutral' };
function spamSummary(spam) {
    if (!spam) return '';
    return `
        <div class="summary-spam">
            <span class="summary-spam-label">Spam filter${spam.provider ? ` · ${escapeHtml(spam.provider)}` : ''}</span>
            <span class="summary-spam-items">${spam.items.map(item => `
                <span class="summary-spam-item" title="${escapeHtml(item.title)}"><span class="${spamTones[item.tone]}">${escapeHtml(item.label)}</span>${item.detail
                    ? `<span class="summary-then-note">${escapeHtml(item.detail)}</span>` : ''}</span>`).join('')}</span>
        </div>`;
}

function setSummaryCheck(check, result, note) {
    summaryState.checks[check] = { result, note };
    setJumpStatus('section-' + check, result, note);
    displaySummary();
}

function dkimSummaryNote(dkimResults) {
    if (!dkimResults.length) return 'No signature';
    const verified = [...new Set(dkimResults.filter(({ result }) => result.valid).map(({ dkim }) => dkim.tags.d))];
    if (verified.length) return 'Verified for ' + verified.join(', ');
    if (dkimResults.some(({ result }) => result.bodyMissing && result.headersVerified === true)) return 'Headers verify; body not provided';
    if (dkimResults.some(({ result }) => result.headersVerified === true || result.bodyHash?.valid === false)) return 'Body changed after signing';
    if (network.offline && dkimResults.some(({ result }) => result.status === 'temperror')) return 'Keys not looked up';
    if (dkimResults.some(({ result }) => result.status === 'expired')) return 'Signature expired';
    return 'Signature doesn\'t verify';
}

function spfSummaryNote(spf) {
    const ip = spf.senderIp ? normalizeIp(spf.senderIp) : 'The sending IP';
    switch (spf.result) {
        case 'pass': return `${ip} allowed for ${spf.domain}`;
        case 'fail': case 'softfail': return `${ip} not allowed for ${spf.domain}`;
        case 'neutral': return `${spf.domain} takes no position on ${ip}`;
        case 'none': return `${spf.domain} has no SPF record`;
        default: return network.offline ? 'Record not looked up' : 'Not checked';
    }
}

function dmarcSummaryNote(dmarc) {
    switch (dmarc.result) {
        case 'pass': return 'Passed via ' + dmarc.passedBy.join(' and ');
        case 'fail': return 'No passing check matches the From domain';
        case 'unavailable': return 'Can\'t be confirmed from this email';
        case 'none': return 'No DMARC policy';
        case 'temperror': return network.offline ? 'Policy not looked up' : 'DNS error';
        default: return '';
    }
}

function summaryVerdict(fromDomain, reported) {
    const dmarc = summaryState.checks.dmarc;
    const domain = fromDomain ? `<code>${escapeHtml(fromDomain)}</code>` : 'the From domain';
    const delivered = reported.byMethod.dmarc;
    const service = `<code>${escapeHtml(reported.top?.service || 'the receiving server')}</code>`;
    const atDelivery = !delivered ? ''
        : delivered.result === dmarc?.result ? ` ${service} reported the same at delivery.`
        : ` At delivery ${service} reported DMARC <span class="${verdictClass(delivered.result)}">${escapeHtml(verdictLabel(delivered.result))}</span>.`;
    if (!dmarc) return ['is-neutral', network.offline ? 'Checking what can be checked offline…' : 'Checking DKIM, SPF and DMARC…'];
    if (network.offline) return ['is-neutral', offlineVerdict(`Nothing was looked up, so DKIM, SPF and DMARC can't be confirmed.${atDelivery}`)];
    switch (dmarc.result) {
        case 'pass': return ['is-pass', `Authenticated: DMARC passed for ${domain}, ${escapeHtml(dmarc.note.replace(/^Passed/, 'passed').replace(/^passed via/, 'via'))}.${atDelivery}`];
        case 'fail': return ['is-fail', `Not authenticated: DMARC failed for ${domain}.${atDelivery}`];
        case 'unavailable': return ['is-warn', `Couldn't be fully verified from this email.${atDelivery}`];
        case 'none': return ['is-neutral', `${domain} publishes no DMARC policy, so only DKIM and SPF apply.${atDelivery}`];
        case 'temperror': return ['is-warn', 'A DNS lookup failed, so the checks are incomplete. <button type="button" class="link-toggle recheck-btn">Recheck</button>'];
        default: return ['is-neutral', escapeHtml(verdictLabel(dmarc.result))];
    }
}

function reportedDetails(reported) {
    return reported.dto.headers.map((header, position) => `
        <h4>${escapeHtml(header.service || 'Unknown server')}${position === 0 && reported.dto.headers.length > 1 ? ' · most recent' : ''}</h4>
        <table class="reported-results"><tbody>
            ${header.results.map(entry => `
            <tr>
                <th scope="row">${escapeHtml(entry.method.toUpperCase())}</th>
                <td><span class="${verdictClass(entry.result)}">${escapeHtml(verdictLabel(entry.result))}</span></td>
                <td>${Object.entries(entry.props).map(([key, value]) =>
                    `<span class="reported-prop">${escapeHtml(key)}=<span class="reported-value">${escapeHtml(value)}</span></span>`).join('')}
                    ${entry.comment ? checkNote(escapeHtml(entry.comment)) : ''}</td>
            </tr>`).join('') || '<tr><td colspan="3" class="check-note">No results in this header.</td></tr>'}
        </tbody></table>
        <div class="data-card"><div class="data-value" data-copy="Authentication-Results: ${escapeHtml(header.raw)}">${escapeHtml(header.raw)}</div></div>`).join('');
}

function displaySummary() {
    const email = currentEmail;
    if (!email) return;
    const reported = summaryState.reported || reportedAtDelivery(email);
    const subject = firstHeader(email, 'Subject');
    const from = firstHeader(email, 'From');
    const to = firstHeader(email, 'To');
    const replyTo = firstHeader(email, 'Reply-To');
    const date = firstHeader(email, 'Date');
    const fromMailboxes = from ? EmailAddress.parseMailboxes(from) : [];
    const fromDomain = fromMailboxes.length === 1 ? fromMailboxes[0].domain : null;
    const replyMailbox = replyTo ? EmailAddress.parseMailboxes(replyTo)[0] : null;
    const showReplyTo = replyMailbox && replyMailbox.address.toLowerCase() !== (fromMailboxes[0]?.address || '').toLowerCase();
    const replyElsewhere = showReplyTo && fromDomain && replyMailbox.domain.toLowerCase() !== fromDomain.toLowerCase();
    const sentAt = date ? parseMailDate(date) : NaN;
    const [tone, verdict] = summaryVerdict(fromDomain, reported);
    const checked = Boolean(summaryState.checks.dmarc);
    setJumpStatus('section-summary', checked ? { 'is-pass': 'pass', 'is-fail': 'fail', 'is-warn': 'warn' }[tone] || 'neutral' : 'pending',
        checked ? plainText(verdict).replace(/\s+(Turn it off and recheck|Recheck)$/, '') : 'checking');
    const wasOpen = document.getElementById('summary-reported') && !document.getElementById('summary-reported').classList.contains('hidden');

    const tiles = [['dkim', 'DKIM'], ['spf', 'SPF'], ['dmarc', 'DMARC']].map(([id, label]) => {
        const now = summaryState.checks[id];
        const then = reported.byMethod[id];
        return `
            <a class="summary-check" href="#section-${id}" title="Go to the ${label} section">
                <span class="summary-check-head">
                    <span class="summary-check-name">${label}</span>
                    <span class="${verdictClass(now?.result || 'pending')} summary-pill">${escapeHtml(verdictLabel(now?.result || 'pending'))}</span>
                </span>
                <span class="summary-check-note">${escapeHtml(now?.note || 'Checking…')}</span>
                <span class="summary-check-then">At delivery ${then
                    ? `<span class="${verdictClass(then.result)}">${escapeHtml(verdictLabel(then.result))}</span>${then.note ? ` <span class="summary-then-note">${escapeHtml(then.note)}</span>` : ''}`
                    : '<span class="summary-then-note">not recorded</span>'}</span>
            </a>`;
    }).join('');

    const logo = bimiStatus();
    const subjectHtml = `<div class="subject-text" title="${escapeHtml(subject ? decodeMimeWords(subject) : '')}">${escapeHtml(subject ? decodeMimeWords(subject) : '(No subject)')}</div>`;
    const logoNote = logo?.show ? `Brand logo (BIMI) for <code>${escapeHtml(logo.bimi.domain)}</code> · ${summaryState.logoFailed ? 'the image couldn\'t be loaded'
        : logo.bimi.authority ? 'mark certificate published, not verified here' : 'no mark certificate, so Gmail and Apple Mail won\'t show it'}` : '';
    summaryOutput.innerHTML = `
        ${logo?.show ? `
        <div class="summary-head">
            ${summaryState.logoFailed ? '' : '<span class="summary-logo" data-logo-slot></span>'}
            <div class="summary-head-text">${subjectHtml}<p class="summary-logo-note">${logoNote}</p></div>
        </div>` : subjectHtml}
        <dl class="facts summary-facts">
            <div><dt>From</dt><dd class="mono summary-address">${from ? breakable(decodeMimeWords(from)) : 'Unknown'}</dd></div>
            <div><dt>To</dt><dd class="mono summary-address">${to ? breakable(decodeMimeWords(to)) : 'Unknown'}</dd></div>
            <div><dt>Sent</dt><dd>${Number.isNaN(sentAt) ? escapeHtml(date || 'Unknown') : escapeHtml(new Date(sentAt).toLocaleString())}</dd></div>
            ${showReplyTo ? `<div><dt>Reply-To</dt><dd class="mono summary-address">${breakable(decodeMimeWords(replyTo))}</dd>
                <dd class="fact-note${replyElsewhere ? ' summary-reply-elsewhere' : ''}">${replyElsewhere
                    ? `Replies go to a different domain (<code>${escapeHtml(replyMailbox.domain)}</code>) than From`
                    : 'A different address on the same domain as From'}</dd></div>` : ''}
        </dl>
        ${email.headersOnly ? '<p class="note summary-headers-only">Only headers were provided, so checks that need the message body are skipped.</p>' : ''}
        <div class="summary-verdict ${tone}">${verdict}</div>
        ${logo?.failed ? `<p class="note summary-bimi-warning"><code>${escapeHtml(logo.bimi.domain)}</code> publishes a brand logo, but this message failed DMARC,
            so mail clients won't show it. Be wary of anything in it that looks branded.</p>` : ''}
        <div class="summary-checks">${tiles}</div>
        ${spamSummary(summaryState.spam)}
        ${reported.top ? `
        <button type="button" class="dkim-advanced-toggle" aria-controls="summary-reported" aria-expanded="${wasOpen}">
            ${detailDisclosureIcon}<span>Reported at delivery</span>
            <span class="toggle-meta">${escapeHtml(reported.top.service || '')} · ${reported.top.results.length} results${reported.dto.headers.length > 1 ? ` · ${reported.dto.headers.length} headers` : ''}${arcSealed(reported) ? ' · ARC-sealed' : ''}</span>
        </button>
        <div id="summary-reported" class="${wasOpen ? '' : 'hidden'}">${reportedDetails(reported)}</div>`
            : '<p class="note summary-unreported">No Authentication-Results header, so there\'s no record of what the receiving server decided.</p>'}`;
    if (logo?.show && !summaryState.logoFailed) attachSummaryLogo(logo.bimi.logo);
}

// --- Plain-text report, for pasting into a ticket or message ---
function plainText(html) {
    const box = document.createElement('div');
    box.innerHTML = html;
    return box.textContent.replace(/\s+/g, ' ').trim();
}

async function buildReport() {
    const email = currentEmail;
    const reported = summaryState.reported || reportedAtDelivery(email);
    const header = name => {
        const value = firstHeader(email, name);
        return value ? decodeMimeWords(value).replace(/\s+/g, ' ').trim() : null;
    };
    const fromMailboxes = header('From') ? EmailAddress.parseMailboxes(firstHeader(email, 'From')) : [];
    const fromDomain = fromMailboxes.length === 1 ? fromMailboxes[0].domain : null;
    const sentAt = header('Date') ? parseMailDate(header('Date')) : NaN;
    const lines = ['Email authentication report', ''];
    lines.push(`Subject:  ${header('Subject') || '(No subject)'}`, `From:     ${header('From') || 'Unknown'}`, `To:       ${header('To') || 'Unknown'}`);
    if (header('Reply-To')) lines.push(`Reply-To: ${header('Reply-To')}`);
    lines.push(`Sent:     ${Number.isNaN(sentAt) ? header('Date') || 'Unknown' : new Date(sentAt).toLocaleString()}`);
    if (email.headersOnly) lines.push('', 'Only headers were provided; checks that need the body were skipped.');
    lines.push('', `Verdict: ${plainText(summaryVerdict(fromDomain, reported)[1])}`, '');
    for (const [id, label] of [['dkim', 'DKIM'], ['spf', 'SPF'], ['dmarc', 'DMARC']]) {
        const now = summaryState.checks[id];
        const then = reported.byMethod[id];
        lines.push(`${label.padEnd(6)} ${verdictLabel(now?.result || 'pending')}${now?.note ? ' - ' + now.note : ''}`
            + (then ? ` (at delivery: ${verdictLabel(then.result)}${then.note ? ', ' + then.note : ''})` : ''));
    }

    const spam = summaryState.spam;
    if (spam) lines.push(`Spam filter${spam.provider ? ` (${spam.provider})` : ''}: ${spam.items.map(item => item.label + (item.detail ? ` (${item.detail})` : '')).join(', ')}`);

    const route = relayState.route;
    if (route?.steps.length) {
        lines.push('', `Route, oldest first (${route.zone ? 'times in ' + route.zone : 'local time'}):`);
        if (route.sent) lines.push(`  ${hopTime(route.sent, route).padEnd(12)} Sent (Date header)`);
        for (const step of route.steps) {
            const group = route.groups.findIndex(entry => entry.steps.includes(step));
            const role = orgRole(group, route);
            const parts = [
                step.source === 'Reported' ? '' : hopTime(step, route), step.host,
                step.delay !== null && step.delay !== undefined ? formatDuration(step.delay) : '',
                step.ip ? normalizeIp(step.ip) : '', step.tls || '',
                route.groups[group]?.org ? `[${route.groups[group].org}${role ? ', ' + role : ''}]` : ''
            ];
            lines.push(`  ${parts[0].padEnd(12)} ${parts.slice(1).filter(Boolean).join('  ')}`);
        }
        const entry = route.steps.find(step => step.entry);
        if (entry?.ip) {
            // The owner lookup is normally cached already; don't hold the copy up waiting for it.
            const owner = await Promise.race([IpAddress.networkOwner(entry.ip), new Promise(resolve => setTimeout(resolve, 1500, null))]);
            const name = owner && (owner.organization || owner.asName);
            lines.push('', `Sending network: ${normalizeIp(entry.ip)}${name ? ` - ${name}${owner.asn ? ' (AS' + owner.asn + ')' : ''}` : ''}`);
        }
    }
    lines.push('', `Checked ${new Date().toLocaleString()} with Email Parser & DKIM Validator; DNS records as published at that time.`);
    return lines.join('\n');
}

document.getElementById('copy-report').addEventListener('click', async () => {
    if (!currentEmail) return;
    const copied = await writeClipboard(await buildReport());
    showToast(copied, copied ? 'Report copied' : 'Couldn\'t copy the report');
});

// --- Message content: readable text, links and attachments. The email's HTML is only ever
// parsed into an inert document (no scripts run, no images load); it is never put into the page.
const clickTrackers = [
    ['list-manage.com', 'Mailchimp'], ['mailchi.mp', 'Mailchimp'], ['mcsv.net', 'Mailchimp'], ['sendgrid.net', 'SendGrid'],
    ['mailgun.org', 'Mailgun'], ['exct.net', 'Salesforce Marketing Cloud'], ['klclick.com', 'Klaviyo'], ['klclick1.com', 'Klaviyo'],
    ['klclick2.com', 'Klaviyo'], ['awstrack.me', 'Amazon SES'], ['hubspotlinks.com', 'HubSpot'], ['mandrillapp.com', 'Mailchimp Transactional'],
    ['sparkpostmail.com', 'SparkPost'], ['ct.sendgrid.net', 'SendGrid'], ['safelinks.protection.outlook.com', 'Microsoft Safe Links'],
    ['urldefense.com', 'Proofpoint URL Defense'], ['cmail19.com', 'Campaign Monitor'], ['cmail20.com', 'Campaign Monitor']
];
const riskyExtensions = {
    code: ['exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'bat', 'cmd', 'com', 'msi', 'ps1', 'jar', 'hta', 'lnk', 'wsf', 'cpl', 'reg', 'app', 'dmg', 'pkg'],
    browser: ['html', 'htm', 'shtml', 'svg', 'xhtml'],
    macro: ['docm', 'xlsm', 'pptm', 'xlam', 'dotm'],
    container: ['iso', 'img', 'vhd', 'vhdx', 'zip', 'rar', '7z', 'gz', 'tar', 'cab']
};

function htmlToText(html) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    doc.querySelectorAll('script, style, head, noscript, template, title').forEach(node => node.remove());
    doc.querySelectorAll('br').forEach(node => node.replaceWith('\n'));
    doc.querySelectorAll('p, div, tr, li, h1, h2, h3, h4, h5, h6, table, section, article, header, footer, blockquote')
        .forEach(node => node.append('\n'));
    return cleanText(doc.body?.textContent || '');
}

// Removes invisible padding characters that marketing emails use, and collapses whitespace.
function cleanText(text) {
    return text.replace(/[\u200b-\u200f\u034f\u00ad\u2060\ufeff\u2007\u2028]/g, '')
        .replace(/[ \t ]+/g, ' ')
        .split('\n').map(line => line.trim()).join('\n')
        .replace(/\n{3,}/g, '\n\n').trim();
}

function looksLikeDomain(text) {
    const match = text.trim().match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$/i);
    return match ? match[1].toLowerCase() : null;
}

function collectLinks(htmlPart, textPart) {
    const links = [];
    const images = [];
    if (htmlPart) {
        const doc = new DOMParser().parseFromString(htmlPart.text, 'text/html');
        for (const anchor of doc.querySelectorAll('a[href], area[href]')) {
            links.push({ href: anchor.getAttribute('href').trim(), text: cleanText(anchor.textContent || anchor.getAttribute('alt') || '') });
        }
        for (const image of doc.querySelectorAll('img[src]')) {
            const width = image.getAttribute('width'), height = image.getAttribute('height');
            images.push({ src: image.getAttribute('src').trim(), pixel: (width === '1' || width === '0') && (height === '1' || height === '0') });
        }
    } else if (textPart) {
        for (const [href] of textPart.text.matchAll(/https?:\/\/[^\s<>()"']+/gi)) links.push({ href: href.replace(/[.,;:!?]+$/, ''), text: '' });
    }
    return { links, images };
}

function linkGroups(links, fromDomain) {
    const groups = new Map();
    const other = [];
    for (const link of links) {
        let url;
        try {
            url = new URL(link.href);
        } catch {
            continue;
        }
        if (!/^https?:$/.test(url.protocol)) {
            if (/^(mailto|tel):$/.test(url.protocol)) other.push(link);
            continue;
        }
        const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
        const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
        const domain = isIp ? host : registrableDomain(host) || host;
        const group = groups.get(domain) || { domain, hosts: new Set(), links: [], flags: new Set(), mismatches: [] };
        group.hosts.add(host);
        group.links.push({ ...link, href: url.href });
        if (isIp) group.flags.add('ip');
        if (url.protocol === 'http:') group.flags.add('http');
        if (host.includes('xn--')) group.flags.add('punycode');
        const shown = looksLikeDomain(link.text);
        if (shown && (registrableDomain(shown) || shown) !== domain) {
            group.flags.add('mismatch');
            group.mismatches.push({ shown, href: url.href });
        }
        groups.set(domain, group);
    }
    const tracker = domain => clickTrackers.find(([key]) => domain === key || domain.endsWith('.' + key))?.[1] || null;
    const from = fromDomain ? registrableDomain(fromDomain) : null;
    return {
        groups: [...groups.values()].map(group => ({ ...group, tracker: tracker(group.domain), isFrom: group.domain === from }))
            .sort((a, b) => (b.flags.has('mismatch') - a.flags.has('mismatch')) || b.links.length - a.links.length),
        other
    };
}

function attachmentWarning(name) {
    const lower = (name || '').toLowerCase();
    const parts = lower.split('.');
    const ext = parts.length > 1 ? parts.at(-1) : '';
    if (parts.length > 2 && riskyExtensions.code.includes(ext) && /^(pdf|docx?|xlsx?|jpe?g|png|txt)$/.test(parts.at(-2))) {
        return ['status-fail', 'Disguised file type', `Looks like .${parts.at(-2)} but is a .${ext}`];
    }
    if (riskyExtensions.code.includes(ext)) return ['status-fail', 'Can run code', 'Programs and scripts can take over a computer when opened'];
    if (riskyExtensions.macro.includes(ext)) return ['status-pending', 'Contains macros', 'Office files with macros can run code'];
    if (riskyExtensions.browser.includes(ext)) return ['status-pending', 'Opens in a browser', 'Often used to show fake sign-in pages'];
    if (riskyExtensions.container.includes(ext)) return ['status-pending', 'Archive or disk image', 'Its contents aren\'t checked here'];
    return null;
}

function displayContent(email) {
    if (email.headersOnly) {
        contentOutput.innerHTML = '<p class="note">Only headers were provided, so there\'s no message content to show.</p>';
        return;
    }
    let leaves;
    try {
        const mime = new MimeParser();
        leaves = mime.flatten(mime.parse(email));
    } catch (error) {
        contentOutput.innerHTML = `<div class="error">Couldn't read the message structure: ${escapeHtml(error.message)}</div>`;
        return;
    }
    const textPart = leaves.find(part => !part.attachment && part.contentType === 'text/plain' && cleanText(part.text).length > 40);
    const htmlPart = leaves.find(part => !part.attachment && part.contentType === 'text/html');
    const attachments = leaves.filter(part => part.attachment);
    const text = textPart ? cleanText(textPart.text) : htmlPart ? htmlToText(htmlPart.text) : '';
    const from = firstHeader(email, 'From');
    const fromMailboxes = from ? EmailAddress.parseMailboxes(from) : [];
    const fromDomain = fromMailboxes.length === 1 ? fromMailboxes[0].domain : null;
    const { links, images } = collectLinks(htmlPart, textPart);
    const { groups, other } = linkGroups(links, fromDomain);
    const remote = images.filter(image => /^https?:/i.test(image.src));
    const pixels = remote.filter(image => image.pixel).length;
    const mismatches = groups.flatMap(group => group.mismatches);
    const webLinks = groups.reduce((sum, group) => sum + group.links.length, 0);
    const formats = [textPart && 'plain text', htmlPart && 'HTML'].filter(Boolean).join(' and ') || 'no readable text';

    const flagLabels = {
        mismatch: ['status-fail', 'Text shows another domain'], ip: ['status-fail', 'Raw IP address'],
        http: ['status-pending', 'Not encrypted (http)'], punycode: ['status-pending', 'Look-alike characters (punycode)']
    };
    const groupRows = groups.map((group, index) => `
        <tr${group.flags.has('mismatch') || group.flags.has('ip') ? ' class="is-risky"' : ''}>
            <th scope="row"><span class="link-domain">${escapeHtml(group.domain)}</span>
                ${group.hosts.size > 1 || !group.hosts.has(group.domain) ? checkNote([...group.hosts].slice(0, 3).map(escapeHtml).join(', ') + (group.hosts.size > 3 ? ` +${group.hosts.size - 3}` : '')) : ''}</th>
            <td class="link-count">${group.links.length}</td>
            <td>${[group.isFrom ? '<span class="status-pass">From domain</span>' : '',
                group.tracker ? `<span class="status-neutral">Click tracking · ${escapeHtml(group.tracker)}</span>` : '',
                ...[...group.flags].map(flag => `<span class="${flagLabels[flag][0]}">${flagLabels[flag][1]}</span>`)].join(' ')}
                ${group.mismatches.slice(0, 2).map(item => checkNote(`Text shows <code>${escapeHtml(item.shown)}</code>, but the link goes to <code>${escapeHtml(new URL(item.href).hostname)}</code>`)).join('')}
                <button type="button" class="link-toggle" aria-controls="links-${index}" aria-expanded="false">Show links</button>
                <ul id="links-${index}" class="link-list hidden">${group.links.slice(0, 40).map(link =>
                    `<li><span class="link-url">${escapeHtml(link.href)}</span>${link.text && link.text !== link.href ? `<span class="check-note">${escapeHtml(link.text.slice(0, 120))}</span>` : ''}</li>`).join('')}
                    ${group.links.length > 40 ? `<li class="check-note">and ${group.links.length - 40} more</li>` : ''}</ul></td>
        </tr>`).join('');

    const attachmentFlags = attachments.map(part => attachmentWarning(part.filename || '')?.[0]).filter(Boolean);
    if (mismatches.length || groups.some(group => group.flags.has('ip')) || attachmentFlags.includes('status-fail')) {
        setJumpStatus('section-content', 'fail', 'has warning signs');
    } else if (attachmentFlags.length || groups.some(group => group.flags.has('punycode'))) {
        setJumpStatus('section-content', 'warn', 'has items to check');
    }

    contentOutput.innerHTML = `
        ${mismatches.length ? `<div class="error">${mismatches.length === 1 ? 'A link shows' : `${mismatches.length} links show`} one domain but go${mismatches.length === 1 ? 'es' : ''} to another. That's a common phishing trick; check before clicking.</div>` : ''}
        <dl class="facts content-facts">
            <div><dt>Body</dt><dd>${escapeHtml(formats.replace(/^./, letter => letter.toUpperCase()))}</dd><dd class="fact-note">${leaves.length} ${leaves.length === 1 ? 'part' : 'parts'}</dd></div>
            <div><dt>Links</dt><dd>${webLinks ? `${webLinks} to ${groups.length} ${groups.length === 1 ? 'domain' : 'domains'}` : 'None'}</dd>${other.length ? `<dd class="fact-note">${other.length} email or phone links</dd>` : ''}</div>
            <div><dt>Remote images</dt><dd>${remote.length || 'None'}</dd>${remote.length ? `<dd class="fact-note">Loading them tells the sender you opened it${pixels ? ` · ${pixels} tracking pixel${pixels === 1 ? '' : 's'}` : ''}</dd>` : ''}</div>
            <div><dt>Attachments</dt><dd>${attachments.length || 'None'}</dd></div>
        </dl>

        ${attachments.length ? `
        <h4>Attachments</h4>
        <table class="content-table attachments"><tbody>${attachments.map(part => {
            const warning = attachmentWarning(part.filename);
            const inline = part.contentId && part.contentType.startsWith('image/') && part.disposition !== 'attachment';
            return `<tr${warning?.[0] === 'status-fail' ? ' class="is-risky"' : ''}>
                <th scope="row"><span class="link-domain">${escapeHtml(part.filename || (part.contentType === 'message/rfc822' ? 'Attached email' : 'Unnamed'))}</span></th>
                <td class="mono">${escapeHtml(part.contentType)}</td>
                <td class="link-count">${formatBytes(part.size)}</td>
                <td>${warning ? `<span class="${warning[0]}">${warning[1]}</span>${checkNote(warning[2])}` : inline ? '<span class="check-note">Inline image</span>' : ''}</td>
            </tr>`;
        }).join('')}</tbody></table>` : ''}

        ${groups.length ? `
        <h4>Links by domain</h4>
        <table class="content-table link-groups"><tbody>${groupRows}</tbody></table>` : ''}

        <h4>Text</h4>
        ${text ? `<div class="content-preview${text.length > 900 ? ' is-long' : ''}" id="content-preview">${escapeHtml(text)}</div>
            ${text.length > 900 ? '<button type="button" class="btn btn-secondary content-more" aria-expanded="false">Show full text</button>' : ''}
            <p class="note content-source">${textPart ? 'From the plain-text part.' : 'Converted from HTML; images and formatting aren\'t shown.'}</p>`
            : '<p class="note">No readable text in this message.</p>'}`;

    contentOutput.querySelector('.content-more')?.addEventListener('click', event => {
        const expanded = event.currentTarget.getAttribute('aria-expanded') !== 'true';
        event.currentTarget.setAttribute('aria-expanded', String(expanded));
        event.currentTarget.textContent = expanded ? 'Show less' : 'Show full text';
        document.getElementById('content-preview').classList.toggle('is-expanded', expanded);
    });
}

// --- Sender domain: how the From domain is set up beyond SPF, DKIM and DMARC ---
async function txtRecords(name) {
    try {
        return (await EmailDns.lookup(name, 'TXT')).map(value => EmailDns.txt(value));
    } catch {
        return null;
    }
}

function domainRow(label, cls, status, detail) {
    return `<tr><th scope="row">${label}</th><td><span class="${cls}">${escapeHtml(status)}</span></td><td>${detail || ''}</td></tr>`;
}

async function domainRegistration(domain) {
    try {
        const response = await fetch('https://rdap.org/domain/' + encodeURIComponent(domain),
            { headers: { Accept: 'application/rdap+json' }, signal: AbortSignal.timeout(8000) });
        if (!response.ok) return null;
        const json = await response.json();
        const event = action => json.events?.find(item => item.eventAction === action)?.eventDate;
        const registrar = json.entities?.find(entity => entity.roles?.includes('registrar'))
            ?.vcardArray?.[1]?.find(item => item[0] === 'fn')?.[3];
        return { registered: event('registration'), expires: event('expiration'), registrar: registrar || null };
    } catch {
        return null;
    }
}

function ageText(date) {
    const days = Math.floor((Date.now() - date.getTime()) / 86400000);
    if (days < 60) return `${days} days ago`;
    if (days < 730) return `${Math.round(days / 30.4)} months ago`;
    return `${Math.floor(days / 365.25)} years ago`;
}

async function displayDomain(email, run) {
    const from = firstHeader(email, 'From');
    const mailboxes = from ? EmailAddress.parseMailboxes(from) : [];
    if (mailboxes.length !== 1) {
        domainOutput.innerHTML = '<p class="note">The From header doesn\'t name a single sender domain.</p>';
        return;
    }
    const domain = mailboxes[0].domain.toLowerCase();
    const org = registrableDomain(domain) || domain;
    if (network.offline) {
        domainOutput.innerHTML = `<p class="note">${offlineVerdict(`The checks for <code>${escapeHtml(domain)}</code> (registration, MX, BIMI, MTA-STS and TLS reporting) need lookups.`)}</p>`;
        return;
    }
    domainOutput.innerHTML = `<p class="note">Checking <code>${escapeHtml(domain)}</code>…</p>`;
    setJumpStatus('section-domain', 'pending', 'checking');

    const [mx, bimi, sts, tlsrpt, registration] = await Promise.all([
        EmailDns.lookup(domain, 'MX').catch(() => null), bimiLookup(domain),
        txtRecords('_mta-sts.' + domain), txtRecords('_smtp._tls.' + domain), domainRegistration(org)
    ]);
    if (run !== latestRun) return;

    const rows = [];
    setJumpStatus('section-domain', null);
    if (registration?.registered) {
        const date = new Date(registration.registered);
        const days = (Date.now() - date.getTime()) / 86400000;
        if (days < 180) setJumpStatus('section-domain', days < 30 ? 'fail' : 'warn', `registered ${ageText(date)}`);
        rows.push(domainRow('Registered', days < 30 ? 'status-fail' : days < 180 ? 'status-pending' : 'status-pass', ageText(date),
            `<code>${escapeHtml(org)}</code> on ${escapeHtml(date.toLocaleDateString())}${registration.registrar ? ` · ${escapeHtml(registration.registrar)}` : ''}`
            + (days < 180 ? checkNote('Newly registered domains are often used for phishing') : '')));
    } else {
        rows.push(domainRow('Registered', 'status-neutral', 'Unknown', checkNote('The registry didn\'t answer for <code>' + escapeHtml(org) + '</code>')));
    }

    const exchanges = (mx || []).map(value => value.trim().split(/\s+/)).filter(parts => parts.length === 2)
        .map(([priority, host]) => ({ priority: Number(priority), host: host.replace(/\.$/, '') })).sort((a, b) => a.priority - b.priority);
    if (mx === null) {
        rows.push(domainRow('Receives mail', 'status-pending', 'Lookup failed', ''));
    } else if (exchanges.length && !(exchanges.length === 1 && exchanges[0].host === '')) {
        const provider = spfProvider(registrableDomain(exchanges[0].host) || exchanges[0].host) || null;
        rows.push(domainRow('Receives mail', 'status-pass', 'Yes', `${exchanges.slice(0, 3).map(item => `<span class="spf-token">${escapeHtml(item.host)}</span>`).join(', ')}`
            + (exchanges.length > 3 ? ` +${exchanges.length - 3}` : '') + (provider ? checkNote(`Mail handled by ${escapeHtml(provider)}`) : '')));
    } else {
        rows.push(domainRow('Receives mail', 'status-neutral', 'No', checkNote(`<code>${escapeHtml(domain)}</code> has no MX record, so replies to the From address won't arrive`)));
    }

    if (bimi.record) {
        const logo = bimi.logo;
        rows.push(domainRow('BIMI logo', logo ? 'status-pass' : 'status-neutral', logo ? 'Published' : 'Record without logo',
            (logo ? `<span class="link-url">${escapeHtml(logo)}</span> <button type="button" class="link-toggle bimi-show" data-logo="${escapeHtml(logo)}">Show logo</button><span class="bimi-logo"></span>` : '')
            + checkNote(bimi.authority ? 'Has a mark certificate (not checked here); mail clients show the logo next to verified mail' : 'No mark certificate, so most mail clients won\'t show the logo')
            + (logo ? '<span id="bimi-eligibility" class="check-note" hidden></span>' : '')));
    } else if (bimi.error) {
        rows.push(domainRow('BIMI logo', 'status-pending', 'Lookup failed', ''));
    } else {
        rows.push(domainRow('BIMI logo', 'status-neutral', 'None', checkNote('No brand logo published for mail clients')));
    }

    const stsRecord = (sts || []).find(value => /^v=STSv1/i.test(value));
    rows.push(stsRecord
        ? domainRow('MTA-STS', 'status-pass', 'Published', `Mail sent to this domain must use verified TLS.
            <a class="link-url" href="https://mta-sts.${escapeHtml(domain)}/.well-known/mta-sts.txt" target="_blank" rel="noopener noreferrer">View policy</a>`)
        : domainRow('MTA-STS', 'status-neutral', 'None', checkNote('No policy requiring encrypted delivery to this domain')));

    const tlsRecord = (tlsrpt || []).find(value => /^v=TLSRPTv1/i.test(value));
    rows.push(tlsRecord
        ? domainRow('TLS reporting', 'status-pass', 'Published', checkNote('Reports of TLS delivery problems go to ' + escapeHtml(EmailDns.parseTags(tlsRecord).tags.rua || 'an unspecified address')))
        : domainRow('TLS reporting', 'status-neutral', 'None', checkNote('Servers sending to this domain have nowhere to report TLS delivery problems')));

    domainOutput.innerHTML = `
        <p class="domain-intro">Checks for <code>${escapeHtml(domain)}</code>${org !== domain ? `, part of <code>${escapeHtml(org)}</code>` : ''}. SPF, DKIM and DMARC have their own sections.</p>
        <table class="content-table domain-checks"><tbody>${rows.join('')}</tbody></table>`;
    domainOutput.querySelector('.bimi-show')?.addEventListener('click', event => {
        const button = event.currentTarget;
        // An <img> never runs scripts inside an SVG, so the logo is safe to show.
        button.nextElementSibling.innerHTML = `<img src="${escapeHtml(button.dataset.logo)}" alt="Brand logo" width="56" height="56" referrerpolicy="no-referrer">`;
        logRequest(new URL(button.dataset.logo), 'logo');
        button.remove();
    });
    updateBimiNote();
}

// --- ARC chain ---
// True when the receiving server's results were also sealed with ARC and every seal verifies.
function arcSealed(reported) {
    const arc = summaryState.arc;
    if (!arc?.sets.length || arc.sets.some(set => set.seal.valid !== true)) return false;
    const service = reported.top?.service?.toLowerCase();
    return Boolean(service) && arc.sets.some(set => new ServerValidationParser().parseOne(set.recorded).service?.toLowerCase() === service);
}

// Headers a signature lists that this copy of the message no longer has.
function missingSignedHeaders(dkim) {
    const present = new Set(Object.keys(currentEmail?.headers || {}).map(name => name.toLowerCase()));
    const names = String(dkim?.tags?.h || '').split(':').map(name => name.trim()).filter(Boolean);
    return [...new Map(names.filter(name => !present.has(name.toLowerCase())).map(name => [name.toLowerCase(), name])).values()];
}

function arcAmsCell(ams) {
    const missing = missingSignedHeaders(ams.dkim);
    if (!ams.valid && ams.headersVerified === false && missing.length) {
        return pill('status-fail', 'Doesn\'t verify') + checkNote(`${missing.length} signed ${missing.length === 1 ? 'header is' : 'headers are'} missing from this copy`);
    }
    if (ams.valid) return pill('status-pass', 'Verifies');
    if (ams.bodyMissing) return pill('status-neutral', 'Body not provided') + checkNote(ams.headersVerified ? 'Signed headers verify' : '');
    if (ams.headersVerified === true) return pill('status-fail', 'Body changed') + checkNote('Signed headers still verify');
    if (ams.headersVerified === false) return pill('status-fail', 'Doesn\'t verify') + checkNote('The signed headers and body changed after sealing');
    return pill(verdictClass(ams.status || 'fail'), ams.status === 'unavailable' || ams.status === 'temperror' ? 'Not checked' : 'Doesn\'t verify')
        + checkNote(network.offline && ams.status === 'temperror' ? '' : escapeHtml(ams.error || ''));
}

function arcVerdict(result) {
    const sets = result.sets;
    const sealers = [...new Set(sets.map(set => set.sealer).filter(Boolean))].map(name => `<code>${escapeHtml(name)}</code>`).join(', ');
    const sealsOk = sets.length && sets.every(set => set.seal.valid === true);
    switch (result.status) {
        case 'none': return 'No ARC headers. Forwarding services and mailing lists add them, and so do some providers, such as Gmail, when mail arrives.';
        case 'pass': return sets.length === 1
            ? `${sealers} sealed the authentication results it recorded, and the seal verifies, so those results haven't been altered since.`
            : `All ${sets.length} seals verify (${sealers}), so the results each server recorded haven't been altered since.`;
        case 'unavailable': return network.offline
            ? offlineVerdict(`The sealers' public keys weren't looked up, so the seals weren't checked. The ${sets.length === 1 ? 'set is' : 'sets are'} listed as found.`)
            : escapeHtml(result.error || sets.find(set => set.seal.valid === null)?.seal.error || 'Part of the chain could not be checked.');
        default:
            if (result.error) return `The chain is broken: ${escapeHtml(result.error)}.`;
            if (sets.some((set, index) => set.cv !== (index === 0 ? 'none' : 'pass'))) return 'The chain is broken: a server recorded that the chain before it had already failed.';
            const missing = sealsOk ? missingSignedHeaders(sets[sets.length - 1].ams.dkim) : [];
            if (missing.length) {
                return `The seals verify, so the recorded results are intact. The latest message signature fails because this copy is missing headers it signed (${missing.map(name => `<code>${escapeHtml(name)}</code>`).join(', ')}). Outlook removes these when a message is saved or exported.`;
            }
            return sealsOk
                ? 'The seals verify, so the recorded results are intact, but the message changed after the last seal.'
                : 'A seal doesn\'t verify, so the recorded results can\'t be trusted.';
    }
}

function displayArc(result) {
    const rows = result.sets.map(set => {
        const recorded = new ServerValidationParser().parseOne(set.recorded);
        return `
            <tr>
                <th scope="row">${set.instance}</th>
                <td data-label="Sealed by"><span class="dmarc-domain">${escapeHtml(set.sealer || 'unknown')}</span>
                    ${checkNote(`selector <code>${escapeHtml(set.selector || '')}</code>${set.time ? ' · ' + escapeHtml(formatUnixTime(set.time)) : ''}`)}</td>
                <td data-label="Seal">${set.seal.valid === true ? pill('status-pass', 'Verifies') : set.seal.valid === false ? pill('status-fail', 'Doesn\'t verify') : pill('status-pending', 'Not checked')}
                    ${set.seal.error && !network.offline ? checkNote(escapeHtml(set.seal.error)) : ''}</td>
                <td data-label="Message signature">${arcAmsCell(set.ams)}</td>
                <td data-label="Chain before">${pill(set.cv === 'pass' || (set.instance === 1 && set.cv === 'none') ? 'status-pass' : set.cv === 'fail' ? 'status-fail' : 'status-neutral', set.cv || '?')}</td>
                <td data-label="Recorded">${recorded.service ? `<span class="check-note">${escapeHtml(recorded.service)}</span>` : ''}
                    <span class="arc-recorded">${recorded.results.filter(entry => ['dkim', 'spf', 'dmarc', 'arc'].includes(entry.method))
                        .map(entry => `<span class="${['none', 'neutral'].includes(entry.result) ? 'status-neutral' : verdictClass(entry.result)}" title="${escapeHtml(entry.raw)}">${escapeHtml(entry.method.toUpperCase())} ${escapeHtml(verdictLabel(entry.result))}</span>`).join('')}</span></td>
            </tr>`;
    }).join('');
    arcOutput.innerHTML = `
        <div class="dmarc-verdict">
            <span class="${result.status === 'none' ? 'status-neutral' : verdictClass(offlineStatus(result.status))} summary-pill">${escapeHtml(verdictLabel(offlineStatus(result.status)))}</span>
            <span class="dmarc-verdict-text">${arcVerdict(result)}</span>
        </div>
        ${rows ? `
        <p class="note arc-explain">Each server that handles the message can add a numbered set: the results it recorded, a signature of the message, and a seal over every set so far. Oldest first.</p>
        <table class="dmarc-checks arc-sets">
            <thead><tr><th scope="col">Set</th><th scope="col">Sealed by</th><th scope="col">Seal</th><th scope="col">Message signature</th><th scope="col">Chain before</th><th scope="col">Recorded</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>
        <button type="button" class="dkim-advanced-toggle" aria-controls="arc-raw" aria-expanded="false">
            ${detailDisclosureIcon}<span>ARC headers</span><span class="toggle-meta">${result.sets.length * 3} headers</span>
        </button>
        <div id="arc-raw" class="hidden"><pre class="tech-value code scrollable-pre">${escapeHtml(result.sets.flatMap(set => set.raw).join('\r\n'))}</pre></div>` : ''}`;
}

// What a signature's result says about the headers it lists.
function headerCoverage(dkim, result) {
    if (!result.details?.signedHeaders?.length) return null;
    const headers = dkimHeadersVerified(result);
    if (result.valid) return 'verified';
    if (headers === true) return dkimExpired(dkim) ? 'expired' : 'headers';
    return headers === false ? 'failed' : 'unchecked';
}

// --- Headers: in message order with hop markers, or grouped by purpose ---
const headersUi = { email: null, view: storedHeadersView(), openRows: new Set(), groups: {} };
const chevronIcon = `<svg class="hdr-chevron" width="14" height="14" ${iconAttrs}><path d="m9 6 6 6-6 6"/></svg>`;
const headerSections = {
    'dkim-signature': ['section-dkim', 'DKIM'], 'arc-seal': ['section-arc', 'ARC'], 'arc-message-signature': ['section-arc', 'ARC'],
    'arc-authentication-results': ['section-arc', 'ARC'], 'authentication-results': ['section-summary', 'Summary'], 'received-spf': ['section-spf', 'SPF'],
    'return-path': ['section-spf', 'SPF'], 'received': ['section-relay', 'Hops'], 'x-received': ['section-relay', 'Hops'], 'from': ['section-dmarc', 'DMARC'],
    'content-type': ['section-content', 'Content']
};

function storedHeadersView() {
    try {
        return localStorage.getItem('emailParserHeadersView') === 'purpose' ? 'purpose' : 'order';
    } catch {
        return 'order';
    }
}

for (const button of document.querySelectorAll('.headers-views .relay-tab')) {
    button.addEventListener('click', () => {
        headersUi.view = button.dataset.view;
        try {
            localStorage.setItem('emailParserHeadersView', headersUi.view);
        } catch {
            // Only persistence is optional.
        }
        displayHeaders();
    });
}

// Remember what the reader opened, so re-rendering (search, DKIM results arriving) keeps it open.
headersOutput.addEventListener('click', event => {
    const row = event.target.closest('.hdr-name');
    if (row) {
        const index = Number(row.dataset.index);
        if (row.getAttribute('aria-expanded') === 'true') headersUi.openRows.delete(index);
        else headersUi.openRows.add(index);
    }
    const group = event.target.closest('.hdr-group-head');
    if (group) headersUi.groups[group.dataset.group] = group.getAttribute('aria-expanded') !== 'true';
});

// Every header field in message order (newest first), with its value unfolded.
function headerFieldList(email) {
    if (!email.headerFields) {
        email.headerFields = new DkimValidator().getRawHeaderFields(email.rawHeaders).map((field, index) => {
            const colon = field.raw.indexOf(':');
            return { index, key: field.key, instance: field.instance, name: field.raw.slice(0, colon).trim(),
                value: field.raw.slice(colon + 1).replace(/\r?\n[ \t]+/g, ' ').trim(), raw: field.raw };
        });
    }
    return email.headerFields;
}

function highlight(text, query) {
    if (!query) return escapeHtml(text);
    const lower = text.toLowerCase();
    let html = '';
    let at = 0;
    for (let found = lower.indexOf(query); found >= 0; found = lower.indexOf(query, at)) {
        html += escapeHtml(text.slice(at, found)) + `<mark>${escapeHtml(text.slice(found, found + query.length))}</mark>`;
        at = found + query.length;
    }
    return html + escapeHtml(text.slice(at));
}

// A header's time in the reader's time zone: the Date header, or the date at the end of a Received line.
function headerLocalTime(field) {
    const text = field.key === 'date' || field.key === 'resent-date' ? field.value
        : field.key === 'received' || field.key === 'x-received' ? field.value.slice(field.value.lastIndexOf(';') + 1) : null;
    const time = text ? parseMailDate(text) : NaN;
    return Number.isNaN(time) ? null : new Date(time).toLocaleString();
}

function headerRow(field, { coverage, issues, query, hop }) {
    const badge = signatureBadges[coverage];
    const open = headersUi.openRows.has(field.index);
    const decoded = decodeMimeWords(field.value);
    const note = HeaderInsights.describe(field.key);
    const section = headerSections[field.key];
    const time = headerLocalTime(field);
    const classes = ['hdr-row', coverage && 'coverage-' + coverage, issues.length && 'is-flagged', hop && 'is-hop'].filter(Boolean).join(' ');
    return `
        <div class="${classes}">
            <button type="button" class="hdr-name" data-index="${field.index}" aria-expanded="${open}" aria-controls="hdr-detail-${field.index}">
                ${chevronIcon}${badge ? `<span class="signature-badge ${coverage}" role="img" aria-label="${badge.label}" title="${badge.label}">${badge.icon}</span>` : ''}
                <span class="hdr-name-text">${highlight(field.name, query)}</span>${hop ? `<span class="hdr-hop">Hop ${hop}</span>` : ''}
            </button>
            <span class="hdr-value" data-copy="${escapeHtml(field.value)}">${highlight(decoded, query)}</span>
            <div id="hdr-detail-${field.index}" class="hdr-detail${open ? '' : ' hidden'}">
                ${issues.map(issue => `<p class="hdr-issue">${escapeHtml(issue.message)}</p>`).join('')}
                ${note || section ? `<p class="hdr-note">${note ? escapeHtml(note) : ''}${section ? ` <a class="hdr-link" href="#${section[0]}">See ${section[1]}</a>` : ''}</p>` : ''}
                ${badge ? `<p class="hdr-note">${badge.label}.</p>` : ''}
                <pre class="tech-value code hdr-full" data-copy="${escapeHtml(field.name + ': ' + field.value)}">${escapeHtml(field.raw)}</pre>
                ${decoded !== field.value ? `<p class="hdr-extra"><span class="tech-label">Decoded</span>${escapeHtml(decoded)}</p>` : ''}
                ${time ? `<p class="hdr-extra"><span class="tech-label">Your time</span>${escapeHtml(time)}</p>` : ''}
            </div>
        </div>`;
}

function displayHeaders() {
    if (!currentEmail) return;
    if (headersUi.email !== currentEmail) {
        headersUi.email = currentEmail;
        headersUi.openRows.clear();
        headersUi.groups = {};
    }
    const fields = headerFieldList(currentEmail);
    const showSignedOnly = headersSignedToggle.getAttribute('aria-pressed') === 'true';
    const query = headersSearch.value.trim().toLowerCase();
    const matches = field => !query || field.name.toLowerCase().includes(query) || field.value.toLowerCase().includes(query)
        || decodeMimeWords(field.value).toLowerCase().includes(query);
    const raw = headersRawToggle.getAttribute('aria-pressed') === 'true';
    // The signed-only filter and the arrangement don't apply to the raw view.
    headersSignedToggle.disabled = raw;
    for (const button of document.querySelectorAll('.headers-views .relay-tab')) {
        button.setAttribute('aria-pressed', String(button.dataset.view === headersUi.view));
        button.disabled = raw;
    }

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
    const covered = new Set([...coverageByHeader].filter(([, kind]) => kind !== 'failed').map(([id]) => id));
    const issues = HeaderInsights.anomalies(fields, { covered, receiver: summaryState.reported?.top?.service || null });
    setJumpStatus('section-headers', issues.length ? 'fail' : null, issues.length ? `${issues.length} warning ${issues.length === 1 ? 'sign' : 'signs'}` : null);
    const issuesFor = index => issues.filter(issue => issue.indexes.includes(index));
    const warnings = issues.length ? `
        <div class="error headers-warnings">
            <strong>${issues.length === 1 ? 'Warning sign' : `${issues.length} warning signs`}</strong>
            <ul>${issues.map(issue => `<li>${escapeHtml(issue.message)}</li>`).join('')}</ul>
        </div>` : '';

    if (raw) {
        const shown = fields.filter(matches);
        headersCount.textContent = query ? `${shown.length} of ${fields.length} headers` : `${fields.length} headers`;
        const text = shown.map(field => field.raw).join('\r\n');
        headersOutput.innerHTML = `
            <div class="headers-raw-actions"><button type="button" class="btn btn-secondary headers-copy-all">Copy ${query ? 'these' : 'all'}</button></div>
            <pre class="tech-value code headers-raw">${escapeHtml(text) || 'No headers match.'}</pre>`;
        headersOutput.querySelector('.headers-copy-all').addEventListener('click', async () => {
            const copied = await writeClipboard(text);
            showToast(copied, copied ? `Copied ${shown.length} headers` : 'Couldn\'t copy the headers');
        });
        return;
    }
    if (showSignedOnly && !coverageByHeader.size) {
        headersCount.textContent = '';
        const checking = !currentEmail.dkimResults && currentEmail.dkim.length > 0;
        headersOutput.innerHTML = warnings + '<p class="note">' + (checking ? 'Checking DKIM signatures…'
            : currentEmail.dkim.length ? 'No DKIM signature lists any of these headers.' : 'This message has no DKIM signature.') + '</p>';
        return;
    }

    const coverageOf = field => coverageByHeader.get(field.key + ':' + field.instance);
    const pool = showSignedOnly ? fields.filter(coverageOf) : fields;
    const visible = pool.filter(matches);
    const hops = fields.filter(field => field.key === 'received');
    const hopNumber = field => field.key === 'received' ? hops.length - hops.indexOf(field) : null;
    const row = field => headerRow(field, { coverage: coverageOf(field), issues: issuesFor(field.index), query, hop: hopNumber(field) });
    const kinds = Object.keys(signatureBadges).filter(kind => visible.some(field => coverageOf(field) === kind));
    let html = warnings + (kinds.length ? `<div class="header-legend">${kinds.map(kind =>
        `<span class="header-legend-item signature-badge ${kind}">${signatureBadges[kind].icon}${escapeHtml(signatureBadges[kind].short)}</span>`).join('')}</div>` : '');

    if (headersUi.view === 'order') {
        const filtered = Boolean(query) || showSignedOnly;
        const oldest = hops.at(-1);
        const microsoftBelow = oldest && fields.some(field => field.index > oldest.index && /^x-(ms|microsoft|forefront)-/.test(field.key));
        if (!filtered) html += '<p class="hdr-order-note">Newest first: each server adds its headers above the ones already there.</p>';
        html += '<div class="hdr-list">';
        for (const field of visible) {
            html += row(field);
            if (!filtered && field === oldest && field !== fields.at(-1)) {
                html += `<div class="hdr-divider">Below the oldest hop: written by the sending software${microsoftBelow ? ', plus headers Microsoft adds at delivery' : ''}</div>`;
            }
        }
        html += '</div>';
    } else {
        for (const group of HeaderInsights.groups) {
            const members = visible.filter(field => HeaderInsights.category(field.key) === group.id);
            if (!members.length) continue;
            const open = query ? true : headersUi.groups[group.id] ?? !group.folded;
            html += `
                <section class="hdr-group">
                    <button type="button" class="hdr-group-head" data-group="${group.id}" aria-expanded="${open}" aria-controls="hdr-group-${group.id}">
                        ${chevronIcon}<span>${escapeHtml(group.title)}</span><span class="hdr-group-count">${members.length}</span>
                        ${group.folded ? '<span class="hdr-group-hint">internal bookkeeping, rarely useful</span>' : ''}
                    </button>
                    <div id="hdr-group-${group.id}" class="hdr-list${open ? '' : ' hidden'}">${members.map(row).join('')}</div>
                </section>`;
        }
    }
    if (!visible.length) html += '<p class="note">No headers match this filter.</p>';
    if (showSignedOnly && query) {
        const hidden = fields.filter(field => !coverageOf(field) && matches(field)).length;
        if (hidden) html += `<p class="note headers-hidden-matches">${hidden} unsigned ${hidden === 1 ? 'header matches' : 'headers match'}.
            <button type="button" class="link-toggle headers-show-all">Show all headers</button></p>`;
    }
    headersCount.textContent = query || showSignedOnly ? `${visible.length} of ${fields.length} headers` : `${fields.length} headers`;
    headersOutput.innerHTML = html;
    headersOutput.querySelector('.headers-show-all')?.addEventListener('click', () => headersSignedToggle.click());
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
        section.id = 'section-relay';
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
    // The server that handed the message to your provider: worth naming who runs its IP.
    if (entry && entry.source !== 'Reported') entry.entry = true;
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

// A placeholder filled in with the IP's network owner once the lookup finishes (public IPs only).
function ownerSlot(ip) {
    return ip && ipScope(ip) === 'public' && !network.offline
        ? `<span class="net-owner" data-owner-ip="${escapeHtml(normalizeIp(ip))}">Looking up who runs this IP…</span>` : '';
}

function fillNetworkOwners(root) {
    for (const slot of root.querySelectorAll('[data-owner-ip]:not([data-owner-done])')) {
        slot.dataset.ownerDone = '';
        IpAddress.networkOwner(slot.dataset.ownerIp).then(info => {
            if (!slot.isConnected) return;
            if (!info) {
                slot.textContent = 'Network owner unknown';
                return;
            }
            const name = info.organization || info.asName || info.network;
            slot.title = [info.network && `Network ${info.network}${info.range ? ` (${info.range})` : ''}`,
                info.registry && `registered with ${info.registry}`,
                info.asn && `announced by AS${info.asn}${info.asName ? ' ' + info.asName : ''}`,
                info.country].filter(Boolean).join(' · ');
            slot.innerHTML = `<span class="net-owner-name">${escapeHtml(name)}</span>${info.asn ? ` · AS${escapeHtml(info.asn)}` : ''}`;
        });
    }
}

function hopChips(step) {
    const scope = ipScope(step.ip);
    return [
        step.protocol ? `<span class="route-chip">${escapeHtml(step.protocol)}</span>` : '',
        step.tls ? `<span class="route-chip is-secure" title="${escapeHtml(step.cipher || 'Encrypted in transit')}">${smallLockIcon}${escapeHtml(step.tls)}</span>` : '',
        step.ip ? `<span class="route-chip is-mono route-ip" data-copy="${escapeHtml(normalizeIp(step.ip))}">${scope === 'public' ? '' : `<span class="route-ip-scope">${scope}</span>`}${escapeHtml(normalizeIp(step.ip))}</span>` : '',
        step.ip ? embeddedChip(step.ip) : '',
        step.ip && normalizeIp(step.ip) === relayState.spfIp
            ? `<span class="route-spf">${copiedIcon}SPF checked this IP</span>` : '',
        step.entry ? `<span class="route-owner">${ownerSlot(step.ip)}</span>` : ''
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
    // A third element marks a value that is already HTML.
    const network = ownerSlot(step.ip);
    const fields = (reported ? [['Named by', step.reportedBy], ['IP', ip], ['Network', network, true], ['HELO', step.helo]] : [
        ['Received', step.timestamp ? new Date(step.timestamp).toLocaleString() : 'No readable date'],
        ['Gap', step.delay !== null ? formatDuration(step.delay) + (step.firstRecorded ? ' after the Date header' : '') : step.firstRecorded ? 'First step' : 'Unknown'],
        ['From', step.from], ['IP', ip], ['Network', network, true], ['HELO', step.helo], ['Protocol', step.protocol],
        ['TLS', step.tls && step.tls + (step.cipher ? ', ' + step.cipher : '')],
        ['Note', step.delayedDelivery && 'Microsoft held this message before this step (X-MS-DelayedDelivery: true)']
    ]).filter(([, value]) => value);
    const note = reported ? 'Sending server · no Received header of its own' : step.source === 'X-Received' ? 'internal processing' : '';
    return `
        <div class="map-detail-head"><span class="route-host">${escapeHtml(step.host)}</span>${embeddedChip(step.host)}<span class="route-note">Step ${step.index} of ${route.steps.length}${note ? ' · ' + note : ''}</span></div>
        <dl class="relay-details">${fields.map(([label, value, html]) => `<dt>${label}</dt><dd${html ? ' class="is-html"' : ''}>${html ? value : escapeHtml(value)}</dd>`).join('')}</dl>
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
    fillNetworkOwners(container);
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
    if (detail) {
        detail.innerHTML = renderMapDetail(relayState.route);
        fillNetworkOwners(detail);
    }
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
    if (network.offline && spfDto.result === 'temperror') {
        const ip = spfDto.senderIp ? normalizeIp(spfDto.senderIp) : null;
        spfOutput.innerHTML = `
            <div class="spf-record-card">
                <div class="dmarc-verdict">
                    <span class="status-neutral summary-pill">Offline</span>
                    <span class="dmarc-verdict-text">${offlineVerdict(`The SPF record${spfDto.domain ? ` for <code>${escapeHtml(spfDto.domain)}</code>` : ''} wasn't looked up${ip ? `, so <code>${escapeHtml(ip)}</code> can't be checked against it` : ''}.`)}</span>
                </div>
                <div class="dmarc-reported">${spfDto.headerResult ? `At delivery <code>${escapeHtml(spfDto.reportedBy || 'the receiving server')}</code> recorded
                    <span class="${verdictClass(spfDto.headerResult)}">${escapeHtml(verdictLabel(spfDto.headerResult))}</span>` : 'No SPF result was recorded at delivery'}</div>
            </div>`;
        return;
    }
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
                    ${ownerSlot(ip) ? `<dd class="fact-note">${ownerSlot(ip)}</dd>` : ''}
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

    // Reverse DNS and the network owner are only for display, so they load after the panel.
    fillNetworkOwners(spfOutput);
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
    if (network.offline && dto.result === 'temperror') {
        dmarcOutput.innerHTML = `
            <div class="dmarc-record-card">
                <div class="dmarc-verdict">
                    <span class="status-neutral summary-pill">Offline</span>
                    <span class="dmarc-verdict-text">${offlineVerdict(`The DMARC policy${dto.domain ? ` for <code>${escapeHtml(dto.domain)}</code>` : ''} wasn't looked up.`)}</span>
                </div>
                ${dto.reported ? `<div class="dmarc-reported">At delivery <code>${escapeHtml(dto.reported.authServId)}</code> reported
                    <span class="${verdictClass(dto.reported.result)}">${escapeHtml(verdictLabel(dto.reported.result))}</span></div>` : ''}
            </div>`;
        return;
    }
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
    new ArcValidator(validator).verify(email)
        .catch(error => ({ status: 'unavailable', error: error.message, sets: [] }))
        .then(result => {
            if (run !== latestRun) return;
            summaryState.arc = result;
            displayArc(result);
            setJumpStatus('section-arc', offlineStatus(result.status));
            displaySummary();
        });
    const spfCheck = new SpfValidator().verify(email)
        .catch(error => ({ result: 'unavailable', error: error.message }))
        .then(result => {
            if (run === latestRun) {
                displaySpf(result);
                setSummaryCheck('spf', offlineStatus(result.result), spfSummaryNote(result));
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
    setSummaryCheck('dkim', offlineStatus(dkim), dkimSummaryNote(dkimResults));

    const spf = await spfCheck;
    if (run !== latestRun) return;

    const dmarc = await new DmarcValidator().verify(email, spf, dkimResults);
    if (run !== latestRun) return;
    displayDmarc(dmarc);

    summaryState.dmarcDto = dmarc;
    setSummaryCheck('dmarc', offlineStatus(dmarc.result), dmarcSummaryNote(dmarc));
    updateBimiNote();
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
    if (result.bodyMissing) {
        return headers === true ? { cls: 'notice', text: 'Only the headers were provided, so the body can\'t be checked. The signed headers verify against the current key.' }
            : headers === false ? { cls: 'error', text: 'Only the headers were provided, and the signed headers don\'t verify against the current key.' }
            : { cls: 'note', text: 'Only the headers were provided, so the body can\'t be checked, and the signed headers couldn\'t be checked either.' };
    }
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
    if (network.offline && (result.status === 'temperror' || result.keyError)) {
        const keyName = `<code>${escapeHtml(dkim.tags.s || '')}._domainkey.${escapeHtml(dkim.tags.d || '')}</code>`;
        return result.bodyHash?.valid === false
            ? { cls: 'notice', text: offlineVerdict(`The body changed after signing, so this signature fails whatever the key says. The key ${keyName} wasn't looked up, so the signed headers weren't checked.`) }
            : { cls: 'note', text: offlineVerdict(`The key ${keyName} wasn't looked up, so the signed headers weren't checked.${result.bodyHash?.valid ? ' The body matches what was signed.' : ''}`) };
    }
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
    const status = result.valid ? 'pass' : result.bodyMissing ? result.status : offlineStatus(result.status || 'fail');
    const bhResult = result.bodyHash || {};
    statusDiv.className = `dkim-status-badge ${verdictClass(status)}`;
    statusDiv.textContent = verdictLabel(status);

    const verdict = dkimVerdict(dkim, result);
    const headers = dkimHeadersVerified(result);
    const expired = dkimExpired(dkim);
    const keyName = `${dkim.tags.s || ''}._domainkey.${dkim.tags.d || ''}`;
    const key = result.key;
    const keyText = key ? (key.type === 'rsa' ? `RSA, ${key.bits}-bit` : 'Ed25519') : dkim.publicKey ? 'Published' : network.offline ? 'Not looked up' : 'Not found';
    const weakKey = key?.type === 'rsa' && key.bits < 2048;
    const identity = dkim.tags.i && dkim.tags.i !== '@' + dkim.tags.d ? dkim.tags.i : null;

    const checks = [
        result.bodyMissing ? dkimCheckRow(null, 'Body not provided', 'Only headers were given, so the body hash can\'t be checked')
            : bhResult.valid === undefined ? dkimCheckRow(null, 'Body not checked', escapeHtml(result.error || ''))
            : bhResult.valid ? dkimCheckRow(true, 'Body matches what was signed', '')
            : dkimCheckRow(false, 'Body changed after signing', 'Its hash differs from the one in the signature'),
        headers === true ? dkimCheckRow(true, 'Signed headers verify', 'Checked against the key published today')
            : headers === false ? dkimCheckRow(false, 'Signed headers don\'t verify', 'The signature doesn\'t match them with the key published today')
            : dkimCheckRow(null, 'Signed headers not checked', network.offline ? 'The key wasn\'t looked up' : escapeHtml(result.keyError || (result.status === 'unavailable' ? result.error : '') || '')),
        expired ? dkimCheckRow('warn', `Expired on ${escapeHtml(formatUnixTime(dkim.tags.x))}`, 'Receivers ignore signatures past their expiry')
            : dkimCheckRow(true, dkim.tags.x ? `Valid until ${escapeHtml(formatUnixTime(dkim.tags.x))}` : 'No expiry set', ''),
        key ? dkimCheckRow(weakKey ? 'warn' : true, `Key found: ${keyText}`, weakKey ? '2048-bit keys are recommended; 1024-bit keys are considered weak' : `<code>${escapeHtml(keyName)}</code>`)
            : network.offline ? dkimCheckRow(null, 'Key not looked up', `<code>${escapeHtml(keyName)}</code> · offline mode`)
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
