// --- UI Logic ---

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const errorMsg = document.getElementById('error-msg');
const resultsDiv = document.getElementById('results');
const headersOutput = document.getElementById('headers-output');
const summaryOutput = document.getElementById('summary-output');
const dkimOutput = document.getElementById('dkim-output');
const spfOutput = document.getElementById('spf-output');
const dmarcOutput = document.getElementById('dmarc-output');
const toggleSignedOnlyBtn = document.getElementById('toggle-signed-only');
const themeSelector = document.getElementById('theme-selector');

// Define all themes
const allThemes = [
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
    { id: 'theme-dark-solarized', title: 'Solarized Dark', type: 'dark' },
    { id: 'theme-dark-dracula', title: 'Dracula', type: 'dark' },
    { id: 'theme-dark-monokai', title: 'Monokai', type: 'dark' },
    { id: 'theme-dark-gruvbox', title: 'Gruvbox Dark', type: 'dark' },
    { id: 'theme-dark-catppuccin', title: 'Catppuccin Macchiato', type: 'dark' },
    { id: 'theme-dark-kiwi', title: 'Minimal Kiwi', type: 'dark' },
    { id: 'theme-dark-onedark', title: 'One Dark Pro', type: 'dark' }
];

if (themeSelector) {
    themeSelector.innerHTML = ''; // Clear existing
    
    // Render Light Themes
    allThemes.filter(t => t.type === 'light').forEach(theme => {
        const btn = document.createElement('div');
        btn.className = 'theme-btn';
        btn.dataset.theme = theme.id;
        btn.title = theme.title;
        themeSelector.appendChild(btn);
    });

    // Divider
    const divider = document.createElement('div');
    divider.className = 'theme-separator';
    themeSelector.appendChild(divider);

    // Render Dark Themes
    allThemes.filter(t => t.type === 'dark').forEach(theme => {
        const btn = document.createElement('div');
        btn.className = 'theme-btn';
        btn.dataset.theme = theme.id;
        btn.title = theme.title;
        themeSelector.appendChild(btn);
    });
}

// Inject Paste Area into Drop Zone
const pasteContainer = document.createElement('div');
pasteContainer.className = 'paste-container';
pasteContainer.innerHTML = `
    <div class="divider"><span>OR</span></div>
    <textarea id="paste-input" class="paste-area" placeholder="Paste raw email content here to analyze automatically..."></textarea>
`;
dropZone.appendChild(pasteContainer);

const pasteInput = document.getElementById('paste-input');
pasteInput.addEventListener('click', (e) => e.stopPropagation());

let pasteTimeout;
pasteInput.addEventListener('input', () => {
    clearTimeout(pasteTimeout);
    pasteTimeout = setTimeout(() => {
        const text = pasteInput.value;
        if (text.trim().length > 0) {
            processRawEmail(text);
        }
    }, 800);
});

const copyIcon = '⧉';
const checkIcon = '✓';
const crossIcon = '✗';
const chevronDownIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>`;

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

dropZone.addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    const files = e.target.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
    // Reset value to allow re-selecting the same file
    fileInput.value = '';
});

toggleSignedOnlyBtn.addEventListener('click', () => {
    const isLocked = toggleSignedOnlyBtn.textContent.trim() === '🔐';
    toggleSignedOnlyBtn.textContent = isLocked ? '🔓' : '🔐';
    toggleSignedOnlyBtn.title = isLocked ? 'Show only signed headers' : 'Show all headers';
    displayHeaders();
});

// Load saved theme
const validThemes = allThemes.map(t => t.id);

let savedTheme = localStorage.getItem('emailParserTheme');
if (!savedTheme || !validThemes.includes(savedTheme)) {
    savedTheme = 'theme-light-nord';
}
document.body.className = savedTheme;
updateActiveThemeButton(savedTheme);
themeSelector.addEventListener('click', (e) => {
    if (e.target.classList.contains('theme-btn')) {
        const theme = e.target.dataset.theme;
        document.body.className = theme;
        localStorage.setItem('emailParserTheme', theme);
        updateActiveThemeButton(theme);
    }
});

// Initialize static toggle buttons
document.querySelectorAll('.toggle-section-btn').forEach(btn => {
    if (!btn.querySelector('svg')) {
        btn.innerHTML = chevronDownIcon;
    }
});

document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.copy-btn');
    if (!btn) return;

    const card = btn.closest('.data-card');
    const valueDiv = card ? card.querySelector('.data-value') : null;
    
    if (valueDiv) {
        try {
            const textToCopy = valueDiv.getAttribute('data-full-value') || valueDiv.textContent;
            await navigator.clipboard.writeText(textToCopy);
            btn.innerHTML = checkIcon;
            btn.classList.add('copied');
            setTimeout(() => {
                btn.innerHTML = copyIcon;
                btn.classList.remove('copied');
            }, 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    }
});

document.addEventListener('click', (e) => {
    const btn = e.target.closest('.toggle-section-btn');
    if (btn) {
        const section = btn.closest('.section');
        const content = section.querySelector('div[id$="-output"]');
        
        if (content) {
            // Toggle state
            content.classList.toggle('hidden');
            // Toggle rotation
            btn.classList.toggle('rotated');
            // Update button
            const isHidden = content.classList.contains('hidden');
            btn.title = isHidden ? 'Expand section' : 'Collapse section';
        }
    }
});

document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.copy-trace-btn');
    if (!btn) return;

    try {
        const textToCopy = btn.dataset.value;
        await navigator.clipboard.writeText(textToCopy);
        const originalContent = btn.innerHTML;
        btn.innerHTML = checkIcon;
        btn.classList.add('success');
        setTimeout(() => {
            btn.innerHTML = originalContent;
            btn.classList.remove('success');
        }, 2000);
    } catch (err) {
        console.error('Failed to copy:', err);
    }
});

document.addEventListener('click', (e) => {
    if (e.target.classList.contains('toggle-all-spf')) {
        const btn = e.target;
        const container = btn.closest('.spf-record-card').querySelector('.spf-trace-container');
        if (!container) return;
        
        const isExpanded = btn.textContent.trim() === 'Collapse All';
        const children = container.querySelectorAll('.spf-children');
        
        children.forEach(child => {
            if (isExpanded) child.classList.add('hidden');
            else child.classList.remove('hidden');
        });
        
        btn.textContent = isExpanded ? 'Expand All' : 'Collapse All';
    }
});

function updateActiveThemeButton(theme) {
    const buttons = themeSelector.querySelectorAll('.theme-btn');
    buttons.forEach(btn => {
        if (btn.dataset.theme === theme) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
}


function processFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        processRawEmail(e.target.result);
    };
    reader.readAsText(file);
}

async function processRawEmail(rawText) {
    errorMsg.classList.add('hidden');
    errorMsg.textContent = '';
    resultsDiv.classList.add('hidden');
    
    try {
        const parser = new EmailParser();
        const email = parser.parse(rawText);
        currentEmail = email;
        
        // Manually parse DKIM headers as EmailParser no longer does it
        const dkimHeaders = getHeaderValue(email.headers, 'DKIM-Signature');
        if (dkimHeaders) {
            const dkimParser = new DkimParser();
            if (Array.isArray(dkimHeaders)) {
                email.dkim = dkimHeaders.map(h => dkimParser.parse(h));
            } else {
                email.dkim = [dkimParser.parse(dkimHeaders)];
            }
        }
        
        displaySummary(getHeaderValue(email.headers, 'Subject'), 'Verifying...', 'status-pending');
        displayHeaders();
        displayRelay(getHeaderValue(email.headers, 'Received'));
        displayServerValidation(getHeaderValue(email.headers, 'Authentication-Results'));
        displayDkim(email.dkim);
        displaySpfLoading();
        displayDmarcLoading();
        
        resultsDiv.classList.remove('hidden');
        await runVerification(email);
    } catch (err) {
        errorMsg.textContent = 'Error parsing email: ' + err.message;
        errorMsg.classList.remove('hidden');
        console.error(err);
    }
}

function displaySummary(subject, status, statusClass) {
    const subj = Array.isArray(subject) ? subject[0] : subject;
    const safeSubject = subj ? subj.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '(No Subject)';
    const icon = statusClass.includes('status-pass') ? checkIcon : (statusClass.includes('status-fail') ? crossIcon : '');
    
    summaryOutput.innerHTML = `
        <div class="summary-layout">
            <div class="summary-group">
                <div class="summary-label">Subject</div>
                <div class="summary-value subject-text" title="${safeSubject.replace(/"/g, '&quot;')}">${safeSubject}</div>
            </div>
            <div class="summary-group status-group">
                <div class="summary-label">Result</div>
                <div class="summary-value">
                    <span class="${statusClass} summary-pill">${icon} ${status}</span>
                </div>
            </div>
        </div>
    `;
}

function displayHeaders() {
    if (!currentEmail) return;
    const headers = currentEmail.headers;
    const dkimList = currentEmail.dkim || [];
    const showSignedOnly = toggleSignedOnlyBtn.textContent.trim() === '🔐';

    const headerH2 = headersOutput.closest('.section').querySelector('h2');
    if (headerH2 && headerH2.firstChild.nodeType === 3) {
        headerH2.firstChild.textContent = showSignedOnly ? 'Headers (Signed Only) ' : 'Headers (All) ';
    }

    const signedHeaders = new Set();
    dkimList.forEach(dkim => {
        if (dkim.signedHeaders) {
            dkim.signedHeaders.forEach(h => signedHeaders.add(h.toLowerCase()));
        }
    });

    let html = '<div class="headers-grid">';
    for (const [key, value] of Object.entries(headers)) {
        const isSigned = signedHeaders.has(key.toLowerCase());
        
        if (showSignedOnly && !isSigned) continue;

        const valStr = Array.isArray(value) ? value.join('\n') : value;
        const signedClass = isSigned ? ' signed-header' : '';
        
        html += `
            <div class="data-card${signedClass}">
                <div class="data-key">${key}</div>
                <div class="data-value" title="${valStr.replace(/"/g, '&quot;')}">${valStr.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
                <button class="copy-btn" title="Copy value">${copyIcon}</button>
            </div>`;
    }
    html += '</div>';
    headersOutput.innerHTML = html;
}

function displayRelay(receivedHeaders) {
    // Ensure container exists
    let container = document.getElementById('relay-output');
    if (!container) {
        const section = document.createElement('div');
        section.className = 'section';
        section.innerHTML = `
            <div class="card-header">
                <h3>Email Hops (Relay)</h3>
                <div class="header-controls">
                    <button class="toggle-section-btn" title="Collapse section">${chevronDownIcon}</button>
                </div>
            </div>
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

    if (!receivedHeaders) {
        container.innerHTML = '<p>No Received headers found.</p>';
        return;
    }

    if (typeof RelayParser === 'undefined') {
        container.innerHTML = '<div class="error">RelayParser library not loaded.</div>';
        return;
    }

    let dto;
    try {
        const parser = new RelayParser();
        dto = parser.parse(receivedHeaders);
    } catch (e) {
        container.innerHTML = `<div class="error">Error parsing relay: ${e.message}</div>`;
        return;
    }

    const hopCount = dto.hops.length;
    let totalTime = 'N/A';
    
    if (hopCount > 0) {
        const latest = dto.hops[0];
        const earliest = dto.hops[hopCount - 1];
        if (latest.timestamp && earliest.timestamp) {
            totalTime = ((latest.timestamp - earliest.timestamp) / 1000).toFixed(2) + 's';
        }
    }

    const section = container.closest('.section');
    if (section) {
        const headerH3 = section.querySelector('h3');
        if (headerH3) {
             headerH3.innerHTML = `Email Hops (Relay) <span class="header-stats">${hopCount} hops &bull; ${totalTime}</span>`;
        }
    }

    let html = '<div class="relay-timeline">';
    
    dto.hops.forEach((hop, index) => {
        const side = index % 2 === 0 ? 'left' : 'right';
        const delayStr = hop.delay !== null ? `+${hop.delay.toFixed(2)}s` : (index === dto.hops.length - 1 ? 'Origin' : 'N/A');
        const delayClass = hop.delay > 5 ? 'status-fail' : (hop.delay > 1 ? 'status-pending' : 'status-pass');
        const hopNum = dto.hops.length - index;
        
        html += `
        <div class="relay-hop ${side}">
            <div class="relay-spacer"></div>
            <div class="relay-dot">${hopNum}</div>
            <div class="relay-content">
                <div class="relay-header">
                    <span class="relay-time">${hop.date || 'Unknown Date'}</span>
                    <span class="relay-delay ${delayClass}">${delayStr}</span>
                </div>
                <div class="relay-details">
                    ${hop.from ? `<div><strong>From:</strong> ${hop.from}</div>` : ''}
                    ${hop.ip ? `<div><strong>IP:</strong> ${hop.ip}</div>` : ''}
                    ${hop.by ? `<div><strong>By:</strong> ${hop.by}</div>` : ''}
                    ${hop.with ? `<div><strong>With:</strong> ${hop.with}</div>` : ''}
                </div>
            </div>
        </div>`;
    });

    html += '</div>';
    container.innerHTML = html;
}

function displayServerValidation(headerValue) {
    let container = document.getElementById('server-validation-output');
    if (!container) {
        const section = document.createElement('div');
        section.className = 'section';
        section.innerHTML = `
            <div class="card-header">
                <h3>Server Validation (Authentication-Results)</h3>
                <div class="header-controls">
                    <button class="toggle-section-btn" title="Collapse section">${chevronDownIcon}</button>
                </div>
            </div>
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
        container.innerHTML = '<p class="text-muted">No Authentication-Results header found.</p>';
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
        const icon = statusClass.includes('status-pass') ? checkIcon : (statusClass.includes('status-fail') ? crossIcon : '');
        
        html += `
            <div class="auth-result-card">
                <div class="auth-method">${res.method.toUpperCase()}</div>
                <div class="auth-status ${statusClass}">${icon} ${res.result.toUpperCase()}</div>
            </div>
        `;
    });

    html += `
            </div>
            <div class="mt-15">
                <div class="dns-command-label">Raw Header:</div>
                <div class="data-card">
                    <div class="data-value">${dto.fullHeader}</div>
                    <button class="copy-btn" title="Copy value">${copyIcon}</button>
                </div>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

function displayDkim(dkimList) {
    if (!dkimList || dkimList.length === 0) {
        dkimOutput.innerHTML = '<p>No DKIM signatures found.</p>';
        return;
    }
    let html = '';
    dkimList.forEach((dkim, index) => {
        const domain = dkim.tags.d || 'unknown';
        const selector = dkim.tags.s || 'unknown';
        
        html += `<div class="dkim-signature-card">
            <div class="dkim-card-header">
                <div class="dkim-header-info">
                    <span class="dkim-domain">${domain}</span>
                    <span class="dkim-selector">s=${selector}</span>
                </div>
                <div id="dkim-status-${index}" class="dkim-status-badge status-pending">Verifying...</div>
            </div>
            
            <div id="dkim-verification-${index}"></div>

            <div class="dkim-advanced-toggle" onclick="const el = document.getElementById('dkim-tech-${index}'); el.classList.toggle('hidden'); this.querySelector('.toggle-details-btn').classList.toggle('expanded');">
                <button class="toggle-details-btn">${chevronDownIcon}</button>
                <span>Technical Verification Details</span>
            </div>
            <div id="dkim-tech-${index}" class="hidden"></div>

            <div class="dkim-advanced-toggle" onclick="const el = document.getElementById('dkim-raw-${index}'); el.classList.toggle('hidden'); this.querySelector('.toggle-details-btn').classList.toggle('expanded');">
                <button class="toggle-details-btn">${chevronDownIcon}</button>
                <span>Raw Signature Tags</span>
            </div>
            <div id="dkim-raw-${index}" class="hidden mt-10">
                <div class="tags-grid">`;
        
        for (const [key, value] of Object.entries(dkim.tags)) {
            html += `
                <div class="data-card">
                    <div class="data-key">${key}</div>
                    <div class="data-value" title="${value.replace(/"/g, '&quot;')}">${value}</div>
                    <button class="copy-btn" title="Copy value">${copyIcon}</button>
                </div>`;
        }
        html += `   </div>
            </div>
            <div id="dkim-dns-${index}" class="mt-15"></div>
        </div>`;
    });
    dkimOutput.innerHTML = html;
}

function displaySpfLoading() {
    spfOutput.innerHTML = '<div class="spf-record-card"><span class="status-pending">Fetching SPF Record...</span></div>';
}

function renderSpfTrace(node, depth = 0) {
    if (!node) return '';
    
    const statusClass = node.result === 'Pass' ? 'status-pass' : 
                       (node.result === 'Fail' || node.result === 'SoftFail' ? 'status-fail' : 'status-pending');
    const icon = statusClass.includes('status-pass') ? checkIcon : (statusClass.includes('status-fail') ? crossIcon : '');
    
    const isMatch = node.matchMechanism ? true : false;
    const matchClass = isMatch ? ' match' : '';
    const hasChildren = node.children && node.children.length > 0;
    
    let html = `
        <div class="spf-trace-node${matchClass}" style="--depth: ${depth}">
            <div class="spf-trace-header">
                <strong>${node.domain}</strong>
                <span class="${statusClass} spf-trace-status">${icon} ${node.result}</span>
            </div>
            <div class="spf-trace-record">
                ${node.record || 'No Record'}
            </div>
            ${node.reason ? `<div class="spf-trace-reason">➜ ${node.reason}</div>` : ''}
            
            ${node.dnsCommand ? `
            <div class="spf-trace-dns">
                <span class="spf-dns-cmd">${node.dnsCommand}</span>
                <button class="copy-trace-btn" data-value="${node.dnsCommand}" title="Copy command">${copyIcon}</button>
            </div>` : ''}
        </div>
    `;

    if (hasChildren) {
        html += '<div class="spf-children hidden">';
        node.children.forEach(child => {
            html += renderSpfTrace(child.trace, depth + 1);
        });
        html += '</div>';
    }

    return html;
}

function displaySpf(spfDto) {
    if (spfDto.error && !spfDto.record) {
        spfOutput.innerHTML = `<div class="error">Error: ${spfDto.error}</div>`;
        return;
    }

    const statusClass = spfDto.headerResult === 'pass' ? 'status-pass' : (spfDto.headerResult === 'fail' || spfDto.headerResult === 'softfail' ? 'status-fail' : 'status-pending');
    const statusText = spfDto.headerResult ? spfDto.headerResult.toUpperCase() : 'UNKNOWN';
    const icon = statusClass.includes('status-pass') ? checkIcon : (statusClass.includes('status-fail') ? crossIcon : '');
    
    const dnsOutput = spfDto.rawDns || 'N/A';
    const dnsOutputDisplay = (dnsOutput.length > 255 ? dnsOutput.substring(0, 255) + '...' : dnsOutput)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const dnsOutputAttr = dnsOutput.replace(/&/g, '&amp;').replace(/"/g, '&quot;');

    let html = `
        <div class="spf-record-card">
            <div class="dkim-grid">
                <div><strong>Domain:</strong> <span class="data-value inline-val">${spfDto.domain}</span></div>
                <div><strong>Auth Result:</strong> <span class="${statusClass}">${icon} ${statusText}</span></div>
                ${spfDto.senderIp ? `<div><strong>Sender IP:</strong> ${spfDto.senderIp}</div>` : ''}
            </div>
            
            ${spfDto.matchChain ? `
            <h4 class="mt-15">Match Chain</h4>
            <div class="spf-match-chain">
                ${spfDto.matchChain.map((step, idx) => `
                    <div class="chain-node">
                        <strong>${step.domain}</strong>
                        ${step.mechanism ? `<div class="chain-mech">${step.mechanism}</div>` : ''}
                        <div class="chain-result ${step.result === 'Pass' ? 'pass' : ''}">${step.result}</div>
                    </div>
                    ${idx < spfDto.matchChain.length - 1 ? '<div class="chain-arrow">➜</div>' : ''}
                `).join('')}
            </div>
            ` : ''}

            ${spfDto.trace ? `
            <div class="mt-15 spf-trace-header-container">
                <h4>Evaluation Trace</h4>
                ${(spfDto.trace.children && spfDto.trace.children.length > 0) ? '<button class="toggle-all-spf spf-trace-toggle-btn">Expand All</button>' : ''}
            </div>
            <div class="spf-trace-container">
                ${renderSpfTrace(spfDto.trace)}
            </div>
            ` : ''}

            ${spfDto.record ? `
            <h4>Mechanisms</h4>
            <div class="tags-grid">
                ${spfDto.mechanisms.map(mech => `
                    <div class="data-card">
                        <div class="data-value">${mech}</div>
                        <button class="copy-btn" title="Copy value">${copyIcon}</button>
                    </div>
                `).join('')}
            </div>` : '<div class="error">No SPF record found</div>'}

            <div class="dns-command-card mt-20">
                <div class="dns-command-label">SPF Check Command:</div>
                <div class="data-card">
                    <div class="data-value">${spfDto.dnsCommand}</div>
                    <button class="copy-btn" title="Copy command">${copyIcon}</button>
                </div>
                <div class="dns-command-label mt-12">Raw SPF Record:</div>
                <div class="data-card">
                    <div class="data-value" data-full-value="${dnsOutputAttr}">${dnsOutputDisplay}</div>
                    <button class="copy-btn" title="Copy output">${copyIcon}</button>
                </div>
            </div>
        </div>
    `;
    spfOutput.innerHTML = html;
}

function displayDmarcLoading() {
    dmarcOutput.innerHTML = '<div class="dmarc-record-card"><span class="status-pending">Fetching DMARC Record...</span></div>';
}

function displayDmarc(dmarcDto) {
    if (dmarcDto.error && !dmarcDto.record) {
        dmarcOutput.innerHTML = `<div class="error">Error: ${dmarcDto.error}</div>`;
        return;
    }

    const statusClass = dmarcDto.result === 'pass' ? 'status-pass' : (dmarcDto.result === 'fail' ? 'status-fail' : 'status-pending');
    const spfAlignClass = dmarcDto.spfAlignment === 'pass' ? 'status-pass' : 'status-fail';
    const dkimAlignClass = dmarcDto.dkimAlignment === 'pass' ? 'status-pass' : 'status-fail';
    
    const icon = (cls) => cls.includes('status-pass') ? checkIcon : (cls.includes('status-fail') ? crossIcon : '');

    const dnsOutput = dmarcDto.rawDns || 'N/A';
    const dnsOutputDisplay = (dnsOutput.length > 255 ? dnsOutput.substring(0, 255) + '...' : dnsOutput)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const dnsOutputAttr = dnsOutput.replace(/&/g, '&amp;').replace(/"/g, '&quot;');

    // Tag descriptions for tooltips
    const tagDescriptions = {
        'v': 'Version (must be DMARC1)',
        'p': 'Policy for organizational domain',
        'sp': 'Policy for subdomains',
        'pct': 'Percentage of messages subjected to filtering',
        'rua': 'Reporting URI for Aggregate reports',
        'ruf': 'Reporting URI for Forensic reports',
        'adkim': 'DKIM Alignment mode (r=relaxed, s=strict)',
        'aspf': 'SPF Alignment mode (r=relaxed, s=strict)',
        'fo': 'Failure reporting options',
        'rf': 'Report Format',
        'ri': 'Reporting Interval'
    };

    const getTagTitle = (key) => tagDescriptions[key] || key;

    let html = `
        <div class="dmarc-record-card">
            <div class="dkim-grid">
                <div><strong>From Domain:</strong> <span class="data-value inline-val">${dmarcDto.domain}</span></div>
                ${dmarcDto.fetchedDomain && dmarcDto.fetchedDomain !== dmarcDto.domain ? 
                    `<div><strong>Record Found At:</strong> <span class="data-value inline-val">${dmarcDto.fetchedDomain}</span> <span class="org-domain-hint">(Organizational Domain)</span></div>` : ''}
            </div>
            <div class="dkim-grid mt-10">
                <div><strong>DMARC Result:</strong> <span class="${statusClass}">${icon(statusClass)} ${dmarcDto.result.toUpperCase()}</span></div>
                <div>
                    <strong>SPF Alignment:</strong> <span class="${spfAlignClass}">${icon(spfAlignClass)} ${dmarcDto.spfAlignment.toUpperCase()}</span>
                    ${dmarcDto.spfAlignment !== 'pass' && dmarcDto.spfAuthDomain ? 
                        `<div class="dmarc-auth-domain" title="SPF Authenticated Domain does not match From Domain">Auth: ${dmarcDto.spfAuthDomain}</div>` : ''}
                </div>
                <div><strong>DKIM Alignment:</strong> <span class="${dkimAlignClass}">${icon(dkimAlignClass)} ${dmarcDto.dkimAlignment.toUpperCase()}</span></div>
            </div>

            ${dmarcDto.record ? `
            <h4>Policy Tags</h4>
            <div class="tags-grid">
                ${Object.entries(dmarcDto.tags).map(([key, value]) => `
                    <div class="data-card" title="${getTagTitle(key)}">
                        <div class="data-key">${key}</div>
                        <div class="data-value" title="${value.replace(/"/g, '&quot;')}">${value}</div>
                        <button class="copy-btn" title="Copy value">${copyIcon}</button>
                    </div>`).join('')}
            </div>` : '<div class="error">No DMARC record found</div>'}

            <div class="dns-command-card mt-20">
                <div class="dns-command-label">DMARC Check Command:</div>
                <div class="data-card">
                    <div class="data-value">${dmarcDto.dnsCommand}</div>
                    <button class="copy-btn" title="Copy command">${copyIcon}</button>
                </div>
                <div class="dns-command-label mt-12">Raw DMARC Record:</div>
                <div class="data-card">
                    <div class="data-value" data-full-value="${dnsOutputAttr}">${dnsOutputDisplay}</div>
                    <button class="copy-btn" title="Copy output">${copyIcon}</button>
                </div>
            </div>
        </div>
    `;
    dmarcOutput.innerHTML = html;
}

async function runVerification(email) {
    if (!email.dkim || email.dkim.length === 0) {
        displaySummary(email.headers['Subject'], 'No DKIM Signatures', 'status-fail');
        return;
    }

    const validator = new DkimValidator();
    const dmarcValidator = new DmarcValidator(); // For alignment checks
    
    // Extract From domain
    let fromDomain = null;
    const fromHeader = getHeaderValue(email.headers, 'From');
    if (fromHeader) {
        const val = Array.isArray(fromHeader) ? fromHeader[0] : fromHeader;
        const match = val.match(/@([a-zA-Z0-9.-]+)/);
        if (match) fromDomain = match[1];
    }

    const dkimResults = [];
    let validCount = 0;

    for (let i = 0; i < email.dkim.length; i++) {
        const dkim = email.dkim[i];
        const statusDiv = document.getElementById(`dkim-status-${i}`);
        const verificationDiv = document.getElementById(`dkim-verification-${i}`);
        const dnsDiv = document.getElementById(`dkim-dns-${i}`);
        
        const result = await validator.verify(email, dkim);
        dkimResults.push({ result, dkim });
        if (result.valid) validCount++;
        // Re-run body hash specifically for display details
        const bhResult = await validator.verifyBodyHash(email, dkim);
        
        // Update Status Badge
        const overallClass = result.valid ? 'status-pass' : 'status-fail';
        const overallText = result.valid ? 'PASS' : 'FAIL';
        const icon = result.valid ? checkIcon : crossIcon;
        statusDiv.className = `dkim-status-badge ${overallClass}`;
        statusDiv.innerHTML = `${icon} ${overallText}`;

        // Check alignment (relaxed)
        const dDomain = dkim.tags['d'];
        const isAligned = fromDomain && dmarcValidator.checkAlignment(dDomain, fromDomain, 'r');

        let verificationHtml = '';

        // Alignment Warning
        if (!isAligned && fromDomain && dDomain) {
            verificationHtml += `<div class="dkim-error-details dkim-alignment-warning mb-15">
                <strong>Alignment Warning:</strong> Signing domain (d=${dDomain}) does not align with From domain (${fromDomain})
            </div>`;
        }

        if (!result.valid) {
             const errorMsg = result.error || (result.stage === 'body_hash' ? 'Body Hash Mismatch' : 'Signature Verification Failed');
             verificationHtml += `<div class="error mb-15">${errorMsg}</div>`;
        }

        verificationHtml += `<div class="dkim-overview-grid">`;
        
        // Card 1: Body Hash
        const bhIcon = bhResult.valid ? '✓' : '✗';
        const bhColor = bhResult.valid ? 'var(--success-color)' : 'var(--fail-color)';
        verificationHtml += `
            <div class="dkim-check-card" style="border-left: 4px solid ${bhColor}">
                <div class="dkim-check-header">
                    <span>Body Hash</span>
                    <span style="color: ${bhColor}; font-size: 1.2em;">${bhIcon}</span>
                </div>
                <div>
                    <div class="dkim-check-label">Algorithm</div>
                    <div class="dkim-check-value">${dkim.tags['a'] || 'rsa-sha256'}</div>
                </div>
                <div>
                    <div class="dkim-check-label">Canon (Body)</div>
                    <div class="dkim-check-value">${(dkim.tags['c'] || 'simple/simple').split('/')[1] || 'simple'}</div>
                </div>
                <div>
                    <div class="dkim-check-label">Calculated</div>
                    <div class="dkim-check-value" title="${bhResult.calculated}">${bhResult.calculated ? bhResult.calculated.substring(0, 10) + '...' : 'N/A'}</div>
                </div>
            </div>
        `;

        // Card 2: Signature
        const sigIcon = result.valid ? '✓' : '✗';
        const sigColor = result.valid ? 'var(--success-color)' : 'var(--fail-color)';
        verificationHtml += `
            <div class="dkim-check-card" style="border-left: 4px solid ${sigColor}">
                <div class="dkim-check-header">
                    <span>Signature</span>
                    <span style="color: ${sigColor}; font-size: 1.2em;">${sigIcon}</span>
                </div>
                <div>
                    <div class="dkim-check-label">Selector</div>
                    <div class="dkim-check-value">${dkim.tags['s']}</div>
                </div>
                <div>
                    <div class="dkim-check-label">Canon (Header)</div>
                    <div class="dkim-check-value">${(dkim.tags['c'] || 'simple/simple').split('/')[0]}</div>
                </div>
                <div>
                    <div class="dkim-check-label">Signed Headers</div>
                    <div class="dkim-check-value" title="${dkim.tags['h']}">${dkim.tags['h'] ? dkim.tags['h'].split(':').length : 0} headers</div>
                </div>
            </div>
        `;

        // Card 3: Timestamps
        const signedTime = dkim.tags['t'] ? new Date(parseInt(dkim.tags['t']) * 1000).toLocaleString() : 'Not specified';
        const expireTime = dkim.tags['x'] ? new Date(parseInt(dkim.tags['x']) * 1000).toLocaleString() : 'Not specified';
        
        verificationHtml += `
            <div class="dkim-check-card">
                <div class="dkim-check-header">
                    <span>Timestamps</span>
                    <span>🕒</span>
                </div>
                <div>
                    <div class="dkim-check-label">Signed At</div>
                    <div class="dkim-check-value">${signedTime}</div>
                </div>
                <div>
                    <div class="dkim-check-label">Expires At</div>
                    <div class="dkim-check-value">${expireTime}</div>
                </div>
            </div>
        `;

        verificationHtml += `</div>`; // End grid
        verificationDiv.innerHTML = verificationHtml;

        const techDiv = document.getElementById(`dkim-tech-${i}`);
        if (techDiv) {
            const dataToVerify = result.details?.dataToVerify?.replace(/</g, '&lt;') || 'Not available.';
            const publicKey = dkim.dnsTags?.p || 'Not available.';
            const signature = dkim.tags.b || 'Not available.';

            let techHtml = `
                <div class="tech-details-grid">
                    <div class="tech-detail-card">
                        <span class="tech-label">Body Hash (Expected)</span>
                        <div class="tech-value code">${bhResult.expected || 'N/A'}</div>
                    </div>
                    <div class="tech-detail-card">
                        <span class="tech-label">Body Hash (Calculated)</span>
                        <div class="tech-value code">${bhResult.calculated || 'N/A'}</div>
                    </div>
                    <div class="tech-detail-card full-width">
                        <span class="tech-label">Canonicalized Headers (Data Signed)</span>
                        <pre class="tech-value code scrollable-pre">${dataToVerify}</pre>
                    </div>
                    <div class="tech-detail-card full-width">
                        <span class="tech-label">Public Key (p=)</span>
                        <div class="tech-value code">${publicKey}</div>
                    </div>
                    <div class="tech-detail-card full-width">
                        <span class="tech-label">Signature (b=)</span>
                        <div class="tech-value code">${signature}</div>
                    </div>
                </div>`;
            techDiv.innerHTML = techHtml;
        }

        const dnsOutput = dkim.dnsRaw || 'N/A';
        const dnsOutputDisplay = (dnsOutput.length > 255 ? dnsOutput.substring(0, 255) + '...' : dnsOutput)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const dnsOutputAttr = dnsOutput.replace(/&/g, '&amp;').replace(/"/g, '&quot;');

        dnsDiv.innerHTML = `
            <div class="dns-command-card mt-20">
                <div class="dns-command-label">DKIM Policy Check Command:</div>
                <div class="data-card">
                    <div class="data-value">${dkim.dnsCommand || `dig TXT ${dkim.tags['s'] || 'selector'}._domainkey.${dkim.tags['d'] || 'domain'}`}</div>
                    <button class="copy-btn" title="Copy command">${copyIcon}</button>
                </div>
                ${dkim.dnsTags ? `
                <div class="dns-command-label mt-12">Parsed Policy Tags:</div>
                <div class="tags-grid">
                    ${Object.entries(dkim.dnsTags).map(([key, value]) => `
                        <div class="data-card">
                            <div class="data-key">${key}</div>
                            <div class="data-value" title="${value.replace(/"/g, '&quot;')}">${value}</div>
                            <button class="copy-btn" title="Copy value">${copyIcon}</button>
                        </div>`).join('')}
                </div>` : ''}
                <div class="dns-command-label mt-12">Raw DKIM Policy Record:</div>
                <div class="data-card">
                    <div class="data-value" data-full-value="${dnsOutputAttr}">${dnsOutputDisplay}</div>
                    <button class="copy-btn" title="Copy output">${copyIcon}</button>
                </div>
            </div>`;
    }
            
    // Run SPF Verification
    
    const spfValidator = new SpfValidator();
    const spfResult = await spfValidator.verify(email);
    displaySpf(spfResult);

    // Run DMARC Verification
    const dmarcResult = await dmarcValidator.verify(email, spfResult, dkimResults);
    displayDmarc(dmarcResult);

    const overallStatus = validCount > 0 ? 'PASS' : 'FAIL';
    const statusClass = validCount > 0 ? 'status-pass' : 'status-fail';
    displaySummary(getHeaderValue(email.headers, 'Subject'), overallStatus, statusClass);
}

function getHeaderValue(headers, key) {
    if (!headers) return undefined;
    const match = Object.keys(headers).find(k => k.toLowerCase() === key.toLowerCase());
    return match ? headers[match] : undefined;
}
