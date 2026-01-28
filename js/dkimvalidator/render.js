/**
 * DKIM Validator - Rendering Module
 * Functions for rendering HTML output
 */

import { esc, getBadgeForResult, formatLatency, getLatencyClass, logs } from './utils.js';
import {
    DKIM_TAGS, DNS_TAGS, SPF_MECHANISMS, SPF_QUALIFIERS, SPF_RESULTS,
    DMARC_TAGS, DMARC_POLICIES, ARC_SEAL_TAGS, ARC_CV_STATUS,
    MTA_STS_MODES, AUTH_RESULTS, RFC_LINKS, SECURITY_IMPLICATIONS
} from './constants.js';
import { parseSpfRecord } from './spf.js';
import { parseDmarcRecord } from './dmarc.js';

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate RFC link HTML
 * @param {string} rfcNum - RFC number
 * @param {string} section - Section reference
 * @returns {string} HTML link
 */
function renderRfcLink(rfcNum, section) {
    const rfcInfo = RFC_LINKS[rfcNum];
    if (!rfcInfo) return '';
    const url = section ? `${rfcInfo.url}#section-${section}` : rfcInfo.url;
    return `<a href="${esc(url)}" target="_blank" rel="noopener" class="rfc-link" title="${esc(rfcInfo.title)}">RFC ${rfcNum}${section ? ' §' + section : ''}</a>`;
}

/**
 * Render security implication tooltip/hint
 * @param {string} type - Type of check (dkim, spf, dmarc, overall)
 * @param {string} result - Result code
 * @returns {string} HTML string
 */
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
// Tag Rendering
// ============================================================================

/**
 * Render a single tag element
 * @param {string} name - Tag name
 * @param {string} value - Tag value
 * @param {Object} info - Tag info object with name and desc
 * @param {string} classes - Additional CSS classes
 * @returns {string} HTML string
 */
export function renderTag(name, value, info, classes = '') {
    const short = value.length > 25 ? value.slice(0, 25) + '\u2026' : value;
    const rfcLink = info.rfc ? renderRfcLink(info.rfc, info.section) : '';
    const descWithRfc = info.rfc ? info.desc.replace(/\[RFC \d+[^\]]*\]/, '') + ' ' : info.desc;
    return `<div class="tag ${classes}" data-tag="${esc(name)}" data-tag-name="${esc(info.name)}" data-tag-desc="${esc(descWithRfc)}" data-tag-value="${esc(value)}" ${info.rfc ? `data-rfc="${info.rfc}" data-section="${info.section || ''}"` : ''}>
        <span class="dot"></span>
        <span class="tag-name">${esc(name)}</span>
        <span class="tag-value">${esc(short)}</span>
        <button class="copy-btn" onclick="event.stopPropagation();copy(this,\`${esc(value.replace(/`/g, ''))}\`)">&#x29C9;</button>
    </div>`;
}

// ============================================================================
// Headers Rendering
// ============================================================================

/**
 * Render email headers section
 * @param {Array} headers - Email headers
 * @param {Set} signed - Set of signed header names
 * @returns {string} HTML string
 */
export function renderHeaders(headers, signed) {
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

// ============================================================================
// Overall Authentication Summary
// ============================================================================

/**
 * Compute overall authentication status
 * @param {Object} results - All authentication results
 * @returns {Object} Overall status with level, message, details
 */
export function computeOverallStatus(results) {
    const { dkimResults, spfResult, dmarcResult, authResults } = results;

    let level = 'unknown'; // pass, partial, fail, unknown
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

    // Generate message
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

/**
 * Render overall authentication summary card
 * @param {Object} results - All authentication results
 * @returns {string} HTML string
 */
export function renderOverallSummary(results) {
    const status = computeOverallStatus(results);

    const passesHtml = status.passes.map(p =>
        `<span class="auth-check pass" data-type="${p.type}">\u2713 ${esc(p.text)}</span>`
    ).join('');

    const issuesHtml = status.issues.map(i =>
        `<span class="auth-check ${i.severity === 'error' ? 'fail' : 'warn'}" data-type="${i.type}">${i.severity === 'error' ? '\u2717' : '\u26A0'} ${esc(i.text)}</span>`
    ).join('');

    // Score ring visualization
    const scoreColor = status.score >= 80 ? 'var(--success)' : (status.score >= 50 ? 'var(--warning)' : 'var(--error)');
    const scorePercent = (status.score / 100) * 283; // circumference for r=45
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
// Authentication-Results Rendering
// ============================================================================

/**
 * Render Authentication-Results header section
 * @param {Array} authResults - Parsed auth results
 * @returns {string} HTML string
 */
export function renderAuthenticationResults(authResults) {
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

// ============================================================================
// DKIM Signature Rendering
// ============================================================================

/**
 * Render a DKIM signature card
 * @param {Object} r - Verification result
 * @param {number} i - Signature number
 * @returns {string} HTML string
 */
export function renderSig(r, i) {
    const errHtml = r.errors.map(e => `<div class="error-msg">${esc(e)}</div>`).join('');
    const warnHtml = (r.warnings || []).map(w => `<div class="warning-msg">\u26A0\uFE0F <strong>Security Warning:</strong> ${esc(w.message)}<span class="suggestion">${esc(w.detail)}</span></div>`).join('');
    const dkimTags = Object.entries(r.tags).map(([k, v]) => renderTag(k, v, DKIM_TAGS[k] || { name: k.toUpperCase(), desc: 'DKIM tag' }, 'signed')).join('');
    const dnsTags = r.dnsTags ? Object.entries(r.dnsTags).map(([k, v]) => renderTag(k, v, DNS_TAGS[k] || { name: k.toUpperCase(), desc: 'DNS tag' }, 'dns')).join('') : '';
    const dnsCmd = `dig TXT ${r.dns?.name || r.selector + '._domainkey.' + r.domain}`;
    const hasWarnings = r.warnings && r.warnings.length > 0;

    return `<div class="sig-card ${r.status} expanded">
        <div class="sig-header" onclick="toggleCard(this)">
            <div class="sig-title">
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

// ============================================================================
// SPF Rendering
// ============================================================================

/**
 * Render SPF mechanism tag
 * @param {Object} mech - Mechanism object
 * @returns {string} HTML string
 */
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

/**
 * Get default policy from mechanisms
 * @param {Array} mechanisms - SPF mechanisms
 * @returns {string} Policy name
 */
function getDefaultPolicy(mechanisms) {
    const allMech = mechanisms.find(m => m.mechanism === 'all');
    if (!allMech) return 'None (default: neutral)';
    const qual = SPF_QUALIFIERS[allMech.qualifier];
    return qual ? qual.name : 'Unknown';
}

/**
 * Get default policy CSS class
 * @param {Array} mechanisms - SPF mechanisms
 * @returns {string} CSS class
 */
function getDefaultPolicyClass(mechanisms) {
    const allMech = mechanisms.find(m => m.mechanism === 'all');
    if (!allMech) return 'neutral';
    const qual = SPF_QUALIFIERS[allMech.qualifier];
    return qual ? qual.color : 'neutral';
}

/**
 * Render SPF evaluation section
 * @param {Object} evalResult - SPF evaluation result
 * @returns {string} HTML string
 */
export function renderSpfEvaluation(evalResult) {
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

// ============================================================================
// DMARC Rendering
// ============================================================================

/**
 * Render DMARC tag
 * @param {string} name - Tag name
 * @param {string} value - Tag value
 * @returns {string} HTML string
 */
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

/**
 * Render DMARC section
 * @param {Object} dmarcResult - DMARC lookup result
 * @returns {string} HTML string
 */
export function renderDmarc(dmarcResult) {
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

// ============================================================================
// ARC Rendering
// ============================================================================

/**
 * Render ARC chain section
 * @param {Array} arcSets - ARC sets
 * @returns {string} HTML string
 */
export function renderArc(arcSets) {
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

// ============================================================================
// Relay Chain Rendering
// ============================================================================

/**
 * Render email relay chain
 * @param {Array} hops - Relay hops
 * @returns {string} HTML string
 */
export function renderRelayChain(hops) {
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
// BIMI Rendering
// ============================================================================

/**
 * Render BIMI section
 * @param {Object} bimiResult - BIMI lookup result
 * @returns {string} HTML string
 */
export function renderBimi(bimiResult) {
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
// MTA-STS Rendering
// ============================================================================

/**
 * Render MTA-STS section
 * @param {Object} stsResult - MTA-STS lookup result
 * @returns {string} HTML string
 */
export function renderMtaSts(stsResult) {
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
// Debug Log Rendering
// ============================================================================

/**
 * Render debug log
 * @returns {string} HTML string
 */
export function renderDebug() {
    return logs.map(l => `<div class="log-entry"><span class="log-time">${l.time}</span><span class="log-type ${l.type}">${l.type.toUpperCase()}</span><span class="log-msg">${esc(l.msg)}</span></div>`).join('');
}

// ============================================================================
// Summary Rendering
// ============================================================================

/**
 * Render validation summary
 * @param {Object} params - Summary parameters
 * @returns {string} HTML string
 */
export function renderSummary(params) {
    const { spfResult, dkimResults } = params;
    const valid = dkimResults?.filter(r => r.status === 'valid').length || 0;
    const invalid = (dkimResults?.length || 0) - valid;

    const spfSummaryClass = spfResult?.result === 'pass' ? 'success' : (spfResult?.result === 'fail' || spfResult?.result === 'permerror' ? 'error' : 'warning');
    const spfSummaryIcon = spfResult?.result === 'pass' ? '\u2713' : (spfResult?.result === 'fail' || spfResult?.result === 'permerror' ? '\u2717' : '?');
    const spfSummaryLabel = spfResult ? (SPF_RESULTS[spfResult.result]?.name || 'Unknown') : 'N/A';

    return `
        <div class="summary-item"><div class="summary-icon">\uD83D\uDEE1\uFE0F</div><div><span class="summary-value ${spfSummaryClass}">${spfSummaryIcon}</span><div class="summary-label">SPF ${spfSummaryLabel}</div></div></div>
        <div class="summary-item"><div class="summary-icon">\uD83D\uDCE7</div><div><span class="summary-value">${dkimResults?.length || 0}</span><div class="summary-label">DKIM Signatures</div></div></div>
        <div class="summary-item"><div class="summary-icon">\u2713</div><div><span class="summary-value success">${valid}</span><div class="summary-label">Valid</div></div></div>
        <div class="summary-item"><div class="summary-icon">\u2717</div><div><span class="summary-value error">${invalid}</span><div class="summary-label">Invalid</div></div></div>
    `;
}
