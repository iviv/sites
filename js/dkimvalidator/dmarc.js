/**
 * DKIM Validator - DMARC Module
 * DMARC record parsing and alignment checking
 */

import { parseTagValuePairs } from './utils.js';

// ============================================================================
// DMARC Parsing
// ============================================================================

/**
 * Parse DMARC record into tags
 * @param {string} record - DMARC record string
 * @returns {Object} Parsed tags
 */
export function parseDmarcRecord(record) {
    return parseTagValuePairs(record);
}

// ============================================================================
// Domain Utilities
// ============================================================================

/**
 * Get the organizational domain (registrable domain) from a hostname
 * This is a simplified implementation - production would use Public Suffix List
 * @param {string} domain - Full domain name
 * @returns {string} Organizational domain
 */
export function getOrganizationalDomain(domain) {
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

// ============================================================================
// Alignment Checking
// ============================================================================

/**
 * Check DKIM alignment for DMARC
 * @param {string} fromDomain - Domain from the From header
 * @param {string} dkimDomain - Domain from DKIM d= tag
 * @param {string} mode - Alignment mode: 'r' (relaxed) or 's' (strict)
 * @returns {{aligned: boolean, mode: string, fromDomain: string, dkimDomain: string}}
 */
export function checkDkimAlignment(fromDomain, dkimDomain, mode = 'r') {
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
export function checkSpfAlignment(fromDomain, mailFromDomain, mode = 'r') {
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

// ============================================================================
// DMARC Evaluation
// ============================================================================

/**
 * Evaluate DMARC policy based on DKIM and SPF results
 * @param {Object} params - Evaluation parameters
 * @returns {Object} DMARC evaluation result
 */
export function evaluateDmarc(params) {
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
