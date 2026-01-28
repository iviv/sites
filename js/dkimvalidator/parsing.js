/**
 * DKIM Validator - Email Parsing Module
 * Functions for parsing email headers, body, and extracting information
 */

import { log, parseTagValuePairs, isPrivateIP } from './utils.js';
import { AUTH_RESULTS } from './constants.js';

// ============================================================================
// Email Parsing
// ============================================================================

/**
 * Parse raw email into headers and body
 * @param {string} raw - Raw email content
 * @returns {{headers: Array, body: string, dkimSigs: Array, errors: Array, warnings: Array}}
 */
export function parseEmail(raw) {
    const errors = [];
    const warnings = [];

    if (!raw || raw.trim().length === 0) {
        errors.push({ type: 'empty', message: 'No email content provided', suggestion: 'Paste the raw email source including headers and body' });
        return { headers: [], body: '', dkimSigs: [], authResults: [], errors, warnings };
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

// ============================================================================
// DKIM Tag Parsing
// ============================================================================

/**
 * Parse DKIM signature tags
 * @param {string} raw - Raw DKIM-Signature header
 * @returns {Object|null} Parsed tags or null
 */
export function parseDkimTags(raw) {
    const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
    const match = unfolded.match(/DKIM-Signature:\s*(.+)/i);
    if (!match) return null;
    return parseTagValuePairs(match[1], ['b', 'bh']);
}

/**
 * Parse DNS TXT record tags
 * @param {string} record - DNS TXT record content
 * @returns {Object} Parsed tags
 */
export function parseDnsTags(record) {
    return parseTagValuePairs(record, ['p']);
}

// ============================================================================
// Authentication-Results Header Parsing (RFC 8601)
// ============================================================================

/**
 * Parse Authentication-Results header
 * @param {string} value - Header value
 * @returns {Object} Parsed authentication results
 */
export function parseAuthenticationResults(value) {
    const unfolded = value.replace(/\r?\n[ \t]+/g, ' ').trim();
    const result = {
        authserv_id: null,
        version: null,
        results: []
    };

    // Extract authserv-id (the first token before any semicolon)
    const firstSemicolon = unfolded.indexOf(';');
    if (firstSemicolon === -1) {
        // No results, just authserv-id
        result.authserv_id = unfolded.trim();
        return result;
    }

    const authservPart = unfolded.slice(0, firstSemicolon).trim();
    // authserv-id might have a version number
    const versionMatch = authservPart.match(/^(.+?)\s+(\d+)$/);
    if (versionMatch) {
        result.authserv_id = versionMatch[1].trim();
        result.version = parseInt(versionMatch[2], 10);
    } else {
        result.authserv_id = authservPart;
    }

    // Parse individual results (each separated by semicolons)
    const resultsPart = unfolded.slice(firstSemicolon + 1);

    // Split by semicolons but be careful of quoted strings
    const resultEntries = splitAuthResults(resultsPart);

    for (const entry of resultEntries) {
        const parsed = parseAuthResultEntry(entry.trim());
        if (parsed) {
            result.results.push(parsed);
        }
    }

    return result;
}

/**
 * Split auth results by semicolons, respecting quoted strings
 * @param {string} str - Results string
 * @returns {string[]} Array of result entries
 */
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

/**
 * Parse a single auth result entry
 * @param {string} entry - Single result entry (e.g., "dkim=pass header.d=example.com")
 * @returns {Object|null} Parsed result or null
 */
function parseAuthResultEntry(entry) {
    if (!entry) return null;

    // Match: method=result (optional reason) prop1=val1 prop2=val2 ...
    // Methods: dkim, spf, dmarc, auth, iprev, etc.
    const methodMatch = entry.match(/^(\w+)\s*=\s*(\w+)/);
    if (!methodMatch) return null;

    const method = methodMatch[1].toLowerCase();
    const resultCode = methodMatch[2].toLowerCase();

    const parsed = {
        method,
        result: resultCode,
        resultInfo: AUTH_RESULTS[resultCode] || { name: resultCode.toUpperCase(), desc: 'Unknown result', color: 'neutral', icon: '?' },
        properties: {},
        reason: null,
        comment: null
    };

    // Extract reason in parentheses
    const reasonMatch = entry.match(/\(\s*([^)]+)\s*\)/);
    if (reasonMatch) {
        parsed.reason = reasonMatch[1].trim();
    }

    // Extract properties (prop.subprop=value or prop=value)
    const propRegex = /([\w.]+)\s*=\s*(?:"([^"]+)"|([^\s;]+))/g;
    let match;
    let skipFirst = true;

    while ((match = propRegex.exec(entry)) !== null) {
        // Skip the first match which is method=result
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
// Relay Chain Parsing
// ============================================================================

/**
 * Parse Received headers into relay chain
 * @param {Array} headers - Email headers
 * @returns {Array} Array of hop objects
 */
export function parseRelayChain(headers) {
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

        // X-Received format: by 2002:a17:90a:abc:0:0:0:0 with SMTP id xyz; timestamp
        const byMatch = val.match(/by\s+([^\s;]+)/i);
        if (byMatch) hop.by = byMatch[1];

        const withMatch = val.match(/with\s+(\w+)/i);
        if (withMatch) hop.protocol = withMatch[1].toUpperCase();

        // Extract timestamp from X-Received
        const dateMatch = val.match(/;\s*([A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*[+-]?\d{0,4})/);
        if (dateMatch) {
            try {
                hop.timestamp = new Date(dateMatch[1]);
                if (isNaN(hop.timestamp.getTime())) hop.timestamp = null;
            } catch { hop.timestamp = null; }
        }

        // Extract SMTP ID if present
        const idMatch = val.match(/id\s+([^\s;]+)/i);
        if (idMatch) hop.smtpId = idMatch[1];

        hops.push(hop);
    }

    // Sort by timestamp if available, otherwise keep order
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

// ============================================================================
// Domain/IP Extraction
// ============================================================================

/**
 * Extract mail domain from headers (Return-Path or From)
 * @param {Array} headers - Email headers
 * @returns {string|null} Domain or null
 */
export function extractMailDomain(headers) {
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

/**
 * Extract From header domain (for DMARC alignment)
 * @param {Array} headers - Email headers
 * @returns {string|null} Domain or null
 */
export function extractFromDomain(headers) {
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

/**
 * Extract sender IP from Received headers
 * @param {Array} headers - Email headers
 * @returns {{ip: string, version: number}|null} IP info or null
 */
export function extractSenderIP(headers) {
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

// ============================================================================
// ARC Parsing
// ============================================================================

/**
 * Parse ARC headers into sets
 * @param {Array} headers - Email headers
 * @returns {Array} Array of ARC set objects
 */
export function parseArcHeaders(headers) {
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

/**
 * Parse ARC tag=value pairs
 * @param {string} value - ARC header value
 * @returns {Object} Parsed tags
 */
export function parseArcTags(value) {
    const unfolded = value.replace(/\r?\n[ \t]+/g, ' ');
    return parseTagValuePairs(unfolded, ['b', 'bh']);
}

/**
 * Parse ARC-Authentication-Results header
 * @param {string} value - Header value
 * @returns {Object} Parsed results
 */
export function parseArcAuthResults(value) {
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
