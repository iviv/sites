/**
 * DKIM Validator - Utility Functions Module
 * Common utility functions used across modules
 */

// ============================================================================
// State - Shared logging
// ============================================================================

export const logs = [];

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * HTML escape function for safe rendering
 * @param {string} s - String to escape
 * @returns {string} Escaped string
 */
export function esc(s) {
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

/**
 * Log a message to the debug log
 * @param {string} type - Log type (info, error, success, warn)
 * @param {string} msg - Log message
 */
export function log(type, msg) {
    logs.push({ time: new Date().toISOString().split('T')[1].split('.')[0], type, msg });
}

/**
 * Clear all logs
 */
export function clearLogs() {
    logs.length = 0;
}

/**
 * Clean DNS TXT record data by removing quotes and joining split strings
 * @param {string} data - Raw DNS TXT record data
 * @returns {string} Cleaned record string
 */
export function cleanDnsRecord(data) {
    return data.replace(/^"|"$/g, '').replace(/" "/g, '');
}

/**
 * Parse tag=value pairs from a record string (used by DKIM, DMARC, ARC)
 * @param {string} record - Record string with tag=value; format
 * @param {string[]} stripWhitespace - Tags that should have whitespace removed
 * @returns {Object} Object with tag names as keys
 */
export function parseTagValuePairs(record, stripWhitespace = []) {
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
export function getBadgeForResult(result, type = 'generic') {
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

/**
 * Format latency in human-readable form
 * @param {number} ms - Latency in milliseconds
 * @returns {string|null} Formatted string or null
 */
export function formatLatency(ms) {
    if (ms === undefined || ms === null) return null;
    if (ms < 0) ms = 0;
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    if (ms < 3600000) return `${(ms / 60000).toFixed(1)}m`;
    return `${(ms / 3600000).toFixed(1)}h`;
}

/**
 * Get CSS class for latency value
 * @param {number} ms - Latency in milliseconds
 * @returns {string} CSS class name
 */
export function getLatencyClass(ms) {
    if (ms === undefined || ms === null) return '';
    if (ms < 1000) return 'fast';
    if (ms < 10000) return 'medium';
    return 'slow';
}

// ============================================================================
// IP Address Utilities
// ============================================================================

/**
 * Convert IPv4 address to integer
 * @param {string} ip - IPv4 address string
 * @returns {number} Integer representation
 */
export function ipv4ToInt(ip) {
    const parts = ip.split('.').map(Number);
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Check if IPv4 matches CIDR range
 * @param {string} ip - IPv4 address
 * @param {string} cidr - CIDR notation (e.g., "192.168.1.0/24")
 * @returns {boolean} True if IP is in range
 */
export function ipv4MatchesCIDR(ip, cidr) {
    let [network, prefixStr] = cidr.split('/');
    const prefix = prefixStr ? parseInt(prefixStr, 10) : 32;

    const ipInt = ipv4ToInt(ip);
    const networkInt = ipv4ToInt(network);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;

    return (ipInt & mask) === (networkInt & mask);
}

/**
 * Expand shortened IPv6 address to full form
 * @param {string} ip - IPv6 address
 * @returns {string} Expanded IPv6 address
 */
export function expandIPv6(ip) {
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

/**
 * Convert IPv6 address to BigInt
 * @param {string} ip - IPv6 address
 * @returns {BigInt} BigInt representation
 */
export function ipv6ToBigInt(ip) {
    const expanded = expandIPv6(ip);
    const hex = expanded.replace(/:/g, '');
    return BigInt('0x' + hex);
}

/**
 * Check if IPv6 matches CIDR range
 * @param {string} ip - IPv6 address
 * @param {string} cidr - CIDR notation
 * @returns {boolean} True if IP is in range
 */
export function ipv6MatchesCIDR(ip, cidr) {
    let [network, prefixStr] = cidr.split('/');
    const prefix = prefixStr ? parseInt(prefixStr, 10) : 128;

    const ipBig = ipv6ToBigInt(ip);
    const networkBig = ipv6ToBigInt(network);
    const mask = prefix === 0 ? 0n : (~0n << BigInt(128 - prefix));

    return (ipBig & mask) === (networkBig & mask);
}

/**
 * Check if IP is a private/internal address
 * @param {string} ip - IPv4 address
 * @returns {boolean} True if private
 */
export function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    return false;
}
