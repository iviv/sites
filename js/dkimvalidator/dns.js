/**
 * DKIM Validator - DNS Module
 * DNS lookup functions for DKIM, SPF, DMARC, BIMI, MTA-STS
 */

import { log, cleanDnsRecord, parseTagValuePairs } from './utils.js';

// ============================================================================
// Generic DNS Query Helper
// ============================================================================

/**
 * Generic DNS query helper
 * @param {string} domain - Domain to query
 * @param {string} type - DNS record type (A, AAAA, MX, TXT)
 * @param {number} typeCode - DNS type code for filtering answers
 * @param {function} extractor - Function to extract data from answer record
 * @returns {Promise<Array>} Array of extracted values
 */
export async function fetchDnsRecords(domain, type, typeCode, extractor) {
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

// ============================================================================
// Specific Record Type Lookups
// ============================================================================

/**
 * Fetch A records for a domain
 * @param {string} domain - Domain to query
 * @returns {Promise<string[]>} Array of IPv4 addresses
 */
export async function fetchARecords(domain) {
    return fetchDnsRecords(domain, 'A', 1, a => a.data);
}

/**
 * Fetch AAAA records for a domain
 * @param {string} domain - Domain to query
 * @returns {Promise<string[]>} Array of IPv6 addresses
 */
export async function fetchAAAARecords(domain) {
    return fetchDnsRecords(domain, 'AAAA', 28, a => a.data);
}

/**
 * Fetch MX records for a domain
 * @param {string} domain - Domain to query
 * @returns {Promise<string[]>} Array of MX hostnames
 */
export async function fetchMXRecords(domain) {
    return fetchDnsRecords(domain, 'MX', 15, a => {
        const parts = a.data.split(' ');
        return parts.length >= 2 ? parts[1].replace(/\.$/, '') : null;
    });
}

// ============================================================================
// DKIM DNS Lookup
// ============================================================================

/**
 * Fetch DKIM public key from DNS
 * @param {string} domain - Signing domain
 * @param {string} selector - DKIM selector
 * @returns {Promise<{ok: boolean, record?: string, name: string, error?: string}>}
 */
export async function fetchDkimDns(domain, selector) {
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
// SPF DNS Lookup
// ============================================================================

/**
 * Fetch SPF record for a domain
 * @param {string} domain - Domain to query
 * @returns {Promise<{ok: boolean, record?: string, domain: string, error?: string}>}
 */
export async function fetchSpfRecord(domain) {
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

// ============================================================================
// DMARC DNS Lookup
// ============================================================================

/**
 * Fetch DMARC record for a domain
 * @param {string} domain - Domain to query
 * @returns {Promise<{ok: boolean, record?: string, domain: string, dmarcDomain: string, error?: string}>}
 */
export async function fetchDmarcRecord(domain) {
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

// ============================================================================
// BIMI DNS Lookup
// ============================================================================

/**
 * Fetch BIMI record for a domain
 * @param {string} domain - Domain to lookup
 * @returns {Promise<{ok: boolean, record?: string, l?: string, a?: string, error?: string}>}
 */
export async function fetchBimiRecord(domain) {
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

// ============================================================================
// MTA-STS DNS Lookup
// ============================================================================

/**
 * Parse MTA-STS policy file
 * @param {string} policyText - Raw policy text
 * @returns {Object} Parsed policy
 */
export function parseMtaStsPolicy(policyText) {
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
 * Fetch MTA-STS record and policy for a domain
 * @param {string} domain - Domain to lookup
 * @returns {Promise<{ok: boolean, record?: string, policy?: Object, error?: string}>}
 */
export async function fetchMtaStsRecord(domain) {
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
