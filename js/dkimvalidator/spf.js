/**
 * DKIM Validator - SPF Module
 * SPF record parsing and evaluation
 */

import { log, ipv4MatchesCIDR, ipv6MatchesCIDR } from './utils.js';
import { fetchSpfRecord, fetchARecords, fetchAAAARecords, fetchMXRecords } from './dns.js';

// ============================================================================
// SPF Parsing
// ============================================================================

/**
 * Parse SPF record into mechanisms
 * @param {string} record - SPF record string
 * @returns {Array} Array of mechanism objects
 */
export function parseSpfRecord(record) {
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

// ============================================================================
// SPF Evaluation
// ============================================================================

/**
 * Evaluate SPF for a given sender IP and domain
 * @param {Object} senderIP - Sender IP object {ip, version}
 * @param {string} domain - Mail domain
 * @param {number} depth - Recursion depth
 * @param {Object} lookupCount - DNS lookup counter
 * @param {Object} trace - Evaluation trace object
 * @returns {Promise<Object>} SPF evaluation result
 */
export async function evaluateSpf(senderIP, domain, depth = 0, lookupCount = { count: 0 }, trace = null) {
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
