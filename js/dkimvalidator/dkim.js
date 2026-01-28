/**
 * DKIM Validator - DKIM Verification Module
 * DKIM signature verification and cryptographic functions
 */

import { log } from './utils.js';
import { fetchDkimDns } from './dns.js';
import { parseDnsTags } from './parsing.js';

// ============================================================================
// Canonicalization (RFC 6376)
// ============================================================================

/**
 * Canonicalize header using relaxed algorithm
 * @param {string} name - Header name
 * @param {string} value - Header value
 * @returns {string} Canonicalized header line
 */
export function canonHeaderRelaxed(name, value) {
    let v = value.replace(/\r?\n[ \t]+/g, ' ').replace(/[ \t]+/g, ' ').trim();
    return name.toLowerCase() + ':' + v;
}

/**
 * Canonicalize body using relaxed algorithm
 * @param {string} body - Email body
 * @returns {string} Canonicalized body
 */
export function canonBodyRelaxed(body) {
    if (!body) return '\r\n';
    let c = body.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
    c = c.split('\r\n').map(l => l.replace(/[ \t]+/g, ' ').replace(/ +$/, '')).join('\r\n');
    c = c.replace(/(\r\n)+$/, '') || '';
    return c + '\r\n';
}

/**
 * Canonicalize body using simple algorithm
 * @param {string} body - Email body
 * @returns {string} Canonicalized body
 */
export function canonBodySimple(body) {
    if (!body) return '\r\n';
    let c = body.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
    c = c.replace(/(\r\n)+$/, '') || '';
    return c + '\r\n';
}

// ============================================================================
// Cryptographic Functions
// ============================================================================

/**
 * Convert base64 string to ArrayBuffer
 * @param {string} b64 - Base64 string
 * @returns {ArrayBuffer} Decoded buffer
 */
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

/**
 * ASN.1 length encoding helper
 * @param {number} tag - ASN.1 tag
 * @param {number} len - Length value
 * @returns {Uint8Array} Encoded tag and length
 */
function asn1Len(tag, len) {
    if (len < 128) return new Uint8Array([tag, len]);
    if (len < 256) return new Uint8Array([tag, 0x81, len]);
    return new Uint8Array([tag, 0x82, (len >> 8) & 0xff, len & 0xff]);
}

/**
 * Convert PKCS#1 RSA key to SPKI format
 * @param {Uint8Array} pkcs1 - PKCS#1 encoded key
 * @returns {ArrayBuffer} SPKI encoded key
 */
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

/**
 * Import RSA public key for verification
 * @param {string} b64 - Base64 encoded public key
 * @param {string} algorithm - Signing algorithm (rsa-sha256 or rsa-sha1)
 * @returns {Promise<CryptoKey>} Imported key
 */
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

/**
 * Compute body hash
 * @param {string} body - Email body
 * @param {string} canon - Canonicalization method
 * @param {string|undefined} limit - Body length limit
 * @param {string} algorithm - Hash algorithm
 * @returns {Promise<string>} Base64 encoded hash
 */
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

/**
 * Build the signing input for verification
 * @param {Array} headers - Email headers
 * @param {Object} tags - DKIM signature tags
 * @param {string} rawDkim - Raw DKIM-Signature header
 * @param {string} headerCanon - Header canonicalization method
 * @returns {string} Signing input string
 */
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

/**
 * Verify signature
 * @param {string} input - Signing input
 * @param {string} sig - Base64 signature
 * @param {CryptoKey} key - Public key
 * @returns {Promise<boolean>} True if valid
 */
async function verifySig(input, sig, key) {
    try {
        return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64ToBuffer(sig), new TextEncoder().encode(input));
    } catch { return false; }
}

// ============================================================================
// DKIM Verification
// ============================================================================

/**
 * Verify a DKIM signature
 * @param {Object} sig - Signature object with raw and parsed properties
 * @param {Array} headers - Email headers
 * @param {string} body - Email body
 * @returns {Promise<Object>} Verification result
 */
export async function verifyDkim(sig, headers, body) {
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

    const dns = await fetchDkimDns(tags.d, tags.s);
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
