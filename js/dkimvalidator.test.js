/**
 * Unit tests for DKIM Signature Validator
 * Tests core parsing, canonicalization, and IP utility functions
 */

const {
    // Parsing functions
    parseEmail,
    parseDkimTags,
    parseDnsTags,
    parseSpfRecord,
    parseDmarcRecord,
    parseArcHeaders,
    parseArcTags,
    parseArcAuthResults,
    parseRelayChain,

    // Canonicalization
    canonHeaderRelaxed,
    canonBodyRelaxed,
    canonBodySimple,

    // IP utilities
    ipv4ToInt,
    ipv4MatchesCIDR,
    expandIPv6,
    ipv6ToBigInt,
    ipv6MatchesCIDR,
    isPrivateIP,

    // Extraction
    extractMailDomain,
    extractSenderIP,

    // Utilities
    esc,
    formatLatency,
    getLatencyClass,

    // Constants
    DKIM_TAGS,
    DNS_TAGS,
    SPF_MECHANISMS,
    SPF_QUALIFIERS,
    SPF_RESULTS,
    DMARC_TAGS,
    DMARC_POLICIES
} = require('./dkimvalidator.js');

// ============================================================================
// Email Parsing Tests
// ============================================================================

describe('parseEmail', () => {
    test('parses simple email with headers and body', () => {
        const raw = `From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nHello, World!`;
        const result = parseEmail(raw);

        expect(result.headers).toHaveLength(3);
        expect(result.headers[0].name).toBe('From');
        expect(result.headers[0].value).toBe(' sender@example.com');
        expect(result.body).toBe('Hello, World!');
        expect(result.errors).toHaveLength(0);
    });

    test('handles LF line endings', () => {
        const raw = `From: sender@example.com\nTo: recipient@example.com\n\nBody`;
        const result = parseEmail(raw);

        expect(result.headers).toHaveLength(2);
        expect(result.body).toBe('Body');
    });

    test('handles folded headers', () => {
        const raw = `Subject: This is a very long subject\r\n that spans multiple lines\r\n\r\nBody`;
        const result = parseEmail(raw);

        expect(result.headers).toHaveLength(1);
        expect(result.headers[0].value).toContain('that spans multiple lines');
    });

    test('returns error for empty input', () => {
        const result = parseEmail('');
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].type).toBe('empty');
    });

    test('returns warning for missing body', () => {
        const raw = `From: sender@example.com\r\nTo: recipient@example.com`;
        const result = parseEmail(raw);
        expect(result.warnings.some(w => w.type === 'no_body')).toBe(true);
    });

    test('returns warning for missing From header', () => {
        const raw = `To: recipient@example.com\r\nSubject: Test\r\n\r\nBody`;
        const result = parseEmail(raw);
        expect(result.warnings.some(w => w.type === 'missing_from')).toBe(true);
    });

    test('extracts DKIM signatures', () => {
        const raw = `DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector; b=abc123\r\nFrom: sender@example.com\r\n\r\nBody`;
        const result = parseEmail(raw);

        expect(result.dkimSigs).toHaveLength(1);
        expect(result.dkimSigs[0].parsed.d).toBe('example.com');
    });

    test('detects HTML-encoded content', () => {
        const raw = `From: sender@example.com\r\n\r\n&lt;html&gt;`;
        const result = parseEmail(raw);
        expect(result.warnings.some(w => w.type === 'html_encoded')).toBe(true);
    });
});

describe('parseDkimTags', () => {
    test('parses standard DKIM-Signature header', () => {
        const raw = 'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector; h=from:to:subject; bh=hash123; b=sig456';
        const tags = parseDkimTags(raw);

        expect(tags.v).toBe('1');
        expect(tags.a).toBe('rsa-sha256');
        expect(tags.d).toBe('example.com');
        expect(tags.s).toBe('selector');
        expect(tags.h).toBe('from:to:subject');
        expect(tags.bh).toBe('hash123');
        expect(tags.b).toBe('sig456');
    });

    test('handles folded DKIM-Signature', () => {
        const raw = 'DKIM-Signature: v=1; a=rsa-sha256;\r\n d=example.com; s=selector;\r\n b=sig456';
        const tags = parseDkimTags(raw);

        expect(tags.d).toBe('example.com');
        expect(tags.b).toBe('sig456');
    });

    test('removes whitespace from b and bh tags', () => {
        const raw = 'DKIM-Signature: v=1; bh=hash 123; b=sig 456';
        const tags = parseDkimTags(raw);

        expect(tags.bh).toBe('hash123');
        expect(tags.b).toBe('sig456');
    });

    test('returns null for non-DKIM header', () => {
        const raw = 'From: sender@example.com';
        const tags = parseDkimTags(raw);
        expect(tags).toBeNull();
    });
});

describe('parseDnsTags', () => {
    test('parses DKIM public key record', () => {
        const record = 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN';
        const tags = parseDnsTags(record);

        expect(tags.v).toBe('DKIM1');
        expect(tags.k).toBe('rsa');
        expect(tags.p).toBe('MIGfMA0GCSqGSIb3DQEBAQUAA4GN');
    });

    test('removes whitespace from p tag', () => {
        const record = 'v=DKIM1; p=MIGf MA0G CSqG';
        const tags = parseDnsTags(record);
        expect(tags.p).toBe('MIGfMA0GCSqG');
    });
});

// ============================================================================
// SPF Parsing Tests
// ============================================================================

describe('parseSpfRecord', () => {
    test('parses simple SPF record', () => {
        const record = 'v=spf1 ip4:192.168.1.0/24 -all';
        const mechanisms = parseSpfRecord(record);

        expect(mechanisms).toHaveLength(2);
        expect(mechanisms[0].mechanism).toBe('ip4');
        expect(mechanisms[0].value).toBe('192.168.1.0/24');
        expect(mechanisms[0].qualifier).toBe('+');
        expect(mechanisms[1].mechanism).toBe('all');
        expect(mechanisms[1].qualifier).toBe('-');
    });

    test('parses include mechanism', () => {
        const record = 'v=spf1 include:_spf.google.com ~all';
        const mechanisms = parseSpfRecord(record);

        expect(mechanisms[0].mechanism).toBe('include');
        expect(mechanisms[0].value).toBe('_spf.google.com');
        expect(mechanisms[1].qualifier).toBe('~');
    });

    test('parses redirect modifier', () => {
        const record = 'v=spf1 redirect=_spf.example.com';
        const mechanisms = parseSpfRecord(record);

        expect(mechanisms[0].mechanism).toBe('redirect');
        expect(mechanisms[0].value).toBe('_spf.example.com');
    });

    test('handles all qualifiers', () => {
        const record = 'v=spf1 +a -mx ~include:test.com ?all';
        const mechanisms = parseSpfRecord(record);

        expect(mechanisms[0].qualifier).toBe('+');
        expect(mechanisms[1].qualifier).toBe('-');
        expect(mechanisms[2].qualifier).toBe('~');
        expect(mechanisms[3].qualifier).toBe('?');
    });

    test('parses ip6 mechanism', () => {
        const record = 'v=spf1 ip6:2001:db8::/32 -all';
        const mechanisms = parseSpfRecord(record);

        expect(mechanisms[0].mechanism).toBe('ip6');
        expect(mechanisms[0].value).toBe('2001:db8::/32');
    });
});

// ============================================================================
// DMARC Parsing Tests
// ============================================================================

describe('parseDmarcRecord', () => {
    test('parses DMARC record with all tags', () => {
        const record = 'v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@example.com; adkim=s; aspf=r';
        const tags = parseDmarcRecord(record);

        expect(tags.v).toBe('DMARC1');
        expect(tags.p).toBe('reject');
        expect(tags.sp).toBe('quarantine');
        expect(tags.pct).toBe('100');
        expect(tags.rua).toBe('mailto:dmarc@example.com');
        expect(tags.adkim).toBe('s');
        expect(tags.aspf).toBe('r');
    });

    test('parses minimal DMARC record', () => {
        const record = 'v=DMARC1; p=none';
        const tags = parseDmarcRecord(record);

        expect(tags.v).toBe('DMARC1');
        expect(tags.p).toBe('none');
    });
});

// ============================================================================
// ARC Parsing Tests
// ============================================================================

describe('parseArcTags', () => {
    test('parses ARC-Seal tags', () => {
        const value = 'i=1; a=rsa-sha256; cv=pass; d=example.com; s=selector; b=signature';
        const tags = parseArcTags(value);

        expect(tags.i).toBe('1');
        expect(tags.a).toBe('rsa-sha256');
        expect(tags.cv).toBe('pass');
        expect(tags.d).toBe('example.com');
    });

    test('removes whitespace from signature tags', () => {
        const value = 'i=1; b=sig na\r\nture; bh=body hash';
        const tags = parseArcTags(value);

        expect(tags.b).toBe('signature');
        expect(tags.bh).toBe('bodyhash');
    });
});

describe('parseArcAuthResults', () => {
    test('parses ARC-Authentication-Results', () => {
        const value = 'i=1; mx.google.com; dkim=pass; spf=pass; dmarc=pass';
        const result = parseArcAuthResults(value);

        expect(result.instance).toBe(1);
        expect(result.results).toContainEqual({ method: 'dkim', result: 'pass' });
        expect(result.results).toContainEqual({ method: 'spf', result: 'pass' });
        expect(result.results).toContainEqual({ method: 'dmarc', result: 'pass' });
    });

    test('handles failed results', () => {
        const value = 'i=2; example.com; dkim=fail; spf=softfail';
        const result = parseArcAuthResults(value);

        expect(result.instance).toBe(2);
        expect(result.results).toContainEqual({ method: 'dkim', result: 'fail' });
        expect(result.results).toContainEqual({ method: 'spf', result: 'softfail' });
    });
});

describe('parseArcHeaders', () => {
    test('parses complete ARC chain', () => {
        const headers = [
            { name: 'ARC-Seal', value: 'i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=sig1' },
            { name: 'ARC-Message-Signature', value: 'i=1; a=rsa-sha256; d=example.com; s=sel; b=sig2; bh=hash1; h=from' },
            { name: 'ARC-Authentication-Results', value: 'i=1; example.com; dkim=pass' }
        ];
        const sets = parseArcHeaders(headers);

        expect(sets).toHaveLength(1);
        expect(sets[0].instance).toBe(1);
        expect(sets[0].seal.tags.cv).toBe('none');
        expect(sets[0].message.tags.d).toBe('example.com');
        expect(sets[0].auth.parsed.results[0].method).toBe('dkim');
    });

    test('handles multiple ARC sets', () => {
        const headers = [
            { name: 'ARC-Seal', value: 'i=1; cv=none; d=first.com; s=sel; b=sig1' },
            { name: 'ARC-Seal', value: 'i=2; cv=pass; d=second.com; s=sel; b=sig2' }
        ];
        const sets = parseArcHeaders(headers);

        expect(sets).toHaveLength(2);
        expect(sets[0].seal.tags.d).toBe('first.com');
        expect(sets[1].seal.tags.d).toBe('second.com');
    });
});

// ============================================================================
// Canonicalization Tests
// ============================================================================

describe('canonHeaderRelaxed', () => {
    test('lowercases header name', () => {
        const result = canonHeaderRelaxed('From', ' sender@example.com');
        expect(result.startsWith('from:')).toBe(true);
    });

    test('removes trailing whitespace', () => {
        const result = canonHeaderRelaxed('Subject', ' Test   ');
        expect(result).toBe('subject:Test');
    });

    test('collapses multiple spaces', () => {
        const result = canonHeaderRelaxed('Subject', '  Hello    World  ');
        expect(result).toBe('subject:Hello World');
    });

    test('unfolds header values', () => {
        const result = canonHeaderRelaxed('Subject', ' Test\r\n value');
        expect(result).toBe('subject:Test value');
    });
});

describe('canonBodyRelaxed', () => {
    test('returns CRLF for empty body', () => {
        expect(canonBodyRelaxed('')).toBe('\r\n');
        expect(canonBodyRelaxed(null)).toBe('\r\n');
    });

    test('collapses whitespace in lines', () => {
        const result = canonBodyRelaxed('Hello   World');
        expect(result).toBe('Hello World\r\n');
    });

    test('removes trailing whitespace from lines', () => {
        const result = canonBodyRelaxed('Hello   \r\nWorld   ');
        expect(result).toBe('Hello\r\nWorld\r\n');
    });

    test('removes trailing empty lines', () => {
        const result = canonBodyRelaxed('Hello\r\n\r\n\r\n');
        expect(result).toBe('Hello\r\n');
    });

    test('normalizes line endings', () => {
        const result = canonBodyRelaxed('Hello\nWorld\r\nTest');
        expect(result).toBe('Hello\r\nWorld\r\nTest\r\n');
    });
});

describe('canonBodySimple', () => {
    test('returns CRLF for empty body', () => {
        expect(canonBodySimple('')).toBe('\r\n');
        expect(canonBodySimple(null)).toBe('\r\n');
    });

    test('preserves internal whitespace', () => {
        const result = canonBodySimple('Hello   World');
        expect(result).toBe('Hello   World\r\n');
    });

    test('removes trailing empty lines', () => {
        const result = canonBodySimple('Hello\r\n\r\n\r\n');
        expect(result).toBe('Hello\r\n');
    });

    test('normalizes line endings', () => {
        const result = canonBodySimple('Hello\nWorld');
        expect(result).toBe('Hello\r\nWorld\r\n');
    });
});

// ============================================================================
// IP Utility Tests
// ============================================================================

describe('ipv4ToInt', () => {
    test('converts IPv4 to integer', () => {
        expect(ipv4ToInt('0.0.0.0')).toBe(0);
        expect(ipv4ToInt('0.0.0.1')).toBe(1);
        expect(ipv4ToInt('0.0.1.0')).toBe(256);
        expect(ipv4ToInt('192.168.1.1')).toBe(3232235777);
        expect(ipv4ToInt('255.255.255.255')).toBe(4294967295);
    });
});

describe('ipv4MatchesCIDR', () => {
    test('matches exact IP without prefix', () => {
        expect(ipv4MatchesCIDR('192.168.1.1', '192.168.1.1')).toBe(true);
        expect(ipv4MatchesCIDR('192.168.1.1', '192.168.1.2')).toBe(false);
    });

    test('matches IP in /32 range', () => {
        expect(ipv4MatchesCIDR('192.168.1.1', '192.168.1.1/32')).toBe(true);
        expect(ipv4MatchesCIDR('192.168.1.2', '192.168.1.1/32')).toBe(false);
    });

    test('matches IP in /24 range', () => {
        expect(ipv4MatchesCIDR('192.168.1.1', '192.168.1.0/24')).toBe(true);
        expect(ipv4MatchesCIDR('192.168.1.255', '192.168.1.0/24')).toBe(true);
        expect(ipv4MatchesCIDR('192.168.2.1', '192.168.1.0/24')).toBe(false);
    });

    test('matches IP in /16 range', () => {
        expect(ipv4MatchesCIDR('192.168.0.1', '192.168.0.0/16')).toBe(true);
        expect(ipv4MatchesCIDR('192.168.255.255', '192.168.0.0/16')).toBe(true);
        expect(ipv4MatchesCIDR('192.169.0.1', '192.168.0.0/16')).toBe(false);
    });

    test('matches IP in /8 range', () => {
        expect(ipv4MatchesCIDR('10.0.0.1', '10.0.0.0/8')).toBe(true);
        expect(ipv4MatchesCIDR('10.255.255.255', '10.0.0.0/8')).toBe(true);
        expect(ipv4MatchesCIDR('11.0.0.1', '10.0.0.0/8')).toBe(false);
    });

    test('matches all IPs with /0', () => {
        expect(ipv4MatchesCIDR('192.168.1.1', '0.0.0.0/0')).toBe(true);
        expect(ipv4MatchesCIDR('1.2.3.4', '0.0.0.0/0')).toBe(true);
    });
});

describe('expandIPv6', () => {
    test('expands :: notation', () => {
        expect(expandIPv6('::1')).toBe('0000:0000:0000:0000:0000:0000:0000:0001');
        expect(expandIPv6('::')).toBe('0000:0000:0000:0000:0000:0000:0000:0000');
        expect(expandIPv6('2001:db8::1')).toBe('2001:0db8:0000:0000:0000:0000:0000:0001');
    });

    test('pads short segments', () => {
        expect(expandIPv6('2001:db8:0:0:0:0:0:1')).toBe('2001:0db8:0000:0000:0000:0000:0000:0001');
    });
});

describe('ipv6ToBigInt', () => {
    test('converts IPv6 to BigInt', () => {
        expect(ipv6ToBigInt('::1')).toBe(1n);
        expect(ipv6ToBigInt('::')).toBe(0n);
    });
});

describe('ipv6MatchesCIDR', () => {
    test('matches exact IPv6', () => {
        expect(ipv6MatchesCIDR('2001:db8::1', '2001:db8::1/128')).toBe(true);
        expect(ipv6MatchesCIDR('2001:db8::2', '2001:db8::1/128')).toBe(false);
    });

    test('matches IPv6 in range', () => {
        expect(ipv6MatchesCIDR('2001:db8::1', '2001:db8::/32')).toBe(true);
        expect(ipv6MatchesCIDR('2001:db8:ffff::1', '2001:db8::/32')).toBe(true);
        expect(ipv6MatchesCIDR('2001:db9::1', '2001:db8::/32')).toBe(false);
    });
});

describe('isPrivateIP', () => {
    test('detects 10.x.x.x range', () => {
        expect(isPrivateIP('10.0.0.1')).toBe(true);
        expect(isPrivateIP('10.255.255.255')).toBe(true);
    });

    test('detects 172.16-31.x.x range', () => {
        expect(isPrivateIP('172.16.0.1')).toBe(true);
        expect(isPrivateIP('172.31.255.255')).toBe(true);
        expect(isPrivateIP('172.15.0.1')).toBe(false);
        expect(isPrivateIP('172.32.0.1')).toBe(false);
    });

    test('detects 192.168.x.x range', () => {
        expect(isPrivateIP('192.168.0.1')).toBe(true);
        expect(isPrivateIP('192.168.255.255')).toBe(true);
        expect(isPrivateIP('192.169.0.1')).toBe(false);
    });

    test('detects localhost', () => {
        expect(isPrivateIP('127.0.0.1')).toBe(true);
        expect(isPrivateIP('127.255.255.255')).toBe(true);
    });

    test('identifies public IPs', () => {
        expect(isPrivateIP('8.8.8.8')).toBe(false);
        expect(isPrivateIP('1.1.1.1')).toBe(false);
        expect(isPrivateIP('203.0.113.1')).toBe(false);
    });
});

// ============================================================================
// Extraction Tests
// ============================================================================

describe('extractMailDomain', () => {
    test('extracts domain from From header', () => {
        const headers = [{ name: 'From', value: ' sender@example.com' }];
        expect(extractMailDomain(headers)).toBe('example.com');
    });

    test('extracts domain from angle bracket format', () => {
        const headers = [{ name: 'From', value: ' John Doe <john@example.com>' }];
        expect(extractMailDomain(headers)).toBe('example.com');
    });

    test('prefers Return-Path over From', () => {
        const headers = [
            { name: 'Return-Path', value: ' <bounce@returns.example.com>' },
            { name: 'From', value: ' sender@example.com' }
        ];
        expect(extractMailDomain(headers)).toBe('returns.example.com');
    });

    test('returns null for missing headers', () => {
        const headers = [{ name: 'To', value: ' recipient@example.com' }];
        expect(extractMailDomain(headers)).toBeNull();
    });
});

describe('extractSenderIP', () => {
    test('extracts IPv4 from Received header', () => {
        const headers = [
            { name: 'Received', value: ' from mail.example.com ([203.0.113.1]) by mx.test.com' }
        ];
        const result = extractSenderIP(headers);
        expect(result.ip).toBe('203.0.113.1');
        expect(result.version).toBe(4);
    });

    test('extracts IPv4 from parentheses format', () => {
        const headers = [
            { name: 'Received', value: ' from server (203.0.113.2) by mx.test.com' }
        ];
        const result = extractSenderIP(headers);
        expect(result.ip).toBe('203.0.113.2');
    });

    test('skips private IPs', () => {
        const headers = [
            { name: 'Received', value: ' from internal ([192.168.1.1]) by mx.test.com' },
            { name: 'Received', value: ' from mail.example.com ([203.0.113.1]) by internal' }
        ];
        const result = extractSenderIP(headers);
        expect(result.ip).toBe('203.0.113.1');
    });

    test('extracts IPv6 address', () => {
        const headers = [
            { name: 'Received', value: ' from mail.example.com ([2001:db8::1]) by mx.test.com' }
        ];
        const result = extractSenderIP(headers);
        expect(result.ip).toBe('2001:db8::1');
        expect(result.version).toBe(6);
    });

    test('returns null when no IP found', () => {
        const headers = [
            { name: 'Received', value: ' from mail.example.com by mx.test.com' }
        ];
        expect(extractSenderIP(headers)).toBeNull();
    });
});

// ============================================================================
// Relay Chain Parsing Tests
// ============================================================================

describe('parseRelayChain', () => {
    test('parses single hop', () => {
        const headers = [
            { name: 'Received', value: ' from mail.example.com ([203.0.113.1]) by mx.test.com with SMTP; Mon, 27 Jan 2025 10:30:45 +0000' }
        ];
        const hops = parseRelayChain(headers);

        expect(hops).toHaveLength(1);
        expect(hops[0].from).toBe('mail.example.com');
        expect(hops[0].by).toBe('mx.test.com');
        expect(hops[0].ip).toBe('203.0.113.1');
    });

    test('calculates latency between hops', () => {
        const headers = [
            { name: 'Received', value: ' from hop2 by final; Mon, 27 Jan 2025 10:30:50 +0000' },
            { name: 'Received', value: ' from hop1 by hop2; Mon, 27 Jan 2025 10:30:45 +0000' }
        ];
        const hops = parseRelayChain(headers);

        expect(hops).toHaveLength(2);
        expect(hops[1].latency).toBe(5000); // 5 seconds
    });

    test('detects TLS', () => {
        const headers = [
            { name: 'Received', value: ' from mail.example.com by mx.test.com with ESMTPS' }
        ];
        const hops = parseRelayChain(headers);

        expect(hops[0].tls).toBe(true);
        expect(hops[0].protocol).toBe('ESMTPS');
    });
});

// ============================================================================
// Utility Tests
// ============================================================================

describe('esc', () => {
    test('escapes HTML special characters', () => {
        expect(esc('<script>')).toBe('&lt;script&gt;');
        expect(esc('a & b')).toBe('a &amp; b');
        expect(esc('"quoted"')).toBe('&quot;quoted&quot;');
    });

    test('handles plain text', () => {
        expect(esc('Hello World')).toBe('Hello World');
    });
});

describe('formatLatency', () => {
    test('formats milliseconds', () => {
        expect(formatLatency(500)).toBe('500ms');
        expect(formatLatency(999)).toBe('999ms');
    });

    test('formats seconds', () => {
        expect(formatLatency(1000)).toBe('1.0s');
        expect(formatLatency(5500)).toBe('5.5s');
    });

    test('formats minutes', () => {
        expect(formatLatency(60000)).toBe('1.0m');
        expect(formatLatency(90000)).toBe('1.5m');
    });

    test('formats hours', () => {
        expect(formatLatency(3600000)).toBe('1.0h');
        expect(formatLatency(5400000)).toBe('1.5h');
    });

    test('handles null/undefined', () => {
        expect(formatLatency(null)).toBeNull();
        expect(formatLatency(undefined)).toBeNull();
    });

    test('handles negative values', () => {
        expect(formatLatency(-100)).toBe('0ms');
    });
});

describe('getLatencyClass', () => {
    test('returns fast for <1s', () => {
        expect(getLatencyClass(500)).toBe('fast');
        expect(getLatencyClass(999)).toBe('fast');
    });

    test('returns medium for 1-10s', () => {
        expect(getLatencyClass(1000)).toBe('medium');
        expect(getLatencyClass(9999)).toBe('medium');
    });

    test('returns slow for >10s', () => {
        expect(getLatencyClass(10000)).toBe('slow');
        expect(getLatencyClass(60000)).toBe('slow');
    });

    test('handles null/undefined', () => {
        expect(getLatencyClass(null)).toBe('');
        expect(getLatencyClass(undefined)).toBe('');
    });
});

// ============================================================================
// Constants Tests
// ============================================================================

describe('Constants', () => {
    test('DKIM_TAGS has expected tags', () => {
        expect(DKIM_TAGS.v).toBeDefined();
        expect(DKIM_TAGS.a).toBeDefined();
        expect(DKIM_TAGS.b).toBeDefined();
        expect(DKIM_TAGS.d).toBeDefined();
        expect(DKIM_TAGS.s).toBeDefined();
    });

    test('SPF_QUALIFIERS has all qualifiers', () => {
        expect(SPF_QUALIFIERS['+']).toBeDefined();
        expect(SPF_QUALIFIERS['-']).toBeDefined();
        expect(SPF_QUALIFIERS['~']).toBeDefined();
        expect(SPF_QUALIFIERS['?']).toBeDefined();
    });

    test('SPF_RESULTS has all results', () => {
        expect(SPF_RESULTS.pass).toBeDefined();
        expect(SPF_RESULTS.fail).toBeDefined();
        expect(SPF_RESULTS.softfail).toBeDefined();
        expect(SPF_RESULTS.neutral).toBeDefined();
        expect(SPF_RESULTS.none).toBeDefined();
    });

    test('DMARC_POLICIES has all policies', () => {
        expect(DMARC_POLICIES.none).toBeDefined();
        expect(DMARC_POLICIES.quarantine).toBeDefined();
        expect(DMARC_POLICIES.reject).toBeDefined();
    });
});
