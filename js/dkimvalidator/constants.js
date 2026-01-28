/**
 * DKIM Validator - Constants Module
 * Tag descriptions with RFC references for tooltips and documentation
 */

// RFC Links for clickable references
export const RFC_LINKS = {
    6376: { title: 'DKIM Signatures', url: 'https://datatracker.ietf.org/doc/html/rfc6376' },
    7208: { title: 'SPF', url: 'https://datatracker.ietf.org/doc/html/rfc7208' },
    7489: { title: 'DMARC', url: 'https://datatracker.ietf.org/doc/html/rfc7489' },
    8601: { title: 'Authentication-Results', url: 'https://datatracker.ietf.org/doc/html/rfc8601' },
    8617: { title: 'ARC', url: 'https://datatracker.ietf.org/doc/html/rfc8617' },
    8461: { title: 'MTA-STS', url: 'https://datatracker.ietf.org/doc/html/rfc8461' }
};

// Security implications for authentication results
export const SECURITY_IMPLICATIONS = {
    dkim: {
        pass: { level: 'good', message: 'Email content has not been modified since it was signed by the sender\'s domain.' },
        fail: { level: 'bad', message: 'Email may have been tampered with, or the signature is invalid. Treat with caution.' },
        none: { level: 'neutral', message: 'No DKIM signature present. Cannot verify message integrity.' }
    },
    spf: {
        pass: { level: 'good', message: 'Sending server is authorized to send mail for this domain.' },
        fail: { level: 'bad', message: 'Sending server is NOT authorized. This could be a spoofed email.' },
        softfail: { level: 'warning', message: 'Sender is probably not authorized. Domain is transitioning to stricter policy.' },
        neutral: { level: 'neutral', message: 'Domain makes no assertion about the sender\'s authorization.' },
        none: { level: 'neutral', message: 'No SPF record found. Domain has not configured sender authorization.' },
        permerror: { level: 'bad', message: 'SPF record has errors. Domain configuration is broken.' },
        temperror: { level: 'warning', message: 'Temporary DNS error. Try again later.' }
    },
    dmarc: {
        pass: { level: 'good', message: 'Email passes DMARC alignment. Both authentication and domain alignment verified.' },
        fail: { level: 'bad', message: 'DMARC check failed. Email may be forged or misconfigured.' },
        none: { level: 'neutral', message: 'No DMARC policy. Domain owner has not set up anti-spoofing protection.' },
        reject: { level: 'good', message: 'Domain uses strict policy - unauthorized emails are rejected.' },
        quarantine: { level: 'warning', message: 'Domain uses moderate policy - suspicious emails go to spam.' },
        policy_none: { level: 'warning', message: 'Domain is only monitoring - no action taken on failures.' }
    },
    overall: {
        pass: { level: 'good', title: 'Email Authentication: ✓ Fully Authenticated', message: 'All authentication checks passed. This email can be trusted as legitimately from the claimed sender.' },
        partial: { level: 'warning', title: 'Email Authentication: ⚠ Partial Issues', message: 'Some authentication checks passed, but there are issues. Review the specific failures below.' },
        fail: { level: 'bad', title: 'Email Authentication: ✗ Authentication Failed', message: 'Critical authentication failures detected. This email may be forged or spoofed.' },
        unknown: { level: 'neutral', title: 'Email Authentication: ? Unknown', message: 'Could not determine authentication status.' }
    }
};

export const DKIM_TAGS = {
    v: { name: 'Version', desc: 'DKIM signature version (must be "1") [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    a: { name: 'Algorithm', desc: 'Signing algorithm: rsa-sha256 or rsa-sha1 [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    b: { name: 'Signature', desc: 'Base64-encoded cryptographic signature [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    bh: { name: 'Body Hash', desc: 'Hash of canonicalized message body [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    c: { name: 'Canonicalization', desc: 'Header/body normalization: simple or relaxed [RFC 6376 §3.4]', rfc: '6376', section: '3.4' },
    d: { name: 'Domain', desc: 'Signing domain identifier (SDID) [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    s: { name: 'Selector', desc: 'DNS selector for public key lookup [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    h: { name: 'Signed Headers', desc: 'Headers included in signature [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    t: { name: 'Timestamp', desc: 'Signature creation time (Unix epoch) [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    x: { name: 'Expiration', desc: 'Signature expiration time (Unix epoch) [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    l: { name: 'Body Length', desc: 'Number of body bytes signed (security risk!) [RFC 6376 §3.5]', rfc: '6376', section: '3.5' },
    i: { name: 'Identity', desc: 'Agent/user identifier (AUID) [RFC 6376 §3.5]', rfc: '6376', section: '3.5' }
};

export const DNS_TAGS = {
    v: { name: 'Version', desc: 'DKIM key record version (must be "DKIM1") [RFC 6376 §3.6.1]', rfc: '6376', section: '3.6.1' },
    k: { name: 'Key Type', desc: 'Type of key: rsa (default) or ed25519 [RFC 6376 §3.6.1]', rfc: '6376', section: '3.6.1' },
    p: { name: 'Public Key', desc: 'Base64-encoded public key data [RFC 6376 §3.6.1]', rfc: '6376', section: '3.6.1' },
    h: { name: 'Hash Algorithms', desc: 'Acceptable hash algorithms [RFC 6376 §3.6.1]', rfc: '6376', section: '3.6.1' },
    t: { name: 'Flags', desc: 'Flags: y=testing mode, s=strict [RFC 6376 §3.6.1]', rfc: '6376', section: '3.6.1' }
};

export const SPF_MECHANISMS = {
    all: { name: 'All', desc: 'Matches all senders (catchall) [RFC 7208 §5.1]', rfc: '7208', section: '5.1' },
    ip4: { name: 'IPv4', desc: 'Match if sender IP is in this IPv4 range [RFC 7208 §5.6]', rfc: '7208', section: '5.6' },
    ip6: { name: 'IPv6', desc: 'Match if sender IP is in this IPv6 range [RFC 7208 §5.6]', rfc: '7208', section: '5.6' },
    a: { name: 'A Record', desc: 'Match if sender IP matches domain A record [RFC 7208 §5.3]', rfc: '7208', section: '5.3' },
    mx: { name: 'MX Record', desc: 'Match if sender IP matches domain MX hosts [RFC 7208 §5.4]', rfc: '7208', section: '5.4' },
    include: { name: 'Include', desc: 'Include SPF policy from another domain [RFC 7208 §5.2]', rfc: '7208', section: '5.2' },
    redirect: { name: 'Redirect', desc: 'Use SPF policy from another domain instead [RFC 7208 §6.1]', rfc: '7208', section: '6.1' },
    exists: { name: 'Exists', desc: 'Match if domain exists (has any A record) [RFC 7208 §5.7]', rfc: '7208', section: '5.7' },
    ptr: { name: 'PTR', desc: 'Match via reverse DNS (deprecated) [RFC 7208 §5.5]', rfc: '7208', section: '5.5' }
};

export const SPF_QUALIFIERS = {
    '+': { name: 'Pass', desc: 'IP is authorized', color: 'success' },
    '-': { name: 'Fail', desc: 'IP is not authorized', color: 'error' },
    '~': { name: 'SoftFail', desc: 'IP is probably not authorized', color: 'warning' },
    '?': { name: 'Neutral', desc: 'No assertion about IP', color: 'neutral' }
};

export const SPF_RESULTS = {
    pass: { name: 'Pass', desc: 'Sender IP is authorized', color: 'success', icon: '\u2713' },
    fail: { name: 'Fail', desc: 'Sender IP is NOT authorized', color: 'error', icon: '\u2717' },
    softfail: { name: 'SoftFail', desc: 'Sender IP is probably not authorized', color: 'warning', icon: '~' },
    neutral: { name: 'Neutral', desc: 'No assertion about sender IP', color: 'neutral', icon: '?' },
    none: { name: 'None', desc: 'No SPF record found', color: 'neutral', icon: '\u2212' },
    permerror: { name: 'PermError', desc: 'Permanent error in SPF evaluation', color: 'error', icon: '!' },
    temperror: { name: 'TempError', desc: 'Temporary error (DNS timeout)', color: 'warning', icon: '\u26A0' }
};

export const DMARC_TAGS = {
    v: { name: 'Version', desc: 'DMARC version (must be "DMARC1") [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    p: { name: 'Policy', desc: 'Policy for the domain: none, quarantine, reject [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    sp: { name: 'Subdomain Policy', desc: 'Policy for subdomains (defaults to p=) [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    pct: { name: 'Percentage', desc: 'Percentage of messages to apply policy (default: 100) [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    rua: { name: 'Aggregate Reports', desc: 'URI(s) for aggregate reports [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    ruf: { name: 'Forensic Reports', desc: 'URI(s) for forensic/failure reports [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    adkim: { name: 'DKIM Alignment', desc: 'DKIM alignment mode: r=relaxed, s=strict [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    aspf: { name: 'SPF Alignment', desc: 'SPF alignment mode: r=relaxed, s=strict [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    fo: { name: 'Failure Options', desc: 'When to generate failure reports: 0, 1, d, s [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    rf: { name: 'Report Format', desc: 'Format for failure reports (afrf) [RFC 7489 §6.3]', rfc: '7489', section: '6.3' },
    ri: { name: 'Report Interval', desc: 'Interval between aggregate reports in seconds [RFC 7489 §6.3]', rfc: '7489', section: '6.3' }
};

export const DMARC_POLICIES = {
    none: { name: 'None', desc: 'No action taken, monitor only [RFC 7489 §6.3]', color: 'warning', icon: '?', rfc: '7489', section: '6.3' },
    quarantine: { name: 'Quarantine', desc: 'Treat as suspicious (spam folder) [RFC 7489 §6.3]', color: 'warning', icon: '\u26A0', rfc: '7489', section: '6.3' },
    reject: { name: 'Reject', desc: 'Reject the message outright [RFC 7489 §6.3]', color: 'success', icon: '\u2713', rfc: '7489', section: '6.3' }
};

// ARC (Authenticated Received Chain) tags - RFC 8617
export const ARC_SEAL_TAGS = {
    i: { name: 'Instance', desc: 'ARC chain instance number (1, 2, 3...) [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    a: { name: 'Algorithm', desc: 'Signing algorithm (rsa-sha256) [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    b: { name: 'Signature', desc: 'Base64-encoded signature of ARC headers [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    cv: { name: 'Chain Validation', desc: 'Validation status: none, fail, pass [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    d: { name: 'Domain', desc: 'Signing domain [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    s: { name: 'Selector', desc: 'DNS selector for public key [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    t: { name: 'Timestamp', desc: 'Signature creation time (Unix epoch) [RFC 8617 §4.1]', rfc: '8617', section: '4.1' }
};

export const ARC_MESSAGE_TAGS = {
    i: { name: 'Instance', desc: 'ARC chain instance number [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    a: { name: 'Algorithm', desc: 'Signing algorithm [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    b: { name: 'Signature', desc: 'Base64-encoded signature [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    bh: { name: 'Body Hash', desc: 'Hash of canonicalized body [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    c: { name: 'Canonicalization', desc: 'Header/body normalization method [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    d: { name: 'Domain', desc: 'Signing domain [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    h: { name: 'Signed Headers', desc: 'Headers included in signature [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    s: { name: 'Selector', desc: 'DNS selector for public key [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    t: { name: 'Timestamp', desc: 'Signature creation time [RFC 8617 §4.1]', rfc: '8617', section: '4.1' }
};

export const ARC_AUTH_TAGS = {
    i: { name: 'Instance', desc: 'ARC chain instance number [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    dkim: { name: 'DKIM Result', desc: 'DKIM authentication result [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    spf: { name: 'SPF Result', desc: 'SPF authentication result [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    dmarc: { name: 'DMARC Result', desc: 'DMARC authentication result [RFC 8617 §4.1]', rfc: '8617', section: '4.1' },
    arc: { name: 'ARC Result', desc: 'Previous ARC validation result [RFC 8617 §4.1]', rfc: '8617', section: '4.1' }
};

export const ARC_CV_STATUS = {
    none: { name: 'None', desc: 'No previous ARC sets in chain [RFC 8617 §4.1]', color: 'neutral', icon: '\u2212', rfc: '8617', section: '4.1' },
    pass: { name: 'Pass', desc: 'Previous ARC sets validated successfully [RFC 8617 §4.1]', color: 'success', icon: '\u2713', rfc: '8617', section: '4.1' },
    fail: { name: 'Fail', desc: 'Previous ARC set validation failed [RFC 8617 §4.1]', color: 'error', icon: '\u2717', rfc: '8617', section: '4.1' }
};

// BIMI (Brand Indicators for Message Identification) - draft-brand-indicators-for-message-identification
export const BIMI_TAGS = {
    v: { name: 'Version', desc: 'BIMI version (must be "BIMI1") [BIMI spec]' },
    l: { name: 'Logo Location', desc: 'HTTPS URL to SVG logo file [BIMI spec]' },
    a: { name: 'Authority', desc: 'URL to Verified Mark Certificate (VMC) [BIMI spec]' }
};

// MTA-STS (Mail Transfer Agent Strict Transport Security) - RFC 8461
export const MTA_STS_MODES = {
    enforce: { name: 'Enforce', desc: 'Require TLS; reject on failure [RFC 8461 §5]', color: 'success', icon: '\u2713' },
    testing: { name: 'Testing', desc: 'Report TLS failures but deliver anyway [RFC 8461 §5]', color: 'warning', icon: '~' },
    none: { name: 'None', desc: 'MTA-STS is disabled [RFC 8461 §5]', color: 'neutral', icon: '\u2212' }
};

// Authentication-Results header result codes - RFC 8601
export const AUTH_RESULTS = {
    pass: { name: 'Pass', desc: 'Authentication succeeded', color: 'success', icon: '\u2713' },
    fail: { name: 'Fail', desc: 'Authentication failed', color: 'error', icon: '\u2717' },
    softfail: { name: 'SoftFail', desc: 'Weak failure (SPF)', color: 'warning', icon: '~' },
    neutral: { name: 'Neutral', desc: 'No definitive result', color: 'neutral', icon: '?' },
    none: { name: 'None', desc: 'No authentication performed', color: 'neutral', icon: '\u2212' },
    temperror: { name: 'TempError', desc: 'Temporary error during check', color: 'warning', icon: '\u26A0' },
    permerror: { name: 'PermError', desc: 'Permanent error in record', color: 'error', icon: '!' },
    policy: { name: 'Policy', desc: 'Local policy decision', color: 'neutral', icon: '\u2261' },
    hardfail: { name: 'HardFail', desc: 'Strong failure', color: 'error', icon: '\u2717' },
    bestguesspass: { name: 'BestGuessPass', desc: 'Probable pass (no record)', color: 'warning', icon: '~' }
};

// Available themes
export const THEMES = {
    dark: ['dark-cyber', 'dark-dracula', 'dark-nord', 'dark-monokai', 'dark-ocean'],
    light: ['light-classic', 'light-solarized', 'light-github', 'light-rose', 'light-mint']
};
