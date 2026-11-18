const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync, sign } = require('node:crypto');
const { test } = require('node:test');
const { EmailParser, parseEmail, decodeMimeWords, RelayParser, IpAddress, parseMailDate, ServerValidationParser, MimeParser, HeaderInsights, DeliveryRecords } = require('../v2_email_parser');
const EmailDns = require('../v2_dns');
const PublicSuffix = require('../v2_public_suffix');
const { DkimParser, DkimValidator, ArcValidator } = require('../v2_dkim_validator');
const { DmarcValidator } = require('../v2_dmarc_validator');
const { SpfValidator } = require('../v2_spf_validator');

const hash = bytes => createHash('sha256').update(bytes).digest();

test('decodes Q and Base64 encoded words across a folded Subject header', () => {
  const header = 'Subject: Re: =?UTF-8?Q?You=E2=80=99re_ready_?=\r\n\t=?UTF-8?B?8J+Yig==?= today';
  const email = new EmailParser().parseBytes(Buffer.from(header + '\r\n\r\n'));
  assert.equal(decodeMimeWords(email.headers.Subject), 'Re: You’re ready 😊 today');
  assert.equal(email.rawHeaders, header);
});

test('leaves plain subjects and unrecognized MIME words intact', () => {
  const subject = 'Plain résumé with =?unknown?Q?caf=E9?= and =?UTF-8?Q?bad=G1?=';
  assert.equal(decodeMimeWords(subject), subject);
  assert.equal(decodeMimeWords('=?ISO-8859-1?Q?caf=E9?='), 'café');
});

test('relay parser reads SendGrid and Microsoft Received formats', () => {
  const [microsoft, goStyle, fractional] = new RelayParser().parse([
    'from o1320.shared.klaviyomail.com (167.89.66.183) by BN3PEPF00022BC0.mail.protection.outlook.com (10.167.248.123) with ' +
      'Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.21.615.4 via Frontend Transport; Tue, 10 Nov 2026 16:55:12 +0000',
    'by recvd-79cc74d4d6-hc588 with SMTP id recvd-79cc74d4d6-hc588-1-6AF34C6F-1A7\r\n\t2026-11-10 16:55:11.859154455 +0000 UTC m=+405959.638670212',
    'from Mjk3NzYxMDk (unknown)\r\n\tby geopod-ismtpd-0 (SG) with HTTP\r\n\tid zXne3tKOREaiYRqMmL7SSQ\r\n\tTue, 10 Nov 2026 16:55:11.851 +0000 (UTC)'
  ]).hops;
  assert.deepEqual([microsoft.ip, microsoft.with, microsoft.tls, microsoft.timestamp],
    ['167.89.66.183', 'Microsoft SMTP', 'TLS 1.3', Date.parse('2026-11-10T16:55:12Z')]);
  assert.equal(goStyle.timestamp, Date.parse('2026-11-10T16:55:11.859Z'));
  assert.equal(fractional.timestamp, Date.parse('2026-11-10T16:55:11.851Z'));
  assert.equal(fractional.ip, null);
  assert.equal(parseMailDate('13 Nov 26 08:13:15 EST'), Date.parse('2026-11-13T13:13:15Z'));
  assert.ok(Number.isNaN(parseMailDate('not a date')));
});

test('unwraps the IPv4 address carried inside 6to4, mapped, NAT64 and Teredo IPv6 forms', () => {
  const cases = {
    '2002:a05:7022:ec8a:b0:1b5:474:b524': { ipv4: '10.5.112.34', kind: '6to4' },
    '[IPv6:2002:c000:0204::1]': { ipv4: '192.0.2.4', kind: '6to4' },
    '::ffff:192.0.2.33': { ipv4: '192.0.2.33', kind: 'IPv4-mapped' },
    '::ffff:c000:221': { ipv4: '192.0.2.33', kind: 'IPv4-mapped' },
    '64:ff9b::198.51.100.7': { ipv4: '198.51.100.7', kind: 'NAT64' },
    '2001:0:4136:e378:8000:63bf:3fff:fdd2': { ipv4: '192.0.2.45', kind: 'Teredo' }
  };
  for (const [address, expected] of Object.entries(cases)) assert.deepEqual(IpAddress.embeddedIpv4(address), expected, address);
  for (const other of ['2607:f8b0:4864:20::62b', '2002:a05:7022', '1::2::3', '::ffff:300.1.1.1', 'mx.google.com', '10.5.112.34']) {
    assert.equal(IpAddress.embeddedIpv4(other), null, other);
  }
  assert.deepEqual(IpAddress.parseIpv6('2001:db8::1'), [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
});

test('names the network and organization behind an IP from routing and registry data', async () => {
  const asked = [];
  const lookup = async (name, type) => {
    asked.push(type + ' ' + name);
    return {
      'TXT 48.171.220.204.origin.asn.cymru.com': ['"396479 | 204.220.171.0/24 | US | arin | 1995-01-05"'],
      'TXT AS396479.asn.cymru.com': ['"396479 | US | arin | 2017-06-21 | MAILGUN-US - Mailgun Technologies Inc., US"']
    }[type + ' ' + name] || [];
  };
  const getJson = async url => {
    assert.equal(url, 'https://rdap.arin.net/registry/ip/204.220.171.48');
    return { name: 'MAILGUN-204-220-160-20', cidr0_cidrs: [{ v4prefix: '204.220.160.0', length: 20 }],
      entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'Mailgun Technologies Inc.']]] }] };
  };
  const owner = await IpAddress.networkOwner('204.220.171.48', { lookup, getJson });
  assert.deepEqual(owner, { ip: '204.220.171.48', asn: '396479', prefix: '204.220.171.0/24', country: 'US', registry: 'ARIN',
    asName: 'Mailgun Technologies Inc.', organization: 'Mailgun Technologies Inc.', network: 'MAILGUN-204-220-160-20', range: '204.220.160.0/20' });
  assert.deepEqual(owner.lookups.dns.map(({ name, records }) => [name, records.length]),
    [['48.171.220.204.origin.asn.cymru.com', 1], ['AS396479.asn.cymru.com', 1]]);
  assert.deepEqual([owner.lookups.rdap, owner.lookups.rdapOk], ['https://rdap.arin.net/registry/ip/204.220.171.48', true]);

  // Without a registry answer the routing data still names the network.
  const routingOnly = await IpAddress.networkOwner('204.220.171.48', { lookup, getJson: async () => { throw new Error('offline'); } });
  assert.equal(routingOnly.organization, null);
  assert.equal(routingOnly.asName, 'Mailgun Technologies Inc.');

  // IPv6 uses the nibble-reversed origin6 zone; non-addresses are never looked up.
  await IpAddress.networkOwner('2001:db8::1', { lookup, getJson });
  assert.ok(asked.includes('TXT 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com'));
  assert.equal(await IpAddress.networkOwner('mx.example.test', { lookup, getJson }), null);
});

test('reads every Authentication-Results header with each result, its details and comment', () => {
  const dto = new ServerValidationParser().parse([
    'mx.microsoft.com 1; spf=pass (sender IP is\r\n 204.220.171.48) smtp.mailfrom=marketing.example.test; dkim=pass (signature was verified) ' +
      'header.d=marketing.example.test;dmarc=pass action=none header.from=marketing.example.test;compauth=pass reason=100',
    'relay.example.test; dkim=fail (body; hash mismatch) header.i=@example.test'
  ]);
  assert.equal(dto.headers.length, 2);
  assert.deepEqual([dto.service, dto.headers[0].version], ['mx.microsoft.com', '1']);
  assert.deepEqual(dto.results.map(({ method, result }) => method + '=' + result), ['spf=pass', 'dkim=pass', 'dmarc=pass', 'compauth=pass']);
  assert.deepEqual(dto.results[0].props, { 'smtp.mailfrom': 'marketing.example.test' });
  assert.equal(dto.results[0].comment, 'sender IP is 204.220.171.48');
  // A ';' inside a comment doesn't start a new result.
  assert.deepEqual(dto.headers[1].results.map(({ method, result, comment }) => [method, result, comment]), [['dkim', 'fail', 'body; hash mismatch']]);
});

test('relay parser reads dates without a semicolon and ignores clauses inside comments', () => {
  const [postfix, bare, ipv6] = new RelayParser().parse([
    'from mail.example.org (mail.example.org [203.0.113.5]) (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 ' +
      '(256/256 bits)) by mx.example.net (Postfix) with ESMTPS id 4F2; Tue, 17 Nov 2026 10:00:01 +0000',
    'from 127.0.0.1 (localhost. [127.0.0.1]) by eaas-34 (EaaS) id 0003 for <a@example.test> Tue, 17 Nov 2026 15:33:20 GMT\r\n (GMT)',
    'from relay.example.org ([2001:db8::25]) (helo=relay.example.org) by mx.example.net with ESMTP; Tue, 17 Nov 2026 10:00:00 +0000'
  ]).hops;
  assert.deepEqual([postfix.from, postfix.by, postfix.with, postfix.ip, postfix.tls, postfix.cipher],
    ['mail.example.org', 'mx.example.net', 'ESMTPS', '203.0.113.5', 'TLS 1.3', 'TLS_AES_256_GCM_SHA384']);
  assert.equal(bare.timestamp, Date.parse('2026-11-17T15:33:20Z'));
  assert.equal(bare.by, 'eaas-34');
  assert.deepEqual([ipv6.ip, ipv6.helo, ipv6.tls], ['2001:db8::25', 'relay.example.org', null]);
});

for (const algorithm of ['rsa-sha256', 'ed25519-sha256']) {
  test('verifies a valid ' + algorithm + ' signature with a folded signed-header list', async () => {
    const rsa = algorithm.startsWith('rsa');
    const { publicKey, privateKey } = rsa
      ? generateKeyPairSync('rsa', { modulusLength: 1024 }) : generateKeyPairSync('ed25519');
    const publicBytes = rsa ? publicKey.export({ type: 'pkcs1', format: 'der' })
      : Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
    const canonicalTags = ['v=1', 'a=' + algorithm, 'c=relaxed/simple', 'd=example.test', 's=mail',
      'h=from: subject', 'bh=' + hash('\r\n').toString('base64'), 'b='].join('; ');
    const tags = canonicalTags.replace('h=from: subject', 'h=from:\r\n\tsubject');
    const subject = '=?UTF-8?Q?You=E2=80=99re_ready?=';
    const signed = Buffer.from('from:sender@example.test\r\nsubject:' + subject + '\r\ndkim-signature:' + canonicalTags);
    const signature = sign(rsa ? 'sha256' : null, rsa ? signed : hash(signed), privateKey).toString('base64');
    const raw = 'DKIM-Signature: ' + tags + '\r\n ' + signature + '\r\n' +
      'From: sender@example.test\r\nSubject: Added later\r\nSubject:  ' + subject + '\r\n\r\n';
    const email = new EmailParser().parseBytes(Buffer.from(raw));
    const validator = new DkimValidator();
    validator.queryDns = async (name, type) => {
      assert.equal(name, 'mail._domainkey.example.test');
      assert.equal(type, 'TXT');
      return ['"v=DKIM1; k=' + (rsa ? 'rsa' : 'ed25519') + '; p=' + publicBytes.toString('base64') + '"'];
    };
    const dkim = new DkimParser().parse(tags + '\r\n ' + signature, 0);
    const result = await validator.verify(email, dkim);
    assert.equal(result.valid, true, result.error);
    assert.deepEqual(result.details.signedHeaders, [{ key: 'from', instance: 0 }, { key: 'subject', instance: 1 }]);
  });
}

test('a body changed after signing fails DKIM but reports that the signed headers verify', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const key = publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64');
  const tags = sig => 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.test; s=mail; h=from:subject; bh=' +
    hash('Hello\r\n').toString('base64') + '; b=' + sig;
  const build = (sig, body) => parseEmail('DKIM-Signature: ' + tags(sig) + '\r\nFrom: sender@example.test\r\nSubject: Hi\r\n\r\n' + body);
  const validator = new DkimValidator();
  validator.queryDns = async () => ['v=DKIM1; p=' + key];
  const draft = await validator.verify(build('AAAA', 'Hello\r\n'), new DkimParser().parse(tags('AAAA'), 0));
  const signature = sign('sha256', Buffer.from(draft.details.dataToVerify), privateKey).toString('base64');

  const intact = await validator.verify(build(signature, 'Hello\r\n'), new DkimParser().parse(tags(signature), 0));
  assert.equal(intact.valid, true);
  const changed = await validator.verify(build(signature, 'Hello, rewritten\r\n'), new DkimParser().parse(tags(signature), 0));
  assert.equal(changed.valid, false);
  assert.equal(changed.status, 'fail');
  assert.equal(changed.error, 'Body hash mismatch');
  assert.equal(changed.headersVerified, true);
  const forged = await validator.verify(build('YWJjZA==', 'Hello, rewritten\r\n'), new DkimParser().parse(tags('YWJjZA=='), 0));
  assert.equal(forged.headersVerified, false);
});

test('headers pasted without a body report the body as unchecked, not as a DKIM failure', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const key = publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64');
  const tags = sig => 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.test; s=mail; h=from:subject; bh=' +
    hash('Hello\r\n').toString('base64') + '; b=' + sig;
  const headers = sig => 'DKIM-Signature: ' + tags(sig) + '\r\nFrom: sender@example.test\r\nSubject: Hi';
  const validator = new DkimValidator();
  validator.queryDns = async () => ['v=DKIM1; p=' + key];
  const draft = await validator.verify(parseEmail(headers('AAAA') + '\r\n\r\nHello\r\n'), new DkimParser().parse(tags('AAAA'), 0));
  const signature = sign('sha256', Buffer.from(draft.details.dataToVerify), privateKey).toString('base64');

  const email = parseEmail(headers(signature));
  assert.equal(email.headersOnly, true);
  const result = await validator.verify(email, new DkimParser().parse(tags(signature), 0));
  assert.equal(result.valid, false);
  assert.equal(result.status, 'unavailable');
  assert.equal(result.bodyMissing, true);
  assert.equal(result.headersVerified, true);
});

test('DKIM hashes the original octets and reports the covered byte count', async () => {
  const email = new EmailParser().parseBytes(Buffer.concat([
    Buffer.from('From: sender@example.test\r\n\r\n'), Buffer.from([0xe9, 0x61, 0xd, 0xa])
  ]));
  const expected = hash(Buffer.from([0xe9])).toString('base64');
  const result = await new DkimValidator().verifyBodyHash(email, new DkimParser().parse('l=1; bh=' + expected));
  assert.equal(result.valid, true);
  assert.equal(result.signedBytes, 1);
  assert.equal(result.totalBytes, 4);
});

test('an incomplete DKIM signature is rejected before DNS', async () => {
  const validator = new DkimValidator();
  validator.queryDns = async () => assert.fail('Unexpected DNS request');
  const result = await validator.verify(parseEmail('From: sender@example.test\r\n\r\n'), new DkimParser().parse('v=1'));
  assert.equal(result.valid, false);
  assert.match(result.error, /required DKIM tag/);
});

test('expired DKIM shows the signed data and DNS key without passing DMARC', async () => {
  const tags = 'v=1; a=rsa-sha256; d=example.test; s=mail; t=1700000000; x=1700000060; ' +
    'h=from:\r\n\tsubject; bh=' + hash('Hello\r\n').toString('base64') + '; b=YWJjZA==';
  const email = parseEmail('DKIM-Signature: ' + tags +
    '\r\nFrom: sender@example.test\r\nSubject: Archived message\r\n\r\nHello\r\n');
  const dkim = new DkimParser().parse(tags, 0);
  const validator = new DkimValidator();
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const key = publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64');
  validator.queryDns = async (name, type) => {
    assert.equal(name, 'mail._domainkey.example.test');
    assert.equal(type, 'TXT');
    return ['v=DKIM1; p=' + key];
  };
  const result = await validator.verify(email, dkim);
  assert.equal(result.status, 'expired');
  assert.equal(result.valid, false);
  assert.equal(result.signatureValid, false);
  assert.match(result.error, /does not verify against the current DNS key/);
  assert.equal(result.bodyHash.valid, true);
  assert.ok(result.details.dataToVerify.startsWith('From: sender@example.test\r\nSubject: Archived message\r\n'));
  assert.ok(result.details.dataToVerify.endsWith('; b='));
  assert.equal(dkim.publicKey, key);

  const dmarc = new DmarcValidator();
  dmarc.queryDns = async () => ['v=DMARC1; p=none'];
  const outcome = await dmarc.verify(email, { result: 'pass', source: 'headers', domain: 'example.test' }, [{ dkim, result }]);
  assert.equal(outcome.dkimAlignment, 'expired');
  assert.equal(outcome.result, 'unavailable');
  assert.deepEqual(outcome.expiredAlignedDkim, []);

  validator.queryDns = async () => [];
  const missing = await validator.verify(email, dkim);
  assert.equal(missing.status, 'expired');
  assert.equal(missing.signatureValid, undefined);
  assert.equal(missing.keyError, 'No DKIM key record');
  assert.equal(missing.details.dataToVerify, result.details.dataToVerify);
  assert.equal(dkim.publicKey, undefined);

  validator.queryDns = async () => { throw new Error('DNS unavailable'); };
  const failed = await validator.verify(email, dkim);
  assert.equal(failed.status, 'expired');
  assert.equal(failed.keyError, 'DNS lookup failed: DNS unavailable');
  assert.equal(dkim.dnsCommand, 'dig TXT mail._domainkey.example.test');
});

test('an expired DKIM signature that still verifies is reported as aligned but not passing', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const key = publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64');
  const tags = sig => 'v=1; a=rsa-sha256; d=mail.example.test; s=mail; t=1700000000; x=1700000060; ' +
    'h=from:subject; bh=' + hash('Hello\r\n').toString('base64') + '; b=' + sig;
  const build = sig => parseEmail('Received: from mail.example.test by mx.receiver.test; Tue, 14 Nov 2023 22:13:30 +0000\r\n' +
    'Authentication-Results: mx.receiver.test; dkim=pass header.d=mail.example.test;' +
    ' dmarc=pass (p=NONE) header.from=example.test\r\nDKIM-Signature: ' + tags(sig) +
    '\r\nFrom: sender@example.test\r\nSubject: Archived message\r\n\r\nHello\r\n');
  const validator = new DkimValidator();
  validator.queryDns = async () => ['v=DKIM1; p=' + key];
  const draft = await validator.verify(build('AAAA'), new DkimParser().parse(tags('AAAA'), 0));
  const signature = sign('sha256', Buffer.from(draft.details.dataToVerify), privateKey).toString('base64');
  const email = build(signature);
  const dkim = new DkimParser().parse(tags(signature), 0);

  const result = await validator.verify(email, dkim);
  assert.equal(result.valid, false);
  assert.equal(result.status, 'expired');
  assert.equal(result.signatureValid, true);
  assert.match(result.error, /verifies against the current DNS key but has expired/);

  const dmarc = new DmarcValidator();
  dmarc.queryDns = async name => name === '_dmarc.example.test' ? ['v=DMARC1; p=none'] : [];
  const outcome = await dmarc.verify(email, { result: 'unavailable' }, [{ dkim, result }]);
  assert.equal(outcome.result, 'unavailable');
  assert.equal(outcome.dkimAlignment, 'expired');
  assert.deepEqual(outcome.passedBy, []);
  assert.deepEqual(outcome.expiredAlignedDkim, [{ domain: 'mail.example.test', expires: 1700000060 }]);
  assert.deepEqual(outcome.reported, { result: 'pass', authServId: 'mx.receiver.test' });
});

test('SPF records each rule outcome in order, the DNS lookups used, and the reverse DNS name', async () => {
  const validator = new SpfValidator();
  validator.queryDns = async (name, type) => ({
    'TXT example.test': ['"v=spf1 include:other.example.test ip4:192.0.2.0/24 include:never.example.test -all"'],
    'TXT other.example.test': ['"v=spf1 ip4:198.51.100.0/24 -all"'],
    'PTR 10.2.0.192.in-addr.arpa': ['mail.example.test.']
  })[type + ' ' + name] || [];
  const budget = { terms: 0, voids: 0, ptr: null };
  const trace = await validator.evaluateRecursive('192.0.2.10', 'example.test', 0, 'bounce@example.test', null, budget);
  assert.equal(trace.result, 'Pass');
  assert.deepEqual(trace.terms.map(({ token, outcome }) => ({ token, outcome })), [
    { token: 'include:other.example.test', outcome: 'no-match' },
    { token: 'ip4:192.0.2.0/24', outcome: 'matched' }
  ]);
  assert.deepEqual(trace.terms[0].detail, { target: 'other.example.test', result: 'Fail' });
  assert.equal(budget.terms, 1);
  assert.equal(await validator.reverseName('192.0.2.10'), 'mail.example.test');
});

test('SPF records every DNS question with its answer and the rule that asked it', async () => {
  const email = parseEmail([
    'Return-Path: <bounce@mailer.example.test>',
    'Received: from mail.example.test (mail.example.test [192.0.2.25]) by mx.example.net',
    'From: a@example.test', '', 'Hi'
  ].join('\r\n'));
  const validator = new SpfValidator();
  validator.queryDns = async (name, type) => ({
    'TXT mailer.example.test': ['"v=spf1 mx include:esp.example.net -all"'],
    'MX mailer.example.test': ['10 mx1.mailer.example.test.'],
    'A mx1.mailer.example.test': ['198.51.100.9'],
    'TXT esp.example.net': ['"v=spf1 ip4:192.0.2.0/24 ~all"']
  })[type + ' ' + name] || [];
  const result = await validator.verify(email);
  assert.equal(result.result, 'pass');
  assert.deepEqual([result.mailboxSource, result.ipSource, result.helo], ['Return-Path', 'Received', 'mail.example.test']);
  assert.deepEqual(result.operations.map(({ depth, domain, token, type, name, records }) => [depth, domain, token, `${type} ${name}`, records.length]), [
    [0, 'mailer.example.test', null, 'TXT mailer.example.test', 1],
    [0, 'mailer.example.test', 'mx', 'MX mailer.example.test', 1],
    [0, 'mailer.example.test', 'mx', 'A mx1.mailer.example.test', 1],
    [1, 'esp.example.net', null, 'TXT esp.example.net', 1]
  ]);
  assert.deepEqual(result.trace.terms.map(term => [term.token, term.outcome, term.detail]), [
    ['mx', 'no-match', { target: 'mailer.example.test', hosts: ['mx1.mailer.example.test'], prefix: 32 }],
    ['include:esp.example.net', 'matched', { target: 'esp.example.net', result: 'Pass' }]
  ]);
  // A domain without a policy doesn't use up the void lookup allowance, which is for the rules' own lookups.
  validator.queryDns = async () => [];
  const none = await validator.verify(email);
  assert.deepEqual([none.result, none.voidLookups, none.operations.length], ['none', 0, 1]);
});

test('SPF matches IPv6 CIDRs and uses AAAA for a and mx', async () => {
  for (const mechanism of ['ip6:2001:db8::/32', 'a:mail.example.test//64', 'mx:example.test//64']) {
    const validator = new SpfValidator();
    validator.queryDns = async (name, type) => {
      if (name === 'example.test' && type === 'TXT') return ['v=spf1 ' + mechanism + ' -all'];
      if (name === 'example.test' && type === 'MX') return ['10 mail.example.test.'];
      if (name === 'mail.example.test' && type === 'AAAA') return ['2001:db8::123'];
      assert.fail('Unexpected DNS question ' + name + ' ' + type);
    };
    assert.equal((await validator.evaluateRecursive('2001:0db8::1', 'example.test')).result, 'Pass');
  }
});

test('SPF shares the lookup limit across sibling includes', async () => {
  const validator = new SpfValidator();
  const terms = Array.from({length: 11}, (_, index) => 'include:mail' + index + '.example.test');
  const queried = [];
  validator.queryDns = async name => {
    queried.push(name);
    return [name === 'example.test' ? 'v=spf1 ' + terms.join(' ') + ' -all' : 'v=spf1 -all'];
  };
  const trace = await validator.evaluateRecursive('192.0.2.1', 'example.test');
  assert.equal(trace.result, 'PermError');
  assert.equal(queried.length, 11); // One initial TXT record and ten include terms.
});

test('SPF distinguishes an unavailable DNS server from an absent record', async () => {
  const validator = new SpfValidator();
  validator.queryDns = async () => [];
  assert.equal((await validator.evaluateRecursive('192.0.2.1', 'example.test')).result, 'None');
  validator.queryDns = async () => { throw new Error('Resolver unavailable'); };
  assert.equal((await validator.evaluateRecursive('192.0.2.1', 'example.test')).result, 'TempError');
});

test('SPF reports the historical result when the sending IP is unavailable', async () => {
  const email = parseEmail('Received: from mail.example.test by receiver.example.test\r\n' +
    'From: sender@example.test\r\nReturn-Path: <sender@example.test>\r\n' +
    'Authentication-Results: receiver.example.test; spf=pass smtp.mailfrom=example.test\r\n\r\n');
  const validator = new SpfValidator();
  validator.queryDns = async () => ['v=spf1 ip4:192.0.2.0/24 -all'];
  const reported = await validator.verify(email);
  assert.equal(reported.headerResult, 'pass');
  assert.equal(reported.result, 'unavailable');
  assert.match(reported.error, /sending IP/);
  const checked = await validator.verify(email, { ip: '192.0.2.1', mailFrom: 'sender@example.test' });
  assert.equal(checked.result, 'pass');

  const dmarc = new DmarcValidator();
  dmarc.queryDns = async () => ['v=DMARC1; p=none'];
  assert.equal((await dmarc.verify(email, reported, [])).result, 'unavailable');
  const dmarcResult = await dmarc.verify(email, checked, []);
  assert.equal(dmarcResult.result, 'pass');
  assert.deepEqual(dmarcResult.passedBy, ['SPF']);
});

test('SPF automatically checks the Received-SPF client and the envelope sender against current DNS', async () => {
  const email = parseEmail([
    'Return-Path: <bounce@mailer.example.test>',
    'Received: from relay.example.test (relay.example.test [10.0.0.8]) by inbox.example.test',
    'Received-SPF: pass (mx.example.test: permitted sender); client-ip=192.0.2.11;',
    ' envelope-from="bounce@mailer.example.test"; receiver=mx.example.test',
    'From: Sender <sender@example.test>', '', 'Hello'
  ].join('\r\n'));
  const validator = new SpfValidator();
  validator.queryDns = async (name, type) => {
    assert.equal(name, 'mailer.example.test');
    assert.equal(type, 'TXT');
    return ['v=spf1 ip4:192.0.2.0/24 -all'];
  };
  const passed = await validator.verify(email);
  assert.equal(passed.result, 'pass');
  assert.equal(passed.domain, 'mailer.example.test');
  assert.equal(passed.senderIp, '192.0.2.11');
  assert.equal(passed.ipSource, 'Received-SPF');

  // A change to the published policy can make the current result differ from the recorded one.
  validator.queryDns = async () => ['v=spf1 ip4:198.51.100.0/24 -all'];
  const failed = await validator.verify(email);
  assert.equal(failed.headerResult, 'pass');
  assert.equal(failed.result, 'fail');

  const dmarc = new DmarcValidator();
  dmarc.queryDns = async name => name === '_dmarc.example.test' ? ['v=DMARC1; p=none'] : [];
  const dmarcResult = await dmarc.verify(email, passed, []);
  assert.equal(dmarcResult.spfAlignment, 'pass');
  assert.equal(dmarcResult.spfFromHeaders, true);
  assert.equal(dmarcResult.result, 'unavailable');
  assert.deepEqual(dmarcResult.passedBy, []);
});

test('SPF finds the IPv6 peer at the receiver named in Authentication-Results', async () => {
  const email = parseEmail([
    'Received: from internal.example.test (internal.example.test [10.0.0.10]) by inbox.example.test',
    'Received: from mail.example.test (mail.example.test [IPv6:2001:db8::7]) by mx.example.test',
    'Authentication-Results: mx.example.test; spf=pass (matched; policy checked) smtp.mailfrom=example.test',
    'From: sender@example.test', '', 'Hello'
  ].join('\r\n'));
  const validator = new SpfValidator();
  validator.queryDns = async () => ['v=spf1 ip6:2001:db8::/32 -all'];
  const result = await validator.verify(email);
  assert.equal(result.result, 'pass');
  assert.equal(result.ipSource, 'Received');
  assert.equal(result.senderIp, '2001:db8::7');
});

test('SPF can use delivery metadata in the SPF clause of Authentication-Results', async () => {
  const email = parseEmail([
    'Received: from mail.example.test by mx.example.test',
    'Authentication-Results: mx.example.test;',
    ' spf=pass (sender IP is 192.0.2.11) smtp.mailfrom=mailer.example.test;',
    ' dkim=none (no signature)', 'From: sender@example.test', '', 'Hello'
  ].join('\r\n'));
  const validator = new SpfValidator();
  validator.queryDns = async () => ['v=spf1 ip4:192.0.2.0/24 -all'];
  const result = await validator.verify(email);
  assert.equal(result.result, 'pass');
  assert.equal(result.ipSource, 'Authentication-Results');
});

test('SPF uses the HELO domain for an explicitly empty envelope sender', async () => {
  const email = parseEmail([
    'Return-Path: <>', 'Received: from mail.example.test (mail.example.test [192.0.2.11]) by mx.example.test',
    'From: Mailer Daemon <daemon@example.test>', '', 'Delivery report'
  ].join('\r\n'));
  const validator = new SpfValidator();
  validator.queryDns = async name => {
    assert.equal(name, 'mail.example.test');
    return ['v=spf1 ip4:192.0.2.0/24 -all'];
  };
  assert.equal((await validator.verify(email)).result, 'pass');
});

test('SPF does not substitute the visible From domain for missing envelope metadata', async () => {
  const email = parseEmail([
    'From: sender@example.test',
    'Received: from mail.example.test (mail.example.test [192.0.2.11]) by mx.example.test', '', 'Hello'
  ].join('\r\n'));
  const validator = new SpfValidator();
  validator.queryDns = async () => assert.fail('Unexpected DNS request');
  const result = await validator.verify(email);
  assert.equal(result.result, 'unavailable');
  assert.match(result.error, /envelope sender domain/);
});

test('DMARC parses the mailbox in a lowercase From and discovers its organization policy', async () => {
  const parser = new EmailParser();
  const email = parser.parse('from: "Contact @ office.example" (customer replies) <user@news.example.co.uk>\r\n\r\n');
  const dmarc = new DmarcValidator();
  dmarc.queryDns = async name => ({
    '_dmarc.example.co.uk': ['v=DMARC1; p=none'],
    '_dmarc.co.uk': ['v=DMARC1; p=none; psd=y']
  })[name] || [];
  const spf = { domain: 'bounce.example.co.uk', result: 'pass' };
  const result = await dmarc.verify(email, spf, []);
  assert.equal(result.domain, 'news.example.co.uk');
  assert.equal(result.fetchedDomain, 'example.co.uk');
  assert.equal(result.result, 'pass');
  assert.equal(await dmarc.checkAlignment('bounce.other.co.uk', result.domain), false);
});

test('DMARC handles repeated From headers as unavailable', async () => {
  const email = parseEmail('From: a@example.test\r\nfrom: b@example.test\r\n\r\n');
  const dmarc = new DmarcValidator();
  dmarc.queryDns = async () => assert.fail('Unexpected DNS request');
  const result = await dmarc.verify(email, null, []);
  assert.equal(result.result, 'unavailable');
});

test('DMARC explains each check: domain match, authentication and whether it counts', async () => {
  const email = parseEmail('From: news@news.example.test\r\n\r\n');
  const validator = new DmarcValidator();
  validator.queryDns = async name => name === '_dmarc.example.test' ? ['v=DMARC1; p=reject; adkim=s'] : [];
  const spf = { domain: 'bounce.news.example.test', result: 'pass', source: 'headers', senderIp: '192.0.2.10' };
  const dkim = [
    { result: { valid: true }, dkim: { tags: { d: 'news.example.test', s: 'one' } } },
    { result: { valid: true }, dkim: { tags: { d: 'mail.example.test', s: 'two' } } },
    { result: { valid: false, status: 'fail', error: 'Body hash mismatch', headersVerified: true }, dkim: { tags: { d: 'example.net', s: 'three' } } }
  ];
  const result = await validator.verify(email, spf, dkim);
  assert.equal(result.result, 'pass');
  assert.deepEqual(result.checks.map(({ kind, domain, match, auth, counts }) => [kind, domain, match, auth.state, counts]), [
    ['DKIM', 'news.example.test', 'exact', 'pass', true],
    ['DKIM', 'mail.example.test', 'strict', 'pass', false],
    ['DKIM', 'example.net', 'none', 'body-changed', false],
    ['SPF', 'bounce.news.example.test', 'relaxed', 'unconfirmed', false]
  ]);
  assert.equal(result.checks[3].auth.ip, '192.0.2.10');
});

test('DMARC passes via aligned DKIM when SPF passes for a delivery provider', async () => {
  const email = parseEmail('From: sender@brand.example.test\r\n\r\n');
  const validator = new DmarcValidator();
  validator.queryDns = async name => name === '_dmarc.brand.example.test' ? ['v=DMARC1; p=quarantine; aspf=r'] : [];
  const spf = { domain: 'mailer.example.net', result: 'pass', source: 'headers' };
  const dkim = [{ result: { valid: true }, dkim: { tags: { d: 'brand.example.test' } } }];
  const result = await validator.verify(email, spf, dkim);
  assert.equal(result.spfAuthDomain, 'mailer.example.net');
  assert.equal(result.spfAlignment, 'fail');
  assert.equal(result.dkimAlignment, 'pass');
  assert.equal(result.result, 'pass');
  assert.deepEqual(result.passedBy, ['DKIM']);
});

test('DMARC fails from headers alone when the envelope domain can\'t match From and no signature does', async () => {
  const email = parseEmail('From: support@bank.example\r\n\r\nHi\r\n');
  const validator = new DmarcValidator();
  validator.queryDns = async name => name === '_dmarc.bank.example' ? ['v=DMARC1; p=reject'] : [];
  // The sender's own domain passes SPF, but it isn't the From domain, so SPF can't count whatever the session was.
  const spoof = await validator.verify(email, { domain: 'attacker.example', result: 'pass', source: 'headers' }, []);
  assert.equal(spoof.result, 'fail');
  assert.deepEqual(spoof.passedBy, []);
  // An envelope domain that matches From could have passed SPF in the real session, so that stays unconfirmed.
  const aligned = await validator.verify(email, { domain: 'bounce.bank.example', result: 'pass', source: 'headers' }, []);
  assert.equal(aligned.result, 'unavailable');
});

test('a Received header claiming the receiver handled the message before it arrived is flagged as forged', () => {
  const at = 'Tue, 17 Nov 2026 15:38:16 -0800';
  const scam = parseEmail([
    `Received: by 2002:a05:7022:ec8a:b0:1b5:474:b524 with SMTP id q; ${at}`,
    `Received: from sb076.cfd (success.bank.example. [185.215.184.118]) by mx.google.com with ESMTPS id x; ${at}`,
    'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=sb076.throwaway.example',
    'From: alex <alert@gqgtn.nkx>',
    `Received: from efianalytics.com (efianalytics.com. 216.244.76.116) by mx.google.com with ESMTPS id ?act=cl; ${at}`,
    'Subject: Storage full', '', 'Hi', ''
  ].join('\r\n'));
  const delivery = DeliveryRecords.assess(scam);
  assert.deepEqual(delivery.forgedHops.map(hop => [hop.index, hop.by, hop.entryFrom]), [[4, 'mx.google.com', 'sb076.cfd']]);
  const issues = HeaderInsights.anomalies(headerFields(scam.rawHeaders), { delivery });
  assert.deepEqual(issues.map(issue => [issue.kind, issue.indexes]), [['forged-hop', [4]]]);
  assert.match(issues[0].message, /claims mx\.google\.com handled the message before sb076\.cfd handed it to mx\.google\.com/);

  // Gmail to Gmail: the hops below the receiving server came from Google's own outbound servers, so nothing is flagged.
  const gmailToGmail = parseEmail([
    `Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS id y; ${at}`,
    `Received: by 2002:a05:6a20:1234::1 with SMTP id z; ${at}`,
    `Received: from laptop ([192.0.2.20]) by smtp.gmail.com with ESMTPSA id w; ${at}`,
    'From: alex@example.com', '', 'Hi', ''
  ].join('\r\n'));
  assert.deepEqual(DeliveryRecords.assess(gmailToGmail).forgedHops, []);
  // A content filter re-injecting on the same server is fine too: the server took it from itself.
  const filtered = parseEmail([
    `Received: from localhost (localhost [127.0.0.1]) by mail.example.net (Postfix) with ESMTP id a; ${at}`,
    `Received: from mail.sender.example (mail.sender.example [198.51.100.4]) by mail.example.net (Postfix) with ESMTPS id b; ${at}`,
    `Received: from laptop by mail.sender.example; ${at}`, 'From: a@sender.example', '', 'Hi', ''
  ].join('\r\n'));
  assert.deepEqual(DeliveryRecords.assess(filtered).forgedHops, []);
});

test('top-level domains come from the suffix list, including ones listed only under wildcards', () => {
  for (const host of ['example.com', 'sb076.cfd', 'shop.co.uk', 'foo.ck', 'site.xn--p1ai']) assert.equal(PublicSuffix.knownTld(host), true, host);
  for (const host of ['gqgtn.nkx', 'bank.example', 'mail.test', 'printer.local', '']) assert.equal(PublicSuffix.knownTld(host), false, host);
});

test('a Google Takeout export\'s Spam label counts as Gmail\'s spam verdict', () => {
  const spam = HeaderInsights.spamVerdicts(headerFields('X-Gmail-Labels: Spam,Category Promotions,Unread\r\nSubject: Hi'));
  assert.deepEqual([spam.provider, spam.items.map(item => [item.label, item.tone])], ['Gmail', [['In Spam', 'fail']]]);
  assert.equal(HeaderInsights.spamVerdicts(headerFields('X-Gmail-Labels: Inbox,Important\r\nSubject: Hi')), null);
  assert.equal(HeaderInsights.category('X-Gmail-Labels'), 'spam');
});

test('MIME parser decodes text parts and lists attachments with RFC 2231 names and decoded sizes', () => {
  const pdf = Buffer.from('%PDF-1.4 fake document bytes');
  const email = new EmailParser().parseBytes(Buffer.from([
    'From: sender@example.test',
    'Content-Type: multipart/mixed; boundary="outer"',
    '',
    '--outer',
    'Content-Type: multipart/alternative; boundary=inner',
    '',
    '--inner',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'Caf=C3=A9 is open=',
    ' today',
    '--inner',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from('<p>Café</p>').toString('base64'),
    '--inner--',
    '--outer',
    'Content-Type: application/pdf',
    "Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf",
    'Content-Transfer-Encoding: base64',
    '',
    pdf.toString('base64'),
    '--outer--',
    ''
  ].join('\r\n')));
  const parser = new MimeParser();
  const leaves = parser.flatten(parser.parse(email));
  assert.deepEqual(leaves.map(({ contentType, attachment }) => [contentType, attachment]),
    [['text/plain', false], ['text/html', false], ['application/pdf', true]]);
  assert.equal(leaves[0].text, 'Café is open today');
  assert.equal(leaves[1].text, '<p>Café</p>');
  assert.equal(leaves[2].filename, 'résumé.pdf');
  assert.equal(leaves[2].size, pdf.length);
});

test('ARC verifies a sealed set, and breaks when the recorded results or the chain change', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const key = publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64');
  const dkim = new DkimValidator();
  dkim.queryDns = async () => ['v=DKIM1; p=' + key];
  const arc = new ArcValidator(dkim);
  const body = 'Hello\r\n';
  const results = 'i=1; mx.forwarder.test; dkim=pass header.d=example.test';
  const amsTags = sig => 'i=1; a=rsa-sha256; c=relaxed/relaxed; d=forwarder.test; s=arc; h=from:subject; bh=' +
    hash(body).toString('base64') + '; b=' + sig;
  const sealTags = (sig, cv = 'none') => `i=1; a=rsa-sha256; cv=${cv}; d=forwarder.test; s=arc; b=${sig}`;
  const build = (ams, seal, recorded = results) => parseEmail(`ARC-Seal: ${seal}\r\nARC-Message-Signature: ${ams}\r\n` +
    `ARC-Authentication-Results: ${recorded}\r\nFrom: sender@example.test\r\nSubject: Hi\r\n\r\n${body}`);

  const draft = await dkim.verify(build(amsTags('AAAA'), sealTags('AAAA')), new DkimParser().parse(amsTags('AAAA'), 0),
    { field: 'arc-message-signature', arc: true });
  const ams = amsTags(sign('sha256', Buffer.from(draft.details.dataToVerify), privateKey).toString('base64'));
  const sealData = (seal, recorded = results) => ['ARC-Authentication-Results: ' + recorded, 'ARC-Message-Signature: ' + ams, 'ARC-Seal: ' + seal]
    .map(field => dkim.canonicalizeHeader(field, 'relaxed')).join('').slice(0, -2);
  const seal = sealTags(sign('sha256', Buffer.from(sealData(sealTags(''))), privateKey).toString('base64'));

  const intact = await arc.verify(build(ams, seal));
  assert.equal(intact.status, 'pass');
  assert.deepEqual([intact.sets[0].sealer, intact.sets[0].cv, intact.sets[0].seal.valid, intact.sets[0].ams.valid],
    ['forwarder.test', 'none', true, true]);
  assert.equal(intact.sets[0].recorded, 'mx.forwarder.test; dkim=pass header.d=example.test');
  // The seal keeps its key lookup and the data it covers, for the step-by-step explanation.
  assert.equal(intact.sets[0].seal.question.type, 'TXT');
  assert.match(intact.sets[0].seal.question.name, /\._domainkey\./);
  assert.match(intact.sets[0].seal.data, /^arc-authentication-results:i=1;/);

  const altered = await arc.verify(build(ams, seal, 'i=1; mx.forwarder.test; dkim=fail header.d=example.test'));
  assert.equal(altered.status, 'fail');
  assert.equal(altered.sets[0].seal.valid, false);

  const firstClaimsPass = await arc.verify(build(ams, sealTags('AAAA', 'pass')));
  assert.equal(firstClaimsPass.status, 'fail');

  const gap = await arc.verify(parseEmail(`ARC-Seal: ${seal.replace('i=1', 'i=2')}\r\nFrom: sender@example.test\r\n\r\n`));
  assert.deepEqual([gap.status, gap.error], ['fail', 'ARC set 1 is missing or incomplete']);
  assert.equal((await arc.verify(parseEmail('From: sender@example.test\r\n\r\nHi'))).status, 'none');
});

const headerFields = text => new DkimValidator().getRawHeaderFields(text).map((field, index) => ({
  index, key: field.key, instance: field.instance, name: field.raw.slice(0, field.raw.indexOf(':')),
  value: field.raw.slice(field.raw.indexOf(':') + 1).replace(/\r\n[ \t]+/g, ' ').trim()
}));

test('header insights group headers by purpose and explain common ones', () => {
  assert.deepEqual(['From', 'Subject', 'DKIM-Signature', 'X-MS-Exchange-Organization-SCL', 'X-Microsoft-Antispam-Untrusted', 'X-Received',
    'List-Unsubscribe', 'X-Mailgun-Sid', 'X-MS-Exchange-CrossTenant-Id', 'X-Gm-Message-State', 'X-Unknown'].map(HeaderInsights.category),
    ['people', 'message', 'auth', 'spam', 'microsoft', 'route', 'list', 'service', 'microsoft', 'google', 'other']);
  assert.match(HeaderInsights.describe('Return-Path'), /SPF checks its domain/);
  assert.match(HeaderInsights.describe('X-Forefront-Antispam-Report-Untrusted'), /sending organization/);
  assert.equal(HeaderInsights.describe('X-Unknown'), null);
});

test('spam verdicts come from the receiving provider, not from the sender\'s untrusted copies', () => {
  const microsoft = HeaderInsights.spamVerdicts(headerFields([
    'X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;SCL:9;SFV:SPM;CAT:PHSH',
    'X-MS-Exchange-Organization-SCL: 1',
    'X-Microsoft-Antispam: BCL:3;ARA:1444111002|62400799021',
    'X-Microsoft-Antispam-Mailbox-Delivery: ucf:0;jmr:0;auth:1;dest:I;ENG:(5062000311)'
  ].join('\r\n')));
  assert.equal(microsoft.provider, 'Microsoft');
  assert.deepEqual(microsoft.items.map(({ label, tone, detail }) => [label, tone, detail]),
    [['Not spam', 'pass', 'SCL 1'], ['Bulk level 3', 'neutral', 'few complaints'], ['Delivered to Inbox', 'pass', 'dest:I']]);
  assert.deepEqual(microsoft.untrusted, ['X-Forefront-Antispam-Report-Untrusted']);

  const filtered = HeaderInsights.spamVerdicts(headerFields('X-Forefront-Antispam-Report: SFV:SPM;CAT:PHSH\r\nX-Microsoft-Antispam-Mailbox-Delivery: dest:J'));
  assert.deepEqual(filtered.items.map(item => item.label), ['Spam', 'Phishing', 'Delivered to Junk']);
  const assassin = HeaderInsights.spamVerdicts(headerFields('X-Spam-Status: No, score=-0.9 required=5.0 tests=DKIM_SIGNED'));
  assert.deepEqual(assassin.items.map(({ label, detail }) => [label, detail]), [['Not spam', 'score -0.9 of 5.0']]);
  assert.equal(HeaderInsights.spamVerdicts(headerFields('Subject: Hi')), null);
});

test('header warnings flag repeated From headers and receiver results written below the oldest hop', () => {
  const text = [
    'Authentication-Results: mx.example.net; dmarc=fail',
    'Received: from mail.sender.test by mx.example.net; Tue, 10 Nov 2026 16:55:12 +0000',
    'From: Bank <alerts@bank.example>',
    'Authentication-Results: mx.example.net; dkim=pass; dmarc=pass',
    'From: someone@sender.test',
    'Subject: Hi'
  ].join('\r\n');
  const delivery = DeliveryRecords.assess(parseEmail(text + '\r\n\r\n'));
  const issues = HeaderInsights.anomalies(headerFields(text), { covered: new Set(['from:1']), delivery });
  assert.deepEqual(issues.map(issue => [issue.kind, issue.indexes]), [['duplicate', [2, 4]], ['forged-results', [3]]]);
  assert.match(issues[0].message, /only one is signed/);
  assert.match(issues[1].message, /naming mx\.example\.net may be forged/);
  // A server the Received chain doesn't show isn't used, but isn't a warning sign on its own.
  const other = 'Received: by mx.example.net\r\nAuthentication-Results: other.example; spf=pass\r\nFrom: a@b.test';
  assert.deepEqual(HeaderInsights.anomalies(headerFields(other), { delivery: DeliveryRecords.assess(parseEmail(other + '\r\n\r\n')) }), []);
});

test('delivery results count only where the Received chain shows a receiving server writing them', async () => {
  const dmarc = new DmarcValidator();
  dmarc.queryDns = async name => name === '_dmarc.bank.example' ? ['v=DMARC1; p=reject'] : [];
  const spf = new SpfValidator();
  spf.queryDns = async () => ['v=spf1 ip4:198.51.100.0/24 -all'];

  // The sender wrote the only results header, naming a server the message never passed through.
  const forged = parseEmail([
    'Received: from attacker.example (attacker.example [203.0.113.9]) by mx.victim.example with ESMTP; Tue, 17 Nov 2026 12:00:00 +0000',
    'Authentication-Results: mx.google.com; dkim=pass header.d=bank.example; spf=pass (sender IP is 198.51.100.4) smtp.mailfrom=bank.example; dmarc=pass header.from=bank.example',
    'Received-SPF: pass (google.com: domain of a@bank.example designates 198.51.100.4 as permitted sender) client-ip=198.51.100.4;',
    'From: support@bank.example', '', 'Hi', ''
  ].join('\r\n'));
  assert.deepEqual(DeliveryRecords.assess(forged).records.map(record => [record.server, record.trusted, record.reason]),
    [['mx.google.com', false, 'unknown-server'], ['google.com', false, 'unknown-server']]);
  assert.equal((await dmarc.verify(forged, null, [])).reported, null);
  const forgedSpf = await spf.verify(forged);
  assert.deepEqual([forgedSpf.headerResult, forgedSpf.senderIp, forgedSpf.ignoredReports], [null, '203.0.113.9', 2]);

  // Gmail writes its results just below its own Received header; a copy below the sender's hop came with the message.
  const gmail = parseEmail([
    'Received: by 2002:a05:6a20:1234:b0:1b5:474:b524 with SMTP id x; Tue, 17 Nov 2026 12:00:02 -0800 (PST)',
    'Received: from mail.bank.example (mail.bank.example. [198.51.100.4]) by mx.google.com with ESMTPS id y; Tue, 17 Nov 2026 12:00:01 -0800 (PST)',
    'Received-SPF: pass (google.com: domain of a@bank.example designates 198.51.100.4 as permitted sender) client-ip=198.51.100.4;',
    'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bank.example; dmarc=fail (p=REJECT) header.from=bank.example',
    'Received: from laptop by mail.bank.example; Tue, 17 Nov 2026 12:00:00 -0800',
    'Authentication-Results: mx.google.com; dkim=pass header.d=bank.example; dmarc=pass header.from=bank.example',
    'From: support@bank.example', '', 'Hi', ''
  ].join('\r\n'));
  const gmailRecords = DeliveryRecords.assess(gmail).records;
  assert.deepEqual(gmailRecords.map(record => [record.name, record.trusted, record.reason, record.suspicious]), [
    ['received-spf', true, null, false], ['authentication-results', true, null, false],
    ['authentication-results', false, 'below-other', true]]);
  assert.match(DeliveryRecords.explain(gmailRecords[2]), /below the Received header added by mail\.bank\.example/);
  assert.deepEqual([gmailRecords[1].via.by, gmailRecords[1].org, gmailRecords[1].byReceiver], ['mx.google.com', 'google.com', false]);
  assert.deepEqual((await dmarc.verify(gmail, null, [])).reported, { result: 'fail', authServId: 'mx.google.com' });

  // Microsoft names no server; its results sit above its own Received header. The sending tenant's copy sits lower.
  const microsoft = parseEmail([
    'Received: from DM6PR11MB1234.namprd11.prod.outlook.com (2603:10b6:5:1::1) by SN6PR11MB5678.namprd11.prod.outlook.com with HTTPS; Tue, 17 Nov 2026 20:00:03 +0000',
    'Authentication-Results: spf=pass (sender IP is 198.51.100.4) smtp.mailfrom=bank.example; dkim=pass (signature was verified) header.d=bank.example;dmarc=pass action=none header.from=bank.example;compauth=pass reason=100',
    'Received-SPF: Pass (protection.outlook.com: domain of bank.example designates 198.51.100.4 as permitted sender) receiver=protection.outlook.com; client-ip=198.51.100.4; helo=mail.bank.example; pr=C',
    'Received: from mail.bank.example (198.51.100.4) by BN8NAM12FT034.mail.protection.outlook.com (10.13.182.1) with Microsoft SMTP Server; Tue, 17 Nov 2026 20:00:02 +0000',
    'Received: from laptop by mail.bank.example; Tue, 17 Nov 2026 20:00:00 +0000',
    'Authentication-Results: dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=bank.example;',
    'From: support@bank.example', '', 'Hi', ''
  ].join('\r\n'));
  const microsoftRecords = DeliveryRecords.assess(microsoft).records;
  assert.deepEqual(microsoftRecords.map(record => [record.server, record.trusted, record.reason, record.suspicious]), [
    [null, true, null, false], ['protection.outlook.com', true, null, false], [null, false, 'below-other', false]]);
  assert.equal(microsoftRecords[0].byReceiver, true);
  const parsed = new ServerValidationParser().parseOne(microsoftRecords[0].value);
  assert.equal(parsed.service, null);
  assert.deepEqual(parsed.results.map(({ method, result }) => method + '=' + result), ['spf=pass', 'dkim=pass', 'dmarc=pass', 'compauth=pass']);
  assert.deepEqual((await dmarc.verify(microsoft, null, [])).reported, { result: 'pass', authServId: null });
  const microsoftSpf = await spf.verify(microsoft);
  assert.deepEqual([microsoftSpf.result, microsoftSpf.senderIp, microsoftSpf.ipSource], ['pass', '198.51.100.4', 'Received-SPF']);

  // Without any Received header nothing shows which server wrote it.
  const pasted = DeliveryRecords.assess(parseEmail('Authentication-Results: mx.example.net; spf=pass\r\nFrom: a@b.test\r\n\r\n'));
  assert.deepEqual(pasted.records.map(record => record.reason), ['no-trace']);
});

test('registrable domains follow the public suffix list', () => {
  const cases = {
    'mail.shop.com.vn': 'shop.com.vn', 'news.example.co.id': 'example.co.id', 'mail.example.gov.au': 'example.gov.au',
    'a.b.example.co.uk': 'example.co.uk', 'evil.github.io': 'evil.github.io', 'mx.google.com': 'google.com',
    'BN8NAM12FT034.mail.protection.outlook.com.': 'outlook.com', 'foo.www.ck': 'www.ck', 'a.b.ck': 'a.b.ck',
    'news.example.test': 'example.test', 'co.uk': null, 'eaas-34.svc.cluster.local': null, '10.0.0.1': null,
    '[IPv6:2001:db8::1]': null, 'localhost': null
  };
  for (const [host, expected] of Object.entries(cases)) assert.equal(PublicSuffix.registrableDomain(host), expected, host);
  // Registration lookups want the domain bought from a registrar, not a customer's name under a private suffix.
  assert.equal(PublicSuffix.registrableDomain('evil.github.io', { icannOnly: true }), 'github.io');
  assert.equal(PublicSuffix.publicSuffix('x.s3.amazonaws.com'), 's3.amazonaws.com');
  assert.match(PublicSuffix.version, /^\d{4}-\d{2}-\d{2}/);
  assert.equal(DeliveryRecords.organization('SN6PR11MB5678.namprd11.prod.outlook.com'), 'outlook.com');
  assert.equal(DeliveryRecords.organization('mail-sor-f41.gmail.com'), 'google.com');
});

test('each DNS question is asked once per check, failures included, until the cache is cleared', async () => {
  const realFetch = global.fetch;
  const asked = [];
  global.fetch = async url => {
    const name = new URL(url).searchParams.get('name');
    asked.push(name);
    if (name === 'down.example.test') throw new Error('network down');
    return { ok: true, json: async () => ({ Status: 0, Answer: [{ name: name + '.', type: 16, data: '"v=spf1 -all"' }] }) };
  };
  try {
    EmailDns.clearCache();
    const [first, second] = await Promise.all([EmailDns.lookup('example.test', 'TXT'), EmailDns.lookup('Example.test.', 'TXT')]);
    assert.deepEqual(first, ['"v=spf1 -all"']);
    first.push('changed by one caller');
    assert.deepEqual(second, ['"v=spf1 -all"']);
    await assert.rejects(EmailDns.lookup('down.example.test', 'TXT'), /network down/);
    await assert.rejects(EmailDns.lookup('down.example.test', 'TXT'), /network down/);
    assert.deepEqual(asked, ['example.test', 'down.example.test']);
    EmailDns.clearCache();
    await EmailDns.lookup('example.test', 'TXT');
    assert.equal(asked.length, 3);
  } finally {
    global.fetch = realFetch;
    EmailDns.clearCache();
  }
});

test('DNS tells a name that doesn\'t exist from one that only lacks mail records', async () => {
  const realFetch = global.fetch;
  const asked = [];
  global.fetch = async url => {
    const name = new URL(url).searchParams.get('name');
    asked.push(name);
    const status = name === 'gone.example.test' ? 3 : 0;
    return { ok: true, json: async () => ({ Status: status, Answer: [] }) };
  };
  try {
    EmailDns.clearCache();
    assert.equal(await EmailDns.exists('gone.example.test'), false);
    assert.equal(await EmailDns.exists('quiet.example.test'), true);
    assert.deepEqual(await EmailDns.lookup('gone.example.test', 'MX'), []);
    // The existence check is the MX question, so it costs no extra request.
    assert.deepEqual(asked, ['gone.example.test', 'quiet.example.test']);
  } finally {
    global.fetch = realFetch;
    EmailDns.clearCache();
  }
});

test('DMARC records each policy question and why it was asked; DKIM keeps its key answer', async () => {
  const email = parseEmail('From: news@news.example.test\r\n\r\nHi\r\n');
  const validator = new DmarcValidator();
  validator.queryDns = async name => name === '_dmarc.example.test' ? ['"v=DMARC1; p=quarantine"'] : [];
  const spf = { domain: 'bounce.example.net', result: 'pass', source: 'headers' };
  const dkim = [{ dkim: { tags: { d: 'example.test', s: 'one' } }, result: { valid: true } }];
  const dto = await validator.verify(email, spf, dkim);
  assert.equal(dto.result, 'pass');
  assert.deepEqual(dto.operations.map(({ purpose, name, records }) => [purpose, name, records.length]), [
    ['policy', '_dmarc.news.example.test', 0], ['policy', '_dmarc.example.test', 1], ['policy', '_dmarc.test', 0],
    ['organization', '_dmarc.bounce.example.net', 0], ['organization', '_dmarc.example.net', 0], ['organization', '_dmarc.net', 0]
  ]);

  const signer = new DkimValidator();
  signer.queryDns = async () => [];
  const signature = new DkimParser().parse('v=1; a=rsa-sha256; d=example.test; s=gone; h=from; bh=' + hash('').toString('base64') + '; b=AAAA', 0);
  const result = await signer.verify(parseEmail('DKIM-Signature: ' + 'v=1; a=rsa-sha256; d=example.test; s=gone; h=from; bh=' +
    hash('').toString('base64') + '; b=AAAA\r\nFrom: a@example.test\r\n\r\n'), signature);
  assert.equal(result.keyError, 'No DKIM key record');
  // The lookup itself worked and came back empty; "no key" is the conclusion, shown apart from the answer.
  assert.deepEqual(signature.dnsQuestion, { type: 'TXT', name: 'gone._domainkey.example.test', records: [], error: null });
});

test('DMARC looks up each policy name once for the verdict and its explanation', async () => {
  const email = parseEmail('From: a@example.test\r\n\r\nHi\r\n');
  const asked = [];
  const validator = new DmarcValidator();
  validator.queryDns = async name => {
    asked.push(name);
    return name === '_dmarc.example.test' ? ['v=DMARC1; p=reject'] : [];
  };
  const spf = { result: 'pass', domain: 'bounce.example.test', source: 'smtp', senderIp: '192.0.2.1' };
  const dkim = [{ dkim: { tags: { d: 'example.test', s: 'one' } }, result: { valid: true } },
    { dkim: { tags: { d: 'esp-mail.example', s: 'two' } }, result: { valid: true } }];
  assert.equal((await validator.verify(email, spf, dkim)).result, 'pass');
  assert.deepEqual(asked.filter((name, index) => asked.indexOf(name) !== index), []);
});

test('a leading mbox separator line is not read as a header', () => {
  const email = parseEmail('From MAILER-DAEMON Tue Nov 17 12:00:01 2026\r\nFrom: a@example.test\r\nSubject: Hi\r\n\r\nBody\r\n');
  assert.deepEqual(Object.keys(email.headers), ['From', 'Subject']);
  assert.equal(parseEmail('From : a@example.test\r\n\r\n').headers.From, 'a@example.test');
});
