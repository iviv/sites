const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync, sign } = require('node:crypto');
const { test } = require('node:test');
const { EmailParser, parseEmail, decodeMimeWords, RelayParser, IpAddress, parseMailDate } = require('../v2_email_parser');
const { DkimParser, DkimValidator } = require('../v2_dkim_validator');
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
  const build = sig => parseEmail('Authentication-Results: mx.receiver.test; dkim=pass header.d=mail.example.test;' +
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
  assert.deepEqual(trace.terms, [
    { token: 'include:other.example.test', outcome: 'no-match' },
    { token: 'ip4:192.0.2.0/24', outcome: 'matched' }
  ]);
  assert.equal(budget.terms, 1);
  assert.equal(await validator.reverseName('192.0.2.10'), 'mail.example.test');
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
  const email = parseEmail('From: sender@example.test\r\nReturn-Path: <sender@example.test>\r\n' +
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
