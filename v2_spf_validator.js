(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./v2_dns'), require('./v2_email_parser').EmailAddress);
  } else {
    Object.assign(root, factory(root.EmailDns, root.EmailAddress));
  }
}(typeof self !== 'undefined' ? self : this, function (dns, address) {
  const verdicts = { '+': 'Pass', '-': 'Fail', '~': 'SoftFail', '?': 'Neutral' };

  class SpfError extends Error {
    constructor(result, message) {
      super(message);
      this.result = result;
    }
  }

  function parseIp(text) {
    if (!text.includes(':')) {
      const octets = text.split('.');
      if (octets.length !== 4 || !octets.every(value => /^(?:0|[1-9]\d{0,2})$/.test(value) && Number(value) <= 255)) return null;
      return { bits: 32, value: octets.reduce((value, byte) => (value << 8n) + BigInt(byte), 0n), macro: text };
    }

    if (text.includes('.')) {
      const colon = text.lastIndexOf(':');
      const ipv4 = parseIp(text.slice(colon + 1));
      if (!ipv4 || ipv4.bits !== 32) return null;
      text = text.slice(0, colon + 1) + (ipv4.value >> 16n).toString(16) + ':' + (ipv4.value & 65535n).toString(16);
    }
    const sides = text.split('::');
    if (sides.length > 2) return null;
    const left = sides[0] ? sides[0].split(':') : [];
    const right = sides[1] ? sides[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if (sides.length === 1 ? missing !== 0 : missing < 1) return null;
    const groups = [...left, ...Array(missing).fill('0'), ...right];
    if (!groups.every(value => /^[\da-f]{1,4}$/i.test(value))) return null;
    const hex = groups.map(value => value.toLowerCase().padStart(4, '0')).join('');
    return { bits: 128, value: BigInt('0x' + hex), macro: [...hex].join('.') };
  }

  function matchesCidr(ip, network, prefix = ip.bits) {
    if (network?.bits !== ip.bits) return false;
    const shift = BigInt(ip.bits - prefix);
    return (ip.value >> shift) === (network.value >> shift);
  }

  function prefixLength(value, bits) {
    if (value === undefined) return bits;
    const number = Number(value);
    if (!/^(?:0|[1-9]\d{0,2})$/.test(value) || number > bits) throw new SpfError('PermError', 'Invalid SPF CIDR prefix');
    return number;
  }

  function parsePolicy(record) {
    const terms = [];
    const modifiers = new Map();
    for (const token of record.split(/ +/).slice(1).filter(Boolean)) {
      const modifier = token.match(/^([a-z][a-z0-9_.-]*)=(.+)$/i);
      if (modifier) {
        const name = modifier[1].toLowerCase();
        if (name !== 'redirect' && name !== 'exp') continue;
        if (modifiers.has(name)) throw new SpfError('PermError', 'Duplicate SPF modifier');
        modifiers.set(name, modifier[2]);
        continue;
      }

      const qualifier = /^[+~?-]/.test(token) ? token[0] : '+';
      const mechanism = token.slice(/^[+~?-]/.test(token) ? 1 : 0);
      const ipRange = mechanism.match(/^(ip4|ip6):([^/]+)(?:\/(\d+))?$/i);
      if (ipRange) {
        const network = parseIp(ipRange[2]);
        const bits = ipRange[1].toLowerCase() === 'ip4' ? 32 : 128;
        if (network?.bits !== bits) throw new SpfError('PermError', 'Invalid SPF IP address');
        terms.push({ token, qualifier, type: 'ip', network, prefix: prefixLength(ipRange[3], bits) });
        continue;
      }
      const dnsAddress = mechanism.match(/^(a|mx)(?::((?:%\{[^}]+\}|%(?!\{)|[^/%])+))?(?:\/(\d+))?(?:\/\/(\d+))?$/i);
      if (dnsAddress) {
        terms.push({ token, qualifier, type: dnsAddress[1].toLowerCase(), target: dnsAddress[2],
          ipv4Prefix: prefixLength(dnsAddress[3], 32), ipv6Prefix: prefixLength(dnsAddress[4], 128) });
        continue;
      }
      const domainMechanism = mechanism.match(/^(include|exists|ptr):(.+)$/i);
      if (domainMechanism) {
        terms.push({ token, qualifier, type: domainMechanism[1].toLowerCase(), target: domainMechanism[2] });
        continue;
      }
      if (/^(all|ptr)$/i.test(mechanism)) {
        terms.push({ token, qualifier, type: mechanism.toLowerCase() });
        continue;
      }
      throw new SpfError('PermError', 'Invalid or unsupported SPF mechanism: ' + token);
    }
    return { terms, redirect: modifiers.get('redirect') };
  }

  function headerValues(headers, name) {
    const value = address.getHeader(headers, name);
    return Array.isArray(value) ? value : value ? [value] : [];
  }

  function traceClauses(header) {
    let clause = { text: '', comment: '' };
    const clauses = [clause];
    let depth = 0;
    // Semicolons in quoted values and comments do not separate methods or properties.
    for (const [token] of header.matchAll(/"(?:[^"\\]|\\.)*"|\\.|[();]|[^"\\();]+|["\\]/g)) {
      if (token === '(') {
        if (!depth) clause.text += ' ';
        depth++;
      } else if (token === ')' && depth) {
        depth--;
        if (!depth) clause.comment += ' ';
      } else if (depth) {
        clause.comment += token;
      } else if (token === ';') {
        clause = { text: '', comment: '' };
        clauses.push(clause);
      } else {
        clause.text += token;
      }
    }
    return clauses;
  }

  function traceProperties(text) {
    const fields = new Map();
    for (const [, name, quoted, bare] of text.matchAll(/(?:^|[\s;])([a-z][\w.-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s;]+))/gi)) {
      const key = name.toLowerCase();
      if (!fields.has(key)) fields.set(key, quoted?.replace(/\\(.)/g, '$1') ?? bare);
    }
    return fields;
  }

  function envelopeFrom(value, allowDomain = false) {
    if (typeof value !== 'string') return null;
    if (value.trim() === '<>') return { empty: true };
    const mailboxes = address.parseMailboxes(value);
    if (mailboxes.length === 1) return mailboxes[0];
    const domain = allowDomain ? dns.mailboxDomain(value.trim()) : null;
    return domain ? { domain, address: null, localPart: null } : null;
  }

  function peerIp(value) {
    const ipText = value?.trim().replace(/^\[|\]$/g, '').replace(/^IPv6:/i, '');
    return ipText && parseIp(ipText) ? ipText : null;
  }

  function readSpfReports(headers) {
    const received = headerValues(headers, 'Received-SPF').flatMap(header => {
      const clauses = traceClauses(header);
      const result = clauses[0].text.match(/^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b/i)?.[1];
      if (!result) return [];
      const props = traceProperties(clauses.map(clause => clause.text).join(';'));
      const hintedIp = clauses[0].comment.match(/\bdesignates\s+(\S+)\s+as\b/i)?.[1];
      return [{
        result: result.toLowerCase(), source: 'Received-SPF',
        envelope: envelopeFrom(props.get('envelope-from'), true),
        ip: peerIp(props.get('client-ip')) || peerIp(hintedIp),
        helo: dns.mailboxDomain(props.get('helo')),
        receiver: dns.mailboxDomain(props.get('receiver')),
        heloOnly: props.get('identity')?.toLowerCase() === 'helo'
      }];
    });
    const auth = headerValues(headers, 'Authentication-Results').flatMap(header => {
      const clauses = traceClauses(header);
      const receiver = dns.mailboxDomain(clauses[0].text.trim().split(/[\s/]+/)[0]);
      return clauses.flatMap(({ text, comment }) => {
        const match = text.match(/^\s*spf(?:\/\d+)?\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b(.*)$/i);
        if (!match) return [];
        const props = traceProperties(match[2]);
        const reason = traceProperties(props.get('reason') || '');
        const hintedIp = comment.match(/\b(?:sender IP is|designates)\s+(\[?(?:IPv6:)?[\da-f:.]+\]?)/i)?.[1];
        return [{
          result: match[1].toLowerCase(), source: 'Authentication-Results', receiver,
          envelope: envelopeFrom(props.get('smtp.mailfrom') ?? reason.get('smtp.mailfrom'), true),
          ip: peerIp(props.get('smtp.remote-ip') ?? props.get('client-ip') ?? reason.get('client-ip')) || peerIp(hintedIp),
          helo: dns.mailboxDomain(props.get('smtp.helo') ?? reason.get('smtp.helo')),
          heloOnly: !props.has('smtp.mailfrom') && !reason.has('smtp.mailfrom') && props.has('smtp.helo')
        }];
      });
    });
    return { received, auth };
  }

  function relayPeer(header) {
    const from = header.match(/^\s*from\s+(.+?)\s+by\s+([^\s;(]+)/i);
    if (!from) return null;
    const peers = from[1].matchAll(/\[([^\]]+)\]|([^\s()[\];]+)/g);
    const ip = Array.from(peers, match => peerIp(match[1] ?? match[2])).find(Boolean);
    if (!ip) return null;
    return {
      ip, source: 'Received', helo: dns.mailboxDomain(from[1].split(/\s+/)[0]),
      receiver: dns.mailboxDomain(from[2])
    };
  }

  function inferSession(headers, reports) {
    const allReports = [...reports.received, ...reports.auth];
    const envelope = envelopeFrom(address.getHeader(headers, 'Return-Path')) ||
      allReports.find(report => report.envelope && !report.heloOnly)?.envelope;
    const relevant = allReports.filter(report =>
      (!report.heloOnly || envelope?.empty) &&
      (!report.envelope || (report.envelope.domain === envelope?.domain && report.envelope.empty === envelope?.empty)));
    const explicitPeer = relevant.find(report => report.ip);
    const receiver = explicitPeer?.receiver || relevant.find(report => report.receiver)?.receiver;
    const hops = headerValues(headers, 'Received').map(relayPeer).filter(Boolean);
    const relay = hops.find(hop => hop.ip === explicitPeer?.ip) ||
      hops.find(hop => receiver && hop.receiver === receiver) || (!explicitPeer ? hops[0] : null);
    const peer = explicitPeer || relay;
    const helo = explicitPeer?.helo ||
      relevant.find(report => report.helo && (!explicitPeer || report.receiver === receiver))?.helo || relay?.helo;
    const mailbox = envelope?.empty ? envelopeFrom(helo ? 'postmaster@' + helo : null) : envelope;
    return { mailbox, helo, ipText: peer?.ip, ipSource: peer?.source, emptyEnvelope: envelope?.empty };
  }

  class SpfDTO {
    constructor(domain = null) {
      this.domain = domain;
      this.result = 'unavailable';
      this.record = null;
      this.mechanisms = [];
      this.dnsCommand = null;
      this.rawDns = null;
      this.headerResult = null;
      this.senderIp = null;
      this.ipSource = null;
      this.source = null;
      this.error = null;
      this.trace = null;
      this.matchChain = null;
      this.mailbox = null;
      this.reportedBy = null;
      this.lookups = null;
      this.voidLookups = null;
    }
  }

  class SpfValidator {
    queryDns(name, type) {
      return dns.lookup(name, type);
    }

    async lookup(name, type, budget) {
      const records = await this.queryDns(name, type);
      if (budget && !records.length && ++budget.voids > 2) throw new SpfError('PermError', 'SPF void lookup limit exceeded');
      return records;
    }

    async fetchSPF(domain, budget) {
      const dnsCommand = 'dig TXT ' + domain;
      const answers = await this.lookup(domain, 'TXT', budget);
      const records = answers.map(rawDns => ({ rawDns, record: dns.txt(rawDns) }))
        .filter(({ record }) => /^v=spf1(?: |$)/i.test(record));
      if (records.length > 1) throw new SpfError('PermError', 'Multiple SPF records');
      return { ...records[0], dnsCommand };
    }

    countTerm(budget) {
      if (++budget.terms > 10) throw new SpfError('PermError', 'SPF DNS lookup limit exceeded');
    }

    async validatedPtr(ip, budget) {
      if (!budget.ptr) {
        budget.ptr = (async () => {
          const reverse = ip.macro.split('.').reverse().join('.') + (ip.bits === 32 ? '.in-addr.arpa' : '.ip6.arpa');
          const names = await this.lookup(reverse, 'PTR', budget);
          const validated = [];
          for (const value of names.slice(0, 10)) {
            const name = dns.normalizeName(value);
            if (!name) continue;
            const records = await this.lookup(name, ip.bits === 32 ? 'A' : 'AAAA', budget);
            if (records.some(text => matchesCidr(ip, parseIp(text)))) validated.push(name);
          }
          return validated;
        })();
      }
      return budget.ptr;
    }

    async expandDomain(spec, domain, session, budget) {
      if (!spec) return domain;
      const { ip, mailbox, helo } = session;
      let result = '';
      let end = 0;
      const macros = /%(?:[%_-]|\{([a-z])(\d*)(r?)([-.+,/_=]*)\})/gi;
      for (const match of spec.matchAll(macros)) {
        const literal = spec.slice(end, match.index);
        if (literal.includes('%')) throw new SpfError('PermError', 'Invalid SPF macro');
        result += literal;
        end = match.index + match[0].length;
        if (!match[1]) {
          result += { '%%': '%', '%_': ' ', '%-': '%20' }[match[0]];
          continue;
        }
        const [, letter, digits, reverse, delimiters] = match;
        const values = { s: mailbox.address, l: mailbox.localPart, o: mailbox.domain, d: domain,
          i: ip.macro, v: ip.bits === 32 ? 'in-addr' : 'ip6', h: helo };
        const key = letter.toLowerCase();
        if (key === 'p') {
          const names = await this.validatedPtr(ip, budget);
          values.p = names.find(name => name === domain) || names.find(name => name.endsWith('.' + domain)) || names[0] || 'unknown';
        }
        if (!Object.hasOwn(values, key) || (digits && Number(digits) === 0)) throw new SpfError('PermError', 'Invalid SPF macro');
        if (!values[key]) {
          throw new SpfError('Unavailable', key === 'h' ? 'The SPF policy needs the SMTP HELO name' :
            'The SPF policy needs the complete envelope sender address');
        }
        const parts = [...values[key].split(delimiters ? new RegExp('[' + delimiters.replace(/-/g, '\\-') + ']') : '.')];
        if (reverse) parts.reverse();
        const expanded = (digits ? parts.slice(-Number(digits)) : parts).join('.');
        result += letter === key ? expanded : encodeURIComponent(expanded).replace(/[!'()*]/g, char => '%' + char.charCodeAt(0).toString(16));
      }
      if (spec.slice(end).includes('%')) throw new SpfError('PermError', 'Invalid SPF macro');
      result += spec.slice(end);
      const name = dns.normalizeName(result, true);
      if (!name?.includes('.')) throw new SpfError('PermError', 'Invalid SPF lookup name');
      return name;
    }

    async evaluateRecursive(ipText, domain, depth = 0, sender = null, session = null, budget = null) {
      const node = { domain, record: null, rawDns: null, dnsCommand: null, children: [], terms: [],
        result: 'None', reason: 'No SPF record found', matchMechanism: null };
      let current = null;
      try {
        const name = dns.normalizeName(domain, true);
        const ip = session?.ip || parseIp(ipText);
        if (!ip || !name) throw new SpfError('PermError', 'Invalid SPF address or domain');
        session ||= { ip, mailbox: address.parseMailboxes(sender || 'postmaster@' + name)[0], helo: null };
        if (!session.mailbox) throw new SpfError('PermError', 'Invalid SMTP MAIL FROM');
        budget ||= { terms: depth, voids: 0, ptr: null };
        Object.assign(node, await this.fetchSPF(name, budget));
        if (!node.record) return node;

        const { terms, redirect } = parsePolicy(node.record);
        const addressType = ip.bits === 32 ? 'A' : 'AAAA';
        for (const term of terms) {
          current = term.token;
          let matched = term.type === 'all';
          if (term.type === 'ip') {
            matched = matchesCidr(ip, term.network, term.prefix);
          } else if (term.type !== 'all') {
            this.countTerm(budget);
            const target = await this.expandDomain(term.target, name, session, budget);
            if (term.type === 'include') {
              const trace = await this.evaluateRecursive(ipText, target, depth + 1, sender, session, budget);
              node.children.push({ type: 'include', val: target, trace });
              if (trace.result === 'None') throw new SpfError('PermError', 'SPF include has no policy');
              if (['PermError', 'TempError', 'Unavailable'].includes(trace.result)) throw new SpfError(trace.result, trace.reason);
              matched = trace.result === 'Pass';
              if (matched) node.matchTarget = target;
            } else if (term.type === 'exists') {
              matched = (await this.lookup(target, 'A', budget)).length > 0;
            } else if (term.type === 'ptr') {
              matched = (await this.validatedPtr(ip, budget)).some(name => name === target || name.endsWith('.' + target));
            } else {
              let names = [target];
              if (term.type === 'mx') {
                const exchanges = await this.lookup(target, 'MX', budget);
                if (exchanges.length > 10) throw new SpfError('PermError', 'Too many SPF MX records');
                names = exchanges.map(value => dns.normalizeName(value.trim().split(/\s+/)[1])).filter(Boolean);
              }
              const prefix = ip.bits === 32 ? term.ipv4Prefix : term.ipv6Prefix;
              for (const host of names) {
                const addresses = await this.lookup(host, addressType, budget);
                if (addresses.some(text => matchesCidr(ip, parseIp(text), prefix))) {
                  matched = true;
                  break;
                }
              }
            }
          }
          node.terms.push({ token: term.token, outcome: matched ? 'matched' : 'no-match' });
          current = null;
          if (matched) return { ...node, result: verdicts[term.qualifier], reason: 'Matched ' + term.token, matchMechanism: term.token };
        }

        if (redirect) {
          current = 'redirect=' + redirect;
          this.countTerm(budget);
          const target = await this.expandDomain(redirect, name, session, budget);
          const trace = await this.evaluateRecursive(ipText, target, depth + 1, sender, session, budget);
          node.children.push({ type: 'redirect', val: target, trace });
          if (trace.result === 'None') throw new SpfError('PermError', 'SPF redirect has no policy');
          node.terms.push({ token: 'redirect=' + redirect, outcome: trace.result === 'Pass' ? 'matched' : 'no-match' });
          return { ...node, result: trace.result, reason: trace.reason, matchTarget: target, matchMechanism: 'redirect=' + redirect };
        }
        return { ...node, result: 'Neutral', reason: 'No mechanism matched' };
      } catch (error) {
        if (current) node.terms.push({ token: current, outcome: 'error' });
        return { ...node, result: error.result || 'TempError', reason: error.message };
      }
    }

    // The reverse DNS name of the sending IP, for display only.
    async reverseName(ipText) {
      const ip = parseIp(ipText);
      if (!ip) return null;
      const reverse = ip.macro.split('.').reverse().join('.') + (ip.bits === 32 ? '.in-addr.arpa' : '.ip6.arpa');
      const names = await this.queryDns(reverse, 'PTR');
      return names.map(name => dns.normalizeName(name)).find(Boolean) || null;
    }

    getMatchChain(trace) {
      const chain = [];
      for (let node = trace; node; node = node.children.find(child => child.val === node.matchTarget)?.trace) {
        chain.push({ domain: node.domain, mechanism: node.matchMechanism, result: node.result });
      }
      return chain;
    }

    async verify(email, smtp = null) {
      const dto = new SpfDTO();
      const reports = readSpfReports(email.headers);
      dto.headerResult = reports.auth[0]?.result ?? reports.received[0]?.result ?? null;
      dto.reportedBy = (reports.auth[0] ? reports.auth[0].receiver : reports.received[0]?.receiver) ?? null;
      dto.source = smtp ? 'smtp' : 'headers';
      let session;
      if (smtp) {
        const helo = dns.mailboxDomain(smtp.helo?.trim());
        const envelope = envelopeFrom(smtp.mailFrom);
        const mailbox = envelope?.empty ? envelopeFrom(helo ? 'postmaster@' + helo : null) : envelope;
        session = { ipText: peerIp(smtp.ip), mailbox, helo, emptyEnvelope: envelope?.empty };
      } else {
        session = inferSession(email.headers, reports);
      }
      const { ipText, ipSource, mailbox, helo, emptyEnvelope } = session;
      dto.domain = mailbox?.domain ?? null;
      dto.mailbox = mailbox?.address ?? null;
      dto.senderIp = ipText ?? null;
      dto.ipSource = ipSource ?? null;
      if (mailbox && ipText) {
        const ip = parseIp(ipText);
        const budget = { terms: 0, voids: 0, ptr: null };
        dto.trace = await this.evaluateRecursive(ipText, dto.domain, 0, mailbox.address, { ip, mailbox, helo }, budget);
        dto.lookups = budget.terms;
        dto.voidLookups = budget.voids;
        const { record, rawDns, dnsCommand, result } = dto.trace;
        Object.assign(dto, { record, rawDns, dnsCommand, result: result.toLowerCase(), matchChain: this.getMatchChain(dto.trace) });
      } else {
        const missing = [];
        if (!mailbox) missing.push(emptyEnvelope ? 'the HELO name for the empty envelope sender' : 'the envelope sender domain');
        if (!ipText) missing.push('the sending IP');
        dto.error = 'Unable to check SPF without ' + missing.join(' and ') + '.';
        if (mailbox) {
          try { Object.assign(dto, await this.fetchSPF(dto.domain)); }
          catch (error) { dto.error += ' DNS lookup failed: ' + error.message; }
        }
      }
      if (dto.record) dto.mechanisms = dto.record.split(/ +/).slice(1).filter(Boolean);
      return dto;
    }
  }

  return { SpfValidator, SpfDTO };
}));
