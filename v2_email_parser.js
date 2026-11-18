(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js
    const dkim = require('./v2_dkim_validator');
    module.exports = factory(require('./v2_dns'), require('./v2_public_suffix'), dkim);
  } else {
    // Browser globals
    const modules = factory(root.EmailDns, root.PublicSuffix);
    root.EmailDTO = modules.EmailDTO;
    root.EmailParser = modules.EmailParser;
    root.parseEmail = modules.parseEmail;
    root.decodeMimeWords = modules.decodeMimeWords;
    root.EmailAddress = modules.EmailAddress;
    root.IpAddress = modules.IpAddress;
    root.parseMailDate = modules.parseMailDate;
    root.MimeParser = modules.MimeParser;
    root.HeaderInsights = modules.HeaderInsights;
    root.DeliveryRecords = modules.DeliveryRecords;
    root.RelayParser = modules.RelayParser;
    root.RelayDTO = modules.RelayDTO;
    root.ServerValidationParser = modules.ServerValidationParser;
    root.ServerValidationDTO = modules.ServerValidationDTO;
  }
}(typeof self !== 'undefined' ? self : this, function(dns, suffixes, dkimModule) {

  /**
   * Data Transfer Object for the parsed email.
   */
  class EmailDTO {
    constructor(rawText, rawHeaders, headers, body, dkim = []) {
      this.rawText = rawText;
      this.rawHeaders = rawHeaders;
      this.headers = headers;
      this.body = body;
      this.dkim = dkim;
    }
  }

  /**
   * Class responsible for parsing email text.
   */
  class EmailParser {
    parseBytes(bytes) {
      // A byte string keeps wire octets intact, including non-UTF-8 body data.
      let wire = '';
      for (let i = 0; i < bytes.length; i += 8192) {
        wire += String.fromCharCode(...bytes.subarray(i, i + 8192));
      }
      return this.parse(wire, true);
    }

    parse(rawText, wireBytes = false) {
      // Messages saved from an mbox start with a "From sender date" separator line, which isn't a header.
      rawText = rawText.replace(/^From (?![ \t]*:)[^\r\n]*\r?\n/, '');
      const match = rawText.match(/\r\n\r\n|\n\n/);
      let rawHeaders = rawText;
      let body = '';

      if (match) {
        rawHeaders = rawText.substring(0, match.index);
        body = rawText.substring(match.index + match[0].length);
      }

      const headers = Object.create(null);
      const headerKeys = new Map();
      const lines = rawHeaders.split(/\r?\n/);
      let currentKey = null;

      for (const line of lines) {
        if (/^[ \t]/.test(line)) {
          if (!currentKey) continue;
          const val = headers[currentKey];
          if (Array.isArray(val)) {
            val[val.length - 1] += ' ' + line.trim();
          } else {
            headers[currentKey] += ' ' + line.trim();
          }
        } else {
          const separatorIndex = line.indexOf(':');
          if (separatorIndex !== -1) {
            const key = line.substring(0, separatorIndex).trim();
            const value = line.substring(separatorIndex + 1).trim();

            const lowerKey = key.toLowerCase();
            if (!headerKeys.has(lowerKey)) headerKeys.set(lowerKey, key);
            const headerKey = headerKeys.get(lowerKey);

            if (Object.prototype.hasOwnProperty.call(headers, headerKey)) {
              if (Array.isArray(headers[headerKey])) {
                headers[headerKey].push(value);
              } else {
                headers[headerKey] = [headers[headerKey], value];
              }
            } else {
              headers[headerKey] = value;
            }
            currentKey = headerKey;
          } else {
            currentKey = null;
          }
        }
      }

      if (wireBytes) {
        const decoder = new TextDecoder('utf-8', { fatal: true });
        const decode = value => {
          try { return decoder.decode(Uint8Array.from(value, char => char.charCodeAt(0))); }
          catch { return value; }
        };
        for (const key of Object.keys(headers)) {
          const value = headers[key];
          headers[key] = Array.isArray(value) ? value.map(decode) : decode(value);
        }
      }

      const email = new EmailDTO(rawText, rawHeaders, headers, body, []);
      // Pasted headers (e.g. from a mail client's "Show original") often come without the body.
      email.headersOnly = !body.trim();
      email.wireBytes = wireBytes;
      return email;
    }
  }

  function parseEmail(rawText) {
    return new EmailParser().parse(rawText);
  }

  function decodeMimeWord(charset, encoding, payload) {
    try {
      let bytes;
      if (encoding.toLowerCase() === 'b') {
        bytes = Uint8Array.from(atob(payload), char => char.charCodeAt(0));
      } else {
        if (/=(?![\da-f]{2})/i.test(payload)) return null;
        bytes = Uint8Array.from(payload.match(/=[\da-f]{2}|./gi), part => {
          if (part === '_') return 0x20;
          return part.startsWith('=') ? parseInt(part.slice(1), 16) : part.charCodeAt(0);
        });
      }
      return new TextDecoder(charset.split('*')[0], { fatal: true }).decode(bytes);
    } catch {
      // Leave unknown charsets and malformed words readable in their original form.
      return null;
    }
  }

  function decodeMimeWords(value) {
    const pattern = /(?<!\S)=\?([^\s?]+)\?([qb])\?([\x21-\x3e\x40-\x7e]+)\?=(?!\S)/gi;
    let text = '';
    let offset = 0;
    let previousDecoded = false;
    for (const match of value.matchAll(pattern)) {
      const [original, charset, encoding, payload] = match;
      const decoded = decodeMimeWord(charset, encoding, payload);
      const between = value.slice(offset, match.index);
      // RFC 2047 ignores the whitespace between adjacent encoded words.
      if (!(previousDecoded && decoded !== null && /^[ \t\r\n]*$/.test(between))) text += between;
      text += decoded ?? original;
      offset = match.index + original.length;
      previousDecoded = decoded !== null;
    }
    return text + value.slice(offset);
  }

  function getHeader(headers, name) {
    const key = Object.keys(headers).find(key => key.toLowerCase() === name.toLowerCase());
    return key === undefined ? undefined : headers[key];
  }

  function parseMailboxes(value) {
    if (typeof value !== 'string' || /[\x00-\x08\x0a-\x1f\x7f]/.test(value)) return [];
    const entries = [];
    let part = '';
    let quoted = false;
    let escaped = false;
    let comments = 0;
    let angleStart = -1;
    let angleEnd = -1;
    let invalidPhrase = false;
    const addMailbox = () => {
      if (angleStart >= 0 && (angleEnd < 0 || part.slice(angleEnd + 1).trim())) return false;
      const address = (angleStart < 0 ? part : part.slice(angleStart + 1, angleEnd)).trim();
      const match = address.match(/^("(?:[^"\\\r\n]|\\[^\r\n])*"|[^\s"@(),:;<>\[\]\\]+)[ \t]*@[ \t]*([^\s@]+)$/u);
      if (!match || (!match[1].startsWith('"') && /(?:^\.|\.\.|\.$)/.test(match[1]))) return false;
      const domain = dns.mailboxDomain(match[2]);
      if (!domain) return false;
      entries.push({ localPart: match[1], domain, address: match[1] + '@' + domain });
      part = '';
      angleStart = angleEnd = -1;
      invalidPhrase = false;
      return true;
    };

    for (const char of value) {
      if (escaped) {
        escaped = false;
      } else if (char === '\\' && (quoted || comments)) {
        escaped = true;
      } else if (comments) {
        if (char === '(') comments++;
        if (char === ')') comments--;
        continue;
      } else if (char === '"') {
        quoted = !quoted;
      } else if (!quoted) {
        if (char === '(') {
          comments++;
          continue;
        }
        if (char === ')') return [];
        if (angleStart < 0 && '@:;'.includes(char)) invalidPhrase = true;
        if (char === '<') {
          if (angleStart >= 0 || invalidPhrase) return [];
          angleStart = part.length;
        }
        if (char === '>') {
          if (angleStart < 0 || angleEnd >= 0) return [];
          angleEnd = part.length;
        }
        if (char === ',' && (angleStart < 0 || angleEnd >= 0)) {
          if (!addMailbox()) return [];
          continue;
        }
      }
      if (!comments) part += char;
    }

    return !quoted && !comments && !escaped && addMailbox() ? entries : [];
  }

  const EmailAddress = { getHeader, parseMailboxes };

  class HopDTO {
    constructor() {
      this.from = null;
      this.by = null;
      this.with = null;
      this.date = null;
      this.timestamp = 0;
      this.ip = null;
      this.helo = null;
      this.tls = null;
      this.cipher = null;
      this.delay = null;
      this.fullHeader = null;
    }
  }

  // Dates as mail servers write them: RFC 5322 ("Tue, 10 Nov 2026 16:55:11 +0000"), with optional
  // fractional seconds, or ISO-like ("2026-11-10 16:55:11.859154455 +0000 UTC", as SendGrid writes).
  const dateLike = new RegExp([
    '(?:(?:mon|tue|wed|thu|fri|sat|sun),? )?\\d{1,2} (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* \\d{2,4} ' +
      '\\d{1,2}:\\d{2}(?::\\d{2}(?:\\.\\d+)?)?(?: ?(?:[+-]\\d{4}|[a-z]{1,5}\\b))?(?: ?\\([^)]*\\))?',
    '\\d{4}-\\d{2}-\\d{2}[ t]\\d{1,2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?: ?(?:z|[+-]\\d{2}:?\\d{2}))?(?: (?:utc|gmt))?'
  ].join('|'), 'gi');
  const monthIndex = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  const zoneMinutes = { ut: 0, utc: 0, gmt: 0, z: 0, est: -300, edt: -240, cst: -360, cdt: -300, mst: -420, mdt: -360, pst: -480, pdt: -420 };

  // Parses those formats itself, so results don't depend on each browser's Date.parse.
  function parseMailDate(text) {
    const value = String(text ?? '').replace(/\s+/g, ' ');
    let parts = value.match(/(\d{1,2}) (jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* (\d{2,4}) (\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(?: ?([+-]\d{4}|[a-z]{1,5})\b)?/i);
    let year, month, day, zone;
    if (parts) {
      [, day, month, year] = parts;
      month = monthIndex[month.toLowerCase()];
      year = Number(year);
      if (year < 50) year += 2000;
      else if (year < 1000) year += 1900;
      zone = parts[8];
      parts = parts.slice(4, 8);
    } else {
      parts = value.match(/(\d{4})-(\d{2})-(\d{2})[ t](\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?(?: ?(z|[+-]\d{2}:?\d{2}))?/i);
      if (!parts) return NaN;
      year = Number(parts[1]);
      month = Number(parts[2]) - 1;
      day = parts[3];
      zone = parts[8];
      parts = parts.slice(4, 8);
    }
    const [hour, minute, second = '0', fraction = ''] = parts;
    let offset = 0;
    if (zone && /^[+-]/.test(zone)) {
      const digits = zone.replace(':', '');
      offset = (zone[0] === '-' ? -1 : 1) * (Number(digits.slice(1, 3)) * 60 + Number(digits.slice(3, 5)));
    } else if (zone) {
      offset = zoneMinutes[zone.toLowerCase()] ?? 0;
    }
    if (month === undefined || month < 0 || month > 11 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) return NaN;
    const millis = Number((fraction + '000').slice(0, 3));
    return Date.UTC(year, month, Number(day), Number(hour), Number(minute), Number(second), millis) - offset * 60000;
  }

  function withoutComments(text) {
    let previous;
    do {
      previous = text;
      text = text.replace(/\([^()]*\)/g, ' ');
    } while (text !== previous);
    return text;
  }

  class RelayDTO {
    constructor() {
      this.hops = [];
    }
  }

  class RelayParser {
    parse(receivedHeaders) {
      const dto = new RelayDTO();
      if (!receivedHeaders) return dto;

      const headers = Array.isArray(receivedHeaders) ? receivedHeaders : [receivedHeaders];
      
      headers.forEach(header => {
        if (typeof header !== 'string') return;
        const hop = new HopDTO();
        hop.fullHeader = header;
        
        const cleanHeader = header.replace(/\s+/g, ' ');
        // Comments hold free text such as "(using TLSv1.3 with cipher ...)", so read the
        // from/by/with clauses without them.
        const clauses = withoutComments(cleanHeader);

        // The date follows the last ';'. Some servers (SendGrid, for one) leave out the ';', so then
        // take the last date in the header.
        const tail = header.match(/;\s*([^;]+)$/)?.[1].replace(/\s+/g, ' ');
        const dates = tail?.match(dateLike) || cleanHeader.match(dateLike);
        hop.date = (tail && tail.match(dateLike) ? tail.match(dateLike)[0] : dates?.at(-1) ?? tail ?? '').trim() || null;
        if (hop.date) {
            const ts = parseMailDate(hop.date);
            const fallback = Number.isNaN(ts) ? Date.parse(hop.date) : ts;
            if (!Number.isNaN(fallback)) hop.timestamp = fallback;
        }

        const clause = name => clauses.match(new RegExp('(?:^|[\\s;])' + name + '\\s+([^\\s;]+)', 'i'))?.[1] ?? null;
        hop.from = clause('from');
        hop.by = clause('by');
        hop.with = /\bwith\s+Microsoft\s+SMTP\s+Server\b/i.test(clauses) ? 'Microsoft SMTP' : clause('with');

        const ipMatch = cleanHeader.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/) ||
                        cleanHeader.match(/\[(IPv6:[a-fA-F0-9:.]+)\]/i) ||
                        cleanHeader.match(/\[([a-fA-F0-9]*:[a-fA-F0-9:]*:[a-fA-F0-9:.]*)\]/) ||
                        // Microsoft writes "from host (203.0.113.5)" with no brackets.
                        cleanHeader.match(/\bfrom\s+[^\s;()]+\s+\(([0-9a-fA-F:.]+)\)/i);
        if (ipMatch && (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ipMatch[1]) || parseIpv6(ipMatch[1]))) hop.ip = ipMatch[1];

        hop.helo = cleanHeader.match(/\bhelo[=\s]+([^\s)\];]+)/i)?.[1] ?? null;
        const tlsMatch = cleanHeader.match(/\b(?:version=|using\s+)(TLS|SSL)v?(\d)(?:[._](\d))?/i);
        hop.tls = tlsMatch ? tlsMatch[1].toUpperCase() + ' ' + tlsMatch[2] + (tlsMatch[3] ? '.' + tlsMatch[3] : '')
            : /^(?:E|UTF8)?(?:SMTP|LMTP)S/i.test(hop.with || '') ? 'TLS' : null;
        hop.cipher = cleanHeader.match(/\bcipher[=\s]+([A-Z0-9][A-Z0-9_-]{5,})/i)?.[1] ?? null;

        dto.hops.push(hop);
      });

      for (let i = 0; i < dto.hops.length - 1; i++) {
        const current = dto.hops[i];
        const prev = dto.hops[i+1];
        if (current.timestamp && prev.timestamp) {
            current.delay = (current.timestamp - prev.timestamp) / 1000;
        }
      }

      return dto;
    }
  }

  class ServerValidationDTO {
    constructor() {
      this.service = null;
      this.results = [];
      this.fullHeader = null;
      // Every Authentication-Results header, topmost (most recent) first.
      this.headers = [];
    }
  }

  // Split an Authentication-Results value on ';' outside comments and quoted strings, keeping each
  // clause's comment text apart: "spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=a.example".
  function resultClauses(value) {
    const clauses = [{ text: '', comment: '' }];
    let depth = 0;
    let quoted = false;
    for (let i = 0; i < value.length; i++) {
      const char = value[i];
      const clause = clauses.at(-1);
      if (quoted) {
        clause.text += char;
        if (char === '\\') clause.text += value[++i] ?? '';
        else if (char === '"') quoted = false;
      } else if (depth) {
        if (char === '\\') { clause.comment += value[++i] ?? ''; continue; }
        if (char === '(') depth++;
        if (char === ')' && --depth === 0) continue;
        clause.comment += char;
      } else if (char === '(') {
        depth = 1;
        if (clause.comment) clause.comment += ' ';
      } else if (char === '"') {
        quoted = true;
        clause.text += char;
      } else if (char === ';') {
        clauses.push({ text: '', comment: '' });
      } else {
        clause.text += char;
      }
    }
    return clauses.map(clause => ({ text: clause.text.replace(/\s+/g, ' ').trim(), comment: clause.comment.replace(/\s+/g, ' ').trim() }))
      .filter(clause => clause.text || clause.comment);
  }

  // "spf=pass ..." rather than a server name such as "mx.google.com 1".
  function isResultClause(text) {
    return /^[a-z0-9_.-]+(?:\/\d+)?\s*=/i.test(text || '');
  }

  class ServerValidationParser {
    parseOne(header) {
      const clauses = resultClauses(header);
      // Microsoft leaves out the server name and starts with the first result.
      const named = clauses.length && !isResultClause(clauses[0].text);
      const [service = null, version = null] = named ? clauses[0].text.split(/\s+/) : [];
      const results = [];
      for (const clause of named ? clauses.slice(1) : clauses) {
        const match = clause.text.match(/^([a-z0-9_.-]+)(?:\/\d+)?\s*=\s*([a-z0-9_-]+)\s*(.*)$/i);
        if (!match) continue;
        const props = {};
        for (const [, key, raw] of match[3].matchAll(/([a-z0-9_.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s;]+)/gi)) {
          props[key.toLowerCase()] = raw.replace(/^"|"$/g, '');
        }
        results.push({ method: match[1].toLowerCase(), result: match[2].toLowerCase(), props, comment: clause.comment || null,
          raw: clause.text + (clause.comment ? ' (' + clause.comment + ')' : '') });
      }
      return { service, version, results, raw: header };
    }

    parse(headerValue) {
      const dto = new ServerValidationDTO();
      const headers = (Array.isArray(headerValue) ? headerValue : [headerValue]).filter(value => typeof value === 'string');
      dto.headers = headers.map(header => this.parseOne(header));
      if (dto.headers.length) {
        Object.assign(dto, { service: dto.headers[0].service, results: dto.headers[0].results, fullHeader: dto.headers[0].raw });
      }
      return dto;
    }
  }

  // --- Delivery records: what a receiving server concluded (Authentication-Results, Received-SPF). Anyone can
  // write these headers, the sender included, so a record counts only where the Received chain shows the server it
  // names handling the message: from that server's topmost Received header down to the next one written by another
  // organization. Below that, the record was already in the message when it arrived. Microsoft's records name no
  // server, so they're placed against the receiving organization: the one that wrote the topmost Received header
  // with a domain. A sender can still write a record next to the receiver's own hop when the receiver adds none;
  // nothing in the message can rule that out.
  const DeliveryRecords = (() => {
    // Domains one provider uses for its own servers.
    const aliases = {
      'office365.com': 'outlook.com', 'exchangelabs.com': 'outlook.com', 'office.com': 'outlook.com', 'hotmail.com': 'outlook.com',
      'live.com': 'outlook.com', 'gmail.com': 'google.com', 'googlemail.com': 'google.com', 'me.com': 'icloud.com', 'mac.com': 'icloud.com'
    };

    function organization(host) {
      const domain = suffixes.registrableDomain(host);
      return aliases[domain] || domain;
    }

    // Header fields in order, split the way the DKIM verifier splits them, so indexes match the Headers view.
    function traceFields(rawHeaders) {
      const fields = [];
      let current = null;
      for (const line of String(rawHeaders || '').split(/\r?\n/)) {
        if (/^[ \t]/.test(line)) {
          if (current) current.value += ' ' + line.trim();
          continue;
        }
        const colon = line.indexOf(':');
        current = colon > 0 ? { index: fields.length, name: line.slice(0, colon).trim().toLowerCase(), value: line.slice(colon + 1).trim() } : null;
        if (current) fields.push(current);
      }
      return fields;
    }

    // The server a Received header names in its "by" (who wrote it) or "from" (who handed the message over) clause.
    function receivedClause(value, name) {
      const host = withoutComments(value.replace(/\s+/g, ' ')).match(new RegExp('(?:^|[\\s;])' + name + '\\s+([^\\s;]+)', 'i'))?.[1];
      return host ? host.replace(/\.$/, '').toLowerCase() : null;
    }

    // The server a record names: Authentication-Results' first word, or Received-SPF's receiver= (or the
    // "(google.com: domain of ...)" comment).
    function serverName(field) {
      let name;
      if (field.name === 'authentication-results') {
        const first = resultClauses(field.value)[0]?.text || '';
        name = isResultClause(first) ? null : first.split(/\s+/)[0];
      } else {
        name = field.value.match(/\breceiver\s*=\s*([^\s;()]+)/i)?.[1] || field.value.match(/^\s*[a-z]+\s*\(([^\s:()]+):/i)?.[1];
      }
      return name && /^[a-z0-9_.-]+$/i.test(name) ? name.replace(/\.$/, '').toLowerCase() : null;
    }

    // "mx1" in a Received header and "mx1.example.net" in a record are the same server.
    function sameHost(a, b) {
      return a === b || (!a.includes('.') && b.split('.')[0] === a) || (!b.includes('.') && a.split('.')[0] === b);
    }

    function place(field, hops, receiving) {
      const server = serverName(field);
      const serverOrg = server ? organization(server) : null;
      const record = { index: field.index, name: field.name, value: field.value, server, trusted: false, reason: null, below: null, suspicious: false };
      if (!hops.length) return { ...record, reason: 'no-trace' };
      let own = server ? hops.filter(hop => hop.by && (sameHost(hop.by, server) || (serverOrg && hop.org === serverOrg))) : [];
      let org = serverOrg || own.find(hop => hop.org)?.org || null;
      if (!own.length && serverOrg) return { ...record, org: serverOrg, reason: 'unknown-server' };
      // Records that name no server are placed against the receiving organization.
      const byReceiver = !own.length;
      if (!own.length) {
        own = receiving ? hops.filter(hop => hop.org === receiving) : [];
        org = receiving;
      }
      if (!own.length) return { ...record, reason: 'unplaced' };
      // For the explanation: the hop that ties the record to its server, and the organization compared against.
      const placed = { ...record, org, byReceiver, via: { index: own[0].index, by: own[0].by } };
      const next = hops.find(hop => hop.index > own[0].index && hop.org && hop.org !== org);
      if (next && field.index > next.index) {
        // Claiming to be the receiver while sitting below another organization's hop is a warning sign.
        return { ...placed, reason: 'below-other', below: next.by, suspicious: Boolean(serverOrg) && serverOrg === receiving };
      }
      return { ...placed, trusted: true };
    }

    function assess(email) {
      if (email.deliveryRecords) return email.deliveryRecords;
      const fields = traceFields(email.rawHeaders);
      const hops = fields.filter(field => field.name === 'received').map(field => {
        const by = receivedClause(field.value, 'by');
        const from = receivedClause(field.value, 'from');
        return { index: field.index, by, org: by ? organization(by) : null, from, fromOrg: from ? organization(from) : null, value: field.value };
      });
      const receiving = hops.find(hop => hop.org)?.org || null;
      const records = fields.filter(field => field.name === 'authentication-results' || field.name === 'received-spf')
        .map(field => place(field, hops, receiving));
      // A server writes one record per pass. A second copy naming it, below the oldest hop, came with the message.
      const oldest = hops.at(-1);
      const seen = new Set();
      for (const record of records) {
        const key = record.name + ' ' + record.server;
        if (record.trusted && record.server && seen.has(key) && oldest && record.index > oldest.index) {
          Object.assign(record, { trusted: false, reason: 'repeated', suspicious: true });
        }
        if (record.server) seen.add(key);
      }
      // Where the receiving organization took the message from another one. The Received header right below that hop
      // was written before the message reached it, so one claiming the receiving organization wrote it is forged.
      const entry = receiving && hops.find(hop => hop.org === receiving && hop.fromOrg && hop.fromOrg !== receiving);
      const next = entry && hops.find(hop => hop.index > entry.index);
      const forgedHops = next && next.org === receiving ? [{ index: next.index, by: next.by, entryBy: entry.by, entryFrom: entry.from }] : [];
      const result = { records, receiving, forgedHops, hops, trusted: name => records.filter(record => record.trusted && record.name === name) };
      Object.defineProperty(email, 'deliveryRecords', { value: result, configurable: true, writable: true });
      return result;
    }

    // Why a record isn't used, in a sentence.
    function explain(record) {
      const server = record.server || 'the receiving server';
      switch (record.reason) {
        case 'unknown-server': return `It names ${record.server}, which doesn't appear in any Received header.`;
        case 'below-other': return `It sits below the Received header added by ${record.below || 'another server'}, so it was already in the message before ${server} handled it.`;
        case 'repeated': return `${server} recorded results higher up, and this copy sits below the oldest Received header, where the sender's software writes.`;
        case 'no-trace': return 'There\'s no Received header to show which server added it.';
        case 'unplaced': return 'No Received header shows which server added it.';
        default: return '';
      }
    }

    return { assess, explain, organization };
  })();

  // Exact IPv6 parsing, so addresses that carry an IPv4 inside them can be unwrapped.
  function parseIpv6(text) {
    let value = String(text ?? '').trim().replace(/^\[|\]$/g, '').replace(/^IPv6:/i, '').toLowerCase();
    const dotted = value.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (dotted) {
      const octets = dotted[2].split('.').map(Number);
      if (octets.some(octet => octet > 255)) return null;
      value = dotted[1] + ((octets[0] << 8) | octets[1]).toString(16) + ':' + ((octets[2] << 8) | octets[3]).toString(16);
    }
    const halves = value.split('::');
    if (halves.length > 2) return null;
    const parts = halves.map(half => half ? half.split(':') : []);
    if (parts.flat().some(part => !/^[0-9a-f]{1,4}$/.test(part))) return null;
    const missing = 8 - parts.flat().length;
    if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
    const words = halves.length === 1 ? parts[0] : [...parts[0], ...Array(missing).fill('0'), ...parts[1]];
    return words.map(word => parseInt(word, 16));
  }

  // The IPv4 address carried inside an IPv6 address, for the formats that embed one.
  function embeddedIpv4(text) {
    const words = parseIpv6(text);
    if (!words) return null;
    const ipv4 = (high, low) => [high >> 8, high & 255, low >> 8, low & 255].join('.');
    const zero = (from, to) => words.slice(from, to).every(word => word === 0);
    if (words[0] === 0x2002) return { ipv4: ipv4(words[1], words[2]), kind: '6to4' };
    if (zero(0, 5) && words[5] === 0xffff) return { ipv4: ipv4(words[6], words[7]), kind: 'IPv4-mapped' };
    if (words[0] === 0x64 && words[1] === 0xff9b && zero(2, 6)) return { ipv4: ipv4(words[6], words[7]), kind: 'NAT64' };
    // Teredo stores the client's IPv4 with every bit inverted.
    if (words[0] === 0x2001 && words[1] === 0) return { ipv4: ipv4(words[6] ^ 0xffff, words[7] ^ 0xffff), kind: 'Teredo' };
    return null;
  }

  // --- Who runs an IP: the network announcing it (ASN, via Team Cymru's DNS zone) and the
  // organization it's registered to (RDAP at the regional registry). Results are cached per IP.
  const rdapBases = {
    arin: 'https://rdap.arin.net/registry/ip/', ripencc: 'https://rdap.db.ripe.net/ip/', apnic: 'https://rdap.apnic.net/ip/',
    lacnic: 'https://rdap.lacnic.net/rdap/ip/', afrinic: 'https://rdap.afrinic.net/rdap/ip/'
  };
  const registryNames = { arin: 'ARIN', ripencc: 'RIPE NCC', apnic: 'APNIC', lacnic: 'LACNIC', afrinic: 'AFRINIC' };
  const ownerCache = new Map();

  function plainIp(text) {
    const value = String(text ?? '').trim().replace(/^\[|\]$/g, '').replace(/^IPv6:/i, '');
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) && value.split('.').every(octet => Number(octet) <= 255)) return { text: value, v6: false };
    const words = parseIpv6(value);
    return words ? { text: words.map(word => word.toString(16)).join(':'), v6: true, words } : null;
  }

  // "396479 | 204.220.171.0/24 | US | arin | 1995-01-05" and "396479 | US | arin | 2017-06-21 | MAILGUN-US - Mailgun Technologies Inc., US"
  function parseCymru(text) {
    const fields = String(text ?? '').replace(/^"|"$/g, '').split('|').map(field => field.trim());
    return fields.length >= 4 ? fields : null;
  }

  function rdapSummary(json) {
    const entities = [...(json.entities || []), ...(json.entities || []).flatMap(entity => entity.entities || [])];
    const named = role => entities.filter(entity => (entity.roles || []).includes(role))
      .map(entity => entity.vcardArray?.[1]?.find(item => item[0] === 'fn')?.[3]).find(Boolean);
    const cidr = (json.cidr0_cidrs || []).map(item => (item.v4prefix || item.v6prefix) + '/' + item.length)[0];
    return {
      organization: named('registrant') || named('administrative') || null,
      network: json.name || json.handle || null,
      range: cidr || (json.startAddress && json.endAddress ? json.startAddress + ' – ' + json.endAddress : null)
    };
  }

  async function fetchRdap(url) {
    const response = await fetch(url, { headers: { Accept: 'application/rdap+json' }, signal: AbortSignal.timeout(8000) });
    if (!response.ok) throw new Error('RDAP HTTP ' + response.status);
    return response.json();
  }

  // Tests pass their own lookup and getJson; only the real lookups are cached.
  function networkOwner(ipText, hooks = null) {
    const lookup = hooks?.lookup || ((name, type) => dns.lookup(name, type));
    const getJson = hooks?.getJson || fetchRdap;
    const ip = plainIp(ipText);
    if (!ip) return Promise.resolve(null);
    if (hooks || !ownerCache.has(ip.text)) {
      const pending = (async () => {
        // The questions asked and their answers, for the step-by-step explanation; kept out of the result's own fields.
        const lookups = { dns: [], rdap: null, rdapOk: false };
        const ask = async name => {
          const records = await lookup(name, 'TXT');
          lookups.dns.push({ type: 'TXT', name, records, error: null });
          return records;
        };
        const reversed = ip.v6
          ? ip.words.map(word => word.toString(16).padStart(4, '0')).join('').split('').reverse().join('.') + '.origin6.asn.cymru.com'
          : ip.text.split('.').reverse().join('.') + '.origin.asn.cymru.com';
        const origin = parseCymru((await ask(reversed))[0]);
        const asn = origin ? origin[0].split(/\s+/)[0] : null;
        const result = { ip: ip.text, asn, prefix: origin?.[1] || null, country: origin?.[2] || null,
          registry: registryNames[origin?.[3]] || origin?.[3] || null, asName: null, organization: null, network: null, range: null };
        Object.defineProperty(result, 'lookups', { value: lookups, enumerable: false });
        if (asn) {
          const details = parseCymru((await ask('AS' + asn + '.asn.cymru.com'))[0]);
          // "MAILGUN-US - Mailgun Technologies Inc., US" -> "Mailgun Technologies Inc."
          result.asName = details?.[4]?.replace(/^[^ ]+ - /, '').replace(/, [A-Z]{2}$/, '') || null;
        }
        const base = rdapBases[origin?.[3]];
        lookups.rdap = base ? base + encodeURIComponent(ip.text) : null;
        if (base) {
          try {
            Object.assign(result, rdapSummary(await getJson(lookups.rdap)));
            lookups.rdapOk = true;
          } catch {
            // The registry is optional; the routing data above still names the network.
          }
        }
        return result.asn || result.organization ? result : null;
      })().catch(() => null);
      if (hooks) return pending;
      ownerCache.set(ip.text, pending);
      // Keep only answers, so a later lookup can retry after a network error.
      pending.then(result => { if (!result) ownerCache.delete(ip.text); });
    }
    return ownerCache.get(ip.text);
  }

  const IpAddress = { parseIpv6, embeddedIpv4, networkOwner, parseCymru, rdapSummary, clearCache: () => ownerCache.clear() };

  // --- MIME structure: the parts of a message, decoded, with their types and file names ---
  function headerFields(block) {
    const fields = [];
    for (const line of block.split(/\r?\n/)) {
      if (/^[ \t]/.test(line) && fields.length) fields.at(-1).value += ' ' + line.trim();
      else if (line.includes(':')) fields.push({ name: line.slice(0, line.indexOf(':')).trim().toLowerCase(), value: line.slice(line.indexOf(':') + 1).trim() });
    }
    return fields;
  }

  // "text/plain; charset=utf-8", including RFC 2231 forms such as filename*=UTF-8''na%C3%AFve.pdf
  function headerParams(value) {
    const [main, ...rest] = String(value || '').match(/(?:"(?:[^"\\]|\\.)*"|[^;])+/g) || [''];
    const params = {};
    const pieces = {};
    for (const item of rest) {
      const at = item.indexOf('=');
      if (at < 0) continue;
      const key = item.slice(0, at).trim().toLowerCase();
      let raw = item.slice(at + 1).trim();
      if (raw.startsWith('"')) raw = raw.slice(1, -1).replace(/\\(.)/g, '$1');
      const continued = key.match(/^([^*]+)\*(\d+)(\*?)$/);
      if (continued) (pieces[continued[1]] ||= []).push({ index: Number(continued[2]), raw, encoded: Boolean(continued[3]) });
      else if (key.endsWith('*')) params[key.slice(0, -1)] = decodeExtended(raw, true);
      else params[key] = raw;
    }
    for (const [key, list] of Object.entries(pieces)) {
      list.sort((a, b) => a.index - b.index);
      params[key] = decodeExtended(list.map(piece => piece.raw).join(''), list[0].encoded);
    }
    return { value: main.trim().toLowerCase(), params };
  }

  function decodeExtended(raw, encoded) {
    if (!encoded) return raw;
    const match = raw.match(/^([^']*)'[^']*'(.*)$/);
    const charset = match ? match[1] || 'utf-8' : 'utf-8';
    const text = match ? match[2] : raw;
    const bytes = [];
    for (let i = 0; i < text.length; i++) {
      if (text[i] === '%' && /^[0-9a-f]{2}$/i.test(text.slice(i + 1, i + 3))) {
        bytes.push(parseInt(text.slice(i + 1, i + 3), 16));
        i += 2;
      } else {
        bytes.push(text.charCodeAt(i) & 255);
      }
    }
    return decodeCharset(Uint8Array.from(bytes), charset);
  }

  function decodeCharset(bytes, charset) {
    try {
      return new TextDecoder(charset || 'utf-8').decode(bytes);
    } catch {
      return new TextDecoder('windows-1252').decode(bytes);
    }
  }

  function stringBytes(text, wire) {
    return wire ? Uint8Array.from(text, char => char.charCodeAt(0) & 255) : new TextEncoder().encode(text);
  }

  // Returns the decoded bytes, plus the text as-is when a pasted (already decoded) part needs no decoding.
  function decodeTransfer(raw, encoding, wire) {
    if (encoding === 'base64') {
      try {
        return { bytes: Uint8Array.from(atob(raw.replace(/[^A-Za-z0-9+/=]/g, '')), char => char.charCodeAt(0)) };
      } catch {
        return { bytes: stringBytes(raw, wire) };
      }
    }
    if (encoding === 'quoted-printable') {
      const text = raw.replace(/=\r?\n/g, '');
      const bytes = [];
      for (let i = 0; i < text.length; i++) {
        if (text[i] === '=' && /^[0-9a-f]{2}$/i.test(text.slice(i + 1, i + 3))) {
          bytes.push(parseInt(text.slice(i + 1, i + 3), 16));
          i += 2;
        } else {
          bytes.push(...stringBytes(text[i], wire));
        }
      }
      return { bytes: Uint8Array.from(bytes) };
    }
    return wire ? { bytes: stringBytes(raw, true) } : { bytes: stringBytes(raw, false), text: raw };
  }

  function splitMultipart(body, boundary) {
    const delimiter = '--' + boundary;
    const parts = [];
    let current = null;
    for (const line of body.split(/\r?\n/)) {
      if (line.startsWith(delimiter)) {
        const rest = line.slice(delimiter.length);
        if (rest.startsWith('--')) break;
        if (/^[ \t]*$/.test(rest)) {
          if (current) parts.push(current);
          current = [];
          continue;
        }
      }
      if (current) current.push(line);
    }
    if (current) parts.push(current);
    return parts.map(lines => lines.join('\r\n'));
  }

  class MimeParser {
    parse(email) {
      this.count = 0;
      return this.parsePart(headerFields(email.rawHeaders), email.body, Boolean(email.wireBytes), 0, 'text/plain');
    }

    parsePart(fields, body, wire, depth, defaultType) {
      const field = name => fields.find(entry => entry.name === name)?.value;
      const type = headerParams(field('content-type') || defaultType);
      const disposition = headerParams(field('content-disposition') || '');
      const encoding = (field('content-transfer-encoding') || '7bit').trim().toLowerCase();
      const rawName = disposition.params.filename || type.params.name || null;
      const part = {
        contentType: type.value || defaultType, charset: type.params.charset || null, disposition: disposition.value || null,
        filename: rawName ? decodeMimeWords(rawName) : null, contentId: field('content-id')?.replace(/^<|>$/g, '') || null,
        encoding, size: 0, children: [], text: null
      };
      this.count++;
      if (part.contentType.startsWith('multipart/') && type.params.boundary && depth < 20 && this.count < 500) {
        const childDefault = part.contentType === 'multipart/digest' ? 'message/rfc822' : 'text/plain';
        for (const chunk of splitMultipart(body, type.params.boundary)) {
          const split = chunk.match(/\r?\n\r?\n/);
          const headerBlock = chunk.startsWith('\r\n') || chunk.startsWith('\n') || !split ? '' : chunk.slice(0, split.index);
          const childBody = headerBlock ? chunk.slice(split.index + split[0].length) : chunk.replace(/^\r?\n/, '');
          part.children.push(this.parsePart(headerFields(headerBlock), childBody, wire, depth + 1, childDefault));
        }
        part.size = part.children.reduce((sum, child) => sum + child.size, 0);
        return part;
      }
      const decoded = decodeTransfer(body, encoding, wire);
      part.size = decoded.bytes.length;
      if (part.contentType.startsWith('text/') && part.disposition !== 'attachment') {
        part.text = decoded.text ?? decodeCharset(decoded.bytes, part.charset || 'utf-8');
      }
      return part;
    }

    // Leaf parts in order, each with whether it's an attachment rather than message text.
    flatten(part, out = []) {
      if (part.children.length) {
        for (const child of part.children) this.flatten(child, out);
      } else {
        const isText = part.text !== null && !part.filename;
        out.push({ ...part, attachment: !isText });
      }
      return out;
    }
  }

  // --- Header insights: what a header is for, how to group them, spam verdicts and warning signs ---
  const HeaderInsights = (() => {
    // RFC 5322 allows at most one of each of these.
    const singletons = ['from', 'sender', 'reply-to', 'to', 'cc', 'bcc', 'subject', 'date', 'message-id', 'in-reply-to', 'references'];
    const spamHeader = /^(x-ms-exchange-organization-scl|x-microsoft-antispam(-mailbox-delivery)?|x-forefront-antispam-report|x-spam-[a-z-]+|x-ham-report|x-gmail-labels)$/;

    const groups = [
      { id: 'people', title: 'Sender and recipients', match: name => /^(from|sender|reply-to|to|cc|bcc|return-path|delivered-to|x-original-to|envelope-to|resent-[a-z-]+)$/.test(name) },
      { id: 'message', title: 'Message', match: name => /^(subject|date|message-id|in-reply-to|references|thread-topic|thread-index|importance|x-priority|priority|sensitivity|content-[a-z-]+|mime-version|accept-language|organization|x-entity-ref-id)$/.test(name) },
      { id: 'auth', title: 'Authentication', match: name => /^(dkim-signature|arc-[a-z-]+|authentication-results(-original)?|received-spf|x-google-dkim-signature|bimi-[a-z-]+|x-original-authentication-results)$/.test(name) },
      { id: 'spam', title: 'Spam filter verdicts', match: name => spamHeader.test(name) },
      { id: 'route', title: 'Route', match: name => /^(received|x-received|x-originating-ip|x-sender-ip|x-forwarded-to|x-forwarded-for)$/.test(name) },
      { id: 'list', title: 'Mailing list and bulk mail', match: name => /^(list-[a-z-]+|precedence|feedback-id|x-feedback-id|auto-submitted|x-auto-response-suppress|x-report-abuse(-to)?|x-complaints-to|x-csa-complaints|x-abuse[a-z-]*)$/.test(name) },
      { id: 'service', title: 'Sending software and service', match: name => /^(x-mailer|user-agent|x-mailgun-[a-z-]+|x-sg-[a-z-]+|x-ses-[a-z-]+|x-sfmc-[a-z-]+|x-job|x-mc-[a-z-]+|x-mandrill-[a-z-]+|x-pm-[a-z-]+|x-sid-[a-z-]+|x-campaign[a-z-]*|x-hs-[a-z-]+|x-klaviyo-[a-z-]+|x-sender-id|x-sendgrid-[a-z-]+)$/.test(name) },
      { id: 'microsoft', title: 'Microsoft Exchange internals', folded: true, match: name => /^x-(ms|microsoft|forefront)-|^x-incomingtopheadermarker$|^x-eoptenantattributedmessage$/.test(name) },
      { id: 'google', title: 'Google internals', folded: true, match: name => /^x-(gm|google)-/.test(name) },
      { id: 'other', title: 'Other', match: () => true }
    ];

    function category(name) {
      return groups.find(group => group.match(String(name).toLowerCase())).id;
    }

    const notes = {
      'from': 'The author shown to you. DMARC checks this domain.',
      'sender': 'Who actually sent it on the author\'s behalf, such as an assistant or a mailing list.',
      'reply-to': 'Where replies go, if not to From.',
      'to': 'Recipients as written by the sender. The addresses it was actually delivered to can differ.',
      'cc': 'Copied recipients as written by the sender.',
      'bcc': 'Hidden recipients. Normally removed before delivery.',
      'subject': 'The subject line.',
      'date': 'When the sender\'s software says the message was written.',
      'message-id': 'A unique ID the sending system gave the message.',
      'in-reply-to': 'The message this replies to, used for threading.',
      'references': 'Earlier messages in the conversation, used for threading.',
      'return-path': 'The envelope sender (bounce address), added at delivery. SPF checks its domain.',
      'delivered-to': 'The mailbox the message was delivered to.',
      'x-original-to': 'The address the message was originally sent to, before forwarding or aliases.',
      'envelope-to': 'The envelope recipient at delivery.',
      'received': 'One relay hop, added by the server that accepted the message.',
      'x-received': 'An internal step inside the provider, such as between Google\'s servers.',
      'x-originating-ip': 'The address of the sender\'s device or webmail session, if the provider records it.',
      'dkim-signature': 'A domain\'s signature over chosen headers and the body.',
      'x-google-dkim-signature': 'Google\'s internal signature. Other receivers don\'t use it for DKIM.',
      'authentication-results': 'What a receiving server concluded about SPF, DKIM and DMARC.',
      'authentication-results-original': 'Results recorded before the message was forwarded.',
      'received-spf': 'The SPF result recorded by a receiving server.',
      'arc-seal': 'ARC: a forwarding server\'s seal over the ARC sets so far.',
      'arc-message-signature': 'ARC: a forwarding server\'s signature of the message, like DKIM.',
      'arc-authentication-results': 'ARC: the authentication results a server recorded, preserved for later servers.',
      'bimi-selector': 'Which BIMI record (brand logo) the sender wants used.',
      'bimi-location': 'The brand logo location a receiver found for this message.',
      'mime-version': 'Marks the message as MIME formatted.',
      'content-type': 'How the body is structured: plain text, HTML, attachments.',
      'content-transfer-encoding': 'How the body is encoded for transport.',
      'content-language': 'The language of the message.',
      'thread-topic': 'Outlook conversation threading.',
      'thread-index': 'Outlook conversation threading.',
      'importance': 'Priority set by the sender.',
      'x-priority': 'Priority set by the sender.',
      'list-unsubscribe': 'The address or link a mail client\'s Unsubscribe button uses.',
      'list-unsubscribe-post': 'Enables one-click unsubscribe (RFC 8058).',
      'list-id': 'Identifies the mailing list.',
      'precedence': 'Marks bulk or list mail, so auto-replies skip it.',
      'feedback-id': 'Lets mailbox providers report spam complaints to the sender per campaign.',
      'x-feedback-id': 'Lets mailbox providers report spam complaints to the sender per campaign.',
      'auto-submitted': 'Marks automatically generated mail.',
      'x-auto-response-suppress': 'Asks Exchange not to send automatic replies.',
      'x-mailer': 'The software that wrote the message.',
      'user-agent': 'The software that wrote the message.',
      'x-ms-exchange-organization-scl': 'Microsoft\'s spam score for your mailbox: -1 means not scanned, 0 to 1 not spam, 5 and above spam.',
      'x-microsoft-antispam': 'Microsoft\'s filter details. BCL is the bulk level, 0 to 9.',
      'x-microsoft-antispam-mailbox-delivery': 'Where Microsoft delivered the message: dest:I is the Inbox, dest:J is Junk.',
      'x-forefront-antispam-report': 'Microsoft\'s filter report: SFV is the verdict, CAT the category, CIP the sending IP.',
      'x-spam-status': 'A spam filter\'s verdict and score, usually SpamAssassin.',
      'x-spam-flag': 'A spam filter\'s yes or no verdict.',
      'x-spam-score': 'A spam filter\'s score.',
      'x-incomingtopheadermarker': 'Microsoft internal marker.',
      'x-gmail-labels': 'Gmail labels, added by a Google Takeout export. "Spam" means Gmail filed it in Spam.'
    };

    function describe(name) {
      const key = String(name).toLowerCase();
      if (notes[key]) return notes[key];
      if (/^x-(microsoft|forefront)-.*-untrusted$/.test(key)) return 'Copied from the sending organization\'s own Microsoft system, so it says nothing about your mailbox.';
      if (/^x-ms-exchange-crosstenant-/.test(key)) return 'Microsoft 365 routing between organizations.';
      if (/^x-ms-exchange-organization-/.test(key)) return 'Set by Microsoft Exchange for the receiving organization.';
      if (/^x-(ms|microsoft)-/.test(key)) return 'Microsoft Exchange internal data.';
      if (/^x-(gm|google)-/.test(key)) return 'Google internal data.';
      if (/^list-/.test(key)) return 'Mailing list information.';
      if (/^content-/.test(key)) return 'Describes the body\'s format.';
      if (/^x-spam-/.test(key)) return 'Written by a spam filter, usually SpamAssassin.';
      const services = [[/^x-mailgun-/, 'Mailgun'], [/^x-sg-|^x-sendgrid-/, 'SendGrid'], [/^x-ses-/, 'Amazon SES'], [/^x-sfmc-/, 'Salesforce Marketing Cloud'],
        [/^x-mc-|^x-mandrill-/, 'Mailchimp'], [/^x-pm-/, 'Postmark'], [/^x-hs-/, 'HubSpot'], [/^x-klaviyo-/, 'Klaviyo']];
      const service = services.find(([pattern]) => pattern.test(key));
      if (service) return `Sending details from ${service[1]}.`;
      return null;
    }

    function semicolonTags(value) {
      const tags = {};
      for (const part of String(value).split(';')) {
        const colon = part.indexOf(':');
        if (colon > 0) tags[part.slice(0, colon).trim().toUpperCase()] = part.slice(colon + 1).trim();
      }
      return tags;
    }

    const sfvVerdicts = {
      NSPM: ['Not spam', 'pass'], SPM: ['Spam', 'fail'], SKN: ['Marked safe before filtering', 'neutral'], SKA: ['Allowed sender', 'neutral'],
      SKB: ['Blocked sender', 'fail'], SKI: ['Internal message', 'neutral'], SKQ: ['Released from quarantine', 'neutral'],
      SKS: ['Marked spam before filtering', 'fail'], SFE: ['On your safe senders list', 'neutral'], BLK: ['On your blocked senders list', 'fail']
    };
    const categories = {
      BULK: 'Bulk', DIMP: 'Domain impersonation', GIMP: 'Impersonation', HPHSH: 'High-confidence phishing', HSPM: 'High-confidence spam',
      MALW: 'Malware', PHSH: 'Phishing', SPM: 'Spam', SPOOF: 'Spoofing', UIMP: 'User impersonation', OSPM: 'Outbound spam', INTOS: 'Internal phishing'
    };

    // The receiving provider's spam verdicts, from the headers it adds. Microsoft's "-Untrusted" copies come from the
    // sending organization and are only listed, never used.
    function spamVerdicts(fields) {
      const value = key => fields.find(field => field.key === key)?.value?.trim();
      const items = [];
      let provider = null;
      const scl = value('x-ms-exchange-organization-scl');
      if (scl !== undefined && /^-?\d+$/.test(scl)) {
        provider = 'Microsoft';
        const level = Number(scl);
        const [label, tone] = level < 0 ? ['Not scanned', 'neutral'] : level <= 1 ? ['Not spam', 'pass'] : level <= 4 ? ['Low spam score', 'neutral']
          : level <= 6 ? ['Spam', 'fail'] : ['High-confidence spam', 'fail'];
        items.push({ label, tone, detail: `SCL ${level}`, title: level < 0 ? 'Spam confidence level -1: filtering was skipped, usually for trusted or internal senders'
          : `Spam confidence level ${level} (0 to 1 is not spam, 5 and above is spam)` });
      }
      const report = value('x-forefront-antispam-report');
      if (report) {
        provider = 'Microsoft';
        const tags = semicolonTags(report);
        const verdict = sfvVerdicts[(tags.SFV || '').toUpperCase()];
        if (verdict && scl === undefined) items.push({ label: verdict[0], tone: verdict[1], detail: `SFV:${tags.SFV}`, title: 'Microsoft spam filter verdict' });
        const category = (tags.CAT || '').toUpperCase();
        if (category && category !== 'NONE') {
          items.push({ label: categories[category] || category, tone: category === 'BULK' ? 'neutral' : 'fail', detail: `CAT:${category}`, title: 'The category Microsoft\'s filter assigned' });
        }
      }
      const bcl = value('x-microsoft-antispam')?.match(/(?:^|;)\s*BCL:(\d)\b/i)?.[1];
      if (bcl !== undefined) {
        provider = 'Microsoft';
        const level = Number(bcl);
        items.push({ label: level === 0 ? 'Not bulk' : `Bulk level ${level}`, tone: level >= 8 ? 'fail' : level >= 4 ? 'warn' : 'neutral',
          detail: level === 0 ? 'BCL 0' : level <= 3 ? 'few complaints' : level <= 7 ? 'some complaints' : 'many complaints',
          title: `Bulk complaint level ${level} of 9: how often mail from this bulk sender draws complaints` });
      }
      const destination = value('x-microsoft-antispam-mailbox-delivery')?.match(/(?:^|;)\s*dest:([A-Z])\b/i)?.[1]?.toUpperCase();
      if (destination) {
        provider = 'Microsoft';
        items.push(destination === 'I' ? { label: 'Delivered to Inbox', tone: 'pass', detail: 'dest:I', title: 'Microsoft put the message in the Inbox' }
          : destination === 'J' ? { label: 'Delivered to Junk', tone: 'fail', detail: 'dest:J', title: 'Microsoft put the message in the Junk folder' }
          : { label: `Folder ${destination}`, tone: 'neutral', detail: `dest:${destination}`, title: 'Where Microsoft delivered the message' });
      }
      const status = value('x-spam-status');
      const flag = value('x-spam-flag');
      if (status || flag) {
        provider = provider || 'Spam filter';
        const spam = /^yes\b/i.test(status || flag);
        const score = status?.match(/\bscore=(-?[\d.]+)/i)?.[1];
        const required = status?.match(/\brequired=(-?[\d.]+)/i)?.[1];
        items.push({ label: spam ? 'Spam' : 'Not spam', tone: spam ? 'fail' : 'pass', detail: score ? `score ${score}${required ? ` of ${required}` : ''}` : '',
          title: 'X-Spam-Status, usually from SpamAssassin. Any server on the way could have added it.' });
      }
      // Gmail doesn't write its spam decision into the message; a Google Takeout export adds the message's labels.
      const labels = (value('x-gmail-labels') || '').split(',').map(label => label.trim().toLowerCase());
      if (labels.includes('spam')) {
        provider = provider || 'Gmail';
        items.push({ label: 'In Spam', tone: 'fail', detail: 'X-Gmail-Labels', title: 'Gmail filed the message in Spam (label from a Google Takeout export)' });
      }
      const untrusted = fields.filter(field => /^x-(microsoft|forefront)-.*-untrusted$/.test(field.key)).map(field => field.name || field.key);
      return items.length ? { provider, items, untrusted } : null;
    }

    // Signs that a header was added to mislead: repeated single-use headers, and receiver results written where only the sender writes.
    function anomalies(fields, { covered = new Set(), delivery = null } = {}) {
      const issues = [];
      for (const key of singletons) {
        const copies = fields.filter(field => field.key === key);
        if (copies.length < 2) continue;
        const name = copies[0].name || key;
        const signed = copies.filter(field => covered.has(field.key + ':' + field.instance)).length;
        issues.push({ kind: 'duplicate', key, indexes: copies.map(field => field.index),
          message: signed && signed < copies.length
            ? `There are ${copies.length} ${name} headers and only ${signed === 1 ? 'one is' : `${signed} are`} signed. A mail client may show you the unsigned one.`
            : `There are ${copies.length} ${name} headers, where a message should have one. Mail clients may show a different one than the checks used.` });
      }
      for (const record of delivery?.records || []) {
        if (!record.suspicious) continue;
        const name = fields.find(field => field.index === record.index)?.name || record.name;
        issues.push({ kind: 'forged-results', key: record.name, indexes: [record.index],
          message: `${/^[aeiou]/i.test(name) ? 'An' : 'A'} ${name} header naming ${record.server} may be forged. ${DeliveryRecords.explain(record)}` });
      }
      for (const hop of delivery?.forgedHops || []) {
        issues.push({ kind: 'forged-hop', key: 'received', indexes: [hop.index],
          message: `A Received header claims ${hop.by} handled the message before ${hop.entryFrom} handed it to ${hop.entryBy}. That can't happen, so the sender wrote it.` });
      }
      return issues;
    }

    return { singletons, groups, category, describe, spamVerdicts, anomalies };
  })();

  const exports = { EmailDTO, EmailParser, parseEmail, decodeMimeWords, EmailAddress, IpAddress, parseMailDate, MimeParser, HeaderInsights, DeliveryRecords, RelayDTO, RelayParser, ServerValidationDTO, ServerValidationParser };

  if (dkimModule) {
    Object.assign(exports, dkimModule);
  }

  return exports;
}));
