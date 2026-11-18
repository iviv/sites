(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js
    const dkim = require('./v2_dkim_validator');
    module.exports = factory(require('./v2_dns'), dkim);
  } else {
    // Browser globals
    const modules = factory(root.EmailDns);
    root.EmailDTO = modules.EmailDTO;
    root.EmailParser = modules.EmailParser;
    root.parseEmail = modules.parseEmail;
    root.decodeMimeWords = modules.decodeMimeWords;
    root.EmailAddress = modules.EmailAddress;
    root.IpAddress = modules.IpAddress;
    root.parseMailDate = modules.parseMailDate;
    root.RelayParser = modules.RelayParser;
    root.RelayDTO = modules.RelayDTO;
    root.ServerValidationParser = modules.ServerValidationParser;
    root.ServerValidationDTO = modules.ServerValidationDTO;
  }
}(typeof self !== 'undefined' ? self : this, function(dns, dkimModule) {

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
    }
  }

  class ServerValidationParser {
    parse(headerValue) {
      const dto = new ServerValidationDTO();
      if (!headerValue) return dto;

      const header = Array.isArray(headerValue) ? headerValue[0] : headerValue;
      dto.fullHeader = header;

      const parts = header.split(';').map(p => p.trim()).filter(p => p);

      if (parts.length > 0) {
        dto.service = parts[0];

        for (let i = 1; i < parts.length; i++) {
          const part = parts[i];
          const eqIndex = part.indexOf('=');
          if (eqIndex !== -1) {
            const method = part.substring(0, eqIndex).trim();
            const rest = part.substring(eqIndex + 1).trim();
            
            const spaceIndex = rest.indexOf(' ');
            let result = rest;
            let props = '';
            
            if (spaceIndex !== -1) {
                result = rest.substring(0, spaceIndex);
                props = rest.substring(spaceIndex + 1);
            }
            
            dto.results.push({
                method: method.toLowerCase(),
                result: result.toLowerCase(),
                props: props,
                raw: part
            });
          }
        }
      }
      return dto;
    }
  }

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
        const reversed = ip.v6
          ? ip.words.map(word => word.toString(16).padStart(4, '0')).join('').split('').reverse().join('.') + '.origin6.asn.cymru.com'
          : ip.text.split('.').reverse().join('.') + '.origin.asn.cymru.com';
        const origin = parseCymru((await lookup(reversed, 'TXT'))[0]);
        const asn = origin ? origin[0].split(/\s+/)[0] : null;
        const result = { ip: ip.text, asn, prefix: origin?.[1] || null, country: origin?.[2] || null,
          registry: registryNames[origin?.[3]] || origin?.[3] || null, asName: null, organization: null, network: null, range: null };
        if (asn) {
          const details = parseCymru((await lookup('AS' + asn + '.asn.cymru.com', 'TXT'))[0]);
          // "MAILGUN-US - Mailgun Technologies Inc., US" -> "Mailgun Technologies Inc."
          result.asName = details?.[4]?.replace(/^[^ ]+ - /, '').replace(/, [A-Z]{2}$/, '') || null;
        }
        const base = rdapBases[origin?.[3]];
        if (base) {
          try {
            Object.assign(result, rdapSummary(await getJson(base + encodeURIComponent(ip.text))));
          } catch {
            // The registry is optional; the routing data above still names the network.
          }
        }
        return result.asn || result.organization ? result : null;
      })().catch(() => null);
      if (hooks) return pending;
      ownerCache.set(ip.text, pending);
    }
    return ownerCache.get(ip.text);
  }

  const IpAddress = { parseIpv6, embeddedIpv4, networkOwner, parseCymru, rdapSummary };

  const exports = { EmailDTO, EmailParser, parseEmail, decodeMimeWords, EmailAddress, IpAddress, parseMailDate, RelayDTO, RelayParser, ServerValidationDTO, ServerValidationParser };

  if (dkimModule) {
    Object.assign(exports, dkimModule);
  }

  return exports;
}));
