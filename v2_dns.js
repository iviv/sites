(function (root, factory) {
  const dns = factory();
  if (typeof module === 'object' && module.exports) module.exports = dns;
  else root.EmailDns = dns;
}(typeof self !== 'undefined' ? self : this, function () {
  const endpoint = 'https://cloudflare-dns.com/dns-query';
  const types = { A: 1, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };

  function normalizeName(value, allowUnderscore = false) {
    if (typeof value !== 'string') return null;
    const name = value.replace(/\.$/, '').toLowerCase();
    const label = allowUnderscore ? /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/ : /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
    if (!name || name.length > 253 || name.split('.').some(part => part.length > 63 || !label.test(part))) return null;
    return name;
  }

  function mailboxDomain(value) {
    if (!value || /[\x00-\x20\x7f:/?#@\[\]\\%]/.test(value)) return null;
    try {
      // Use URL's IDNA conversion for internationalized names, after excluding URL syntax.
      const hostname = new URL('https://' + value).hostname;
      const name = normalizeName(hostname);
      return name?.includes('.') && !/^\d+(?:\.\d+){3}$/.test(name) ? name : null;
    } catch {
      return null;
    }
  }

  // Answers (and failures) are kept until clearCache(), which the page calls for each new check, so every
  // panel sees the same answer and a name asked for by several checks is looked up once.
  const cache = new Map();

  function answer(name, type) {
    const key = type + ' ' + normalizeName(name, true);
    if (!cache.has(key)) cache.set(key, query(name, type));
    return cache.get(key);
  }

  function lookup(name, type) {
    // A copy each time, so no caller can change what the others see.
    return answer(name, type).then(result => [...result.records]);
  }

  // False when DNS has no record of the name at all (NXDOMAIN), rather than the name existing without mail records.
  // It reuses the MX question, which the Sender Domain checks ask anyway.
  function exists(name) {
    return answer(name, 'MX').then(result => !result.missing);
  }

  function clearCache() {
    cache.clear();
  }

  async function query(name, type) {
    name = normalizeName(name, true);
    if (!name || !Object.hasOwn(types, type)) throw new Error('Invalid DNS question');
    const url = new URL(endpoint);
    url.search = new URLSearchParams({ name, type });
    const response = await fetch(url, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) throw new Error('DNS HTTP error ' + response.status);
    const data = await response.json();
    // An alias to a missing name still means the name itself exists.
    if (data.Status === 3) return { records: [], missing: !(data.Answer || []).length };
    if (data.Status !== 0 || data.TC) throw new Error('DNS lookup failed for ' + name);
    const answers = data.Answer || [];
    const seen = new Set();
    while (!seen.has(name)) {
      seen.add(name);
      const records = answers.filter(record => normalizeName(record.name, true) === name);
      const matches = records.filter(record => record.type === types[type]);
      if (matches.length) return { records: matches.map(record => record.data), missing: false };
      const alias = records.find(record => record.type === 5);
      if (!alias) return { records: [], missing: false };
      name = normalizeName(alias.data, true);
      if (!name) throw new Error('Invalid DNS alias');
    }
    throw new Error('DNS alias loop');
  }

  function txt(raw) {
    if (!raw.startsWith('"')) return raw;
    const chunks = [...raw.matchAll(/"((?:\\.|[^"\\])*)"/g)];
    return chunks.map(chunk => chunk[1].replace(/\\(\d{3}|.)/g, (_, value) =>
      value.length === 3 ? String.fromCharCode(Number(value)) : value)).join('');
  }

  function parseTags(value) {
    const tags = Object.create(null);
    let error = null;
    const parts = value.split(';');
    if (!parts.at(-1).trim()) parts.pop();
    for (const part of parts) {
      const match = part.match(/^[ \t\r\n]*([a-zA-Z][a-zA-Z0-9_]*)[ \t\r\n]*=([\s\S]*)$/);
      if (!match || Object.hasOwn(tags, match[1])) {
        error = 'Invalid or duplicate tag';
        continue;
      }
      tags[match[1]] = match[2].replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
    }
    return { tags, error };
  }

  return { lookup, exists, clearCache, normalizeName, mailboxDomain, txt, parseTags };
}));
