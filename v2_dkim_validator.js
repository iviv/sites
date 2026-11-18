(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./v2_dns'), require('node:crypto').webcrypto);
  } else {
    Object.assign(root, factory(root.EmailDns, root.crypto));
  }
}(typeof self !== 'undefined' ? self : this, function (dns, crypto) {
  const algorithms = { 'rsa-sha256': 'rsa', 'ed25519-sha256': 'ed25519' };
  const rsaAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  const fieldName = /^[!-9;-~]+$/;
  const trimWsp = value => value.replace(/^[ \t]+|[ \t]+$/g, '');
  const splitTagList = value => value.replace(/\r\n(?=[ \t])/g, '').split(':').map(trimWsp);

  function decodeBase64(value) {
    const text = value.replace(/[ \t\r\n]/g, '');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) throw new Error('Invalid base64');
    return Uint8Array.from(atob(text), char => char.charCodeAt(0));
  }

  function wireBytes(value, email) {
    return email.wireBytes
      ? Uint8Array.from(value, char => char.charCodeAt(0))
      : new TextEncoder().encode(value);
  }

  // Web Crypto imports RSA keys as SPKI. DKIM also publishes bare PKCS#1 keys.
  function wrapRsaKey(key) {
    function der(tag, data) {
      const size = data.length;
      const length = size < 128 ? [size] : size < 256 ? [0x81, size] : [0x82, size >> 8, size & 255];
      return [tag, ...length, ...data];
    }
    if (key.length > 8192) throw new Error('RSA key is too large');
    const rsaIdentifier = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    return new Uint8Array(der(0x30, [...rsaIdentifier, ...der(0x03, [0, ...key])]));
  }

  class DkimDTO {
    constructor(tags, signedHeaders = [], signatureIndex = null, parseError = null) {
      this.tags = tags;
      this.signedHeaders = signedHeaders;
      this.signatureIndex = signatureIndex;
      this.parseError = parseError;
      this.dnsRaw = null;
      this.publicKey = null;
      this.dnsCommand = null;
      this.dnsTags = null;
    }
  }

  class DkimParser {
    parse(headerValue, signatureIndex = null) {
      const { tags, error } = dns.parseTags(headerValue);
      const headers = tags.h ? splitTagList(tags.h) : [];
      return new DkimDTO(tags, headers, signatureIndex, error);
    }
  }

  class DkimValidator {
    queryDns(name, type) {
      return dns.lookup(name, type);
    }

    canonicalizeBody(body, canonicalization) {
      const normalized = body.replace(/\r?\n/g, '\r\n');
      if (canonicalization === 'simple') {
        let end = normalized.length;
        while (end > 1 && normalized.slice(end - 2, end) === '\r\n') end -= 2;
        return normalized.slice(0, end) + '\r\n';
      }
      const lines = normalized.split('\r\n').map(line => line.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
      while (lines.length && lines.at(-1) === '') lines.pop();
      return lines.length ? lines.join('\r\n') + '\r\n' : '';
    }

    getRawHeaderFields(rawHeaders) {
      const fields = [];
      const counts = new Map();
      let current = null;
      for (const line of rawHeaders.split(/\r?\n/)) {
        if (/^[ \t]/.test(line)) {
          if (current) current.raw += '\r\n' + line;
          continue;
        }
        const colon = line.indexOf(':');
        current = colon > 0 ? { key: trimWsp(line.slice(0, colon)).toLowerCase(), raw: line } : null;
        if (current) {
          current.instance = counts.get(current.key) || 0;
          counts.set(current.key, current.instance + 1);
          fields.push(current);
        }
      }
      return fields;
    }

    canonicalizeHeader(rawField, algorithm) {
      if (algorithm === 'simple') return rawField + '\r\n';
      const colon = rawField.indexOf(':');
      const key = trimWsp(rawField.slice(0, colon)).toLowerCase();
      const value = trimWsp(rawField.slice(colon + 1).replace(/\r\n/g, '').replace(/[ \t]+/g, ' '));
      return key + ':' + value + '\r\n';
    }

    async verifyBodyHash(email, dkim) {
      const expected = dkim.tags.bh;
      if (!expected) return { valid: false, error: 'Missing body hash' };
      const bodyAlgorithm = (dkim.tags.c || 'simple').split('/')[1] || 'simple';
      const bytes = wireBytes(this.canonicalizeBody(email.body, bodyAlgorithm), email);
      const length = dkim.tags.l === undefined ? bytes.length : Number(dkim.tags.l);
      if ((dkim.tags.l !== undefined && !/^\d{1,76}$/.test(dkim.tags.l)) ||
          !Number.isSafeInteger(length) || length > bytes.length) {
        return { valid: false, expected, error: 'Invalid signed body length' };
      }
      const hash = await crypto.subtle.digest('SHA-256', bytes.subarray(0, length));
      const calculated = btoa(String.fromCharCode(...new Uint8Array(hash)));
      return { valid: calculated === expected.replace(/[ \t\r\n]/g, ''), calculated, expected, signedBytes: length, totalBytes: bytes.length };
    }

    async fetchPublicKey(selector, domain) {
      const name = dns.normalizeName(selector + '._domainkey.' + domain, true);
      if (!name) return { error: 'Invalid DKIM DNS name' };
      const dnsCommand = 'dig TXT ' + name;
      let records;
      try {
        records = await this.queryDns(name, 'TXT');
      } catch (error) {
        return { dnsCommand, status: 'temperror', error: 'DNS lookup failed: ' + error.message };
      }
      if (records.length !== 1) return { dnsCommand, error: records.length ? 'Multiple DKIM key records' : 'No DKIM key record' };
      const rawDns = dns.txt(records[0]);
      const { tags: dnsTags, error } = dns.parseTags(rawDns);
      const record = { dnsCommand, rawDns, dnsTags, publicKey: dnsTags.p };
      if (error || !dnsTags.p || (dnsTags.v !== undefined && (dnsTags.v !== 'DKIM1' || Object.keys(dnsTags)[0] !== 'v'))) {
        return { ...record, error: 'Invalid or revoked DKIM key' };
      }
      return record;
    }

    validateSignature(dkim) {
      const { tags, signedHeaders } = dkim;
      if (dkim.parseError) return dkim.parseError;
      if (tags.v !== '1' || ['a', 'b', 'bh', 'd', 'h', 's'].some(tag => !tags[tag])) {
        return 'Missing or invalid required DKIM tag';
      }
      if (!Object.hasOwn(algorithms, tags.a)) return 'Unsupported DKIM algorithm';
      if (tags.c !== undefined && !/^(simple|relaxed)(\/(simple|relaxed))?$/.test(tags.c)) {
        return 'Unsupported DKIM canonicalization';
      }
      if (tags.q !== undefined && !splitTagList(tags.q).includes('dns/txt')) {
        return 'Unsupported DKIM query method';
      }
      if (!signedHeaders.every(name => fieldName.test(name))) return 'Invalid name in the DKIM signed header list';
      if (!signedHeaders.some(name => name.toLowerCase() === 'from')) return 'The From header must be signed';
      const domain = dns.normalizeName(tags.d);
      if (!domain?.includes('.') || !dns.normalizeName(tags.s) || tags.d.endsWith('.') || tags.s.endsWith('.')) {
        return 'Invalid DKIM selector or signing domain';
      }
      if (tags.i !== undefined) {
        const at = tags.i.lastIndexOf('@');
        const identity = at >= 0 ? dns.normalizeName(tags.i.slice(at + 1)) : null;
        if (!identity || (identity !== domain && !identity.endsWith('.' + domain))) return 'Invalid DKIM signing identity';
      }
      if (['t', 'x'].some(tag => tags[tag] !== undefined && !/^\d{1,12}$/.test(tags[tag]))) return 'Invalid DKIM timestamp';
      if (tags.x !== undefined && tags.t !== undefined && Number(tags.x) <= Number(tags.t)) {
        return 'DKIM expiration must be after the signing time';
      }
      return null;
    }

    async verify(email, dkim) {
      const error = this.validateSignature(dkim);
      if (error) return { valid: false, error };
      if (!crypto?.subtle) return { valid: false, status: 'unavailable', error: 'Web Crypto is unavailable' };

      const { tags } = dkim;
      let signature;
      try {
        signature = decodeBase64(tags.b);
        if (decodeBase64(tags.bh).length !== 32) throw new Error('Invalid SHA-256 body hash length');
      } catch (error) {
        return { valid: false, error: error.message };
      }

      // A body that no longer matches still gets its header signature checked: if that verifies, the
      // signer and headers are genuine and only the body changed after signing.
      const bodyHash = await this.verifyBodyHash(email, dkim);
      const bodyError = bodyHash.valid ? null : bodyHash.error || 'Body hash mismatch';

      const rawFields = this.getRawHeaderFields(email.rawHeaders);
      const signatures = rawFields.filter(field => field.key === 'dkim-signature');
      const matches = field => {
        const parsed = dns.parseTags(field.raw.slice(field.raw.indexOf(':') + 1)).tags;
        return Object.keys(parsed).length === Object.keys(tags).length &&
          Object.keys(tags).every(key => parsed[key]?.replace(/\r\n[ \t]+/g, ' ') === tags[key].replace(/\r\n[ \t]+/g, ' '));
      };
      const ownField = dkim.signatureIndex === null ? signatures.find(matches) : signatures[dkim.signatureIndex];
      if (!ownField || !matches(ownField)) return { valid: false, error: 'DKIM signature header could not be matched', bodyHash };
      if (!rawFields.some(field => field.key === 'from')) return { valid: false, error: 'From header is absent', bodyHash };

      const available = rawFields.filter(field => field !== ownField).reverse();
      const signedFields = [];
      for (const name of dkim.signedHeaders) {
        const index = available.findIndex(field => field.key === name.toLowerCase());
        if (index >= 0) signedFields.push(available.splice(index, 1)[0]);
      }
      const headerAlgorithm = (tags.c || 'simple').split('/')[0];
      const splitAt = ownField.raw.indexOf(':') + 1;
      const withoutSignature = ownField.raw.slice(0, splitAt) +
        ownField.raw.slice(splitAt).replace(/(^|;)([ \t\r\n]*b[ \t\r\n]*=)[^;]*/, '$1$2');
      const dataToVerify = signedFields.map(field => this.canonicalizeHeader(field.raw, headerAlgorithm)).join('') +
        this.canonicalizeHeader(withoutSignature, headerAlgorithm).slice(0, -2);
      const details = { dataToVerify, signedHeaders: signedFields.map(({ key, instance }) => ({ key, instance })) };
      const result = { valid: false, bodyHash, details };
      const expired = tags.x !== undefined && Number(tags.x) < Date.now() / 1000;

      const record = await this.fetchPublicKey(tags.s, tags.d);
      Object.assign(dkim, { publicKey: record.publicKey, dnsRaw: record.rawDns, dnsTags: record.dnsTags, dnsCommand: record.dnsCommand });
      if (record.error) result.keyError = record.error;
      // The current DNS record is useful for inspection even after expiration.
      if (record.error) {
        return bodyError ? { ...result, status: 'fail', error: bodyError }
          : expired ? { ...result, status: 'expired', error: 'The DKIM signature has expired' }
          : { ...result, status: record.status, error: record.error };
      }

      const check = await this.checkSignature(record, tags, signature, wireBytes(dataToVerify, email));
      if (bodyError) {
        return { ...result, status: 'fail', error: bodyError, key: check.key, headersVerified: check.status === 'unavailable' ? null : check.valid };
      }
      if (!expired) return { ...result, ...check };
      // An expired signature never passes, but whether it still verifies against the current key
      // separates an old genuine message from one that was altered or forged.
      const signatureValid = check.status === 'unavailable' ? null : check.valid;
      return {
        ...result, status: 'expired', signatureValid, key: check.key,
        error: signatureValid ? 'The DKIM signature verifies against the current DNS key but has expired'
          : signatureValid === false ? 'The DKIM signature has expired and does not verify against the current DNS key' +
            (check.error ? ': ' + check.error : '')
          : 'The DKIM signature has expired'
      };
    }

    async checkSignature(record, tags, signature, data) {
      const keyTags = record.dnsTags;
      const keyType = algorithms[tags.a];
      const services = splitTagList(keyTags.s || '*');
      if ((keyTags.k || 'rsa') !== keyType ||
          (keyTags.h !== undefined && !splitTagList(keyTags.h).includes('sha256')) ||
          (!services.includes('*') && !services.includes('email')) ||
          (splitTagList(keyTags.t || '').includes('s') && tags.i &&
           dns.normalizeName(tags.i.slice(tags.i.lastIndexOf('@') + 1)) !== dns.normalizeName(tags.d))) {
        return { valid: false, error: 'DKIM key restrictions do not permit this signature' };
      }

      try {
        const keyData = decodeBase64(record.publicKey);
        if (keyType === 'rsa') {
          let key;
          try {
            key = await crypto.subtle.importKey('spki', keyData, rsaAlgorithm, false, ['verify']);
          } catch {
            key = await crypto.subtle.importKey('spki', wrapRsaKey(keyData), rsaAlgorithm, false, ['verify']);
          }
          const info = { type: 'rsa', bits: key.algorithm.modulusLength };
          if (info.bits < 1024) return { valid: false, key: info, error: 'DKIM RSA key is shorter than 1024 bits' };
          return { valid: await crypto.subtle.verify(rsaAlgorithm, key, signature, data), key: info };
        }
        const key = await crypto.subtle.importKey('raw', keyData, 'Ed25519', false, ['verify']);
        return { valid: await crypto.subtle.verify('Ed25519', key, signature, await crypto.subtle.digest('SHA-256', data)), key: { type: 'ed25519', bits: 256 } };
      } catch (error) {
        return { valid: false, status: error.name === 'NotSupportedError' ? 'unavailable' : 'fail', error: error.message };
      }
    }
  }

  return { DkimDTO, DkimParser, DkimValidator };
}));
