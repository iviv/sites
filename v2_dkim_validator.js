(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js
    const crypto = require('crypto');
    const https = require('https');
    module.exports = factory(true, crypto, https);
  } else {
    // Browser globals
    const modules = factory(false, window.crypto, window.fetch);
    root.DkimValidator = modules.DkimValidator;
    root.DkimParser = modules.DkimParser;
    root.DkimDTO = modules.DkimDTO;
  }
}(typeof self !== 'undefined' ? self : this, function(isNode, cryptoLib, netLib) {

  /**
   * Data Transfer Object for DKIM signature tags.
   */
  class DkimDTO {
    constructor(tags, signedHeaders = []) {
      this.tags = tags;
      this.signedHeaders = signedHeaders;
      this.dnsRaw = null;
      this.publicKey = null;
      this.dnsCommand = null;
      this.dnsTags = null;
    }
  }

  /**
   * Class responsible for parsing DKIM-Signature headers.
   */
  class DkimParser {
    parse(headerValue) {
      const tags = {};
      const parts = headerValue.split(';');
      for (const part of parts) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex !== -1) {
          const key = trimmed.substring(0, eqIndex).trim();
          const value = trimmed.substring(eqIndex + 1).trim();
          tags[key] = value;
        }
      }

      let signedHeaders = [];
      if (tags.h) {
        signedHeaders = tags.h.split(':').map(h => h.trim());
      }

      return new DkimDTO(tags, signedHeaders);
    }
  }

  /**
   * Class responsible for validating DKIM signatures.
   */
  class DkimValidator {
    canonicalizeBody(body, canonicalization) {
      // Normalize newlines to CRLF
      let normalized = body.replace(/\r?\n/g, '\r\n');

      if (canonicalization === 'simple') {
        // Ignore all empty lines at the end of the message body.
        while (normalized.endsWith('\r\n\r\n')) {
          normalized = normalized.substring(0, normalized.length - 2);
        }
        // If non-empty and no trailing CRLF, add one.
        if (normalized.length > 0 && !normalized.endsWith('\r\n')) {
          normalized += '\r\n';
        }
        return normalized;
      }

      if (canonicalization === 'relaxed') {
        let lines = normalized.split('\r\n');
        
        // Remove last empty element from split if string ends with \r\n
        if (lines.length > 0 && lines[lines.length - 1] === '') {
          lines.pop();
        }

        lines = lines.map(line => {
          // Reduce WSP to single space and ignore WSP at end of line
          return line.replace(/[ \t]+/g, ' ').replace(/[ \t]+$/, '');
        });

        // Ignore empty lines at the end of the message body.
        while (lines.length > 0 && lines[lines.length - 1] === '') {
          lines.pop();
        }

        if (lines.length === 0) return '';

        return lines.join('\r\n') + '\r\n';
      }

      return normalized;
    }

    getRawHeaderFields(rawHeaders) {
      const fields = [];
      const normalized = rawHeaders.replace(/\r?\n/g, '\r\n');
      const lines = normalized.split('\r\n');
      let currentField = null;
      for (const line of lines) {
        if (line === '') continue;
        if (/^[ \t]/.test(line) && currentField) {
          currentField.raw += '\r\n' + line;
        } else {
          if (currentField) fields.push(currentField);
          const colonIdx = line.indexOf(':');
          if (colonIdx !== -1) {
            currentField = { key: line.substring(0, colonIdx).trim(), raw: line };
          } else {
            currentField = null;
          }
        }
      }
      if (currentField) fields.push(currentField);
      return fields;
    }

    canonicalizeHeader(rawField, algo) {
      if (algo === 'simple') return rawField + '\r\n';
      const colonIdx = rawField.indexOf(':');
      const key = rawField.substring(0, colonIdx).toLowerCase().trim();
      let value = rawField.substring(colonIdx + 1).replace(/\r\n/g, '').replace(/[ \t]+/g, ' ').trim();
      return `${key}:${value}\r\n`;
    }

    /**
     * Verifies the body hash of the email against the DKIM signature.
     * @param {EmailDTO} email
     * @param {DkimDTO} dkim
     * @returns {Promise<{valid: boolean, calculated?: string, expected?: string, error?: string}>}
     */
    async verifyBodyHash(email, dkim) {
      const bh = dkim.tags['bh'];
      if (!bh) return { valid: false, error: 'No body hash (bh) tag' };

      const c = dkim.tags['c'] || 'simple/simple';
      const bodyCanonAlgo = c.split('/')[1] || 'simple';
      const canonicalBody = this.canonicalizeBody(email.body, bodyCanonAlgo);

      const a = dkim.tags['a'] || 'rsa-sha256';
      const hashAlgo = a === 'rsa-sha1' ? 'sha1' : 'sha256';
      
      // Handle 'l' tag (length)
      let bodyToHash = canonicalBody;
      if (dkim.tags['l']) {
        const length = parseInt(dkim.tags['l'], 10);
        if (!isNaN(length) && length < canonicalBody.length) {
          bodyToHash = canonicalBody.substring(0, length);
        }
      }

      let calculatedBh;
      if (isNode) {
        calculatedBh = cryptoLib.createHash(hashAlgo).update(bodyToHash).digest('base64');
      } else {
        const algoName = a === 'rsa-sha1' ? 'SHA-1' : 'SHA-256';
        const encoder = new TextEncoder();
        const data = encoder.encode(bodyToHash);
        const hashBuffer = await cryptoLib.subtle.digest(algoName, data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        calculatedBh = btoa(String.fromCharCode.apply(null, hashArray));
      }

      return {
        valid: calculatedBh === bh.replace(/\s/g, ''),
        calculated: calculatedBh,
        expected: bh
      };
    }

    /**
     * Fetches the DKIM public key from DNS (Cloudflare DoH).
     * @param {string} selector
     * @param {string} domain
     * @returns {Promise<{publicKey: string, rawDns: string, dnsCommand: string, dnsTags: Object}>} Object containing public key, raw DNS data, dig command, and parsed tags
     */
    fetchPublicKey(selector, domain) {
      const dnsCommand = `dig TXT ${selector}._domainkey.${domain}`;
      const handleResponse = (json, resolve, reject) => {
        if (json.Status !== 0 || !json.Answer) {
          return reject(new Error(`DNS query failed for ${selector}._domainkey.${domain}`));
        }
        const txtRecord = json.Answer.find(r => r.type === 16);
        if (!txtRecord) return reject(new Error('No TXT record found'));
        
        let rawData = txtRecord.data;
        if (rawData.startsWith('"')) {
          rawData = rawData.replace(/^"|"$/g, '').replace(/" "/g, '').replace(/\\"/g, '"');
        }

        const tags = {};
        rawData.split(';').forEach(part => {
          const trimmed = part.trim();
          const eqIndex = trimmed.indexOf('=');
          if (eqIndex !== -1) {
            const k = trimmed.substring(0, eqIndex).trim();
            const v = trimmed.substring(eqIndex + 1).trim();
            tags[k] = v;
          }
        });

        if (!tags.p) return reject(new Error('No public key (p tag) found'));
        resolve({
          publicKey: tags.p.replace(/\s/g, ''),
          rawDns: rawData,
          dnsCommand: dnsCommand,
          dnsTags: tags
        });
      };

      if (isNode) {
        return new Promise((resolve, reject) => {
          const options = {
            hostname: 'cloudflare-dns.com',
            path: `/dns-query?name=${selector}._domainkey.${domain}&type=TXT`,
            method: 'GET',
            headers: { 'Accept': 'application/dns-json' }
          };
          const req = netLib.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
              try { handleResponse(JSON.parse(data), resolve, reject); } catch (e) { reject(e); }
            });
          });
          req.on('error', reject);
          req.end();
        });
      } else {
        const url = `https://cloudflare-dns.com/dns-query?name=${selector}._domainkey.${domain}&type=TXT`;
        return netLib(url, { headers: { 'Accept': 'application/dns-json' } })
          .then(res => res.json())
          .then(json => new Promise((resolve, reject) => handleResponse(json, resolve, reject)));
      }
    }

    async verify(email, dkim) {
      const bodyHashResult = await this.verifyBodyHash(email, dkim);
      if (!bodyHashResult.valid) {
        return { valid: false, stage: 'body_hash', details: bodyHashResult };
      }

      const s = dkim.tags['s'];
      const d = dkim.tags['d'];
      if (!s || !d) return { valid: false, error: 'Missing selector or domain' };

      let publicKeyBase64;
      try {
        const result = await this.fetchPublicKey(s, d);
        dkim.publicKey = result.publicKey;
        dkim.dnsRaw = result.rawDns;
        dkim.dnsCommand = result.dnsCommand;
        dkim.dnsTags = result.dnsTags;
        publicKeyBase64 = result.publicKey;
      } catch (e) {
        return { valid: false, error: 'DNS Lookup failed: ' + e.message };
      }

      const c = dkim.tags['c'] || 'simple/simple';
      const [headerAlgo] = c.split('/');
      const hTags = dkim.signedHeaders.map(x => x.toLowerCase());
      const rawFields = this.getRawHeaderFields(email.rawHeaders);
      const canonicalizedHeaders = [];
      const fieldsReversed = [...rawFields].reverse();

      for (const headerName of hTags) {
        const idx = fieldsReversed.findIndex(f => f.key.toLowerCase() === headerName);
        if (idx !== -1) canonicalizedHeaders.push(this.canonicalizeHeader(fieldsReversed.splice(idx, 1)[0].raw, headerAlgo));
      }

      const bValue = dkim.tags['b'].replace(/\s/g, '');
      const dkimField = rawFields.find(f => f.key.toLowerCase() === 'dkim-signature' && f.raw.replace(/\s/g, '').includes(`b=${bValue}`));
      if (!dkimField) return { valid: false, error: 'DKIM-Signature header not found in raw headers' };

      const dkimRaw = dkimField.raw.replace(/(\bb\s*=)([^;]*)/, '$1');
      canonicalizedHeaders.push(this.canonicalizeHeader(dkimRaw, headerAlgo).slice(0, -2));

      const dataToVerify = canonicalizedHeaders.join('');

      if (isNode) {
        const publicKey = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64}\n-----END PUBLIC KEY-----`;
        const verify = cryptoLib.createVerify(dkim.tags['a'] === 'rsa-sha1' ? 'RSA-SHA1' : 'RSA-SHA256');
        verify.update(dataToVerify);
        const isValid = verify.verify(publicKey, bValue, 'base64');
        return { valid: isValid, details: { dataToVerify } };
      } else {
        const binaryDerString = atob(publicKeyBase64);
        const binaryDer = new Uint8Array(binaryDerString.length);
        for (let i = 0; i < binaryDerString.length; i++) {
          binaryDer[i] = binaryDerString.charCodeAt(i);
        }
        
        const a = dkim.tags['a'] || 'rsa-sha256';
        const hashAlgo = a === 'rsa-sha1' ? 'SHA-1' : 'SHA-256';

        try {
          const key = await cryptoLib.subtle.importKey(
            "spki",
            binaryDer.buffer,
            { name: "RSASSA-PKCS1-v1_5", hash: hashAlgo },
            false,
            ["verify"]
          );
          
          const encoder = new TextEncoder();
          const data = encoder.encode(dataToVerify);
          const signature = Uint8Array.from(atob(bValue), c => c.charCodeAt(0));
          
          const isValid = await cryptoLib.subtle.verify(
            "RSASSA-PKCS1-v1_5",
            key,
            signature,
            data
          );
          return { valid: isValid, details: { dataToVerify } };
        } catch (e) {
          return { valid: false, error: 'Crypto Verify failed: ' + e.message, details: { dataToVerify } };
        }
      }
    }
  }

  return { DkimDTO, DkimParser, DkimValidator };
}));