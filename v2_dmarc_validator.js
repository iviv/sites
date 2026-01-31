(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js
    const https = require('https');
    module.exports = factory(true, https);
  } else {
    // Browser globals
    const modules = factory(false, window.fetch);
    root.DmarcValidator = modules.DmarcValidator;
    root.DmarcDTO = modules.DmarcDTO;
  }
}(typeof self !== 'undefined' ? self : this, function(isNode, netLib) {

  class DmarcDTO {
    constructor(domain) {
      this.domain = domain;
      this.record = null;
      this.tags = {};
      this.dnsCommand = null;
      this.rawDns = null;
      this.result = 'none'; // pass, fail, none
      this.spfAlignment = 'fail';
      this.dkimAlignment = 'fail';
      this.error = null;
      this.fetchedDomain = null; // The domain where the record was actually found
      this.spfAuthDomain = null;
    }
  }

  class DmarcValidator {
    
    async fetchDMARC(domain) {
      const fetchTxt = (d) => {
        if (!d) return isNode ? Promise.resolve(null) : Promise.resolve(null);
        const dnsCommand = `dig TXT _dmarc.${d}`;
        const handleResponse = (json) => {
          if (json.Status !== 0 || !json.Answer) return null;
          
          let rawData = null;
          const txt = json.Answer.find(r => {
            if (r.type !== 16) return false;
            let d = r.data;
            if (d.startsWith('"')) {
              d = d.replace(/^"|"$/g, '').replace(/" "/g, '').replace(/\\"/g, '"');
            }
            if (d.trim().startsWith('v=DMARC1')) {
              rawData = d;
              return true;
            }
            return false;
          });

          if (!txt || !rawData) return null;
          
          return { record: rawData, rawDns: txt.data, dnsCommand };
        };

        if (isNode) {
          return new Promise((resolve, reject) => {
            const options = {
              hostname: 'cloudflare-dns.com',
              path: `/dns-query?name=_dmarc.${d}&type=TXT`,
              method: 'GET',
              headers: { 'Accept': 'application/dns-json' }
            };
            const req = netLib.request(options, (res) => {
              let data = '';
              res.on('data', (chunk) => data += chunk);
              res.on('end', () => {
                try { resolve(handleResponse(JSON.parse(data))); } catch (e) { resolve(null); }
              });
            });
            req.on('error', () => resolve(null));
            req.end();
          });
        } else {
          const url = `https://cloudflare-dns.com/dns-query?name=_dmarc.${d}&type=TXT`;
          return netLib(url, { headers: { 'Accept': 'application/dns-json' } })
            .then(res => res.json())
            .then(json => handleResponse(json))
            .catch(() => null);
        }
      };

      // 1. Try exact domain
      let result = await fetchTxt(domain);
      if (result) return { ...result, fetchedDomain: domain };

      // 2. Try Organizational Domain (Simplified: last 2 parts)
      const parts = domain.split('.');
      if (parts.length > 2) {
        const orgDomain = parts.slice(-2).join('.');
        result = await fetchTxt(orgDomain);
        if (result) return { ...result, fetchedDomain: orgDomain };
      }

      return { record: null, rawDns: 'No DMARC record found', dnsCommand: `dig TXT _dmarc.${domain}` };
    }

    checkAlignment(authDomain, fromDomain, mode = 'r') {
      if (!authDomain || !fromDomain) return false;
      authDomain = authDomain.toLowerCase();
      fromDomain = fromDomain.toLowerCase();
      mode = (mode || 'r').toLowerCase();

      if (mode === 's') {
        return authDomain === fromDomain;
      } else {
        // Relaxed: Share Organizational Domain
        // Simplified heuristic: match last 2 parts
        const getBase = (d) => {
          const p = d.split('.');
          return p.length >= 2 ? p.slice(-2).join('.') : d;
        };
        return getBase(authDomain) === getBase(fromDomain);
      }
    }

    async verify(email, spfResult, dkimResults) {
      // 1. Get From Domain
      let fromDomain = null;
      if (email.headers['From']) {
        const match = email.headers['From'].match(/@([a-zA-Z0-9.-]+)/);
        if (match) fromDomain = match[1];
      }

      const dto = new DmarcDTO(fromDomain);
      if (!fromDomain) {
        dto.error = 'Could not determine From domain';
        return dto;
      }

      // 2. Fetch Record
      try {
        const fetchRes = await this.fetchDMARC(fromDomain);
        dto.record = fetchRes.record;
        dto.rawDns = fetchRes.rawDns;
        dto.dnsCommand = fetchRes.dnsCommand;
        dto.fetchedDomain = fetchRes.fetchedDomain;

        if (dto.record) {
          const parts = dto.record.split(';');
          for (const part of parts) {
            const trimmed = part.trim();
            if (!trimmed) continue;
            const eqIndex = trimmed.indexOf('=');
            if (eqIndex !== -1) {
              const k = trimmed.substring(0, eqIndex).trim().toLowerCase();
              const v = trimmed.substring(eqIndex + 1).trim();
              dto.tags[k] = v;
            }
          }
        }
      } catch (e) {
        dto.error = e.message;
      }

      // 3. Check Alignment
      // SPF
      const aspf = dto.tags['aspf'] || 'r';
      if (spfResult) {
        dto.spfAuthDomain = spfResult.domain;
        if (spfResult.headerResult === 'pass' && this.checkAlignment(spfResult.domain, fromDomain, aspf)) {
          dto.spfAlignment = 'pass';
        }
      }

      // DKIM
      const adkim = dto.tags['adkim'] || 'r';
      const validDkim = dkimResults.find(r => r.result.valid && this.checkAlignment(r.dkim.tags['d'], fromDomain, adkim));
      if (validDkim) dto.dkimAlignment = 'pass';

      // 4. Final Result
      if (!dto.record) {
        dto.result = 'none';
      } else if (dto.spfAlignment === 'pass' || dto.dkimAlignment === 'pass') {
        dto.result = 'pass';
      } else {
        dto.result = 'fail';
      }

      return dto;
    }
  }

  return { DmarcValidator, DmarcDTO };
}));