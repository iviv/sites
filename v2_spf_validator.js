(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js
    const https = require('https');
    module.exports = factory(true, https);
  } else {
    // Browser globals
    const modules = factory(false, window.fetch);
    root.SpfValidator = modules.SpfValidator;
    root.SpfDTO = modules.SpfDTO;
  }
}(typeof self !== 'undefined' ? self : this, function(isNode, netLib) {

  class SpfDTO {
    constructor(domain) {
      this.domain = domain;
      this.record = null;
      this.mechanisms = [];
      this.dnsCommand = null;
      this.rawDns = null;
      this.headerResult = null; // From Authentication-Results
      this.senderIp = null;
      this.error = null;
      this.trace = null; // Recursive evaluation trace
      this.matchChain = null;
    }
  }

  class SpfValidator {
    
    // Generic DNS fetcher
    queryDns(name, type) {
      if (isNode) {
        return new Promise((resolve, reject) => {
          const options = {
            hostname: 'cloudflare-dns.com',
            path: `/dns-query?name=${name}&type=${type}`,
            method: 'GET',
            headers: { 'Accept': 'application/dns-json' }
          };
          const req = netLib.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
              try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
            });
          });
          req.on('error', reject);
          req.end();
        });
      } else {
        const url = `https://cloudflare-dns.com/dns-query?name=${name}&type=${type}`;
        return netLib(url, { headers: { 'Accept': 'application/dns-json' } })
          .then(res => res.json());
      }
    }

    async fetchSPF(domain) {
      const dnsCommand = `dig TXT ${domain}`;
      try {
        const json = await this.queryDns(domain, 'TXT');
        
        if (json.Status !== 0 || !json.Answer) {
          // No answer or error, but might just be no SPF record
          return { record: null, rawDns: 'No TXT record found', dnsCommand };
        }
        
        let rawData = null;
        const spfRecord = json.Answer.find(r => {
          if (r.type !== 16) return false;
          let d = r.data;
          if (d.startsWith('"')) {
            d = d.replace(/^"|"$/g, '').replace(/" "/g, '').replace(/\\"/g, '"');
          }
          if (d.trim().startsWith('v=spf1')) {
            rawData = d;
            return true;
          }
          return false;
        });

        if (!spfRecord || !rawData) {
          return { record: null, rawDns: 'No SPF record found in TXT records', dnsCommand };
        }
        
        return {
          record: rawData,
          rawDns: spfRecord.data,
          dnsCommand
        };
      } catch (e) {
        return { record: null, rawDns: 'DNS Error: ' + e.message, dnsCommand };
      }
    }

    // Helper to convert IPv4 to integer
    ip4ToLong(ip) {
      return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
    }

    // Helper to check CIDR match
    checkCidr(ip, cidr, isIp6) {
      if (isIp6) {
        // Simplified IPv6: Exact match or simple prefix check could be added here
        // For now, just check if the IP starts with the CIDR IP (very basic)
        const [rangeIp] = cidr.split('/');
        return ip === rangeIp; 
      }
      try {
        const [rangeIp, bitsStr] = cidr.split('/');
        const bits = bitsStr ? parseInt(bitsStr, 10) : 32;
        const mask = ~(2 ** (32 - bits) - 1);
        return (this.ip4ToLong(ip) & mask) === (this.ip4ToLong(rangeIp) & mask);
      } catch (e) { return false; }
    }

    // Helper for IPv6 expansion
    expandIp6(ip) {
      let fullIp = ip;
      if (ip.includes('::')) {
        const parts = ip.split('::');
        const left = parts[0] ? parts[0].split(':').filter(Boolean) : [];
        const right = parts[1] ? parts[1].split(':').filter(Boolean) : [];
        const missing = 8 - (left.length + right.length);
        const zeros = Array(Math.max(0, missing)).fill('0000');
        fullIp = [...left, ...zeros, ...right].join(':');
      }
      const groups = fullIp.split(':');
      const nibbles = groups.map(g => g.padStart(4, '0').split('')).flat();
      return nibbles.join('.');
    }

    expandMacros(str, ip, domain, sender) {
      if (!str || !str.includes('%')) return str;
      
      // Helper to split/join/reverse
      const process = (val, digits, reverse, delimiters) => {
        if (!val) return '';
        // Default delimiter is '.'
        const delimRegex = delimiters ? new RegExp(`[${delimiters.replace(/[-[\]/{}()*+?.\\^$|]/g, "\\$&")}]`) : /\./;
        
        let parts = val.split(delimRegex);
        if (reverse) parts.reverse();
        if (digits && digits > 0) parts = parts.slice(-digits);
        return parts.join('.');
      };

      return str.replace(/%\{([a-zA-Z])(\d+)?(r)?([-.+,/_=]*)?\}/g, (match, letter, digits, reverse, delimiters) => {
        let val = '';
        const safeSender = sender || '';
        switch (letter.toLowerCase()) {
          case 'i': val = ip.includes(':') ? this.expandIp6(ip) : ip; break;
          case 's': val = safeSender; break;
          case 'l': val = safeSender.split('@')[0]; break;
          case 'o': val = safeSender.split('@')[1] || safeSender; break;
          case 'd': val = domain; break;
          case 'v': val = ip.includes(':') ? 'ip6' : 'in-addr'; break;
          case 'h': val = domain; break; // Fallback for HELO
          default: return match;
        }
        return process(val, digits, reverse === 'r', delimiters);
      })
      .replace(/%%/g, '%')
      .replace(/%_/g, ' ')
      .replace(/%-/g, '%20');
    }

    async evaluateRecursive(ip, domain, depth = 0, sender = null) {
      if (depth > 10) return { result: 'PermError', reason: 'Max depth exceeded', domain };

      const fetchRes = await this.fetchSPF(domain);
      const node = {
        domain,
        record: fetchRes.record,
        rawDns: fetchRes.rawDns,
        dnsCommand: fetchRes.dnsCommand,
        children: [],
        result: 'None',
        reason: 'No match found',
        matchMechanism: null
      };

      if (!node.record) {
        node.result = 'None';
        node.reason = 'No SPF record found';
        return node;
      }

      const terms = node.record.split(/\s+/).filter(t => t && t !== 'v=spf1');
      const isIp6 = ip.includes(':');
      let redirectDomain = null;

      for (const term of terms) {
        let qualifier = '+';
        let mechanism = term;
        if (/^[-+?~]/.test(term)) {
          qualifier = term[0];
          mechanism = term.substring(1);
        }

        const qualResult = (q) => {
          if (q === '-') return 'Fail';
          if (q === '~') return 'SoftFail';
          if (q === '?') return 'Neutral';
          return 'Pass';
        };

        if (mechanism.startsWith('ip4:') && !isIp6) {
          if (this.checkCidr(ip, mechanism.substring(4), false)) {
            node.result = qualResult(qualifier);
            node.matchMechanism = term;
            node.reason = `Matched IP ${ip} against ${mechanism}`;
            return node;
          }
        } else if (mechanism.startsWith('ip6:') && isIp6) {
          if (this.checkCidr(ip, mechanism.substring(4), true)) {
            node.result = qualResult(qualifier);
            node.matchMechanism = term;
            node.reason = `Matched IP ${ip} against ${mechanism}`;
            return node;
          }
        } else if (mechanism === 'all') {
          node.result = qualResult(qualifier);
          node.matchMechanism = term;
          node.reason = `Hit default '${term}' mechanism`;
          return node;
        } else if (mechanism.startsWith('a') || mechanism.startsWith('mx')) {
          // Parse a/mx mechanism: type[:domain][/cidr]
          const match = mechanism.match(/^(a|mx)(?::([^/]+))?(?:\/(\d+))?$/);
          if (match) {
            const type = match[1];
            let targetDomain = match[2] || domain;
            targetDomain = this.expandMacros(targetDomain, ip, domain, sender);
            const cidr = match[3]; // Optional CIDR override
            
            let ipsToCheck = [];
            
            if (type === 'a') {
              const json = await this.queryDns(targetDomain, 'A');
              if (json.Answer) ipsToCheck = json.Answer.filter(r => r.type === 1).map(r => r.data);
            } else {
              // MX: Fetch MX records, then A records for each
              const mxJson = await this.queryDns(targetDomain, 'MX');
              if (mxJson.Answer) {
                const exchanges = mxJson.Answer.filter(r => r.type === 15).map(r => {
                  // MX data format: "preference exchange"
                  const parts = r.data.split(' ');
                  return parts.length > 1 ? parts[1] : parts[0];
                });
                
                for (const exchange of exchanges) {
                  const aJson = await this.queryDns(exchange, 'A');
                  if (aJson.Answer) ipsToCheck.push(...aJson.Answer.filter(r => r.type === 1).map(r => r.data));
                }
              }
            }

            // Check IPs
            for (const checkIp of ipsToCheck) {
              // If cidr specified, use it, otherwise /32 (exact match)
              const range = cidr ? `${checkIp}/${cidr}` : `${checkIp}/32`;
              if (this.checkCidr(ip, range, isIp6)) {
                node.result = qualResult(qualifier);
                node.matchMechanism = term;
                node.reason = `Matched ${type} record of ${targetDomain} (${checkIp})`;
                return node;
              }
            }
          }
        } else if (mechanism.startsWith('exists:')) {
          let target = mechanism.substring(7);
          target = this.expandMacros(target, ip, domain, sender);
          const json = await this.queryDns(target, 'A');
          if (json.Answer && json.Answer.length > 0) {
            node.result = qualResult(qualifier);
            node.matchMechanism = term;
            node.reason = `Matched 'exists' mechanism (DNS A record found for ${target})`;
            return node;
          }
        } else if (mechanism.startsWith('include:')) {
          let subDomain = mechanism.substring(8);
          subDomain = this.expandMacros(subDomain, ip, domain, sender);
          const subResult = await this.evaluateRecursive(ip, subDomain, depth + 1, sender);
          node.children.push({ type: 'include', val: subDomain, trace: subResult });
          if (subResult.result === 'Pass') {
            node.result = qualResult(qualifier);
            node.matchMechanism = term;
            node.reason = `Matched include:${subDomain}`;
            return node;
          }
        } else if (mechanism.startsWith('redirect=')) {
          redirectDomain = mechanism.substring(9);
          redirectDomain = this.expandMacros(redirectDomain, ip, domain, sender);
        }
      }

      if (redirectDomain) {
        const subResult = await this.evaluateRecursive(ip, redirectDomain, depth + 1, sender);
        node.children.push({ type: 'redirect', val: redirectDomain, trace: subResult });
        node.result = subResult.result;
        node.matchMechanism = `redirect=${redirectDomain}`;
        node.reason = `Followed redirect to ${redirectDomain}`;
        return node;
      }

      node.result = 'Neutral'; // Default if no match and no redirect
      node.reason = 'Defaulted to Neutral (no match)';
      return node;
    }

    getMatchChain(trace) {
      if (!trace) return null;
      const chain = [];
      let current = trace;
      
      while (current) {
        chain.push({
          domain: current.domain,
          mechanism: current.matchMechanism,
          result: current.result
        });

        if (!current.matchMechanism) break;

        const mech = current.matchMechanism.replace(/^[-+?~]/, '');
        let nextDomain = null;

        if (mech.startsWith('include:')) {
          nextDomain = mech.substring(8);
        } else if (mech.startsWith('redirect=')) {
          nextDomain = mech.substring(9);
        }

        if (nextDomain && current.children) {
          const child = current.children.find(c => c.val === nextDomain);
          current = child ? child.trace : null;
        } else {
          current = null;
        }
      }
      return chain;
    }

    async verify(email) {
      // Helper for case-insensitive header lookup
      const getHeader = (name) => {
        const key = Object.keys(email.headers).find(k => k.toLowerCase() === name.toLowerCase());
        return key ? email.headers[key] : null;
      };

      // 1. Determine Domain
      let domain = null;
      let sender = null;
      const returnPath = getHeader('Return-Path');
      if (returnPath) {
        const val = Array.isArray(returnPath) ? returnPath[0] : returnPath;
        sender = val.replace(/[<>]/g, '').trim();
        const parts = sender.split('@');
        if (parts.length > 1) domain = parts[parts.length - 1].trim();
      }
      if (!domain) {
        const fromHeader = getHeader('From');
        if (fromHeader) {
          const val = Array.isArray(fromHeader) ? fromHeader[0] : fromHeader;
          const match = val.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/);
          if (match) {
             sender = match[1];
             const parts = sender.split('@');
             if (parts.length > 1) domain = parts[parts.length - 1];
          }
        }
      }
      if (domain && !sender) sender = `postmaster@${domain}`;

      const dto = new SpfDTO(domain);
      if (!domain) {
        dto.error = 'Could not determine domain from Return-Path or From header';
        return dto;
      }

      // 2. Extract Header Results (Authentication-Results or Received-SPF)
      // This is "what the server thought"
      let authResults = getHeader('Authentication-Results');
      if (Array.isArray(authResults)) {
        authResults = authResults.find(h => h.toLowerCase().includes('spf='));
      }

      let receivedSpf = getHeader('Received-SPF');
      if (Array.isArray(receivedSpf)) {
        receivedSpf = receivedSpf[0];
      }

      if (authResults && authResults.toLowerCase().includes('spf=')) {
        const match = authResults.match(/spf=([a-z]+)/i);
        if (match) dto.headerResult = match[1].toLowerCase();
        
        // Try to find IP in Auth-Results
        const ipMatch = authResults.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
        if (ipMatch) dto.senderIp = ipMatch[1];
      }
      
      if (!dto.headerResult && receivedSpf) {
        const match = receivedSpf.match(/^([a-z]+)/i);
        if (match) dto.headerResult = match[1].toLowerCase();
        
        // Try to find IP in Received-SPF
        const ipMatch = receivedSpf.match(/client-ip=([^;\s)]+)/);
        if (ipMatch) dto.senderIp = ipMatch[1];
      }

      // Fallback: Try to find IP in Received headers
      if (!dto.senderIp) {
        const received = getHeader('Received');
        if (received) {
          const lines = Array.isArray(received) ? received : [received];
          for (const line of lines) {
            // Look for IP in brackets, e.g. [1.2.3.4]
            const match = line.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
            if (match) {
              dto.senderIp = match[1];
              break;
            }
          }
        }
      }

      // 3. Recursive Evaluation
      try {
        if (dto.senderIp) {
          dto.trace = await this.evaluateRecursive(dto.senderIp, domain, 0, sender);
          dto.matchChain = this.getMatchChain(dto.trace);
          dto.record = dto.trace.record;
          dto.rawDns = dto.trace.rawDns;
          dto.dnsCommand = dto.trace.dnsCommand;

          // If no header result was found, use the calculated result
          if (!dto.headerResult && dto.trace.result) {
            dto.headerResult = dto.trace.result.toLowerCase();
          }
        } else {
          // Fallback to simple fetch if no IP
          const result = await this.fetchSPF(domain);
          dto.record = result.record;
          dto.rawDns = result.rawDns;
          dto.dnsCommand = result.dnsCommand;
        }
        if (dto.record) {
            dto.mechanisms = dto.record.split(/\s+/).filter(s => s && s !== 'v=spf1');
        }
      } catch (e) {
        dto.error = e.message;
      }

      return dto;
    }
  }

  return { SpfValidator, SpfDTO };
}));