(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js
    const dkim = require('./v2_dkim_validator');
    module.exports = factory(dkim);
  } else {
    // Browser globals
    const modules = factory();
    root.EmailDTO = modules.EmailDTO;
    root.EmailParser = modules.EmailParser;
    root.parseEmail = modules.parseEmail;
    root.RelayParser = modules.RelayParser;
    root.RelayDTO = modules.RelayDTO;
    root.ServerValidationParser = modules.ServerValidationParser;
    root.ServerValidationDTO = modules.ServerValidationDTO;
  }
}(typeof self !== 'undefined' ? self : this, function(dkimModule) {

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
    parse(rawText) {
      const match = rawText.match(/\r\n\r\n|\n\n/);
      let rawHeaders = rawText;
      let body = '';

      if (match) {
        rawHeaders = rawText.substring(0, match.index);
        body = rawText.substring(match.index + match[0].length);
      }

      const headers = {};
      const lines = rawHeaders.split(/\r?\n/);
      let currentKey = null;

      for (const line of lines) {
        if (/^\s/.test(line) && currentKey) {
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

            let headerKey = key;
            const lowerKey = key.toLowerCase();
            for (const k of Object.keys(headers)) {
              if (k.toLowerCase() === lowerKey) {
                headerKey = k;
                break;
              }
            }

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

      return new EmailDTO(rawText, rawHeaders, headers, body, []);
    }
  }

  function parseEmail(rawText) {
    return new EmailParser().parse(rawText);
  }

  class HopDTO {
    constructor() {
      this.from = null;
      this.by = null;
      this.with = null;
      this.date = null;
      this.timestamp = 0;
      this.ip = null;
      this.delay = null;
      this.fullHeader = null;
    }
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

        const dateMatch = header.match(/;\s*([^;]+)$/);
        if (dateMatch) {
            hop.date = dateMatch[1].trim();
            const ts = Date.parse(hop.date);
            if (!isNaN(ts)) {
                hop.timestamp = ts;
            }
        }

        const fromMatch = cleanHeader.match(/from\s+([^\s]+)/i);
        if (fromMatch) hop.from = fromMatch[1].replace(/;$/, '');

        const ipMatch = cleanHeader.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/) || 
                        cleanHeader.match(/\[(IPv6:[a-fA-F0-9:]+)\]/);
        if (ipMatch) hop.ip = ipMatch[1];

        const byMatch = cleanHeader.match(/by\s+([^\s]+)/i);
        if (byMatch) hop.by = byMatch[1].replace(/;$/, '');

        const withMatch = cleanHeader.match(/with\s+([^\s]+)/i);
        if (withMatch) hop.with = withMatch[1].replace(/;$/, '');

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

  const exports = { EmailDTO, EmailParser, parseEmail, RelayDTO, RelayParser, ServerValidationDTO, ServerValidationParser };

  if (dkimModule) {
    Object.assign(exports, dkimModule);
  }

  return exports;
}));