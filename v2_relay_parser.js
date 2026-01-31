(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    const modules = factory();
    root.RelayParser = modules.RelayParser;
    root.RelayDTO = modules.RelayDTO;
  }
}(typeof self !== 'undefined' ? self : this, function() {

  class HopDTO {
    constructor() {
      this.from = null;
      this.by = null;
      this.with = null;
      this.date = null;
      this.timestamp = 0;
      this.ip = null;
      this.delay = null; // Seconds since previous hop (which is next in the list)
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
      
      // Headers are typically Top (Latest) -> Bottom (Earliest)
      headers.forEach(header => {
        if (typeof header !== 'string') return;
        const hop = new HopDTO();
        hop.fullHeader = header;
        
        // Normalize whitespace
        const cleanHeader = header.replace(/\s+/g, ' ');

        // Extract Date (usually after the last semicolon)
        const dateMatch = header.match(/;\s*([^;]+)$/);
        if (dateMatch) {
            hop.date = dateMatch[1].trim();
            const ts = Date.parse(hop.date);
            if (!isNaN(ts)) {
                hop.timestamp = ts;
            }
        }

        // Extract 'from'
        const fromMatch = cleanHeader.match(/from\s+([^\s]+)/i);
        if (fromMatch) hop.from = fromMatch[1].replace(/;$/, '');

        // Extract IP
        const ipMatch = cleanHeader.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/) || 
                        cleanHeader.match(/\[(IPv6:[a-fA-F0-9:]+)\]/);
        if (ipMatch) hop.ip = ipMatch[1];

        // Extract 'by'
        const byMatch = cleanHeader.match(/by\s+([^\s]+)/i);
        if (byMatch) hop.by = byMatch[1].replace(/;$/, '');

        // Extract 'with'
        const withMatch = cleanHeader.match(/with\s+([^\s]+)/i);
        if (withMatch) hop.with = withMatch[1].replace(/;$/, '');

        dto.hops.push(hop);
      });

      // Calculate delays
      // hops[0] is latest. hops[1] is previous in time.
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

  return { RelayParser, RelayDTO };
}));