(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const parser = require('./v2_email_parser');
    module.exports = factory(require('./v2_dns'), parser.EmailAddress, parser.DeliveryRecords, parser.ServerValidationParser);
  } else {
    Object.assign(root, factory(root.EmailDns, root.EmailAddress, root.DeliveryRecords, root.ServerValidationParser));
  }
}(typeof self !== 'undefined' ? self : this, function (dns, address, delivery, ResultsParser) {
  class DmarcDTO {
    constructor(domain) {
      this.domain = domain;
      this.record = null;
      this.tags = {};
      this.dnsCommand = null;
      this.rawDns = null;
      this.result = 'none';
      this.spfAlignment = 'unavailable';
      this.dkimAlignment = 'unavailable';
      this.error = null;
      this.fetchedDomain = null;
      this.spfAuthDomain = null;
      this.spfFromHeaders = false;
      this.passedBy = [];
      this.expiredAlignedDkim = [];
      this.reported = null;
      this.checks = [];
      // Every _dmarc question asked, in order: { purpose: 'policy' | 'organization', type, name, records, error }.
      this.operations = [];
    }
  }

  // The DMARC verdict the topmost receiving server recorded for this author domain, if any. Only records the
  // Received chain ties to a receiving server count; a sender can write its own.
  function reportedDmarc(email, domain) {
    const parser = new ResultsParser();
    for (const record of delivery.assess(email).trusted('authentication-results')) {
      const header = parser.parseOne(record.value);
      for (const entry of header.results) {
        if (entry.method !== 'dmarc') continue;
        const headerFrom = entry.props['header.from'];
        if (headerFrom && dns.normalizeName(headerFrom) !== dns.normalizeName(domain)) continue;
        return { result: entry.result, authServId: header.service };
      }
    }
    return null;
  }

  class DmarcValidator {
    queryDns(name, type) {
      return dns.lookup(name, type);
    }

    async lookupPolicy(domain, cache) {
      if (!cache.has(domain)) {
        cache.set(domain, (async () => {
          const name = '_dmarc.' + domain;
          // A valid author domain can be too long to have a _dmarc child.
          if (!dns.normalizeName(name, true)) return null;
          // A cache that keeps a log records each question for the step-by-step explanation, with why it was asked.
          const entry = cache.log ? { purpose: cache.purpose || 'policy', type: 'TXT', name, records: null, error: null } : null;
          if (entry) cache.log.push(entry);
          let answers;
          try {
            answers = await this.queryDns(name, 'TXT');
          } catch (error) {
            if (entry) entry.error = error.message;
            throw error;
          }
          if (entry) entry.records = answers;
          const records = answers.map(rawDns => ({ rawDns, record: dns.txt(rawDns) }))
            .filter(({ record }) => /^[ \t]*v[ \t]*=[ \t]*DMARC1[ \t]*(?:;|$)/.test(record));
          if (records.length !== 1) return null;
          const { tags, error } = dns.parseTags(records[0].record);
          if (error) return null;
          return { ...records[0], tags, fetchedDomain: domain, dnsCommand: 'dig TXT ' + name };
        })());
      }
      return cache.get(domain);
    }

    async treeWalk(domain, cache) {
      const labels = domain.split('.');
      const records = [];
      for (let count = labels.length; count > 0; count = Math.min(count - 1, 7)) {
        const policy = await this.lookupPolicy(labels.slice(-count).join('.'), cache);
        if (!policy) continue;
        records.push(policy);
        if (/^[ny]$/i.test(policy.tags.psd || '')) break;
      }
      return records;
    }

    organizationalDomain(domain, records) {
      for (const record of records) {
        const psd = record.tags.psd?.toLowerCase();
        if (psd === 'n') return record.fetchedDomain;
        if (psd === 'y' && record.fetchedDomain !== domain) {
          return domain.split('.').slice(-(record.fetchedDomain.split('.').length + 1)).join('.');
        }
      }
      return records.at(-1)?.fetchedDomain || domain;
    }

    async fetchDMARC(domain, cache = new Map()) {
      const exact = await this.lookupPolicy(domain, cache);
      if (exact) return exact;
      const records = await this.treeWalk(domain, cache);
      const org = this.organizationalDomain(domain, records);
      return records.find(record => record.fetchedDomain === org) ||
        records.find(record => record.tags.psd?.toLowerCase() === 'y') || null;
    }

    async checkAlignment(authDomain, fromDomain, mode = 'r', cache = new Map()) {
      const authenticated = dns.normalizeName(authDomain);
      const author = dns.normalizeName(fromDomain);
      if (!authenticated || !author) return false;
      if (authenticated === author) return true;
      if (mode.toLowerCase() === 's') return false;
      const [authRecords, authorRecords] = await Promise.all([
        this.treeWalk(authenticated, cache), this.treeWalk(author, cache)
      ]);
      return this.organizationalDomain(authenticated, authRecords) ===
        this.organizationalDomain(author, authorRecords);
    }

    async verify(email, spfResult, dkimResults) {
      // One cache for the verdict and the explanation, so each _dmarc name is looked up once.
      const cache = new Map();
      cache.log = [];
      const dto = await this.evaluate(email, spfResult, dkimResults, cache);
      dto.operations = cache.log;
      if (dto.domain) {
        try {
          dto.checks = await this.describeChecks(dto, spfResult, dkimResults || [], cache);
        } catch {
          // The table is explanatory; the verdict above stands without it.
        }
      }
      return dto;
    }

    // How a signing or envelope domain matches the From domain: exactly, by organizational domain
    // ("relaxed"), only by organizational domain while the policy demands strict, or not at all.
    async matchKind(authDomain, fromDomain, mode, cache) {
      const authenticated = dns.normalizeName(authDomain);
      const author = dns.normalizeName(fromDomain);
      if (!authenticated || !author) return 'unknown';
      if (authenticated === author) return 'exact';
      try {
        if (!await this.checkAlignment(authenticated, author, 'r', cache)) return 'none';
      } catch {
        return 'unknown';
      }
      return (mode || 'r').toLowerCase() === 's' ? 'strict' : 'relaxed';
    }

    // One row per DKIM signature and one for SPF: does the domain match From, did it authenticate,
    // and does it count toward DMARC.
    async describeChecks(dto, spfResult, dkimResults, cache = new Map()) {
      const aligned = match => match === 'exact' || match === 'relaxed';
      const checks = [];
      for (const { dkim, result } of dkimResults) {
        const match = await this.matchKind(dkim.tags.d, dto.domain, dto.tags.adkim, cache);
        const auth = result.valid ? { state: 'pass' }
          : result.status === 'expired' ? { state: 'expired', signatureValid: result.signatureValid ?? null, expires: Number(dkim.tags.x) }
          : result.headersVerified === true ? { state: 'body-changed' }
          : ['temperror', 'unavailable'].includes(result.status) ? { state: result.status, reason: result.error }
          : { state: 'fail', reason: result.error || null };
        checks.push({ kind: 'DKIM', domain: dkim.tags.d || null, selector: dkim.tags.s || null, match, auth, counts: aligned(match) && auth.state === 'pass' });
      }
      if (spfResult) {
        const fromHeaders = spfResult.source === 'headers';
        const result = spfResult.result || 'unavailable';
        const match = spfResult.domain ? await this.matchKind(spfResult.domain, dto.domain, dto.tags.aspf, cache) : 'unknown';
        checks.push({
          kind: 'SPF', domain: spfResult.domain || null, match,
          auth: { state: result === 'pass' && fromHeaders ? 'unconfirmed' : result, ip: spfResult.senderIp || null, ipSource: spfResult.ipSource || null, reason: spfResult.error || null },
          counts: aligned(match) && result === 'pass' && !fromHeaders
        });
      }
      return checks;
    }

    async evaluate(email, spfResult, dkimResults, cache = new Map()) {
      const from = address.getHeader(email.headers, 'From');
      const domains = [...new Set(address.parseMailboxes(from).map(mailbox => mailbox.domain))];
      const dto = new DmarcDTO(domains.length === 1 ? domains[0] : null);
      if (!dto.domain) {
        dto.result = 'unavailable';
        dto.error = 'Expected one From header with a single author domain';
        return dto;
      }
      dto.reported = reportedDmarc(email, dto.domain);
      try {
        cache.purpose = 'policy';
        const record = await this.fetchDMARC(dto.domain, cache);
        // Later questions find organizational domains, to compare the signing and envelope domains with From.
        cache.purpose = 'organization';
        if (!record) {
          dto.dnsCommand = 'dig TXT _dmarc.' + dto.domain;
          return dto;
        }
        Object.assign(dto, record);
        const validPolicy = value => /^(none|quarantine|reject)$/i.test(value || '');
        if (!validPolicy(dto.tags.p) || ['np', 'sp'].some(tag => dto.tags[tag] !== undefined && !validPolicy(dto.tags[tag]))) {
          const hasReportUri = (dto.tags.rua || '').split(',').some(value => {
            try { return Boolean(new URL(value.trim()).pathname); } catch { return false; }
          });
          if (!hasReportUri) {
            dto.result = 'none';
            dto.error = 'The DMARC record has no valid policy';
            return dto;
          }
        }
        const alignment = async (domains, mode, otherResult) => {
          let dnsError = false;
          for (const domain of domains) {
            try {
              if (await this.checkAlignment(domain, dto.domain, mode, cache)) return 'pass';
            } catch {
              dnsError = true;
            }
          }
          return dnsError ? 'temperror' : otherResult;
        };
        const spfChecked = spfResult?.result;
        dto.spfFromHeaders = spfResult?.source === 'headers';
        dto.spfAuthDomain = spfChecked === 'pass' ? spfResult.domain : null;
        const possibleDkim = dkimResults.filter(check => check.result.valid).map(check => check.dkim.tags.d);
        const dkimStatuses = dkimResults.map(check => check.result.status);
        const allExpired = dkimStatuses.length > 0 && dkimStatuses.every(status => status === 'expired');
        const dkimWithoutAlignment = ['temperror', 'unavailable'].find(status => dkimStatuses.includes(status)) ||
          (allExpired ? 'expired' : 'fail');
        [dto.spfAlignment, dto.dkimAlignment] = await Promise.all([
          alignment(dto.spfAuthDomain ? [dto.spfAuthDomain] : [], dto.tags.aspf,
            spfChecked === 'temperror' ? 'temperror' : !spfChecked || spfChecked === 'unavailable' ? 'unavailable' : 'fail'),
          alignment(possibleDkim, dto.tags.adkim, dkimWithoutAlignment)
        ]);
        if (dto.dkimAlignment === 'expired') {
          for (const { dkim, result } of dkimResults) {
            if (!result.signatureValid) continue;
            try {
              if (await this.checkAlignment(dkim.tags.d, dto.domain, dto.tags.adkim, cache)) {
                dto.expiredAlignedDkim.push({ domain: dkim.tags.d, expires: Number(dkim.tags.x) });
              }
            } catch {
              // Alignment is only explanatory here; the verdict is already settled.
            }
          }
        }
        // Display alignment for header-derived inputs while keeping it out of the verified verdict. The envelope
        // domain alone can rule SPF out, though: when it doesn't match From, SPF can't count whatever the session was.
        let verifiedSpfAlignment = dto.spfFromHeaders ? 'unavailable' : dto.spfAlignment;
        if (dto.spfFromHeaders && spfResult.domain) {
          const match = await this.matchKind(spfResult.domain, dto.domain, dto.tags.aspf, cache);
          if (match === 'none' || match === 'strict') verifiedSpfAlignment = 'fail';
        }
        if (verifiedSpfAlignment === 'pass') dto.passedBy.push('SPF');
        if (dto.dkimAlignment === 'pass') dto.passedBy.push('DKIM');
        const outcomes = [verifiedSpfAlignment, dto.dkimAlignment];
        dto.result = dto.passedBy.length ? 'pass' : outcomes.includes('temperror') ? 'temperror' :
          outcomes.includes('unavailable') ? 'unavailable' : 'fail';
      } catch (error) {
        dto.result = 'temperror';
        dto.error = error.message;
      }
      return dto;
    }
  }

  return { DmarcValidator, DmarcDTO };
}));
