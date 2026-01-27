# Manual SPF Verification Guide

This guide walks through manually verifying SPF (Sender Policy Framework) authentication for an email.

## Prerequisites

You need one of these DNS lookup tools:
- `dig` (recommended, available on macOS/Linux)
- `nslookup` (available on all platforms)
- `host` (available on most Linux distributions)

## Step 1: Extract Key Information from Email Headers

From the email headers, identify:

### Envelope From (Return-Path)
```
Return-Path: <CustomerExperience@cxfocus.amexgbt.com>
```
**Domain to check:** `cxfocus.amexgbt.com`

### Sending Server IP
```
Received: from smtp-253-55.pdx1.qemailserver.com (smtp-253-55.pdx1.qemailserver.com. [98.97.253.55])
        by mx.google.com ...
```
**IP to verify:** `98.97.253.55`

### Existing SPF Result (for comparison)
```
Received-SPF: pass (google.com: domain of customerexperience@cxfocus.amexgbt.com designates 98.97.253.55 as permitted sender) client-ip=98.97.253.55;
```

---

## Step 2: Look Up the SPF Record

Query the TXT records for the envelope-from domain:

```bash
dig TXT cxfocus.amexgbt.com +short
```

Alternative using nslookup:
```bash
nslookup -type=TXT cxfocus.amexgbt.com
```

Alternative using host:
```bash
host -t TXT cxfocus.amexgbt.com
```

**What to look for:** A TXT record starting with `v=spf1`

---

## Step 3: Parse SPF Mechanisms

SPF records contain mechanisms that define authorized senders. Common mechanisms:

| Mechanism | Description | Example |
|-----------|-------------|---------|
| `ip4:` | Authorized IPv4 address or range | `ip4:98.97.253.55` or `ip4:98.97.253.0/24` |
| `ip6:` | Authorized IPv6 address or range | `ip6:2001:db8::/32` |
| `include:` | Include another domain's SPF | `include:_spf.google.com` |
| `a:` | Authorize the domain's A record IPs | `a:mail.example.com` |
| `mx:` | Authorize the domain's MX record IPs | `mx` |
| `all` | Match all (with qualifier) | `-all` (fail others) |

### Qualifiers
- `+` (pass) - default if not specified
- `-` (fail) - reject if matched
- `~` (softfail) - accept but mark
- `?` (neutral) - no policy

---

## Step 4: Recursively Resolve `include:` Mechanisms

For each `include:` found, look up that domain's SPF record:

```bash
# If the SPF record contains include:_spf.qemailserver.com
dig TXT _spf.qemailserver.com +short
```

```bash
# If it contains include:spf.protection.outlook.com
dig TXT spf.protection.outlook.com +short
```

Keep following includes until you find IP addresses or ranges.

---

## Step 5: Verify the Sending IP is Authorized

Check if `98.97.253.55` falls within any authorized IP ranges.

### Check if IP is in a CIDR range

For a range like `98.97.253.0/24`:
- `/24` means first 24 bits (first 3 octets) must match
- `98.97.253.0/24` covers `98.97.253.0` - `98.97.253.255`
- `98.97.253.55` **is within** this range ✓

### Verify reverse DNS (PTR record)

```bash
dig -x 98.97.253.55 +short
```

Expected output: `smtp-253-55.pdx1.qemailserver.com.`

### Verify forward DNS matches

```bash
dig A smtp-253-55.pdx1.qemailserver.com +short
```

Expected output: `98.97.253.55`

---

## Step 6: Check Parent Domain SPF

For context, check the main domain's SPF:

```bash
dig TXT amexgbt.com +short
```

---

## Step 7: Verify DMARC Policy

DMARC ties SPF and DKIM together. Check the DMARC record:

```bash
dig TXT _dmarc.amexgbt.com +short
```

**DMARC alignment for SPF:** The domain in the `From:` header (`amexgbt.com`) must align with the envelope-from domain (`cxfocus.amexgbt.com`). Since `cxfocus.amexgbt.com` is a subdomain of `amexgbt.com`, this passes **relaxed alignment**.

---

## Complete Example: One-Liner

Run all lookups at once:

```bash
echo "=== SPF for cxfocus.amexgbt.com ===" && \
dig TXT cxfocus.amexgbt.com +short && \
echo "" && \
echo "=== SPF for amexgbt.com ===" && \
dig TXT amexgbt.com +short && \
echo "" && \
echo "=== DMARC for amexgbt.com ===" && \
dig TXT _dmarc.amexgbt.com +short && \
echo "" && \
echo "=== Reverse DNS for 98.97.253.55 ===" && \
dig -x 98.97.253.55 +short
```

---

## Example Verification Walkthrough

### Given:
- **Envelope-From:** `CustomerExperience@cxfocus.amexgbt.com`
- **Sending IP:** `98.97.253.55`
- **From Header:** `CustomerExperience@cxfocus.amexgbt.com` (domain: `amexgbt.com`)

### Verification Steps:

1. Look up SPF for `cxfocus.amexgbt.com`
2. Follow any `include:` mechanisms
3. Find IP ranges that contain `98.97.253.55`
4. If found → **SPF PASS**
5. Check DMARC alignment (subdomain aligns with parent in relaxed mode)
6. If aligned → **DMARC PASS** (for SPF portion)

---

## Troubleshooting

### No SPF record found
```bash
# Check if domain exists
dig A cxfocus.amexgbt.com +short

# Check for CNAME that might redirect
dig CNAME cxfocus.amexgbt.com +short
```

### Multiple TXT records
Filter for SPF only:
```bash
dig TXT cxfocus.amexgbt.com +short | grep "v=spf1"
```

### DNS propagation issues
Try different DNS servers:
```bash
# Google DNS
dig TXT cxfocus.amexgbt.com @8.8.8.8 +short

# Cloudflare DNS
dig TXT cxfocus.amexgbt.com @1.1.1.1 +short
```

---

## References

- [RFC 7208 - SPF Specification](https://tools.ietf.org/html/rfc7208)
- [RFC 7489 - DMARC Specification](https://tools.ietf.org/html/rfc7489)
- [SPF Record Syntax](http://www.open-spf.org/SPF_Record_Syntax/)
