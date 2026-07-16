---
name: foundrynet-cyber-intelligence
description: CVE lookup with exploit-probability (EPSS) + CISA KEV, IP/domain threat reputation, and daily threat briefs from the FoundryNet Data Network
---

# FoundryNet Cyber Intelligence

## Connect
```bash
claude mcp add --transport http foundrynet-cyber https://cyber-intel-mcp-production.up.railway.app/mcp
```

## Available Tools
- `cve_detail` (free) — Full CVE detail — NVD description + CVSS + EPSS + KEV status
- `search_cve` ($0.01) — Search CVEs by severity, CVSS, EPSS, attack vector, KEV
- `check_ip` ($0.01) — IP threat reputation (AbuseIPDB + OTX)
- `check_domain` ($0.01) — Domain threat reputation across feeds
- `vulnerability_scan` ($0.02) — Product/vendor CVE exposure scan
- `threat_feed` ($0.01) — Recent threat indicators
- `daily_brief` ($15) — Curated daily threat intelligence, MINT-attested
- `mint_info` (free) — Network + attestation info

A daily free-tier allowance precedes the paywall; paid tools are metered (pay-per-query)
or settle via Stripe. An `Authorization: Bearer fnet_…` key bypasses the gate.

## Part of the FoundryNet Data Network
17 interconnected data-intelligence servers with MINT-attested, verifiable outputs.
Live network activity: https://mint.foundrynet.io/feed
