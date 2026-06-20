# Cybersecurity Threat Intelligence MCP

**Cybersecurity threat intelligence for AI agents** — CVE search enriched with
EPSS exploit-likelihood + CISA known-exploited (KEV) status, plus live IP/domain
reputation and a real-time threat feed.

> Part of the **FoundryNet Data Network**. Attest your agent's security analysis
> with [MINT Protocol](https://mint-mcp-production.up.railway.app/mcp). See also:
> **gov-contracts-mcp**, **brand-intel-mcp**, **patent-intel-mcp**,
> **financial-signals-mcp**, **weather-intel-mcp**, **compliance-mcp**.

## Connect

- **MCP endpoint** (Streamable HTTP): `https://cyber-intel-mcp-production.up.railway.app/mcp`
- **Registry:** `io.github.FoundryNet/cyber-intel-mcp`
- **Agent card:** `https://cyber-intel-mcp-production.up.railway.app/.well-known/agent-card.json`

### Claude Desktop / Cursor / Claude Code

```bash
claude mcp add --transport http cyber-intel https://cyber-intel-mcp-production.up.railway.app/mcp
```

```json
{ "mcpServers": { "cyber-intel": { "url": "https://cyber-intel-mcp-production.up.railway.app/mcp" } } }
```

## Tools

| Tool | Price | What it does |
|---|---|---|
| `search_cve` | $0.01 | CVE search by severity, CVSS, **EPSS**, attack vector, KEV status |
| `cve_detail` | **free** | Full CVE — CVSS breakdown, EPSS, KEV, CWE, affected products, refs |
| `check_ip` | $0.01 | IP reputation (AbuseIPDB + OTX) — abuse score, threat type, pulses |
| `check_domain` | $0.01 | Domain threat indicators (OTX) |
| `vulnerability_scan` | $0.02 | All CVEs for a product, **sorted by EPSS** — "should I worry about this dependency?" |
| `threat_feed` | $0.01 | Recent threat indicators (IPs/domains/hashes/URLs) |
| `mint_info` | **free** | FoundryNet Data Network + MINT Protocol |

**Free tier:** 25 paid-tool queries/day per agent. Then x402: the tool returns an
HTTP-402 with a Solana USDC payment memo — pay it, re-call with the same args plus
`payment_tx=<signature>`. An `Authorization: Bearer fnet_…` key bypasses the paywall.

## The edge: EPSS-ranked vulnerabilities

Raw CVE counts are noise. Every vulnerability here carries its **EPSS score** (the
probability it'll be exploited) and a **CISA KEV** flag (whether it's *actively*
exploited). `vulnerability_scan` sorts a product's CVEs by exploit likelihood — so
an agent triaging a dependency sees what actually matters first.

## Sources

Every 6 hours: **NVD** (CVEs, keyless + throttled), **EPSS** (exploit probability),
**CISA KEV** (known-exploited catalog), **GitHub Advisories**. Live on demand:
**AbuseIPDB** (IP reputation) + **AlienVault OTX** (IP/domain/pulse indicators).
Stored in a standalone Supabase project.

## Discovery

MCP registry: `io.github.FoundryNet/cyber-intel-mcp`

Built by [FoundryNet](https://foundrynet.io) · hello@foundrynet.io

## Live network activity

**Live feed:** [mint.foundrynet.io/feed](https://mint.foundrynet.io/feed)  
Real-time verified work across 13 servers and autonomous agents, anchored on Solana via [MINT Protocol](https://mint.foundrynet.io).
