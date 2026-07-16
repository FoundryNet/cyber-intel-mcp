"""Env-driven configuration for cyber-intel-mcp.

Cybersecurity threat intelligence: CVEs (NVD) enriched with EPSS exploit-likelihood
+ CISA KEV + GitHub advisories, plus live IP/domain reputation (AbuseIPDB + OTX),
in its own standalone Supabase project. 7 tools, x402 metered. Part of the
FoundryNet Data Network.

Required to be useful:
  SUPABASE_URL, SUPABASE_SERVICE_KEY   the standalone cyber-intel project.
Optional:
  NVD_API_KEY          higher NVD rate limit (else keyless + throttled)
  ABUSEIPDB_API_KEY    check_ip (free 1000/day) — tool no-ops without it
  OTX_API_KEY          AlienVault OTX indicators — tools degrade without it
  PORT, REQUEST_TIMEOUT
  X402_ENABLED, SOLANA_WALLET, PAYMENT_RECIPIENT, PAYMENT_VERIFY_RPC,
  PAYMENT_USDC_MINT, PAYMENT_EXPIRY_SECONDS
  FREE_TIER_DAILY      default 5
  LOOKBACK_HOURS       cold-start CVE window, default 24
  PRICE_*              per-tool USDC prices
"""
from __future__ import annotations

import os


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _flag(name: str, default: bool) -> bool:
    return _env(name, "true" if default else "false").strip().lower() in ("1", "true", "yes", "on")


SUPABASE_URL         = _env("SUPABASE_URL", "https://mkgjxbhvyxfkfsdqvhme.supabase.co").rstrip("/")
SUPABASE_SERVICE_KEY = _env("SUPABASE_SERVICE_KEY")

PORT            = int(_env("PORT", "8080"))
REQUEST_TIMEOUT = int(_env("REQUEST_TIMEOUT", "30"))

# ── Sources ──────────────────────────────────────────────────────────────────
NVD_API     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = _env("NVD_API_KEY")
KEV_FEED    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API    = "https://api.first.org/data/v1/epss"
GHSA_API    = "https://api.github.com/advisories"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_API_KEY = _env("ABUSEIPDB_API_KEY")
OTX_API     = "https://otx.alienvault.com/api/v1/indicators"
OTX_API_KEY = _env("OTX_API_KEY")
SOURCE_USER_AGENT = _env("SOURCE_USER_AGENT", "FoundryNet Data Network forge@foundrynet.io")

LOOKBACK_HOURS = int(_env("LOOKBACK_HOURS", "24"))

# ── x402 per-tool pricing ────────────────────────────────────────────────────
X402_ENABLED      = _flag("X402_ENABLED", True)
SOLANA_WALLET     = _env("SOLANA_WALLET", "wUumjWJjfn27VQhTXd1jUNTzszCmsErkzaEeHWbLThd")
PAYMENT_RECIPIENT = _env("PAYMENT_RECIPIENT", SOLANA_WALLET).strip()
PAYMENT_VERIFY_RPC = _env("PAYMENT_VERIFY_RPC", "https://api.mainnet-beta.solana.com").rstrip("/")
PAYMENT_USDC_MINT  = _env("PAYMENT_USDC_MINT", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").strip()
PAYMENT_EXPIRY_SECONDS = int(_env("PAYMENT_EXPIRY_SECONDS", "300"))

FREE_TIER_DAILY = int(_env("FREE_TIER_DAILY", "5"))

PRICE_SEARCH      = float(_env("PRICE_SEARCH", "0.01"))
PRICE_CHECK_IP    = float(_env("PRICE_CHECK_IP", "0.01"))
PRICE_CHECK_DOMAIN = float(_env("PRICE_CHECK_DOMAIN", "0.01"))
PRICE_SCAN        = float(_env("PRICE_SCAN", "0.05"))   # premium (raised 0.02→0.05 for agent market)
PRICE_FEED        = float(_env("PRICE_FEED", "0.01"))
PRICE_DAILY_BRIEF = float(_env("PRICE_DAILY_BRIEF", "15"))
PRICE_BRIEF_SUMMARY = float(_env("PRICE_BRIEF_SUMMARY", "0.5"))  # $0.50 sample tier → upsells daily_brief

# ── Stripe rail (parallel payment option to x402, for the daily brief) ────────
# Agents without a USDC wallet pay this hosted Payment Link instead. The secret
# key verifies the resulting Checkout Session; the link URL is shown on a 402.
STRIPE_SECRET_KEY       = _env("STRIPE_SECRET_KEY", "")
STRIPE_LINK_DAILY_BRIEF = _env("STRIPE_LINK_DAILY_BRIEF",
                               "https://foundrynet.io/pricing")

# ── Daily curated brief ──────────────────────────────────────────────────────
BRIEF_HOUR_UTC = int(_env("BRIEF_HOUR_UTC", "5"))   # curator runs at 05:00 UTC
SERVER_SLUG    = "cyber-intel"
# Cross-network brief catalog (server -> price + tool) for related_briefs.
NETWORK_BRIEFS = {
    "financial-signals": "$25", "cyber-intel": "$15", "patent-intel": "$10",
    "gov-contracts": "$10", "compliance": "$10", "brand-intel": "$5", "weather-intel": "$5",
}

# ── FoundryNet Data Network cross-promo ──────────────────────────────────────
MINT_MCP_URL  = _env("MINT_MCP_URL", "https://mint-mcp-production.up.railway.app/mcp")
MINT_INFO_URL = _env("MINT_INFO_URL", "https://mint.foundrynet.io")
SISTER_SERVERS = {
    "gov-contracts-mcp":     "https://gov-contracts-mcp-production.up.railway.app/mcp",
    "brand-intel-mcp":       "https://brand-intel-mcp-production.up.railway.app/mcp",
    "patent-intel-mcp":      "https://patent-intel-mcp-production.up.railway.app/mcp",
    "financial-signals-mcp": "https://financial-signals-mcp-production.up.railway.app/mcp",
    "weather-intel-mcp":     "https://weather-intel-mcp-production.up.railway.app/mcp",
    "compliance-mcp":        "https://compliance-mcp-production.up.railway.app/mcp",
}

PUBLIC_MCP_URL = _env("PUBLIC_MCP_URL", "https://cyber-intel-mcp-production.up.railway.app/mcp")

# ── FoundryNet Data Network — full sister-server map (auto-updated 2026-06-19) ──
# Re-binds SISTER_SERVERS to the complete network (all 11 servers, self excluded),
# now including fact-check-mcp, oss-intel-mcp, social-intel-mcp.
_FNET_ALL_SERVERS = {
    "mint-mcp":              "https://mint-mcp-production.up.railway.app/mcp",
    "foundrynet-mcp":        "https://foundrynet-mcp-production.up.railway.app/mcp",
    "gov-contracts-mcp":     "https://gov-contracts-mcp-production.up.railway.app/mcp",
    "brand-intel-mcp":       "https://brand-intel-mcp-production.up.railway.app/mcp",
    "patent-intel-mcp":      "https://patent-intel-mcp-production.up.railway.app/mcp",
    "financial-signals-mcp": "https://financial-signals-mcp-production.up.railway.app/mcp",
    "weather-intel-mcp":     "https://weather-intel-mcp-production.up.railway.app/mcp",
    "cyber-intel-mcp":       "https://cyber-intel-mcp-production.up.railway.app/mcp",
    "compliance-mcp":        "https://compliance-mcp-production.up.railway.app/mcp",
    "academic-intel-mcp":    "https://academic-intel-mcp-production.up.railway.app/mcp",
    "fact-check-mcp":        "https://fact-check-mcp-production.up.railway.app/mcp",
    "oss-intel-mcp":         "https://oss-intel-mcp-production.up.railway.app/mcp",
    "social-intel-mcp":      "https://social-intel-mcp-production.up.railway.app/mcp",
    "crypto-intel-mcp":      "https://crypto-intel-mcp-production.up.railway.app/mcp",
    "market-data-mcp":       "https://market-data-mcp-production.up.railway.app/mcp",
    "email-verify-mcp":      "https://email-verify-mcp-production.up.railway.app/mcp",
    "currency-intel-mcp":    "https://currency-intel-mcp-production.up.railway.app/mcp",
}
SISTER_SERVERS = {k: v for k, v in _FNET_ALL_SERVERS.items() if k != "cyber-intel-mcp"}

# ── Subscriptions (network-wide $19/$49 Stripe links; same on every server) ──────
# These lead the 402 response: a credit-card subscription converts where "send USDC
# with an SPL-memo" does not. Both unlock unlimited queries here; Intelligence also
# unlocks Knowledge Bases + composite products on foundrynet-agents.
STRIPE_LINK_PRO      = _env("STRIPE_LINK_PRO",   "https://buy.stripe.com/3cIdR278Cglq7bY5b67N604")
STRIPE_LINK_INTEL    = _env("STRIPE_LINK_INTEL", "https://buy.stripe.com/4gMaEQ78C8SYaoa32Y7N605")
NETWORK_SERVER_COUNT = int(_env("NETWORK_SERVER_COUNT", "17"))

# ── Dynamic allowlist (subscriber keys, 5-min cache; static env = fallback) ──────
# Default: poll the agents /v1/allowlist (no DB creds needed). To read forge_api_keys
# directly instead, set FORGE_KEYS_SUPABASE_URL + FORGE_KEYS_SUPABASE_KEY.
FNET_ALLOWLIST_URL      = _env("FNET_ALLOWLIST_URL",
                               "https://foundrynet-agents-production.up.railway.app/v1/allowlist")
FORGE_KEYS_SUPABASE_URL = _env("FORGE_KEYS_SUPABASE_URL", "")
FORGE_KEYS_SUPABASE_KEY = _env("FORGE_KEYS_SUPABASE_KEY", "")

# ── Per-call event log (fire-and-forget telemetry to the agents ingest) ──────────
EVENT_LOG_URL   = _env("EVENT_LOG_URL",
                       "https://foundrynet-agents-production.up.railway.app/v1/call-events")
EVENT_LOG_TOKEN = _env("EVENT_LOG_TOKEN", "")
