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
  FREE_TIER_DAILY      default 25
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
SOURCE_USER_AGENT = _env("SOURCE_USER_AGENT", "FoundryNet Data Network hello@foundrynet.io")

LOOKBACK_HOURS = int(_env("LOOKBACK_HOURS", "24"))

# ── x402 per-tool pricing ────────────────────────────────────────────────────
X402_ENABLED      = _flag("X402_ENABLED", True)
SOLANA_WALLET     = _env("SOLANA_WALLET", "wUumjWWvtFEr69qkTw3wHNVQVxLA8DTyJSyVgGmLThd")
PAYMENT_RECIPIENT = _env("PAYMENT_RECIPIENT", SOLANA_WALLET).strip()
PAYMENT_VERIFY_RPC = _env("PAYMENT_VERIFY_RPC", "https://api.mainnet-beta.solana.com").rstrip("/")
PAYMENT_USDC_MINT  = _env("PAYMENT_USDC_MINT", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").strip()
PAYMENT_EXPIRY_SECONDS = int(_env("PAYMENT_EXPIRY_SECONDS", "300"))

FREE_TIER_DAILY = int(_env("FREE_TIER_DAILY", "25"))

PRICE_SEARCH      = float(_env("PRICE_SEARCH", "0.01"))
PRICE_CHECK_IP    = float(_env("PRICE_CHECK_IP", "0.01"))
PRICE_CHECK_DOMAIN = float(_env("PRICE_CHECK_DOMAIN", "0.01"))
PRICE_SCAN        = float(_env("PRICE_SCAN", "0.02"))
PRICE_FEED        = float(_env("PRICE_FEED", "0.01"))

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
