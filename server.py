"""cyber-intel-mcp — cybersecurity threat intelligence for autonomous agents.

Part of the FoundryNet Data Network. CVEs (NVD) enriched with EPSS exploit
probability + CISA KEV + GitHub advisories, plus live IP/domain reputation
(AbuseIPDB + OTX). 7 tools + free mint_info. Free tier 25/day, then x402 (USDC on
Solana). Re-aggregates every 6h. Transport: Streamable HTTP at /mcp (+ /sse).
"""
from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

import config
import core
import daily_curator
import identity
import payment_gate
import supa
import threat_aggregator as agg
import tools

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("cyber.mcp")

if not supa.configured():
    logger.warning("SUPABASE_SERVICE_KEY not set — dataset disabled until configured.")

mcp = FastMCP("cyber-intel")

if payment_gate.is_active():
    logger.info(f"pay-per-query ARMED → {config.PAYMENT_RECIPIENT} after {config.FREE_TIER_DAILY}/day free")
else:
    logger.info("pay-per-query INERT — all tools free")

tools.register_all(mcp)


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ok", "service": "cyber-intel-mcp", "transport": "streamable-http",
        "network": "FoundryNet Data Network",
        "tools": ["search_cve", "cve_detail", "check_ip", "check_domain",
                  "vulnerability_scan", "threat_feed", "daily_brief", "mint_info"],
        "dataset": "supabase:vulnerabilities" if supa.configured() else "unconfigured",
        "sources": "nvd + cisa_kev + epss + ghsa + abuseipdb + otx",
        "abuseipdb": "set" if config.ABUSEIPDB_API_KEY else "unset",
        "otx": "set" if config.OTX_API_KEY else "unset",
        "x402_enabled": config.X402_ENABLED,
        "query_payment": "armed" if payment_gate.is_active() else "free",
        "free_tier_daily": config.FREE_TIER_DAILY,
        "payment_recipient": config.PAYMENT_RECIPIENT,
    })


@mcp.custom_route("/ping", methods=["GET"])
async def ping(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


# ── REST surface ─────────────────────────────────────────────────────────────
_ERR = {"bad_request": 400, "not_configured": 503, "not_found": 404, "payment_required": 402}


def _resp(d: dict) -> JSONResponse:
    if "error" not in d:
        return JSONResponse(d, status_code=200)
    err = str(d.get("error") or "")
    code = _ERR.get(err, 502 if err in ("network", "non_json_response", "unreachable") else 400)
    if err.startswith("http_") and err[5:].isdigit():
        code = int(err[5:])
    return JSONResponse(d, status_code=code)


async def _body(request: Request) -> dict:
    try:
        b = await request.json()
        return b if isinstance(b, dict) else {}
    except Exception:
        return {}


def _akey(request: Request, body: dict) -> str:
    return identity.resolve_agent_key(body.get("agent_id"), request=request)


@mcp.custom_route("/v1/search", methods=["POST"])
async def rest_search(request: Request) -> JSONResponse:
    b = await _body(request)
    filters = {k: b.get(k) for k in ("keyword", "severity", "min_cvss", "min_epss",
                                     "attack_vector", "days_back", "is_kev", "limit")}
    return _resp(await core.do_search(filters, agent_key=_akey(request, b),
                                      payment_tx=b.get("payment_tx"), api_key=identity.bearer(request)))


@mcp.custom_route("/v1/cve", methods=["POST"])
async def rest_cve(request: Request) -> JSONResponse:
    b = await _body(request)
    return _resp(await core.do_cve_detail(b.get("cve_id", "")))


@mcp.custom_route("/v1/check-ip", methods=["POST"])
async def rest_ip(request: Request) -> JSONResponse:
    b = await _body(request)
    return _resp(await core.do_check_ip(b.get("ip_address", ""), agent_key=_akey(request, b),
                                        payment_tx=b.get("payment_tx"), api_key=identity.bearer(request)))


@mcp.custom_route("/v1/check-domain", methods=["POST"])
async def rest_domain(request: Request) -> JSONResponse:
    b = await _body(request)
    return _resp(await core.do_check_domain(b.get("domain", ""), agent_key=_akey(request, b),
                                            payment_tx=b.get("payment_tx"), api_key=identity.bearer(request)))


@mcp.custom_route("/v1/scan", methods=["POST"])
async def rest_scan(request: Request) -> JSONResponse:
    b = await _body(request)
    return _resp(await core.do_scan(b.get("product_name"), b.get("vendor"), b.get("cpe"),
                                    agent_key=_akey(request, b), payment_tx=b.get("payment_tx"),
                                    api_key=identity.bearer(request)))


@mcp.custom_route("/v1/feed", methods=["POST"])
async def rest_feed(request: Request) -> JSONResponse:
    b = await _body(request)
    return _resp(await core.do_threat_feed(b.get("indicator_type"), b.get("threat_type"),
                                           b.get("min_confidence"), b.get("hours_back"),
                                           agent_key=_akey(request, b), payment_tx=b.get("payment_tx"),
                                           api_key=identity.bearer(request)))


@mcp.custom_route("/v1/mint-info", methods=["GET", "POST"])
async def rest_mint(request: Request) -> JSONResponse:
    return JSONResponse(core.mint_info())


@mcp.custom_route("/admin/aggregate", methods=["POST"])
async def admin_aggregate(request: Request) -> JSONResponse:
    import os
    tok = os.environ.get("ADMIN_TOKEN", "")
    if not tok or request.headers.get("x-admin-token") != tok:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    qp = request.query_params
    hours = int(qp["hours"]) if qp.get("hours", "").isdigit() else None
    if qp.get("wait") == "1":
        return JSONResponse(await agg.run_aggregation(hours))
    asyncio.create_task(agg.run_aggregation(hours))
    return JSONResponse({"started": True, "hours": hours})


# ── Discovery ────────────────────────────────────────────────────────────────
_TAGLINE = "Cybersecurity threat intelligence for agents — CVEs, EPSS, KEV, IP reputation."
_DESC = ("Cybersecurity threat intelligence for agents: CVE search, vulnerability database, "
         "exploit prediction (EPSS), CISA known-exploited (KEV), IP reputation, and security "
         "scanning. CVEs enriched with exploit-likelihood scores. Part of the FoundryNet Data "
         "Network — attest analysis with MINT Protocol; see also gov-contracts, brand-intel, "
         "patent-intel, financial-signals, weather-intel, compliance.")
_KEYWORDS = ["cybersecurity", "CVE search", "vulnerability database", "threat intelligence",
             "IP reputation", "security scanning", "exploit prediction"]

_AGENT_CARD = {
    "name": "Cybersecurity Threat Intelligence MCP",
    "description": ("Search CVEs with EPSS exploit-prediction and CISA KEV status, check IP/domain "
                    "reputation, and run vulnerability scans — threat intel from NVD, CISA, EPSS, "
                    "GHSA, AbuseIPDB, and OTX."),
    "url": "https://cyber-intel-mcp-production.up.railway.app/mcp",
    "version": "1.0.0",
    "capabilities": {"tools": ["search_cve", "cve_detail", "check_ip", "check_domain",
                               "vulnerability_scan", "threat_feed", "daily_brief", "mint_info"]},
    "provider": {"name": "FoundryNet", "url": "https://foundrynet.io"},
    "network": "FoundryNet Data Network",
    "attestation": {"protocol": "MINT Protocol",
                    "endpoint": "https://mint-mcp-production.up.railway.app/mcp",
                    "verified_outputs": True, "live_feed": "https://mint.foundrynet.io/feed", "feed_api": "https://mint-mcp-production.up.railway.app/v1/feed"},
    "protocols": {"mcp": {"endpoint": config.PUBLIC_MCP_URL, "transport": "streamable-http", "tools_count": 8},
                  "x402": {"supported": True, "currency": "USDC", "network": "solana"}},
    "see_also": config.SISTER_SERVERS, "mint_protocol": config.MINT_MCP_URL,
    "contact": "hello@foundrynet.io",
}


@mcp.custom_route("/.well-known/agent-card.json", methods=["GET"])
async def agent_card(request: Request) -> JSONResponse:
    return JSONResponse(_AGENT_CARD, headers={"Cache-Control": "public, max-age=300"})


@mcp.custom_route("/.well-known/mcp", methods=["GET"])
async def mcp_endpoints(request: Request) -> JSONResponse:
    return JSONResponse({"endpoints": [{"url": config.PUBLIC_MCP_URL, "transport": "streamable-http",
                                        "name": "Cybersecurity Threat Intelligence MCP"}]},
                        headers={"Cache-Control": "public, max-age=300"})


async def _live_tools() -> list:
    res = mcp.list_tools()
    if inspect.iscoroutine(res):
        res = await res
    return [{"name": t.name, "description": (getattr(t, "description", "") or "").strip(),
             "inputSchema": getattr(t, "parameters", None) or {"type": "object"}} for t in res]


@mcp.custom_route("/.well-known/mcp/server-card.json", methods=["GET"])
async def server_card(request: Request) -> JSONResponse:
    live = await _live_tools()
    return JSONResponse({
        "serverInfo": {"name": "Cybersecurity Threat Intelligence MCP", "version": "1.0.0"},
        "authentication": {"type": "http", "scheme": "bearer",
                           "description": ("cve_detail and mint_info are free; other tools give 25 free "
                                           "queries/day then take an fnet_ Bearer key OR x402 USDC.")},
        "tools": live, "version": "1.0", "name": "Cybersecurity Threat Intelligence MCP",
        "tagline": _TAGLINE, "description": _DESC,
        "serverUrl": config.PUBLIC_MCP_URL, "transport": "streamable-http",
        "tools_count": len(live),
        "categories": ["security", "cybersecurity", "data", "devops", "vulnerability"],
        "keywords": _KEYWORDS, "network": "FoundryNet Data Network",
        "see_also": config.SISTER_SERVERS,
        "pricing": {"model": "metered",
                    "free_tier": f"{config.FREE_TIER_DAILY} queries/day + free cve_detail",
                    "paid_from": f"{config.PRICE_SEARCH} USDC per query (x402)"},
    }, headers={"Cache-Control": "public, max-age=300"})


# ── Background: re-aggregate every 6h ────────────────────────────────────────
async def _agg_loop():
    while True:
        await asyncio.sleep(6 * 3600)
        try:
            if supa.configured():
                await agg.run_aggregation()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"agg loop: {e}")


_FREE_TOOL_NAMES = {"mint_info", "macro_dashboard", "cve_detail", "detail",
                    "domain_age", "convert", "rates", "market_overview", "price",
                    "quote", "batch_quote", "sector_performance"}


@mcp.custom_route("/.well-known/mcp.json", methods=["GET"])
async def wellknown_mcp_json(request: Request) -> JSONResponse:
    """Machine-discovery card (emerging standard) for AI clients/crawlers."""
    live = await _live_tools()
    names = [t["name"] for t in live]
    return JSONResponse({
        "name": _AGENT_CARD["name"],
        "description": _AGENT_CARD["description"],
        "url": config.PUBLIC_MCP_URL,
        "transport": ["streamable-http"],
        "tools": names,
        "pricing": {"model": "per-query", "free_tier": True,
                    "paid_tools": [n for n in names if n not in _FREE_TOOL_NAMES]},
        "attestation": {"enabled": True, "protocol": "MINT Protocol",
                        "feed": "https://mint.foundrynet.io/feed"},
        "network": {"name": "FoundryNet Data Network", "servers": 17,
                    "homepage": "https://foundrynet.io"},
    }, headers={"Cache-Control": "public, max-age=300"})


def build_dual_app():
    main_app = mcp.http_app(transport="http", path="/mcp")
    sse_app = mcp.http_app(transport="sse", path="/sse")
    for r in sse_app.routes:
        if getattr(r, "path", None) in ("/sse", "/messages"):
            main_app.router.routes.append(r)
    main_life, sse_life = main_app.router.lifespan_context, sse_app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def _dual_lifespan(app):
        async with main_life(app):
            async with sse_life(app):
                task = asyncio.create_task(_agg_loop())
                brief_task = asyncio.create_task(daily_curator.curator_loop())
                try:
                    yield
                finally:
                    for t in (task, brief_task):
                        t.cancel()
                        with contextlib.suppress(Exception):
                            await t
    main_app.router.lifespan_context = _dual_lifespan
    return main_app


if __name__ == "__main__":
    import uvicorn
    logger.info(f"cyber-intel-mcp starting on 0.0.0.0:{config.PORT} "
                f"(dataset={'supabase' if supa.configured() else 'off'}, x402={config.X402_ENABLED})")
    uvicorn.run(build_dual_app(), host="0.0.0.0", port=config.PORT, log_level="warning")
