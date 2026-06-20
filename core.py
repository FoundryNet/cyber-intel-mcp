"""Shared logic behind the MCP tools + REST routes: 7 operations + x402 gating.
cve_detail and mint_info are free; the rest run payment_gate.precheck(price) first.
check_ip/check_domain do live AbuseIPDB/OTX lookups and cache indicators.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import config
import cyber_sources as src
import daily_curator
import mint_integration
import payment_gate
import supa

logger = logging.getLogger("cyber.core")


def _days_ago_iso(n):
    return (datetime.now(timezone.utc) - timedelta(days=int(n))).strftime("%Y-%m-%d")


def _hours_ago_iso(n):
    return (datetime.now(timezone.utc) - timedelta(hours=int(n))).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _billing(d):
    g = d.get("gate")
    if g == "free":
        cap, cnt = d.get("cap"), d.get("count")
        return {"tier": "free", "used_today": cnt, "daily_free": cap,
                "remaining_today": (cap - cnt) if (cap is not None and cnt is not None) else None}
    if g == "paid":
        return {"tier": "paid", "charged_usdc": d.get("amount_usdc")}
    if g == "api_key":
        return {"tier": "api_key", "note": "billed to your Forge account"}
    return {"tier": "free", "note": "gating inert"}


async def do_search(filters, *, agent_key, payment_tx=None, api_key=None):
    params = {k: v for k, v in (filters or {}).items() if v not in (None, "")}
    dec = await payment_gate.precheck("search_cve", params, config.PRICE_SEARCH, agent_key, payment_tx, api_key)
    if dec["gate"] == "blocked":
        return dec["body"]
    days_back = params.pop("days_back", None)
    rows = await supa.search_cve(days_from=_days_ago_iso(days_back) if days_back else None, **params)
    return {"results": rows, "count": len(rows), "billing": _billing(dec)}


async def do_cve_detail(cve_id):
    if not cve_id:
        return {"error": "bad_request", "detail": "cve_id is required"}
    row = await supa.cve_by_id(cve_id)
    if not row:
        return {"error": "not_found", "detail": f"{cve_id} not in the dataset yet (it ingests new/modified CVEs every 6h)"}
    return {"cve": row}


async def do_check_ip(ip, *, agent_key, payment_tx=None, api_key=None):
    if not ip:
        return {"error": "bad_request", "detail": "ip_address is required"}
    dec = await payment_gate.precheck("check_ip", {"ip": ip}, config.PRICE_CHECK_IP, agent_key, payment_tx, api_key)
    if dec["gate"] == "blocked":
        return dec["body"]
    res = await src.check_ip(ip)
    if res.get("indicators"):
        await supa.upsert_indicators([{**i, "first_seen": i.get("last_seen") or supa.now_iso(),
                                       "last_seen": i.get("last_seen") or supa.now_iso()}
                                      for i in res["indicators"]])
    note = None
    if not config.ABUSEIPDB_API_KEY and not config.OTX_API_KEY:
        note = "Set ABUSEIPDB_API_KEY / OTX_API_KEY to enable live IP reputation."
    return {"ip_address": ip, "sources": res["sources"], "indicators": res["indicators"],
            "note": note, "billing": _billing(dec)}


async def do_check_domain(domain, *, agent_key, payment_tx=None, api_key=None):
    if not domain:
        return {"error": "bad_request", "detail": "domain is required"}
    dec = await payment_gate.precheck("check_domain", {"domain": domain}, config.PRICE_CHECK_DOMAIN,
                                      agent_key, payment_tx, api_key)
    if dec["gate"] == "blocked":
        return dec["body"]
    res = await src.check_domain(domain)
    if res.get("indicators"):
        await supa.upsert_indicators([{**i, "first_seen": supa.now_iso(), "last_seen": supa.now_iso()}
                                      for i in res["indicators"]])
    note = None if config.OTX_API_KEY else "Set OTX_API_KEY to enable live domain intel."
    return {"domain": domain, "sources": res["sources"], "indicators": res["indicators"],
            "note": note, "billing": _billing(dec)}


async def do_scan(product, vendor, cpe, *, agent_key, payment_tx=None, api_key=None):
    if not (product or vendor or cpe):
        return {"error": "bad_request", "detail": "product_name, vendor, or cpe is required"}
    params = {k: v for k, v in {"product": product, "vendor": vendor, "cpe": cpe}.items() if v}
    dec = await payment_gate.precheck("vulnerability_scan", params, config.PRICE_SCAN, agent_key, payment_tx, api_key)
    if dec["gate"] == "blocked":
        return dec["body"]
    rows = await supa.scan_product(product=product, vendor=vendor, cpe=cpe)
    kev = [r for r in rows if r.get("is_kev")]
    result = {"query": params, "count": len(rows),
              "kev_count": len(kev), "max_epss": max([r.get("epss_score") or 0 for r in rows], default=0),
              "results": rows, "note": "sorted by EPSS (exploit likelihood) desc",
              "billing": _billing(dec)}
    # Provenance attestation (additive; fail-open; off the event loop).
    result["provenance"] = await asyncio.to_thread(
        mint_integration.attest_data, result, "analysis", "vulnerability_scan query result")
    return result


async def do_threat_feed(indicator_type, threat_type, min_confidence, hours_back, *,
                         agent_key, payment_tx=None, api_key=None):
    params = {k: v for k, v in {"indicator_type": indicator_type, "threat_type": threat_type,
                                "min_confidence": min_confidence, "hours_back": hours_back}.items()
              if v not in (None, "")}
    dec = await payment_gate.precheck("threat_feed", params, config.PRICE_FEED, agent_key, payment_tx, api_key)
    if dec["gate"] == "blocked":
        return dec["body"]
    since = _hours_ago_iso(hours_back) if hours_back else None
    rows = await supa.threat_feed(indicator_type=indicator_type, threat_type=threat_type,
                                  min_confidence=min_confidence, since=since)
    return {"count": len(rows), "indicators": rows, "billing": _billing(dec)}


# ── daily_brief (premium, curated) ────────────────────────────────────────────
async def do_daily_brief(date, *, agent_key, payment_tx=None, api_key=None):
    day = (date or datetime.now(timezone.utc).strftime("%Y-%m-%d")).strip()
    dec = await payment_gate.precheck("daily_brief", {"date": day}, config.PRICE_DAILY_BRIEF,
                                      agent_key, payment_tx, api_key)
    if dec["gate"] == "blocked":
        return dec["body"]
    brief = await daily_curator.get_brief(day)
    if not brief:
        return {"error": "not_available",
                "detail": f"No brief for {day} (not yet generated, or expired at midnight UTC). "
                          f"Briefs are curated daily at {config.BRIEF_HOUR_UTC:02d}:00 UTC.",
                "billing": _billing(dec)}
    await daily_curator.bump_purchase(day)
    return {**brief, "billing": _billing(dec)}


def mint_info():
    return {
        "network": "FoundryNet Data Network", **mint_integration.network_feed_block(),
        "message": "Attest your agent's security analysis with MINT Protocol for verifiable proof.",
        "mint_protocol": {"mcp_endpoint": config.MINT_MCP_URL, "info_url": config.MINT_INFO_URL,
                          "tools": ["mint_register", "mint_attest", "mint_verify",
                                    "mint_rate", "mint_recommend", "mint_discover"]},
        "see_also": config.SISTER_SERVERS,
    }


# ── Soft upsell: surface the daily_brief on every paid, non-brief response ─────
# Appends one non-blocking `available_intelligence` field to successful paid tool
# responses so the calling agent learns a single curated brief can replace many
# individual paid queries. Skips error and 402/payment_required bodies, and never
# touches daily_brief itself (no self-upsell). Brief status is cached 5 min, so
# this adds no per-call DB latency. Added 2026-06-20 (seller_agent v2 upsell hook).
import time as _upsell_time

_brief_upsell_cache = {"day": None, "ts": 0.0, "available": False, "count": 0}


async def _brief_status_cached() -> tuple[bool, int]:
    day = _upsell_time.strftime("%Y-%m-%d", _upsell_time.gmtime())
    now = _upsell_time.time()
    c = _brief_upsell_cache
    if c["day"] == day and (now - c["ts"]) < 300:
        return c["available"], c["count"]
    avail, count = False, 0
    try:
        brief = await daily_curator.get_brief(day)
        if brief:
            avail, count = True, int(brief.get("signal_count") or 0)
    except Exception:  # noqa: BLE001
        return c["available"], c["count"]
    c.update(day=day, ts=now, available=avail, count=count)
    return avail, count


async def _available_intelligence() -> dict:
    avail, count = await _brief_status_cached()
    return {"daily_brief": {
        "available": avail,
        "signal_count": count,
        "price_usd": config.PRICE_DAILY_BRIEF,
        "tool": "daily_brief",
        "note": "Curated daily intelligence — more efficient than individual queries",
    }}


def _make_upsell(_fn):
    import functools

    @functools.wraps(_fn)
    async def _wrapped(*a, **k):
        result = await _fn(*a, **k)
        if isinstance(result, dict) and "error" not in result and "payment_required" not in result:
            try:
                result["available_intelligence"] = await _available_intelligence()
            except Exception:  # noqa: BLE001
                pass
            try:
                import asyncio as _aio, mint_integration as _mint
                result["foundrynet_network"] = await _aio.to_thread(_mint.network_heartbeat)
            except Exception:  # noqa: BLE001
                pass
        return result

    return _wrapped


for _upsell_fn in ("do_search", "do_check_ip", "do_check_domain", "do_scan", "do_threat_feed",):
    if _upsell_fn in globals():
        globals()[_upsell_fn] = _make_upsell(globals()[_upsell_fn])
