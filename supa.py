"""Supabase PostgREST client for cyber-intel-mcp (standalone project)."""
from __future__ import annotations

import logging
import time
from typing import Optional

import config
from http_util import request_json

logger = logging.getLogger("cyber.supa")


def configured() -> bool:
    return bool(config.SUPABASE_URL and config.SUPABASE_SERVICE_KEY)


def _headers(extra: Optional[dict] = None) -> dict:
    h = {"apikey": config.SUPABASE_SERVICE_KEY,
         "Authorization": f"Bearer {config.SUPABASE_SERVICE_KEY}",
         "Content-Type": "application/json", "Accept": "application/json"}
    if extra:
        h.update(extra)
    return h


def _url(path: str) -> str:
    return f"{config.SUPABASE_URL}/rest/v1/{path}"


async def select(table: str, params: dict) -> list:
    if not configured():
        return []
    r = await request_json("GET", _url(table), headers=_headers(), params=params,
                           timeout=config.REQUEST_TIMEOUT)
    return r if isinstance(r, list) else []


async def rpc(fn: str, body: dict):
    if not configured():
        return None
    return await request_json("POST", _url(f"rpc/{fn}"), headers=_headers(), body=body,
                              timeout=config.REQUEST_TIMEOUT)


async def upsert(table: str, rows: list, on_conflict: str) -> dict:
    if not configured() or not rows:
        return {"data": []}
    r = await request_json("POST", _url(table),
                           headers=_headers({"Prefer": "resolution=merge-duplicates,return=minimal"}),
                           params={"on_conflict": on_conflict},
                           body=rows, timeout=max(config.REQUEST_TIMEOUT, 60))
    if isinstance(r, dict) and r.get("error"):
        return r
    return {"data": rows}


async def _bulk_upsert(table: str, rows: list, on_conflict: str) -> int:
    if not configured() or not rows:
        return 0
    seen, deduped = set(), []
    keys = on_conflict.split(",")
    for r in rows:
        k = tuple(r.get(c) for c in keys)
        if any(x is None for x in k) or k in seen:
            continue
        seen.add(k)
        deduped.append(r)
    allkeys = set()
    for r in deduped:
        allkeys.update(r.keys())
    deduped = [{k: r.get(k) for k in allkeys} for r in deduped]
    written = 0
    for i in range(0, len(deduped), 500):
        resp = await request_json("POST", _url(table),
                                  headers=_headers({"Prefer": "resolution=merge-duplicates,return=minimal"}),
                                  params={"on_conflict": on_conflict},
                                  body=deduped[i:i + 500], timeout=max(config.REQUEST_TIMEOUT, 60))
        if isinstance(resp, dict) and resp.get("error"):
            logger.warning(f"upsert {table} chunk {i}: {str(resp)[:200]}")
        else:
            written += len(deduped[i:i + 500])
    return written


async def upsert_vulns(rows: list) -> int:
    return await _bulk_upsert("vulnerabilities", rows, "cve_id")


async def upsert_indicators(rows: list) -> int:
    return await _bulk_upsert("threat_indicators", rows, "indicator_type,indicator_value,source")


_VFIELDS = ("cve_id,description,published_date,modified_date,cvss_v3_score,cvss_v3_severity,"
            "cvss_v3_vector,attack_vector,attack_complexity,cwe_id,cwe_name,affected_products,"
            "epss_score,epss_percentile,is_kev,kev_due_date,reference_urls,patch_available")


# ── reads ─────────────────────────────────────────────────────────────────────
async def search_cve(*, keyword=None, severity=None, min_cvss=None, min_epss=None,
                     attack_vector=None, days_from=None, is_kev=None, limit=50) -> list:
    p = {"select": _VFIELDS, "order": "published_date.desc.nullslast",
         "limit": str(min(max(int(limit or 50), 1), 200))}
    if keyword:
        kw = keyword.replace("*", "").replace(",", " ")
        p["description"] = f"ilike.*{kw}*"
    if severity:
        p["cvss_v3_severity"] = f"eq.{severity.lower()}"
    if min_cvss is not None:
        p["cvss_v3_score"] = f"gte.{min_cvss}"
    if min_epss is not None:
        p["epss_score"] = f"gte.{min_epss}"
    if attack_vector:
        p["attack_vector"] = f"eq.{attack_vector.lower()}"
    if is_kev is not None:
        p["is_kev"] = f"eq.{str(bool(is_kev)).lower()}"
    if days_from:
        p["published_date"] = f"gte.{days_from}"
    return await select("vulnerabilities", p)


async def cve_by_id(cve_id: str) -> Optional[dict]:
    rows = await select("vulnerabilities", {"select": _VFIELDS, "cve_id": f"eq.{cve_id.upper()}", "limit": "1"})
    return rows[0] if rows else None


async def scan_product(*, product=None, vendor=None, cpe=None, limit=200) -> list:
    p = {"select": _VFIELDS, "order": "epss_score.desc.nullslast", "limit": str(limit)}
    term = cpe or product or vendor
    if term:
        kw = term.replace("*", "")
        # match affected_products jsonb text OR description
        p["or"] = f"(description.ilike.*{kw}*,affected_products.cs.[\"{kw}\"])"
    return await select("vulnerabilities", p)


async def indicators_for_value(value: str) -> list:
    return await select("threat_indicators", {"select": "*", "indicator_value": f"eq.{value}",
                                              "order": "last_seen.desc.nullslast"})


async def threat_feed(*, indicator_type=None, threat_type=None, min_confidence=None,
                      since=None, limit=100) -> list:
    p = {"select": "*", "order": "last_seen.desc.nullslast", "limit": str(limit)}
    if indicator_type:
        p["indicator_type"] = f"eq.{indicator_type}"
    if threat_type:
        p["threat_type"] = f"eq.{threat_type}"
    if min_confidence is not None:
        p["confidence"] = f"gte.{min_confidence}"
    if since:
        p["last_seen"] = f"gte.{since}"
    return await select("threat_indicators", p)


# ── free-tier + payments ──────────────────────────────────────────────────────
async def claim_free_query(agent_key: str, day: str, cap: int) -> Optional[dict]:
    r = await rpc("cyber_claim_free_query", {"p_agent_key": agent_key, "p_day": day, "p_cap": cap})
    if isinstance(r, dict) and "allowed" in r:
        return r
    if isinstance(r, list) and r and isinstance(r[0], dict):
        return r[0]
    return None


async def payment_tx_used(tx_signature: str) -> bool:
    rows = await select("cyber_payments", {"tx_signature": f"eq.{tx_signature}",
                                           "select": "tx_signature", "limit": "1"})
    return bool(rows)


async def insert_payment(row: dict) -> dict:
    if not configured():
        return {"error": "not_configured"}
    r = await request_json("POST", _url("cyber_payments"),
                           headers=_headers({"Prefer": "return=minimal"}),
                           body=row, timeout=config.REQUEST_TIMEOUT)
    if isinstance(r, dict) and r.get("error"):
        return r
    return {"data": [row]}


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
