"""Daily curated brief — cyber-intel.

Runs once a day at BRIEF_HOUR_UTC (05:00 UTC) as an in-process background task
(same shape as the aggregation loop). It queries the last 24h of vulnerability +
threat data, ranks by exploit-likelihood, packages the most significant items,
attests the package through MINT for verifiable provenance, and upserts it into
the `daily_briefs` table. The paid `daily_brief` tool just reads that row back.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import config
import mint_integration
import supa

logger = logging.getLogger("cyber.curator")

SERVER = config.SERVER_SLUG
PRICE = config.PRICE_DAILY_BRIEF


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _expires_at(date_str: str) -> str:
    d = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return (d + timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")


def related_briefs(exclude: str) -> list:
    return [{"server": s, "price": p, "tool": "daily_brief"}
            for s, p in config.NETWORK_BRIEFS.items() if s != exclude]


_VFIELDS = ("cve_id,description,published_date,cvss_v3_score,cvss_v3_severity,"
            "attack_vector,epss_score,epss_percentile,is_kev,kev_due_date")


async def _curate_signals(since_iso: str) -> tuple[dict, int]:
    """Build the cyber brief body from the last 24h. Returns (signals, count)."""
    # Critical CVEs in 24h with EPSS > 0.5 (high severity + high exploit likelihood).
    crit = await supa.select("vulnerabilities", {
        "select": _VFIELDS, "cvss_v3_severity": "eq.critical",
        "epss_score": "gt.0.5", "published_date": f"gte.{since_iso}",
        "order": "epss_score.desc.nullslast", "limit": "50"})
    critical_cves = [{"cve_id": r.get("cve_id"), "severity": r.get("cvss_v3_severity"),
                      "cvss": r.get("cvss_v3_score"), "epss": r.get("epss_score"),
                      "is_kev": r.get("is_kev"), "description": r.get("description")}
                     for r in crit]

    # CVEs newly added to CISA KEV in the last 24h.
    kev = await supa.select("vulnerabilities", {
        "select": _VFIELDS, "is_kev": "eq.true",
        "kev_due_date": "not.is.null", "published_date": f"gte.{since_iso}",
        "order": "epss_score.desc.nullslast", "limit": "50"})
    new_kev_additions = [{"cve_id": r.get("cve_id"), "severity": r.get("cvss_v3_severity"),
                          "cvss": r.get("cvss_v3_score"), "epss": r.get("epss_score"),
                          "kev_due_date": r.get("kev_due_date"),
                          "description": r.get("description")} for r in kev]

    # Top 5 most exploitable (highest EPSS) in 24h.
    exploit = await supa.select("vulnerabilities", {
        "select": _VFIELDS, "epss_score": "not.is.null",
        "published_date": f"gte.{since_iso}",
        "order": "epss_score.desc.nullslast", "limit": "5"})
    top_exploitable = [{"cve_id": r.get("cve_id"), "severity": r.get("cvss_v3_severity"),
                        "cvss": r.get("cvss_v3_score"), "epss": r.get("epss_score"),
                        "epss_percentile": r.get("epss_percentile"),
                        "is_kev": r.get("is_kev")} for r in exploit]

    # Active threat indicators (IPs/domains) seen in the last 24h.
    ind = await supa.select("threat_indicators", {
        "select": "indicator_type,indicator_value,threat_type,confidence,source,last_seen",
        "last_seen": f"gte.{since_iso}",
        "order": "confidence.desc.nullslast", "limit": "25"})
    active_threat_indicators = [{"type": r.get("indicator_type"), "value": r.get("indicator_value"),
                                 "threat_type": r.get("threat_type"), "confidence": r.get("confidence"),
                                 "source": r.get("source")} for r in ind]

    signals = {
        "critical_cves": critical_cves,
        "new_kev_additions": new_kev_additions,
        "top_exploitable": top_exploitable,
        "active_threat_indicators": active_threat_indicators,
    }
    count = (len(critical_cves) + len(new_kev_additions)
             + len(top_exploitable) + len(active_threat_indicators))
    return signals, count


async def run_curation(date_str: str | None = None) -> dict:
    """Generate, attest, and store today's brief. Idempotent per date (upsert)."""
    date_str = date_str or _today()
    since_iso = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    signals, count = await _curate_signals(since_iso)

    brief = {
        "brief_date": date_str, "server": SERVER, "signal_count": count,
        "signals": signals, "expires_at": _expires_at(date_str),
        "related_briefs": related_briefs(SERVER),
    }
    # Attest for provenance (sync httpx → run off the event loop; fail-open).
    attestation = await asyncio.to_thread(
        mint_integration.attest_data, brief, "analysis",
        f"Daily {SERVER} brief: {count} signals")
    brief["provenance"] = attestation

    row = {
        "brief_date": date_str, "brief_data": brief, "signal_count": count,
        "attestation_hash": attestation.get("attestation_hash"),
        "expires_at": _expires_at(date_str),
    }
    res = await supa.upsert("daily_briefs", [row], "brief_date")
    if isinstance(res, dict) and res.get("error"):
        logger.warning(f"daily brief upsert failed: {str(res)[:200]}")
    else:
        logger.info(f"daily brief stored: {date_str} ({count} signals, "
                    f"attested={attestation.get('mint_verified')})")
    return brief


async def get_brief(date_str: str | None = None) -> dict | None:
    """Read a stored brief; None if missing or expired."""
    date_str = date_str or _today()
    rows = await supa.select("daily_briefs",
                             {"select": "*", "brief_date": f"eq.{date_str}", "limit": "1"})
    if not rows:
        return None
    row = rows[0]
    exp = row.get("expires_at")
    if exp:
        try:
            if datetime.now(timezone.utc) >= datetime.fromisoformat(exp.replace("Z", "+00:00")):
                return None
        except Exception:  # noqa: BLE001
            pass
    return row.get("brief_data")


async def bump_purchase(date_str: str) -> None:
    """Best-effort purchase counter via RPC (no-op if the function is absent)."""
    try:
        await supa.rpc("increment_brief_purchase", {"p_brief_date": date_str})
    except Exception:  # noqa: BLE001
        pass


async def curator_loop() -> None:
    """Sleep until BRIEF_HOUR_UTC each day, then curate. Cancellable."""
    while True:
        now = datetime.now(timezone.utc)
        secs = now.hour * 3600 + now.minute * 60 + now.second
        wait = (config.BRIEF_HOUR_UTC * 3600 - secs) % 86400 or 86400
        try:
            await asyncio.sleep(wait)
            if supa.configured():
                await run_curation()
        except asyncio.CancelledError:
            break
        except Exception as e:  # noqa: BLE001
            logger.warning(f"curator loop error: {e}")
            await asyncio.sleep(3600)
