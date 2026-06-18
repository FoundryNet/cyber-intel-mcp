#!/usr/bin/env python3
"""threat_aggregator — every 6h. Pulls new/modified CVEs (NVD), enriches with EPSS
exploit probability + CISA KEV (known-exploited) flags, folds in GitHub advisories,
and upserts into Supabase vulnerabilities. Also pulls recent OTX pulse indicators
into threat_indicators (the threat_feed).

Manual entry point:
  python threat_aggregator.py            # last LOOKBACK_HOURS
  python threat_aggregator.py 168        # last 7 days (backfill)
"""
from __future__ import annotations

import asyncio
import logging
import sys

import config
import cyber_sources as src
import supa

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cyber.agg")


async def run_aggregation(hours_back: int | None = None) -> dict:
    hours = hours_back or config.LOOKBACK_HOURS

    kev = await src.load_kev()
    vulns = await src.fetch_nvd(hours)
    by_id = {v["cve_id"]: v for v in vulns}

    # GHSA: only CVEs not already from NVD (don't clobber NVD's richer record).
    for g in await src.fetch_ghsa():
        if g["cve_id"] not in by_id:
            by_id[g["cve_id"]] = g

    # EPSS for the whole set.
    epss = await src.enrich_epss(list(by_id.keys()))
    for cid, v in by_id.items():
        e = epss.get(cid) or {}
        v["epss_score"] = e.get("epss")
        v["epss_percentile"] = e.get("percentile")
        if cid in kev:
            v["is_kev"] = True
            v["kev_due_date"] = kev[cid]
        else:
            v["is_kev"] = False

    written_v = await supa.upsert_vulns(list(by_id.values()))
    log.info(f"vulnerabilities: upserted {written_v}")

    pulses = await src.fetch_otx_pulses()
    written_i = await supa.upsert_indicators(pulses)
    log.info(f"threat_indicators: upserted {written_i}")

    out = {"cves": len(by_id), "vulns_written": written_v, "indicators_written": written_i,
           "kev_total": len(kev)}
    log.info(f"done: {out}")
    return out


async def main() -> None:
    args = [a for a in sys.argv[1:] if a.strip()]
    hours = int(args[0]) if args and args[0].isdigit() else None
    print(await run_aggregation(hours))


if __name__ == "__main__":
    asyncio.run(main())
