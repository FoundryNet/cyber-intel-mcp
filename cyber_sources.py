"""Free cybersecurity threat-intel sources + enrichment.

Vulnerabilities: NVD CVE 2.0 (keyless, throttled) enriched with EPSS exploit
probability + CISA KEV (known-exploited) + GitHub advisories. Threat indicators:
AbuseIPDB (IP reputation) + AlienVault OTX (IP/domain/pulse indicators). All async
via request_json; defensive.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import config
from http_util import request_json

logger = logging.getLogger("cyber.src")

_UA = {"User-Agent": config.SOURCE_USER_AGENT}
_AV = {"NETWORK": "network", "ADJACENT_NETWORK": "adjacent", "LOCAL": "local", "PHYSICAL": "physical"}


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


# ── CISA KEV ──────────────────────────────────────────────────────────────────
async def load_kev() -> dict:
    r = await request_json("GET", config.KEV_FEED, headers=_UA, timeout=max(config.REQUEST_TIMEOUT, 45))
    out = {}
    if isinstance(r, dict):
        for v in r.get("vulnerabilities", []):
            cid = v.get("cveID")
            if cid:
                out[cid] = v.get("dueDate")
    logger.info(f"KEV: {len(out)} known-exploited CVEs")
    return out


# ── NVD CVE ───────────────────────────────────────────────────────────────────
async def fetch_nvd(hours_back: int, max_pages: int = 6) -> list:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours_back)
    headers = dict(_UA)
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY
    rows, idx = [], 0
    for page in range(max_pages):
        params = {"lastModStartDate": _iso(start), "lastModEndDate": _iso(end),
                  "resultsPerPage": "2000", "startIndex": str(idx)}
        # NVD is flaky keyless (intermittent 503/429) — retry with backoff.
        r = None
        for attempt in range(4):
            r = await request_json("GET", config.NVD_API, headers=headers, params=params,
                                   timeout=max(config.REQUEST_TIMEOUT, 60))
            if isinstance(r, dict) and "vulnerabilities" in r:
                break
            err = r.get("error") if isinstance(r, dict) else str(r)
            logger.info(f"NVD page {page} attempt {attempt + 1} retry ({err}); backing off")
            await asyncio.sleep(8 + attempt * 6)
        if not isinstance(r, dict) or "vulnerabilities" not in r:
            logger.warning(f"NVD page {page} failed after retries: {str(r)[:160]}")
            break
        batch = r.get("vulnerabilities", [])
        for item in batch:
            m = _map_cve(item.get("cve") or {})
            if m:
                rows.append(m)
        total = r.get("totalResults", 0)
        idx += len(batch)
        logger.info(f"NVD page {page + 1}: +{len(batch)} ({idx}/{total})")
        if idx >= total or not batch:
            break
        if not config.NVD_API_KEY:
            await asyncio.sleep(6)  # keyless: 5 req/30s
    logger.info(f"NVD: {len(rows)} CVEs in last {hours_back}h")
    return rows


def _map_cve(cve: dict) -> dict | None:
    cid = cve.get("id")
    if not cid:
        return None
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", ""); break
    metrics = cve.get("metrics") or {}
    cvss = None
    for k in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(k):
            cvss = metrics[k][0]; break
    score = sev = vector = av = ac = None
    if cvss:
        cd = cvss.get("cvssData") or {}
        score = cd.get("baseScore")
        sev = (cd.get("baseSeverity") or "").lower() or None
        vector = cd.get("vectorString")
        av = _AV.get(cd.get("attackVector"))
        ac = (cd.get("attackComplexity") or "").lower() or None
    elif metrics.get("cvssMetricV2"):
        cd = metrics["cvssMetricV2"][0]
        score = (cd.get("cvssData") or {}).get("baseScore")
        sev = (cd.get("baseSeverity") or "").lower() or None
    cwe_id = None
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if (d.get("value") or "").startswith("CWE-"):
                cwe_id = d["value"]; break
        if cwe_id:
            break
    products = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                c = cm.get("criteria")
                if c and c not in products:
                    products.append(c)
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    patch = any("patch" in (t or "").lower() for r in cve.get("references", []) for t in (r.get("tags") or []))
    return {
        "cve_id": cid, "description": desc, "published_date": cve.get("published"),
        "modified_date": cve.get("lastModified"), "cvss_v3_score": score,
        "cvss_v3_severity": sev, "cvss_v3_vector": vector, "attack_vector": av,
        "attack_complexity": ac, "cwe_id": cwe_id, "cwe_name": None,
        "affected_products": products[:50] or None, "reference_urls": refs[:30] or None,
        "patch_available": patch,
    }


# ── EPSS enrichment ───────────────────────────────────────────────────────────
async def enrich_epss(cve_ids: list) -> dict:
    out = {}
    for i in range(0, len(cve_ids), 100):
        chunk = cve_ids[i:i + 100]
        r = await request_json("GET", config.EPSS_API, headers=_UA,
                               params={"cve": ",".join(chunk)}, timeout=config.REQUEST_TIMEOUT)
        if isinstance(r, dict):
            for d in r.get("data", []):
                cid = d.get("cve")
                if cid:
                    out[cid] = {"epss": _f(d.get("epss")), "percentile": _f(d.get("percentile"))}
    return out


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ── GitHub Advisory DB (supplementary; CVE-bearing only) ─────────────────────
async def fetch_ghsa(per_page: int = 100) -> list:
    headers = {"Accept": "application/vnd.github+json", **_UA}
    r = await request_json("GET", config.GHSA_API, headers=headers,
                           params={"per_page": str(per_page), "sort": "published", "direction": "desc"},
                           timeout=config.REQUEST_TIMEOUT)
    rows = []
    if isinstance(r, list):
        for a in r:
            cid = a.get("cve_id")
            if not cid:
                continue
            rows.append({"cve_id": cid, "description": (a.get("summary") or "")[:1000],
                         "cvss_v3_severity": (a.get("severity") or "").lower() or None,
                         "reference_urls": [a.get("html_url")] if a.get("html_url") else None})
    logger.info(f"GHSA: {len(rows)} CVE-bearing advisories")
    return rows


# ── AbuseIPDB + OTX (threat indicators) ──────────────────────────────────────
_ABUSE_CATS = {4: "ddos", 5: "ftp_bruteforce", 14: "port_scan", 15: "hacking",
               18: "brute_force", 19: "bad_web_bot", 20: "exploited_host",
               21: "web_app_attack", 22: "ssh", 23: "iot_targeted", 9: "open_proxy",
               10: "web_spam", 11: "email_spam"}


async def check_ip(ip: str) -> dict:
    out = {"indicator_value": ip, "indicator_type": "ip", "sources": [], "indicators": []}
    # AbuseIPDB
    if config.ABUSEIPDB_API_KEY:
        r = await request_json("GET", config.ABUSEIPDB_API,
                               headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                               params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
                               timeout=config.REQUEST_TIMEOUT)
        d = r.get("data") if isinstance(r, dict) else None
        if d:
            out["sources"].append("abuseipdb")
            ttype = "scanner" if d.get("usageType") else None
            out["indicators"].append({
                "indicator_type": "ip", "indicator_value": ip, "source": "abuseipdb",
                "confidence": d.get("abuseConfidenceScore"),
                "threat_type": _abuse_threat(d), "report_count": d.get("totalReports"),
                "last_seen": d.get("lastReportedAt"),
                "tags": {"isp": d.get("isp"), "country": d.get("countryCode"),
                         "domain": d.get("domain"), "usage": d.get("usageType")}})
    # OTX
    if config.OTX_API_KEY:
        r = await request_json("GET", f"{config.OTX_API}/IPv4/{ip}/general",
                               headers={"X-OTX-API-KEY": config.OTX_API_KEY},
                               timeout=config.REQUEST_TIMEOUT)
        if isinstance(r, dict) and "pulse_info" in r:
            out["sources"].append("otx")
            pc = (r.get("pulse_info") or {}).get("count", 0)
            tags = [p.get("name") for p in (r.get("pulse_info") or {}).get("pulses", [])[:10]]
            out["indicators"].append({
                "indicator_type": "ip", "indicator_value": ip, "source": "otx",
                "confidence": min(pc * 10, 100), "threat_type": "malware" if pc else None,
                "report_count": pc, "tags": {"pulses": tags, "reputation": r.get("reputation")}})
    return out


def _abuse_threat(d: dict):
    cats = []
    for rep in (d.get("reports") or [])[:50]:
        cats.extend(rep.get("categories") or [])
    if not cats:
        return "scanner"
    from collections import Counter
    top = Counter(cats).most_common(1)[0][0]
    return _ABUSE_CATS.get(top, "scanner")


async def check_domain(domain: str) -> dict:
    out = {"indicator_value": domain, "indicator_type": "domain", "sources": [], "indicators": []}
    if config.OTX_API_KEY:
        r = await request_json("GET", f"{config.OTX_API}/domain/{domain}/general",
                               headers={"X-OTX-API-KEY": config.OTX_API_KEY},
                               timeout=config.REQUEST_TIMEOUT)
        if isinstance(r, dict) and "pulse_info" in r:
            out["sources"].append("otx")
            pc = (r.get("pulse_info") or {}).get("count", 0)
            tags = [p.get("name") for p in (r.get("pulse_info") or {}).get("pulses", [])[:10]]
            out["indicators"].append({
                "indicator_type": "domain", "indicator_value": domain, "source": "otx",
                "confidence": min(pc * 10, 100), "threat_type": "phishing" if pc else None,
                "report_count": pc, "tags": {"pulses": tags}})
    return out


async def fetch_otx_pulses(limit_pulses: int = 20) -> list:
    """Recent OTX pulse indicators → threat_indicators rows (seeds threat_feed)."""
    if not config.OTX_API_KEY:
        return []
    r = await request_json("GET", f"{config.OTX_API.replace('/indicators','')}/pulses/subscribed",
                           headers={"X-OTX-API-KEY": config.OTX_API_KEY},
                           params={"limit": str(limit_pulses)}, timeout=max(config.REQUEST_TIMEOUT, 45))
    rows = []
    results = r.get("results") if isinstance(r, dict) else None
    if not results:
        return []
    _tmap = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
             "URL": "url", "FileHash-MD5": "hash", "FileHash-SHA256": "hash", "FileHash-SHA1": "hash"}
    for pulse in results:
        name = pulse.get("name", "")
        tags = pulse.get("tags") or []
        created = pulse.get("created")
        for ind in (pulse.get("indicators") or [])[:50]:
            itype = _tmap.get(ind.get("type"))
            if not itype:
                continue
            rows.append({"indicator_type": itype, "indicator_value": ind.get("indicator"),
                         "source": "otx", "threat_type": _pulse_threat(name + " " + " ".join(tags)),
                         "confidence": 60, "first_seen": created, "last_seen": created,
                         "report_count": 1, "tags": {"pulse": name, "tags": tags[:8]}})
    logger.info(f"OTX pulses: {len(rows)} indicators from {len(results)} pulses")
    return rows


def _pulse_threat(text: str) -> str:
    t = text.lower()
    for kw, tt in (("phish", "phishing"), ("botnet", "botnet"), ("scan", "scanner"),
                   ("spam", "spam"), ("ransom", "malware"), ("malware", "malware"),
                   ("trojan", "malware"), ("c2", "botnet"), ("apt", "malware")):
        if kw in t:
            return tt
    return "malware"
