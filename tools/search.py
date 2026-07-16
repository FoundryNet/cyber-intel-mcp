from typing import Optional

import core
import identity


def register(mcp) -> None:
    @mcp.tool
    async def search_cve(
        keyword: Optional[str] = None,
        severity: Optional[str] = None,
        min_cvss: Optional[float] = None,
        min_epss: Optional[float] = None,
        attack_vector: Optional[str] = None,
        days_back: Optional[int] = None,
        is_kev: Optional[bool] = None,
        limit: int = 50,
        agent_id: Optional[str] = None,
        payment_tx: Optional[str] = None,
    ) -> dict:
        """Search CVEs in the vulnerability database by keyword, CVSS severity/score,
        EPSS exploit-prediction likelihood, attack vector, recency, or CISA KEV
        status. Returns CVSS, EPSS, KEV flag, and affected products, newest first.
        Threat intel from NVD, EPSS, CISA KEV, and GHSA.

        PAID: $0.01 per query after a daily free allowance (25/day). On a 402,
        settle the returned payment request and re-call with the SAME args plus
        payment_tx=<reference>. agent_id scopes your allowance; an Authorization:
        Bearer fnet_ key bypasses it.

        Args:
            keyword: text matched against the CVE description.
            severity: critical | high | medium | low.
            min_cvss: minimum CVSS v3 base score (0-10).
            min_epss: minimum EPSS exploit probability (0-1).
            attack_vector: network | adjacent | local | physical.
            days_back: only CVEs published in the last N days.
            is_kev: true → only CISA Known-Exploited Vulnerabilities.
            limit: max rows (1-200, default 50).
            agent_id: stable id for your agent (scopes the free-tier counter).
            payment_tx: payment transaction reference, when re-calling after a 402.
        """
        filters = {"keyword": keyword, "severity": severity, "min_cvss": min_cvss,
                   "min_epss": min_epss, "attack_vector": attack_vector, "days_back": days_back,
                   "is_kev": is_kev, "limit": limit}
        return await core.do_search(filters, agent_key=identity.resolve_agent_key(agent_id),
                                    payment_tx=payment_tx, api_key=identity.bearer())
