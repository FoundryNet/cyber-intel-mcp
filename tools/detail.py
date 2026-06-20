import core


def register(mcp) -> None:
    @mcp.tool
    async def cve_detail(cve_id: str) -> dict:
        """Get the full record for a single CVE from the vulnerability database —
        CVSS v3 breakdown (score/severity/vector/attack vector/complexity), EPSS
        exploit-prediction probability + percentile, CISA KEV status + due date,
        CWE, affected products, and references. Sources: NVD, EPSS, CISA KEV, GHSA.
        FREE.

        Args:
            cve_id: e.g. "CVE-2021-44228".
        """
        return await core.do_cve_detail(cve_id)
