import core


def register(mcp) -> None:
    @mcp.tool
    async def cve_detail(cve_id: str) -> dict:
        """Full record for a single CVE — CVSS v3 breakdown (score/severity/vector/
        attack vector/complexity), EPSS exploit probability + percentile, CISA KEV
        status + due date, CWE, affected products, and references. FREE.

        Args:
            cve_id: e.g. "CVE-2021-44228".
        """
        return await core.do_cve_detail(cve_id)
