from typing import Optional

import core
import identity


def register(mcp) -> None:
    @mcp.tool
    async def vulnerability_scan(
        product_name: Optional[str] = None,
        vendor: Optional[str] = None,
        cpe: Optional[str] = None,
        agent_id: Optional[str] = None,
        payment_tx: Optional[str] = None,
    ) -> dict:
        """Scan a product/vendor/CPE for all known vulnerabilities, sorted by EPSS
        exploit-prediction likelihood with CISA KEV flags — the "should I be worried
        about this dependency?" security scanning tool. Threat intel from NVD, EPSS,
        CISA KEV, and GHSA. Premium.

        PAID: $0.02 per query after the daily free allowance (25/day). On a
        402, settle the returned payment request and re-call with the SAME args plus
        payment_tx=<reference>. An Authorization: Bearer fnet_ key bypasses it.

        Args:
            product_name: product/library/software name, e.g. "log4j".
            vendor: vendor name, e.g. "apache".
            cpe: a CPE string to match exactly.
            agent_id: stable id for your agent (scopes the free-tier counter).
            payment_tx: payment transaction reference, when re-calling after a 402.
        """
        return await core.do_scan(product_name, vendor, cpe,
                                  agent_key=identity.resolve_agent_key(agent_id),
                                  payment_tx=payment_tx, api_key=identity.bearer())
