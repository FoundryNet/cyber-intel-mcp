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
        """All known vulnerabilities affecting a product/vendor/CPE, sorted by EPSS
        (exploit likelihood) with KEV flags — the "should I be worried about this
        dependency?" tool. Premium.

        PAID: $0.02 USDC per query after the daily free allowance (25/day). On a
        402, pay the returned Solana memo and re-call with the SAME args plus
        payment_tx=<signature>. An Authorization: Bearer fnet_ key bypasses it.

        Args:
            product_name: product/library/software name, e.g. "log4j".
            vendor: vendor name, e.g. "apache".
            cpe: a CPE string to match exactly.
            agent_id: stable id for your agent (scopes the free-tier counter).
            payment_tx: Solana tx signature, when re-calling after a 402.
        """
        return await core.do_scan(product_name, vendor, cpe,
                                  agent_key=identity.resolve_agent_key(agent_id),
                                  payment_tx=payment_tx, api_key=identity.bearer())
