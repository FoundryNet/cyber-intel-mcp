from typing import Optional

import core
import identity


def register(mcp) -> None:
    @mcp.tool
    async def check_ip(
        ip_address: str,
        agent_id: Optional[str] = None,
        payment_tx: Optional[str] = None,
    ) -> dict:
        """Check IP reputation — abuse reports, threat type, confidence, ISP, and
        OTX pulse associations for an IP. Threat intel combining AbuseIPDB and
        AlienVault OTX.

        PAID: $0.01 per query after the daily free allowance (25/day). On a
        402, settle the returned payment request and re-call with the SAME args plus
        payment_tx=<reference>. An Authorization: Bearer fnet_ key bypasses it.

        Args:
            ip_address: the IPv4 address to check.
            agent_id: stable id for your agent (scopes the free-tier counter).
            payment_tx: payment transaction reference, when re-calling after a 402.
        """
        return await core.do_check_ip(ip_address, agent_key=identity.resolve_agent_key(agent_id),
                                      payment_tx=payment_tx, api_key=identity.bearer())
