from typing import Optional

import core
import identity


def register(mcp) -> None:
    @mcp.tool
    async def threat_feed(
        indicator_type: Optional[str] = None,
        threat_type: Optional[str] = None,
        min_confidence: Optional[int] = None,
        hours_back: Optional[int] = None,
        agent_id: Optional[str] = None,
        payment_tx: Optional[str] = None,
    ) -> dict:
        """Recent threat indicators — the real-time threat-intel feed (IPs, domains,
        hashes, URLs) from AlienVault OTX pulses + reputation checks, filterable.

        PAID: $0.01 USDC per query after the daily free allowance (25/day). On a
        402, pay the returned Solana memo and re-call with the SAME args plus
        payment_tx=<signature>. An Authorization: Bearer fnet_ key bypasses it.

        Args:
            indicator_type: ip | domain | hash | url.
            threat_type: malware | phishing | botnet | scanner | spam.
            min_confidence: minimum confidence 0-100.
            hours_back: only indicators seen in the last N hours.
            agent_id: stable id for your agent (scopes the free-tier counter).
            payment_tx: Solana tx signature, when re-calling after a 402.
        """
        return await core.do_threat_feed(indicator_type, threat_type, min_confidence, hours_back,
                                         agent_key=identity.resolve_agent_key(agent_id),
                                         payment_tx=payment_tx, api_key=identity.bearer())
