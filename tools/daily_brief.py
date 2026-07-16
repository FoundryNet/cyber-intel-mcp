from typing import Optional

import core
import identity


def register(mcp) -> None:
    @mcp.tool
    async def daily_brief(
        date: Optional[str] = None,
        agent_id: Optional[str] = None,
        payment_tx: Optional[str] = None,
        stripe_token: Optional[str] = None,
    ) -> dict:
        """Get the curated daily threat-intelligence brief — the day's most
        significant signals in one package: critical CVEs with high EPSS
        exploit-prediction, new CISA KEV additions, the most-exploitable
        vulnerabilities, and active threat indicators. Threat intel from NVD, CISA
        KEV, EPSS, GHSA, AbuseIPDB, and OTX. Each brief carries verifiable
        provenance so a buyer can confirm it was produced by this server, unaltered.

        PAID: $15 per brief. Defaults to today (UTC); a brief expires at the
        next midnight UTC. On a 402, settle the returned payment request and re-call with
        the SAME args plus payment_tx=<reference>. An Authorization: Bearer fnet_
        key bypasses payment.

        Args:
            date: brief date YYYY-MM-DD (default today, UTC).
            agent_id: stable id for your agent (scopes the free-tier counter).
            payment_tx: payment transaction reference, when re-calling after a 402.
            stripe_token: Stripe Checkout Session id (cs_…), when re-calling after
                paying the Stripe payment link (alternative to the metered rail). Can
                also be supplied via the X-Stripe-Token header.
        """
        return await core.do_daily_brief(
            date, agent_key=identity.resolve_agent_key(agent_id),
            payment_tx=payment_tx, api_key=identity.bearer(),
            stripe_token=stripe_token or identity.stripe_token())
