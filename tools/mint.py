import core


def register(mcp) -> None:
    @mcp.tool
    async def mint_info() -> dict:
        """Get FoundryNet Data Network info and result-provenance details. FREE.

        Returns how this server attaches verifiable provenance to your agent's
        security/threat-intelligence analysis, plus the sister data servers
        (gov-contracts, brand-intel, patent-intel, financial-signals, weather-intel,
        compliance, academic-intel, fact-check, oss-intel, social-intel).
        """
        return core.mint_info()
