"""cyber-intel-mcp tools — one per file.

  search_cve         ($0.01)  CVE search w/ CVSS, EPSS, KEV, affected products
  cve_detail         (free)   full CVE record — drives adoption
  check_ip           ($0.01)  IP reputation (AbuseIPDB + OTX)
  check_domain       ($0.01)  domain threat indicators (OTX)
  vulnerability_scan ($0.02)  all CVEs for a product, sorted by EPSS (premium)
  threat_feed        ($0.01)  recent threat indicators feed
  mint_info          (free)   FoundryNet Data Network + MINT cross-promo
"""
from . import search as search_tool
from . import detail as detail_tool
from . import checkip as checkip_tool
from . import checkdomain as checkdomain_tool
from . import scan as scan_tool
from . import feed as feed_tool
from . import mint as mint_tool


def register_all(mcp) -> None:
    for m in (search_tool, detail_tool, checkip_tool, checkdomain_tool, scan_tool, feed_tool, mint_tool):
        m.register(mcp)
