"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

# -----------------------------
# FEEDS
# -----------------------------

FEEDS = {
    "General News": [
        "https://thehackernews.com/feeds/posts/default",
        "https://www.bleepingcomputer.com/feed/",
        "https://www.darkreading.com/rss.xml",
        "https://www.securityweek.com/feed",
        "https://krebsonsecurity.com/feed/",
        "https://www.scmagazine.com/home/feed"
    ],

    "Vulnerabilities": [
        "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://www.zerodayinitiative.com/rss/published/",
        "https://www.exploit-db.com/rss.xml"
    ],

    "Threat Intel": [
        "https://isc.sans.edu/rssfeed.xml",
        "https://bazaar.abuse.ch/rss/",
        "https://threatfox.abuse.ch/rss/"
    ],

    "Research Blogs": [
        "https://www.crowdstrike.com/blog/feed/",
        "https://www.mandiant.com/resources/blog/rss.xml",
        "https://unit42.paloaltonetworks.com/feed/",
        "https://www.microsoft.com/en-us/security/blog/feed/",
        "https://googleprojectzero.blogspot.com/feeds/posts/default"
    ],

    "Malware Research": [
        "https://securelist.com/feed/",
        "https://blog.talosintelligence.com/feeds/posts/default",
        "https://www.proofpoint.com/us/rss.xml",
        "https://research.checkpoint.com/feed/",
        "https://www.recordedfuture.com/feed"
    ]
}

# KEV JSON feed
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
