"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""


import feedparser
from .database import conn
from .config import KEYWORDS, COMPANY_NAME, COMPANY_DOMAIN

PHISHING_FEEDS = [
    "https://openphish.com/feed.txt",           # high quality
    "https://openphish.com/alerts.xml",
    "https://phishing-tracker.abuse.ch/feeds/rss/",
    "https://www.cert.pl/feeds/rss/phishing",
    "https://www.darkreading.com/rss_simple.asp",
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",

    # CERT / national CSIRT phishing reports
    "https://www.cert.pl/feeds/rss/phishing",                           # Polish CERT – very active phishing feed
    "https://www.cert.at/static/rss/cert.at_phishing.xml",              # Austrian CERT phishing
    "https://www.belgium.be/fr/rss/phishing.xml",                       # Belgian government phishing alerts (sometimes)
    "https://www.ncsc.gov.uk/collection/phishing/rss",                  # UK NCSC phishing alerts RSS (if active)
    
    # Security blogs & threat intel that publish frequent phishing reports
    "https://www.darkreading.com/rss_simple.asp",                       # Dark Reading (filter later for phishing)
    "https://krebsonsecurity.com/feed/",                                # Krebs on Security – often covers big phishing campaigns
    "https://www.bleepingcomputer.com/feed/",                           # BleepingComputer RSS
    "https://threatpost.com/feed/",                                     # Threatpost RSS
    "https://www.malwarebytes.com/blog/feed",                           # Malwarebytes blog RSS
    
    # Brand & domain-specific phishing monitoring (commercial / free tiers)
    "https://phishstats.info:2096/feed/rss",                            # PhishStats RSS (community phishing tracker)
    "https://phishtank.org/developer_info.php",                         # PhishTank – has RSS but limited; use API instead if possible
    
    # Generic security news aggregators that frequently mention phishing
    "https://feeds.feedburner.com/TheHackersNews",                      # The Hacker News
    "https://securityaffairs.com/feed",                                 # Security Affairs
    "https://www.schneier.com/feed/atom/",                              # Schneier on Security
]

def keyword_match(text: str) -> bool:
    """Check if any company keyword appears in the text (case-insensitive)."""
    text = text.lower()
    return any(k.lower() in text for k in KEYWORDS)


def detect_phishing():
    """
    Collect phishing feeds.
    
    - All entries → saved as 'global_phishing' (visible in Global CTI)
    - Only company-relevant entries → saved as 'phishing_monitor' (visible in Company Intelligence)
    """
    for url in PHISHING_FEEDS:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:10]:  # Increased limit to capture more
                title = getattr(entry, "title", "")
                summary = getattr(entry, "summary", getattr(entry, "description", ""))
                link = getattr(entry, "link", "")
                content = title + " " + summary

                # 1. Always save to global phishing category
                exists_global = conn.execute(
                    "SELECT id FROM articles WHERE title = ? AND category = 'global_phishing'",
                    (title,)
                ).fetchone()

                if not exists_global:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO articles (title, summary, link, category, date)
                        VALUES (?, ?, ?, 'global_phishing', datetime('now'))
                        """,
                        (title, summary[:500], link)
                    )
                    conn.commit()
                    print(f"[+] Global phishing saved: {title[:60]}...")

                # 2. Save to company-specific category only if keyword match
                if keyword_match(content):
                    exists_company = conn.execute(
                        "SELECT id FROM articles WHERE title = ? AND category = 'phishing_monitor'",
                        (title,)
                    ).fetchone()

                    if not exists_company:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO articles (title, summary, link, category, date)
                            VALUES (?, ?, ?, 'phishing_monitor', datetime('now'))
                            """,
                            (title, summary[:500], link)
                        )
                        conn.commit()
                        print(f"[+] COMPANY-RELEVANT PHISHING HIT: {title[:60]}...")

        except Exception as e:
            print(f"[!] Phishing feed error {url}: {e}")


# Optional: call this function directly for testing
if __name__ == "__main__":
    detect_phishing()