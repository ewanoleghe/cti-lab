"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

import shodan
from .database import conn
from .config import SHODAN_API_KEY, COMPANY_DOMAIN

api = shodan.Shodan(SHODAN_API_KEY)

def monitor_shodan():

    if not SHODAN_API_KEY:
        print("[!] Missing SHODAN_API_KEY in .env")
        return

    try:
        results = api.search(COMPANY_DOMAIN)

        for r in results['matches']:

            title = f"Shodan: {r['ip_str']} open port {r.get('port','')}"

            exists = conn.execute(
                "SELECT id FROM articles WHERE title=?",
                (title,)
            ).fetchone()

            if not exists:

                conn.execute(
                    "INSERT INTO articles(title,summary,category,link) VALUES(?,?,?,?)",
                    (
                        title,
                        str(r)[:500],
                        "shodan_monitor",
                        f"https://www.shodan.io/host/{r['ip_str']}"
                    )
                )

                conn.commit()

        print(f"[+] Shodan results: {len(results['matches'])}")

    except Exception as e:
        print(f"[!] Shodan error: {e}")