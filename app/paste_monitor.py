"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

"""
Paste / Leak Monitoring Module
- Primary: LeakCheck.io public API (free, reliable paste/leak search)
- Fallback: DuckDuckGo HTML → Pastebin links (with rotation & polite delays)
- Checks company keywords/emails from .env
- Fetches raw content and saves relevant matches to DB
"""

import requests
import time
import random
from urllib.parse import quote
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Load .env (safe even if config.py already loads it)
load_dotenv()

from .database import conn
from .config import PASTE_SEARCH_TERMS, USER_AGENTS

# Primary free paste/leak search
LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"

# Fallback: DDG HTML for Pastebin
DUCKDUCKGO_HTML_URL = "https://html.duckduckgo.com/html/"

def search_leakcheck_public(term: str):
    """Primary free search using LeakCheck.io public endpoint"""
    print(f"  → Searching LeakCheck for '{term}'...")
    try:
        params = {
            "query": term,
            "type": "auto"  # auto detects email/username/domain/etc.
        }
        headers = {
            "User-Agent": random.choice(USER_AGENTS) if USER_AGENTS else "Mozilla/5.0 (compatible; CTICollector/1.0)"
        }
        r = requests.get(LEAKCHECK_PUBLIC_URL, params=params, headers=headers, timeout=12)
        
        print(f"    LeakCheck status: {r.status_code}")
        if r.status_code != 200:
            return []

        data = r.json()
        if not data.get("found", False):
            print(f"    No results from LeakCheck")
            return []

        # Extract links (LeakCheck sometimes returns URLs directly)
        links = []
        for entry in data.get("data", [])[:10]:
            if "url" in entry and "pastebin.com" in entry["url"].lower():
                links.append(entry["url"])
            elif "paste" in entry.get("source", "").lower():
                # Fallback: construct possible paste link if ID present
                paste_id = entry.get("id") or entry.get("paste_id")
                if paste_id:
                    links.append(f"https://pastebin.com/{paste_id}")

        print(f"    Found {len(links)} potential paste links from LeakCheck")
        return links

    except Exception as e:
        print(f"[!] LeakCheck failed for '{term}': {e}")
        return []


def search_pastebin_public(term: str):
    """Fallback: Aggressive Pastebin search via DuckDuckGo"""
    print(f"  → Running Pastebin fallback search for '{term}'...")
    paste_links = set()

    queries = [
        f'site:pastebin.com "{term}"',
        f'site:pastebin.com {term}',
        f'site:pastebin.com intext:"{term}"',
    ]
    if "@" in term:
        user, domain = term.split("@")
        queries.extend([
            f'site:pastebin.com "{user}"',
            f'site:pastebin.com "{domain}"',
        ])

    for query in queries:
        try:
            headers = {
                "User-Agent": random.choice(USER_AGENTS) if USER_AGENTS else "Mozilla/5.0 ...",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
            params = {"q": query}
            r = requests.get(DUCKDUCKGO_HTML_URL, params=params, headers=headers, timeout=15)

            print(f"    Query '{query}' → status {r.status_code}")
            if r.status_code != 200:
                time.sleep(random.uniform(4, 10))
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            results = soup.find_all("a", class_="result__a")

            for link_tag in results[:8]:
                href = link_tag.get("href", "")
                if not href:
                    continue

                if "uddg=" in href:
                    clean_url = href.split("uddg=")[-1].split("&rut=")[0]
                else:
                    clean_url = href

                if "pastebin.com" in clean_url and clean_url not in paste_links:
                    paste_links.add(clean_url)
                    print(f"      Found: {clean_url}")

        except Exception as e:
            print(f"    [!] Query failed: {e}")

        time.sleep(random.uniform(4, 8))  # longer delay to avoid blocks

    print(f"    → Found {len(paste_links)} unique Pastebin links")
    return list(paste_links)


def fetch_paste_content(url: str):
    """Fetch raw paste content"""
    try:
        if "pastebin.com" in url and "/raw/" not in url:
            raw_url = url.replace("pastebin.com/", "pastebin.com/raw/")
        else:
            raw_url = url

        headers = {"User-Agent": random.choice(USER_AGENTS) if USER_AGENTS else "Mozilla/5.0 ..."}
        r = requests.get(raw_url, headers=headers, timeout=8)
        if r.status_code == 200:
            return r.text
        print(f"[!] Raw fetch failed {raw_url}: {r.status_code}")
        return ""
    except Exception as e:
        print(f"[!] Content fetch error {url}: {e}")
        return ""


def monitor_pastes():
    """Main monitoring loop"""
    print("[+] Starting paste/leak monitoring...")

    terms = PASTE_SEARCH_TERMS
    print(f"  Loaded {len(terms)} search terms: {terms}")

    if not terms:
        print("[!] No PASTE_SEARCH_TERMS — check .env and config.py")
        return

    for term in terms:
        print(f"\n  Searching: {term}")

        # Primary: LeakCheck public
        dump_links = search_leakcheck_public(term)

        # Fallback: Pastebin via DDG
        if not dump_links:
            print("  → No results from LeakCheck → using Pastebin fallback")
            dump_links = search_pastebin_public(term)

        processed = 0
        for link in dump_links[:8]:  # limit per term
            if not link or "pastebin.com" not in link:
                continue

            content = fetch_paste_content(link)
            if not content:
                continue

            matched = [k for k in terms if k.lower() in content.lower()]
            if matched:
                title = f"Paste leak: {link.split('/')[-1]} (match: {matched[0]})"
                summary = content[:500] + ("..." if len(content) > 500 else "")

                exists = conn.execute("SELECT id FROM articles WHERE link = ?", (link,)).fetchone()
                if not exists:
                    iso_utc = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO articles (title, summary, link, category, date)
                        VALUES (?, ?, ?, 'paste_monitor', ?)
                        """,
                        (title, summary, link, iso_utc)
                    )
                    conn.commit()
                    print(f"[+] PASTE LEAK HIT: {link} — keywords: {matched}")
                    processed += 1

            time.sleep(3.0)  # gentle per-link delay

        if processed == 0:
            print(f"  No relevant pastes found for '{term}'")

        time.sleep(6.0)  # delay between terms

    print("[+] Paste/leak monitoring complete")


if __name__ == "__main__":
    monitor_pastes()