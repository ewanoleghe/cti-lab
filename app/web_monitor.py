"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

"""
Company CTI Web Mention & Leak Monitoring
- Searches news, security blogs, forums, and paste-related terms
- Looks for company keywords, domain variations, paste terms
- Checks emails only in suspicious/leak contexts
- Saves unique relevant mentions to SQLite using ISO 8601 UTC dates
"""

import requests
from bs4 import BeautifulSoup
import time
import random
from urllib.parse import quote, urljoin, urlparse
import re
from datetime import datetime, timezone, timedelta
import hashlib
import os

# ─── Load environment variables ──────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

# ─── Helpers for env parsing ────────────────────────────────────────────────
def ensure_list(obj):
    """Safely convert string or list to a clean list of strings."""
    if isinstance(obj, str):
        return [line.strip() for line in obj.splitlines() if line.strip()]
    elif isinstance(obj, list):
        return [str(item).strip() for item in obj if str(item).strip()]
    else:
        return []

# ─── Configuration ──────────────────────────────────────────────────────────
SAFE_DOMAINS = set(
    d.strip().lower()
    for d in os.getenv("SAFE_DOMAINS", "").split(",")
    if d.strip()
)

# Load numbered LEAK_CONTEXT_PATTERNS_1, _2, ...
LEAK_CONTEXT_PATTERNS = []
i = 1
while True:
    key = f"LEAK_CONTEXT_PATTERNS_{i}"
    pattern = os.getenv(key)
    if not pattern:
        break
    LEAK_CONTEXT_PATTERNS.append(pattern.strip())
    i += 1

# Fallback if nothing in .env
if not LEAK_CONTEXT_PATTERNS:
    LEAK_CONTEXT_PATTERNS = [
        r'\b(leak|leaked|dumps?|dumped|breach|breached|paste|pastebin|psbdmp|exposed|exposure|'
        r'credential|credentials|password|passwords|combo|combolist|steal|stolen|'
        r'hack|hacked|hacker|database|databases|dark ?web|telegram|forum|onion)\b',
    ]

# ─── Import project config ───────────────────────────────────────────────────
from .database import conn
from .config import (
    KEYWORDS,
    COMPANY_EMAILS,
    PASTE_SEARCH_TERMS,
    COMPANY_DOMAIN,
    USER_AGENTS,
)

# Ensure clean lists
KEYWORDS_LIST = ensure_list(KEYWORDS)
PASTE_TERMS_LIST = ensure_list(PASTE_SEARCH_TERMS)
COMPANY_EMAILS = ensure_list(COMPANY_EMAILS)
USER_AGENTS = ensure_list(USER_AGENTS)

# ─── Helpers ────────────────────────────────────────────────────────────────
DOMAIN_SAVE_COUNT = {}  # track saved mentions per domain
MAX_PER_DOMAIN = 5      # max mentions saved per domain per run

def is_likely_safe_source(url: str) -> bool:
    if not url:
        return False
    domain = urlparse(url).netloc.lower().replace("www.", "")
    return any(safe in domain for safe in SAFE_DOMAINS)

def is_noisy_source(url: str) -> bool:
    """Skip obvious search/result pages or noisy domains."""
    noisy_domains = [
        "google.com/search",
        "news.google.com/search",
        "bing.com/news/search",
        "reddit.com/search",
        "dehashed.com/search",
        "bleepingcomputer.com/search",
    ]
    url_lower = url.lower()
    return any(nd in url_lower for nd in noisy_domains)

def generate_domain_variations(domain: str) -> list[str]:
    if not domain:
        return []
    base = domain.lower().split('.')[0]
    tlds = [".com", ".co", ".net", ".org", ".io", ".us"]
    variants = {domain, base}

    for sep in ["", "-", "_", ".", "0", "1"]:
        variants.add(base + sep)
        variants.add(sep + base)

    homoglyph_map = {"o": "0", "i": "1", "l": "1", "s": "5", "a": "@"}
    for k, v in homoglyph_map.items():
        if k in base:
            variants.add(base.replace(k, v))

    full_domains = {var + tld for var in variants for tld in tlds}
    return list(full_domains)[:20]

def build_search_urls(days_back: int = 10):
    all_terms = set()
    all_terms.update(KEYWORDS_LIST)
    all_terms.update(PASTE_TERMS_LIST)
    all_terms.update(generate_domain_variations(COMPANY_DOMAIN))

    urls = []
    since = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

    for term in all_terms:
        if not term.strip():
            continue
        q = quote(term.strip())
        google_q = f"{q}+after:{since}+(leak+OR+breach+OR+paste+OR+dump)+-site:dehashed.com+-site:*.dehashed.com"
        bing_q = f"{q}+-site:dehashed.com"

        urls.extend([
            f"https://news.google.com/search?q={q}&hl=en-US&gl=US&ceid=US:en",
            f"https://www.google.com/search?q={google_q}&hl=en",
            f"https://www.bing.com/news/search?q={bing_q}",
            f"https://www.bleepingcomputer.com/search/?q={q}",
            f"https://thehackernews.com/search/label/{q}",
            f"https://krebsonsecurity.com/?s={q}",
            f"https://www.reddit.com/search/?q={q}+(leak+OR+dump+OR+breach)&type=link&sort=new",
        ])

    seen = set()
    return [u for u in urls if u not in seen and not seen.add(u)]

def contains_leak_context(text: str) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    return any(re.search(p, text_lower, re.IGNORECASE) for p in LEAK_CONTEXT_PATTERNS)

def contains_suspicious_email_mention(text: str) -> bool:
    text_lower = text.lower()
    for email in COMPANY_EMAILS:
        email_lower = email.lower()
        if email_lower not in text_lower:
            continue
        pos = text_lower.find(email_lower)
        window_start = max(0, pos - 200)
        window_end = min(len(text_lower), pos + len(email_lower) + 200)
        window = text_lower[window_start:window_end]

        if re.search(r'\b(contact|email us|reach us|write to|get in touch|info@|support@).*' + re.escape(email_lower), window):
            continue

        if contains_leak_context(window):
            return True
    return False

def is_dehashed_noise(text: str, url: str) -> bool:
    text_lower = text.lower()
    url_lower = url.lower()
    noise_patterns = [
        "we didn't find any results for",
        "didn't find any results for",
        "no results for",
        "nothing found for",
        "0 results for",
    ]
    if any(p in text_lower for p in noise_patterns):
        return True
    if "dehashed.com/search" in url_lower:
        return True
    return False

def determine_category(text: str) -> str:
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["paste", "pastebin", "psbdmp", "leak", "dump", "breach", "credentials", "password"]):
        return "potential_leak"
    if contains_leak_context(text):
        return "suspicious_mention"
    return "web_mention"

def save_mention(title: str, summary: str, url: str):
    if is_likely_safe_source(url) or is_noisy_source(url):
        return False

    combined = (title + " " + summary).strip()
    if is_dehashed_noise(combined, url) or len(combined) < 120:
        return False

    domain = urlparse(url).netloc
    DOMAIN_SAVE_COUNT.setdefault(domain, 0)
    if DOMAIN_SAVE_COUNT[domain] >= MAX_PER_DOMAIN:
        return False
    DOMAIN_SAVE_COUNT[domain] += 1

    # Deduplicate
    exists = conn.execute(
        "SELECT 1 FROM articles WHERE link = ? OR (title LIKE ? AND link LIKE ?)",
        (url, f"%{title[:80]}%", f"%{url[:80]}%")
    ).fetchone()
    if exists:
        return False

    category = determine_category(combined)
    has_keyword = any(k.lower() in combined for k in KEYWORDS_LIST + PASTE_TERMS_LIST)
    has_domain = COMPANY_DOMAIN.lower() in combined
    has_suspicious_email = contains_suspicious_email_mention(combined)
    has_leak_context = contains_leak_context(combined)

    if not (has_keyword or has_domain or has_suspicious_email):
        return False
    if category == "web_mention" and not has_leak_context:
        return False

    iso_utc = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT INTO articles (title, summary, link, category, date) VALUES (?, ?, ?, ?, ?)",
            (title[:250] or "Untitled mention", summary[:800], url, category, iso_utc)
        )
        conn.commit()
        print(f"[+] Saved ({category}): {title[:60]}... → {url} [date: {iso_utc}]")
        return True
    except Exception as e:
        print(f"[!] DB error saving {url}: {e}")
        return False

def extract_potential_mentions(soup, base_url: str):
    candidates = []
    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=True)
        if len(text) < 30:
            continue
        href = a["href"].strip()
        if not href or href.startswith(("#", "javascript:")):
            continue
        full_url = urljoin(base_url, href)
        context = text
        parent = a.find_parent(["p", "div", "li", "article", "section"])
        if parent:
            context = parent.get_text(strip=True)[:600]
        candidates.append((text[:160], context[:1000], full_url))
    return candidates

def check_web_mentions():
    print(f"[+] Starting web/leak monitor — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    urls = build_search_urls(days_back=10)
    print(f"  → Checking {len(urls)} search URLs")
    headers_base = {
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    for i, url in enumerate(urls, 1):
        if is_noisy_source(url):
            continue  # skip search result pages
        print(f"  {i}/{len(urls)} → {url.split('?')[0]} ...")
        for attempt in range(1, 4):
            try:
                headers = headers_base.copy()
                headers["User-Agent"] = random.choice(USER_AGENTS)
                r = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
                r.raise_for_status()
                soup = BeautifulSoup(r.text, "html.parser")
                candidates = extract_potential_mentions(soup, url)
                saved_count = 0
                for title_text, context_text, link in candidates:
                    if save_mention(title_text or "Web mention", context_text, link):
                        saved_count += 1
                if saved_count > 0:
                    print(f"    → Saved {saved_count} relevant mention(s)")
                break
            except requests.exceptions.RequestException as e:
                print(f"    [!] Request failed (attempt {attempt}): {e}")
                time.sleep(random.uniform(6, 15))
            except Exception as e:
                print(f"    [!] Parse error: {e}")
                break
        time.sleep(random.uniform(5, 12))
    print("[+] Web/leak monitoring finished")

if __name__ == "__main__":
    check_web_mentions()