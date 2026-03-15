"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

"""
Company Email Breach Monitoring
- Checks company emails against Have I Been Pwned (HIBP)
- Uses careful DeHashed fallback only when needed
- Stores results in SQLite with ISO 8601 UTC dates
- * This one is strick and would work only if an api key is provided, otherwise it would be mostly useless. Consider using breach_monitor__2.py instead if you want a more relaxed monitoring that can work without an API key (but with more false positives).
"""

import requests
import time
from datetime import datetime, timezone
from urllib.parse import quote

from .database import conn
from .config import COMPANY_EMAILS, HIBP_API_KEY

HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_HEADERS = {
    "hibp-api-key": HIBP_API_KEY,
    "User-Agent": "Aspis-Environmental-CTI-Lab",
    "Accept": "application/json"
}


def check_hibp_email(email: str):
    """
    Primary check using official Have I Been Pwned API.
    Returns (breach_count, breach_names_list)
    """
    if not HIBP_API_KEY or HIBP_API_KEY.strip() in ("", "HIBP_API_KEY"):
        print("[!] HIBP_API_KEY not set — skipping HIBP check")
        return 0, []

    try:
        url = f"{HIBP_URL}{quote(email)}?truncateResponse=false"
        r = requests.get(url, headers=HIBP_HEADERS, timeout=10)

        if r.status_code == 404:
            print(f"[HIBP] {email} → 404 Not pwned")
            return 0, []

        if r.status_code == 200:
            try:
                breaches = r.json()
                if isinstance(breaches, list) and len(breaches) > 0:
                    names = [b.get("Name", "Unknown") for b in breaches]
                    print(f"[HIBP] {email} → {len(breaches)} breaches: {', '.join(names)}")
                    return len(breaches), names
                else:
                    print(f"[HIBP] {email} → 200 but empty list")
                    return 0, []
            except ValueError:
                print(f"[!] HIBP JSON parse error for {email}")
                return 0, []

        else:
            print(f"[!] HIBP unexpected status {r.status_code} for {email}: {r.text[:200]}")
            return 0, []

    except Exception as e:
        print(f"[!] HIBP request failed for {email}: {e}")
        return 0, []


def check_dehashed(email: str):
    """
    Fallback check using DeHashed public search page.
    Very strict detection to minimize false positives.
    Only flags if page contains clear evidence of leaked data for this email.
    """
    try:
        url = f"https://dehashed.com/search?query={quote(email)}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        r = requests.get(url, headers=headers, timeout=12)

        if r.status_code != 200:
            print(f"[DeHashed] {email} → status {r.status_code}")
            return 0, []

        text = r.text.lower()

        # Strong positive indicators (must have at least one)
        strong_positives = [
            "breached account", "breached accounts", "password hash", "hashes found",
            "email found in", "credentials found", "data found for", "results for",
            "dehashed found", f"{email} in", "exposed in"
        ]

        # Strong negative indicators (if any present → definitely clean)
        strong_negatives = [
            "no results", "0 results", "nothing found", "no matches", "no hits",
            "no data", "no breach", "clean", "not found in our database",
            "no leaked information", "no compromised accounts"
        ]

        has_strong_negative = any(phrase in text for phrase in strong_negatives)

        if has_strong_negative:
            print(f"[DeHashed] {email} → clear no-results page")
            return 0, []

        has_strong_positive = any(phrase in text for phrase in strong_positives)

        if has_strong_positive:
            # Optional: check for hit counter like "1 result" or "Found X entries"
            import re
            hit_match = re.search(r'found\s*(\d+)\s*(result|hit|entry|record)', text)
            if hit_match and int(hit_match.group(1)) > 0:
                print(f"[DeHashed] {email} → confirmed hit ({hit_match.group(0)})")
                return 1, ["DeHashed confirmed hit"]
            else:
                print(f"[DeHashed] {email} → weak positive signal (skipped)")
                return 0, []

        print(f"[DeHashed] {email} → no credible breach indicators")
        return 0, []

    except Exception as e:
        print(f"[!] DeHashed fallback failed for {email}: {e}")
        return 0, []


def detect_breaches():
    """
    Main breach monitoring function.
    Uses HIBP as primary source, DeHashed only as fallback.
    Stores results with proper ISO 8601 UTC timestamps.
    """
    print("[+] Starting breach monitoring (HIBP + careful DeHashed fallback)...")

    for email in COMPANY_EMAILS:
        # 1. Primary source: Have I Been Pwned
        count, breach_names = check_hibp_email(email)

        # 2. Fallback only if HIBP found nothing
        if count == 0:
            dh_count, dh_names = check_dehashed(email)
            count += dh_count
            breach_names += dh_names

        if count > 0:
            title = f"{email} appeared in {count} breach(es)"
            summary = f"Found in: {', '.join(breach_names[:5])}" + ("..." if len(breach_names) > 5 else "")

            # Prefer HIBP link if real breaches found, otherwise DeHashed
            link = (
                f"https://haveibeenpwned.com/account/{quote(email)}"
                if "DeHashed" not in breach_names
                else "https://dehashed.com/search"
            )

            # Avoid duplicates (same title + category)
            exists = conn.execute(
                "SELECT id FROM articles WHERE title = ? AND category = 'breach_monitor'",
                (title,)
            ).fetchone()

            if not exists:
                # ─── Use ISO 8601 UTC ────────────────────────────────────────
                iso_utc = datetime.now(timezone.utc).isoformat()

                conn.execute(
                    """
                    INSERT OR IGNORE INTO articles (title, summary, link, category, date)
                    VALUES (?, ?, ?, 'breach_monitor', ?)
                    """,
                    (title, summary, link, iso_utc)
                )
                conn.commit()
                print(f"[+] SAVED BREACH HIT: {title}  [date: {iso_utc}]")
            else:
                print(f"[skip duplicate] {title}")
        else:
            print(f"[+] Clean: {email} — no breaches found")

        time.sleep(2.0)  # Respect HIBP rate limit (~1 req/sec) + politeness

    print("[+] Breach monitoring complete")


if __name__ == "__main__":
    detect_breaches()