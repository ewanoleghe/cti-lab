"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

"""
Main CTI Collector Runner
Orchestrates periodic execution of all monitoring tasks
"""

import time
import traceback
import re
from datetime import datetime, timezone

import feedparser
import requests  # for KEV feed and NVD API

from .database import conn
from .web_monitor import check_web_mentions
from .shodan_monitor import monitor_shodan
from .phishing_monitor import detect_phishing
from .breach_monitor import detect_breaches
from .paste_monitor import monitor_pastes
from .feeds import FEEDS, KEV_FEED
from .config import NVD_API_KEY  # ← Imported from config.py (loaded from .env)


def extract_cve(text: str) -> str | None:
    """Extract CVE-ID from text using regex"""
    if not text:
        return None
    match = re.search(r'(CVE-\d{4}-\d{4,7})', text, re.IGNORECASE)
    return match.group(1).upper() if match else None


def enrich_cvss_from_nvd(cve_id: str) -> str | None:
    """Fetch CVSS score from NVD API v2.0 using your API key"""
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return None

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(url, headers=headers, timeout=12)
        
        if resp.status_code == 429:
            print(f"[!] NVD rate limit hit for {cve_id} — skipping this enrichment")
            return None
        
        if resp.status_code != 200:
            print(f"[!] NVD API returned {resp.status_code} for {cve_id}")
            return None

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print(f"[!] No vulnerability data found in NVD for {cve_id}")
            return None

        metrics = vulns[0]["cve"].get("metrics", {})

        # Prefer CVSS v3.1 > v3.0 > v2
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            score = m["baseScore"]
            severity = m.get("baseSeverity", "")
            return f"{score} ({severity})" if severity else f"{score}"

        if "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            m = metrics["cvssMetricV30"][0]["cvssData"]
            score = m["baseScore"]
            severity = m.get("baseSeverity", "")
            return f"{score} ({severity})" if severity else f"{score}"

        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            m = metrics["cvssMetricV2"][0]["cvssData"]
            score = m["baseScore"]
            # Rough severity mapping for v2
            severity = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            return f"{score} ({severity})"

        print(f"[!] No CVSS metrics found in NVD for {cve_id}")
        return None

    except requests.Timeout:
        print(f"[!] NVD request timed out for {cve_id}")
        return None
    except Exception as e:
        print(f"[!] NVD enrichment failed for {cve_id}: {e}")
        return None


def save_feed_entry(
    title: str,
    summary: str,
    link: str,
    category: str,
    cve_id: str = None,
    cvss_score: str = None
):
    """
    Save RSS/JSON feed entry with ISO 8601 UTC timestamp.
    Checks for duplicates by link (preferred) or title.
    Returns True if saved, False if skipped (duplicate or invalid).
    """
    if not title.strip() or not link.strip():
        return False

    # Prefer link for uniqueness, fallback to title
    exists = conn.execute(
        "SELECT id FROM articles WHERE link = ? OR (link IS NULL AND title = ?)",
        (link, title)
    ).fetchone()

    if exists:
        return False

    iso_utc = datetime.now(timezone.utc).isoformat()

    try:
        conn.execute(
            """
            INSERT INTO articles (title, summary, link, category, date, cve_id, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title[:250] or "Untitled entry",
                summary[:800] or "No summary",
                link,
                category,
                iso_utc,
                cve_id,
                cvss_score
            )
        )
        conn.commit()

        extra = ""
        if cve_id:
            extra += f" | CVE: {cve_id}"
        if cvss_score:
            extra += f" | CVSS: {cvss_score}"

        print(f"[+] Saved [{category}]: {title[:70]}... → {link}  [date: {iso_utc}]{extra}")
        return True
    except Exception as e:
        print(f"[!] DB error saving feed entry {link or title}: {e}")
        return False


def collect_rss_feeds():
    """Collect entries from all defined RSS/Atom feeds"""
    print("[+] Collecting global RSS feeds...")

    for category_name, urls in FEEDS.items():
        cat_slug = category_name.lower().replace(" ", "_")

        for url in urls:
            try:
                feed = feedparser.parse(url)
                if feed.bozo:
                    print(f"  [!] Feed parse issue {url}: {feed.bozo_exception}")
                    continue

                print(f"  → {category_name}: {url} ({len(feed.entries)} entries)")

                for entry in feed.entries[:5]:  # reasonable limit per feed
                    title = getattr(entry, "title", "No title").strip()
                    summary = (
                        getattr(entry, "summary", "")
                        or getattr(entry, "description", "")
                        or "No content"
                    ).strip()
                    link = getattr(entry, "link", "").strip()

                    if not title or not link:
                        continue

                    cve_id = None
                    cvss_score = None

                    # Auto-detect CVE for vulnerability-related categories
                    vuln_keywords = ["vulnerabilities", "exploit", "zero-day", "known_exploited", "kev"]
                    if any(kw in cat_slug for kw in vuln_keywords):
                        combined_text = f"{title} {summary} {link}"
                        cve_id = extract_cve(combined_text)

                        # If CVE found but no score yet → enrich from NVD
                        if cve_id and not cvss_score:
                            cvss_score = enrich_cvss_from_nvd(cve_id)
                            if cvss_score:
                                print(f"  [+] Enriched CVSS for {cve_id}: {cvss_score}")

                    save_feed_entry(
                        title, summary, link, cat_slug,
                        cve_id=cve_id,
                        cvss_score=cvss_score
                    )

            except Exception as e:
                print(f"[!] RSS collection failed {url}: {e}")
                continue


def collect_kev_feed():
    """Collect from CISA Known Exploited Vulnerabilities JSON feed"""
    print("[+] Checking CISA Known Exploited Vulnerabilities (KEV)...")

    try:
        r = requests.get(KEV_FEED, timeout=15)
        r.raise_for_status()
        data = r.json()

        vulnerabilities = data.get("vulnerabilities", [])
        print(f"  → Found {len(vulnerabilities)} KEV entries")

        for vuln in vulnerabilities[:15]:  # slightly increased limit
            cve_id = vuln.get("cveID", "Unknown CVE")
            title = f"KEV: {cve_id} - {vuln.get('vulnerabilityName', 'Unnamed Vulnerability')}"

            summary_parts = [
                f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}".strip(),
                f"Added: {vuln.get('dateAdded', 'N/A')}",
                f"Due: {vuln.get('dueDate', 'N/A')}",
                f"Required Action: {vuln.get('requiredAction', 'N/A')}",
            ]
            summary = " — ".join(filter(None, summary_parts))

            # Robust link extraction
            link = ""
            notes = vuln.get("notes", [])
            if isinstance(notes, list) and notes and isinstance(notes[0], dict):
                link = notes[0].get("url", "")
            else:
                link = vuln.get("reference", "") or vuln.get("sourceLink", "")

            # CVSS from CISA (they provide it directly) — we prefer this over NVD for KEV
            cvss_raw = vuln.get("cvssScore")
            severity = vuln.get("baseSeverity", "")
            cvss_score = None
            if cvss_raw is not None:
                cvss_score = f"{cvss_raw} ({severity})" if severity else str(cvss_raw)

            save_feed_entry(
                title, summary, link,
                "known_exploited_vulnerabilities",
                cve_id=cve_id,
                cvss_score=cvss_score
            )

    except Exception as e:
        print(f"[!] KEV feed error: {e}")


def run_all():
    """Execute one full collection cycle"""
    print("\n" + "="*45)
    print(f"CTI COLLECTION START — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("="*45 + "\n")

    # 1. RSS / global feeds
    try:
        collect_rss_feeds()
    except Exception as e:
        print(f"[!] RSS feeds collection crashed: {e}")
        traceback.print_exc()

    # 2. CISA KEV
    try:
        collect_kev_feed()
    except Exception as e:
        print(f"[!] KEV collection error: {e}")

    # 3. Company-specific monitors
    monitors = [
        ("Web mentions", check_web_mentions),
        ("Shodan exposure", monitor_shodan),
        ("Phishing alerts", detect_phishing),
        ("HIBP breaches", detect_breaches),
        ("Paste/leak mentions", monitor_pastes),
    ]

    for name, func in monitors:
        try:
            print(f"[+] Running {name} monitor...")
            func()
        except Exception as e:
            print(f"[!] {name} monitor failed: {e}")
            traceback.print_exc()

    print("\n" + "="*45)
    print("COLLECTION CYCLE COMPLETE")
    print("="*45 + "\n")


def start_collector():
    """Infinite loop — run collection every 2 hours"""
    print("CTI Collector service started. Running every 2 hours...\n")

    while True:
        try:
            run_all()
        except Exception as e:
            print("[CRITICAL] Collector main loop crashed:", e)
            traceback.print_exc()

        print("[+] Sleeping for 2 hours...\n")
        time.sleep(7200)  # 2 hours


if __name__ == "__main__":
    start_collector()