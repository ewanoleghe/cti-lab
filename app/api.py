"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from .database import conn
from .config import COMPANY_NAME, COMPANY_DOMAIN
import logging

app = FastAPI(title="CTI Lab Dashboard")

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ────────────────────────────────────────────────
# GLOBAL CTI - General news, vulnerabilities, research, global phishing, etc.
# Excludes company-specific filtered categories
# ────────────────────────────────────────────────
@app.get("/articles")
def get_articles(day_offset: int = Query(0, ge=0)):
    """
    Get recent global CTI articles.
    Supports day_offset to limit to recent days.
    """
    try:
        # Calculate date threshold
        date_filter = ""
        params = {}
        if day_offset > 0:
            date_filter = "WHERE date >= date('now', ?)"
            params = {"days": f"-{day_offset} days"}

        # IMPORTANT: include cve_id and cvss_score in SELECT
        query = f"""
            SELECT title, summary, link, category, date, cve_id, cvss_score
            FROM articles
            {date_filter}
            WHERE category NOT IN ('phishing_monitor', 'shodan_monitor', 'web_monitor', 'domain_monitor', 'company_cti')
            ORDER BY date DESC
            LIMIT 200
        """

        rows = conn.execute(query, params).fetchall()

        return [
            {
                "title": r[0],
                "summary": r[1],
                "link": r[2],
                "category": r[3],
                "date": r[4],
                "cve_id": r[5],        # ← added
                "cvss_score": r[6]     # ← added
            }
            for r in rows
        ]
    except Exception as e:
        logger.error(f"Error in /articles: {e}")
        return {"error": "Failed to fetch articles"}, 500

# ────────────────────────────────────────────────
# COMPANY BASIC INFO
# ────────────────────────────────────────────────
@app.get("/company-info")
def company_info():
    return {
        "company_name": COMPANY_NAME,
        "company_domain": COMPANY_DOMAIN
    }


# ────────────────────────────────────────────────
# COMPANY INTELLIGENCE - Only company-relevant detections
# ────────────────────────────────────────────────
@app.get("/company-intel")
def company_intel(day_offset: int = Query(0, ge=0)):
    """
    Get recent company-specific threat intelligence.
    Supports day_offset to limit results.
    """
    try:
        date_filter = ""
        params = {}
        if day_offset > 0:
            date_filter = "AND date >= date('now', ?)"
            params["-days"] = f"-{day_offset} days"

        # Phishing (company-relevant only)
        phishing = conn.execute(
            f"""
            SELECT title, summary, link, date 
            FROM articles 
            WHERE category = 'phishing_monitor' {date_filter}
            ORDER BY date DESC 
            LIMIT 10
            """,
            params
        ).fetchall()

        # Breaches
        breaches = conn.execute(
            f"""
            SELECT title, summary, link, date 
            FROM articles 
            WHERE category = 'breach_monitor' {date_filter}
            ORDER BY date DESC 
            LIMIT 10
            """,
            params
        ).fetchall()

        # Shodan
        shodan = conn.execute(
            f"""
            SELECT title, summary, link, date 
            FROM articles 
            WHERE category = 'shodan_monitor' {date_filter}
            ORDER BY date DESC 
            LIMIT 10
            """,
            params
        ).fetchall()

        # Domain Impersonation
        impersonation = conn.execute(
            f"""
            SELECT title, summary, link, date 
            FROM articles 
            WHERE category = 'domain_monitor' {date_filter}
            ORDER BY date DESC 
            LIMIT 10
            """,
            params
        ).fetchall()

        # Paste / Leak Mentions
        paste_mentions = conn.execute(
            f"""
            SELECT title, summary, link, date 
            FROM articles 
            WHERE category = 'paste_monitor' {date_filter}
            ORDER BY date DESC 
            LIMIT 10
            """,
            params
        ).fetchall()
        
        # Mentions / Web Monitor
        mentions = conn.execute(
            f"""
            SELECT title, summary, link, date 
            FROM articles 
            WHERE category IN ('web_monitor', 'company_cti') {date_filter}
            ORDER BY date DESC 
            LIMIT 10
            """,
            params
        ).fetchall()

        return {
            "phishing": [[r[0], r[1], r[2], r[3]] for r in phishing],
            "breaches": [[r[0], r[1], r[2], r[3]] for r in breaches],
            "shodan": [[r[0], r[1], r[2], r[3]] for r in shodan],
            "impersonation": [[r[0], r[1], r[2], r[3]] for r in impersonation],
            "mentions": [[r[0], r[1], r[2], r[3]] for r in mentions],
            "paste_mentions": [],  # always include even if empty
        }
    except Exception as e:
        logger.error(f"Error in /company-intel: {e}")
        return {"error": "Failed to fetch company intelligence"}, 500