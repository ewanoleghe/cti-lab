"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

import os
from dotenv import load_dotenv

load_dotenv()

def parse_multiline(var):
    value = os.getenv(var, "")
    return [line.strip() for line in value.splitlines() if line.strip()]

# API KEYS
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Company info
COMPANY_NAME = os.getenv("COMPANY_NAME", "")
COMPANY_DOMAIN = os.getenv("COMPANY_DOMAIN", "")

# Keyword list
COMPANY_NAME = os.getenv("COMPANY_NAME", "")
COMPANY_DOMAIN = os.getenv("COMPANY_DOMAIN", "")

KEYWORDS = parse_multiline("KEYWORDS")
COMPANY_EMAILS = parse_multiline("COMPANY_EMAILS")
PASTE_SEARCH_TERMS = parse_multiline("PASTE_SEARCH_TERMS")

# User agents for polite rotation (update versions occasionally)
USER_AGENTS = parse_multiline("USER_AGENTS")