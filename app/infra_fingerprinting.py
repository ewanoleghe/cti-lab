"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

"""
Basic Infrastructure Fingerprinting Module
- Performs reverse DNS lookup
- Attempts simple banner grabbing on common ports (80, 443, 22, etc.)
- Stores results in articles table with proper UTC timestamps
"""

import socket
import ssl
import time
from datetime import datetime, timezone
import logging

from .database import conn

logger = logging.getLogger(__name__)

COMMON_PORTS = [80, 443, 22, 21, 25, 3306, 5432, 3389]  # HTTP/S, SSH, FTP, SMTP, MySQL, Postgres, RDP

def get_reverse_dns(ip: str) -> str | None:
    """Safe reverse DNS lookup"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None
    except Exception as e:
        logger.debug(f"Reverse DNS failed for {ip}: {e}")
        return None


def get_banner(ip: str, port: int, timeout: float = 3.0) -> str | None:
    """Attempt to grab service banner on a given port"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            
            # HTTP/HTTPS
            if port in (80, 443):
                context = ssl.create_default_context() if port == 443 else None
                if context:
                    sock = context.wrap_socket(sock, server_hostname=ip)
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                return banner.split("\r\n")[0] if banner else None
            
            # Others: just read initial response
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200] if banner else None
            
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception as e:
        logger.debug(f"Banner grab failed {ip}:{port}: {e}")
        return None


def fingerprint_ip(ip: str):
    """
    Fingerprint an IP address:
    - Reverse DNS
    - Banner grabbing on common ports
    - Store meaningful results in articles table
    """
    print(f"[+] Fingerprinting IP: {ip}")

    results = []
    
    # 1. Reverse DNS
    rdns = get_reverse_dns(ip)
    if rdns:
        results.append(f"Reverse DNS: {rdns}")

    # 2. Banner grabbing on common ports
    banners = []
    for port in COMMON_PORTS:
        banner = get_banner(ip, port)
        if banner:
            banners.append(f"{port}/tcp: {banner[:120]}{'...' if len(banner) > 120 else ''}")
        time.sleep(0.3)  # polite delay

    if banners:
        results.append("Open ports & banners:\n" + "\n".join(banners))

    if not results:
        print(f"  [-] No useful fingerprint data for {ip}")
        return

    # Build article
    title = f"Infrastructure Fingerprint: {ip}"
    summary = "\n".join(results)
    link = f"https://www.shodan.io/host/{ip}"  # useful external reference
    category = "infra_fingerprint"
    iso_utc = datetime.now(timezone.utc).isoformat()

    # Deduplicate: same IP + similar summary in last 24h → skip
    exists = conn.execute(
        """
        SELECT id FROM articles 
        WHERE title = ? 
          AND category = ?
          AND date > datetime('now', '-1 day')
        """,
        (title, category)
    ).fetchone()

    if exists:
        print(f"  [skip duplicate] {title}")
        return

    try:
        conn.execute(
            """
            INSERT INTO articles (title, summary, link, category, date, cve_id, cvss_score)
            VALUES (?, ?, ?, ?, ?, NULL, NULL)
            """,
            (title, summary, link, category, iso_utc)
        )
        conn.commit()
        print(f"[+] Saved infra fingerprint for {ip}")
        print(f"    {summary[:200]}{'...' if len(summary) > 200 else ''}")
    except Exception as e:
        logger.error(f"DB error saving fingerprint for {ip}: {e}")


# Example usage / testing
if __name__ == "__main__":
    test_ips = ["8.8.8.8", "1.1.1.1", "your.target.ip.here"]
    for ip in test_ips:
        fingerprint_ip(ip)
        time.sleep(2)