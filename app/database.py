"""
CTI-Lab – Real-time Cyber Threat Intelligence Dashboard
Created by Ewan Oleghe in 2026
GitHub: https://github.com/ewanoleghe/cti-lab.git
"""

import sqlite3

conn = sqlite3.connect("cti_lab.db", check_same_thread=False)
c = conn.cursor()

# Create main table if not exists
c.execute("""
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    summary TEXT,
    link TEXT UNIQUE,
    category TEXT,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    cve_id TEXT,
    cvss_score TEXT
)
""")

# Safe migration: add columns if missing (SQLite doesn't have IF NOT EXISTS for columns)
def add_column_if_not_exists(table, column, col_type):
    c.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in c.fetchall()]
    if column not in columns:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
        conn.commit()
        print(f"[+] Added column '{column}' to '{table}'")

add_column_if_not_exists("articles", "cve_id", "TEXT")
add_column_if_not_exists("articles", "cvss_score", "TEXT")

conn.commit()
print("✅ Database ready")