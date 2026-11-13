"""SQLite state: which links were processed, and which CVEs already have a note."""
import sqlite3
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    link         TEXT PRIMARY KEY,
    title        TEXT,
    source       TEXT,
    published    TEXT,
    category     TEXT,
    priority     TEXT,
    note_path    TEXT,
    processed_at TEXT
);
CREATE TABLE IF NOT EXISTS cve_notes (
    cve        TEXT PRIMARY KEY,
    note_path  TEXT,
    priority   TEXT,
    first_seen TEXT
);
"""


def connect() -> sqlite3.Connection:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_seen(conn, link: str) -> bool:
    return conn.execute("SELECT 1 FROM items WHERE link = ?", (link,)).fetchone() is not None


def mark_item(conn, item: dict, category: str, priority: str = "", note_path: str = "") -> None:
    conn.execute(
        "INSERT OR REPLACE INTO items VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (item["link"], item["title"], item["source"], item["published"],
         category, priority, note_path, now()),
    )
    conn.commit()


def cve_note(conn, cve: str):
    """Return (note_path, priority) if this CVE already has a note, else None."""
    row = conn.execute("SELECT note_path, priority FROM cve_notes WHERE cve = ?", (cve,)).fetchone()
    return (row["note_path"], row["priority"]) if row else None


def add_cve_note(conn, cve: str, note_path: str, priority: str) -> None:
    conn.execute("INSERT OR IGNORE INTO cve_notes VALUES (?, ?, ?, ?)",
                 (cve, note_path, priority, now()))
    conn.commit()
