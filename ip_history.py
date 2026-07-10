"""SQLite-backed history of public IP addresses.

Each row is one period during which an address was active:
(family, ip, started_ts, ended_ts) — a NULL ended_ts means "still active".
The poller calls record_check() every cycle, but a row is only written when
an address actually changes, so the file stays tiny even after years of
typical residential IP churn.

Connections are opened per call (cheap at this write rate) so the poller
thread and web threads never share sqlite objects. History is advisory like
state.json: record_check() logs and swallows database errors rather than
ever killing a poll cycle.
"""

import contextlib
import logging
import os
import sqlite3
import threading

log = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DDNS_HISTORY_DB", os.path.join(_BASE_DIR, "history.db"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ip_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    family TEXT NOT NULL CHECK (family IN ('IPv4', 'IPv6')),
    ip TEXT NOT NULL,
    started_ts REAL NOT NULL,
    ended_ts REAL
);
CREATE INDEX IF NOT EXISTS idx_ip_history_open
    ON ip_history (family) WHERE ended_ts IS NULL;
"""

_init_lock = threading.Lock()
_initialized = False


def _connect():
    global _initialized
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    if not _initialized:
        with _init_lock:
            if not _initialized:
                conn.executescript(_SCHEMA)
                _initialized = True
    return conn


def record_check(ipv4, ipv6, now):
    """Called once per poll cycle with the current addresses.

    Opens/closes ranges only on change. A None address (lookup failed, or
    the family simply isn't available) leaves the open range untouched so a
    transient lookup failure doesn't fragment the history. Never raises.
    """
    try:
        with contextlib.closing(_connect()) as conn, conn:
            for family, ip in (("IPv4", ipv4), ("IPv6", ipv6)):
                if not ip:
                    continue
                row = conn.execute(
                    "SELECT id, ip FROM ip_history"
                    " WHERE family = ? AND ended_ts IS NULL",
                    (family,)).fetchone()
                if row and row["ip"] == ip:
                    continue
                if row:
                    conn.execute(
                        "UPDATE ip_history SET ended_ts = ? WHERE id = ?",
                        (now, row["id"]))
                conn.execute(
                    "INSERT INTO ip_history (family, ip, started_ts)"
                    " VALUES (?, ?, ?)",
                    (family, ip, now))
    except sqlite3.Error as exc:
        log.warning("Could not record IP history: %s", exc)


def get_page(before_id=None, limit=20, family=None):
    """Return (entries, has_more), newest range first, optionally only one
    address family ('IPv4' / 'IPv6').

    Keyset pagination on id (rows with id < before_id) so "Show more" never
    skips or repeats entries even if new rows are inserted between requests.
    """
    query = "SELECT id, family, ip, started_ts, ended_ts FROM ip_history"
    where, params = [], []
    if family is not None:
        where.append("family = ?")
        params.append(family)
    if before_id is not None:
        where.append("id < ?")
        params.append(before_id)
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit + 1)  # one extra row just to learn if more exist
    with contextlib.closing(_connect()) as conn:
        rows = [dict(r) for r in conn.execute(query, params)]
    return rows[:limit], len(rows) > limit


def get_all():
    """Every range, newest first — for the CSV export."""
    with contextlib.closing(_connect()) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, family, ip, started_ts, ended_ts FROM ip_history"
            " ORDER BY id DESC")]
