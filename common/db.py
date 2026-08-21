"""SQLite access layer shared by every SOC-AI module.

The database is the only integration point between modules:
parser -> events, engine -> alerts, llm_agent -> triage columns, api -> read.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime

DB_PATH = os.getenv("SOCAI_DB", "/data/socai.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    source_ip    TEXT,
    user         TEXT,
    action       TEXT,
    source_type  TEXT    NOT NULL,
    extra        TEXT    DEFAULT '{}',
    raw_log      TEXT    NOT NULL,
    ingested_at  TEXT    NOT NULL,
    processed    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip        ON events(source_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id             TEXT    NOT NULL,
    rule_name           TEXT    NOT NULL,
    rule_severity       TEXT    NOT NULL,
    event_id            INTEGER,
    source_ip           TEXT,
    user                TEXT,
    timestamp           TEXT    NOT NULL,
    raw_log             TEXT,
    match_count         INTEGER DEFAULT 1,
    created_at          TEXT    NOT NULL,
    triage_status       TEXT    NOT NULL DEFAULT 'new',
    severity            TEXT,
    attack_type         TEXT,
    mitre_id            TEXT,
    confidence          INTEGER,
    summary             TEXT,
    recommendation      TEXT,
    false_positive_risk TEXT,
    triage_engine       TEXT,
    triaged_at          TEXT,
    FOREIGN KEY (event_id) REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(triage_status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created  ON alerts(created_at);

CREATE TABLE IF NOT EXISTS cursors (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def now_iso():
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def connect(path=None):
    """Open a SQLite connection with row access by column name."""
    target = path or os.getenv("SOCAI_DB", DB_PATH)
    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(target, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(path=None):
    """Create the schema if it does not exist yet. Idempotent."""
    conn = connect(path)
    with conn:
        conn.executescript(SCHEMA)
    return conn


@contextmanager
def session(path=None):
    """Context manager yielding an initialised connection."""
    conn = init_db(path)
    try:
        yield conn
    finally:
        conn.close()


def insert_event(conn, event):
    """Insert a normalised event and return its row id."""
    cur = conn.execute(
        """INSERT INTO events
           (timestamp, source_ip, user, action, source_type, extra, raw_log, ingested_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event["timestamp"],
            event.get("source_ip"),
            event.get("user"),
            event.get("action"),
            event["source_type"],
            json.dumps(event.get("extra", {}), ensure_ascii=False),
            event["raw_log"],
            now_iso(),
        ),
    )
    return cur.lastrowid


def insert_alert(conn, alert):
    """Insert an alert produced by the Sigma engine and return its row id."""
    cur = conn.execute(
        """INSERT INTO alerts
           (rule_id, rule_name, rule_severity, event_id, source_ip, user,
            timestamp, raw_log, match_count, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert["rule_id"],
            alert["rule_name"],
            alert["rule_severity"],
            alert.get("event_id"),
            alert.get("source_ip"),
            alert.get("user"),
            alert["timestamp"],
            alert.get("raw_log"),
            alert.get("match_count", 1),
            now_iso(),
        ),
    )
    return cur.lastrowid
