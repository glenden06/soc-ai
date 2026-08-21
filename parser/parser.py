"""SOC-AI ingestion module.

Watches a directory of log files, parses every new line into a normalised
Event and stores it in SQLite. Supports a one-shot mode (--once) used by the
demo and the test suite, and a follow mode used by the container.
"""

import argparse
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from formats import PARSERS, detect_format  # noqa: E402

from common import db  # noqa: E402

LOG_DIR = os.getenv("SOCAI_LOG_DIR", "/logs")
POLL_INTERVAL = float(os.getenv("SOCAI_POLL_INTERVAL", "2"))

logging.basicConfig(
    level=os.getenv("SOCAI_LOG_LEVEL", "INFO"),
    format="%(asctime)s [parser] %(levelname)s %(message)s",
)
log = logging.getLogger("parser")


def parse_line(line, fmt):
    """Parse a single line with the given format key. Returns an event or None."""
    module = PARSERS.get(fmt)
    if module is None:
        return None
    try:
        return module.parse(line)
    except Exception as exc:  # a malformed line must never kill the ingester
        log.warning("parse error (%s): %s", fmt, exc)
        return None


def parse_file(path, fmt=None, start_offset=0):
    """Parse a file from an offset. Returns (events, new_offset)."""
    fmt = fmt or detect_format(os.path.basename(path))
    events = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        handle.seek(start_offset)
        for line in handle:
            if not line.strip():
                continue
            event = parse_line(line, fmt)
            if event:
                events.append(event)
        offset = handle.tell()
    return events, offset


def _get_offset(conn, path):
    """Read the stored read offset for a file."""
    row = conn.execute("SELECT value FROM cursors WHERE name = ?", (f"offset:{path}",)).fetchone()
    return int(row["value"]) if row else 0


def _set_offset(conn, path, offset):
    """Persist the read offset so restarts do not re-ingest old lines."""
    conn.execute(
        "INSERT INTO cursors (name, value) VALUES (?, ?) "
        "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
        (f"offset:{path}", str(offset)),
    )


def scan_directory(conn, directory):
    """Ingest every new line from every file in the directory. Returns a count."""
    if not os.path.isdir(directory):
        log.warning("log directory %s does not exist yet", directory)
        return 0

    total = 0
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        try:
            offset = _get_offset(conn, path)
            if os.path.getsize(path) < offset:
                offset = 0  # file was rotated or truncated
            events, new_offset = parse_file(path, start_offset=offset)
            with conn:
                for event in events:
                    db.insert_event(conn, event)
                _set_offset(conn, path, new_offset)
            if events:
                log.info("ingested %d events from %s", len(events), name)
            total += len(events)
        except OSError as exc:
            log.error("cannot read %s: %s", path, exc)
    return total


def main():
    """CLI entry point."""
    argp = argparse.ArgumentParser(description="SOC-AI log parser")
    argp.add_argument("--dir", default=LOG_DIR, help="directory to watch")
    argp.add_argument("--once", action="store_true", help="single pass then exit")
    args = argp.parse_args()

    conn = db.init_db()
    log.info("watching %s (db=%s)", args.dir, os.getenv("SOCAI_DB", db.DB_PATH))

    if args.once:
        count = scan_directory(conn, args.dir)
        log.info("one-shot ingestion complete: %d events", count)
        conn.close()
        return

    while True:
        try:
            scan_directory(conn, args.dir)
        except Exception as exc:
            log.error("scan failed: %s", exc)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
