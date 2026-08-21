"""Parser for generic newline-delimited JSON logs."""

import json
from datetime import UTC, datetime

SOURCE_TYPE = "json"

TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp", "ts", "date")
IP_KEYS = ("source_ip", "src_ip", "ip", "client_ip", "remote_addr")
USER_KEYS = ("user", "username", "account", "user_name")
ACTION_KEYS = ("action", "event", "event_type", "message")


def _first(record, keys, default=None):
    """Return the first present key among candidates."""
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return default


def parse(line):
    """Parse one JSON line into a normalised event, or return None."""
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None

    return {
        "timestamp": str(
            _first(record, TIMESTAMP_KEYS, datetime.now(UTC).isoformat(timespec="seconds"))
        ),
        "source_ip": _first(record, IP_KEYS),
        "user": _first(record, USER_KEYS),
        "action": str(_first(record, ACTION_KEYS, "generic")),
        "source_type": SOURCE_TYPE,
        "extra": record,
        "raw_log": line,
    }
