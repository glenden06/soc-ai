"""Parser for Apache and Nginx access logs in combined/common format."""

import re
from datetime import datetime
from urllib.parse import unquote_plus

SOURCE_TYPE = "web"

# 10.0.0.5 - - [10/Dec/2025:06:55:48 +0100] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "curl/8.0"
LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)


def _timestamp(raw):
    """Convert the Apache timestamp format into ISO-8601."""
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").isoformat(timespec="seconds")
    except ValueError:
        return raw


def parse(line):
    """Parse one access log line into a normalised event, or return None."""
    line = line.rstrip("\n")
    match = LINE_RE.match(line)
    if not match:
        return None

    path = match.group("path")
    return {
        "timestamp": _timestamp(match.group("time")),
        "source_ip": match.group("ip"),
        "user": None if match.group("user") == "-" else match.group("user"),
        "action": "http_request",
        "source_type": SOURCE_TYPE,
        "extra": {
            "method": match.group("method"),
            "path": path,
            "path_decoded": unquote_plus(path),
            "status": int(match.group("status")),
            "size": match.group("size"),
            "user_agent": match.group("agent") or "",
            "referer": match.group("referer") or "",
        },
        "raw_log": line,
    }
