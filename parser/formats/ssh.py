"""Parser for Linux SSH authentication logs (/var/log/auth.log)."""

import re
from datetime import UTC, datetime

SOURCE_TYPE = "ssh"

# Dec 10 06:55:48 host sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 52310 ssh2
LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>sshd)\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)

IP_RE = re.compile(r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
USER_RE = re.compile(r"(?:invalid user|user|for)\s+(?P<user>[\w.\-$]+)\s+from")
PORT_RE = re.compile(r"port\s+(?P<port>\d+)")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _classify(message):
    """Map a raw sshd message to a normalised action name."""
    low = message.lower()
    if low.startswith("failed password") or "authentication failure" in low:
        return "auth_failure"
    if low.startswith("accepted password") or low.startswith("accepted publickey"):
        return "auth_success"
    if "invalid user" in low:
        return "invalid_user"
    if "connection closed by authenticating user" in low:
        return "auth_failure"
    if "disconnect" in low:
        return "disconnect"
    return "other"


def _timestamp(month, day, time_str):
    """Build an ISO timestamp; syslog carries no year, so assume the current one."""
    year = datetime.now(UTC).year
    dt = datetime(
        year, MONTHS[month], int(day),
        *(int(p) for p in time_str.split(":")),
        tzinfo=UTC,
    )
    return dt.isoformat(timespec="seconds")


def parse(line):
    """Parse one auth.log line into a normalised event, or return None."""
    line = line.rstrip("\n")
    match = LINE_RE.match(line)
    if not match:
        return None

    message = match.group("message")
    ip_match = IP_RE.search(message)
    user_match = USER_RE.search(message)
    port_match = PORT_RE.search(message)

    user = user_match.group("user") if user_match else None
    if user in {"invalid", "from"}:
        user = None

    return {
        "timestamp": _timestamp(match.group("month"), match.group("day"), match.group("time")),
        "source_ip": ip_match.group("ip") if ip_match else None,
        "user": user,
        "action": _classify(message),
        "source_type": SOURCE_TYPE,
        "extra": {
            "host": match.group("host"),
            "pid": match.group("pid"),
            "port": port_match.group("port") if port_match else None,
            "message": message,
        },
        "raw_log": line,
    }
