"""Parser for Windows Event Log entries exported as XML (one <Event> per line
or a pretty-printed file). Only the fields SOC-AI needs are extracted."""

import re
from datetime import datetime

SOURCE_TYPE = "windows"

EVENTID_RE = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
TIME_RE = re.compile(r'<TimeCreated[^>]*SystemTime=["\']([^"\']+)["\']')
DATA_RE = re.compile(r'<Data\s+Name=["\'](?P<name>[^"\']+)["\']>(?P<value>[^<]*)</Data>')
COMPUTER_RE = re.compile(r"<Computer>([^<]+)</Computer>")

ACTIONS = {
    "4624": "logon_success",
    "4625": "logon_failure",
    "4672": "special_privileges_assigned",
    "4720": "account_created",
    "4726": "account_deleted",
    "4732": "member_added_to_group",
    "4688": "process_created",
    "4656": "object_handle_requested",
    "4663": "object_access",
}


def _timestamp(raw):
    """Normalise the Windows SystemTime attribute to ISO-8601."""
    if not raw:
        return datetime.utcnow().isoformat(timespec="seconds")
    cleaned = raw.replace("Z", "+00:00")
    cleaned = re.sub(r"\.(\d{6})\d+", r".\1", cleaned)
    try:
        return datetime.fromisoformat(cleaned).isoformat(timespec="seconds")
    except ValueError:
        return raw


def parse(line):
    """Parse one XML event record into a normalised event, or return None."""
    line = line.rstrip("\n")
    event_id = EVENTID_RE.search(line)
    if not event_id:
        return None

    data = {m.group("name"): m.group("value") for m in DATA_RE.finditer(line)}
    time_match = TIME_RE.search(line)
    computer = COMPUTER_RE.search(line)
    eid = event_id.group(1)

    return {
        "timestamp": _timestamp(time_match.group(1) if time_match else None),
        "source_ip": data.get("IpAddress") or data.get("ClientAddress"),
        "user": data.get("TargetUserName") or data.get("SubjectUserName"),
        "action": ACTIONS.get(eid, "windows_event"),
        "source_type": SOURCE_TYPE,
        "extra": {
            "event_id": eid,
            "computer": computer.group(1) if computer else None,
            "object_name": data.get("ObjectName", ""),
            "privileges": data.get("PrivilegeList", ""),
            "process_name": data.get("ProcessName", ""),
            "logon_type": data.get("LogonType", ""),
        },
        "raw_log": line,
    }
