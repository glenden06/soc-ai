"""Log format parsers. Each parser exposes parse(line) -> event dict or None."""

from . import apache, jsonl, ssh, winevent

PARSERS = {
    "ssh": ssh,
    "apache": apache,
    "winevent": winevent,
    "json": jsonl,
}


def detect_format(filename):
    """Guess the log format from the file name. Returns a module key."""
    name = filename.lower()
    if "auth" in name or "secure" in name or name.endswith(".ssh"):
        return "ssh"
    if "access" in name or "error" in name or "nginx" in name or "apache" in name:
        return "apache"
    if name.endswith(".xml") or "winevent" in name or "security" in name:
        return "winevent"
    if name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".ndjson"):
        return "json"
    return "ssh"
