"""SOC-AI detection engine.

Loads Sigma rules from rules/*.yml and evaluates them against the events
ingested by the parser. Two rule shapes are supported:

  * simple match   -> condition: selection
  * aggregation    -> condition: selection | count() by source_ip > 5
                      combined with a timeframe (e.g. 60s, 5m)

Matching an aggregation rule emits a single alert per group instead of one
alert per event, which is what keeps the noise down.
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import db  # noqa: E402

RULES_DIR = os.getenv("SOCAI_RULES_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules"))
POLL_INTERVAL = float(os.getenv("SOCAI_POLL_INTERVAL", "3"))
BATCH_SIZE = int(os.getenv("SOCAI_BATCH_SIZE", "500"))

LEVEL_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
}

AGG_RE = re.compile(
    r"^(?P<sel>\w+)\s*\|\s*count\(\)\s*(?:by\s+(?P<by>\w+)\s*)?(?P<op>>=|>)\s*(?P<threshold>\d+)$"
)
EXCLUSION_RE = re.compile(r"^(?P<sel>\w+)\s+and\s+not\s+(?P<filter>\w+)$")
TIMEFRAME_RE = re.compile(r"^(?P<value>\d+)(?P<unit>[smhd])$")

logging.basicConfig(
    level=os.getenv("SOCAI_LOG_LEVEL", "INFO"),
    format="%(asctime)s [engine] %(levelname)s %(message)s",
)
log = logging.getLogger("engine")


def load_rules(directory=RULES_DIR):
    """Load and validate every YAML rule in the directory."""
    rules = []
    if not os.path.isdir(directory):
        log.error("rules directory not found: %s", directory)
        return rules

    for name in sorted(os.listdir(directory)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as handle:
                rule = yaml.safe_load(handle)
            if not rule or "detection" not in rule or "id" not in rule:
                log.warning("skipping malformed rule %s", name)
                continue
            rules.append(rule)
        except yaml.YAMLError as exc:
            log.error("cannot parse rule %s: %s", name, exc)
    log.info("loaded %d rules from %s", len(rules), directory)
    return rules


def _field_value(event, field):
    """Resolve a field from the event row, falling back to the extra JSON blob."""
    if field in event.keys():
        return event[field]
    try:
        extra = json.loads(event["extra"] or "{}")
    except (json.JSONDecodeError, TypeError):
        extra = {}
    return extra.get(field)


def _match_atom(value, expected, modifier):
    """Compare one field value against one expected value using a Sigma modifier."""
    if value is None:
        return False
    text = str(value)
    expected_text = str(expected)

    if modifier == "contains":
        return expected_text.lower() in text.lower()
    if modifier == "startswith":
        return text.lower().startswith(expected_text.lower())
    if modifier == "endswith":
        return text.lower().endswith(expected_text.lower())
    if modifier == "re":
        return re.search(expected_text, text, re.IGNORECASE) is not None
    if modifier == "gte":
        try:
            return float(text) >= float(expected_text)
        except ValueError:
            return False
    return text.lower() == expected_text.lower()


def match_selection(event, selection):
    """Return True when the event satisfies every field of the selection (AND)."""
    for raw_field, expected in selection.items():
        field, _, modifier = raw_field.partition("|")
        candidates = expected if isinstance(expected, list) else [expected]
        value = _field_value(event, field)
        if not any(_match_atom(value, item, modifier) for item in candidates):
            return False
    return True


def _parse_timeframe(raw):
    """Convert a Sigma timeframe string into a timedelta. Defaults to 60s."""
    match = TIMEFRAME_RE.match(str(raw or "60s"))
    if not match:
        return timedelta(seconds=60)
    value = int(match.group("value"))
    unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[match.group("unit")]
    return timedelta(**{unit: value})


def _event_time(event):
    """Best-effort parse of the event timestamp into a datetime."""
    try:
        return datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def evaluate(rule, events):
    """Evaluate one rule against a batch of events. Returns a list of alerts."""
    detection = rule["detection"]
    condition = str(detection.get("condition", "selection")).strip()
    severity = LEVEL_MAP.get(str(rule.get("level", "medium")).lower(), "MEDIUM")
    alerts = []

    agg = AGG_RE.match(condition)
    exclusion = EXCLUSION_RE.match(condition)
    if agg:
        selection_name = agg.group("sel")
    elif exclusion:
        selection_name = exclusion.group("sel")
    else:
        selection_name = condition.split()[0]

    selection = detection.get(selection_name)
    if not isinstance(selection, dict):
        log.warning("rule %s has no usable selection block", rule["id"])
        return alerts

    matched = [event for event in events if match_selection(event, selection)]

    if exclusion:
        excluded = detection.get(exclusion.group("filter"))
        if isinstance(excluded, dict):
            matched = [event for event in matched if not match_selection(event, excluded)]

    if not matched:
        return alerts

    if not agg:
        for event in matched:
            alerts.append({
                "rule_id": rule["id"],
                "rule_name": rule.get("title", rule["id"]),
                "rule_severity": severity,
                "event_id": event["id"],
                "source_ip": event["source_ip"],
                "user": event["user"],
                "timestamp": event["timestamp"],
                "raw_log": event["raw_log"],
                "match_count": 1,
            })
        return alerts

    # Aggregation branch: group, then slide a window over each group.
    threshold = int(agg.group("threshold"))
    inclusive = agg.group("op") == ">="
    group_field = agg.group("by") or "source_ip"
    window = _parse_timeframe(detection.get("timeframe"))

    groups = defaultdict(list)
    for event in matched:
        key = _field_value(event, group_field) or "unknown"
        groups[key].append(event)

    for group in groups.values():
        timed = [(t, e) for e, t in ((e, _event_time(e)) for e in group) if t is not None]
        timed.sort(key=lambda pair: pair[0])
        if not timed:
            continue

        start = 0
        for end in range(len(timed)):
            while timed[end][0] - timed[start][0] > window:
                start += 1
            count = end - start + 1
            if (count >= threshold) if inclusive else (count > threshold):
                last = timed[end][1]
                alerts.append({
                    "rule_id": rule["id"],
                    "rule_name": rule.get("title", rule["id"]),
                    "rule_severity": severity,
                    "event_id": last["id"],
                    "source_ip": last["source_ip"],
                    "user": last["user"],
                    "timestamp": last["timestamp"],
                    "raw_log": last["raw_log"],
                    "match_count": count,
                })
                break  # one alert per group per batch
    return alerts


def run_once(conn, rules):
    """Process every unprocessed event once. Returns the number of alerts created."""
    rows = conn.execute(
        "SELECT * FROM events WHERE processed = 0 ORDER BY id ASC LIMIT ?", (BATCH_SIZE,)
    ).fetchall()
    if not rows:
        return 0

    created = 0
    with conn:
        for rule in rules:
            for alert in evaluate(rule, rows):
                db.insert_alert(conn, alert)
                created += 1
                log.info("alert %s (%s) from %s", alert["rule_id"], alert["rule_severity"], alert["source_ip"])
        conn.execute(
            "UPDATE events SET processed = 1 WHERE id <= ?", (rows[-1]["id"],)
        )
    return created


def main():
    """CLI entry point."""
    argp = argparse.ArgumentParser(description="SOC-AI Sigma detection engine")
    argp.add_argument("--once", action="store_true", help="single pass then exit")
    argp.add_argument("--rules", default=RULES_DIR, help="rules directory")
    args = argp.parse_args()

    rules = load_rules(args.rules)
    conn = db.init_db()

    if args.once:
        total = run_once(conn, rules)
        log.info("one-shot detection complete: %d alerts", total)
        conn.close()
        return

    while True:
        try:
            run_once(conn, rules)
        except Exception as exc:
            log.error("detection cycle failed: %s", exc)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
