"""Unit tests for the Sigma detection engine."""

import os

import pytest

import engine as detection
from common import db

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "engine", "rules")


def _event(**overrides):
    base = {
        "timestamp": "2026-08-20T09:14:11+00:00",
        "source_ip": "45.83.64.12",
        "user": "admin",
        "action": "auth_failure",
        "source_type": "ssh",
        "extra": {},
        "raw_log": "raw line",
    }
    base.update(overrides)
    return base


def _rows(conn, events):
    with conn:
        for event in events:
            db.insert_event(conn, event)
    return conn.execute("SELECT * FROM events ORDER BY id").fetchall()


def test_all_ten_rules_load():
    rules = detection.load_rules(RULES_DIR)
    assert len(rules) == 10
    ids = {rule["id"] for rule in rules}
    assert {"SSH-001", "SSH-002", "SSH-003", "WEB-001", "WEB-002",
            "WEB-003", "WIN-001", "WIN-002", "WIN-003", "NET-001"} == ids


def test_every_rule_has_required_fields():
    for rule in detection.load_rules(RULES_DIR):
        assert rule["level"] in {"critical", "high", "medium", "low", "informational"}
        assert "condition" in rule["detection"]
        assert rule.get("title")


@pytest.mark.parametrize("count,expected", [(5, 0), (6, 1), (9, 1)])
def test_bruteforce_threshold(conn, count, expected):
    rules = {r["id"]: r for r in detection.load_rules(RULES_DIR)}
    events = [
        _event(timestamp=f"2026-08-20T09:14:{10 + i:02d}+00:00", raw_log=f"line {i}")
        for i in range(count)
    ]
    alerts = detection.evaluate(rules["SSH-001"], _rows(conn, events))
    assert len(alerts) == expected
    if expected:
        assert alerts[0]["rule_severity"] == "HIGH"
        assert alerts[0]["match_count"] >= 6


def test_bruteforce_ignores_events_outside_window(conn):
    rules = {r["id"]: r for r in detection.load_rules(RULES_DIR)}
    events = [_event(timestamp=f"2026-08-20T09:{14 + i}:00+00:00") for i in range(8)]
    assert detection.evaluate(rules["SSH-001"], _rows(conn, events)) == []


def test_root_login_rule(conn):
    rules = {r["id"]: r for r in detection.load_rules(RULES_DIR)}
    rows = _rows(conn, [_event(action="auth_success", user="root", source_ip="203.0.113.77")])
    alerts = detection.evaluate(rules["SSH-002"], rows)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SSH-002"


def test_external_ip_rule_excludes_private_ranges(conn):
    rules = {r["id"]: r for r in detection.load_rules(RULES_DIR)}
    rows = _rows(conn, [
        _event(action="auth_success", user="deploy", source_ip="192.168.1.24"),
        _event(action="auth_success", user="deploy", source_ip="203.0.113.77"),
    ])
    alerts = detection.evaluate(rules["SSH-003"], rows)
    assert [alert["source_ip"] for alert in alerts] == ["203.0.113.77"]


def test_sql_injection_rule(conn):
    rules = {r["id"]: r for r in detection.load_rules(RULES_DIR)}
    rows = _rows(conn, [
        _event(source_type="web", action="http_request",
               extra={"path_decoded": "/p.php?id=1 UNION SELECT user,pass FROM users"}),
        _event(source_type="web", action="http_request", extra={"path_decoded": "/index.php"}),
    ])
    assert len(detection.evaluate(rules["WEB-001"], rows)) == 1


def test_scanner_user_agent_rule(conn):
    rules = {r["id"]: r for r in detection.load_rules(RULES_DIR)}
    rows = _rows(conn, [
        _event(source_type="web", extra={"user_agent": "Mozilla/5.00 (Nikto/2.5.0)"}),
        _event(source_type="web", extra={"user_agent": "Mozilla/5.0 (X11; Linux)"}),
    ])
    assert len(detection.evaluate(rules["WEB-003"], rows)) == 1


def test_win_priv_escalation_filters_system_accounts(conn):
    rules = {r["id"]: r for r in detection.load_rules(RULES_DIR)}
    rows = _rows(conn, [
        _event(source_type="windows", user="svc_backup", extra={"event_id": "4672"}),
        _event(source_type="windows", user="SYSTEM", extra={"event_id": "4672"}),
    ])
    alerts = detection.evaluate(rules["WIN-001"], rows)
    assert [alert["user"] for alert in alerts] == ["svc_backup"]


def test_sam_access_rule(conn):
    rules = {r["id"]: r for r in detection.load_rules(RULES_DIR)}
    rows = _rows(conn, [
        _event(source_type="windows", user="j.martin",
               extra={"event_id": "4663", "object_name": "\\REGISTRY\\MACHINE\\SAM\\SAM"}),
    ])
    alerts = detection.evaluate(rules["WIN-003"], rows)
    assert alerts[0]["rule_severity"] == "CRITICAL"


def test_run_once_marks_events_processed(conn):
    rules = detection.load_rules(RULES_DIR)
    _rows(conn, [_event(action="auth_success", user="root", source_ip="203.0.113.77")])
    assert detection.run_once(conn, rules) >= 1
    pending = conn.execute("SELECT COUNT(*) AS n FROM events WHERE processed = 0").fetchone()["n"]
    assert pending == 0
    assert detection.run_once(conn, rules) == 0
