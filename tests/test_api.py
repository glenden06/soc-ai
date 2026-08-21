"""Integration tests for the FastAPI layer."""

import pytest
from fastapi.testclient import TestClient

from common import db


@pytest.fixture()
def client(conn):
    import main

    with conn:
        db.insert_alert(conn, {
            "rule_id": "WIN-003", "rule_name": "Acces a la ruche SAM", "rule_severity": "CRITICAL",
            "source_ip": "10.0.0.9", "user": "j.martin",
            "timestamp": "2026-08-20T08:15:02+00:00", "raw_log": "<Event/>", "match_count": 1,
        })
        db.insert_alert(conn, {
            "rule_id": "WEB-003", "rule_name": "Scanner HTTP", "rule_severity": "LOW",
            "source_ip": "198.51.100.9", "user": None,
            "timestamp": "2026-08-20T09:20:31+00:00", "raw_log": "GET /", "match_count": 1,
        })
        conn.execute("UPDATE alerts SET severity = rule_severity, triage_status = 'triaged'")
    return TestClient(main.app)


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_list_alerts(client):
    body = client.get("/alerts").json()
    assert body["total"] == 2
    assert len(body["items"]) == 2
    assert body["items"][0]["rule_id"] in {"WIN-003", "WEB-003"}


def test_filter_by_severity(client):
    body = client.get("/alerts", params={"severity": "critical"}).json()
    assert body["total"] == 1
    assert body["items"][0]["rule_id"] == "WIN-003"


def test_pagination(client):
    body = client.get("/alerts", params={"limit": 1, "offset": 1}).json()
    assert len(body["items"]) == 1
    assert body["total"] == 2


def test_alert_detail_and_404(client):
    assert client.get("/alerts/1").json()["rule_id"] == "WIN-003"
    assert client.get("/alerts/999").status_code == 404


def test_stats_counters(client):
    body = client.get("/stats").json()
    assert body["alerts_total"] == 2
    assert body["by_severity"]["CRITICAL"] == 1
    assert body["by_severity"]["LOW"] == 1
    assert {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} == set(body["by_severity"])


def test_export_is_downloadable_json(client):
    response = client.get("/export")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert response.json()["count"] == 2


def test_rules_endpoint(client):
    rules = client.get("/rules").json()
    assert {rule["rule_id"] for rule in rules} == {"WIN-003", "WEB-003"}
