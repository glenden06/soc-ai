"""Unit tests for the LLM triage agent, including the offline fallback."""

import json

import agent as triage_agent
import pytest
import requests

from common import db


@pytest.fixture()
def alert_row(conn):
    with conn:
        db.insert_alert(conn, {
            "rule_id": "SSH-001",
            "rule_name": "Brute Force SSH",
            "rule_severity": "HIGH",
            "event_id": None,
            "source_ip": "45.83.64.12",
            "user": "admin",
            "timestamp": "2026-08-20T09:14:31+00:00",
            "raw_log": "Failed password for invalid user admin from 45.83.64.12",
            "match_count": 8,
        })
    return conn.execute("SELECT * FROM alerts WHERE id = 1").fetchone()


def test_heuristic_returns_valid_contract(alert_row):
    result, engine = triage_agent.triage_heuristic(alert_row)
    assert result["severity"] in triage_agent.VALID_SEVERITIES
    assert result["false_positive_risk"] in triage_agent.VALID_RISKS
    assert 0 <= result["confidence"] <= 100
    assert result["mitre_id"] == "T1110.001"
    assert "45.83.64.12" in result["summary"]
    assert engine.startswith("heuristic")


def test_heuristic_handles_unknown_rule(conn):
    with conn:
        db.insert_alert(conn, {
            "rule_id": "CUSTOM-999", "rule_name": "Regle maison", "rule_severity": "LOW",
            "timestamp": "2026-08-20T09:00:00+00:00", "raw_log": "x", "match_count": 1,
        })
    row = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 1").fetchone()
    result, _ = triage_agent.triage_heuristic(row)
    assert result["severity"] == "LOW"


def test_extract_json_strips_markdown_fence():
    payload = triage_agent._extract_json('```json\n{"severity": "HIGH"}\n```')
    assert payload["severity"] == "HIGH"
    with pytest.raises(ValueError):
        triage_agent._extract_json("pas de json ici")


def test_normalise_rejects_invalid_values(alert_row):
    result = triage_agent.normalise(
        {"severity": "BANANE", "confidence": 5000, "false_positive_risk": "?",
         "mitre_id": "null", "summary": "s", "recommendation": "r"},
        alert_row,
    )
    assert result["severity"] == "HIGH"          # falls back to the rule severity
    assert result["confidence"] == 100           # clamped
    assert result["false_positive_risk"] == "MEDIUM"
    assert result["mitre_id"] is None


def test_anonymise_removes_emails_and_optionally_ips():
    text = "user jean.dupont@bmn.fr from 45.83.64.12"
    assert "@" not in triage_agent.anonymise(text)
    assert "45.83.64.12" not in triage_agent.anonymise(text, keep_ip=False)


def test_claude_backend_parses_api_response(monkeypatch, alert_row):
    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"content": [{"type": "text", "text": json.dumps({
                "severity": "CRITICAL", "attack_type": "Brute Force SSH",
                "mitre_id": "T1110.001", "confidence": 97,
                "summary": "Attaque en cours.", "recommendation": "Bloquer l'IP.",
                "false_positive_risk": "LOW",
            })}]}

    monkeypatch.setattr(triage_agent, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(triage_agent.requests, "post", lambda *a, **k: FakeResponse())
    result, engine = triage_agent.triage_claude(alert_row)
    assert result["severity"] == "CRITICAL"
    assert result["confidence"] == 97
    assert engine.startswith("claude:")


def test_triage_falls_back_when_api_fails(monkeypatch, alert_row):
    def boom(*args, **kwargs):
        raise requests.RequestException("network down")

    monkeypatch.setattr(triage_agent, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(triage_agent.requests, "post", boom)
    result, engine = triage_agent.triage(alert_row)
    assert engine.startswith("heuristic")
    assert result["severity"] in triage_agent.VALID_SEVERITIES


def test_run_once_updates_status(conn, alert_row):
    assert triage_agent.run_once(conn) == 1
    row = conn.execute("SELECT * FROM alerts WHERE id = 1").fetchone()
    assert row["triage_status"] == "triaged"
    assert row["summary"]
    assert triage_agent.run_once(conn) == 0
