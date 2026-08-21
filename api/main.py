"""SOC-AI REST API.

Read-only view over the alert store, consumed by the React dashboard and by
any third-party tool. OpenAPI documentation is served on /docs.
"""

import json
import os
import sys
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import db  # noqa: E402

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

app = FastAPI(
    title="SOC-AI API",
    version="1.0.0",
    description="Triage automatise des alertes de securite par regles Sigma et LLM.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("SOCAI_CORS_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


def _row_to_alert(row):
    """Convert a SQLite row into the API alert representation."""
    return {
        "id": row["id"],
        "rule_id": row["rule_id"],
        "rule_name": row["rule_name"],
        "rule_severity": row["rule_severity"],
        "severity": row["severity"] or row["rule_severity"],
        "attack_type": row["attack_type"],
        "mitre_id": row["mitre_id"],
        "confidence": row["confidence"],
        "summary": row["summary"],
        "recommendation": row["recommendation"],
        "false_positive_risk": row["false_positive_risk"],
        "triage_status": row["triage_status"],
        "triage_engine": row["triage_engine"],
        "source_ip": row["source_ip"],
        "user": row["user"],
        "match_count": row["match_count"],
        "timestamp": row["timestamp"],
        "created_at": row["created_at"],
        "raw_log": row["raw_log"],
    }


def _filtered_query(severity, rule_id, source_ip, since_hours):
    """Build the WHERE clause shared by /alerts, /export and /stats."""
    clauses, params = [], []
    if severity:
        clauses.append("COALESCE(severity, rule_severity) = ?")
        params.append(severity.upper())
    if rule_id:
        clauses.append("rule_id = ?")
        params.append(rule_id.upper())
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip)
    if since_hours:
        cutoff = (datetime.now(UTC) - timedelta(hours=since_hours)).isoformat(timespec="seconds")
        clauses.append("created_at >= ?")
        params.append(cutoff)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


@app.get("/health", tags=["system"])
def health():
    """Liveness probe used by Docker Compose."""
    try:
        with db.session() as conn:
            conn.execute("SELECT 1").fetchone()
        return {"status": "ok", "database": "reachable"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"database unreachable: {exc}") from exc


@app.get("/alerts", tags=["alerts"])
def list_alerts(
    severity: str | None = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW or INFO"),
    rule_id: str | None = Query(None, description="Sigma rule id, e.g. SSH-001"),
    source_ip: str | None = None,
    since_hours: int | None = Query(None, ge=1, le=8760),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Return a paginated list of alerts, newest first."""
    where, params = _filtered_query(severity, rule_id, source_ip, since_hours)
    with db.session() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM alerts {where}", params).fetchone()["n"]
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY datetime(created_at) DESC, id DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return {"total": total, "limit": limit, "offset": offset,
            "items": [_row_to_alert(row) for row in rows]}


@app.get("/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: int):
    """Return the full detail of one alert, including the originating event."""
    with db.session() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="alert not found")
        alert = _row_to_alert(row)
        if row["event_id"]:
            event = conn.execute("SELECT * FROM events WHERE id = ?", (row["event_id"],)).fetchone()
            if event:
                alert["event"] = {
                    "id": event["id"],
                    "timestamp": event["timestamp"],
                    "source_type": event["source_type"],
                    "action": event["action"],
                    "extra": json.loads(event["extra"] or "{}"),
                }
    return alert


@app.get("/stats", tags=["alerts"])
def stats(since_hours: int = Query(24, ge=1, le=8760)):
    """Return alert counters for the dashboard, over a rolling window."""
    cutoff = (datetime.now(UTC) - timedelta(hours=since_hours)).isoformat(timespec="seconds")
    with db.session() as conn:
        by_severity = {level: 0 for level in SEVERITIES}
        for row in conn.execute(
            "SELECT COALESCE(severity, rule_severity) AS sev, COUNT(*) AS n "
            "FROM alerts WHERE created_at >= ? GROUP BY sev", (cutoff,)
        ):
            if row["sev"] in by_severity:
                by_severity[row["sev"]] = row["n"]

        by_rule = [
            {"rule_id": row["rule_id"], "rule_name": row["rule_name"], "count": row["n"]}
            for row in conn.execute(
                "SELECT rule_id, rule_name, COUNT(*) AS n FROM alerts WHERE created_at >= ? "
                "GROUP BY rule_id, rule_name ORDER BY n DESC LIMIT 10", (cutoff,)
            )
        ]
        top_sources = [
            {"source_ip": row["source_ip"], "count": row["n"]}
            for row in conn.execute(
                "SELECT source_ip, COUNT(*) AS n FROM alerts WHERE created_at >= ? "
                "AND source_ip IS NOT NULL GROUP BY source_ip ORDER BY n DESC LIMIT 5", (cutoff,)
            )
        ]
        totals = conn.execute(
            "SELECT COUNT(*) AS alerts, "
            "SUM(CASE WHEN triage_status = 'new' THEN 1 ELSE 0 END) AS pending FROM alerts"
        ).fetchone()
        events = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]

    return {
        "window_hours": since_hours,
        "events_ingested": events,
        "alerts_total": totals["alerts"] or 0,
        "alerts_pending_triage": totals["pending"] or 0,
        "by_severity": by_severity,
        "by_rule": by_rule,
        "top_sources": top_sources,
    }


@app.get("/export", tags=["alerts"])
def export(
    severity: str | None = None,
    rule_id: str | None = None,
    source_ip: str | None = None,
    since_hours: int | None = Query(None, ge=1, le=8760),
):
    """Export the filtered alerts as a downloadable JSON file."""
    where, params = _filtered_query(severity, rule_id, source_ip, since_hours)
    with db.session() as conn:
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY datetime(created_at) DESC", params
        ).fetchall()

    payload = {
        "generated_at": db.now_iso(),
        "count": len(rows),
        "filters": {"severity": severity, "rule_id": rule_id,
                    "source_ip": source_ip, "since_hours": since_hours},
        "alerts": [_row_to_alert(row) for row in rows],
    }
    filename = f"soc-ai-export-{datetime.now(UTC):%Y%m%d-%H%M%S}.json"
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/rules", tags=["system"])
def rules():
    """Return the distinct rules that have fired at least once."""
    with db.session() as conn:
        rows = conn.execute(
            "SELECT rule_id, rule_name, rule_severity, COUNT(*) AS n "
            "FROM alerts GROUP BY rule_id, rule_name, rule_severity ORDER BY rule_id"
        ).fetchall()
    return [{"rule_id": r["rule_id"], "rule_name": r["rule_name"],
             "severity": r["rule_severity"], "alerts": r["n"]} for r in rows]
