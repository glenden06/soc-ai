"""SOC-AI triage agent.

Consumes alerts with triage_status = 'new' and qualifies each one with a
severity, an attack type, a MITRE technique, a summary and a recommendation.

Three backends, tried in this order:
  1. Claude API   -> ANTHROPIC_API_KEY is set
  2. Ollama local -> OLLAMA_HOST is set (offline deployment)
  3. Heuristic    -> always available, keeps the pipeline deterministic in CI
"""

import argparse
import json
import logging
import os
import re
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import db  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PROMPT_PATH = os.path.join(HERE, "prompts", "triage_system.txt")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "").strip()
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")
POLL_INTERVAL = float(os.getenv("SOCAI_POLL_INTERVAL", "4"))
REQUEST_TIMEOUT = float(os.getenv("SOCAI_LLM_TIMEOUT", "45"))

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_RISKS = {"LOW", "MEDIUM", "HIGH"}

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
FENCE_RE = re.compile(r"^```(?:json)?|```$", re.MULTILINE)

# Deterministic fallback knowledge base, keyed by rule id.
HEURISTICS = {
    "SSH-001": ("HIGH", "Brute Force SSH", "T1110.001", 92, "LOW",
                "Bloquer l'IP source au niveau du pare-feu et activer fail2ban.",
                "Tentative de brute force SSH detectee depuis {ip}."),
    "SSH-002": ("HIGH", "Valid Accounts: Local Accounts", "T1078.003", 85, "MEDIUM",
                "Desactiver PermitRootLogin dans sshd_config et forcer l'usage de sudo.",
                "Connexion root directe en SSH depuis {ip}."),
    "SSH-003": ("MEDIUM", "Valid Accounts", "T1078", 70, "MEDIUM",
                "Verifier la legitimite de la session et restreindre l'acces SSH par liste blanche.",
                "Connexion SSH reussie depuis une adresse externe {ip}."),
    "WEB-001": ("HIGH", "Exploit Public-Facing Application", "T1190", 90, "LOW",
                "Bloquer l'IP source et verifier les journaux applicatifs et la base de donnees.",
                "Motif d'injection SQL detecte dans une requete HTTP depuis {ip}."),
    "WEB-002": ("MEDIUM", "File and Directory Discovery", "T1083", 78, "MEDIUM",
                "Verifier si un fichier sensible a ete servi et durcir la normalisation des chemins.",
                "Tentative de path traversal detectee depuis {ip}."),
    "WEB-003": ("LOW", "Active Scanning", "T1595", 88, "MEDIUM",
                "Surveiller la source et appliquer une limitation de debit si le scan persiste.",
                "Scanner de vulnerabilite identifie par son User-Agent depuis {ip}."),
    "WIN-001": ("CRITICAL", "Valid Accounts", "T1078", 80, "MEDIUM",
                "Verifier l'identite du compte et l'appartenance aux groupes a privileges.",
                "Privileges speciaux assignes a une session Windows (event 4672)."),
    "WIN-002": ("MEDIUM", "Create Account: Local Account", "T1136.001", 75, "MEDIUM",
                "Confirmer que la creation de compte correspond a une demande RH tracee.",
                "Creation d'un compte utilisateur Windows detectee (event 4720)."),
    "WIN-003": ("CRITICAL", "OS Credential Dumping: Security Account Manager", "T1003.002", 94, "LOW",
                "Isoler la machine et lancer une reponse a incident sur le vol d'empreintes.",
                "Acces a la ruche SAM detecte, vol d'empreintes probable."),
    "NET-001": ("HIGH", "Network Service Discovery", "T1046", 87, "LOW",
                "Bloquer l'IP source et verifier les services exposes sur les ports scannes.",
                "Balayage de ports detecte depuis {ip}."),
}


def _load_prompt():
    """Read the system prompt template from disk."""
    try:
        with open(PROMPT_PATH, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return "You are a senior SOC analyst. Return only a valid JSON triage object."


SYSTEM_PROMPT = _load_prompt()

logging.basicConfig(
    level=os.getenv("SOCAI_LOG_LEVEL", "INFO"),
    format="%(asctime)s [llm_agent] %(levelname)s %(message)s",
)
log = logging.getLogger("llm_agent")


def anonymise(text, keep_ip=True):
    """Strip obvious personal data before the log leaves the perimeter."""
    if not text:
        return ""
    cleaned = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "<email>", text)
    if not keep_ip:
        cleaned = IP_RE.sub("<ip>", cleaned)
    return cleaned[:1500]


def build_user_prompt(alert):
    """Build the alert context sent to the model."""
    keep_ip = os.getenv("SOCAI_SEND_IP", "true").lower() != "false"
    return (
        f"Sigma rule triggered: {alert['rule_id']} - {alert['rule_name']}\n"
        f"Rule severity: {alert['rule_severity']}\n"
        f"Timestamp: {alert['timestamp']}\n"
        f"Source IP: {alert['source_ip'] if keep_ip else '<redacted>'}\n"
        f"User: {alert['user'] or 'n/a'}\n"
        f"Occurrences in window: {alert['match_count']}\n"
        f"Raw log: {anonymise(alert['raw_log'], keep_ip)}"
    )


def _extract_json(text):
    """Pull the first JSON object out of a model response."""
    cleaned = FENCE_RE.sub("", text or "").strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in model response")
    return json.loads(cleaned[start:end + 1])


def normalise(payload, alert):
    """Validate and coerce the model output into the SOC-AI triage contract."""
    severity = str(payload.get("severity", "")).upper()
    if severity not in VALID_SEVERITIES:
        severity = alert["rule_severity"]

    risk = str(payload.get("false_positive_risk", "")).upper()
    if risk not in VALID_RISKS:
        risk = "MEDIUM"

    try:
        confidence = int(payload.get("confidence", 50))
    except (TypeError, ValueError):
        confidence = 50
    confidence = max(0, min(100, confidence))

    mitre = payload.get("mitre_id")
    if mitre in ("null", "None", ""):
        mitre = None

    return {
        "severity": severity,
        "attack_type": str(payload.get("attack_type") or alert["rule_name"])[:120],
        "mitre_id": str(mitre)[:20] if mitre else None,
        "confidence": confidence,
        "summary": str(payload.get("summary") or "")[:600],
        "recommendation": str(payload.get("recommendation") or "")[:600],
        "false_positive_risk": risk,
    }


def triage_claude(alert):
    """Call the Anthropic Messages API. Raises on any transport or format error."""
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": ANTHROPIC_MODEL,
            "max_tokens": 700,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": build_user_prompt(alert)}],
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    body = response.json()
    text = "".join(block.get("text", "") for block in body.get("content", []) if block.get("type") == "text")
    return normalise(_extract_json(text), alert), f"claude:{ANTHROPIC_MODEL}"


def triage_ollama(alert):
    """Call a local Ollama server for fully offline deployments."""
    response = requests.post(
        f"{OLLAMA_HOST.rstrip('/')}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "system": SYSTEM_PROMPT,
            "prompt": build_user_prompt(alert),
            "stream": False,
            "format": "json",
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return normalise(_extract_json(response.json().get("response", "")), alert), f"ollama:{OLLAMA_MODEL}"


def triage_heuristic(alert):
    """Deterministic fallback so the pipeline never stalls without an LLM."""
    severity, attack, mitre, confidence, risk, reco, summary = HEURISTICS.get(
        alert["rule_id"],
        (alert["rule_severity"], alert["rule_name"], None, 50, "MEDIUM",
         "Analyser manuellement l'alerte et son contexte.",
         "Alerte generee par la regle {rule}."),
    )
    ip = alert["source_ip"] or "source inconnue"
    text = summary.format(ip=ip, rule=alert["rule_id"])
    if alert["match_count"] and alert["match_count"] > 1:
        text += f" {alert['match_count']} occurrences dans la fenetre de detection."

    return {
        "severity": severity,
        "attack_type": attack,
        "mitre_id": mitre,
        "confidence": confidence,
        "summary": text,
        "recommendation": reco,
        "false_positive_risk": risk,
    }, "heuristic:v1"


def triage(alert):
    """Qualify one alert using the best available backend."""
    if ANTHROPIC_API_KEY:
        try:
            return triage_claude(alert)
        except (requests.RequestException, ValueError, KeyError) as exc:
            log.error("Claude triage failed, falling back: %s", exc)
    if OLLAMA_HOST:
        try:
            return triage_ollama(alert)
        except (requests.RequestException, ValueError, KeyError) as exc:
            log.error("Ollama triage failed, falling back: %s", exc)
    return triage_heuristic(alert)


def run_once(conn, limit=25):
    """Triage every pending alert. Returns the number of alerts processed."""
    rows = conn.execute(
        "SELECT * FROM alerts WHERE triage_status = 'new' ORDER BY id ASC LIMIT ?", (limit,)
    ).fetchall()

    processed = 0
    for alert in rows:
        try:
            result, engine = triage(alert)
        except Exception as exc:
            log.error("unexpected triage failure on alert %s: %s", alert["id"], exc)
            continue

        with conn:
            conn.execute(
                """UPDATE alerts SET triage_status='triaged', severity=?, attack_type=?,
                   mitre_id=?, confidence=?, summary=?, recommendation=?,
                   false_positive_risk=?, triage_engine=?, triaged_at=?
                   WHERE id = ?""",
                (
                    result["severity"], result["attack_type"], result["mitre_id"],
                    result["confidence"], result["summary"], result["recommendation"],
                    result["false_positive_risk"], engine, db.now_iso(), alert["id"],
                ),
            )
        processed += 1
        log.info("alert %s triaged %s (%s)", alert["id"], result["severity"], engine)
    return processed


def main():
    """CLI entry point."""
    argp = argparse.ArgumentParser(description="SOC-AI LLM triage agent")
    argp.add_argument("--once", action="store_true", help="single pass then exit")
    args = argp.parse_args()

    backend = "claude" if ANTHROPIC_API_KEY else ("ollama" if OLLAMA_HOST else "heuristic")
    log.info("triage backend: %s", backend)
    conn = db.init_db()

    if args.once:
        total = run_once(conn)
        log.info("one-shot triage complete: %d alerts", total)
        conn.close()
        return

    while True:
        try:
            run_once(conn)
        except Exception as exc:
            log.error("triage cycle failed: %s", exc)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
