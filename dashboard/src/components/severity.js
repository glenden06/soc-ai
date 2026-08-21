// Severity vocabulary shared by every view. Colours come from the technical
// specification so the console matches the printed runbook.
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export const SEVERITY_META = {
  CRITICAL: { color: "#FF0000", sla: "Intervention immédiate, moins de 15 min", weight: 5 },
  HIGH: { color: "#FF6600", sla: "Traitement dans l'heure", weight: 4 },
  MEDIUM: { color: "#FFB300", sla: "Traitement dans la journée", weight: 3 },
  LOW: { color: "#0066CC", sla: "Revue hebdomadaire", weight: 2 },
  INFO: { color: "#666666", sla: "Archivage, pas d'action", weight: 1 },
};

export const meta = (severity) => SEVERITY_META[severity] || SEVERITY_META.INFO;
