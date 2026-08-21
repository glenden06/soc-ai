import SeverityTag from "./SeverityTag.jsx";
import { meta } from "./severity.js";

function Field({ label, value }) {
  if (!value) return null;
  return (
    <div className="border-b border-line py-2 last:border-0">
      <dt className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted">{label}</dt>
      <dd className="mt-1 text-sm">{value}</dd>
    </div>
  );
}

export default function AlertDetail({ alert, loading, onClose }) {
  if (loading) {
    return <div className="h-full animate-pulse bg-panel" />;
  }

  if (!alert) {
    return (
      <div className="flex h-full flex-col items-start justify-center gap-2 p-6">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">Aucune alerte ouverte</p>
        <p className="text-sm text-muted">
          Choisissez une alerte dans la liste pour lire le triage complet et le journal brut.
        </p>
      </div>
    );
  }

  const { sla, color } = meta(alert.severity);

  return (
    <article className="flex h-full flex-col overflow-y-auto">
      <header className="sticky top-0 z-10 border-b border-line bg-ink/95 px-5 py-4 backdrop-blur">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityTag severity={alert.severity} />
              <span className="font-mono text-xs text-muted">{alert.rule_id}</span>
            </div>
            <h2 className="mt-2 text-lg font-semibold leading-tight">{alert.rule_name}</h2>
            <p className="mt-1 font-mono text-[11px] text-muted">{sla}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="shrink-0 rounded border border-line px-2 py-1 font-mono text-[11px] text-muted hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-white/40"
          >
            Fermer
          </button>
        </div>
      </header>

      <div className="px-5 py-4">
        {alert.summary && (
          <p className="border-l-2 pl-3 text-sm leading-relaxed" style={{ borderColor: color }}>
            {alert.summary}
          </p>
        )}

        {alert.recommendation && (
          <div className="mt-4 rounded border border-line bg-panel p-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted">
              Action recommandée
            </p>
            <p className="mt-1 text-sm">{alert.recommendation}</p>
          </div>
        )}

        <dl className="mt-4">
          <Field label="Technique" value={alert.attack_type} />
          <Field label="MITRE ATT&CK" value={alert.mitre_id} />
          <Field
            label="Confiance du triage"
            value={alert.confidence !== null ? `${alert.confidence} / 100` : null}
          />
          <Field label="Risque de faux positif" value={alert.false_positive_risk} />
          <Field label="IP source" value={alert.source_ip} />
          <Field label="Compte concerné" value={alert.user} />
          <Field label="Occurrences dans la fenêtre" value={alert.match_count} />
          <Field label="Horodatage de l'événement" value={alert.timestamp} />
          <Field label="Moteur de triage" value={alert.triage_engine} />
        </dl>

        {alert.raw_log && (
          <section className="mt-4">
            <h3 className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted">
              Journal brut
            </h3>
            <pre className="mt-2 overflow-x-auto rounded border border-line bg-panel p-3 font-mono text-[11px] leading-relaxed text-text/90">
              {alert.raw_log}
            </pre>
          </section>
        )}
      </div>
    </article>
  );
}
