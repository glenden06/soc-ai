import { useCallback, useEffect, useState } from "react";
import AlertDetail from "./components/AlertDetail.jsx";
import AlertRow from "./components/AlertRow.jsx";
import StatsBar from "./components/StatsBar.jsx";
import { exportUrl, getAlert, getAlerts, getStats } from "./api.js";

const REFRESH_MS = 10000;
const PAGE_SIZE = 50;

export default function App() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState(null);
  const [live, setLive] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const [statsBody, alertsBody] = await Promise.all([
        getStats({ since_hours: 24 }),
        getAlerts({ severity, limit: PAGE_SIZE }),
      ]);
      setStats(statsBody);
      setAlerts(alertsBody.items);
      setTotal(alertsBody.total);
      setError(null);
    } catch (err) {
      setError("API injoignable. Vérifiez que le conteneur api est démarré.");
    }
  }, [severity]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!live) return undefined;
    const timer = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(timer);
  }, [live, refresh]);

  useEffect(() => {
    if (selectedId === null) {
      setDetail(null);
      return;
    }
    setDetailLoading(true);
    getAlert(selectedId)
      .then(setDetail)
      .catch(() => setError("Impossible de charger le détail de l'alerte."))
      .finally(() => setDetailLoading(false));
  }, [selectedId]);

  return (
    <div className="mx-auto flex min-h-screen max-w-[1400px] flex-col gap-4 px-4 py-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-mono text-xl font-bold tracking-tight">
            SOC<span className="text-sev-high">-</span>AI
          </h1>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted">
            Triage des alertes par règles Sigma et LLM
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setLive((value) => !value)}
            className="rounded border border-line px-3 py-1.5 font-mono text-[11px] text-muted hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-white/40"
          >
            <span
              className={`mr-2 inline-block h-1.5 w-1.5 rounded-full ${
                live ? "bg-sev-low" : "bg-muted"
              }`}
            />
            {live ? "Rafraîchissement auto" : "En pause"}
          </button>
          <button
            type="button"
            onClick={refresh}
            className="rounded border border-line px-3 py-1.5 font-mono text-[11px] text-muted hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-white/40"
          >
            Rafraîchir
          </button>
          <a
            href={exportUrl({ severity })}
            className="rounded border border-line bg-panel px-3 py-1.5 font-mono text-[11px] hover:border-muted focus:outline-none focus-visible:ring-2 focus-visible:ring-white/40"
          >
            Exporter en JSON
          </a>
        </div>
      </header>

      {error && (
        <p className="rounded border border-sev-high/40 bg-sev-high/10 px-4 py-2 font-mono text-xs text-sev-high">
          {error}
        </p>
      )}

      <StatsBar stats={stats} active={severity} onSelect={setSeverity} />

      <main className="grid flex-1 grid-cols-1 gap-4 lg:grid-cols-[1.4fr_1fr]">
        <section className="flex flex-col overflow-hidden rounded border border-line">
          <header className="flex items-baseline justify-between border-b border-line bg-panel px-4 py-2">
            <h2 className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
              File d'alertes
            </h2>
            <p className="font-mono text-[11px] text-muted">
              {total} résultat{total > 1 ? "s" : ""}
              {severity && ` · filtre ${severity}`}
            </p>
          </header>

          <div className="max-h-[62vh] overflow-y-auto">
            {alerts.length === 0 ? (
              <p className="px-4 py-8 text-sm text-muted">
                Aucune alerte pour ce filtre. Déposez un fichier de logs dans le dossier logs pour
                lancer une détection.
              </p>
            ) : (
              alerts.map((alert) => (
                <AlertRow
                  key={alert.id}
                  alert={alert}
                  selected={alert.id === selectedId}
                  onSelect={setSelectedId}
                />
              ))
            )}
          </div>
        </section>

        <section className="rounded border border-line bg-ink">
          <AlertDetail
            alert={detail}
            loading={detailLoading}
            onClose={() => setSelectedId(null)}
          />
        </section>
      </main>

      <footer className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted">
        SOC-AI v1.0 · Licence MIT · Sigma et MITRE ATT&CK
      </footer>
    </div>
  );
}
