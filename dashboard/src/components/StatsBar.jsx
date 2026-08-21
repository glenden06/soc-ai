import { SEVERITIES, meta } from "./severity.js";

// The spine: one bar per severity, height proportional to volume. It is the
// first thing an analyst reads, so it carries the whole 24h posture.
export default function StatsBar({ stats, active, onSelect }) {
  if (!stats) {
    return <div className="h-28 animate-pulse rounded border border-line bg-panel" />;
  }

  const counts = stats.by_severity;
  const peak = Math.max(1, ...SEVERITIES.map((level) => counts[level] || 0));

  return (
    <section className="rounded border border-line bg-panel">
      <header className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line px-4 py-2">
        <h2 className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
          Posture — {stats.window_hours} dernières heures
        </h2>
        <p className="font-mono text-xs text-muted">
          {stats.events_ingested} événements ingérés · {stats.alerts_total} alertes ·{" "}
          {stats.alerts_pending_triage} en attente de triage
        </p>
      </header>

      <div className="grid grid-cols-5 gap-px bg-line">
        {SEVERITIES.map((level) => {
          const value = counts[level] || 0;
          const { color, sla } = meta(level);
          const selected = active === level;
          return (
            <button
              key={level}
              type="button"
              onClick={() => onSelect(selected ? "" : level)}
              title={sla}
              aria-pressed={selected}
              className="group flex flex-col justify-end gap-2 bg-panel px-3 pb-3 pt-4 text-left transition-colors hover:bg-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-white/40"
              style={selected ? { backgroundColor: `${color}14` } : undefined}
            >
              <div className="flex items-end gap-2">
                <span className="font-mono text-2xl font-bold" style={{ color }}>
                  {value}
                </span>
                <span
                  className="mb-1 block w-full rounded-sm"
                  style={{
                    height: `${Math.max(3, (value / peak) * 34)}px`,
                    backgroundColor: value ? color : "#1F2733",
                    opacity: value ? 0.75 : 1,
                  }}
                />
              </div>
              <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted group-hover:text-text">
                {level}
              </span>
            </button>
          );
        })}
      </div>
    </section>
  );
}
