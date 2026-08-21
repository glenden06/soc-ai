import SeverityTag from "./SeverityTag.jsx";
import { meta } from "./severity.js";

const shortTime = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("fr-FR");
};

export default function AlertRow({ alert, selected, onSelect }) {
  const { color } = meta(alert.severity);
  return (
    <button
      type="button"
      onClick={() => onSelect(alert.id)}
      aria-current={selected}
      className={`flex w-full gap-3 border-b border-line px-4 py-3 text-left transition-colors hover:bg-panel focus:outline-none focus-visible:ring-2 focus-visible:ring-white/40 ${
        selected ? "bg-panel" : ""
      }`}
    >
      <span className="mt-1 w-0.5 shrink-0 rounded-full" style={{ backgroundColor: color }} />
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-2">
          <SeverityTag severity={alert.severity} />
          <span className="font-mono text-xs text-muted">{alert.rule_id}</span>
          <span className="truncate text-sm font-medium">{alert.rule_name}</span>
        </span>
        <span className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-muted">
          <span>{shortTime(alert.created_at)}</span>
          {alert.source_ip && <span>src {alert.source_ip}</span>}
          {alert.user && <span>user {alert.user}</span>}
          {alert.mitre_id && <span className="text-text/70">{alert.mitre_id}</span>}
          {alert.match_count > 1 && <span>{alert.match_count} occurrences</span>}
        </span>
        {alert.summary && (
          <span className="mt-1 block truncate text-xs text-muted">{alert.summary}</span>
        )}
      </span>
    </button>
  );
}
