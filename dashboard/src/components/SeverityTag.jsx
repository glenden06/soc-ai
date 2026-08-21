import { meta } from "./severity.js";

export default function SeverityTag({ severity, count }) {
  const { color } = meta(severity);
  return (
    <span
      className="inline-flex items-center gap-2 rounded-sm border px-2 py-0.5 font-mono text-[11px] font-bold tracking-widest"
      style={{ color, borderColor: `${color}55`, backgroundColor: `${color}12` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {severity}
      {count !== undefined && <span className="text-muted">×{count}</span>}
    </span>
  );
}
