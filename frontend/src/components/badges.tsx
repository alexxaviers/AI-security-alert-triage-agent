import type { Severity } from "@/lib/api";
import { attackUrl } from "@/lib/api";

const SEV_STYLE: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300 ring-red-500/40",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  medium: "bg-amber-400/10 text-amber-200 ring-amber-400/30",
  low: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
};
const SEV_DOT: Record<Severity, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-slate-500",
};

export function SeverityBadge({ severity }: { severity: Severity | null }) {
  if (!severity) return <span className="text-xs text-slate-500">—</span>;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ring-1 ring-inset ${SEV_STYLE[severity]}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[severity]}`} />
      {severity}
    </span>
  );
}

const STATUS_STYLE: Record<string, string> = {
  pending: "text-slate-400",
  triaging: "text-sky-300 animate-pulse",
  triaged: "text-emerald-300",
  needs_review: "text-yellow-300",
  overridden: "text-violet-300",
  error: "text-red-400",
};

export function StatusLabel({ status }: { status: string }) {
  return (
    <span className={`text-xs font-medium ${STATUS_STYLE[status] ?? "text-slate-400"}`}>
      {status.replace("_", " ")}
    </span>
  );
}

export function ConfidenceBar({ value }: { value: number | null }) {
  if (value === null || value === undefined) return <span className="text-xs text-slate-500">—</span>;
  const pct = Math.round(value * 100);
  const color = value < 0.6 ? "bg-yellow-400" : value < 0.8 ? "bg-sky-400" : "bg-emerald-400";
  return (
    <div className="flex items-center gap-2" title={`${pct}% confidence`}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-8 text-right font-mono text-xs tabular-nums text-slate-400">{pct}%</span>
    </div>
  );
}

export function TechniqueLink({ technique, name }: { technique: string | null; name?: string | null }) {
  if (!technique) return <span className="text-xs text-slate-500">—</span>;
  const url = attackUrl(technique);
  if (!url) return <span className="font-mono text-xs text-slate-500">none</span>;
  return (
    <a
      href={url}
      target="_blank"
      rel="noreferrer"
      className="font-mono text-xs text-sky-300 hover:text-sky-200 hover:underline"
      onClick={(e) => e.stopPropagation()}
    >
      {technique}
      {name ? <span className="ml-1.5 font-sans text-slate-400">{name}</span> : null}
    </a>
  );
}
