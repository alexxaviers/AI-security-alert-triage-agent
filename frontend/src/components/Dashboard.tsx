"use client";

import { useCallback, useEffect, useState } from "react";
import { api, API_URL, type AlertSummary, type Severity, type Stats } from "@/lib/api";
import AlertDetailPanel from "./AlertDetailPanel";
import { ConfidenceBar, SeverityBadge, StatusLabel, TechniqueLink } from "./badges";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const STATUSES = ["", "needs_review", "triaged", "overridden", "pending", "error"];
const PAGE = 50;

function timeAgo(iso: string): string {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function StatTile({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="rounded-lg bg-slate-900/70 px-4 py-3 ring-1 ring-slate-800">
      <div className="text-[11px] uppercase tracking-[0.12em] text-slate-500">{label}</div>
      <div className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${tone ?? "text-slate-100"}`}>{value}</div>
    </div>
  );
}

export default function Dashboard() {
  const [items, setItems] = useState<AlertSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<Stats | null>(null);
  const [severity, setSeverity] = useState<string>("");
  const [status, setStatus] = useState<string>("");
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<"severity" | "received">("severity");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [debouncedQ, setDebouncedQ] = useState("");

  const load = useCallback(async () => {
    try {
      const [list, st] = await Promise.all([
        api.list({ severity, status, q: debouncedQ, sort, limit: PAGE, offset: page * PAGE }),
        api.stats(),
      ]);
      setItems(list.items);
      setTotal(list.total);
      setStats(st);
      setError(null);
    } catch (e) {
      setError(`Can't reach the API at ${API_URL} (${(e as Error).message})`);
    } finally {
      setLoading(false);
    }
  }, [severity, status, sort, page, debouncedQ]);

  useEffect(() => {
    const t = setTimeout(load, 0); // refetch when filters change
    return () => clearTimeout(t);
  }, [load]);

  // Debounced search
  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedQ(q);
      setPage(0);
    }, 300);
    return () => clearTimeout(t);
  }, [q]);

  // Poll while the agent is still working through alerts
  const busy = (stats?.by_status.pending ?? 0) + (stats?.by_status.triaging ?? 0) > 0;
  useEffect(() => {
    const t = setInterval(load, busy ? 3000 : 15000);
    return () => clearInterval(t);
  }, [load, busy]);

  const sevCount = (s: string) => stats?.by_severity[s] ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  return (
    <div className="flex h-screen flex-col bg-slate-950 text-slate-200">
      <header className="flex items-center justify-between border-b border-slate-800 px-6 py-3">
        <div className="flex items-center gap-3">
          <div className="grid h-8 w-8 place-items-center rounded-md bg-gradient-to-br from-sky-500 to-violet-600 font-mono text-sm font-bold text-white">
            T
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-tight text-slate-100">Alert Triage Console</h1>
            <p className="text-xs text-slate-500">LangGraph agent · IP / hash / ATT&CK tools</p>
          </div>
        </div>
        <div className="flex items-center gap-3 text-xs">
          {busy && (
            <span className="flex items-center gap-1.5 text-sky-300">
              <span className="h-2 w-2 animate-pulse rounded-full bg-sky-400" />
              triaging {(stats?.by_status.pending ?? 0) + (stats?.by_status.triaging ?? 0)}
            </span>
          )}
          {stats && (
            <span className="rounded-md bg-slate-900 px-2 py-1 font-mono text-slate-400 ring-1 ring-slate-800">
              engine: {stats.engine}
            </span>
          )}
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <main className="flex min-w-0 flex-1 flex-col">
          <div className="grid grid-cols-2 gap-3 px-6 pt-5 md:grid-cols-6">
            <StatTile label="Alerts" value={stats?.total ?? "—"} />
            <StatTile label="Critical" value={sevCount("critical")} tone="text-red-300" />
            <StatTile label="High" value={sevCount("high")} tone="text-orange-300" />
            <StatTile label="Needs review" value={stats?.needs_review ?? 0} tone="text-yellow-300" />
            <StatTile
              label="Avg latency"
              value={stats?.avg_latency_ms != null ? `${(stats.avg_latency_ms / 1000).toFixed(1)}s` : "—"}
            />
            <StatTile label="LLM cost" value={stats ? `$${stats.total_cost_usd.toFixed(2)}` : "—"} />
          </div>

          <div className="flex flex-wrap items-center gap-2 px-6 py-4">
            <button
              onClick={() => {
                setSeverity("");
                setPage(0);
              }}
              className={`rounded-md px-2.5 py-1 text-xs font-medium ring-1 ${severity === "" ? "bg-slate-800 text-slate-100 ring-slate-600" : "text-slate-400 ring-slate-800 hover:text-slate-200"}`}
            >
              All
            </button>
            {SEVERITIES.map((s) => (
              <button
                key={s}
                onClick={() => {
                  setSeverity(severity === s ? "" : s);
                  setPage(0);
                }}
                className={`rounded-md px-1 py-0.5 ${severity === s ? "ring-2 ring-sky-400" : severity ? "opacity-50 hover:opacity-100" : ""}`}
              >
                <SeverityBadge severity={s} />
              </button>
            ))}
            <select
              value={status}
              onChange={(e) => {
                setStatus(e.target.value);
                setPage(0);
              }}
              className="ml-2 rounded-md bg-slate-900 px-2 py-1 text-xs text-slate-300 ring-1 ring-slate-800 focus:outline-none"
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s ? s.replace("_", " ") : "any status"}
                </option>
              ))}
            </select>
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as "severity" | "received")}
              className="rounded-md bg-slate-900 px-2 py-1 text-xs text-slate-300 ring-1 ring-slate-800 focus:outline-none"
            >
              <option value="severity">sort: severity</option>
              <option value="received">sort: newest</option>
            </select>
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search ID or title…"
              className="ml-auto w-56 rounded-md bg-slate-900 px-3 py-1.5 text-xs text-slate-200 ring-1 ring-slate-800 placeholder:text-slate-600 focus:outline-none focus:ring-sky-500"
            />
          </div>

          {error && <div className="mx-6 mb-3 rounded-md bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</div>}

          <div className="min-h-0 flex-1 overflow-auto px-6">
            <table className="w-full border-separate border-spacing-0 text-sm">
              <thead className="sticky top-0 z-10 bg-slate-950">
                <tr className="text-left text-[11px] uppercase tracking-[0.1em] text-slate-500">
                  <th className="border-b border-slate-800 py-2 pr-3 font-medium">Severity</th>
                  <th className="border-b border-slate-800 py-2 pr-3 font-medium">Alert</th>
                  <th className="hidden border-b border-slate-800 py-2 pr-3 font-medium lg:table-cell">Source</th>
                  <th className="border-b border-slate-800 py-2 pr-3 font-medium">ATT&CK</th>
                  <th className="hidden border-b border-slate-800 py-2 pr-3 font-medium md:table-cell">Confidence</th>
                  <th className="border-b border-slate-800 py-2 pr-3 font-medium">Status</th>
                  <th className="hidden border-b border-slate-800 py-2 font-medium xl:table-cell">Received</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => setSelected(a.id)}
                    className={`cursor-pointer ${selected === a.id ? "bg-sky-500/10" : "hover:bg-slate-900"}`}
                  >
                    <td className="border-b border-slate-900 py-2.5 pr-3">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="max-w-0 border-b border-slate-900 py-2.5 pr-3">
                      <div className="truncate text-slate-200">{a.title}</div>
                      <div className="font-mono text-[11px] text-slate-500">
                        {a.id}
                        {a.overridden && <span className="ml-2 text-violet-300">overridden</span>}
                      </div>
                    </td>
                    <td className="hidden border-b border-slate-900 py-2.5 pr-3 text-xs text-slate-400 lg:table-cell">
                      {a.source}
                    </td>
                    <td className="border-b border-slate-900 py-2.5 pr-3">
                      <TechniqueLink technique={a.technique} />
                    </td>
                    <td className="hidden border-b border-slate-900 py-2.5 pr-3 md:table-cell">
                      <ConfidenceBar value={a.confidence} />
                    </td>
                    <td className="border-b border-slate-900 py-2.5 pr-3">
                      <StatusLabel status={a.status} />
                    </td>
                    <td className="hidden border-b border-slate-900 py-2.5 text-xs text-slate-500 xl:table-cell">
                      {timeAgo(a.received_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!loading && items.length === 0 && !error && (
              <div className="py-16 text-center text-sm text-slate-500">
                No alerts yet. Seed some with <code className="font-mono text-slate-300">python scripts/seed.py</code>
              </div>
            )}
          </div>

          <div className="flex items-center justify-between border-t border-slate-800 px-6 py-2 text-xs text-slate-500">
            <span>
              {total} alert{total === 1 ? "" : "s"}
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={page === 0}
                onClick={() => setPage(page - 1)}
                className="rounded px-2 py-1 hover:bg-slate-800 disabled:opacity-30"
              >
                ‹ Prev
              </button>
              <span className="font-mono">
                {page + 1} / {pages}
              </span>
              <button
                disabled={page + 1 >= pages}
                onClick={() => setPage(page + 1)}
                className="rounded px-2 py-1 hover:bg-slate-800 disabled:opacity-30"
              >
                Next ›
              </button>
            </div>
          </div>
        </main>

        {selected && (
          <div className="fixed inset-0 z-20 md:static md:inset-auto md:w-[480px] md:shrink-0 xl:w-[560px]">
            <AlertDetailPanel key={selected} id={selected} onClose={() => setSelected(null)} onChanged={load} />
          </div>
        )}
      </div>
    </div>
  );
}
