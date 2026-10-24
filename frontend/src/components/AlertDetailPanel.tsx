"use client";

import { useEffect, useState } from "react";
import { api, type AlertDetail, type Severity } from "@/lib/api";
import { ConfidenceBar, SeverityBadge, StatusLabel, TechniqueLink } from "./badges";

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];
const TOOL_LABEL: Record<string, string> = {
  check_ip_reputation: "IP reputation",
  check_file_hash: "File hash",
  map_to_attack: "ATT&CK mapper",
};

function Section({ title, children, right }: { title: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="border-t border-slate-800 px-5 py-4">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">{title}</h3>
        {right}
      </div>
      {children}
    </section>
  );
}

function Json({ value }: { value: unknown }) {
  return (
    <pre className="max-h-72 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-[11px] leading-relaxed text-slate-300 ring-1 ring-slate-800">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function toolHeadline(tool: string, out: Record<string, unknown>): string {
  if (out.error) return String(out.error);
  if (tool === "check_ip_reputation") {
    if (out.is_private) return "Private address, no reputation data";
    const parts = [`abuse score ${out.abuse_confidence_score ?? "?"}`];
    if (out.country) parts.push(String(out.country));
    if (out.isp) parts.push(String(out.isp));
    if (out.is_tor) parts.push("Tor exit");
    return parts.join(" · ");
  }
  if (tool === "check_file_hash") {
    if (out.found === false) return "Not seen by VirusTotal";
    return [out.verdict, out.detection_ratio, out.family].filter(Boolean).join(" · ");
  }
  if (tool === "map_to_attack") {
    const m = (out.matches as { technique_id: string; name: string }[] | undefined)?.[0];
    return m ? `top match ${m.technique_id} ${m.name}` : "no match";
  }
  return "";
}

export default function AlertDetailPanel({
  id,
  onClose,
  onChanged,
}: {
  id: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openTool, setOpenTool] = useState<number | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [form, setForm] = useState<{ severity: Severity; technique: string; note: string; analyst: string }>({
    severity: "medium",
    technique: "",
    note: "",
    analyst: "",
  });
  const [saving, setSaving] = useState(false);
  const [editing, setEditing] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      try {
        const a = await api.get(id);
        if (!alive) return;
        setAlert(a);
        setError(null);
        if (a.verdict) setForm((f) => ({ ...f, severity: a.verdict!.severity, technique: a.verdict!.technique }));
        if (a.status === "pending" || a.status === "triaging") timer = setTimeout(load, 2000);
      } catch (e) {
        if (alive) setError((e as Error).message);
      }
    };
    load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [id]);

  const submitOverride = async () => {
    setSaving(true);
    try {
      const a = await api.override(id, {
        severity: form.severity,
        technique: form.technique || undefined,
        note: form.note || undefined,
        analyst: form.analyst || "analyst",
      });
      setAlert(a);
      setEditing(false);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const retriage = async () => {
    try {
      const a = await api.retriage(id);
      setAlert(a);
      onChanged();
      setTimeout(async () => {
        setAlert(await api.get(id));
        onChanged();
      }, 2500);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const v = alert?.verdict;
  const lastOverride = alert?.overrides.at(-1);

  return (
    <aside className="flex h-full flex-col overflow-hidden border-l border-slate-800 bg-slate-900/60">
      <header className="flex items-start justify-between gap-3 px-5 py-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 font-mono text-xs text-slate-500">
            {id}
            {alert && (
              <>
                <span>·</span>
                <StatusLabel status={alert.status} />
              </>
            )}
          </div>
          <h2 className="mt-1 text-base font-semibold leading-snug text-slate-100">{alert?.title ?? "Loading…"}</h2>
        </div>
        <button
          onClick={onClose}
          className="rounded-md px-2 py-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
          aria-label="Close"
        >
          ✕
        </button>
      </header>

      <div className="flex-1 overflow-y-auto">
        {error && <p className="mx-5 mb-3 rounded-md bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</p>}
        {alert?.status === "error" && (
          <p className="mx-5 mb-3 rounded-md bg-red-500/10 px-3 py-2 font-mono text-xs text-red-300">{alert.error}</p>
        )}
        {alert && !v && alert.status !== "error" && (
          <p className="px-5 pb-4 text-sm text-slate-400">The agent is triaging this alert…</p>
        )}

        {v && (
          <>
            {v.needs_review && !lastOverride && (
              <div className="mx-5 mb-3 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-sm text-yellow-200">
                <span className="font-semibold">Needs human review.</span> {v.review_reason}
              </div>
            )}
            {lastOverride && (
              <div className="mx-5 mb-3 rounded-md border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-sm text-violet-200">
                <span className="font-semibold">Overridden by {lastOverride.analyst}:</span>{" "}
                {lastOverride.previous_severity} → <b>{lastOverride.severity}</b>
                {lastOverride.previous_technique !== lastOverride.technique &&
                  `, ${lastOverride.previous_technique} → ${lastOverride.technique}`}
                {lastOverride.note && <span className="block text-violet-300/80">“{lastOverride.note}”</span>}
              </div>
            )}

            <div className="grid grid-cols-3 gap-3 px-5 pb-4">
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Severity</div>
                <SeverityBadge severity={v.severity} />
              </div>
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Confidence</div>
                <ConfidenceBar value={v.confidence} />
              </div>
              <div className="min-w-0">
                <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">ATT&CK</div>
                <TechniqueLink technique={v.technique} />
                {v.technique_name && <div className="truncate text-xs text-slate-400">{v.technique_name}</div>}
              </div>
            </div>

            <Section title="Triage summary">
              <p className="text-sm leading-relaxed text-slate-200">{v.summary}</p>
            </Section>

            {v.reasoning && (
              <Section title="Agent reasoning">
                <p className="whitespace-pre-line text-sm leading-relaxed text-slate-300">{v.reasoning}</p>
              </Section>
            )}

            <Section title="Recommended next steps">
              <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-300 marker:text-slate-500">
                {v.next_steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </Section>

            <Section title={`Tool calls (${alert!.tool_calls.length})`}>
              {alert!.tool_calls.length === 0 && <p className="text-sm text-slate-500">No tools were called.</p>}
              <ul className="space-y-1.5">
                {alert!.tool_calls.map((c) => (
                  <li key={c.id} className="rounded-md ring-1 ring-slate-800">
                    <button
                      className="flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-slate-800/60"
                      onClick={() => setOpenTool(openTool === c.id ? null : c.id)}
                    >
                      <span className="w-24 shrink-0 text-xs font-semibold text-slate-200">
                        {TOOL_LABEL[c.tool] ?? c.tool}
                      </span>
                      <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-slate-400">
                        {Object.values(c.args).map(String).join(", ")}
                      </span>
                      <span className="hidden max-w-[45%] truncate text-xs text-slate-400 sm:block">
                        {toolHeadline(c.tool, c.output)}
                      </span>
                      <span className="text-slate-500">{openTool === c.id ? "▾" : "▸"}</span>
                    </button>
                    {openTool === c.id && (
                      <div className="space-y-2 border-t border-slate-800 p-3">
                        <div className="text-[11px] text-slate-500">
                          args · {c.latency_ms} ms
                        </div>
                        <Json value={c.args} />
                        <div className="text-[11px] text-slate-500">output</div>
                        <Json value={c.output} />
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </Section>

            <Section title="Analyst action">
              {!editing ? (
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => setEditing(true)}
                    className="rounded-md bg-violet-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-violet-500"
                  >
                    Override verdict
                  </button>
                  <button
                    onClick={retriage}
                    className="rounded-md px-3 py-1.5 text-sm font-medium text-slate-300 ring-1 ring-slate-700 hover:bg-slate-800"
                  >
                    Re-run agent
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="flex flex-wrap gap-1.5">
                    {SEVERITIES.map((s) => (
                      <button
                        key={s}
                        onClick={() => setForm({ ...form, severity: s })}
                        className={`rounded-md px-1 py-0.5 ${form.severity === s ? "ring-2 ring-violet-400" : "opacity-60 hover:opacity-100"}`}
                      >
                        <SeverityBadge severity={s} />
                      </button>
                    ))}
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <label className="text-xs text-slate-400">
                      ATT&CK technique
                      <input
                        value={form.technique}
                        onChange={(e) => setForm({ ...form, technique: e.target.value })}
                        placeholder="T1110.001 or none"
                        className="mt-1 w-full rounded-md bg-slate-950 px-2 py-1.5 font-mono text-sm text-slate-200 ring-1 ring-slate-700 focus:outline-none focus:ring-violet-500"
                      />
                    </label>
                    <label className="text-xs text-slate-400">
                      Analyst
                      <input
                        value={form.analyst}
                        onChange={(e) => setForm({ ...form, analyst: e.target.value })}
                        placeholder="your name"
                        className="mt-1 w-full rounded-md bg-slate-950 px-2 py-1.5 text-sm text-slate-200 ring-1 ring-slate-700 focus:outline-none focus:ring-violet-500"
                      />
                    </label>
                  </div>
                  <label className="block text-xs text-slate-400">
                    Note
                    <textarea
                      value={form.note}
                      onChange={(e) => setForm({ ...form, note: e.target.value })}
                      rows={2}
                      placeholder="Why the agent was wrong (saved as eval data)"
                      className="mt-1 w-full rounded-md bg-slate-950 px-2 py-1.5 text-sm text-slate-200 ring-1 ring-slate-700 focus:outline-none focus:ring-violet-500"
                    />
                  </label>
                  <div className="flex gap-2">
                    <button
                      disabled={saving}
                      onClick={submitOverride}
                      className="rounded-md bg-violet-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-violet-500 disabled:opacity-50"
                    >
                      {saving ? "Saving…" : "Save override"}
                    </button>
                    <button
                      onClick={() => setEditing(false)}
                      className="rounded-md px-3 py-1.5 text-sm text-slate-400 hover:bg-slate-800"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </Section>

            <Section title="Run details">
              <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <dt className="text-slate-500">Engine</dt>
                <dd className="font-mono text-slate-300">{v.engine}</dd>
                <dt className="text-slate-500">Latency</dt>
                <dd className="font-mono text-slate-300">{(v.latency_ms / 1000).toFixed(2)} s</dd>
                <dt className="text-slate-500">Tokens (in / out)</dt>
                <dd className="font-mono text-slate-300">
                  {v.input_tokens.toLocaleString()} / {v.output_tokens.toLocaleString()}
                </dd>
                <dt className="text-slate-500">Cost</dt>
                <dd className="font-mono text-slate-300">${v.cost_usd.toFixed(4)}</dd>
              </dl>
            </Section>
          </>
        )}

        {alert && (
          <Section
            title="Raw alert"
            right={
              <button onClick={() => setShowRaw(!showRaw)} className="text-xs text-sky-300 hover:underline">
                {showRaw ? "hide" : "show"}
              </button>
            }
          >
            {showRaw ? (
              <Json value={alert.raw} />
            ) : (
              <p className="text-sm text-slate-400">{String(alert.raw.description ?? "")}</p>
            )}
          </Section>
        )}
      </div>
    </aside>
  );
}
