export type Severity = "low" | "medium" | "high" | "critical";

export const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

export interface AlertSummary {
  id: string;
  title: string;
  source: string | null;
  status: string;
  received_at: string;
  severity: Severity | null;
  technique: string | null;
  confidence: number | null;
  needs_review: boolean | null;
  overridden: boolean;
}

export interface Verdict {
  id: number;
  severity: Severity;
  technique: string;
  technique_name: string | null;
  confidence: number;
  summary: string;
  reasoning: string | null;
  next_steps: string[];
  needs_review: boolean;
  review_reason: string | null;
  engine: string;
  latency_ms: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  created_at: string;
}

export interface ToolCall {
  id: number;
  tool: string;
  args: Record<string, unknown>;
  output: Record<string, unknown>;
  latency_ms: number;
  created_at: string;
}

export interface Override {
  id: number;
  previous_severity: string | null;
  previous_technique: string | null;
  severity: Severity;
  technique: string;
  analyst: string;
  note: string | null;
  created_at: string;
}

export interface AlertDetail {
  id: string;
  title: string;
  source: string | null;
  status: string;
  error: string | null;
  received_at: string;
  raw: Record<string, unknown>;
  verdict: Verdict | null;
  tool_calls: ToolCall[];
  overrides: Override[];
}

export interface Stats {
  total: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  needs_review: number;
  avg_latency_ms: number | null;
  total_cost_usd: number;
  engine: string;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {}
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

export interface ListParams {
  severity?: string;
  status?: string;
  q?: string;
  sort?: "severity" | "received";
  limit?: number;
  offset?: number;
}

export const api = {
  list: (p: ListParams) => {
    const qs = new URLSearchParams();
    Object.entries(p).forEach(([k, v]) => v !== undefined && v !== "" && qs.set(k, String(v)));
    return req<{ total: number; items: AlertSummary[] }>(`/alerts?${qs}`);
  },
  get: (id: string) => req<AlertDetail>(`/alerts/${encodeURIComponent(id)}`),
  stats: () => req<Stats>("/stats"),
  override: (id: string, body: { severity: Severity; technique?: string; note?: string; analyst?: string }) =>
    req<AlertDetail>(`/alerts/${encodeURIComponent(id)}/override`, { method: "POST", body: JSON.stringify(body) }),
  retriage: (id: string) => req<AlertDetail>(`/alerts/${encodeURIComponent(id)}/retriage`, { method: "POST" }),
};

export function attackUrl(technique: string): string | null {
  if (!technique || technique === "none") return null;
  return `https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`;
}
