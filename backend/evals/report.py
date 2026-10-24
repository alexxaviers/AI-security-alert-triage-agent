"""Render eval results as Markdown."""

from __future__ import annotations

from evals.metrics import SEVERITIES


def _pct(x) -> str:
    return "n/a" if x is None else f"{x:.1%}"


def render(run: dict, rows: list[dict], history: list[dict]) -> str:
    m = run["metrics"]
    out = [
        "# Evaluation results",
        "",
        f"Latest run: **{run['engine']}**, prompt `{run['prompt_version']}`, intel: {run['intel']}, "
        f"{run['timestamp']}" + (f" — {run['note']}" if run.get("note") else ""),
        "",
    ]
    if not m.get("severity_accuracy") and m.get("errors"):
        out += [f"All {m['errors']} alerts errored. First error: `{rows[0].get('error')}`", ""]
        return "\n".join(out)

    out += [
        "| Metric | Value |",
        "|---|---|",
        f"| Alerts evaluated | {m['n'] - m['errors']} (errors: {m['errors']}) |",
        f"| **Severity accuracy** | **{_pct(m['severity_accuracy'])}** |",
        f"| Severity within one level | {_pct(m['severity_within_one'])} |",
        f"| ATT&CK technique accuracy (exact/accepted) | {_pct(m['technique_accuracy'])} |",
        f"| ATT&CK technique accuracy (parent technique) | {_pct(m['technique_accuracy_parent'])} |",
        f"| **Missed critical alerts** | **{len(m['missed_critical'])} of {m['critical_total']}** |",
        f"| Silent critical misses (called low/medium, not flagged) | {len(m['silent_missed_critical'])} |",
        f"| False criticals | {len(m['false_critical'])} |",
        f"| Flagged for human review | {_pct(m['review_rate'])} |",
        f"| Accuracy when auto-handled / when flagged | {_pct(m['accuracy_auto'])} / {_pct(m['accuracy_flagged'])} |",
        f"| Avg latency / p95 | {m['latency_avg_ms'] / 1000:.1f}s / {m['latency_p95_ms'] / 1000:.1f}s |",
        f"| Avg cost per alert | ${m['cost_avg_usd']:.4f} (total ${m['cost_total_usd']:.2f}) |",
        f"| Avg tokens / tool calls per alert | {m['tokens_avg']:,.0f} / {m['tool_calls_avg']:.1f} |",
        "",
        "## Severity confusion matrix",
        "",
        "Rows are the label, columns the prediction.",
        "",
        "| label \\ predicted | " + " | ".join(SEVERITIES) + " | recall |",
        "|---|" + "---|" * (len(SEVERITIES) + 1),
    ]
    for g in SEVERITIES:
        cells = [f"**{m['confusion'][g][p]}**" if g == p else str(m["confusion"][g][p]) for p in SEVERITIES]
        out.append(f"| {g} | " + " | ".join(cells) + f" | {_pct(m['per_class'][g]['recall'])} |")
    out.append("| precision | " + " | ".join(_pct(m["per_class"][p]["precision"]) for p in SEVERITIES) + " | |")

    out += ["", "## Accuracy by scenario", "", "| Scenario | n | Severity accuracy |", "|---|---|---|"]
    for k, v in m["by_scenario"].items():
        out.append(f"| {k} | {v['n']} | {_pct(v['severity_accuracy'])} |")

    misses = [r for r in rows if r.get("pred") and r["pred"]["severity"] != r["label"]["severity"]]
    if misses:
        out += ["", "## Severity mistakes", "",
                "| Alert | Label | Predicted | Confidence | Review? | Technique (label → pred) |",
                "|---|---|---|---|---|---|"]
        for r in misses[:60]:
            p = r["pred"]
            out.append(f"| {r['id']} | {r['label']['severity']} | {p['severity']} | {p['confidence']:.2f} | "
                       f"{'yes' if p['needs_review'] else 'no'} | {r['label']['technique']} → {p['technique']} |")
    errs = [r for r in rows if not r.get("pred")]
    if errs:
        out += ["", "## Errors", ""] + [f"- {r['id']}: `{r['error'][:200]}`" for r in errs[:20]]

    out += ["", "## History", "",
            "| When (UTC) | Engine | Prompt | Severity acc. | Technique acc. | Missed critical | Review rate | "
            "Avg cost | Note |",
            "|---|---|---|---|---|---|---|---|---|"]
    for h in reversed(history):
        hm = h["metrics"]
        if hm.get("severity_accuracy") is None:
            continue
        out.append(f"| {h['timestamp']} | {h['engine']} | `{h['prompt_version']}` | {_pct(hm['severity_accuracy'])} | "
                   f"{_pct(hm['technique_accuracy'])} | {len(hm['missed_critical'])}/{hm['critical_total']} | "
                   f"{_pct(hm['review_rate'])} | ${hm['cost_avg_usd']:.4f} | {h.get('note', '')} |")
    return "\n".join(out) + "\n"
