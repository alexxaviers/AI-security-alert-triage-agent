"""Pure metric functions for the eval suite (unit-tested in tests/test_metrics.py)."""

from __future__ import annotations

import statistics

SEVERITIES = ["low", "medium", "high", "critical"]


def parent(tech: str) -> str:
    return tech.split(".")[0] if tech else tech


def technique_correct(pred: str, label: dict, level: str = "strict") -> bool:
    gold = label["technique"]
    accepted = [gold, *label.get("accepted_techniques", [])]
    if gold == "none" or pred == "none":
        return pred == gold
    if level == "strict":
        return pred in accepted
    return parent(pred) in {parent(t) for t in accepted}


def compute(rows: list[dict]) -> dict:
    """rows: [{id, label: {...}, pred: {severity, technique, needs_review} | None, latency_ms, cost_usd, ...}]"""
    ok = [r for r in rows if r.get("pred")]
    n = len(ok)
    m: dict = {"n": len(rows), "errors": len(rows) - n}
    if not n:
        return m

    conf = {g: {p: 0 for p in SEVERITIES} for g in SEVERITIES}
    for r in ok:
        conf[r["label"]["severity"]][r["pred"]["severity"]] += 1
    m["confusion"] = conf

    sev_hit = [r["pred"]["severity"] == r["label"]["severity"] for r in ok]
    m["severity_accuracy"] = sum(sev_hit) / n
    m["severity_within_one"] = sum(
        abs(SEVERITIES.index(r["pred"]["severity"]) - SEVERITIES.index(r["label"]["severity"])) <= 1 for r in ok) / n
    per_class = {}
    for s in SEVERITIES:
        tp = conf[s][s]
        pred_s = sum(conf[g][s] for g in SEVERITIES)
        gold_s = sum(conf[s].values())
        per_class[s] = {"precision": tp / pred_s if pred_s else None, "recall": tp / gold_s if gold_s else None,
                        "support": gold_s}
    m["per_class"] = per_class

    m["technique_accuracy"] = sum(technique_correct(r["pred"]["technique"], r["label"]) for r in ok) / n
    m["technique_accuracy_parent"] = sum(
        technique_correct(r["pred"]["technique"], r["label"], "parent") for r in ok) / n

    crit = [r for r in ok if r["label"]["severity"] == "critical"]
    m["critical_total"] = len(crit)
    m["missed_critical"] = [r["id"] for r in crit if r["pred"]["severity"] != "critical"]
    # A "silent miss": critical alert called low/medium AND not flagged for human review.
    m["silent_missed_critical"] = [r["id"] for r in crit
                                   if r["pred"]["severity"] in ("low", "medium") and not r["pred"].get("needs_review")]
    m["false_critical"] = [r["id"] for r in ok
                           if r["pred"]["severity"] == "critical" and r["label"]["severity"] != "critical"]

    def _acc(rs: list[dict]) -> float | None:
        return sum(r["pred"]["severity"] == r["label"]["severity"] for r in rs) / len(rs) if rs else None

    flagged = [r for r in ok if r["pred"].get("needs_review")]
    auto = [r for r in ok if not r["pred"].get("needs_review")]
    m["review_rate"] = len(flagged) / n
    m["accuracy_auto"] = _acc(auto)
    m["accuracy_flagged"] = _acc(flagged)

    lat = [r.get("latency_ms", 0) for r in ok]
    m["latency_avg_ms"] = statistics.mean(lat)
    m["latency_p95_ms"] = sorted(lat)[max(0, int(round(0.95 * len(lat))) - 1)]
    m["cost_avg_usd"] = statistics.mean(r.get("cost_usd", 0) for r in ok)
    m["cost_total_usd"] = sum(r.get("cost_usd", 0) for r in ok)
    m["tokens_avg"] = statistics.mean(r.get("input_tokens", 0) + r.get("output_tokens", 0) for r in ok)
    m["tool_calls_avg"] = statistics.mean(r.get("tool_calls", 0) for r in ok)

    by_scn: dict[str, list[bool]] = {}
    for r, hit in zip(ok, sev_hit, strict=True):
        by_scn.setdefault(r["label"].get("scenario", "?"), []).append(hit)
    m["by_scenario"] = {k: {"n": len(v), "severity_accuracy": sum(v) / len(v)} for k, v in sorted(by_scn.items())}
    return m
