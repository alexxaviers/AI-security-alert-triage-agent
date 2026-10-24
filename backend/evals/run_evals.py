"""Run every labeled alert through a triage engine and score it.

    python -m evals.run_evals                       # LLM agent (needs ANTHROPIC_API_KEY)
    python -m evals.run_evals --engine baseline     # rules baseline, no key needed
    python -m evals.run_evals --model claude-haiku-5-5 --limit 50 --concurrency 4

Threat intel is pinned to data/intel_fixtures.json so that a score change means the prompt or
model changed, not the outside world. Each run:
  - writes the per-alert predictions to evals/runs/<timestamp>_<engine>.json
  - appends a summary line to evals/history.jsonl
  - rewrites evals/results.md (latest run in detail + history of all runs)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
ROOT = EVAL_DIR.parent
sys.path.insert(0, str(ROOT))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["llm", "baseline"], default="llm")
    ap.add_argument("--model", default=None, help="override ANTHROPIC_MODEL")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--ids", nargs="*", help="only these alert IDs")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--labels", default=str(EVAL_DIR / "labels.json"))
    ap.add_argument("--live-intel", action="store_true", help="use real AbuseIPDB/VirusTotal instead of fixtures")
    ap.add_argument("--note", default="", help="free-text note saved with the run, e.g. 'added rubric examples'")
    args = ap.parse_args()

    if not args.live_intel:
        os.environ["INTEL_MODE"] = "fixtures"
    os.environ.setdefault("EMBEDDING_BACKEND", "auto")

    from agent.prompts import DECIDE_PROMPT, SYSTEM_PROMPT
    from agent.runner import BaselineTriager, LLMTriager
    from app.config import DATA_DIR
    from evals.metrics import compute
    from evals.report import render

    labels = json.loads(Path(args.labels).read_text())
    alerts = {a["id"]: a for a in json.loads((DATA_DIR / "alerts.json").read_text())}
    ids = [i for i in (args.ids or labels.keys()) if i in alerts]
    if args.limit:
        ids = ids[: args.limit]

    triager = BaselineTriager() if args.engine == "baseline" else LLMTriager(model=args.model)
    engine_name = triager.model
    print(f"Evaluating {len(ids)} alerts with {engine_name} (concurrency {args.concurrency})")

    def run_one(aid: str) -> dict:
        row = {"id": aid, "label": labels[aid]}
        try:
            res = triager.triage(alerts[aid])
            row.update(pred={"severity": res.verdict["severity"], "technique": res.verdict["attack_technique"],
                             "confidence": res.verdict["confidence"], "needs_review": res.needs_review,
                             "summary": res.verdict["summary"]},
                       latency_ms=res.latency_ms, cost_usd=res.cost_usd, input_tokens=res.input_tokens,
                       output_tokens=res.output_tokens, tool_calls=len(res.tool_audit),
                       tools=[c["tool"] for c in res.tool_audit])
        except Exception as e:
            row.update(pred=None, error=f"{type(e).__name__}: {e}")
        return row

    t0 = time.time()
    rows = []
    workers = 1 if args.engine == "baseline" else args.concurrency
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(run_one, i) for i in ids]
        for k, f in enumerate(as_completed(futs), 1):
            rows.append(f.result())
            if k % 10 == 0 or k == len(ids):
                print(f"  {k}/{len(ids)}")
    rows.sort(key=lambda r: r["id"])
    metrics = compute(rows)

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    prompt_hash = hashlib.sha256((SYSTEM_PROMPT + DECIDE_PROMPT).encode()).hexdigest()[:8]
    run = {"timestamp": stamp, "engine": engine_name, "prompt_version": prompt_hash,
           "intel": "live" if args.live_intel else "fixtures", "note": args.note,
           "wall_seconds": round(time.time() - t0, 1), "metrics": metrics}

    (EVAL_DIR / "runs").mkdir(exist_ok=True)
    (EVAL_DIR / "runs" / f"{stamp}_{engine_name}.json").write_text(json.dumps({**run, "rows": rows}, indent=2))
    with open(EVAL_DIR / "history.jsonl", "a") as fh:
        slim = {k: v for k, v in metrics.items() if k not in ("confusion", "per_class", "by_scenario")}
        fh.write(json.dumps({**run, "metrics": slim}) + "\n")
    history = [json.loads(line) for line in (EVAL_DIR / "history.jsonl").read_text().splitlines() if line.strip()]
    (EVAL_DIR / "results.md").write_text(render(run, rows, history))

    m = metrics
    print(f"\nseverity accuracy  {m.get('severity_accuracy', 0):.1%}")
    print(f"technique accuracy {m.get('technique_accuracy', 0):.1%}")
    print(f"missed critical    {len(m.get('missed_critical', []))}/{m.get('critical_total', 0)}")
    print(f"errors             {m['errors']}")
    print("wrote evals/results.md")


if __name__ == "__main__":
    main()
