"""Post the alert dataset to a running API so the dashboard has data.

    python scripts/seed.py                         # all alerts to http://localhost:8000
    python scripts/seed.py --api https://your-api.onrender.com --limit 30
"""

import argparse
import json
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--file", default=str(ROOT / "data" / "alerts.json"))
    args = ap.parse_args()

    alerts = json.loads(Path(args.file).read_text())[: args.limit]
    created = skipped = 0
    with httpx.Client(base_url=args.api, timeout=30) as c:
        for a in alerts:
            r = c.post("/alerts", json=a)
            if r.status_code == 409:
                skipped += 1
            else:
                r.raise_for_status()
                created += 1
    print(f"created {created}, skipped {skipped} existing. Triage runs in the background; refresh the dashboard.")


if __name__ == "__main__":
    main()
