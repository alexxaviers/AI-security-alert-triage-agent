"""Step through the eval labels one alert at a time and confirm or correct them.

    python scripts/review_labels.py            # only labels not yet reviewed
    python scripts/review_labels.py --all

For each alert you see the raw alert and the proposed label. Press Enter to accept, or type a
new severity and/or technique, e.g. "high", "T1078", or "medium T1110.003". Progress is saved
after every answer, with "reviewed": true on each label, so you can stop and resume.
"""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABELS = ROOT / "evals" / "labels.json"
SEV = {"low", "medium", "high", "critical"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    alerts = {a["id"]: a for a in json.loads((ROOT / "data" / "alerts.json").read_text())}
    techniques = {t["id"]: t["name"] for t in json.loads((ROOT / "data" / "attack_techniques.json").read_text())}
    labels = json.loads(LABELS.read_text())
    todo = [k for k, v in labels.items() if args.all or not v.get("reviewed")]
    print(f"{len(todo)} labels to review ({sum(v.get('reviewed', False) for v in labels.values())} done).\n")

    for n, aid in enumerate(todo, 1):
        a, lab = alerts[aid], labels[aid]
        print("=" * 80)
        print(f"[{n}/{len(todo)}] {aid}  {a.get('title')}")
        print(json.dumps({k: v for k, v in a.items() if k not in ("id", "title")}, indent=2)[:1500])
        print(f"\nProposed: severity={lab['severity']}  technique={lab['technique']} "
              f"({techniques.get(lab['technique'], '')})\nWhy: {lab['rationale']}")
        ans = input("Enter = accept, or new values ('q' to quit): ").strip()
        if ans.lower() == "q":
            break
        for tok in ans.split():
            if tok.lower() in SEV:
                lab["severity"] = tok.lower()
            elif tok.lower() == "none" or tok.upper() in techniques:
                lab["technique"] = "none" if tok.lower() == "none" else tok.upper()
                lab["accepted_techniques"] = [t for t in lab.get("accepted_techniques", []) if t != lab["technique"]]
            else:
                print(f"  ignored '{tok}' (not a severity or known technique ID)")
        lab["reviewed"] = True
        LABELS.write_text(json.dumps(labels, indent=2))
    print("saved.")


if __name__ == "__main__":
    main()
