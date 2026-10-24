"""Build a compact MITRE ATT&CK technique file from the official STIX bundle.

Usage:
    curl -o enterprise-attack.json \
      https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    python scripts/build_attack_data.py enterprise-attack.json

Writes data/attack_techniques.json: one entry per active (non-revoked,
non-deprecated) technique and sub-technique, with id, name, tactics and a
trimmed description. The app embeds these descriptions for the mapper.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "attack_techniques.json"
MAX_DESC_CHARS = 600


def clean(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text)          # drop citation markers
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)     # markdown links -> text
    text = re.sub(r"<[^>]+>", "", text)                      # stray html
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_DESC_CHARS]


def main(src: str) -> None:
    bundle = json.loads(Path(src).read_text())
    techniques = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext:
            continue
        techniques.append(
            {
                "id": ext["external_id"],
                "name": obj["name"],
                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                "description": clean(obj.get("description", "")),
            }
        )
    techniques.sort(key=lambda t: t["id"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(techniques, indent=1))
    print(f"wrote {len(techniques)} techniques to {OUT}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "enterprise-attack.json")
