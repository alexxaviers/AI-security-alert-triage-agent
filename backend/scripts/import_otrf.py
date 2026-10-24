"""Turn real attack telemetry from OTRF Security-Datasets into alerts.

OTRF (github.com/OTRF/Security-Datasets) publishes Windows event logs
recorded while real attack tools ran in a lab. For each dataset listed in
DATASETS this script finds the event a detection rule would fire on, wraps
it in our alert format, and appends it (with a label) to data/alerts.json
and evals/labels.json. Run it after generate_alerts.py.

Usage:
    git clone --depth 1 --filter=blob:none --sparse https://github.com/OTRF/Security-Datasets.git otrf
    cd otrf && git sparse-checkout set --no-cone 'datasets/atomic/windows/*/host/*' && cd ..
    python scripts/import_otrf.py otrf
"""

from __future__ import annotations

import json
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# match: (sysmon event id, field, lowercase substring)
DATASETS = [
    {
        "file": "credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
        "match": (1, "CommandLine", "comsvcs.dll minidump"),
        "rule": "LSASS Memory Dump via comsvcs.dll",
        "label": ("critical", "T1003.001", ["T1003", "T1218.011"],
                  "rundll32 + comsvcs MiniDump of LSASS: credential theft from memory."),
    },
    {
        "file": "credential_access/host/empire_mimikatz_logonpasswords.zip",
        "match": (10, "TargetImage", "lsass.exe"),
        "also": ("SourceImage", "powershell"),
        "rule": "Suspicious LSASS Process Access",
        "label": ("critical", "T1003.001", ["T1003"],
                  "PowerShell (Empire) opening LSASS with read access: Mimikatz logonpasswords."),
    },
    {
        "file": "credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil.zip",
        "match": (1, "CommandLine", "ntdsutil"),
        "rule": "NTDS.dit Extraction via ntdsutil",
        "label": ("critical", "T1003.003", ["T1003"],
                  "ntdsutil IFM copy of NTDS.dit dumps every domain password hash."),
    },
    {
        "file": "credential_access/host/cmd_sam_copy_esentutl.zip",
        "match": (1, "CommandLine", "esentutl"),
        "rule": "SAM Hive Copy via esentutl",
        "label": ("high", "T1003.002", ["T1003"],
                  "esentutl copying the SAM hive to extract local account hashes."),
    },
    {
        "file": "execution/host/empire_launcher_vbs.zip",
        "match": (1, "CommandLine", "-enc"),
        "rule": "Encoded PowerShell from Script Host",
        "label": ("high", "T1059.001", ["T1059.005", "T1059", "T1027"],
                  "VBS launcher spawning hidden encoded PowerShell: Empire stager."),
    },
    {
        "file": "credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip",
        "match": (11, "TargetFilename", "lsass"),
        "rule": "LSASS Dump File Created",
        "label": ("critical", "T1003.001", ["T1003"],
                  "Task Manager used over RDP to write an LSASS dump file."),
    },
]

KEEP = ["Hostname", "User", "Image", "CommandLine", "ParentImage", "ParentCommandLine", "SourceImage",
        "TargetImage", "GrantedAccess", "TargetFilename", "UtcTime", "EventID", "Channel"]


def load_events(path: Path):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith(".json"):
                    for line in z.read(name).decode("utf-8", "ignore").splitlines():
                        if line.strip():
                            yield json.loads(line)
    else:
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if m.name.endswith(".json"):
                    for line in t.extractfile(m).read().decode("utf-8", "ignore").splitlines():
                        if line.strip():
                            yield json.loads(line)


def main(repo: str) -> None:
    base = Path(repo) / "datasets" / "atomic" / "windows"
    alerts = json.loads((ROOT / "data" / "alerts.json").read_text())
    labels = json.loads((ROOT / "evals" / "labels.json").read_text())
    alerts = [a for a in alerts if not a["id"].startswith("OTRF-")]
    labels = {k: v for k, v in labels.items() if not k.startswith("OTRF-")}

    for i, ds in enumerate(DATASETS, 1):
        eid, field, needle = ds["match"]
        ev = next((e for e in load_events(base / ds["file"])
                   if e.get("EventID") == eid and "Sysmon" in str(e.get("Channel"))
                   and needle in str(e.get(field, "")).lower()
                   and (not ds.get("also") or ds["also"][1] in str(e.get(ds["also"][0], "")).lower())), None)
        if ev is None:
            print(f"skip {ds['file']}: no matching event")
            continue
        raw = {k: ev[k] for k in KEEP if k in ev}
        proc = raw.get("Image") or raw.get("SourceImage")
        detail = raw.get("CommandLine") or raw.get("TargetFilename") or f"{proc} -> {raw.get('TargetImage')} (access {raw.get('GrantedAccess')})"
        aid = f"OTRF-{i:04d}"
        alerts.append({
            "id": aid,
            "source": "sysmon",
            "rule_name": ds["rule"],
            "title": f"{ds['rule']} on {raw.get('Hostname', 'unknown')}",
            "description": f"Sysmon event {eid} on {raw.get('Hostname')}: {detail}"
                           + (f" (parent: {raw['ParentImage']})" if raw.get("ParentImage") else ""),
            "timestamp": str(raw.get("UtcTime", "")).replace(" ", "T") + "Z",
            "host": raw.get("Hostname"),
            "user": raw.get("User"),
            "process": {"image": proc, "command_line": raw.get("CommandLine"), "parent": raw.get("ParentImage")},
            "raw": raw,
            "origin": f"OTRF Security-Datasets: {ds['file']}",
        })
        sev, tech, acc, why = ds["label"]
        labels[aid] = {"severity": sev, "technique": tech, "accepted_techniques": acc, "rationale": why,
                       "scenario": "otrf_real"}
        print(f"{aid}: {ds['rule']}")

    (ROOT / "data" / "alerts.json").write_text(json.dumps(alerts, indent=2))
    (ROOT / "evals" / "labels.json").write_text(json.dumps(labels, indent=2))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "otrf")
