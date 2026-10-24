"""A naive rules baseline: keyword matching plus threat-intel lookups, no LLM.

It exists for two reasons:
  1. The API still works end to end without an LLM key (useful for demos and CI).
  2. The eval suite compares the LLM agent against it, so "92% accuracy" has a reference point.

It deliberately does not read deep context (parent processes, change tickets, signed binaries...),
which is exactly where an LLM should beat it.
"""

from __future__ import annotations

import re

from tools.intel import file_hash_reputation, ip_reputation

# (pattern on rule_name/title, technique, base severity)
RULES = [
    (r"ransomware|encrypt", "T1486", "critical"),
    (r"lsass|ntds|credential dump", "T1003.001", "critical"),
    (r"sam hive", "T1003.002", "high"),
    (r"password spray", "T1110.003", "high"),
    (r"brute force", "T1110.001", "medium"),
    (r"failed login", "T1110.001", "medium"),
    (r"mfa push", "T1621", "high"),
    (r"impossible travel", "T1078", "medium"),
    (r"powershell", "T1059.001", "high"),
    (r"malicious file executed", "T1204.002", "critical"),
    (r"malware detected", "T1204.002", "medium"),
    (r"rare binary|unsigned", "T1204.002", "medium"),
    (r"internal port scan", "T1046", "high"),
    (r"port scan", "T1595.001", "low"),
    (r"admin account created", "T1136.001", "high"),
    (r"scheduled task", "T1053.005", "medium"),
    (r"upload to cloud", "T1567.002", "high"),
    (r"beacon", "T1071.001", "medium"),
    (r"rdp", "T1021.001", "high"),
    (r"exploit", "T1190", "medium"),
    (r"uac bypass", "T1548.002", "high"),
]
ORDER = ["low", "medium", "high", "critical"]


def _bump(sev: str, n: int = 1) -> str:
    return ORDER[min(len(ORDER) - 1, ORDER.index(sev) + n)]


def triage_baseline(alert: dict) -> tuple[dict, list[dict]]:
    text = f"{alert.get('rule_name', '')} {alert.get('title', '')}".lower()
    technique, severity = "none", "low"
    for pat, tech, sev in RULES:
        if re.search(pat, text):
            technique, severity = tech, sev
            break

    audit, evidence = [], []
    for field in ("src_ip", "dst_ip"):
        ip = alert.get(field)
        if ip:
            r = ip_reputation(ip)
            audit.append({"tool": "check_ip_reputation", "args": {"ip": ip}, "output": r, "latency_ms": 0})
            score = r.get("abuse_confidence_score") or 0
            if score >= 75:
                severity = _bump(severity)
                evidence.append(f"{ip} abuse score {score}")
    if alert.get("file_hash"):
        r = file_hash_reputation(alert["file_hash"])
        audit.append({"tool": "check_file_hash", "args": {"sha256": alert["file_hash"]}, "output": r, "latency_ms": 0})
        if r.get("verdict") == "malicious":
            evidence.append(f"hash flagged malicious ({r.get('detection_ratio')})")
        elif r.get("verdict") == "clean":
            severity, technique = "low", "none"
            evidence.append("hash is clean")

    if technique == "none":
        severity = "low"
    verdict = {
        "severity": severity,
        "attack_technique": technique,
        "confidence": 0.5 if technique != "none" else 0.7,
        "summary": f"Rules baseline matched '{alert.get('rule_name', 'unknown')}'.",
        "reasoning": "; ".join(evidence) or "Keyword match on the rule name only.",
        "next_steps": ["Review the alert manually."],
    }
    return verdict, audit
