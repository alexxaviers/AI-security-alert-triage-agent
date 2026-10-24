# Evaluation results

Latest run: **claude-sonnet-5-5**, prompt `7feb909b`, intel: fixtures, 20261024T040817Z — first full run (last 37 alerts re-run after credit ran out)

| Metric | Value |
|---|---|
| Alerts evaluated | 206 (errors: 0) |
| **Severity accuracy** | **94.7%** |
| Severity within one level | 100.0% |
| ATT&CK technique accuracy (exact/accepted) | 98.5% |
| ATT&CK technique accuracy (parent technique) | 99.0% |
| **Missed critical alerts** | **5 of 45** |
| Silent critical misses (called low/medium, not flagged) | 0 |
| False criticals | 6 |
| Flagged for human review | 0.5% |
| Accuracy when auto-handled / when flagged | 94.6% / 100.0% |
| Avg latency / p95 | 11.6s / 15.1s |
| Avg cost per alert | $0.0412 (total $8.49) |
| Avg tokens / tool calls per alert | 9,028 / 1.4 |

## Severity confusion matrix

Rows are the label, columns the prediction.

| label \ predicted | low | medium | high | critical | recall |
|---|---|---|---|---|---|
| low | **78** | 0 | 0 | 0 | 100.0% |
| medium | 0 | **21** | 0 | 0 | 100.0% |
| high | 0 | 0 | **56** | 6 | 90.3% |
| critical | 0 | 0 | 5 | **40** | 88.9% |
| precision | 100.0% | 100.0% | 91.8% | 87.0% | |

## Accuracy by scenario

| Scenario | n | Severity accuracy |
|---|---|---|
| beacon | 10 | 100.0% |
| brute_force | 22 | 100.0% |
| exfil | 10 | 100.0% |
| impossible_travel | 14 | 71.4% |
| lsass | 10 | 100.0% |
| malware_hash | 18 | 100.0% |
| mfa_fatigue | 8 | 100.0% |
| new_admin | 10 | 100.0% |
| noise | 22 | 100.0% |
| otrf_real | 6 | 83.3% |
| password_spray | 8 | 100.0% |
| port_scan | 14 | 100.0% |
| powershell | 16 | 68.8% |
| ransomware | 5 | 100.0% |
| rdp | 8 | 87.5% |
| sched_task | 10 | 100.0% |
| uac | 5 | 100.0% |
| web_exploit | 10 | 100.0% |

## Severity mistakes

| Alert | Label | Predicted | Confidence | Review? | Technique (label → pred) |
|---|---|---|---|---|---|
| ALR-0027 | high | critical | 0.85 | no | T1078 → T1621 |
| ALR-0041 | high | critical | 0.80 | no | T1078 → T1621 |
| ALR-0045 | high | critical | 0.82 | no | T1078 → T1078.004 |
| ALR-0059 | critical | high | 0.75 | no | T1059.001 → T1059.001 |
| ALR-0071 | critical | high | 0.75 | no | T1059.001 → T1059.001 |
| ALR-0084 | critical | high | 0.80 | no | T1059.001 → T1059.001 |
| ALR-0089 | high | critical | 0.85 | no | T1078 → T1078.004 |
| ALR-0122 | high | critical | 0.75 | no | T1021.001 → T1021.001 |
| ALR-0143 | critical | high | 0.75 | no | T1059.001 → T1059.001 |
| ALR-0154 | critical | high | 0.70 | no | T1059.001 → T1059.001 |
| OTRF-0004 | high | critical | 0.85 | no | T1003.002 → T1003.002 |

## History

| When (UTC) | Engine | Prompt | Severity acc. | Technique acc. | Missed critical | Review rate | Avg cost | Note |
|---|---|---|---|---|---|---|---|---|
| 20261024T040817Z | claude-sonnet-5-5 | `7feb909b` | 94.7% | 98.5% | 5/45 | 0.5% | $0.0412 | first full run (last 37 alerts re-run after credit ran out) |
| 20261024T021209Z | baseline-rules | `7feb909b` | 64.6% | 80.1% | 9/45 | 85.9% | $0.0000 | rules baseline (keyword + intel, no LLM) |
