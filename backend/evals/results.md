# Evaluation results

Latest run: **baseline-rules**, prompt `7feb909b`, intel: fixtures, 20261024T021209Z — rules baseline (keyword + intel, no LLM)

| Metric | Value |
|---|---|
| Alerts evaluated | 206 (errors: 0) |
| **Severity accuracy** | **64.6%** |
| Severity within one level | 84.5% |
| ATT&CK technique accuracy (exact/accepted) | 80.1% |
| ATT&CK technique accuracy (parent technique) | 80.6% |
| **Missed critical alerts** | **9 of 45** |
| Silent critical misses (called low/medium, not flagged) | 0 |
| False criticals | 15 |
| Flagged for human review | 85.9% |
| Accuracy when auto-handled / when flagged | 100.0% / 58.8% |
| Avg latency / p95 | 0.0s / 0.0s |
| Avg cost per alert | $0.0000 (total $0.00) |
| Avg tokens / tool calls per alert | 0 / 0.6 |

## Severity confusion matrix

Rows are the label, columns the prediction.

| label \ predicted | low | medium | high | critical | recall |
|---|---|---|---|---|---|
| low | **31** | 15 | 28 | 4 | 39.7% |
| medium | 0 | **21** | 0 | 0 | 100.0% |
| high | 0 | 6 | **45** | 11 | 72.6% |
| critical | 0 | 0 | 9 | **36** | 80.0% |
| precision | 100.0% | 50.0% | 54.9% | 70.6% | |

## Accuracy by scenario

| Scenario | n | Severity accuracy |
|---|---|---|
| beacon | 10 | 100.0% |
| brute_force | 22 | 68.2% |
| exfil | 10 | 30.0% |
| impossible_travel | 14 | 71.4% |
| lsass | 10 | 60.0% |
| malware_hash | 18 | 100.0% |
| mfa_fatigue | 8 | 62.5% |
| new_admin | 10 | 50.0% |
| noise | 22 | 100.0% |
| otrf_real | 6 | 100.0% |
| password_spray | 8 | 37.5% |
| port_scan | 14 | 50.0% |
| powershell | 16 | 31.2% |
| ransomware | 5 | 100.0% |
| rdp | 8 | 100.0% |
| sched_task | 10 | 0.0% |
| uac | 5 | 100.0% |
| web_exploit | 10 | 0.0% |

## Severity mistakes

| Alert | Label | Predicted | Confidence | Review? | Technique (label → pred) |
|---|---|---|---|---|---|
| ALR-0001 | high | critical | 0.50 | yes | T1110.003 → T1110.003 |
| ALR-0002 | critical | high | 0.50 | yes | T1110.001 → T1110.001 |
| ALR-0005 | low | medium | 0.50 | yes | T1595.001 → T1595.001 |
| ALR-0007 | low | medium | 0.50 | yes | none → T1053.005 |
| ALR-0008 | low | high | 0.50 | yes | T1190 → T1190 |
| ALR-0011 | low | medium | 0.50 | yes | none → T1053.005 |
| ALR-0012 | low | high | 0.50 | yes | none → T1046 |
| ALR-0022 | high | critical | 0.50 | yes | T1110.003 → T1110.003 |
| ALR-0025 | low | medium | 0.50 | yes | none → T1078 |
| ALR-0028 | low | high | 0.50 | yes | none → T1136.001 |
| ALR-0030 | low | high | 0.50 | yes | T1190 → T1190 |
| ALR-0033 | low | high | 0.50 | yes | none → T1567.002 |
| ALR-0036 | low | high | 0.50 | yes | none → T1567.002 |
| ALR-0040 | low | high | 0.50 | yes | none → T1059.001 |
| ALR-0047 | low | medium | 0.50 | yes | T1595.001 → T1595.001 |
| ALR-0051 | low | medium | 0.50 | yes | none → T1053.005 |
| ALR-0061 | critical | high | 0.50 | yes | T1190 → T1190 |
| ALR-0062 | low | high | 0.50 | yes | none → T1046 |
| ALR-0065 | low | high | 0.50 | yes | none → T1059.001 |
| ALR-0067 | critical | high | 0.50 | yes | T1190 → T1190 |
| ALR-0075 | high | critical | 0.50 | yes | T1110.003 → T1110.003 |
| ALR-0076 | low | high | 0.50 | yes | none → T1567.002 |
| ALR-0077 | low | critical | 0.50 | yes | none → T1003.001 |
| ALR-0079 | high | medium | 0.50 | yes | T1053.005 → T1053.005 |
| ALR-0080 | low | high | 0.50 | yes | none → T1059.001 |
| ALR-0081 | low | high | 0.50 | yes | none → T1059.001 |
| ALR-0085 | low | medium | 0.50 | yes | none → T1053.005 |
| ALR-0086 | high | medium | 0.50 | yes | T1053.005 → T1053.005 |
| ALR-0091 | high | medium | 0.50 | yes | T1053.005 → T1053.005 |
| ALR-0093 | low | high | 0.50 | yes | none → T1046 |
| ALR-0095 | critical | high | 0.50 | yes | T1190 → T1190 |
| ALR-0096 | critical | high | 0.50 | yes | T1190 → T1190 |
| ALR-0097 | low | medium | 0.50 | yes | none → T1110.001 |
| ALR-0098 | low | high | 0.50 | yes | none → T1059.001 |
| ALR-0100 | low | high | 0.50 | yes | none → T1567.002 |
| ALR-0102 | high | critical | 0.50 | yes | T1059.001 → T1059.001 |
| ALR-0105 | low | medium | 0.50 | yes | none → T1078 |
| ALR-0110 | low | critical | 0.50 | yes | none → T1003.001 |
| ALR-0111 | high | medium | 0.50 | yes | T1053.005 → T1053.005 |
| ALR-0112 | low | medium | 0.50 | yes | T1595.001 → T1595.001 |
| ALR-0117 | low | medium | 0.50 | yes | none → T1078 |
| ALR-0118 | low | critical | 0.50 | yes | none → T1003.001 |
| ALR-0120 | low | high | 0.50 | yes | none → T1059.001 |
| ALR-0125 | low | high | 0.50 | yes | T1190 → T1190 |
| ALR-0129 | high | medium | 0.50 | yes | T1053.005 → T1053.005 |
| ALR-0130 | low | high | 0.50 | yes | none → T1567.002 |
| ALR-0136 | low | critical | 0.50 | yes | none → T1003.001 |
| ALR-0137 | low | high | 0.50 | yes | none → T1136.001 |
| ALR-0138 | high | medium | 0.50 | yes | T1053.005 → T1053.005 |
| ALR-0139 | low | high | 0.50 | yes | none → T1046 |
| ALR-0142 | low | high | 0.50 | yes | none → T1567.002 |
| ALR-0144 | high | critical | 0.50 | yes | T1621 → T1621 |
| ALR-0145 | high | critical | 0.50 | yes | T1621 → T1621 |
| ALR-0150 | high | critical | 0.50 | yes | T1059.001 → T1059.001 |
| ALR-0151 | critical | high | 0.50 | yes | T1190 → T1190 |
| ALR-0163 | low | medium | 0.50 | yes | none → T1078 |
| ALR-0166 | low | high | 0.50 | yes | none → T1059.001 |
| ALR-0171 | high | critical | 0.50 | yes | T1621 → T1621 |
| ALR-0173 | low | high | 0.50 | yes | T1190 → T1190 |
| ALR-0174 | critical | high | 0.50 | yes | T1190 → T1190 |

## History

| When (UTC) | Engine | Prompt | Severity acc. | Technique acc. | Missed critical | Review rate | Avg cost | Note |
|---|---|---|---|---|---|---|---|---|
| 20261024T021209Z | baseline-rules | `7feb909b` | 64.6% | 80.1% | 9/45 | 85.9% | $0.0000 | rules baseline (keyword + intel, no LLM) |
