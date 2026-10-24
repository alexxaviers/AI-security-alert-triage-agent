# Labeling guide

`evals/labels.json` is the ground truth the eval suite scores against. Each label has:

| Field | Meaning |
|---|---|
| `severity` | low, medium, high or critical, per the rubric below |
| `technique` | the single best MITRE ATT&CK ID, or `none` for benign alerts |
| `accepted_techniques` | other IDs a competent analyst could reasonably pick; counted as correct |
| `rationale` | one line on why |
| `scenario` | which generator produced it (`otrf_real` = real telemetry from OTRF) |
| `reviewed` | set to `true` once a human has checked it |

## Where the labels come from

`scripts/generate_alerts.py` proposes a label for every synthetic alert from the scenario that
produced it, and `scripts/import_otrf.py` labels the real OTRF samples. These are a starting
point, not hand labels. Review every one with:

```bash
python scripts/review_labels.py
```

Only call the set "hand-labeled" after that review is done. Expect to disagree with some
labels; that's the point of reviewing. When you change one, ask whether the rubric needs a
tweak too, and keep `agent/prompts.py` (`SEVERITY_RUBRIC`) in sync.

## Severity rubric

The same rubric is given to the agent. That is deliberate: a SOC has a written severity
policy and analysts are graded against it. It also means accuracy here measures how well
the agent applies the policy, not how well it would do with no policy.

- **critical**: confirmed or near-certain compromise, or an active high-impact attack.
- **high**: likely malicious and needs action now, but no confirmed success.
- **medium**: suspicious and worth investigating; impact unclear.
- **low**: benign, expected, or fully blocked noise.

See `agent/prompts.py` for the examples under each level.

## Growing the set

Analyst overrides from the dashboard are exported in the same format by
`GET /overrides/export`. Merge them into `labels.json` (and the alerts into
`data/alerts.json`) to turn real corrections into eval cases.
