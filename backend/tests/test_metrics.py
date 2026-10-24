from evals.metrics import compute, technique_correct


def row(i, gold_sev, pred_sev, gold_t="T1110.001", pred_t="T1110.001", review=False, scenario="x"):
    return {"id": i, "label": {"severity": gold_sev, "technique": gold_t, "accepted_techniques": ["T1078"],
                               "scenario": scenario},
            "pred": {"severity": pred_sev, "technique": pred_t, "needs_review": review, "confidence": 0.9},
            "latency_ms": 1000, "cost_usd": 0.01, "input_tokens": 1000, "output_tokens": 100, "tool_calls": 2}


def test_technique_matching_levels():
    lab = {"technique": "T1110.001", "accepted_techniques": ["T1078"]}
    assert technique_correct("T1110.001", lab)
    assert technique_correct("T1078", lab)
    assert not technique_correct("T1110.003", lab)
    assert technique_correct("T1110.003", lab, "parent")
    assert technique_correct("none", {"technique": "none"})
    assert not technique_correct("T1110", {"technique": "none"}, "parent")


def test_compute_core_metrics():
    rows = [
        row("a", "critical", "critical"),
        row("b", "critical", "medium", review=False),        # silent miss
        row("c", "critical", "high", review=True),            # miss, not silent
        row("d", "low", "critical", pred_t="T1110.003"),      # false critical, parent-only technique match
        {"id": "e", "label": {"severity": "low", "technique": "none"}, "pred": None, "error": "boom"},
    ]
    m = compute(rows)
    assert m["n"] == 5 and m["errors"] == 1
    assert m["severity_accuracy"] == 0.25
    assert m["missed_critical"] == ["b", "c"]
    assert m["silent_missed_critical"] == ["b"]
    assert m["false_critical"] == ["d"]
    assert m["technique_accuracy"] == 0.75 and m["technique_accuracy_parent"] == 1.0
    assert m["confusion"]["critical"]["medium"] == 1
    assert m["review_rate"] == 0.25
    assert m["per_class"]["critical"]["recall"] == 1 / 3
