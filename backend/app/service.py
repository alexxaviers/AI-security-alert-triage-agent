"""Glue between the API, the database and the triage agent."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from agent.runner import TriageResult, get_triager
from app.db import SessionLocal
from app.models import Alert, Override, ToolCall, Verdict

log = logging.getLogger(__name__)


def save_result(session: Session, alert: Alert, result: TriageResult) -> Verdict:
    v = result.verdict
    verdict = Verdict(
        alert_id=alert.id, severity=v["severity"], technique=v["attack_technique"],
        technique_name=result.technique_name, confidence=v["confidence"], summary=v["summary"],
        reasoning=v.get("reasoning"), next_steps=v.get("next_steps", []), needs_review=result.needs_review,
        review_reason=result.review_reason, engine=result.engine, latency_ms=result.latency_ms,
        input_tokens=result.input_tokens, output_tokens=result.output_tokens, cost_usd=result.cost_usd,
    )
    session.add(verdict)
    session.flush()
    for call in result.tool_audit:
        session.add(ToolCall(alert_id=alert.id, verdict_id=verdict.id, tool=call["tool"], args=call["args"],
                             output=call["output"], latency_ms=call.get("latency_ms", 0)))
    alert.status = "needs_review" if result.needs_review else "triaged"
    alert.error = None
    return verdict


def triage_alert(alert_id: str) -> None:
    """Run the agent on one stored alert and persist the verdict. Safe to call from a background task."""
    with SessionLocal() as s:
        alert = s.get(Alert, alert_id)
        if alert is None:
            return
        alert.status = "triaging"
        s.commit()
        try:
            result = get_triager().triage(alert.raw)
            save_result(s, alert, result)
        except Exception as e:
            log.exception("triage failed for %s", alert_id)
            s.rollback()
            alert = s.get(Alert, alert_id)
            alert.status = "error"
            alert.error = f"{type(e).__name__}: {e}"[:2000]
        s.commit()


def apply_override(session: Session, alert: Alert, severity: str, technique: str | None,
                   analyst: str, note: str | None) -> Override:
    latest = alert.latest_verdict
    o = Override(
        alert_id=alert.id, verdict_id=latest.id if latest else None,
        previous_severity=latest.severity if latest else None,
        previous_technique=latest.technique if latest else None,
        severity=severity, technique=technique or (latest.technique if latest else "none"),
        analyst=analyst, note=note,
    )
    session.add(o)
    alert.status = "overridden"
    return o
