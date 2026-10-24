import logging
import uuid
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, selectinload

from app.config import get_settings
from app.db import get_session, init_db
from app.models import Alert, Override, Verdict
from app.schemas import (
    AlertDetail,
    AlertIn,
    AlertList,
    AlertSummary,
    OverrideIn,
    OverrideOut,
    Stats,
    ToolCallOut,
    VerdictOut,
)
from app.service import apply_override, triage_alert
from tools.attack_mapper import technique_index

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AI Alert Triage", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in get_settings().cors_origins.split(",")],
                   allow_methods=["*"], allow_headers=["*"])

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _latest_subqueries():
    lv = select(Verdict.alert_id, func.max(Verdict.id).label("vid")).group_by(Verdict.alert_id).subquery()
    lo = select(Override.alert_id, func.max(Override.id).label("oid")).group_by(Override.alert_id).subquery()
    return lv, lo


def _get_alert(session: Session, alert_id: str) -> Alert:
    alert = session.get(Alert, alert_id, options=[selectinload(Alert.verdicts), selectinload(Alert.tool_calls),
                                                  selectinload(Alert.overrides)])
    if alert is None:
        raise HTTPException(404, f"alert {alert_id} not found")
    return alert


def _detail(alert: Alert) -> AlertDetail:
    v = alert.latest_verdict
    calls = [c for c in alert.tool_calls if v is None or c.verdict_id == v.id]
    return AlertDetail(
        id=alert.id, title=alert.title, source=alert.source, status=alert.status, error=alert.error,
        received_at=alert.received_at, raw=alert.raw,
        verdict=VerdictOut.model_validate(v) if v else None,
        tool_calls=[ToolCallOut.model_validate(c) for c in calls],
        overrides=[OverrideOut.model_validate(o) for o in alert.overrides],
    )


@app.get("/health")
def health():
    s = get_settings()
    return {"status": "ok", "engine": s.anthropic_model if s.use_llm else "baseline-rules"}


# Endpoints that start a background triage close their session when they return (scope="function").
# With the default scope the session, and its pooled connection, stays open until the background task
# finishes, so a burst of alerts exhausts the pool.
@app.post("/alerts", response_model=AlertDetail, status_code=201)
def create_alert(body: AlertIn, background: BackgroundTasks, sync: bool = False,
                 session: Session = Depends(get_session, scope="function")):
    """Store an alert as pending and triage it in the background (or inline with ?sync=true)."""
    raw = body.model_dump(exclude_none=True)
    alert_id = raw.get("id") or f"ALR-{uuid.uuid4().hex[:8].upper()}"
    raw["id"] = alert_id
    if session.get(Alert, alert_id):
        raise HTTPException(409, f"alert {alert_id} already exists")
    session.add(Alert(id=alert_id, raw=raw, source=raw.get("source"), title=raw["title"][:300], status="pending"))
    session.commit()
    if sync:
        triage_alert(alert_id)
    else:
        background.add_task(triage_alert, alert_id)
    session.expire_all()
    return _detail(_get_alert(session, alert_id))


@app.get("/alerts", response_model=AlertList)
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    needs_review: bool | None = None,
    q: str | None = Query(None, description="search in id/title"),
    sort: Literal["received", "severity"] = "severity",
    limit: int = Query(50, le=500),
    offset: int = 0,
    session: Session = Depends(get_session),
):
    lv, lo = _latest_subqueries()
    eff_sev = func.coalesce(Override.severity, Verdict.severity)
    stmt = (select(Alert, Verdict, Override)
            .outerjoin(lv, lv.c.alert_id == Alert.id).outerjoin(Verdict, Verdict.id == lv.c.vid)
            .outerjoin(lo, lo.c.alert_id == Alert.id).outerjoin(Override, Override.id == lo.c.oid))
    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(eff_sev == severity)
    if needs_review is not None:
        stmt = stmt.where(Verdict.needs_review.is_(needs_review))
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(func.lower(Alert.title).like(like) | func.lower(Alert.id).like(like))
    total = session.scalar(select(func.count()).select_from(stmt.subquery()))
    if sort == "severity":
        rank = case(*[(eff_sev == k, v) for k, v in SEV_RANK.items()], else_=0)
        stmt = stmt.order_by(rank.desc(), Alert.received_at.desc(), Alert.id)
    else:
        stmt = stmt.order_by(Alert.received_at.desc(), Alert.id)
    rows = session.execute(stmt.limit(limit).offset(offset)).all()
    items = [AlertSummary(
        id=a.id, title=a.title, source=a.source, status=a.status, received_at=a.received_at,
        severity=(o.severity if o else v.severity if v else None),
        technique=(o.technique if o else v.technique if v else None),
        confidence=v.confidence if v else None, needs_review=v.needs_review if v else None,
        overridden=o is not None,
    ) for a, v, o in rows]
    return AlertList(total=total or 0, items=items)


@app.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: str, session: Session = Depends(get_session)):
    return _detail(_get_alert(session, alert_id))


@app.post("/alerts/{alert_id}/override", response_model=AlertDetail)
def override_alert(alert_id: str, body: OverrideIn, session: Session = Depends(get_session)):
    """A human corrects the agent. Corrections are kept and exportable as eval labels."""
    alert = _get_alert(session, alert_id)
    tech = body.technique
    if tech is not None:
        tech = "none" if tech.strip().lower() == "none" else tech.strip().upper()
        if tech != "none" and tech not in technique_index():
            raise HTTPException(422, f"{tech} is not a valid ATT&CK technique ID")
    apply_override(session, alert, body.severity, tech, body.analyst, body.note)
    session.commit()
    session.expire_all()
    return _detail(_get_alert(session, alert_id))


@app.post("/alerts/{alert_id}/retriage", response_model=AlertDetail)
def retriage(alert_id: str, background: BackgroundTasks, sync: bool = False,
             session: Session = Depends(get_session, scope="function")):
    _get_alert(session, alert_id)
    if sync:
        triage_alert(alert_id)
    else:
        background.add_task(triage_alert, alert_id)
    session.expire_all()
    return _detail(_get_alert(session, alert_id))


@app.get("/stats", response_model=Stats)
def stats(session: Session = Depends(get_session)):
    lv, lo = _latest_subqueries()
    eff_sev = func.coalesce(Override.severity, Verdict.severity)
    base = (select(eff_sev.label("sev"), func.count())
            .select_from(Alert)
            .join(lv, lv.c.alert_id == Alert.id).join(Verdict, Verdict.id == lv.c.vid)
            .outerjoin(lo, lo.c.alert_id == Alert.id).outerjoin(Override, Override.id == lo.c.oid)
            .group_by(eff_sev))
    by_sev = {k: n for k, n in session.execute(base).all()}
    by_status = dict(session.execute(select(Alert.status, func.count()).group_by(Alert.status)).all())
    s = get_settings()
    return Stats(
        total=session.scalar(select(func.count(Alert.id))) or 0,
        by_status=by_status, by_severity=by_sev,
        needs_review=by_status.get("needs_review", 0),
        avg_latency_ms=session.scalar(select(func.avg(Verdict.latency_ms))),
        total_cost_usd=round(session.scalar(select(func.coalesce(func.sum(Verdict.cost_usd), 0.0))) or 0.0, 4),
        engine=s.anthropic_model if s.use_llm else "baseline-rules",
    )


@app.get("/overrides/export")
def export_overrides(session: Session = Depends(get_session)):
    """Analyst corrections in the same format as evals/labels.json, ready to grow the eval set."""
    lo = select(Override.alert_id, func.max(Override.id).label("oid")).group_by(Override.alert_id).subquery()
    rows = session.execute(select(Override).join(lo, lo.c.oid == Override.id)).scalars().all()
    return {o.alert_id: {"severity": o.severity, "technique": o.technique, "accepted_techniques": [],
                         "rationale": o.note or f"Analyst override by {o.analyst}", "scenario": "analyst_override"}
            for o in rows}
