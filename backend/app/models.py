from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base

JSONType = JSON().with_variant(JSONB(), "postgresql")


def now() -> datetime:
    return datetime.now(UTC)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    raw: Mapped[dict] = mapped_column(JSONType)
    source: Mapped[str | None] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    # pending | triaging | triaged | needs_review | overridden | error
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    error: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)

    verdicts: Mapped[list["Verdict"]] = relationship(back_populates="alert", order_by="Verdict.created_at",
                                                     cascade="all, delete-orphan")
    tool_calls: Mapped[list["ToolCall"]] = relationship(back_populates="alert", order_by="ToolCall.id",
                                                        cascade="all, delete-orphan")
    overrides: Mapped[list["Override"]] = relationship(back_populates="alert", order_by="Override.created_at",
                                                       cascade="all, delete-orphan")

    @property
    def latest_verdict(self) -> "Verdict | None":
        return self.verdicts[-1] if self.verdicts else None


class Verdict(Base):
    __tablename__ = "verdicts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    technique: Mapped[str] = mapped_column(String(32))
    technique_name: Mapped[str | None] = mapped_column(String(200))
    confidence: Mapped[float] = mapped_column(Float)
    summary: Mapped[str] = mapped_column(Text)
    reasoning: Mapped[str | None] = mapped_column(Text)
    next_steps: Mapped[list] = mapped_column(JSONType, default=list)
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)
    review_reason: Mapped[str | None] = mapped_column(Text)
    engine: Mapped[str] = mapped_column(String(64))  # model name or "baseline-rules"
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    alert: Mapped[Alert] = relationship(back_populates="verdicts")


class ToolCall(Base):
    """Audit log: every tool the agent used, with arguments and output."""

    __tablename__ = "tool_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    verdict_id: Mapped[int | None] = mapped_column(ForeignKey("verdicts.id", ondelete="SET NULL"))
    tool: Mapped[str] = mapped_column(String(64))
    args: Mapped[dict] = mapped_column(JSONType)
    output: Mapped[dict] = mapped_column(JSONType)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    alert: Mapped[Alert] = relationship(back_populates="tool_calls")


class Override(Base):
    """A human correction. These double as new labeled eval data."""

    __tablename__ = "overrides"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    verdict_id: Mapped[int | None] = mapped_column(ForeignKey("verdicts.id", ondelete="SET NULL"))
    previous_severity: Mapped[str | None] = mapped_column(String(16))
    previous_technique: Mapped[str | None] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    technique: Mapped[str] = mapped_column(String(32))
    analyst: Mapped[str] = mapped_column(String(100), default="analyst")
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    alert: Mapped[Alert] = relationship(back_populates="overrides")


class IntelCache(Base):
    """Cached AbuseIPDB / VirusTotal responses, to stay inside free-tier quotas."""

    __tablename__ = "intel_cache"

    kind: Mapped[str] = mapped_column(String(16), primary_key=True)  # "ip" | "hash"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONType)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
