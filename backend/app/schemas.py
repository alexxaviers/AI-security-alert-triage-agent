from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high", "critical"]


class AlertIn(BaseModel):
    """An incoming alert. Only title is required; any extra fields are kept in raw."""

    model_config = ConfigDict(extra="allow")

    id: str | None = None
    title: str
    description: str | None = None
    source: str | None = None
    rule_name: str | None = None


class VerdictOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    severity: Severity
    technique: str
    technique_name: str | None
    confidence: float
    summary: str
    reasoning: str | None
    next_steps: list[str]
    needs_review: bool
    review_reason: str | None
    engine: str
    latency_ms: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    created_at: datetime


class ToolCallOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tool: str
    args: dict[str, Any]
    output: dict[str, Any]
    latency_ms: int
    created_at: datetime


class OverrideIn(BaseModel):
    severity: Severity
    technique: str | None = Field(None, description="ATT&CK ID or 'none'; defaults to the agent's technique")
    analyst: str = "analyst"
    note: str | None = None


class OverrideOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    previous_severity: str | None
    previous_technique: str | None
    severity: str
    technique: str
    analyst: str
    note: str | None
    created_at: datetime


class AlertSummary(BaseModel):
    id: str
    title: str
    source: str | None
    status: str
    received_at: datetime
    severity: Severity | None = None
    technique: str | None = None
    confidence: float | None = None
    needs_review: bool | None = None
    overridden: bool = False


class AlertDetail(BaseModel):
    id: str
    title: str
    source: str | None
    status: str
    error: str | None
    received_at: datetime
    raw: dict[str, Any]
    verdict: VerdictOut | None
    tool_calls: list[ToolCallOut]
    overrides: list[OverrideOut]


class AlertList(BaseModel):
    total: int
    items: list[AlertSummary]


class Stats(BaseModel):
    total: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    needs_review: int
    avg_latency_ms: float | None
    total_cost_usd: float
    engine: str
