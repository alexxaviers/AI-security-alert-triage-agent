"""One entry point for triage, used by the API and the eval suite."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.config import get_settings
from tools.attack_mapper import technique_index


@dataclass
class TriageResult:
    verdict: dict
    needs_review: bool
    review_reason: str | None
    engine: str
    tool_audit: list[dict] = field(default_factory=list)
    latency_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    @property
    def technique_name(self) -> str | None:
        t = technique_index().get(self.verdict.get("attack_technique", ""))
        return t["name"] if t else None


class LLMTriager:
    def __init__(self, llm=None, model: str | None = None):
        from agent.graph import build_agent, make_llm

        self.model = model or get_settings().anthropic_model
        self.agent = build_agent(llm or make_llm(self.model))
        if llm is not None:
            self.model = getattr(llm, "model", None) or getattr(llm, "model_name", None) or "custom-llm"

    def triage(self, alert: dict) -> TriageResult:
        s = get_settings()
        t0 = time.perf_counter()
        state = self.agent.invoke({"alert": alert}, {"recursion_limit": 4 * s.max_tool_rounds + 10})
        ms = int((time.perf_counter() - t0) * 1000)
        tin = sum(u["input"] for u in state.get("usage", []))
        tout = sum(u["output"] for u in state.get("usage", []))
        cost = tin / 1e6 * s.price_input_per_mtok + tout / 1e6 * s.price_output_per_mtok
        return TriageResult(verdict=state["verdict"], needs_review=state["needs_review"],
                            review_reason=state.get("review_reason"), engine=self.model,
                            tool_audit=state.get("tool_audit", []), latency_ms=ms,
                            input_tokens=tin, output_tokens=tout, cost_usd=round(cost, 6))


class BaselineTriager:
    model = "baseline-rules"

    def triage(self, alert: dict) -> TriageResult:
        from agent.baseline import triage_baseline

        t0 = time.perf_counter()
        verdict, audit = triage_baseline(alert)
        thr = get_settings().review_confidence_threshold
        return TriageResult(verdict=verdict, needs_review=verdict["confidence"] < thr,
                            review_reason=f"confidence {verdict['confidence']:.2f} below {thr}"
                            if verdict["confidence"] < thr else None,
                            engine=self.model, tool_audit=audit,
                            latency_ms=int((time.perf_counter() - t0) * 1000))


_default = None


def get_triager():
    global _default
    if _default is None:
        _default = LLMTriager() if get_settings().use_llm else BaselineTriager()
    return _default
