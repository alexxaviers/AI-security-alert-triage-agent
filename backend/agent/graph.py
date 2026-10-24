"""LangGraph triage agent.

    gather_context ──(tool calls?)──yes──▶ tools ──┐
          ▲                                         │
          └─────────────────────────────────────────┘
          │ no
          ▼
       decide ──▶ guardrail ──▶ END

gather_context: the LLM reads the alert and picks which tools to call.
tools:          runs them and records an audit entry per call.
decide:         the LLM returns a structured Verdict (always valid JSON).
guardrail:      validates the technique ID and flags low-confidence verdicts for human review.
"""

from __future__ import annotations

import json
import operator
import time
from typing import Annotated, Any, Literal, TypedDict

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

from agent.prompts import DECIDE_PROMPT, SYSTEM_PROMPT
from app.config import get_settings
from tools import TOOLS, TOOLS_BY_NAME
from tools.attack_mapper import technique_index


class Verdict(BaseModel):
    """Final triage verdict for one alert."""

    severity: Literal["low", "medium", "high", "critical"]
    attack_technique: str = Field(description='MITRE ATT&CK ID such as "T1110.001", or "none" if benign')
    confidence: float = Field(description="Probability the severity is correct, from 0 to 1")
    summary: str = Field(description="1-2 sentence triage summary")
    reasoning: str = Field(description="The key evidence behind the verdict")
    next_steps: list[str] = Field(description="2-5 concrete recommended actions")


class AgentState(TypedDict, total=False):
    alert: dict
    messages: Annotated[list[AnyMessage], add_messages]
    tool_audit: Annotated[list[dict], operator.add]
    rounds: int
    usage: Annotated[list[dict], operator.add]
    verdict: dict
    needs_review: bool
    review_reason: str | None


def _usage(msg: Any) -> list[dict]:
    u = getattr(msg, "usage_metadata", None)
    return [{"input": u.get("input_tokens", 0), "output": u.get("output_tokens", 0)}] if u else []


def build_agent(llm: BaseChatModel):
    settings = get_settings()
    llm_with_tools = llm.bind_tools(TOOLS)
    # Claude's native structured outputs guarantee schema-valid JSON (forced tool calling isn't
    # supported on newer Claude models). Other chat models fall back to the default method.
    if type(llm).__name__ == "ChatAnthropic":
        llm_verdict = llm.with_structured_output(Verdict, include_raw=True, method="json_schema")
    else:
        llm_verdict = llm.with_structured_output(Verdict, include_raw=True)

    def gather_context(state: AgentState) -> dict:
        msgs = state.get("messages") or []
        new: list[AnyMessage] = []
        if not msgs:
            new = [SystemMessage(SYSTEM_PROMPT),
                   HumanMessage("Triage this alert:\n```json\n" + json.dumps(state["alert"], indent=2) + "\n```")]
        resp = llm_with_tools.invoke(msgs + new)
        return {"messages": new + [resp], "rounds": state.get("rounds", 0) + 1, "usage": _usage(resp)}

    def needs_tools(state: AgentState) -> Literal["yes", "no"]:
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls and state.get("rounds", 0) <= settings.max_tool_rounds:
            return "yes"
        return "no"

    def tool_node(state: AgentState) -> dict:
        last: AIMessage = state["messages"][-1]
        out_msgs, audit = [], []
        for call in last.tool_calls:
            t0 = time.perf_counter()
            tool = TOOLS_BY_NAME.get(call["name"])
            try:
                result = tool.invoke(call["args"]) if tool else {"error": f"unknown tool {call['name']}"}
            except Exception as e:  # surface tool failures to the model instead of crashing
                result = {"error": f"{type(e).__name__}: {e}"}
            ms = int((time.perf_counter() - t0) * 1000)
            audit.append({"tool": call["name"], "args": call["args"], "output": result, "latency_ms": ms})
            out_msgs.append(ToolMessage(json.dumps(result, default=str), tool_call_id=call["id"], name=call["name"]))
        return {"messages": out_msgs, "tool_audit": audit}

    def decide(state: AgentState) -> dict:
        msgs = list(state["messages"])
        # If we stopped mid tool-loop (round limit), the trailing AIMessage has unanswered tool calls;
        # drop it so the conversation is valid.
        if isinstance(msgs[-1], AIMessage) and msgs[-1].tool_calls:
            msgs = msgs[:-1]
        out = llm_verdict.invoke(msgs + [HumanMessage(DECIDE_PROMPT)])
        parsed: Verdict | None = out.get("parsed")
        if parsed is None:
            raise ValueError(f"model did not return a valid Verdict: {out.get('parsing_error')}")
        return {"verdict": parsed.model_dump(), "usage": _usage(out.get("raw"))}

    def guardrail(state: AgentState) -> dict:
        v = dict(state["verdict"])
        reasons = []
        tech = v["attack_technique"].strip().upper() if v["attack_technique"].strip().lower() != "none" else "none"
        if tech != "none" and tech not in technique_index():
            reasons.append(f"technique {tech} is not a valid ATT&CK ID")
        v["attack_technique"] = tech
        v["confidence"] = min(1.0, max(0.0, float(v["confidence"])))
        if v["confidence"] < settings.review_confidence_threshold:
            reasons.append(f"confidence {v['confidence']:.2f} below {settings.review_confidence_threshold}")
        return {"verdict": v, "needs_review": bool(reasons), "review_reason": "; ".join(reasons) or None}

    g = StateGraph(AgentState)
    g.add_node("gather_context", gather_context)
    g.add_node("tools", tool_node)
    g.add_node("decide", decide)
    g.add_node("guardrail", guardrail)
    g.set_entry_point("gather_context")
    g.add_conditional_edges("gather_context", needs_tools, {"yes": "tools", "no": "decide"})
    g.add_edge("tools", "gather_context")
    g.add_edge("decide", "guardrail")
    g.add_edge("guardrail", END)
    return g.compile()


def make_llm(model: str | None = None) -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic

    s = get_settings()
    if not s.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    kwargs = {"temperature": s.llm_temperature} if s.llm_temperature is not None else {}
    return ChatAnthropic(model=model or s.anthropic_model, api_key=s.anthropic_api_key,
                         max_tokens=2048, max_retries=3, **kwargs)
