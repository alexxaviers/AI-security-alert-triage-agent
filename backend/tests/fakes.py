"""A scripted chat model so the LangGraph agent can be tested without API calls."""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult


class ScriptedChatModel(BaseChatModel):
    """Returns the queued AIMessages in order, one per call. bind_tools is a no-op."""

    responses: list[AIMessage]
    calls: list[list] = []
    model: str = "scripted-test-model"

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **kwargs: Any):  # with_structured_output also routes through here
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.calls.append(list(messages))
        if not self.responses:
            raise RuntimeError("ScriptedChatModel ran out of responses")
        msg = self.responses.pop(0)
        return ChatResult(generations=[ChatGeneration(message=msg)])


def tool_call(name: str, args: dict, call_id: str) -> dict:
    return {"name": name, "args": args, "id": call_id, "type": "tool_call"}


def verdict_message(**verdict) -> AIMessage:
    return AIMessage(content="", tool_calls=[tool_call("Verdict", verdict, "v1")],
                     usage_metadata={"input_tokens": 900, "output_tokens": 150, "total_tokens": 1050})
