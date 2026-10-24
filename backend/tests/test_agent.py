from langchain_core.messages import AIMessage

from agent.runner import LLMTriager
from tests.fakes import ScriptedChatModel, tool_call, verdict_message

ALERT = {
    "id": "T-1",
    "rule_name": "Brute Force Login Attempt",
    "title": "Brute force against admin",
    "description": "50 failed logins for admin from 185.220.101.20 in 2 minutes.",
    "user": "admin",
    "src_ip": "185.220.101.20",
}


def _run(responses):
    llm = ScriptedChatModel(responses=responses, calls=[])
    return LLMTriager(llm=llm).triage(ALERT), llm


def test_agent_calls_tools_then_returns_verdict():
    result, llm = _run([
        AIMessage(content="", tool_calls=[
            tool_call("check_ip_reputation", {"ip": "185.220.101.20"}, "c1"),
            tool_call("map_to_attack", {"description": "many failed logins for one account"}, "c2"),
        ], usage_metadata={"input_tokens": 800, "output_tokens": 60, "total_tokens": 860}),
        AIMessage(content="IP is a Tor exit with a high abuse score. Brute force, no success.",
                  usage_metadata={"input_tokens": 1200, "output_tokens": 40, "total_tokens": 1240}),
        verdict_message(severity="high", attack_technique="T1110.001", confidence=0.85,
                        summary="Brute force from a Tor exit.", reasoning="High abuse score.",
                        next_steps=["Block the IP", "Reset the password"]),
    ])
    assert result.verdict["severity"] == "high"
    assert result.verdict["attack_technique"] == "T1110.001"
    assert result.technique_name == "Password Guessing"
    assert not result.needs_review
    assert [a["tool"] for a in result.tool_audit] == ["check_ip_reputation", "map_to_attack"]
    assert "abuse_confidence_score" in result.tool_audit[0]["output"]
    assert result.input_tokens == 800 + 1200 + 900
    assert result.cost_usd > 0
    # The tool results were fed back to the model on the second call.
    assert any(getattr(m, "type", "") == "tool" for m in llm.calls[1])


def test_low_confidence_is_flagged_for_review():
    result, _ = _run([
        AIMessage(content="Not enough context."),
        verdict_message(severity="medium", attack_technique="T1110.001", confidence=0.4,
                        summary="Unclear.", reasoning="Little evidence.", next_steps=["Investigate"]),
    ])
    assert result.needs_review
    assert "confidence" in result.review_reason


def test_invalid_technique_is_flagged_for_review():
    result, _ = _run([
        AIMessage(content="done"),
        verdict_message(severity="high", attack_technique="T9999", confidence=0.9,
                        summary="x", reasoning="x", next_steps=["x"]),
    ])
    assert result.needs_review
    assert "not a valid ATT&CK ID" in result.review_reason


def test_none_technique_is_normalized():
    result, _ = _run([
        AIMessage(content="benign"),
        verdict_message(severity="low", attack_technique="None", confidence=0.9,
                        summary="Benign.", reasoning="x", next_steps=["Close"]),
    ])
    assert result.verdict["attack_technique"] == "none"
    assert not result.needs_review


def test_tool_errors_are_returned_to_the_model_not_raised():
    result, _ = _run([
        AIMessage(content="", tool_calls=[tool_call("check_file_hash", {"sha256": "not-a-hash"}, "c1")]),
        AIMessage(content="hash invalid"),
        verdict_message(severity="medium", attack_technique="T1110", confidence=0.7,
                        summary="x", reasoning="x", next_steps=["x"]),
    ])
    assert "error" in result.tool_audit[0]["output"]


def test_thinking_blocks_are_not_replayed_into_the_verdict_call():
    # Signed thinking blocks are bound to the tools list they were made with; the verdict call has
    # no tools, so the API rejects them if they are sent back.
    result, llm = _run([
        AIMessage(content=[
            {"type": "thinking", "thinking": "Check the IP first.", "signature": "sig"},
            {"type": "tool_use", "id": "c1", "name": "check_ip_reputation", "input": {"ip": "185.220.101.20"}},
        ], tool_calls=[tool_call("check_ip_reputation", {"ip": "185.220.101.20"}, "c1")]),
        AIMessage(content=[{"type": "thinking", "thinking": "Tor exit.", "signature": "sig"},
                           {"type": "text", "text": "Brute force from a Tor exit."}]),
        verdict_message(severity="high", attack_technique="T1110.001", confidence=0.85,
                        summary="Brute force.", reasoning="Tor exit.", next_steps=["Block the IP"]),
    ])
    assert result.verdict["severity"] == "high"
    decide_msgs = llm.calls[-1]
    blocks = [b for m in decide_msgs if isinstance(m.content, list) for b in m.content]
    assert blocks and not any(b.get("type") in ("thinking", "redacted_thinking") for b in blocks)
