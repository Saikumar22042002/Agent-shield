import pytest

from agentshield.connectors.aws_agentcore import assemble_stream
from agentshield.connectors.base import ConnectorError


def test_assembles_text_usage_latency_and_stop_reason():
    events = [
        {"messageStart": {"role": "assistant"}},
        {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "Hello, "}}},
        {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "I can help with incidents."}}},
        {"contentBlockStop": {"contentBlockIndex": 0}},
        {"messageStop": {"stopReason": "end_turn"}},
        {"metadata": {"usage": {"inputTokens": 12, "outputTokens": 7, "totalTokens": 19}, "metrics": {"latencyMs": 812}}},
    ]
    out = assemble_stream(events, "s" * 40)
    assert out.text == "Hello, I can help with incidents."
    assert out.stop_reason == "end_turn"
    assert out.usage == {"inputTokens": 12, "outputTokens": 7, "totalTokens": 19}
    assert out.latency_ms == 812.0


def test_multiple_messages_with_tool_use_sum_usage_and_keep_last_stop():
    events = [
        {"contentBlockStart": {"contentBlockIndex": 0, "start": {"toolUse": {"toolUseId": "t1", "name": "lookup_kb"}}}},
        {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"toolUse": {"input": "{\"q\":\"vpn\"}"}}}},
        {"messageStop": {"stopReason": "tool_use"}},
        {"metadata": {"usage": {"inputTokens": 5, "outputTokens": 3, "totalTokens": 8}, "metrics": {"latencyMs": 100}}},
        {"contentBlockDelta": {"contentBlockIndex": 1, "delta": {"text": "Done."}}},
        {"messageStop": {"stopReason": "end_turn"}},
        {"metadata": {"usage": {"inputTokens": 9, "outputTokens": 2, "totalTokens": 11}, "metrics": {"latencyMs": 250}}},
    ]
    out = assemble_stream(events, "s" * 40)
    assert out.text == "Done."
    assert out.stop_reason == "end_turn"
    assert out.usage["totalTokens"] == 19
    assert out.latency_ms == 250.0
    assert out.tool_events[0]["name"] == "lookup_kb"


@pytest.mark.parametrize("key,code", [("runtimeClientError", "RuntimeClientError"),
                                      ("validationException", "ValidationException"),
                                      ("internalServerException", "InternalServerException")])
def test_in_stream_errors_raise_operator_errors(key, code):
    with pytest.raises(ConnectorError) as ei:
        assemble_stream([{key: {"message": "boom"}}], "s" * 40)
    assert ei.value.code == code
    assert ei.value.retryable == (code == "InternalServerException")


def test_session_id_meets_api_constraints():
    from agentshield.connectors.aws_agentcore import AgentCoreConnector

    sid = AgentCoreConnector.new_session_id(None)  # method does not use self
    assert 33 <= len(sid) <= 100
    assert sid[0].isalnum()
