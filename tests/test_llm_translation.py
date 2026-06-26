"""F1-2: LLM format translation — pure, no network, no SDK."""

from netcopilot.llm import LLMResult, ToolCall
from netcopilot.llm.claude import to_anthropic_messages, to_anthropic_tools
from netcopilot.llm.ollama import parse_openai, to_openai_messages, to_openai_tools

TOOLS = [
    {"name": "query_topology", "description": "Get topology", "parameters": {"type": "object"}}
]

HISTORY = [
    {"role": "user", "content": "show topology"},
    {"role": "assistant", "content": None, "tool_calls": [ToolCall("c1", "query_topology", {})]},
    {"role": "tool", "tool_call_id": "c1", "content": "3 devices"},
]


def test_anthropic_tools():
    out = to_anthropic_tools(TOOLS)
    assert out[0]["name"] == "query_topology"
    assert out[0]["input_schema"] == TOOLS[0]["parameters"]


def test_anthropic_messages_coalesce_tool_results():
    msgs = to_anthropic_messages(HISTORY)
    assert msgs[0]["role"] == "user"
    assert msgs[1]["role"] == "assistant"
    assert any(b["type"] == "tool_use" for b in msgs[1]["content"])
    assert msgs[2]["role"] == "user"
    assert msgs[2]["content"][0]["type"] == "tool_result"
    assert msgs[2]["content"][0]["tool_use_id"] == "c1"


def test_openai_tools_and_messages():
    assert to_openai_tools(TOOLS)[0]["type"] == "function"
    msgs = to_openai_messages("SYS", HISTORY)
    # system, user, assistant(tool_calls), tool
    assert msgs[0] == {"role": "system", "content": "SYS"}
    assert msgs[1]["role"] == "user"
    assert msgs[2]["role"] == "assistant"
    assert msgs[2]["tool_calls"][0]["function"]["arguments"] == "{}"
    assert msgs[3]["role"] == "tool" and msgs[3]["tool_call_id"] == "c1"


def test_parse_openai():
    data = {
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {"id": "x", "function": {"name": "blast_radius", "arguments": '{"device": "d1"}'}}
                    ],
                }
            }
        ]
    }
    res = parse_openai(data)
    assert isinstance(res, LLMResult)
    assert res.tool_calls[0].name == "blast_radius"
    assert res.tool_calls[0].arguments == {"device": "d1"}
    assert not res.is_final


def test_final_result_is_final():
    assert LLMResult(text="done", tool_calls=[]).is_final
