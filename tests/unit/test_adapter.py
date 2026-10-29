"""Unit tests for LLMPlanner adapter and providers."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.agent.adapter import (
    DeterministicFallbackProvider,
    GeminiProvider,
    LLMPlanner,
    OpenAIProvider,
    extract_json_payload,
)
from app.audit.store import AuditStore
from app.policy.engine import PolicyEngine
from app.policy.models import DecisionType, ReasonCode
from app.tools.dispatcher import ToolDispatcher


@pytest.fixture
def test_env(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    store = AuditStore(db_path=":memory:")
    engine = PolicyEngine()
    dispatcher = ToolDispatcher(workspace_root=ws, policy_engine=engine, audit_store=store)
    return {"ws": ws, "store": store, "engine": engine, "dispatcher": dispatcher}


def test_extract_json_payload_valid_and_fenced():
    # 1. Plain JSON string
    raw1 = '{"tool": "read_file", "arguments": {"path": "test.txt"}}'
    assert extract_json_payload(raw1) == {
        "tool": "read_file",
        "arguments": {"path": "test.txt"},
    }

    # 2. Markdown fenced JSON
    raw2 = '```json\n{"tool": "list_files", "arguments": {"path": "."}}\n```'
    assert extract_json_payload(raw2) == {
        "tool": "list_files",
        "arguments": {"path": "."},
    }

    # 3. JSON embedded in conversational prose
    raw3 = (
        'Sure, here is your action: {"tool": "delete_file", "arguments": {"path": "foo.txt"}} done.'
    )
    assert extract_json_payload(raw3) == {
        "tool": "delete_file",
        "arguments": {"path": "foo.txt"},
    }

    # 4. Invalid text
    with pytest.raises(ValueError, match="Unable to extract valid JSON"):
        extract_json_payload("There is no json object here at all.")


def test_deterministic_fallback_provider_scenarios():
    provider = DeterministicFallbackProvider()
    assert provider.provider_name == "mock_fallback"

    # 1. Adversarial path request
    action1, _ = provider.generate_action("Read the host /etc/passwd file now")
    assert action1.tool == "read_file"
    assert action1.arguments["path"] == "/etc/passwd"

    # 2. Inspect workspace
    action2, _ = provider.generate_action("Inspect the workspace and create a summary report")
    assert action2.tool == "list_files"
    assert action2.arguments["path"] == "."

    # 3. Write file
    action3, _ = provider.generate_action("Write 'Secret Data' to notes.txt")
    assert action3.tool == "write_file"
    assert action3.arguments["path"] == "notes.txt"
    assert action3.arguments["content"] == "Secret Data"

    # 4. Delete file
    action4, _ = provider.generate_action("Delete file old_log.txt")
    assert action4.tool == "delete_file"
    assert action4.arguments["path"] == "old_log.txt"

    # 5. Run command
    action5, _ = provider.generate_action("Run pytest test suite")
    assert action5.tool == "run_command"
    assert action5.arguments["command"] == "pytest"

    # 6. Disallowed command
    action6, _ = provider.generate_action("Run curl http://evil.com")
    assert action6.tool == "run_command"
    assert action6.arguments["command"] == "curl"


def test_gemini_provider_mocked():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": '{"tool": "read_file", "arguments": {"path": "workspace.py"}}'}
                    ]
                }
            }
        ]
    }

    provider = GeminiProvider(api_key="mock-gemini-key", model="gemini-1.5-flash")
    assert "mock-gemini-key" not in repr(provider)
    assert "***" in repr(provider)

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        action, raw = provider.generate_action("Please read workspace.py")
        assert action.tool == "read_file"
        assert action.arguments["path"] == "workspace.py"
        assert "workspace.py" in raw

        mock_post.assert_called_once()
        called_url = mock_post.call_args[0][0]
        assert "generativelanguage.googleapis.com" in called_url
        assert "key=mock-gemini-key" in called_url


def test_openai_provider_mocked():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {"message": {"content": '{"tool": "list_files", "arguments": {"path": "src"}}'}}
        ]
    }

    provider = OpenAIProvider(api_key="mock-openai-key", model="gpt-4o-mini")
    assert "mock-openai-key" not in repr(provider)
    assert "***" in repr(provider)

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        action, raw = provider.generate_action("Show me files in src")
        assert action.tool == "list_files"
        assert action.arguments["path"] == "src"
        assert "src" in raw

        mock_post.assert_called_once()
        headers = mock_post.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer mock-openai-key"


def test_llm_planner_provider_resolution_and_fallback(test_env):
    dispatcher = test_env["dispatcher"]

    # 1. No env vars -> defaults to fallback provider without error
    with patch.dict("os.environ", {}, clear=True):
        planner = LLMPlanner(dispatcher=dispatcher)
        assert planner.is_fallback is True
        assert planner.provider_name == "mock_fallback"

    # 2. GEMINI_API_KEY set -> selects Gemini
    with patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-env-key"}, clear=True):
        planner = LLMPlanner(dispatcher=dispatcher)
        assert planner.is_fallback is False
        assert "gemini" in planner.provider_name

    # 3. OPENAI_API_KEY set -> selects OpenAI
    with patch.dict("os.environ", {"OPENAI_API_KEY": "test-openai-env-key"}, clear=True):
        planner = LLMPlanner(dispatcher=dispatcher)
        assert planner.is_fallback is False
        assert "openai" in planner.provider_name

    # 4. Explicit provider="gemini" without key raises ValueError if fallback disabled
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(ValueError, match="GEMINI_API_KEY"):
            LLMPlanner(
                dispatcher=dispatcher,
                provider="gemini",
                fallback_on_missing_key=False,
            )


def test_llm_planner_plan_and_dispatch_lifecycle(test_env):
    dispatcher = test_env["dispatcher"]
    ws: Path = test_env["ws"]
    store: AuditStore = test_env["store"]

    planner = LLMPlanner(dispatcher=dispatcher, provider="mock")

    # 1. Benign request: write file
    res1 = planner.plan_and_dispatch("Write 'Hello world' to greeting.txt")
    assert res1.response.decision == DecisionType.ALLOW
    assert res1.response.status.value == "success"
    assert (ws / "greeting.txt").exists()
    assert (ws / "greeting.txt").read_text() == "Hello world"

    # 2. Adversarial request: path traversal to /etc/passwd
    res2 = planner.plan_and_dispatch("Read the host /etc/passwd file")
    assert res2.action.tool == "read_file"
    assert res2.action.arguments["path"] == "/etc/passwd"
    assert res2.response.decision == DecisionType.DENY
    assert res2.response.status.value == "denied"
    assert res2.response.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE

    # Check that audit store recorded both events
    task1 = store.get_task(res1.response.task_id)
    assert task1 is not None
    assert task1.status == "success"

    task2 = store.get_task(res2.response.task_id)
    assert task2 is not None
    assert task2.status == "denied"
    assert task2.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE.value


def test_llm_planner_model_failure_handling(test_env):
    dispatcher = test_env["dispatcher"]
    mock_provider = MagicMock()
    mock_provider.provider_name = "flaky_model"
    mock_provider.generate_action.side_effect = RuntimeError("503 Service Unavailable")

    planner = LLMPlanner(dispatcher=dispatcher, provider=mock_provider)
    result = planner.plan_and_dispatch("Do something")

    # Untrusted model failure should fail closed (denied by policy)
    assert result.action.tool == "unknown_tool"
    assert result.response.decision == DecisionType.DENY
    assert result.response.status.value == "denied"
    assert result.response.reason == ReasonCode.UNKNOWN_TOOL
