"""Unit tests for ToolDispatcher single choke point."""

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from app.api.schemas import ActionStatus
from app.audit.store import AuditStore
from app.policy.engine import PolicyEngine
from app.policy.models import ActionRequest, DecisionType, ReasonCode
from app.tools.dispatcher import ToolDispatcher


@pytest.fixture
def dispatcher_env(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    engine = PolicyEngine()
    dispatcher = ToolDispatcher(workspace_root=ws, policy_engine=engine)
    return {"ws": ws, "engine": engine, "dispatcher": dispatcher}


def test_dispatcher_denial_blocks_execution(dispatcher_env):
    dispatcher = dispatcher_env["dispatcher"]

    # Traversal action
    action = ActionRequest(
        tool="read_file",
        arguments={"path": "../../etc/passwd"},
    )

    with patch("app.tools.dispatcher.read_file") as mock_read:
        response = dispatcher.dispatch(action)

        # Policy denied -> tool must never be called
        mock_read.assert_not_called()
        assert response.decision == DecisionType.DENY
        assert response.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE
        assert response.status == ActionStatus.DENIED
        assert response.result is None


def test_dispatcher_allowed_and_succeeded(dispatcher_env):
    dispatcher = dispatcher_env["dispatcher"]

    # Write action
    action = ActionRequest(
        tool="write_file",
        arguments={"path": "test.txt", "content": "hello secure gateway"},
    )
    res = dispatcher.dispatch(action)
    assert res.decision == DecisionType.ALLOW
    assert res.status == ActionStatus.SUCCESS
    assert res.reason == ReasonCode.ALLOWED
    assert res.result is not None
    assert res.result["bytes_written"] > 0

    # Read action
    read_action = ActionRequest(tool="read_file", arguments={"path": "test.txt"})
    read_res = dispatcher.dispatch(read_action)
    assert read_res.decision == DecisionType.ALLOW
    assert read_res.status == ActionStatus.SUCCESS
    assert read_res.result["content"] == "hello secure gateway"


def test_dispatcher_allowed_but_failed(dispatcher_env):
    dispatcher = dispatcher_env["dispatcher"]
    ws = dispatcher_env["ws"]

    # Policy allows valid relative path, but file does not exist on disk
    action = ActionRequest(tool="read_file", arguments={"path": "nonexistent.txt"})
    res = dispatcher.dispatch(action)

    assert res.decision == DecisionType.ALLOW
    assert res.status == ActionStatus.ERROR
    assert res.error is not None
    assert "File not found" in res.error
    # Must not leak the full host workspace path
    assert str(ws) not in res.error


def test_dispatcher_run_command_allowed_and_succeeded(dispatcher_env):
    dispatcher = dispatcher_env["dispatcher"]

    # Mock successful execution
    with patch.object(dispatcher.executor, "run") as mock_run:
        from app.executor.models import ExecutionResult

        mock_run.return_value = ExecutionResult(
            exit_code=0,
            stdout="pytest passed\n",
            stderr="",
            timed_out=False,
            truncated=False,
            duration_seconds=0.12,
        )

        action = ActionRequest(tool="run_command", arguments={"command": "pytest", "args": ["-v"]})
        res = dispatcher.dispatch(action)

        assert res.decision == DecisionType.ALLOW
        assert res.status == ActionStatus.SUCCESS
        assert res.result["exit_code"] == 0
        assert res.result["stdout"] == "pytest passed\n"
        assert res.error is None
        mock_run.assert_called_once()


def test_dispatcher_run_command_allowed_but_failed_exit_code(dispatcher_env):
    dispatcher = dispatcher_env["dispatcher"]

    with patch.object(dispatcher.executor, "run") as mock_run:
        from app.executor.models import ExecutionResult

        mock_run.return_value = ExecutionResult(
            exit_code=1,
            stdout="test failure\n",
            stderr="AssertionError",
            timed_out=False,
            truncated=False,
            duration_seconds=0.2,
        )

        action = ActionRequest(tool="run_command", arguments={"command": "pytest"})
        res = dispatcher.dispatch(action)

        assert res.decision == DecisionType.ALLOW
        assert res.status == ActionStatus.ERROR
        assert res.result["exit_code"] == 1
        assert "Command failed with exit code 1" in res.error


def test_dispatcher_run_command_timed_out(dispatcher_env):
    dispatcher = dispatcher_env["dispatcher"]

    with patch.object(dispatcher.executor, "run") as mock_run:
        from app.executor.models import ExecutionResult

        mock_run.return_value = ExecutionResult(
            exit_code=124,
            stdout="partial output",
            stderr="",
            timed_out=True,
            truncated=False,
            duration_seconds=10.0,
        )

        action = ActionRequest(tool="run_command", arguments={"command": "python3", "timeout": 10})
        res = dispatcher.dispatch(action)

        assert res.decision == DecisionType.ALLOW
        assert res.status == ActionStatus.TIMED_OUT
        assert res.result["timed_out"] is True
        assert res.error == "Command execution timed out"


def test_dispatcher_run_command_denied_never_reaches_executor(dispatcher_env):
    dispatcher = dispatcher_env["dispatcher"]

    with patch.object(dispatcher.executor, "run") as mock_run:
        action = ActionRequest(
            tool="run_command", arguments={"command": "rm", "args": ["-rf", "/"]}
        )
        res = dispatcher.dispatch(action)

        assert res.decision == DecisionType.DENY
        assert res.status == ActionStatus.DENIED
        assert res.reason == ReasonCode.DISALLOWED_COMMAND
        # Executor must never be called!
        mock_run.assert_not_called()


def test_dispatcher_async_dispatch_and_execution(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    store = AuditStore(db_path=":memory:")
    dispatcher = ToolDispatcher(workspace_root=ws, audit_store=store)

    action = ActionRequest(
        tool="write_file",
        arguments={"path": "async_unit.txt", "content": "unit async content"},
        async_exec=True,
    )
    res = dispatcher.dispatch(action)

    assert res.decision == DecisionType.ALLOW
    assert res.status == ActionStatus.PENDING
    task_id = res.task_id

    # Wait for background worker execution
    final_task = None
    for _ in range(40):
        task = store.get_task(task_id)
        if task and task.status == "success":
            final_task = task
            break
        time.sleep(0.05)

    assert final_task is not None
    assert final_task.status == "success"
    assert (ws / "async_unit.txt").read_text() == "unit async content"


def test_dispatcher_async_denial_blocks_immediately(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    store = AuditStore(db_path=":memory:")
    dispatcher = ToolDispatcher(workspace_root=ws, audit_store=store)

    action = ActionRequest(
        tool="read_file",
        arguments={"path": "../../etc/passwd"},
        async_exec=True,
    )
    res = dispatcher.dispatch(action)

    assert res.decision == DecisionType.DENY
    assert res.status == ActionStatus.DENIED
    assert res.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE

    # Ensure recorded in store as denied
    task = store.get_task(res.task_id)
    assert task is not None
    assert task.status == "denied"
    assert task.decision == "deny"


def test_dispatcher_run_command_passes_sandbox_runtime(tmp_path: Path):
    from app.executor.models import ExecutionResult
    from app.policy.loader import PolicyConfig, ToolConfig

    ws = tmp_path / "workspace"
    ws.mkdir()

    cfg = PolicyConfig(
        policy_version="1.0.0",
        tools={
            "run_command": ToolConfig(
                enabled=True,
                allowed_commands=["python3"],
                sandbox_runtime="runsc",
            ),
        },
    )
    engine = PolicyEngine(config=cfg)
    dispatcher = ToolDispatcher(workspace_root=ws, policy_engine=engine)

    with patch.object(dispatcher.executor, "run") as mock_run:
        mock_run.return_value = ExecutionResult(
            exit_code=0,
            stdout="gvisor ok",
            stderr="",
            extra={"runtime": "runsc"},
        )
        action = ActionRequest(
            tool="run_command",
            arguments={"command": "python3", "args": ["-c", "print('ok')"]},
        )
        res = dispatcher.dispatch(action)

        assert res.decision == DecisionType.ALLOW
        assert res.status == ActionStatus.SUCCESS
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs.get("runtime") == "runsc"
        assert kwargs["limits"].runtime == "runsc"
