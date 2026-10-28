"""Unit tests for deterministic PolicyEngine without FastAPI or LLMs."""

from pathlib import Path

import pytest

from app.policy.engine import PolicyEngine
from app.policy.loader import PolicyConfig, ToolConfig
from app.policy.models import ActionRequest, DecisionType, ReasonCode


@pytest.fixture
def policy_setup(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    cfg = PolicyConfig(
        policy_version="1.0.0",
        tools={
            "list_files": ToolConfig(enabled=True),
            "read_file": ToolConfig(enabled=True, max_size_bytes=100),
            "write_file": ToolConfig(enabled=True, max_size_bytes=100),
            "delete_file": ToolConfig(enabled=False),
            "run_command": ToolConfig(enabled=False),
        },
    )
    engine = PolicyEngine(config=cfg)
    return {"ws": ws, "outside": outside, "engine": engine}


def test_unknown_tool_denied(policy_setup):
    engine = policy_setup["engine"]
    ws = policy_setup["ws"]

    action = ActionRequest(tool="arbitrary_tool", arguments={})
    decision = engine.evaluate(action, ws)

    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.UNKNOWN_TOOL
    assert decision.policy_version == "1.0.0"


def test_disabled_tool_denied(policy_setup):
    engine = policy_setup["engine"]
    ws = policy_setup["ws"]

    for tool_name in ["delete_file", "run_command"]:
        action = ActionRequest(tool=tool_name, arguments={})
        decision = engine.evaluate(action, ws)
        assert decision.decision == DecisionType.DENY
        assert decision.reason == ReasonCode.TOOL_DISABLED


def test_list_files_allowed_and_traversal_denied(policy_setup):
    engine = policy_setup["engine"]
    ws = policy_setup["ws"]

    # Valid relative path
    decision = engine.evaluate(ActionRequest(tool="list_files", arguments={"path": ""}), ws)
    assert decision.decision == DecisionType.ALLOW
    assert decision.reason == ReasonCode.ALLOWED

    # Path traversal attempt
    decision = engine.evaluate(ActionRequest(tool="list_files", arguments={"path": "../"}), ws)
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE


def test_read_file_argument_checks(policy_setup):
    engine = policy_setup["engine"]
    ws = policy_setup["ws"]

    # Missing path
    decision = engine.evaluate(ActionRequest(tool="read_file", arguments={}), ws)
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.MISSING_ARGUMENT

    # Non-string path
    decision = engine.evaluate(ActionRequest(tool="read_file", arguments={"path": 123}), ws)
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.INVALID_ARGUMENTS

    # Path traversal
    action = ActionRequest(tool="read_file", arguments={"path": "../../etc/passwd"})
    decision = engine.evaluate(action, ws)
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE


def test_read_file_size_limit(policy_setup):
    engine = policy_setup["engine"]
    ws = policy_setup["ws"]

    # Create file under 100 bytes limit
    small_file = ws / "small.txt"
    small_file.write_text("a" * 50)
    decision = engine.evaluate(ActionRequest(tool="read_file", arguments={"path": "small.txt"}), ws)
    assert decision.decision == DecisionType.ALLOW

    # Create file exceeding 100 bytes limit
    large_file = ws / "large.txt"
    large_file.write_text("a" * 150)
    decision = engine.evaluate(ActionRequest(tool="read_file", arguments={"path": "large.txt"}), ws)
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.FILE_TOO_LARGE


def test_write_file_argument_and_size_checks(policy_setup):
    engine = policy_setup["engine"]
    ws = policy_setup["ws"]

    # Missing arguments
    decision = engine.evaluate(ActionRequest(tool="write_file", arguments={"path": "file.txt"}), ws)
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.MISSING_ARGUMENT

    decision = engine.evaluate(ActionRequest(tool="write_file", arguments={"content": "data"}), ws)
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.MISSING_ARGUMENT

    # Content exceeds max size limit
    decision = engine.evaluate(
        ActionRequest(tool="write_file", arguments={"path": "big.txt", "content": "x" * 105}),
        ws,
    )
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.FILE_TOO_LARGE

    # Valid write action
    decision = engine.evaluate(
        ActionRequest(tool="write_file", arguments={"path": "ok.txt", "content": "hello"}),
        ws,
    )
    assert decision.decision == DecisionType.ALLOW
    assert decision.reason == ReasonCode.ALLOWED


def test_symlink_escape_denied(policy_setup):
    engine = policy_setup["engine"]
    ws = policy_setup["ws"]
    outside = policy_setup["outside"]

    sym = ws / "sym_out"
    sym.symlink_to(outside)

    decision = engine.evaluate(
        ActionRequest(tool="read_file", arguments={"path": "sym_out/secret.txt"}),
        ws,
    )
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.SYMLINK_ESCAPE


def test_fails_closed_on_malformed_input(policy_setup):
    engine = policy_setup["engine"]
    ws = policy_setup["ws"]

    # Completely invalid object passed to evaluate
    decision = engine.evaluate("not an action object", ws)  # type: ignore
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.INVALID_ARGUMENTS


def test_delete_file_approval_policy(policy_setup):
    from app.policy.loader import PolicyConfig, ToolConfig

    ws = policy_setup["ws"]
    outside = policy_setup["outside"]

    # Configure policy requiring approval for delete_file
    cfg = PolicyConfig(
        policy_version="1.0.0",
        tools={
            "delete_file": ToolConfig(enabled=True, approval_required=True),
        },
    )
    engine = PolicyEngine(config=cfg)

    # 1. Normal safe path -> PENDING_APPROVAL
    decision = engine.evaluate(
        ActionRequest(tool="delete_file", arguments={"path": "safe.txt"}), ws
    )
    assert decision.decision == DecisionType.PENDING_APPROVAL
    assert decision.reason == ReasonCode.REQUIRES_APPROVAL
    assert decision.sanitized_arguments == {"path": "safe.txt"}

    # 2. Traversal attack -> DENIED immediately, never reaches approval
    decision = engine.evaluate(
        ActionRequest(tool="delete_file", arguments={"path": "../../etc/shadow"}), ws
    )
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE

    # 3. Symlink escape -> DENIED immediately, never reaches approval
    sym = ws / "sym_out"
    if not sym.exists():
        sym.symlink_to(outside)
    decision = engine.evaluate(
        ActionRequest(tool="delete_file", arguments={"path": "sym_out/file.txt"}), ws
    )
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.SYMLINK_ESCAPE

    # 4. Bypass approval (approved task re-evaluation) -> ALLOW
    decision = engine.evaluate(
        ActionRequest(tool="delete_file", arguments={"path": "safe.txt"}),
        ws,
        bypass_approval=True,
    )
    assert decision.decision == DecisionType.ALLOW
    assert decision.reason == ReasonCode.ALLOWED
    assert decision.sanitized_arguments == {"path": "safe.txt"}


def test_run_command_sandbox_runtime_propagation(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()

    cfg = PolicyConfig(
        policy_version="1.0.0",
        tools={
            "run_command": ToolConfig(
                enabled=True,
                allowed_commands=["python3"],
                sandbox_image="agentfence-sandbox:0.1.0",
                sandbox_runtime="runsc",
            ),
        },
    )
    engine = PolicyEngine(config=cfg)

    action = ActionRequest(
        tool="run_command",
        arguments={"command": "python3", "args": ["-c", "print(1)"]},
    )
    decision = engine.evaluate(action, ws)

    assert decision.decision == DecisionType.ALLOW
    assert decision.reason == ReasonCode.ALLOWED
    assert decision.sanitized_arguments["sandbox_runtime"] == "runsc"
    assert decision.sanitized_arguments["command"] == "python3"
