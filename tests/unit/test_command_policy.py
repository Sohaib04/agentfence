"""Unit tests for run_command policy and argument validation."""

from pathlib import Path

import pytest

from app.policy.engine import PolicyEngine
from app.policy.loader import PolicyConfig, ToolConfig
from app.policy.models import ActionRequest, DecisionType, ReasonCode


@pytest.fixture
def command_policy_engine(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    cfg = PolicyConfig(
        policy_version="1.0.0",
        tools={
            "run_command": ToolConfig(
                enabled=True,
                allowed_commands=["python3", "pytest", "ls", "echo"],
                max_timeout_seconds=15,
                max_output_bytes=1000,
            )
        },
    )
    return {"ws": ws, "engine": PolicyEngine(config=cfg)}


def test_allowed_command_and_arguments(command_policy_engine):
    engine = command_policy_engine["engine"]
    ws = command_policy_engine["ws"]

    action = ActionRequest(
        tool="run_command",
        arguments={"command": "python3", "args": ["-c", "print('hello')"]},
    )
    decision = engine.evaluate(action, ws)
    assert decision.decision == DecisionType.ALLOW
    assert decision.reason == ReasonCode.ALLOWED
    assert decision.sanitized_arguments["command"] == "python3"
    assert decision.sanitized_arguments["args"] == ["-c", "print('hello')"]
    assert decision.sanitized_arguments["timeout"] == 15


def test_disallowed_command_denied(command_policy_engine):
    engine = command_policy_engine["engine"]
    ws = command_policy_engine["ws"]

    disallowed = ["rm", "curl", "bash", "sh", "nc", "sudo", "docker"]
    for cmd in disallowed:
        action = ActionRequest(tool="run_command", arguments={"command": cmd})
        decision = engine.evaluate(action, ws)
        assert decision.decision == DecisionType.DENY
        assert decision.reason == ReasonCode.DISALLOWED_COMMAND


def test_command_path_separators_denied(command_policy_engine):
    engine = command_policy_engine["engine"]
    ws = command_policy_engine["ws"]

    paths = ["/bin/ls", "/usr/bin/python3", "../bin/pytest"]
    for cmd in paths:
        action = ActionRequest(tool="run_command", arguments={"command": cmd})
        decision = engine.evaluate(action, ws)
        assert decision.decision == DecisionType.DENY
        assert decision.reason == ReasonCode.DISALLOWED_COMMAND


def test_raw_shell_string_arguments_rejected(command_policy_engine):
    engine = command_policy_engine["engine"]
    ws = command_policy_engine["ws"]

    # Passing a string instead of an array of arguments must be rejected
    action = ActionRequest(
        tool="run_command",
        arguments={"command": "python3", "args": "print('inject')"},
    )
    decision = engine.evaluate(action, ws)
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.INVALID_ARGUMENTS


def test_invalid_argument_elements_rejected(command_policy_engine):
    engine = command_policy_engine["engine"]
    ws = command_policy_engine["ws"]

    # Non-string element in array
    action1 = ActionRequest(
        tool="run_command",
        arguments={"command": "python3", "args": [123, "test"]},
    )
    assert engine.evaluate(action1, ws).reason == ReasonCode.INVALID_ARGUMENTS

    # Null byte in arguments
    action2 = ActionRequest(
        tool="run_command",
        arguments={"command": "python3", "args": ["safe", "null\0byte"]},
    )
    assert engine.evaluate(action2, ws).reason == ReasonCode.INVALID_ARGUMENTS


def test_missing_command_rejected(command_policy_engine):
    engine = command_policy_engine["engine"]
    ws = command_policy_engine["ws"]

    action = ActionRequest(tool="run_command", arguments={"args": ["-v"]})
    decision = engine.evaluate(action, ws)
    assert decision.decision == DecisionType.DENY
    assert decision.reason == ReasonCode.MISSING_ARGUMENT


def test_timeout_bounds_enforced(command_policy_engine):
    engine = command_policy_engine["engine"]
    ws = command_policy_engine["ws"]

    # Valid custom timeout within limit
    action1 = ActionRequest(
        tool="run_command",
        arguments={"command": "pytest", "timeout": 5},
    )
    assert engine.evaluate(action1, ws).sanitized_arguments["timeout"] == 5

    # Timeout exceeding policy maximum (15s) is clamped
    action2 = ActionRequest(
        tool="run_command",
        arguments={"command": "pytest", "timeout": 100},
    )
    assert engine.evaluate(action2, ws).sanitized_arguments["timeout"] == 15

    # Non-positive or invalid timeout rejected
    action3 = ActionRequest(
        tool="run_command",
        arguments={"command": "pytest", "timeout": -5},
    )
    assert engine.evaluate(action3, ws).reason == ReasonCode.INVALID_ARGUMENTS
