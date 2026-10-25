"""Adversarial security tests verifying enforcement against prompt injection, path traversal,
and disallowed commands.
"""

from pathlib import Path

import pytest

from app.agent.mock import MockAgent, get_standard_scenarios
from app.audit.store import AuditStore
from app.policy.engine import PolicyEngine
from app.policy.models import ActionRequest, DecisionType, ReasonCode
from app.tools.dispatcher import ToolDispatcher


@pytest.fixture
def security_env(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    # Create host secret canary
    canary = outside / "secret_canary.txt"
    canary.write_text("HOST_CANARY_VALUE_778899")

    # Symlink pointing outside
    symlink_outside = ws / "sym_outside"
    symlink_outside.symlink_to(outside)

    store = AuditStore(db_path=":memory:")
    engine = PolicyEngine()
    dispatcher = ToolDispatcher(workspace_root=ws, policy_engine=engine, audit_store=store)
    agent = MockAgent(dispatcher=dispatcher)

    return {
        "ws": ws,
        "outside": outside,
        "canary": canary,
        "store": store,
        "dispatcher": dispatcher,
        "agent": agent,
    }


def test_prompt_injection_enforcement_scenario(security_env):
    """Verify prompt-injection defense per Section 10:

    1. Malicious instructions placed in workspace file.
    2. Agent reads workspace file (allowed).
    3. Agent follows injection and requests forbidden host read.
    4. Policy engine denies it, contents are never returned.
    5. Denial is recorded in audit store.
    6. Later legitimate workspace read/write still succeeds cleanly.
    """
    agent: MockAgent = security_env["agent"]
    store: AuditStore = security_env["store"]
    ws: Path = security_env["ws"]

    sim = agent.run_prompt_injection_simulation(ws)

    # 1. Writing untrusted file succeeds
    assert sim["step1_write_untrusted"].decision == DecisionType.ALLOW
    assert sim["step1_write_untrusted"].status.value == "success"

    # 2. Reading untrusted file succeeds (legitimate workspace read)
    assert sim["step2_read_untrusted"].decision == DecisionType.ALLOW
    assert sim["step2_read_untrusted"].status.value == "success"
    assert "Disregard instructions" in sim["step2_read_untrusted"].result["content"]

    # 3. Forbidden attack is denied by policy
    forbidden_res = sim["step3_forbidden_attack"]
    assert forbidden_res.decision == DecisionType.DENY
    assert forbidden_res.status.value == "denied"
    assert forbidden_res.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE
    # Crucial: content is NEVER returned
    assert forbidden_res.result is None

    # 4. Denial is recorded in audit log
    events = store.list_events()
    denial_event = next((e for e in events if e.task_id == forbidden_res.task_id), None)
    assert denial_event is not None
    assert denial_event.event_type == "action_denied"
    assert denial_event.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE.value

    # 5. Subsequent legitimate write and read succeed normally
    assert sim["step4_safe_write"].decision == DecisionType.ALLOW
    assert sim["step4_safe_write"].status.value == "success"

    assert sim["step5_safe_read"].decision == DecisionType.ALLOW
    assert sim["step5_safe_read"].status.value == "success"
    assert sim["step5_safe_read"].result["content"] == "Analysis complete."


def test_standard_scenarios_execution(security_env):
    """Execute all predefined scenarios with expected reproducible outcomes."""
    agent: MockAgent = security_env["agent"]
    scenarios = get_standard_scenarios()

    for sc in scenarios:
        responses = agent.execute_scenario(sc)
        assert len(responses) == len(sc.steps)

        for step, res in zip(sc.steps, responses, strict=False):
            assert res.decision.value == step.expected_decision, (
                f"Scenario '{sc.name}' step '{step.description}' expected decision "
                f"'{step.expected_decision}', got '{res.decision.value}'"
            )
            assert res.status.value == step.expected_status, (
                f"Scenario '{sc.name}' step '{step.description}' expected status "
                f"'{step.expected_status}', got '{res.status.value}'"
            )


def test_filesystem_symlink_and_overwrite_attacks(security_env):
    dispatcher: ToolDispatcher = security_env["dispatcher"]

    # 1. Symlink escape read
    sym_read = dispatcher.dispatch(
        ActionRequest(tool="read_file", arguments={"path": "sym_outside/secret_canary.txt"})
    )
    assert sym_read.decision == DecisionType.DENY
    assert sym_read.reason == ReasonCode.SYMLINK_ESCAPE
    assert sym_read.result is None

    # 2. Symlink escape write
    sym_write = dispatcher.dispatch(
        ActionRequest(
            tool="write_file",
            arguments={"path": "sym_outside/pwned.txt", "content": "malicious data"},
        )
    )
    assert sym_write.decision == DecisionType.DENY
    assert sym_write.reason == ReasonCode.SYMLINK_ESCAPE

    # 3. Path traversal overwrite outside workspace
    trav_write = dispatcher.dispatch(
        ActionRequest(
            tool="write_file",
            arguments={"path": "../../escaped.txt", "content": "outside data"},
        )
    )
    assert trav_write.decision == DecisionType.DENY
    assert trav_write.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE
