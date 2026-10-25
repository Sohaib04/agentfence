"""Unit tests for SQLite AuditStore, payload redaction, and dispatcher audit integration."""

from pathlib import Path
from unittest.mock import patch

from app.audit.models import AuditEvent, TaskRecord
from app.audit.redaction import redact_sensitive_payload
from app.audit.store import AuditStore
from app.policy.engine import PolicyEngine
from app.policy.models import ActionRequest, ReasonCode
from app.tools.dispatcher import ToolDispatcher


def test_redact_sensitive_keys():
    payload = {
        "user": "alice",
        "api_key": "sk-1234567890",
        "nested": {
            "auth_token": "bearer-secret",
            "normal_field": "safe",
            "admin_password": "supersecretpassword",
        },
        "list_items": [{"session_token": "tok_xyz"}, "ordinary_string"],
    }
    redacted = redact_sensitive_payload(payload)
    assert redacted["user"] == "alice"
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["nested"]["auth_token"] == "[REDACTED]"
    assert redacted["nested"]["admin_password"] == "[REDACTED]"
    assert redacted["nested"]["normal_field"] == "safe"
    assert redacted["list_items"][0]["session_token"] == "[REDACTED]"
    assert redacted["list_items"][1] == "ordinary_string"


def test_redact_file_contents():
    # In write_file arguments, content must be redacted
    write_args = {"path": "secrets.txt", "content": "SUPER_SECRET_PAYLOAD_BODY"}
    redacted_write = redact_sensitive_payload(write_args, tool_name="write_file")
    assert redacted_write["path"] == "secrets.txt"
    assert "[CONTENT REDACTED" in redacted_write["content"]
    assert "SUPER_SECRET" not in redacted_write["content"]

    # In read_file result, content must be redacted
    read_res = {"path": "secrets.txt", "content": "CONFIDENTIAL_DOC_DATA", "size_bytes": 21}
    redacted_read = redact_sensitive_payload(read_res, tool_name="read_file", is_result=True)
    assert redacted_read["path"] == "secrets.txt"
    assert "[CONTENT REDACTED" in redacted_read["content"]
    assert "CONFIDENTIAL" not in redacted_read["content"]


def test_audit_store_crud_and_persistence(tmp_path: Path):
    db_file = tmp_path / "test_audit.sqlite3"
    store = AuditStore(db_path=db_file)

    task = TaskRecord(
        task_id="task-100",
        created_at="2026-10-25T01:00:00Z",
        updated_at="2026-10-25T01:00:01Z",
        tool="write_file",
        arguments={"path": "demo.txt"},
        decision="allow",
        reason="allowed",
        policy_version="1.0.0",
        status="success",
        exit_code=None,
        result={"bytes_written": 42},
        error=None,
        duration_seconds=0.012,
    )
    store.save_task(task)

    event = AuditEvent(
        timestamp="2026-10-25T01:00:01Z",
        task_id="task-100",
        event_type="action_executed",
        tool="write_file",
        decision="allow",
        reason="allowed",
        details={"status": "success"},
    )
    event_id = store.record_event(event)
    assert event_id > 0

    # Retrieve and verify
    retrieved = store.get_task("task-100")
    assert retrieved is not None
    assert retrieved.task_id == "task-100"
    assert retrieved.status == "success"
    assert retrieved.result == {"bytes_written": 42}

    # Verify audit event listing
    events = store.list_events()
    assert len(events) == 1
    assert events[0].task_id == "task-100"
    assert events[0].event_type == "action_executed"

    # Verify survival across a new connection (simulating server restart)
    new_store_instance = AuditStore(db_path=db_file)
    task_after_restart = new_store_instance.get_task("task-100")
    assert task_after_restart is not None
    assert task_after_restart.task_id == "task-100"

    events_after_restart = new_store_instance.list_events()
    assert len(events_after_restart) == 1
    assert events_after_restart[0].task_id == "task-100"


def test_dispatcher_records_allowed_and_denied_actions(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    store = AuditStore(db_path=":memory:")
    engine = PolicyEngine()
    dispatcher = ToolDispatcher(workspace_root=ws, policy_engine=engine, audit_store=store)

    # 1. Dispatch allowed write_file action
    write_res = dispatcher.dispatch(
        ActionRequest(
            tool="write_file",
            arguments={"path": "test.txt", "content": "Sensitive User Content"},
        )
    )
    assert write_res.status.value == "success"

    # Verify persisted task state
    task1 = store.get_task(write_res.task_id)
    assert task1 is not None
    assert task1.status == "success"
    assert task1.decision == "allow"
    # Ensure sensitive content is redacted in the audit record
    assert "Sensitive User Content" not in str(task1.arguments)
    assert "[CONTENT REDACTED" in str(task1.arguments)

    # 2. Dispatch denied action (traversal attack)
    deny_res = dispatcher.dispatch(
        ActionRequest(
            tool="read_file",
            arguments={"path": "../../etc/passwd"},
        )
    )
    assert deny_res.status.value == "denied"
    assert deny_res.decision.value == "deny"

    # Verify persisted denial task state
    task2 = store.get_task(deny_res.task_id)
    assert task2 is not None
    assert task2.status == "denied"
    assert task2.decision == "deny"
    assert task2.reason == ReasonCode.PATH_OUTSIDE_WORKSPACE.value

    # Verify audit events for both operations
    events = store.list_events()
    assert len(events) == 2
    event_types = [e.event_type for e in events]
    assert "action_executed" in event_types
    assert "action_denied" in event_types


def test_dispatcher_records_timed_out_command(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    store = AuditStore(db_path=":memory:")
    dispatcher = ToolDispatcher(workspace_root=ws, audit_store=store)

    with patch.object(dispatcher.executor, "run") as mock_run:
        from app.executor.models import ExecutionResult

        mock_run.return_value = ExecutionResult(
            exit_code=124,
            stdout="partial log",
            stderr="",
            timed_out=True,
            truncated=False,
            duration_seconds=5.0,
        )

        res = dispatcher.dispatch(
            ActionRequest(tool="run_command", arguments={"command": "python3", "timeout": 5})
        )
        assert res.status.value == "timed_out"

        task = store.get_task(res.task_id)
        assert task is not None
        assert task.status == "timed_out"
        assert task.exit_code == 124
        assert task.error == "Command execution timed out"
