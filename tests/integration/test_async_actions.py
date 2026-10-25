"""Integration tests for asynchronous background execution, polling, and lifecycle transitions."""

import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.api.auth import DEFAULT_DEV_TOKEN
from app.executor.models import ExecutionResult
from app.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    db_path = tmp_path / "test_async_audit.sqlite3"
    app = create_app(workspace_root=ws, db_path=db_path)
    with TestClient(app) as test_client:
        yield test_client, ws


def test_async_command_accepted_and_lifecycle(client):
    test_client, _ = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    with patch.object(test_client.app.state.dispatcher.executor, "run") as mock_run:
        mock_run.return_value = ExecutionResult(
            exit_code=0,
            stdout="async command output\n",
            stderr="",
            timed_out=False,
            truncated=False,
            duration_seconds=0.08,
        )

        # 1. Submit action with async: true
        payload = {
            "tool": "run_command",
            "arguments": {"command": "echo", "args": ["async test"]},
            "async": True,
        }
        res = test_client.post("/v1/actions", json=payload, headers=headers)
        assert res.status_code == 202
        accepted_data = res.json()
        assert accepted_data["decision"] == "allow"
        assert accepted_data["status"] == "pending"
        assert accepted_data["reason"] == "allowed"
        task_id = accepted_data["task_id"]

        # 2. Poll GET /v1/tasks/{task_id} until completion
        final_task = None
        for _ in range(50):
            task_res = test_client.get(f"/v1/tasks/{task_id}", headers=headers)
            assert task_res.status_code == 200
            task_data = task_res.json()
            if task_data["status"] in ("success", "error", "timed_out"):
                final_task = task_data
                break
            time.sleep(0.05)

        assert final_task is not None
        assert final_task["status"] == "success"
        assert final_task["exit_code"] == 0
        assert final_task["result"]["stdout"] == "async command output\n"
        assert final_task["duration_seconds"] is not None

        # 3. Verify audit events: start and completion recorded
        audit_res = test_client.get("/v1/audit", headers=headers)
        assert audit_res.status_code == 200
        events = audit_res.json()["events"]
        task_events = [e for e in events if e["task_id"] == task_id]

        start_event = next((e for e in task_events if e["event_type"] == "action_started"), None)
        assert start_event is not None
        assert start_event["details"]["async"] is True
        assert start_event["details"]["status"] == "pending"

        exec_event = next((e for e in task_events if e["event_type"] == "action_executed"), None)
        assert exec_event is not None
        assert exec_event["details"]["status"] == "success"
        assert exec_event["details"]["async"] is True


def test_async_query_parameter_mode(client):
    test_client, ws = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    payload = {
        "tool": "write_file",
        "arguments": {"path": "async_file.txt", "content": "Async Background Write"},
    }
    # Pass async=true via query parameter
    res = test_client.post("/v1/actions?async=true", json=payload, headers=headers)
    assert res.status_code == 202
    task_id = res.json()["task_id"]

    # Poll for completion
    final_task = None
    for _ in range(50):
        task_res = test_client.get(f"/v1/tasks/{task_id}", headers=headers)
        assert task_res.status_code == 200
        task_data = task_res.json()
        if task_data["status"] == "success":
            final_task = task_data
            break
        time.sleep(0.05)

    assert final_task is not None
    assert final_task["status"] == "success"
    assert (ws / "async_file.txt").exists()
    assert (ws / "async_file.txt").read_text() == "Async Background Write"
    # Ensure sensitive payload was redacted in persisted record
    assert "Async Background Write" not in str(final_task["arguments"])
    assert "[CONTENT REDACTED" in str(final_task["arguments"])


def test_async_command_timeout_lifecycle(client):
    test_client, _ = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    with patch.object(test_client.app.state.dispatcher.executor, "run") as mock_run:
        mock_run.return_value = ExecutionResult(
            exit_code=124,
            stdout="partial stdout",
            stderr="",
            timed_out=True,
            truncated=False,
            duration_seconds=2.0,
        )

        payload = {
            "tool": "run_command",
            "arguments": {"command": "python3", "timeout": 2},
            "async": True,
        }
        res = test_client.post("/v1/actions", json=payload, headers=headers)
        assert res.status_code == 202
        task_id = res.json()["task_id"]

        final_task = None
        for _ in range(50):
            task_res = test_client.get(f"/v1/tasks/{task_id}", headers=headers)
            assert task_res.status_code == 200
            task_data = task_res.json()
            if task_data["status"] == "timed_out":
                final_task = task_data
                break
            time.sleep(0.05)

        assert final_task is not None
        assert final_task["status"] == "timed_out"
        assert final_task["exit_code"] == 124
        assert final_task["error"] == "Command execution timed out"


def test_async_command_error_lifecycle(client):
    test_client, _ = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    with patch.object(test_client.app.state.dispatcher.executor, "run") as mock_run:
        mock_run.return_value = ExecutionResult(
            exit_code=1,
            stdout="",
            stderr="syntax error",
            timed_out=False,
            truncated=False,
            duration_seconds=0.1,
        )

        payload = {
            "tool": "run_command",
            "arguments": {"command": "python3", "args": ["script.py"]},
            "async": True,
        }
        res = test_client.post("/v1/actions", json=payload, headers=headers)
        assert res.status_code == 202
        task_id = res.json()["task_id"]

        final_task = None
        for _ in range(50):
            task_res = test_client.get(f"/v1/tasks/{task_id}", headers=headers)
            assert task_res.status_code == 200
            task_data = task_res.json()
            if task_data["status"] == "error":
                final_task = task_data
                break
            time.sleep(0.05)

        assert final_task is not None
        assert final_task["status"] == "error"
        assert final_task["exit_code"] == 1
        assert "exit code 1" in final_task["error"]


def test_async_forbidden_action_denied_immediately(client):
    test_client, _ = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # Forbidden action: host file traversal
    payload = {
        "tool": "read_file",
        "arguments": {"path": "../../etc/shadow"},
        "async": True,
    }
    res = test_client.post("/v1/actions", json=payload, headers=headers)
    # Denied by policy: must return 200 with denial, not 202 accepted
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "deny"
    assert data["status"] == "denied"
    assert data["reason"] == "path_outside_workspace"
    task_id = data["task_id"]

    # Verify task state in SQLite
    task_res = test_client.get(f"/v1/tasks/{task_id}", headers=headers)
    assert task_res.status_code == 200
    task_data = task_res.json()
    assert task_data["status"] == "denied"
    assert task_data["decision"] == "deny"

    # Verify audit event: action_denied recorded, NO action_started event
    audit_res = test_client.get("/v1/audit", headers=headers)
    events = audit_res.json()["events"]
    task_events = [e for e in events if e["task_id"] == task_id]
    assert len(task_events) == 1
    assert task_events[0]["event_type"] == "action_denied"


def test_bounded_concurrency_execution(client):
    test_client, ws = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    task_ids = []
    # Submit 6 concurrent background tasks
    for i in range(6):
        res = test_client.post(
            "/v1/actions",
            json={
                "tool": "write_file",
                "arguments": {"path": f"bulk_{i}.txt", "content": f"data {i}"},
                "async": True,
            },
            headers=headers,
        )
        assert res.status_code == 202
        task_ids.append(res.json()["task_id"])

    # Wait for all to complete
    completed = set()
    for _ in range(60):
        for tid in task_ids:
            if tid not in completed:
                t_res = test_client.get(f"/v1/tasks/{tid}", headers=headers)
                if t_res.json()["status"] == "success":
                    completed.add(tid)
        if len(completed) == len(task_ids):
            break
        time.sleep(0.05)

    assert len(completed) == 6
    for i in range(6):
        assert (ws / f"bulk_{i}.txt").read_text() == f"data {i}"
