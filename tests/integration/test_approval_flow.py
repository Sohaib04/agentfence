"""Integration tests for fine-grained human approval flow on destructive tools."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.auth import DEFAULT_DEV_TOKEN
from app.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    sym = ws / "sym_out"
    sym.symlink_to(outside)

    db_path = tmp_path / "approval_audit.sqlite3"
    app = create_app(workspace_root=ws, db_path=db_path)
    with TestClient(app) as test_client:
        yield test_client, ws


def test_delete_file_pauses_in_pending_approval(client):
    test_client, ws = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # 1. Create a target file
    file_path = ws / "document.txt"
    file_path.write_text("critical document contents")
    assert file_path.exists()

    # 2. Submit delete_file action
    payload = {
        "tool": "delete_file",
        "arguments": {"path": "document.txt"},
    }
    res = test_client.post("/v1/actions", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["decision"] == "pending_approval"
    assert data["status"] == "pending_approval"
    assert data["reason"] == "requires_approval"
    task_id = data["task_id"]

    # 3. File MUST NOT be deleted
    assert file_path.exists()
    assert file_path.read_text() == "critical document contents"

    # 4. Check persisted task state
    task_res = test_client.get(f"/v1/tasks/{task_id}", headers=headers)
    assert task_res.status_code == 200
    task_data = task_res.json()
    assert task_data["status"] == "pending_approval"
    assert task_data["decision"] == "pending_approval"
    assert task_data["tool"] == "delete_file"

    # 5. Check audit events: approval_requested recorded
    audit_res = test_client.get("/v1/audit", headers=headers)
    assert audit_res.status_code == 200
    events = audit_res.json()["events"]
    req_event = next(
        (e for e in events if e["task_id"] == task_id and e["event_type"] == "approval_requested"),
        None,
    )
    assert req_event is not None
    assert req_event["decision"] == "pending_approval"


def test_approve_task_executes_file_deletion(client):
    test_client, ws = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # 1. Create a file to delete
    target = ws / "obsolete.txt"
    target.write_text("delete me")
    assert target.exists()

    # 2. Submit delete_file
    res = test_client.post(
        "/v1/actions",
        json={"tool": "delete_file", "arguments": {"path": "obsolete.txt"}},
        headers=headers,
    )
    assert res.status_code == 200
    task_id = res.json()["task_id"]
    assert target.exists()  # Not yet deleted

    # 3. Approve the task
    approve_res = test_client.post(f"/v1/tasks/{task_id}/approve", headers=headers)
    assert approve_res.status_code == 200
    approve_data = approve_res.json()
    assert approve_data["decision"] == "allow"
    assert approve_data["status"] == "success"
    assert approve_data["reason"] == "allowed"
    assert approve_data["result"] == {"path": "obsolete.txt", "deleted": True}

    # 4. File is now deleted
    assert not target.exists()

    # 5. Persisted task state is success
    task_res = test_client.get(f"/v1/tasks/{task_id}", headers=headers)
    assert task_res.status_code == 200
    assert task_res.json()["status"] == "success"

    # 6. Audit events: approval and execution recorded
    audit_res = test_client.get("/v1/audit", headers=headers)
    events = audit_res.json()["events"]
    task_events = [e for e in events if e["task_id"] == task_id]
    event_types = [e["event_type"] for e in task_events]
    assert "approval_requested" in event_types
    assert "action_approved" in event_types
    assert "action_executed" in event_types


def test_reject_task_prevents_file_deletion(client):
    test_client, ws = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # 1. Create a sensitive file
    target = ws / "do_not_delete.txt"
    target.write_text("protected content")
    assert target.exists()

    # 2. Submit delete_file
    res = test_client.post(
        "/v1/actions",
        json={"tool": "delete_file", "arguments": {"path": "do_not_delete.txt"}},
        headers=headers,
    )
    assert res.status_code == 200
    task_id = res.json()["task_id"]

    # 3. Reject the task
    reject_res = test_client.post(f"/v1/tasks/{task_id}/reject", headers=headers)
    assert reject_res.status_code == 200
    reject_data = reject_res.json()
    assert reject_data["decision"] == "deny"
    assert reject_data["status"] == "denied"
    assert reject_data["reason"] == "approval_rejected"
    assert "rejected by human operator" in reject_data["error"]

    # 4. File is preserved!
    assert target.exists()
    assert target.read_text() == "protected content"

    # 5. Persisted task state is denied
    task_res = test_client.get(f"/v1/tasks/{task_id}", headers=headers)
    assert task_res.status_code == 200
    task_data = task_res.json()
    assert task_data["status"] == "denied"
    assert task_data["decision"] == "deny"

    # 6. Audit events: rejection recorded
    audit_res = test_client.get("/v1/audit", headers=headers)
    events = audit_res.json()["events"]
    task_events = [e for e in events if e["task_id"] == task_id]
    event_types = [e["event_type"] for e in task_events]
    assert "approval_requested" in event_types
    assert "action_rejected" in event_types


def test_approval_endpoints_require_auth(client):
    test_client, _ = client

    # Without token
    res1 = test_client.post("/v1/tasks/any-task-id/approve")
    assert res1.status_code == 401

    res2 = test_client.post("/v1/tasks/any-task-id/reject")
    assert res2.status_code == 401

    # With invalid token
    bad_headers = {"Authorization": "Bearer bad-token"}
    res3 = test_client.post("/v1/tasks/any-task-id/approve", headers=bad_headers)
    assert res3.status_code == 401


def test_approve_unknown_task_404(client):
    test_client, _ = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    res = test_client.post("/v1/tasks/nonexistent-uuid-9999/approve", headers=headers)
    assert res.status_code == 404
    assert "Task not found" in res.json()["detail"]


def test_reject_unknown_task_404(client):
    test_client, _ = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    res = test_client.post("/v1/tasks/nonexistent-uuid-9999/reject", headers=headers)
    assert res.status_code == 404
    assert "Task not found" in res.json()["detail"]


def test_approve_already_approved_or_executed_task_400(client):
    test_client, ws = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    target = ws / "item.txt"
    target.write_text("content")

    res = test_client.post(
        "/v1/actions",
        json={"tool": "delete_file", "arguments": {"path": "item.txt"}},
        headers=headers,
    )
    task_id = res.json()["task_id"]

    # First approval succeeds
    res1 = test_client.post(f"/v1/tasks/{task_id}/approve", headers=headers)
    assert res1.status_code == 200

    # Second approval fails because status is already success
    res2 = test_client.post(f"/v1/tasks/{task_id}/approve", headers=headers)
    assert res2.status_code == 400
    assert "not pending approval" in res2.json()["detail"]


def test_delete_file_traversal_attack_denied_never_pending(client):
    test_client, _ = client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # Attempt path traversal on delete_file
    res = test_client.post(
        "/v1/actions",
        json={"tool": "delete_file", "arguments": {"path": "../../etc/shadow"}},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "deny"
    assert data["status"] == "denied"
    assert data["reason"] == "path_outside_workspace"

    # Persisted task state is denied, never pending_approval
    task_id = data["task_id"]
    task_res = test_client.get(f"/v1/tasks/{task_id}", headers=headers)
    assert task_res.status_code == 200
    assert task_res.json()["status"] == "denied"

    # Audit events: action_denied, no approval_requested
    audit_res = test_client.get("/v1/audit", headers=headers)
    events = audit_res.json()["events"]
    task_events = [e for e in events if e["task_id"] == task_id]
    assert len(task_events) == 1
    assert task_events[0]["event_type"] == "action_denied"
