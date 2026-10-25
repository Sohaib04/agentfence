"""Integration tests for task state persistence, audit retrieval endpoints,
and server restart survival.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.auth import DEFAULT_DEV_TOKEN
from app.main import create_app


@pytest.fixture
def audit_client(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    db_path = tmp_path / "audit.sqlite3"
    app = create_app(workspace_root=ws, db_path=db_path)
    return TestClient(app), ws, db_path


def test_task_retrieval_and_audit_endpoints(audit_client):
    client, ws, db_path = audit_client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # 1. Post a legitimate action
    action_payload = {
        "tool": "write_file",
        "arguments": {"path": "hello.txt", "content": "Welcome to AgentFence"},
    }
    action_res = client.post("/v1/actions", json=action_payload, headers=headers)
    assert action_res.status_code == 200
    task_id = action_res.json()["task_id"]

    # 2. Retrieve task via GET /v1/tasks/{task_id}
    task_res = client.get(f"/v1/tasks/{task_id}", headers=headers)
    assert task_res.status_code == 200
    task_data = task_res.json()
    assert task_data["task_id"] == task_id
    assert task_data["tool"] == "write_file"
    assert task_data["decision"] == "allow"
    assert task_data["status"] == "success"
    assert task_data["result"]["bytes_written"] > 0
    # Ensure raw content was redacted
    assert "Welcome to AgentFence" not in str(task_data["arguments"])
    assert "[CONTENT REDACTED" in str(task_data["arguments"])

    # 3. Retrieve audit events via GET /v1/audit
    audit_res = client.get("/v1/audit", headers=headers)
    assert audit_res.status_code == 200
    audit_data = audit_res.json()
    assert audit_data["count"] >= 1
    events = audit_data["events"]
    matching_event = next((e for e in events if e["task_id"] == task_id), None)
    assert matching_event is not None
    assert matching_event["event_type"] == "action_executed"
    assert matching_event["decision"] == "allow"


def test_unknown_task_id_returns_404(audit_client):
    client, _, _ = audit_client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    res = client.get("/v1/tasks/nonexistent-uuid-12345", headers=headers)
    assert res.status_code == 404
    data = res.json()
    assert "Task not found" in data["detail"]


def test_task_state_survives_api_restart(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    db_file = tmp_path / "persistent_audit.sqlite3"
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # First app instance
    app1 = create_app(workspace_root=ws, db_path=db_file)
    client1 = TestClient(app1)

    action_res = client1.post(
        "/v1/actions",
        json={"tool": "write_file", "arguments": {"path": "persist.txt", "content": "saved"}},
        headers=headers,
    )
    assert action_res.status_code == 200
    task_id = action_res.json()["task_id"]

    # Terminate client1 / app1 and simulate cold server restart with new app instance
    del client1
    del app1

    app2 = create_app(workspace_root=ws, db_path=db_file)
    client2 = TestClient(app2)

    # Query task on new app instance
    query_res = client2.get(f"/v1/tasks/{task_id}", headers=headers)
    assert query_res.status_code == 200
    task_data = query_res.json()
    assert task_data["task_id"] == task_id
    assert task_data["status"] == "success"
    assert task_data["decision"] == "allow"

    # Query audit log on new app instance
    audit_res = client2.get("/v1/audit", headers=headers)
    assert audit_res.status_code == 200
    events = audit_res.json()["events"]
    assert any(e["task_id"] == task_id for e in events)


def test_denied_action_audited(audit_client):
    client, _, _ = audit_client
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # Submit path traversal attack
    res = client.post(
        "/v1/actions",
        json={"tool": "read_file", "arguments": {"path": "../../etc/shadow"}},
        headers=headers,
    )
    assert res.status_code == 200
    deny_data = res.json()
    assert deny_data["decision"] == "deny"
    task_id = deny_data["task_id"]

    # Verify task is recorded as denied
    task_res = client.get(f"/v1/tasks/{task_id}", headers=headers)
    assert task_res.status_code == 200
    persisted = task_res.json()
    assert persisted["decision"] == "deny"
    assert persisted["status"] == "denied"
    assert persisted["reason"] == "path_outside_workspace"

    # Verify audit event for denial
    audit_res = client.get("/v1/audit", headers=headers)
    assert audit_res.status_code == 200
    events = audit_res.json()["events"]
    denial_event = next((e for e in events if e["task_id"] == task_id), None)
    assert denial_event is not None
    assert denial_event["event_type"] == "action_denied"
    assert denial_event["reason"] == "path_outside_workspace"


def test_audit_endpoints_require_auth(audit_client):
    client, _, _ = audit_client

    # No token
    res1 = client.get("/v1/tasks/any-id")
    assert res1.status_code == 401

    res2 = client.get("/v1/audit")
    assert res2.status_code == 401

    # Invalid token
    res3 = client.get("/v1/audit", headers={"Authorization": "Bearer bad-token"})
    assert res3.status_code == 401
