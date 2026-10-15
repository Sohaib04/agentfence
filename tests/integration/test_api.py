"""Integration tests for AgentFence HTTP API."""

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

    # Symlink inside workspace pointing outside
    sym = ws / "sym_out"
    sym.symlink_to(outside)

    app = create_app(workspace_root=ws)
    return TestClient(app)


def test_health_check_public(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_actions_auth_required(client: TestClient):
    # No auth header
    response = client.post("/v1/actions", json={"tool": "list_files", "arguments": {}})
    assert response.status_code == 401

    # Invalid token
    response = client.post(
        "/v1/actions",
        json={"tool": "list_files", "arguments": {}},
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert response.status_code == 401


def test_legitimate_action_lifecycle(client: TestClient):
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # 1. Write file
    write_payload = {
        "tool": "write_file",
        "arguments": {"path": "notes.txt", "content": "Security Gateway Active"},
    }
    res = client.post("/v1/actions", json=write_payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "allow"
    assert data["status"] == "success"
    assert data["reason"] == "allowed"
    assert data["result"]["bytes_written"] > 0
    assert "task_id" in data

    # 2. Read file
    read_payload = {
        "tool": "read_file",
        "arguments": {"path": "notes.txt"},
    }
    res = client.post("/v1/actions", json=read_payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "allow"
    assert data["status"] == "success"
    assert data["result"]["content"] == "Security Gateway Active"

    # 3. List files
    list_payload = {
        "tool": "list_files",
        "arguments": {"path": ""},
    }
    res = client.post("/v1/actions", json=list_payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "allow"
    assert data["status"] == "success"
    entry_names = [e["name"] for e in data["result"]["entries"]]
    assert "notes.txt" in entry_names


def test_forbidden_actions_denied_with_reasons(client: TestClient):
    headers = {"X-AgentFence-Token": DEFAULT_DEV_TOKEN}

    # Traversal attack
    res = client.post(
        "/v1/actions",
        json={"tool": "read_file", "arguments": {"path": "../../etc/passwd"}},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "deny"
    assert data["status"] == "denied"
    assert data["reason"] == "path_outside_workspace"

    # Absolute path escape
    res = client.post(
        "/v1/actions",
        json={"tool": "read_file", "arguments": {"path": "/etc/passwd"}},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "deny"
    assert data["status"] == "denied"
    assert data["reason"] == "path_outside_workspace"

    # Symlink escape
    res = client.post(
        "/v1/actions",
        json={"tool": "read_file", "arguments": {"path": "sym_out/secret.txt"}},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "deny"
    assert data["status"] == "denied"
    assert data["reason"] == "symlink_escape"

    # Unknown tool
    res = client.post(
        "/v1/actions",
        json={"tool": "unknown_tool", "arguments": {}},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "deny"
    assert data["status"] == "denied"
    assert data["reason"] == "unknown_tool"

    # Disabled tool
    res = client.post(
        "/v1/actions",
        json={"tool": "delete_file", "arguments": {"path": "notes.txt"}},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "deny"
    assert data["status"] == "denied"
    assert data["reason"] == "tool_disabled"


def test_allowed_but_failed_distinct_outcome(client: TestClient):
    headers = {"Authorization": f"Bearer {DEFAULT_DEV_TOKEN}"}

    # Valid path inside workspace, but file does not exist
    res = client.post(
        "/v1/actions",
        json={"tool": "read_file", "arguments": {"path": "missing_file.txt"}},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "allow"
    assert data["status"] == "error"
    assert data["result"] is None
    assert "File not found" in data["error"]


def test_oversized_request_payload_rejected(client: TestClient):
    headers = {
        "Authorization": f"Bearer {DEFAULT_DEV_TOKEN}",
        "Content-Length": str(3 * 1024 * 1024),  # 3MB > 2MB limit
    }
    res = client.post(
        "/v1/actions",
        content=b"x" * 10,
        headers=headers,
    )
    assert res.status_code == 413
