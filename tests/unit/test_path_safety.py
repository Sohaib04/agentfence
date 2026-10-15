"""Unit tests for path confinement, traversal prevention, and symlink escape detection."""

from pathlib import Path

import pytest

from app.policy.models import ReasonCode
from app.tools.path_utils import validate_workspace_path


@pytest.fixture
def workspace_env(tmp_path: Path):
    """Creates a temporary workspace and an external directory for containment tests."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    # Create a secret file outside workspace
    secret = outside / "secret.txt"
    secret.write_text("top_secret_data")

    # Create a legitimate file inside workspace
    allowed = ws / "allowed.txt"
    allowed.write_text("normal_data")

    return {"ws": ws, "outside": outside, "secret": secret, "allowed": allowed}


def test_valid_paths_inside_workspace(workspace_env):
    ws = workspace_env["ws"]

    # File at root
    resolved, reason, rel = validate_workspace_path(ws, "allowed.txt")
    assert reason is None
    assert resolved == (ws / "allowed.txt").resolve()
    assert rel == "allowed.txt"

    # Nested new file
    resolved, reason, rel = validate_workspace_path(ws, "subdir/new_file.txt")
    assert reason is None
    assert rel == "subdir/new_file.txt"

    # Root listing
    resolved, reason, rel = validate_workspace_path(ws, "", allow_empty=True)
    assert reason is None
    assert resolved == ws.resolve()
    assert rel == "."


def test_path_traversal_attempts_blocked(workspace_env):
    ws = workspace_env["ws"]

    # Direct traversal
    resolved, reason, _ = validate_workspace_path(ws, "../outside/secret.txt")
    assert reason == ReasonCode.PATH_OUTSIDE_WORKSPACE
    assert resolved is None

    # Deep traversal
    resolved, reason, _ = validate_workspace_path(ws, "subdir/../../outside/secret.txt")
    assert reason == ReasonCode.PATH_OUTSIDE_WORKSPACE
    assert resolved is None

    # Multi-dot traversal
    resolved, reason, _ = validate_workspace_path(ws, "../../../../etc/passwd")
    assert reason == ReasonCode.PATH_OUTSIDE_WORKSPACE
    assert resolved is None


def test_absolute_path_escape_blocked(workspace_env):
    ws = workspace_env["ws"]

    resolved, reason, _ = validate_workspace_path(ws, "/etc/passwd")
    assert reason == ReasonCode.PATH_OUTSIDE_WORKSPACE
    assert resolved is None

    resolved, reason, _ = validate_workspace_path(ws, "/private/etc/passwd")
    assert reason == ReasonCode.PATH_OUTSIDE_WORKSPACE
    assert resolved is None


def test_symlink_escape_blocked(workspace_env):
    ws = workspace_env["ws"]
    outside = workspace_env["outside"]

    # Symlink file pointing outside
    sym_file = ws / "sym_secret.txt"
    sym_file.symlink_to(outside / "secret.txt")

    resolved, reason, _ = validate_workspace_path(ws, "sym_secret.txt")
    assert reason == ReasonCode.SYMLINK_ESCAPE
    assert resolved is None

    # Symlink directory pointing outside
    sym_dir = ws / "sym_dir"
    sym_dir.symlink_to(outside)

    # Accessing directory itself
    resolved, reason, _ = validate_workspace_path(ws, "sym_dir")
    assert reason == ReasonCode.SYMLINK_ESCAPE
    assert resolved is None

    # Accessing file inside symlinked outside directory
    resolved, reason, _ = validate_workspace_path(ws, "sym_dir/secret.txt")
    assert reason == ReasonCode.SYMLINK_ESCAPE
    assert resolved is None

    # Non-existent file inside symlinked outside directory
    resolved, reason, _ = validate_workspace_path(ws, "sym_dir/new_file.txt")
    assert reason == ReasonCode.SYMLINK_ESCAPE
    assert resolved is None


def test_internal_symlink_allowed(workspace_env):
    ws = workspace_env["ws"]

    # Symlink pointing to another location inside the workspace
    target = ws / "allowed.txt"
    sym_internal = ws / "sym_internal.txt"
    sym_internal.symlink_to(target)

    resolved, reason, rel = validate_workspace_path(ws, "sym_internal.txt")
    assert reason is None
    assert resolved == target.resolve()
    assert rel == "allowed.txt"


def test_invalid_path_arguments(workspace_env):
    ws = workspace_env["ws"]

    # Null bytes
    resolved, reason, _ = validate_workspace_path(ws, "file\0name.txt")
    assert reason == ReasonCode.INVALID_ARGUMENTS
    assert resolved is None

    # Empty string when not allowed
    resolved, reason, _ = validate_workspace_path(ws, "", allow_empty=False)
    assert reason == ReasonCode.INVALID_ARGUMENTS
    assert resolved is None

    # None argument
    resolved, reason, _ = validate_workspace_path(ws, None)
    assert reason == ReasonCode.MISSING_ARGUMENT
    assert resolved is None
