"""Workspace path validation and containment logic for policy enforcement."""

from pathlib import Path

from app.policy.models import ReasonCode


def is_symlink_escape(user_path_str: str, workspace_root: Path) -> bool:
    """Check if the path traverses through any symlink pointing outside the workspace."""
    ws_resolved = workspace_root.resolve()
    # Handle absolute or relative paths
    if Path(user_path_str).is_absolute():
        candidate = workspace_root / user_path_str.lstrip("/\\")
    else:
        candidate = workspace_root / user_path_str

    curr = candidate
    # Traverse from candidate up toward workspace root
    while curr != workspace_root and curr != curr.parent:
        try:
            if curr.is_symlink():
                target = curr.resolve()
                if not target.is_relative_to(ws_resolved):
                    return True
        except (OSError, ValueError):
            pass
        curr = curr.parent

    return False


def validate_workspace_path(
    workspace_root: Path,
    path_str: str,
    allow_empty: bool = False,
) -> tuple[Path | None, ReasonCode | None, str | None]:
    """Validate that path_str stays strictly within workspace_root.

    Returns:
        (resolved_path, None, relative_path_str) on success
        (None, ReasonCode, None) on failure
    """
    if path_str is None:
        return None, ReasonCode.MISSING_ARGUMENT, None

    if not isinstance(path_str, str):
        return None, ReasonCode.INVALID_ARGUMENTS, None

    # Null byte check
    if "\0" in path_str:
        return None, ReasonCode.INVALID_ARGUMENTS, None

    clean_path = path_str.strip()
    if not clean_path:
        if allow_empty:
            ws_resolved = workspace_root.resolve()
            return ws_resolved, None, "."
        return None, ReasonCode.INVALID_ARGUMENTS, None

    ws_resolved = workspace_root.resolve()

    # Reject direct absolute paths attempting to reference host root
    path_obj = Path(clean_path)
    if path_obj.is_absolute():
        resolved_direct = path_obj.resolve()
        if not resolved_direct.is_relative_to(ws_resolved):
            return None, ReasonCode.PATH_OUTSIDE_WORKSPACE, None
        candidate = path_obj
    else:
        candidate = workspace_root / path_obj

    # Check for symlink escapes
    if is_symlink_escape(clean_path, workspace_root):
        return None, ReasonCode.SYMLINK_ESCAPE, None

    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None, ReasonCode.PATH_OUTSIDE_WORKSPACE, None

    # Verify that the fully resolved path is strictly inside workspace_root
    if not resolved.is_relative_to(ws_resolved):
        return None, ReasonCode.PATH_OUTSIDE_WORKSPACE, None

    try:
        relative_path = str(resolved.relative_to(ws_resolved))
    except ValueError:
        return None, ReasonCode.PATH_OUTSIDE_WORKSPACE, None

    return resolved, None, relative_path
