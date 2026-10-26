"""Safe workspace file operations."""

from pathlib import Path
from typing import Any


class ToolExecutionError(Exception):
    """Raised when a safe tool operation fails during execution."""

    pass


def list_files(workspace_root: Path, relative_path: str = ".") -> dict[str, Any]:
    """List directory contents within workspace."""
    target_dir = workspace_root / relative_path if relative_path != "." else workspace_root

    if not target_dir.exists():
        raise ToolExecutionError(f"Directory not found: {relative_path}")
    if not target_dir.is_dir():
        raise ToolExecutionError(f"Path is not a directory: {relative_path}")

    entries = []
    try:
        for item in sorted(target_dir.iterdir(), key=lambda p: p.name):
            try:
                is_dir = item.is_dir()
                size = item.stat().st_size if not is_dir else None
                entries.append(
                    {
                        "name": item.name,
                        "type": "directory" if is_dir else "file",
                        "size_bytes": size,
                    }
                )
            except OSError:
                continue
    except OSError as e:
        raise ToolExecutionError(f"Failed to list directory contents: {e}")

    return {
        "path": relative_path,
        "entries": entries,
    }


def read_file(
    workspace_root: Path, relative_path: str, max_size_bytes: int = 1048576
) -> dict[str, Any]:
    """Read a text file within workspace."""
    target_file = workspace_root / relative_path

    if not target_file.exists():
        raise ToolExecutionError(f"File not found: {relative_path}")
    if not target_file.is_file():
        raise ToolExecutionError(f"Path is not a regular file: {relative_path}")

    try:
        size = target_file.stat().st_size
        if size > max_size_bytes:
            raise ToolExecutionError(
                f"File exceeds maximum allowed size ({size} > {max_size_bytes} bytes)"
            )

        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        return {
            "path": relative_path,
            "content": content,
            "size_bytes": len(content.encode("utf-8")),
        }
    except ToolExecutionError:
        raise
    except OSError as e:
        raise ToolExecutionError(f"Failed to read file: {e}")


def write_file(
    workspace_root: Path, relative_path: str, content: str, max_size_bytes: int = 1048576
) -> dict[str, Any]:
    """Write text content to a workspace file, creating parent directories if needed."""
    target_file = workspace_root / relative_path

    encoded = content.encode("utf-8")
    if len(encoded) > max_size_bytes:
        raise ToolExecutionError(
            f"Content exceeds maximum allowed size ({len(encoded)} > {max_size_bytes} bytes)"
        )

    try:
        # Create parent directories inside workspace if they do not exist
        target_file.parent.mkdir(parents=True, exist_ok=True)

        # Write safely
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(content)

        return {
            "path": relative_path,
            "bytes_written": len(encoded),
        }
    except OSError as e:
        raise ToolExecutionError(f"Failed to write file: {e}")


def delete_file(workspace_root: Path, relative_path: str) -> dict[str, Any]:
    """Delete a regular file within the workspace."""
    target_file = workspace_root / relative_path

    if not target_file.exists():
        raise ToolExecutionError(f"File not found: {relative_path}")
    if not target_file.is_file():
        raise ToolExecutionError(f"Path is not a regular file: {relative_path}")

    try:
        target_file.unlink()
        return {
            "path": relative_path,
            "deleted": True,
        }
    except OSError as e:
        raise ToolExecutionError(f"Failed to delete file: {e}")
