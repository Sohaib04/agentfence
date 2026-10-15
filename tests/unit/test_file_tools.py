"""Unit tests for workspace file tools."""

from pathlib import Path

import pytest

from app.tools.files import ToolExecutionError, list_files, read_file, write_file


@pytest.fixture
def workspace(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def test_write_and_read_file(workspace: Path):
    res_write = write_file(workspace, "hello.txt", "Hello AgentFence!", max_size_bytes=1024)
    assert res_write["path"] == "hello.txt"
    assert res_write["bytes_written"] == len("Hello AgentFence!".encode("utf-8"))

    res_read = read_file(workspace, "hello.txt", max_size_bytes=1024)
    assert res_read["path"] == "hello.txt"
    assert res_read["content"] == "Hello AgentFence!"
    assert res_read["size_bytes"] == len("Hello AgentFence!".encode("utf-8"))


def test_write_nested_file_creates_directories(workspace: Path):
    res_write = write_file(
        workspace, "nested/deep/directory/test.txt", "deep content", max_size_bytes=1024
    )
    assert res_write["path"] == "nested/deep/directory/test.txt"

    res_read = read_file(workspace, "nested/deep/directory/test.txt", max_size_bytes=1024)
    assert res_read["content"] == "deep content"


def test_list_files(workspace: Path):
    # Empty directory
    res = list_files(workspace, ".")
    assert res["entries"] == []

    # Write files and directories
    write_file(workspace, "b_file.txt", "b", max_size_bytes=1024)
    write_file(workspace, "a_file.txt", "a", max_size_bytes=1024)
    (workspace / "sub_dir").mkdir()

    res = list_files(workspace, ".")
    names = [e["name"] for e in res["entries"]]
    assert names == ["a_file.txt", "b_file.txt", "sub_dir"]

    file_entry = next(e for e in res["entries"] if e["name"] == "a_file.txt")
    assert file_entry["type"] == "file"
    assert file_entry["size_bytes"] == 1

    dir_entry = next(e for e in res["entries"] if e["name"] == "sub_dir")
    assert dir_entry["type"] == "directory"
    assert dir_entry["size_bytes"] is None


def test_file_tools_error_handling(workspace: Path):
    # Non-existent file
    with pytest.raises(ToolExecutionError) as exc:
        read_file(workspace, "missing.txt", max_size_bytes=1024)
    assert "File not found" in str(exc.value)

    # Exceeding size on write
    with pytest.raises(ToolExecutionError) as exc:
        write_file(workspace, "oversized.txt", "x" * 200, max_size_bytes=100)
    assert "Content exceeds maximum" in str(exc.value)

    # Exceeding size on read
    (workspace / "large.txt").write_text("x" * 200)
    with pytest.raises(ToolExecutionError) as exc:
        read_file(workspace, "large.txt", max_size_bytes=100)
    assert "File exceeds maximum" in str(exc.value)

    # List non-existent directory
    with pytest.raises(ToolExecutionError) as exc:
        list_files(workspace, "nonexistent_dir")
    assert "Directory not found" in str(exc.value)
