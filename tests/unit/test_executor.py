"""Unit tests for DockerExecutor hardening flags, timeouts, and output limits."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.executor.docker import DockerExecutor
from app.executor.models import ContainerLimits


@pytest.fixture
def executor():
    return DockerExecutor(default_image="agentfence-sandbox:0.1.0")


def test_build_docker_run_args_hardening(executor: DockerExecutor, tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()

    limits = ContainerLimits(
        cpu_quota=1.5,
        memory_limit="512m",
        pids_limit=32,
        tmpfs_size="32m",
        timeout_seconds=20,
    )

    args = executor.build_docker_run_args(
        container_name="test-box",
        workspace_root=ws,
        command="python3",
        args=["-c", "print('safe')"],
        limits=limits,
        image="agentfence-sandbox:0.1.0",
    )

    # Hardening flags checks
    assert "--network" in args and args[args.index("--network") + 1] == "none"
    assert "--read-only" in args
    assert "--cap-drop" in args and args[args.index("--cap-drop") + 1] == "ALL"
    assert (
        "--security-opt" in args and args[args.index("--security-opt") + 1] == "no-new-privileges"
    )
    assert "--user" in args and args[args.index("--user") + 1] == "10001:10001"
    assert "-v" in args and f"{ws.resolve()}:/workspace:rw" in args
    assert "--memory" in args and args[args.index("--memory") + 1] == "512m"
    assert "--cpus" in args and args[args.index("--cpus") + 1] == "1.5"
    assert "--pids-limit" in args and args[args.index("--pids-limit") + 1] == "32"
    assert "--tmpfs" in args and "/tmp:rw,noexec,nosuid,size=32m" in args

    # Check executable and trailing arguments
    assert args[-3:] == ["python3", "-c", "print('safe')"]


def test_executor_successful_run(executor: DockerExecutor, tmp_path: Path):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = b"execution output\n"
    mock_proc.stderr = b""

    with patch("subprocess.run", return_value=mock_proc) as mock_run:
        result = executor.run(
            command="python3",
            args=["test.py"],
            workspace_root=tmp_path,
        )

        assert result.exit_code == 0
        assert result.stdout == "execution output\n"
        assert result.stderr == ""
        assert not result.timed_out
        assert not result.truncated
        assert mock_run.called


def test_executor_timeout_and_kill(executor: DockerExecutor, tmp_path: Path):
    # Mock subprocess.run raising TimeoutExpired
    def side_effect(cmd, *args, **kwargs):
        if "rm" in cmd:
            # Container cleanup call succeeds
            cleanup_proc = MagicMock()
            cleanup_proc.returncode = 0
            return cleanup_proc
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=5, output=b"partial output")

    with patch("subprocess.run", side_effect=side_effect) as mock_run:
        limits = ContainerLimits(timeout_seconds=5)
        result = executor.run(
            command="python3",
            args=["runaway.py"],
            workspace_root=tmp_path,
            limits=limits,
        )

        assert result.timed_out is True
        assert result.exit_code == 124
        assert result.stdout == "partial output"

        # Verify cleanup docker rm -f was invoked
        cleanup_calls = [
            call for call in mock_run.call_args_list if "rm" in call[0][0] and "-f" in call[0][0]
        ]
        assert len(cleanup_calls) >= 1


def test_executor_output_truncation(executor: DockerExecutor, tmp_path: Path):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = b"A" * 2000
    mock_proc.stderr = b""

    with patch("subprocess.run", return_value=mock_proc):
        limits = ContainerLimits(max_output_bytes=500)
        result = executor.run(
            command="echo",
            args=["test"],
            workspace_root=tmp_path,
            limits=limits,
        )

        assert result.truncated is True
        assert len(result.stdout.encode("utf-8")) < 600
        assert "[OUTPUT TRUNCATED]" in result.stdout
