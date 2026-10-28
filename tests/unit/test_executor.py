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


def test_build_docker_run_args_runtime_options(executor: DockerExecutor, tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    limits = ContainerLimits()

    # 1. Default (no runtime specified) -> no --runtime flag
    args_default = executor.build_docker_run_args(
        container_name="box-1",
        workspace_root=ws,
        command="python3",
        args=["-c", "pass"],
        limits=limits,
        image="agentfence-sandbox:0.1.0",
    )
    assert not any(a.startswith("--runtime") for a in args_default)

    # 2. Runtime passed directly to build_docker_run_args -> --runtime=runsc
    args_runsc = executor.build_docker_run_args(
        container_name="box-2",
        workspace_root=ws,
        command="python3",
        args=["-c", "pass"],
        limits=limits,
        image="agentfence-sandbox:0.1.0",
        runtime="runsc",
    )
    assert "--runtime=runsc" in args_runsc

    # 3. Runtime passed as "--runtime=runsc" format normalized
    args_normalized = executor.build_docker_run_args(
        container_name="box-3",
        workspace_root=ws,
        command="python3",
        args=["-c", "pass"],
        limits=limits,
        image="agentfence-sandbox:0.1.0",
        runtime="--runtime=runsc",
    )
    assert "--runtime=runsc" in args_normalized

    # 4. Runtime configured on ContainerLimits
    limits_with_runtime = ContainerLimits(runtime="runsc")
    args_via_limits = executor.build_docker_run_args(
        container_name="box-4",
        workspace_root=ws,
        command="python3",
        args=["-c", "pass"],
        limits=limits_with_runtime,
        image="agentfence-sandbox:0.1.0",
    )
    assert "--runtime=runsc" in args_via_limits

    # 5. Runtime configured on executor instance
    gvisor_executor = DockerExecutor(
        default_image="agentfence-sandbox:0.1.0",
        runtime="runsc",
    )
    args_via_executor = gvisor_executor.build_docker_run_args(
        container_name="box-5",
        workspace_root=ws,
        command="python3",
        args=["-c", "pass"],
        limits=limits,
        image="agentfence-sandbox:0.1.0",
    )
    assert "--runtime=runsc" in args_via_executor


def test_is_runsc_available_detection():
    from app.executor.docker import is_runsc_available

    # Case 1: runsc binary directly in PATH
    with patch("shutil.which", return_value="/usr/local/bin/runsc"):
        assert is_runsc_available() is True

    # Case 2: runsc binary not in PATH, but registered in Docker runtimes
    mock_docker_info = MagicMock()
    mock_docker_info.returncode = 0
    mock_docker_info.stdout = '{"runc":{"path":"runc"},"runsc":{"path":"/usr/bin/runsc"}}'

    with (
        patch("shutil.which", return_value=None),
        patch("app.executor.docker.is_docker_available", return_value=True),
        patch("subprocess.run", return_value=mock_docker_info),
    ):
        assert is_runsc_available() is True

    # Case 3: Neither binary nor Docker runtime has runsc
    mock_docker_info_no_runsc = MagicMock()
    mock_docker_info_no_runsc.returncode = 0
    mock_docker_info_no_runsc.stdout = '{"runc":{"path":"runc"}}'

    with (
        patch("shutil.which", return_value=None),
        patch("app.executor.docker.is_docker_available", return_value=True),
        patch("subprocess.run", return_value=mock_docker_info_no_runsc),
    ):
        assert is_runsc_available() is False

    # Case 4: Docker info subprocess throws exception
    with (
        patch("shutil.which", return_value=None),
        patch("app.executor.docker.is_docker_available", return_value=True),
        patch("subprocess.run", side_effect=OSError("Command not found")),
    ):
        assert is_runsc_available() is False


def test_executor_run_with_gvisor_runtime(tmp_path: Path):
    executor = DockerExecutor(runtime="runsc")
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = b"gvisor sandbox output\n"
    mock_proc.stderr = b""

    with patch("subprocess.run", return_value=mock_proc) as mock_run:
        result = executor.run(
            command="python3",
            args=["-c", "print('hello')"],
            workspace_root=tmp_path,
        )

        assert result.exit_code == 0
        assert result.stdout == "gvisor sandbox output\n"
        assert result.extra.get("runtime") == "runsc"

        # Verify docker run (the first subprocess call before cleanup) had --runtime=runsc
        run_cmd = mock_run.call_args_list[0][0][0]
        assert "--runtime=runsc" in run_cmd
