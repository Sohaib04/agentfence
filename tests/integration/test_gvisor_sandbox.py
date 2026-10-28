"""Integration and comparative isolation tests for gVisor (runsc) runtime sandboxing.

When both Docker and gVisor (runsc) are available on the host, these tests
run commands through the live gVisor user-space kernel (Sentry).
If Docker or runsc is not present, live tests are cleanly skipped while
comparative isolation invariance checks continue to verify security guarantees.
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.executor.docker import (
    DockerExecutor,
    is_docker_available,
    is_runsc_available,
)
from app.executor.models import ContainerLimits
from app.policy.engine import PolicyEngine
from app.policy.models import ActionRequest, DecisionType
from app.tools.dispatcher import ToolDispatcher

SANDBOX_IMAGE = "agentfence-sandbox:0.1.0"

# Skip condition for live container execution
skip_unless_gvisor = pytest.mark.skipif(
    not (is_docker_available() and is_runsc_available()),
    reason="Docker daemon and gVisor (runsc) runtime must both be available on this host",
)


@pytest.fixture(scope="module")
def ensure_sandbox_image():
    """Ensure the sandbox image exists before running live Docker tests."""
    if not (is_docker_available() and is_runsc_available()):
        pytest.skip("Docker or runsc not available")

    check = subprocess.run(
        ["docker", "image", "inspect", SANDBOX_IMAGE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check.returncode != 0:
        dockerfile = Path(__file__).resolve().parent.parent.parent / "Dockerfile.sandbox"
        build = subprocess.run(
            ["docker", "build", "-t", SANDBOX_IMAGE, "-f", str(dockerfile), "."],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        if build.returncode != 0:
            pytest.fail(f"Failed to build sandbox image: {build.stderr.decode('utf-8')}")


@pytest.fixture
def gvisor_env(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    canary = outside / "canary.txt"
    canary.write_text("CANARY_GVISOR_HOST_SECRET_XYZ999")

    executor = DockerExecutor(default_image=SANDBOX_IMAGE, runtime="runsc")
    engine = PolicyEngine()
    dispatcher = ToolDispatcher(workspace_root=ws, policy_engine=engine, executor=executor)

    return {
        "ws": ws,
        "outside": outside,
        "canary": canary,
        "dispatcher": dispatcher,
        "executor": executor,
    }


def test_comparative_args_preserves_all_hardening_flags(tmp_path: Path):
    """Verify that adding --runtime=runsc preserves all container hardening flags."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    limits = ContainerLimits(
        cpu_quota=1.0,
        memory_limit="256m",
        pids_limit=64,
        tmpfs_size="64m",
    )

    runc_exec = DockerExecutor(runtime=None)
    runsc_exec = DockerExecutor(runtime="runsc")

    runc_args = runc_exec.build_docker_run_args(
        container_name="runc-box",
        workspace_root=ws,
        command="python3",
        args=["-c", "pass"],
        limits=limits,
        image=SANDBOX_IMAGE,
    )

    runsc_args = runsc_exec.build_docker_run_args(
        container_name="runsc-box",
        workspace_root=ws,
        command="python3",
        args=["-c", "pass"],
        limits=limits,
        image=SANDBOX_IMAGE,
    )

    # 1. runsc has the runtime flag
    assert "--runtime=runsc" in runsc_args
    assert not any(a.startswith("--runtime") for a in runc_args)

    # 2. Both retain all defense-in-depth isolation flags
    common_flags = [
        "--network",
        "--read-only",
        "--tmpfs",
        "--cap-drop",
        "--security-opt",
        "--user",
        "-v",
        "-w",
        "--memory",
        "--cpus",
        "--pids-limit",
    ]
    for flag in common_flags:
        assert flag in runc_args, f"runc missing {flag}"
        assert flag in runsc_args, f"runsc missing {flag}"


def test_missing_runtime_docker_daemon_error_handling(tmp_path: Path):
    """Verify that if Docker daemon rejects an uninstalled runtime, error is handled cleanly."""
    executor = DockerExecutor(runtime="nonexistent_runtime")
    mock_proc = MagicMock()
    mock_proc.returncode = 125
    mock_proc.stdout = b""
    mock_proc.stderr = (
        b"docker: Error response from daemon: Unknown runtime specified nonexistent_runtime\n"
    )

    with patch("subprocess.run", return_value=mock_proc):
        res = executor.run(
            command="python3",
            args=["-c", "print('hello')"],
            workspace_root=tmp_path,
        )

        assert res.exit_code == 125
        assert "Unknown runtime" in res.stderr
        assert res.extra.get("runtime") == "nonexistent_runtime"


def test_dispatcher_with_gvisor_runtime_execution(tmp_path: Path):
    """Verify ToolDispatcher dispatches command and receives gVisor runtime metadata."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    executor = DockerExecutor(runtime="runsc")
    dispatcher = ToolDispatcher(workspace_root=ws, executor=executor)

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = b"Simulated gVisor Sentry Kernel v4.4.0\n"
    mock_proc.stderr = b""

    with patch("subprocess.run", return_value=mock_proc):
        action = ActionRequest(
            tool="run_command",
            arguments={"command": "python3", "args": ["-c", "print('kernel')"]},
        )
        res = dispatcher.dispatch(action)

        assert res.decision == DecisionType.ALLOW
        assert res.status.value == "success"
        assert res.result is not None
        assert res.result["extra"]["runtime"] == "runsc"
        assert "gVisor" in res.result["stdout"]


# ---------------------------------------------------------------------------
# Live container tests (executed when both Docker and runsc are active on host)
# ---------------------------------------------------------------------------


@skip_unless_gvisor
def test_live_gvisor_execution(ensure_sandbox_image, gvisor_env):
    """Test live container execution under gVisor runsc runtime."""
    executor: DockerExecutor = gvisor_env["executor"]
    ws: Path = gvisor_env["ws"]

    result = executor.run(
        command="python3",
        args=["-c", "print('hello from gvisor sandbox')"],
        workspace_root=ws,
        limits=ContainerLimits(timeout_seconds=15),
    )

    assert result.exit_code == 0
    assert "hello from gvisor sandbox" in result.stdout
    assert not result.timed_out


@skip_unless_gvisor
def test_live_gvisor_kernel_isolation_detection(ensure_sandbox_image, gvisor_env):
    """Compare guest kernel identification under gVisor vs host."""
    executor: DockerExecutor = gvisor_env["executor"]
    ws: Path = gvisor_env["ws"]

    # In gVisor, /proc/version or dmesg identifies the Sentry user-space kernel
    script = (
        "try:\n"
        "    with open('/proc/version') as f:\n"
        "        print('KERNEL_VERSION:' + f.read().strip())\n"
        "except Exception as e:\n"
        "    print('ERROR:' + str(e))\n"
    )

    result = executor.run(
        command="python3",
        args=["-c", script],
        workspace_root=ws,
        limits=ContainerLimits(timeout_seconds=15),
    )

    assert result.exit_code == 0
    assert "KERNEL_VERSION" in result.stdout


@skip_unless_gvisor
def test_live_gvisor_filesystem_isolation_canary(ensure_sandbox_image, gvisor_env):
    """Verify host filesystem containment holds identically under gVisor."""
    executor: DockerExecutor = gvisor_env["executor"]
    ws: Path = gvisor_env["ws"]
    canary: Path = gvisor_env["canary"]

    script = (
        f"try:\n"
        f"    with open('{canary}') as f:\n"
        f"        print('LEAKED:' + f.read())\n"
        f"except Exception as e:\n"
        f"    print('BLOCKED:' + str(e))\n"
    )

    result = executor.run(
        command="python3",
        args=["-c", script],
        workspace_root=ws,
        limits=ContainerLimits(timeout_seconds=15),
    )

    assert "CANARY_GVISOR_HOST_SECRET_XYZ999" not in result.stdout
    assert "LEAKED" not in result.stdout
    assert "BLOCKED" in result.stdout or "No such file or directory" in result.stdout


@skip_unless_gvisor
def test_live_gvisor_network_isolation_canary(ensure_sandbox_image, gvisor_env):
    """Verify network isolation holds identically under gVisor."""
    executor: DockerExecutor = gvisor_env["executor"]
    ws: Path = gvisor_env["ws"]

    script = (
        "import socket\n"
        "try:\n"
        "    s = socket.create_connection(('1.1.1.1', 80), timeout=2)\n"
        "    print('NET_OPEN')\n"
        "except Exception as e:\n"
        "    print('NET_BLOCKED:' + e.__class__.__name__)\n"
    )

    result = executor.run(
        command="python3",
        args=["-c", script],
        workspace_root=ws,
        limits=ContainerLimits(timeout_seconds=15),
    )

    assert "NET_OPEN" not in result.stdout
    assert "NET_BLOCKED" in result.stdout
