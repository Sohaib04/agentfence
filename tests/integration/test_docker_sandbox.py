"""Integration tests for the real Docker sandbox container.

These tests run only when the Docker daemon is active and accessible.
If Docker is unavailable, they are cleanly skipped as specified in the implementation plan.
"""

import subprocess
from pathlib import Path

import pytest

from app.executor.docker import DockerExecutor, is_docker_available
from app.executor.models import ContainerLimits
from app.policy.engine import PolicyEngine
from app.policy.models import ActionRequest, DecisionType, ReasonCode
from app.tools.dispatcher import ToolDispatcher

pytestmark = pytest.mark.skipif(
    not is_docker_available(),
    reason="Docker daemon is not reachable on this host; skipping real container tests",
)

SANDBOX_IMAGE = "agentfence-sandbox:0.1.0"


@pytest.fixture(scope="module")
def ensure_sandbox_image():
    """Build the sandbox image once if running real Docker tests."""
    if not is_docker_available():
        pytest.skip("Docker daemon not available")

    # Check if image already exists
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
def sandbox_env(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    # Harmless canary secret outside workspace
    canary = outside / "canary.txt"
    canary.write_text("CANARY_HOST_SECRET_TOKEN_XYZ123")

    executor = DockerExecutor(default_image=SANDBOX_IMAGE)
    engine = PolicyEngine()
    dispatcher = ToolDispatcher(workspace_root=ws, policy_engine=engine, executor=executor)

    return {
        "ws": ws,
        "outside": outside,
        "canary": canary,
        "dispatcher": dispatcher,
        "executor": executor,
    }


def test_docker_allowed_command_execution(ensure_sandbox_image, sandbox_env):
    executor: DockerExecutor = sandbox_env["executor"]
    ws: Path = sandbox_env["ws"]

    result = executor.run(
        command="python3",
        args=["-c", "print('hello from sandbox container')"],
        workspace_root=ws,
        limits=ContainerLimits(timeout_seconds=10),
    )

    assert result.exit_code == 0
    assert "hello from sandbox container" in result.stdout
    assert not result.timed_out
    assert not result.truncated


def test_docker_runaway_command_timeout_and_cleanup(ensure_sandbox_image, sandbox_env):
    executor: DockerExecutor = sandbox_env["executor"]
    ws: Path = sandbox_env["ws"]

    limits = ContainerLimits(timeout_seconds=2)
    result = executor.run(
        command="python3",
        args=["-c", "import time; time.sleep(10)"],
        workspace_root=ws,
        limits=limits,
    )

    assert result.timed_out is True
    assert result.exit_code == 124

    # Verify container was removed and is not left running
    container_id = result.container_id
    if container_id:
        check = subprocess.run(
            ["docker", "ps", "-a", "-q", "-f", f"name={container_id}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        assert check.stdout.strip() == b""


def test_docker_output_truncation(ensure_sandbox_image, sandbox_env):
    executor: DockerExecutor = sandbox_env["executor"]
    ws: Path = sandbox_env["ws"]

    limits = ContainerLimits(max_output_bytes=500, timeout_seconds=10)
    result = executor.run(
        command="python3",
        args=["-c", "print('A' * 2000)"],
        workspace_root=ws,
        limits=limits,
    )

    assert result.truncated is True
    assert "[OUTPUT TRUNCATED]" in result.stdout
    assert len(result.stdout.encode("utf-8")) < 600


def test_docker_filesystem_isolation_canary(ensure_sandbox_image, sandbox_env):
    executor: DockerExecutor = sandbox_env["executor"]
    ws: Path = sandbox_env["ws"]
    canary_path: Path = sandbox_env["canary"]

    # Attempt to read the host canary file from within container
    script = (
        f"try:\n"
        f"    with open('{canary_path}') as f:\n"
        f"        print('LEAKED:' + f.read())\n"
        f"except Exception as e:\n"
        f"    print('BLOCKED:' + str(e))\n"
    )

    result = executor.run(
        command="python3",
        args=["-c", script],
        workspace_root=ws,
        limits=ContainerLimits(timeout_seconds=10),
    )

    # Secret token must NEVER appear in output
    assert "CANARY_HOST_SECRET_TOKEN_XYZ123" not in result.stdout
    assert "LEAKED" not in result.stdout
    assert "BLOCKED" in result.stdout or "No such file or directory" in result.stdout


def test_docker_network_isolation_canary(ensure_sandbox_image, sandbox_env):
    executor: DockerExecutor = sandbox_env["executor"]
    ws: Path = sandbox_env["ws"]

    # Attempt external network connection inside container
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
        limits=ContainerLimits(timeout_seconds=10),
    )

    assert "NET_OPEN" not in result.stdout
    assert "NET_BLOCKED" in result.stdout


def test_docker_disallowed_command_never_executes(ensure_sandbox_image, sandbox_env):
    dispatcher: ToolDispatcher = sandbox_env["dispatcher"]

    action = ActionRequest(
        tool="run_command",
        arguments={"command": "curl", "args": ["http://1.1.1.1"]},
    )
    res = dispatcher.dispatch(action)

    assert res.decision == DecisionType.DENY
    assert res.status.value == "denied"
    assert res.reason == ReasonCode.DISALLOWED_COMMAND
