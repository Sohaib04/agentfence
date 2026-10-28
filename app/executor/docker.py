"""Restricted Docker container command executor with resource bounds and cleanup."""

import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Protocol

from app.executor.models import CommandExecutionError, ContainerLimits, ExecutionResult


def is_docker_available() -> bool:
    """Check if the Docker CLI and daemon are reachable."""
    docker_path = shutil.which("docker")
    if not docker_path:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return proc.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def is_runsc_available() -> bool:
    """Check if the gVisor runsc runtime is installed on the host or registered in Docker."""
    if shutil.which("runsc") is not None:
        return True
    if is_docker_available():
        try:
            proc = subprocess.run(
                ["docker", "info", "--format", "{{json .Runtimes}}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=3,
                text=True,
            )
            if proc.returncode == 0 and "runsc" in proc.stdout:
                return True
        except (subprocess.SubprocessError, OSError):
            pass
    return False


class CommandExecutor(Protocol):
    """Protocol defining the executor interface."""

    def run(
        self,
        command: str,
        args: list[str],
        workspace_root: Path,
        limits: ContainerLimits | None = None,
        image: str | None = None,
        runtime: str | None = None,
    ) -> ExecutionResult: ...


class DockerExecutor:
    """Executes validated commands inside an isolated, unprivileged Docker container."""

    DEFAULT_IMAGE = "agentfence-sandbox:0.1.0"

    def __init__(
        self,
        default_image: str | None = None,
        runtime: str | None = None,
    ) -> None:
        self.image = default_image or self.DEFAULT_IMAGE
        self.runtime = runtime

    def build_docker_run_args(
        self,
        container_name: str,
        workspace_root: Path,
        command: str,
        args: list[str],
        limits: ContainerLimits,
        image: str,
        runtime: str | None = None,
    ) -> list[str]:
        """Construct the hardened Docker CLI arguments array."""
        ws_resolved = str(workspace_root.resolve())
        eff_runtime = runtime or limits.runtime or self.runtime

        docker_args = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
        ]

        # Optional gVisor or alternative runtime (e.g., --runtime=runsc)
        if eff_runtime:
            clean_runtime = eff_runtime.removeprefix("--runtime=").strip()
            if clean_runtime:
                docker_args.append(f"--runtime={clean_runtime}")

        docker_args.extend(
            [
                # Hardening: complete network isolation
                "--network",
                "none",
                # Hardening: read-only root filesystem
                "--read-only",
                # Hardening: minimal isolated tmpfs for temporary operations
                "--tmpfs",
                f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_size}",
                # Hardening: drop all Linux capabilities
                "--cap-drop",
                "ALL",
                # Hardening: prevent privilege escalation
                "--security-opt",
                "no-new-privileges",
                # Hardening: unprivileged user
                "--user",
                "10001:10001",
                # Filesystem mount: workspace only
                "-v",
                f"{ws_resolved}:/workspace:rw",
                "-w",
                "/workspace",
                # Resource bounds
                "--memory",
                limits.memory_limit,
                "--cpus",
                str(limits.cpu_quota),
                "--pids-limit",
                str(limits.pids_limit),
                # Container image
                image,
                # Executable and arguments (array format, never shell string)
                command,
                *args,
            ]
        )
        return docker_args

    def run(
        self,
        command: str,
        args: list[str],
        workspace_root: Path,
        limits: ContainerLimits | None = None,
        image: str | None = None,
        runtime: str | None = None,
    ) -> ExecutionResult:
        """Run a command inside the hardened Docker sandbox with timeout and cleanup."""
        eff_limits = limits or ContainerLimits()
        eff_image = image or self.image
        eff_runtime = runtime or eff_limits.runtime or self.runtime
        container_name = f"af-box-{uuid.uuid4().hex[:12]}"

        docker_cmd = self.build_docker_run_args(
            container_name=container_name,
            workspace_root=workspace_root,
            command=command,
            args=args,
            limits=eff_limits,
            image=eff_image,
            runtime=eff_runtime,
        )

        start_time = time.monotonic()
        timed_out = False
        stdout_raw = b""
        stderr_raw = b""
        exit_code = 1

        try:
            # Execute with strict timeout; never shell=True
            proc = subprocess.run(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=eff_limits.timeout_seconds,
            )
            exit_code = proc.returncode
            stdout_raw = proc.stdout
            stderr_raw = proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout_raw = getattr(exc, "output", None) or getattr(exc, "stdout", None) or b""
            stderr_raw = getattr(exc, "stderr", None) or b""
            exit_code = 124  # Standard timeout exit code
            # Critical cleanup: kill runaway container
            self._kill_container(container_name)
        except OSError as exc:
            # Host level invocation error
            self._kill_container(container_name)
            raise CommandExecutionError(f"Failed to invoke container executor: {exc}")
        finally:
            # Ensure container is purged even if abnormal termination occurs
            self._kill_container(container_name)

        duration = time.monotonic() - start_time

        # Safe output decoding and bounded truncation
        stdout_text, stdout_truncated = self._truncate_output(
            stdout_raw, eff_limits.max_output_bytes
        )
        stderr_text, stderr_truncated = self._truncate_output(
            stderr_raw, eff_limits.max_output_bytes
        )

        extra_info: dict[str, str] = {}
        if eff_runtime:
            clean_runtime = eff_runtime.removeprefix("--runtime=").strip()
            if clean_runtime:
                extra_info["runtime"] = clean_runtime

        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            timed_out=timed_out,
            truncated=stdout_truncated or stderr_truncated,
            duration_seconds=round(duration, 3),
            container_id=container_name,
            extra=extra_info,
        )

    def _kill_container(self, container_name: str) -> None:
        """Forcefully remove the container if it still exists."""
        try:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except (subprocess.SubprocessError, OSError):
            pass

    def _truncate_output(self, raw_bytes: bytes, max_bytes: int) -> tuple[str, bool]:
        """Safely truncate output if it exceeds configured limit."""
        if len(raw_bytes) > max_bytes:
            truncated_bytes = raw_bytes[:max_bytes]
            text = truncated_bytes.decode("utf-8", errors="replace") + "\n[OUTPUT TRUNCATED]"
            return text, True
        return raw_bytes.decode("utf-8", errors="replace"), False
