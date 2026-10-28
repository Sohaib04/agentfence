"""Data models for restricted command execution."""

from pydantic import BaseModel, Field


class ContainerLimits(BaseModel):
    """Resource and execution limits for the sandbox container."""

    cpu_quota: float = 1.0
    memory_limit: str = "256m"
    pids_limit: int = 64
    timeout_seconds: int = 30
    max_output_bytes: int = 1048576  # 1MB
    tmpfs_size: str = "64m"
    runtime: str | None = None


class ExecutionResult(BaseModel):
    """Result of running a command inside the restricted executor."""

    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False
    duration_seconds: float = 0.0
    container_id: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)


class CommandExecutionError(Exception):
    """Raised when container execution encounters an infrastructure error."""

    pass
