"""Data models for task persistence and audit events."""

from typing import Any

from pydantic import BaseModel, Field


class TaskRecord(BaseModel):
    """Represents the persisted lifecycle and outcome of a task."""

    task_id: str
    created_at: str
    updated_at: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    decision: str
    reason: str
    policy_version: str
    status: str
    exit_code: int | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    duration_seconds: float | None = None


class AuditEvent(BaseModel):
    """Represents an immutable recorded audit event for tracking and compliance."""

    id: int | None = None
    timestamp: str
    task_id: str
    event_type: str
    tool: str
    decision: str
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)
