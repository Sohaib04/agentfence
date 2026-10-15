"""Pydantic schemas for AgentFence API."""

from enum import Enum
from typing import Any

from pydantic import BaseModel

from app.policy.models import DecisionType, ReasonCode


class ActionStatus(str, Enum):
    DENIED = "denied"
    SUCCESS = "success"
    ERROR = "error"
    TIMED_OUT = "timed_out"


class ActionResponse(BaseModel):
    task_id: str
    tool: str
    decision: DecisionType
    reason: ReasonCode
    policy_version: str
    status: ActionStatus
    result: dict[str, Any] | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
