"""Policy data models and reason codes."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ReasonCode(str, Enum):
    ALLOWED = "allowed"
    UNKNOWN_TOOL = "unknown_tool"
    TOOL_DISABLED = "tool_disabled"
    INVALID_ARGUMENTS = "invalid_arguments"
    MISSING_ARGUMENT = "missing_argument"
    PATH_OUTSIDE_WORKSPACE = "path_outside_workspace"
    SYMLINK_ESCAPE = "symlink_escape"
    FILE_TOO_LARGE = "file_too_large"
    DISALLOWED_COMMAND = "disallowed_command"
    INTERNAL_ERROR = "internal_error"


class ActionRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    decision: DecisionType
    reason: ReasonCode
    policy_version: str
    sanitized_arguments: dict[str, Any] = Field(default_factory=dict)
