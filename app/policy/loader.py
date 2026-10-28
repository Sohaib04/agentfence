"""Policy configuration loader using standard library tomllib."""

import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # Fallback if Python < 3.11


class ToolConfig(BaseModel):
    enabled: bool = False
    approval_required: bool = False
    max_size_bytes: int = 1048576  # Default 1MB
    allowed_arguments: list[str] = Field(default_factory=list)
    allowed_commands: list[str] = Field(default_factory=list)
    max_timeout_seconds: int = 30
    max_output_bytes: int = 1048576
    sandbox_image: str = "agentfence-sandbox:0.1.0"
    sandbox_runtime: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class WorkspaceConfig(BaseModel):
    relative_root: str = "workspace"


class PolicyConfig(BaseModel):
    policy_version: str = "1.0.0"
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    tools: dict[str, ToolConfig] = Field(default_factory=dict)


def load_policy(policy_path: Path | str | None = None) -> PolicyConfig:
    """Load and parse policy from a TOML file.

    If policy_path is None, loads policies/default_policy.toml relative to workspace or project.
    """
    if policy_path is None:
        policy_path = (
            Path(__file__).resolve().parent.parent.parent / "policies" / "default_policy.toml"
        )
    else:
        policy_path = Path(policy_path)

    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    with open(policy_path, "rb") as f:
        raw_data = tomllib.load(f)

    # Convert nested tool dicts into ToolConfig models
    raw_tools = raw_data.get("tools", {})
    tools: dict[str, ToolConfig] = {}
    for tool_name, tool_data in raw_tools.items():
        if isinstance(tool_data, dict):
            standard_keys = {
                "enabled",
                "approval_required",
                "max_size_bytes",
                "allowed_arguments",
                "allowed_commands",
                "max_timeout_seconds",
                "max_output_bytes",
                "sandbox_image",
                "sandbox_runtime",
            }
            tools[tool_name] = ToolConfig(
                enabled=tool_data.get("enabled", False),
                approval_required=tool_data.get("approval_required", False),
                max_size_bytes=tool_data.get("max_size_bytes", 1048576),
                allowed_arguments=tool_data.get("allowed_arguments", []),
                allowed_commands=tool_data.get("allowed_commands", []),
                max_timeout_seconds=tool_data.get("max_timeout_seconds", 30),
                max_output_bytes=tool_data.get("max_output_bytes", 1048576),
                sandbox_image=tool_data.get("sandbox_image", "agentfence-sandbox:0.1.0"),
                sandbox_runtime=tool_data.get("sandbox_runtime"),
                extra={k: v for k, v in tool_data.items() if k not in standard_keys},
            )

    workspace_data = raw_data.get("workspace", {})
    workspace = WorkspaceConfig(relative_root=workspace_data.get("relative_root", "workspace"))

    return PolicyConfig(
        policy_version=str(raw_data.get("policy_version", "1.0.0")),
        workspace=workspace,
        tools=tools,
    )
