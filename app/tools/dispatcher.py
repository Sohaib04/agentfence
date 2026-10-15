"""Tool dispatcher: single choke point routing approved actions to tool implementations."""

import uuid
from pathlib import Path
from typing import Any

from app.api.schemas import ActionResponse, ActionStatus
from app.policy.engine import PolicyEngine
from app.policy.models import ActionRequest, DecisionType, ReasonCode
from app.tools.files import ToolExecutionError, list_files, read_file, write_file


class ToolDispatcher:
    """Enforces that all tool invocations pass through policy evaluation."""

    def __init__(self, workspace_root: Path, policy_engine: PolicyEngine | None = None) -> None:
        self.workspace_root = workspace_root.resolve()
        self.policy_engine = policy_engine or PolicyEngine()

    def dispatch(
        self, action: ActionRequest | dict[str, Any], task_id: str | None = None
    ) -> ActionResponse:
        """Route an action through policy validation and, if approved, to execution."""
        task_id = task_id or str(uuid.uuid4())

        # Validate request structure
        if isinstance(action, dict):
            try:
                action_req = ActionRequest.model_validate(action)
            except Exception:
                return ActionResponse(
                    task_id=task_id,
                    tool=str(action.get("tool", "unknown")),
                    decision=DecisionType.DENY,
                    reason=ReasonCode.INVALID_ARGUMENTS,
                    policy_version=self.policy_engine.version,
                    status=ActionStatus.DENIED,
                    result=None,
                    error=None,
                )
        elif isinstance(action, ActionRequest):
            action_req = action
        else:
            return ActionResponse(
                task_id=task_id,
                tool="unknown",
                decision=DecisionType.DENY,
                reason=ReasonCode.INVALID_ARGUMENTS,
                policy_version=self.policy_engine.version,
                status=ActionStatus.DENIED,
                result=None,
                error=None,
            )

        # 1. Deterministic Policy Evaluation (Choke Point)
        decision = self.policy_engine.evaluate(action_req, self.workspace_root)

        # 2. Denied by policy
        if decision.decision != DecisionType.ALLOW:
            return ActionResponse(
                task_id=task_id,
                tool=action_req.tool,
                decision=decision.decision,
                reason=decision.reason,
                policy_version=decision.policy_version,
                status=ActionStatus.DENIED,
                result=None,
                error=None,
            )

        # 3. Allowed: execute tool with sanitized arguments
        try:
            result = self._execute_tool(action_req.tool, decision.sanitized_arguments)
            return ActionResponse(
                task_id=task_id,
                tool=action_req.tool,
                decision=DecisionType.ALLOW,
                reason=decision.reason,
                policy_version=decision.policy_version,
                status=ActionStatus.SUCCESS,
                result=result,
                error=None,
            )
        except ToolExecutionError as e:
            # Safe domain error without leaking host root paths
            safe_error = self._sanitize_error(str(e))
            return ActionResponse(
                task_id=task_id,
                tool=action_req.tool,
                decision=DecisionType.ALLOW,
                reason=decision.reason,
                policy_version=decision.policy_version,
                status=ActionStatus.ERROR,
                result=None,
                error=safe_error,
            )
        except Exception:
            # Fallback for unexpected errors
            return ActionResponse(
                task_id=task_id,
                tool=action_req.tool,
                decision=DecisionType.ALLOW,
                reason=decision.reason,
                policy_version=decision.policy_version,
                status=ActionStatus.ERROR,
                result=None,
                error="Internal tool execution error",
            )

    def _execute_tool(self, tool_name: str, sanitized_args: dict[str, Any]) -> dict[str, Any]:
        """Dispatch to internal tool implementations."""
        if tool_name == "list_files":
            rel_path = sanitized_args.get("path", ".")
            return list_files(self.workspace_root, rel_path)
        elif tool_name == "read_file":
            rel_path = sanitized_args["path"]
            tool_cfg = self.policy_engine.config.tools.get(tool_name)
            max_size = tool_cfg.max_size_bytes if tool_cfg else 1048576
            return read_file(self.workspace_root, rel_path, max_size)
        elif tool_name == "write_file":
            rel_path = sanitized_args["path"]
            content = sanitized_args["content"]
            tool_cfg = self.policy_engine.config.tools.get(tool_name)
            max_size = tool_cfg.max_size_bytes if tool_cfg else 1048576
            return write_file(self.workspace_root, rel_path, content, max_size)
        else:
            raise ToolExecutionError(f"Unsupported tool: {tool_name}")

    def _sanitize_error(self, message: str) -> str:
        """Strip host workspace root from error messages to avoid leaking filesystem layout."""
        ws_str = str(self.workspace_root)
        if ws_str in message:
            return message.replace(ws_str, "<workspace>")
        return message
