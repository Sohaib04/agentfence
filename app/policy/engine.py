"""Deterministic policy engine for AgentFence."""

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.policy.loader import PolicyConfig, load_policy
from app.policy.models import ActionRequest, DecisionType, PolicyDecision, ReasonCode
from app.policy.path_safety import validate_workspace_path


class PolicyEngine:
    """Deterministic, fail-closed authorization engine for tool actions."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or load_policy()

    @property
    def version(self) -> str:
        return self.config.policy_version

    def _deny(self, reason: ReasonCode, sanitized: dict[str, Any] | None = None) -> PolicyDecision:
        return PolicyDecision(
            decision=DecisionType.DENY,
            reason=reason,
            policy_version=self.version,
            sanitized_arguments=sanitized or {},
        )

    def _allow(
        self,
        reason: ReasonCode = ReasonCode.ALLOWED,
        sanitized: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=DecisionType.ALLOW,
            reason=reason,
            policy_version=self.version,
            sanitized_arguments=sanitized or {},
        )

    def evaluate(
        self, action: ActionRequest | dict[str, Any], workspace_root: Path
    ) -> PolicyDecision:
        """Evaluate an action request against the policy configuration and workspace root.

        Fail-closed: Any unhandled exception or parsing failure results in DENY.
        """
        try:
            if isinstance(action, dict):
                try:
                    action_req = ActionRequest.model_validate(action)
                except ValidationError:
                    return self._deny(ReasonCode.INVALID_ARGUMENTS)
            elif isinstance(action, ActionRequest):
                action_req = action
            else:
                return self._deny(ReasonCode.INVALID_ARGUMENTS)

            tool_name = action_req.tool
            args = action_req.arguments

            # Check if tool is known in policy configuration
            if tool_name not in self.config.tools:
                return self._deny(ReasonCode.UNKNOWN_TOOL)

            tool_cfg = self.config.tools[tool_name]
            if not tool_cfg.enabled:
                return self._deny(ReasonCode.TOOL_DISABLED)

            # Route to tool-specific deterministic evaluation
            if tool_name == "list_files":
                return self._evaluate_list_files(args, workspace_root, tool_cfg)
            elif tool_name == "read_file":
                return self._evaluate_read_file(args, workspace_root, tool_cfg)
            elif tool_name == "write_file":
                return self._evaluate_write_file(args, workspace_root, tool_cfg)
            else:
                # Any other tool not explicitly evaluated in Milestone 1 is denied
                return self._deny(ReasonCode.TOOL_DISABLED)

        except Exception:
            # Fails closed on any unexpected error
            return self._deny(ReasonCode.INTERNAL_ERROR)

    def _evaluate_list_files(
        self, args: dict[str, Any], workspace_root: Path, tool_cfg: Any
    ) -> PolicyDecision:
        path_arg = args.get("path", "")
        if path_arg is None:
            path_arg = ""

        if not isinstance(path_arg, str):
            return self._deny(ReasonCode.INVALID_ARGUMENTS)

        resolved_path, reason, relative_path = validate_workspace_path(
            workspace_root, path_arg, allow_empty=True
        )
        if reason is not None:
            return self._deny(reason)

        return self._allow(sanitized={"path": relative_path})

    def _evaluate_read_file(
        self, args: dict[str, Any], workspace_root: Path, tool_cfg: Any
    ) -> PolicyDecision:
        if "path" not in args:
            return self._deny(ReasonCode.MISSING_ARGUMENT)

        path_arg = args["path"]
        if not isinstance(path_arg, str):
            return self._deny(ReasonCode.INVALID_ARGUMENTS)

        resolved_path, reason, relative_path = validate_workspace_path(
            workspace_root, path_arg, allow_empty=False
        )
        if reason is not None:
            return self._deny(reason)

        # Check file size limit if file exists on disk
        if resolved_path and resolved_path.is_file():
            try:
                size = resolved_path.stat().st_size
                if size > tool_cfg.max_size_bytes:
                    return self._deny(ReasonCode.FILE_TOO_LARGE)
            except OSError:
                return self._deny(ReasonCode.INTERNAL_ERROR)

        return self._allow(sanitized={"path": relative_path})

    def _evaluate_write_file(
        self, args: dict[str, Any], workspace_root: Path, tool_cfg: Any
    ) -> PolicyDecision:
        if "path" not in args or "content" not in args:
            return self._deny(ReasonCode.MISSING_ARGUMENT)

        path_arg = args["path"]
        content_arg = args["content"]

        if not isinstance(path_arg, str) or not isinstance(content_arg, str):
            return self._deny(ReasonCode.INVALID_ARGUMENTS)

        # Check payload size
        content_bytes = content_arg.encode("utf-8")
        if len(content_bytes) > tool_cfg.max_size_bytes:
            return self._deny(ReasonCode.FILE_TOO_LARGE)

        resolved_path, reason, relative_path = validate_workspace_path(
            workspace_root, path_arg, allow_empty=False
        )
        if reason is not None:
            return self._deny(reason)

        return self._allow(sanitized={"path": relative_path, "content": content_arg})
