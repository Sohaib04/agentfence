import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.api.schemas import ActionResponse, ActionStatus
from app.audit.models import AuditEvent, TaskRecord
from app.audit.redaction import redact_sensitive_payload
from app.audit.store import AuditStore
from app.executor.docker import CommandExecutor, DockerExecutor
from app.executor.models import CommandExecutionError, ContainerLimits
from app.policy.engine import PolicyEngine
from app.policy.models import ActionRequest, DecisionType, ReasonCode
from app.tools.files import ToolExecutionError, list_files, read_file, write_file


class ToolDispatcher:
    """Enforces that all tool invocations pass through policy evaluation."""

    def __init__(
        self,
        workspace_root: Path,
        policy_engine: PolicyEngine | None = None,
        executor: CommandExecutor | None = None,
        audit_store: AuditStore | None = None,
    ) -> None:
        self.workspace_root = workspace_root.resolve()
        self.policy_engine = policy_engine or PolicyEngine()
        self.executor = executor or DockerExecutor()
        self.audit_store = audit_store

    def dispatch(
        self, action: ActionRequest | dict[str, Any], task_id: str | None = None
    ) -> ActionResponse:
        """Route an action through policy validation and, if approved, to execution."""
        task_id = task_id or str(uuid.uuid4())
        start_time = time.monotonic()
        raw_args: dict[str, Any] = {}

        # Validate request structure
        if isinstance(action, dict):
            raw_args = (
                action.get("arguments", {}) if isinstance(action.get("arguments"), dict) else {}
            )
            try:
                action_req = ActionRequest.model_validate(action)
            except Exception:
                res = ActionResponse(
                    task_id=task_id,
                    tool=str(action.get("tool", "unknown")),
                    decision=DecisionType.DENY,
                    reason=ReasonCode.INVALID_ARGUMENTS,
                    policy_version=self.policy_engine.version,
                    status=ActionStatus.DENIED,
                    result=None,
                    error=None,
                )
                self._record_outcome(res, raw_args, time.monotonic() - start_time)
                return res
        elif isinstance(action, ActionRequest):
            action_req = action
            raw_args = action_req.arguments
        else:
            res = ActionResponse(
                task_id=task_id,
                tool="unknown",
                decision=DecisionType.DENY,
                reason=ReasonCode.INVALID_ARGUMENTS,
                policy_version=self.policy_engine.version,
                status=ActionStatus.DENIED,
                result=None,
                error=None,
            )
            self._record_outcome(res, raw_args, time.monotonic() - start_time)
            return res

        # 1. Deterministic Policy Evaluation (Choke Point)
        decision = self.policy_engine.evaluate(action_req, self.workspace_root)

        # 2. Denied by policy
        if decision.decision != DecisionType.ALLOW:
            res = ActionResponse(
                task_id=task_id,
                tool=action_req.tool,
                decision=decision.decision,
                reason=decision.reason,
                policy_version=decision.policy_version,
                status=ActionStatus.DENIED,
                result=None,
                error=None,
            )
            self._record_outcome(res, raw_args, time.monotonic() - start_time)
            return res

        # 3. Allowed: execute tool with sanitized arguments
        try:
            result, status = self._execute_tool(action_req.tool, decision.sanitized_arguments)
            error_msg = None
            if status == ActionStatus.TIMED_OUT:
                error_msg = "Command execution timed out"
            elif (
                status == ActionStatus.ERROR
                and isinstance(result, dict)
                and result.get("exit_code", 0) != 0
            ):
                error_msg = f"Command failed with exit code {result['exit_code']}"

            res = ActionResponse(
                task_id=task_id,
                tool=action_req.tool,
                decision=DecisionType.ALLOW,
                reason=decision.reason,
                policy_version=decision.policy_version,
                status=status,
                result=result,
                error=error_msg,
            )
            self._record_outcome(res, raw_args, time.monotonic() - start_time)
            return res
        except ToolExecutionError as e:
            safe_error = self._sanitize_error(str(e))
            res = ActionResponse(
                task_id=task_id,
                tool=action_req.tool,
                decision=DecisionType.ALLOW,
                reason=decision.reason,
                policy_version=decision.policy_version,
                status=ActionStatus.ERROR,
                result=None,
                error=safe_error,
            )
            self._record_outcome(res, raw_args, time.monotonic() - start_time)
            return res
        except CommandExecutionError as e:
            safe_error = self._sanitize_error(str(e))
            res = ActionResponse(
                task_id=task_id,
                tool=action_req.tool,
                decision=DecisionType.ALLOW,
                reason=decision.reason,
                policy_version=decision.policy_version,
                status=ActionStatus.ERROR,
                result=None,
                error=safe_error,
            )
            self._record_outcome(res, raw_args, time.monotonic() - start_time)
            return res
        except Exception:
            res = ActionResponse(
                task_id=task_id,
                tool=action_req.tool,
                decision=DecisionType.ALLOW,
                reason=decision.reason,
                policy_version=decision.policy_version,
                status=ActionStatus.ERROR,
                result=None,
                error="Internal tool execution error",
            )
            self._record_outcome(res, raw_args, time.monotonic() - start_time)
            return res

    def _record_outcome(
        self,
        response: ActionResponse,
        arguments: dict[str, Any],
        duration_seconds: float,
    ) -> None:
        """Persist task state and audit event if audit_store is configured."""
        if not self.audit_store:
            return

        now_iso = datetime.now(timezone.utc).isoformat()
        redacted_args = redact_sensitive_payload(arguments, tool_name=response.tool)
        redacted_result = (
            redact_sensitive_payload(response.result, tool_name=response.tool, is_result=True)
            if response.result
            else None
        )

        exit_code = None
        if isinstance(response.result, dict) and "exit_code" in response.result:
            exit_code = response.result["exit_code"]

        task_record = TaskRecord(
            task_id=response.task_id,
            created_at=now_iso,
            updated_at=now_iso,
            tool=response.tool,
            arguments=redacted_args if isinstance(redacted_args, dict) else {},
            decision=response.decision.value,
            reason=response.reason.value,
            policy_version=response.policy_version,
            status=response.status.value,
            exit_code=exit_code,
            result=redacted_result if isinstance(redacted_result, dict) else None,
            error=response.error,
            duration_seconds=round(duration_seconds, 3),
        )

        event_type = (
            "action_denied" if response.decision == DecisionType.DENY else "action_executed"
        )
        audit_event = AuditEvent(
            timestamp=now_iso,
            task_id=response.task_id,
            event_type=event_type,
            tool=response.tool,
            decision=response.decision.value,
            reason=response.reason.value,
            details={
                "status": response.status.value,
                "duration_seconds": round(duration_seconds, 3),
            },
        )

        try:
            self.audit_store.save_task(task_record)
            self.audit_store.record_event(audit_event)
        except Exception:
            # Audit failure must not crash dispatcher; fail closed / safe
            pass

    def _execute_tool(
        self, tool_name: str, sanitized_args: dict[str, Any]
    ) -> tuple[dict[str, Any], ActionStatus]:
        """Dispatch to internal tool implementations, returning (result_dict, status)."""
        if tool_name == "list_files":
            rel_path = sanitized_args.get("path", ".")
            return list_files(self.workspace_root, rel_path), ActionStatus.SUCCESS
        elif tool_name == "read_file":
            rel_path = sanitized_args["path"]
            tool_cfg = self.policy_engine.config.tools.get(tool_name)
            max_size = tool_cfg.max_size_bytes if tool_cfg else 1048576
            return read_file(self.workspace_root, rel_path, max_size), ActionStatus.SUCCESS
        elif tool_name == "write_file":
            rel_path = sanitized_args["path"]
            content = sanitized_args["content"]
            tool_cfg = self.policy_engine.config.tools.get(tool_name)
            max_size = tool_cfg.max_size_bytes if tool_cfg else 1048576
            return write_file(
                self.workspace_root, rel_path, content, max_size
            ), ActionStatus.SUCCESS
        elif tool_name == "run_command":
            cmd = sanitized_args["command"]
            args = sanitized_args.get("args", [])
            timeout = sanitized_args.get("timeout", 30)
            max_output = sanitized_args.get("max_output_bytes", 1048576)
            image = sanitized_args.get("sandbox_image")

            limits = ContainerLimits(
                timeout_seconds=timeout,
                max_output_bytes=max_output,
            )

            exec_res = self.executor.run(
                command=cmd,
                args=args,
                workspace_root=self.workspace_root,
                limits=limits,
                image=image,
            )

            if exec_res.timed_out:
                status = ActionStatus.TIMED_OUT
            elif exec_res.exit_code != 0:
                status = ActionStatus.ERROR
            else:
                status = ActionStatus.SUCCESS

            return exec_res.model_dump(), status
        else:
            raise ToolExecutionError(f"Unsupported tool: {tool_name}")

    def _sanitize_error(self, message: str) -> str:
        """Strip host workspace root from error messages to avoid leaking filesystem layout."""
        ws_str = str(self.workspace_root)
        if ws_str in message:
            return message.replace(ws_str, "<workspace>")
        return message
