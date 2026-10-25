"""API endpoints for AgentFence."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from app.__init__ import __version__
from app.api.auth import verify_auth_token
from app.api.schemas import ActionResponse, ActionStatus, HealthResponse
from app.policy.models import ActionRequest, DecisionType
from app.tools.dispatcher import ToolDispatcher

router = APIRouter()


def get_dispatcher(request: Request) -> ToolDispatcher:
    """Retrieve ToolDispatcher from application state or create default."""
    if hasattr(request.app.state, "dispatcher"):
        return request.app.state.dispatcher
    workspace_root = Path("workspace").resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    from app.audit.store import AuditStore

    store = getattr(request.app.state, "audit_store", None) or AuditStore()
    return ToolDispatcher(workspace_root=workspace_root, audit_store=store)


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Minimal liveness check; does not run sandbox."""
    return HealthResponse(status="ok", version=__version__)


@router.post(
    "/v1/actions",
    response_model=ActionResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {
            "model": ActionResponse,
            "description": "Action executed synchronously or denied by policy",
        },
        status.HTTP_202_ACCEPTED: {
            "model": ActionResponse,
            "description": "Action accepted for asynchronous background execution",
        },
    },
)
def handle_action(
    action: ActionRequest,
    response: Response,
    async_query: bool | None = Query(default=None, alias="async"),
    _token: str = Depends(verify_auth_token),
    dispatcher: ToolDispatcher = Depends(get_dispatcher),
) -> ActionResponse:
    """Validate, authorize, and execute a requested tool action."""
    is_async = async_query if async_query is not None else action.async_exec
    result = dispatcher.dispatch(action, is_async=is_async)
    if is_async and result.decision == DecisionType.ALLOW and result.status == ActionStatus.PENDING:
        response.status_code = status.HTTP_202_ACCEPTED
    return result


@router.get("/v1/tasks/{task_id}", response_model=dict[str, Any])
def get_task(
    task_id: str,
    _token: str = Depends(verify_auth_token),
    dispatcher: ToolDispatcher = Depends(get_dispatcher),
) -> dict[str, Any]:
    """Retrieve task state and outcome (404 for unknown task ID)."""
    if not dispatcher.audit_store:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Audit store not configured",
        )

    task = dispatcher.audit_store.get_task(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task not found: {task_id}",
        )

    return task.model_dump()


@router.get("/v1/audit", response_model=dict[str, Any])
def get_audit(
    limit: int = 50,
    offset: int = 0,
    _token: str = Depends(verify_auth_token),
    dispatcher: ToolDispatcher = Depends(get_dispatcher),
) -> dict[str, Any]:
    """Inspect recorded decisions and audit results (dev/demo inspection)."""
    if not dispatcher.audit_store:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Audit store not configured",
        )

    eff_limit = max(1, min(limit, 200))
    eff_offset = max(0, offset)
    events = dispatcher.audit_store.list_events(limit=eff_limit, offset=eff_offset)
    return {
        "events": [e.model_dump() for e in events],
        "count": len(events),
        "limit": eff_limit,
        "offset": eff_offset,
    }
