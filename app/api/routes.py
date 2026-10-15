"""API endpoints for AgentFence."""

from pathlib import Path

from fastapi import APIRouter, Depends, Request

from app.__init__ import __version__
from app.api.auth import verify_auth_token
from app.api.schemas import ActionResponse, HealthResponse
from app.policy.models import ActionRequest
from app.tools.dispatcher import ToolDispatcher

router = APIRouter()


def get_dispatcher(request: Request) -> ToolDispatcher:
    """Retrieve ToolDispatcher from application state or create default."""
    if hasattr(request.app.state, "dispatcher"):
        return request.app.state.dispatcher
    workspace_root = Path("workspace").resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    return ToolDispatcher(workspace_root=workspace_root)


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Minimal liveness check; does not run sandbox."""
    return HealthResponse(status="ok", version=__version__)


@router.post("/v1/actions", response_model=ActionResponse)
def handle_action(
    action: ActionRequest,
    _token: str = Depends(verify_auth_token),
    dispatcher: ToolDispatcher = Depends(get_dispatcher),
) -> ActionResponse:
    """Validate, authorize, and execute a requested tool action."""
    return dispatcher.dispatch(action)
