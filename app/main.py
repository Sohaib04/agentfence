"""Main application entry point for AgentFence."""

from pathlib import Path

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.routes import router
from app.policy.engine import PolicyEngine
from app.tools.dispatcher import ToolDispatcher

# Maximum request body size allowed: 2 MB
MAX_REQUEST_BYTES = 2 * 1024 * 1024


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects requests exceeding the maximum allowed body size."""

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_REQUEST_BYTES:
                    # Use HTTP_413_CONTENT_TOO_LARGE (or 413)
                    return JSONResponse(
                        status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                        content={"detail": "Request body exceeds maximum allowed size (2MB)"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Invalid Content-Length header"},
                )

        return await call_next(request)


def create_app(
    workspace_root: Path | None = None,
    policy_engine: PolicyEngine | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AgentFence",
        description="Local security gateway mediating AI agent tool access",
        version="0.1.0",
        docs_url=None,  # Disabled by default for local security
        redoc_url=None,
    )

    app.add_middleware(RequestSizeLimitMiddleware)

    # Initialize workspace and dispatcher
    ws_path = (workspace_root or Path("workspace")).resolve()
    ws_path.mkdir(parents=True, exist_ok=True)

    app.state.workspace_root = ws_path
    app.state.dispatcher = ToolDispatcher(
        workspace_root=ws_path,
        policy_engine=policy_engine or PolicyEngine(),
    )

    app.include_router(router)

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> Response:
        """Prevent internal stack traces and server details from leaking to clients."""
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    # Enforce loopback binding
    uvicorn.run(app, host="127.0.0.1", port=8000)
