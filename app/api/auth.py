"""Local client authentication."""

import os

from fastapi import Header, HTTPException, status

DEFAULT_DEV_TOKEN = "agentfence-dev-token"


def get_expected_token() -> str:
    """Return the configured auth token from environment or fallback default for local dev."""
    return os.environ.get("AGENTFENCE_AUTH_TOKEN", DEFAULT_DEV_TOKEN)


def verify_auth_token(
    authorization: str | None = Header(default=None),
    x_agentfence_token: str | None = Header(default=None),
) -> str:
    """Verify local authentication token from either Authorization header or X-AgentFence-Token."""
    expected = get_expected_token()
    token = None

    if x_agentfence_token:
        token = x_agentfence_token
    elif authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        else:
            token = authorization

    if not token or token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid or missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token
