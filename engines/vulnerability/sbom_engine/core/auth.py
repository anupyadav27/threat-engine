"""
API key authentication for SBOM Engine.
Accepts Bearer token or X-API-Key header.
"""

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader

from core.config import settings

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(token: str) -> str:
    if token and token in settings.API_KEYS:
        return token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key",
    )


async def get_current_user(
    bearer: HTTPAuthorizationCredentials = Security(bearer_scheme),
    api_key: str = Security(api_key_header),
) -> str:
    token = None
    if bearer:
        token = bearer.credentials
    elif api_key:
        token = api_key
    return verify_api_key(token)
