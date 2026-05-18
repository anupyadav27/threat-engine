"""BFF view: /chat/* endpoints

Thin BFF layer — delegates to engine-chat for session management and
quick questions. The streaming message endpoint is proxied directly so
SSE flows through without buffering.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx
from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse, JSONResponse

from ._auth import resolve_tenant_id
from ._shared import ENGINE_URLS

logger = logging.getLogger("api-gateway.bff.chat")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

CHAT_URL = ENGINE_URLS.get("chat", "http://engine-chat:8036")


def _fwd_headers(request: Request) -> dict:
    auth = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    active_tenant = request.headers.get("X-Active-Tenant-Id")
    h = {}
    if auth:
        h["X-Auth-Context"] = auth
    if active_tenant:
        h["X-Active-Tenant-Id"] = active_tenant
    return h


@router.post("/chat/sessions")
async def create_chat_session(request: Request):
    body = await request.json()
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{CHAT_URL}/api/v1/chat/sessions",
            json=body,
            headers=_fwd_headers(request),
        )
    return JSONResponse(content=resp.json(), status_code=resp.status_code)


@router.get("/chat/sessions")
async def list_chat_sessions(
    request: Request,
    limit: int = Query(default=20, le=50),
):
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{CHAT_URL}/api/v1/chat/sessions",
            params={"limit": limit},
            headers=_fwd_headers(request),
        )
    return JSONResponse(content=resp.json(), status_code=resp.status_code)


@router.get("/chat/sessions/{session_id}/messages")
async def get_session_messages(session_id: str, request: Request):
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{CHAT_URL}/api/v1/chat/sessions/{session_id}/messages",
            headers=_fwd_headers(request),
        )
    return JSONResponse(content=resp.json(), status_code=resp.status_code)


@router.post("/chat/sessions/{session_id}/messages")
async def send_chat_message(session_id: str, request: Request):
    """Proxy SSE stream from chat engine to browser."""
    body = await request.body()

    async def _proxy():
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                f"{CHAT_URL}/api/v1/chat/sessions/{session_id}/messages",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    **_fwd_headers(request),
                },
            ) as upstream:
                async for chunk in upstream.aiter_bytes():
                    yield chunk

    return StreamingResponse(
        _proxy(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/chat/quick-questions")
async def get_quick_questions(
    request: Request,
    category: Optional[str] = Query(default=None),
):
    params = {}
    if category:
        params["category"] = category
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{CHAT_URL}/api/v1/chat/quick-questions",
            params=params,
            headers=_fwd_headers(request),
        )
    return JSONResponse(content=resp.json(), status_code=resp.status_code)
