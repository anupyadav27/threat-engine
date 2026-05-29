"""
Chat Engine — AI Query Platform
Port 8036

Endpoints:
  POST /api/v1/chat/sessions                     — Create chat session
  GET  /api/v1/chat/sessions                     — List sessions for user
  POST /api/v1/chat/sessions/{session_id}/messages — Send message (SSE stream)
  GET  /api/v1/chat/quick-questions              — Fetch pre-seeded questions
  GET  /api/v1/health/live
  GET  /api/v1/health/ready
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from uuid import uuid4

import psycopg2
import psycopg2.extras
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from engine_common.db_connections import get_di_conn

try:
    from engine_auth.fastapi.middleware import AuthMiddleware
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH = True
except ImportError:
    _AUTH = False
    AuthContext = None  # type: ignore[assignment,misc]

from chat_engine.agent import run_agent

logger = logging.getLogger("chat-engine")

# ── App lifespan ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Chat engine starting on port 8036")
    yield
    logger.info("Chat engine shutting down")


app = FastAPI(
    title="Chat Engine",
    description="AI Query Platform for CSPM — AWS Bedrock agentic interface",
    version="1.0.0",
    lifespan=lifespan,
)

if _AUTH:
    app.add_middleware(AuthMiddleware)


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _get_auth_ctx(request: Request) -> Optional[Any]:
    raw = request.headers.get("X-Auth-Context")
    if not raw or not _AUTH:
        return None
    try:
        return AuthContext.from_dict(json.loads(raw))
    except Exception:
        return None


def _resolve_tenant(request: Request) -> str:
    ctx = _get_auth_ctx(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    if ctx.engine_tenant_id:
        return ctx.engine_tenant_id
    if ctx.tenant_ids:
        return ctx.tenant_ids[0]
    raise HTTPException(status_code=400, detail="No active tenant in session")


def _resolve_user(request: Request) -> str:
    ctx = _get_auth_ctx(request)
    if ctx and ctx.user_id:
        return str(ctx.user_id)
    return "anonymous"


def _resolve_role(request: Request) -> str:
    ctx = _get_auth_ctx(request)
    if ctx and ctx.role:
        return ctx.role
    return "viewer"


def _resolve_accounts(request: Request) -> Optional[List[str]]:
    ctx = _get_auth_ctx(request)
    if ctx:
        return ctx.account_ids
    return None


# ── Pydantic models ───────────────────────────────────────────────────────────

class CreateSessionRequest(BaseModel):
    title: Optional[str] = "New Chat"


class SendMessageRequest(BaseModel):
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/api/v1/chat/sessions")
async def create_session(
    body: CreateSessionRequest,
    request: Request,
    _: Any = Depends(require_permission("discoveries:read")) if _AUTH else Depends(lambda: None),
):
    tenant_id = _resolve_tenant(request)
    user_id   = _resolve_user(request)
    session_id = str(uuid4())

    conn = get_di_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO chat_sessions (session_id, tenant_id, user_id, title)
                VALUES (%s, %s, %s, %s)
                """,
                (session_id, tenant_id, user_id, body.title or "New Chat"),
            )
        conn.commit()
    finally:
        conn.close()

    return {"session_id": session_id, "title": body.title or "New Chat"}


@app.get("/api/v1/chat/sessions")
async def list_sessions(
    request: Request,
    limit: int = Query(default=20, le=50),
    _: Any = Depends(require_permission("discoveries:read")) if _AUTH else Depends(lambda: None),
):
    tenant_id = _resolve_tenant(request)
    user_id   = _resolve_user(request)

    conn = get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT s.session_id, s.title, s.created_at, s.updated_at,
                       COUNT(m.message_id) AS message_count
                FROM chat_sessions s
                LEFT JOIN chat_messages m ON m.session_id = s.session_id
                WHERE s.tenant_id = %s AND s.user_id = %s
                GROUP BY s.session_id
                ORDER BY s.updated_at DESC
                LIMIT %s
                """,
                (tenant_id, user_id, limit),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    sessions = []
    for r in rows:
        sessions.append({
            "session_id":    str(r["session_id"]),
            "title":         r["title"],
            "message_count": int(r["message_count"]),
            "created_at":    r["created_at"].isoformat(),
            "updated_at":    r["updated_at"].isoformat(),
        })

    return {"sessions": sessions}


@app.get("/api/v1/chat/sessions/{session_id}/messages")
async def get_messages(
    session_id: str,
    request: Request,
    _: Any = Depends(require_permission("discoveries:read")) if _AUTH else Depends(lambda: None),
):
    tenant_id = _resolve_tenant(request)

    conn = get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Verify session belongs to tenant
            cur.execute(
                "SELECT session_id FROM chat_sessions WHERE session_id = %s AND tenant_id = %s",
                (session_id, tenant_id),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Session not found")

            cur.execute(
                """
                SELECT message_id, role, content, created_at
                FROM chat_messages
                WHERE session_id = %s
                ORDER BY created_at
                """,
                (session_id,),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    messages = [
        {
            "message_id": str(r["message_id"]),
            "role":       r["role"],
            "content":    r["content"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]
    return {"messages": messages}


@app.post("/api/v1/chat/sessions/{session_id}/messages")
async def send_message(
    session_id: str,
    body: SendMessageRequest,
    request: Request,
    _: Any = Depends(require_permission("discoveries:read")) if _AUTH else Depends(lambda: None),
):
    if not body.message or not body.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    tenant_id   = _resolve_tenant(request)
    user_id     = _resolve_user(request)
    role        = _resolve_role(request)
    account_ids = _resolve_accounts(request)

    conn = get_di_conn()

    # Verify session ownership
    with conn.cursor() as cur:
        cur.execute(
            "SELECT session_id FROM chat_sessions WHERE session_id = %s AND tenant_id = %s",
            (session_id, tenant_id),
        )
        if not cur.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="Session not found")

    async def event_stream():
        try:
            async for chunk in run_agent(
                user_message=body.message.strip(),
                tenant_id=tenant_id,
                user_id=user_id,
                role=role,
                account_ids=account_ids,
                session_id=session_id,
                di_conn=conn,
            ):
                yield chunk
        finally:
            conn.close()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/v1/chat/quick-questions")
async def get_quick_questions(
    request: Request,
    category: Optional[str] = Query(default=None),
    _: Any = Depends(require_permission("discoveries:read")) if _AUTH else Depends(lambda: None),
):
    conn = get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if category:
                cur.execute(
                    """
                    SELECT id, category, question_text, description, min_role_level, sort_order
                    FROM quick_questions
                    WHERE is_active = TRUE AND category = %s
                    ORDER BY sort_order
                    """,
                    (category,),
                )
            else:
                cur.execute(
                    """
                    SELECT id, category, question_text, description, min_role_level, sort_order
                    FROM quick_questions
                    WHERE is_active = TRUE
                    ORDER BY category, sort_order
                    """
                )
            rows = cur.fetchall()
    finally:
        conn.close()

    # Group by category
    grouped: Dict[str, List[Dict]] = {}
    for r in rows:
        cat = r["category"]
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append({
            "id":            r["id"],
            "question_text": r["question_text"],
            "description":   r["description"],
        })

    return {"categories": grouped}


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health/live")
async def health_live():
    return {"status": "ok"}


@app.get("/api/v1/health/ready")
async def health_ready():
    try:
        conn = get_di_conn()
        conn.close()
        return {"status": "ok"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_server:app", host="0.0.0.0", port=8036, reload=False)
