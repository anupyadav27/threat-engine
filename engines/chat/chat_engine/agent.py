"""
Bedrock agentic loop for the chat engine.

Flow:
  1. Load last N messages from DB as conversation history
  2. Call Bedrock converse() in a tool loop (max 3 rounds)
  3. After tools complete, call converse_stream() for final answer
  4. Yield SSE-formatted strings: {"type":"thinking"} | {"type":"token","content":"..."} | {"type":"done"}
  5. Persist user + assistant messages to DB
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import date
from typing import Any, AsyncGenerator, Dict, List, Optional
from uuid import uuid4

import boto3
import psycopg2
import psycopg2.extras

from .tools import TOOL_CONFIG, execute_tool

logger = logging.getLogger("chat-engine.agent")

BEDROCK_REGION  = os.getenv("AWS_REGION", "ap-south-1")
BEDROCK_MODEL   = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")
MAX_TOOL_ROUNDS = 3
HISTORY_LIMIT   = 10  # last N message pairs to include as context

SYSTEM_PROMPT = """You are an AI security analyst for a Cloud Security Posture Management (CSPM) platform.
You help security stakeholders understand their cloud security posture by answering questions about findings, compliance scores, threat detections, network exposure, and resource configurations.

You have access to tools that query live data from the platform. Always use tools to get accurate, current data.

Guidelines:
- Respond in clear, plain English — no raw SQL, JSON blobs, or technical jargon
- Lead with the most important numbers (e.g. "You have 12 critical findings across 3 accounts")
- Highlight critical and high severity items prominently
- For lists, show the top 5-10 items and note if more exist
- Be concise — a good answer is 3-8 sentences with key data points
- If data is unavailable, say so clearly and suggest what to check

Context:
- Platform: CSPM (Cloud Security Posture Management)
- Tenant: {tenant_id}
- User role: {role}
- Today: {today}
- All data is automatically scoped to your tenant and permitted accounts"""


def _build_client() -> Any:
    return boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)


def _load_history(conn, session_id: str) -> List[Dict[str, Any]]:
    """Load last HISTORY_LIMIT messages as Bedrock message dicts."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT role, content FROM chat_messages
            WHERE session_id = %s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (session_id, HISTORY_LIMIT * 2),
        )
        rows = list(reversed(cur.fetchall()))

    messages = []
    for row in rows:
        messages.append({
            "role": row["role"],
            "content": [{"text": row["content"]}],
        })
    return messages


def _persist_message(
    conn,
    session_id: str,
    tenant_id: str,
    role: str,
    content: str,
    generated_query: Optional[str] = None,
    query_type: Optional[str] = None,
    latency_ms: Optional[int] = None,
    token_count: Optional[int] = None,
) -> str:
    message_id = str(uuid4())
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO chat_messages
                (message_id, session_id, tenant_id, role, content,
                 generated_query, query_type, latency_ms, token_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (message_id, session_id, tenant_id, role, content,
             generated_query, query_type, latency_ms, token_count),
        )
        # Bump session updated_at
        cur.execute(
            "UPDATE chat_sessions SET updated_at = NOW() WHERE session_id = %s",
            (session_id,),
        )
    conn.commit()
    return message_id


def _sse(event: Dict[str, Any]) -> str:
    return f"data: {json.dumps(event)}\n\n"


async def run_agent(
    user_message: str,
    tenant_id: str,
    user_id: str,
    role: str,
    account_ids: Optional[List[str]],
    session_id: str,
    inv_conn,
) -> AsyncGenerator[str, None]:
    """Agentic loop. Yields SSE strings."""
    bedrock = _build_client()
    t_start = time.monotonic()

    # Persist user message
    _persist_message(inv_conn, session_id, tenant_id, "user", user_message)

    # Build conversation
    history = _load_history(inv_conn, session_id)
    # The user message we just saved will appear in history on next load.
    # For this turn, build it explicitly so we don't double-count.
    # Filter history to exclude the message we just inserted.
    history = [m for m in history if not (
        m["role"] == "user" and
        m["content"][0]["text"] == user_message and
        history.index(m) == len(history) - 1
    )]
    messages = history + [{
        "role": "user",
        "content": [{"text": user_message}],
    }]

    system = [{"text": SYSTEM_PROMPT.format(
        tenant_id=tenant_id,
        role=role,
        today=date.today().isoformat(),
    )}]

    # ── Tool loop (non-streaming) ─────────────────────────────────────────────
    tool_rounds = 0
    all_queries: List[str] = []
    full_text = ""
    token_count = 0
    used_tools = False

    while tool_rounds < MAX_TOOL_ROUNDS:
        try:
            resp = bedrock.converse(
                modelId=BEDROCK_MODEL,
                system=system,
                messages=messages,
                toolConfig=TOOL_CONFIG,
                inferenceConfig={"maxTokens": 1024, "temperature": 0.1},
            )
        except Exception as exc:
            logger.error("Bedrock converse error: %s", exc)
            yield _sse({"type": "error", "detail": "AI service temporarily unavailable."})
            return

        stop_reason = resp.get("stopReason", "end_turn")
        out_msg = resp["output"]["message"]

        if stop_reason == "end_turn":
            # Extract text directly — don't append assistant msg then re-call stream
            for block in out_msg.get("content", []):
                if "text" in block:
                    chunk = block["text"]
                    full_text += chunk
                    yield _sse({"type": "token", "content": chunk})
            usage = resp.get("usage", {})
            token_count = usage.get("outputTokens", 0)
            break

        if stop_reason != "tool_use":
            break

        # Tool use round — execute tools and continue loop
        used_tools = True
        yield _sse({"type": "thinking"})
        messages.append(out_msg)

        tool_results = []
        for block in out_msg.get("content", []):
            if "toolUse" not in block:
                continue
            tool_use    = block["toolUse"]
            tool_name   = tool_use["name"]
            tool_input  = tool_use["input"]
            tool_use_id = tool_use["toolUseId"]

            all_queries.append(f"{tool_name}({json.dumps(tool_input)})")

            result = await execute_tool(
                tool_name, tool_input,
                tenant_id, account_ids, role, inv_conn,
            )
            tool_results.append({
                "toolResult": {
                    "toolUseId": tool_use_id,
                    "content": [{"text": json.dumps(result)}],
                }
            })

        messages.append({"role": "user", "content": tool_results})
        tool_rounds += 1

    # ── Streaming final answer (only when tool loop hit max rounds) ───────────
    if not full_text:
        try:
            stream_resp = bedrock.converse_stream(
                modelId=BEDROCK_MODEL,
                system=system,
                messages=messages,
                toolConfig=TOOL_CONFIG,
                inferenceConfig={"maxTokens": 1024, "temperature": 0.1},
            )
            for event in stream_resp["stream"]:
                if "contentBlockDelta" in event:
                    delta = event["contentBlockDelta"]["delta"]
                    if "text" in delta:
                        chunk = delta["text"]
                        full_text += chunk
                        yield _sse({"type": "token", "content": chunk})
                elif "metadata" in event:
                    usage = event["metadata"].get("usage", {})
                    token_count = usage.get("outputTokens", 0)
        except Exception as exc:
            logger.error("Bedrock stream error: %s", exc)
            if not full_text:
                yield _sse({"type": "error", "detail": "Streaming response failed."})
                return

    # Persist assistant message (rollback any aborted tool transaction first)
    try:
        inv_conn.rollback()
    except Exception:
        pass
    latency_ms = int((time.monotonic() - t_start) * 1000)
    query_log  = "; ".join(all_queries) if all_queries else None
    message_id = _persist_message(
        inv_conn, session_id, tenant_id, "assistant", full_text,
        generated_query=query_log,
        query_type="sql" if all_queries else "none",
        latency_ms=latency_ms,
        token_count=token_count,
    )

    yield _sse({"type": "done", "message_id": message_id, "latency_ms": latency_ms})
