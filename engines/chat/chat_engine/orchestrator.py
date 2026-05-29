"""
Multi-agent orchestrator for the chat engine.

Flow:
  1. Orchestrator (Bedrock call #1) decides which specialist(s) to consult
  2. Each specialist runs its own Bedrock call with domain-specific tools
  3. Orchestrator synthesizes all specialist outputs into a final answer
  4. Streams SSE back to the user

SSE event types:
  {"type": "thinking", "content": "Consulting IAM specialist..."}
  {"type": "specialist_result", "domain": "iam", "summary": "..."}
  {"type": "token", "content": "..."}
  {"type": "done", "message_id": "...", "latency_ms": ...}
  {"type": "error", "detail": "..."}
"""

from __future__ import annotations

import asyncio
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

from .specialists import (
    AISecuritySpecialist,
    CDRSpecialist,
    ComplianceSpecialist,
    ContainerSpecialist,
    DataSecSpecialist,
    DBSecSpecialist,
    EncryptionSpecialist,
    FindingsSpecialist,
    IAMSpecialist,
    InventorySpecialist,
    NetworkSpecialist,
    RiskSpecialist,
    ThreatSpecialist,
    VulnerabilitySpecialist,
)

logger = logging.getLogger("chat-engine.orchestrator")

BEDROCK_REGION = os.getenv("AWS_REGION", "ap-south-1")
BEDROCK_MODEL  = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
MAX_TOOL_ROUNDS = 4  # orchestrator can call up to 4 specialists
HISTORY_LIMIT   = 8

# ── Specialist registry ────────────────────────────────────────────────────────

_SPECIALIST_CLASSES = {
    "findings_analyst":    FindingsSpecialist,
    "compliance_analyst":  ComplianceSpecialist,
    "iam_analyst":         IAMSpecialist,
    "network_analyst":     NetworkSpecialist,
    "vulnerability_analyst": VulnerabilitySpecialist,
    "threat_analyst":      ThreatSpecialist,
    "datasec_analyst":     DataSecSpecialist,
    "risk_analyst":        RiskSpecialist,
    "inventory_analyst":   InventorySpecialist,
    "dbsec_analyst":       DBSecSpecialist,
    "container_analyst":   ContainerSpecialist,
    "encryption_analyst":  EncryptionSpecialist,
    "cdr_analyst":         CDRSpecialist,
    "ai_security_analyst": AISecuritySpecialist,
}

_SPECIALIST_DESCRIPTIONS = {
    "findings_analyst":      "Cross-engine security findings — severity breakdowns, top issues across all cloud security engines",
    "compliance_analyst":    "Compliance framework scores — CIS, NIST, PCI-DSS, ISO 27001, HIPAA, GDPR, SOC 2, FedRAMP pass/fail rates",
    "iam_analyst":           "IAM posture — users without MFA, wildcard policies, admin roles, privilege escalation, cross-account access, stale keys",
    "network_analyst":       "Network exposure — publicly accessible resources, security groups, VPC topology, WAF coverage, exposed attack paths",
    "vulnerability_analyst": "CVE and vulnerability management — CVSS scores, EPSS exploit probability, CISA KEV (known exploited), SBOM",
    "threat_analyst":        "Attack paths and MITRE ATT&CK — crown jewel assets, blast radius, choke points, technique mappings",
    "datasec_analyst":       "Data security — PII exposure, S3 misconfigurations, unencrypted data stores, classification, exfiltration paths",
    "risk_analyst":          "Risk quantification — FAIR model scores, blast radius, dollar exposure, exploitable exposed resources",
    "inventory_analyst":     "Asset inventory — resource counts by type/provider/region, discovery coverage, cloud accounts, drift detection",
    "dbsec_analyst":         "Database security — RDS/Aurora/DynamoDB posture, unencrypted DBs, audit logging, authentication issues",
    "container_analyst":     "Container and K8s security — privileged containers, image CVEs, K8s RBAC, network policies, ECR scanning",
    "encryption_analyst":    "Encryption posture — KMS coverage, certificate validity/expiry, TLS versions, in-transit and at-rest gaps",
    "cdr_analyst":           "Cloud Detection & Response — active threat actors, MITRE tactic detections, behavioral anomalies, incident indicators",
    "ai_security_analyst":   "AI/ML security — SageMaker/Bedrock exposure, shadow AI services, model access controls, training data PII",
}

# ── Orchestrator system prompt ─────────────────────────────────────────────────

_ORCHESTRATOR_SYSTEM = """You are a Security Command Center AI for a Cloud Security Posture Management (CSPM) platform.
You coordinate specialized security analysts to answer user questions about cloud security.

Your approach:
1. Read the user's question carefully
2. Call ONLY the most relevant specialist(s) — typically 1-3 for a focused question, up to 4 for broad overviews
3. Each specialist performs their own deep analysis using live platform data
4. Synthesize their results into a clear, concise, actionable answer

Available specialists:
{specialist_list}

Guidelines for routing:
- "findings" or "issues" → findings_analyst (general), or specific engine analyst if named
- "compliance" / framework names (CIS, NIST, PCI) → compliance_analyst
- "IAM" / "MFA" / "access key" / "role" / "identity" → iam_analyst
- "network" / "exposed" / "public" / "VPC" / "security group" → network_analyst
- "CVE" / "vulnerability" / "patch" / "exploit" → vulnerability_analyst
- "attack path" / "blast radius" / "crown jewel" / "MITRE" → threat_analyst
- "data" / "PII" / "S3" / "classification" / "encryption" → datasec_analyst + encryption_analyst
- "risk" / "dollar" / "exposure score" → risk_analyst
- "inventory" / "how many resources" / "accounts" → inventory_analyst
- "database" / "RDS" / "DynamoDB" → dbsec_analyst
- "container" / "K8s" / "EKS" / "Docker" → container_analyst
- "certificate" / "TLS" / "KMS" → encryption_analyst
- "detection" / "threat actor" / "suspicious" / "behavioral" → cdr_analyst
- "AI" / "SageMaker" / "Bedrock" / "ML" → ai_security_analyst

Context:
- Tenant: {tenant_id}
- User role: {role}
- Today: {today}
- All data is automatically scoped to tenant and permitted accounts"""

# ── Delegate tool config ───────────────────────────────────────────────────────

def _build_delegate_tools() -> Dict:
    tools = []
    for name, desc in _SPECIALIST_DESCRIPTIONS.items():
        tools.append({
            "toolSpec": {
                "name": name,
                "description": f"Consult the {name.replace('_', ' ')} specialist. {desc}",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "question": {
                                "type": "string",
                                "description": "The specific question for this specialist to answer using live platform data.",
                            }
                        },
                        "required": ["question"],
                    }
                },
            }
        })
    return {"tools": tools}


_DELEGATE_TOOL_CONFIG = _build_delegate_tools()


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _load_history(conn, session_id: str) -> List[Dict]:
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
    return [{"role": r["role"], "content": [{"text": r["content"]}]} for r in rows]


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
        cur.execute(
            "UPDATE chat_sessions SET updated_at = NOW() WHERE session_id = %s",
            (session_id,),
        )
    conn.commit()
    return message_id


def _sse(event: Dict) -> str:
    return f"data: {json.dumps(event)}\n\n"


# ── Specialist runner ──────────────────────────────────────────────────────────

def _run_specialist(
    tool_name: str,
    question: str,
    bedrock_client: Any,
    tenant_id: str,
    account_ids: Optional[List[str]],
    role: str,
    di_conn: Any,
) -> Dict:
    """Instantiate the named specialist and run it. Blocking."""
    cls = _SPECIALIST_CLASSES.get(tool_name)
    if cls is None:
        return {"domain": tool_name, "answer": f"Unknown specialist: {tool_name}", "data": {}}
    specialist = cls(bedrock_client, tenant_id, account_ids, role, di_conn)
    return specialist.run(question)


# ── Main entry point ───────────────────────────────────────────────────────────

async def run_agent(
    user_message: str,
    tenant_id: str,
    user_id: str,
    role: str,
    account_ids: Optional[List[str]],
    session_id: str,
    di_conn: Any,
) -> AsyncGenerator[str, None]:
    """Multi-agent orchestrator. Yields SSE strings."""
    bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
    t_start = time.monotonic()

    # Persist user message
    _persist_message(di_conn, session_id, tenant_id, "user", user_message)

    # Build conversation history
    history = _load_history(di_conn, session_id)
    history = [
        m for m in history
        if not (
            m["role"] == "user"
            and m["content"][0]["text"] == user_message
            and history.index(m) == len(history) - 1
        )
    ]
    messages = history + [{"role": "user", "content": [{"text": user_message}]}]

    specialist_list = "\n".join(
        f"  - {name}: {desc}"
        for name, desc in _SPECIALIST_DESCRIPTIONS.items()
    )
    system = [{"text": _ORCHESTRATOR_SYSTEM.format(
        specialist_list=specialist_list,
        tenant_id=tenant_id,
        role=role,
        today=date.today().isoformat(),
    )}]

    # ── Orchestrator tool loop ────────────────────────────────────────────────
    full_text = ""
    token_count = 0
    specialists_called: List[str] = []

    for round_num in range(MAX_TOOL_ROUNDS + 1):
        try:
            resp = bedrock.converse(
                modelId=BEDROCK_MODEL,
                system=system,
                messages=messages,
                toolConfig=_DELEGATE_TOOL_CONFIG,
                inferenceConfig={"maxTokens": 2048, "temperature": 0.1},
            )
        except Exception as exc:
            logger.error("Orchestrator Bedrock error: %s", exc)
            yield _sse({"type": "error", "detail": "AI service temporarily unavailable."})
            return

        stop_reason = resp.get("stopReason", "end_turn")
        out_msg = resp["output"]["message"]

        if stop_reason == "end_turn":
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

        messages.append(out_msg)
        tool_results = []

        for block in out_msg.get("content", []):
            if "toolUse" not in block:
                continue
            tu = block["toolUse"]
            specialist_name = tu["name"]
            question_for_specialist = tu["input"].get("question", user_message)
            tool_use_id = tu["toolUseId"]

            # Notify UI which specialist is being consulted
            display_name = specialist_name.replace("_", " ").title()
            yield _sse({"type": "thinking", "content": f"Consulting {display_name}..."})
            specialists_called.append(specialist_name)

            # Run specialist in thread pool (blocking Bedrock + DB calls)
            try:
                result = await asyncio.to_thread(
                    _run_specialist,
                    specialist_name,
                    question_for_specialist,
                    bedrock,
                    tenant_id,
                    account_ids,
                    role,
                    di_conn,
                )
            except Exception as exc:
                logger.warning("Specialist %s failed: %s", specialist_name, exc)
                result = {"domain": specialist_name, "answer": f"Specialist error: {exc}", "data": {}}

            # Surface specialist summary as a streaming hint to the user
            if result.get("answer"):
                yield _sse({
                    "type": "specialist_result",
                    "domain": result["domain"],
                    "summary": result["answer"][:200],  # short preview
                })

            tool_results.append({
                "toolResult": {
                    "toolUseId": tool_use_id,
                    "content": [{"text": json.dumps(result, default=str)}],
                }
            })

        messages.append({"role": "user", "content": tool_results})

    # ── Fallback streaming if tool loop exhausted without final answer ────────
    if not full_text:
        try:
            stream_resp = bedrock.converse_stream(
                modelId=BEDROCK_MODEL,
                system=system,
                messages=messages,
                toolConfig=_DELEGATE_TOOL_CONFIG,
                inferenceConfig={"maxTokens": 2048, "temperature": 0.1},
            )
            for event in stream_resp["stream"]:
                if "contentBlockDelta" in event:
                    delta = event["contentBlockDelta"]["delta"]
                    if "text" in delta:
                        chunk = delta["text"]
                        full_text += chunk
                        yield _sse({"type": "token", "content": chunk})
                elif "metadata" in event:
                    token_count = event["metadata"].get("usage", {}).get("outputTokens", 0)
        except Exception as exc:
            logger.error("Orchestrator stream error: %s", exc)
            if not full_text:
                yield _sse({"type": "error", "detail": "Streaming response failed."})
                return

    # ── Persist assistant message ─────────────────────────────────────────────
    try:
        di_conn.rollback()
    except Exception:
        pass

    latency_ms = int((time.monotonic() - t_start) * 1000)
    query_log  = "; ".join(specialists_called) if specialists_called else None
    message_id = _persist_message(
        di_conn, session_id, tenant_id, "assistant", full_text,
        generated_query=query_log,
        query_type="multi_agent" if specialists_called else "none",
        latency_ms=latency_ms,
        token_count=token_count,
    )

    yield _sse({"type": "done", "message_id": message_id, "latency_ms": latency_ms})
