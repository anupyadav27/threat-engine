"""
Legacy tools module — replaced by the multi-agent orchestrator.
The orchestrator in orchestrator.py manages all tool routing.
Individual specialist tools live in specialists/*.py.

Each function maps to a Bedrock tool definition. All queries are:
  - Scoped to tenant_id (mandatory, injected server-side)
  - Account-filtered when account_ids is not None
  - Read-only (SELECT only)
  - Result-capped at 50 rows
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx
import psycopg2
import psycopg2.extras

logger = logging.getLogger("chat-engine.tools")

COMPLIANCE_URL = os.getenv("COMPLIANCE_ENGINE_URL", "http://engine-compliance")
ONBOARDING_URL = os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding")

# ── Bedrock tool definitions ───────────────────────────────────────────────────

TOOL_CONFIG = {
    "tools": [
        {
            "toolSpec": {
                "name": "get_findings_summary",
                "description": (
                    "Query security findings. Returns counts and top items from the unified "
                    "security_findings table. Use this for questions about findings, "
                    "vulnerabilities, misconfigurations, threats, or any security issues."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "severity": {
                                "type": "string",
                                "enum": ["critical", "high", "medium", "low", "info"],
                                "description": "Filter by severity level. Omit to get all severities.",
                            },
                            "engine": {
                                "type": "string",
                                "enum": [
                                    "check", "iam", "network", "datasec", "vuln", "cdr",
                                    "container", "dbsec", "encryption", "ai_security",
                                    "secops", "compliance",
                                ],
                                "description": "Filter by source engine. Omit for all engines.",
                            },
                            "account_id": {
                                "type": "string",
                                "description": "Filter by specific cloud account ID.",
                            },
                            "days": {
                                "type": "integer",
                                "description": "Only return findings from the last N days. Omit for all time.",
                                "minimum": 1,
                                "maximum": 365,
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max rows to return for top-N queries. Default 10, max 50.",
                                "minimum": 1,
                                "maximum": 50,
                            },
                        },
                        "required": [],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "get_resource_posture",
                "description": (
                    "Query resource security posture scores. Returns per-resource posture "
                    "data including posture score, compliance score, threat detections, "
                    "and engine-specific flags. Use for questions about specific resource "
                    "types, posture scores, public exposure, or cross-engine risk."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "resource_type": {
                                "type": "string",
                                "description": "Filter by resource type (e.g. 'aws_s3_bucket', 'aws_iam_user', 'aws_ec2_instance').",
                            },
                            "account_id": {
                                "type": "string",
                                "description": "Filter by cloud account ID.",
                            },
                            "is_public": {
                                "type": "boolean",
                                "description": "Filter to only publicly exposed resources.",
                            },
                            "min_score": {
                                "type": "integer",
                                "description": "Minimum posture score filter (0-100). Use to find low-score resources.",
                            },
                            "max_score": {
                                "type": "integer",
                                "description": "Maximum posture score filter. Use with min_score=0 to find worst resources.",
                            },
                            "order_by": {
                                "type": "string",
                                "enum": ["score_asc", "score_desc", "updated_desc"],
                                "description": "Sort order. score_asc = worst first.",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max rows to return. Default 10, max 50.",
                                "minimum": 1,
                                "maximum": 50,
                            },
                        },
                        "required": [],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "get_compliance_scores",
                "description": (
                    "Get compliance framework scores. Returns pass/fail counts and overall "
                    "score per framework. Use for questions about PCI-DSS, NIST, CIS, ISO 27001, "
                    "HIPAA, GDPR, SOC 2, or any compliance framework."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "framework": {
                                "type": "string",
                                "description": "Specific framework name (e.g. 'PCI-DSS', 'NIST', 'CIS', 'ISO 27001', 'HIPAA'). Omit for all frameworks.",
                            },
                            "account_id": {
                                "type": "string",
                                "description": "Filter by cloud account ID.",
                            },
                        },
                        "required": [],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "list_accounts",
                "description": (
                    "List all cloud accounts being scanned in this tenant. Returns account name, "
                    "provider (aws/azure/gcp/oci), cloud account ID, and onboarding/scan status. "
                    "Call this when the user asks how many accounts are scanned, which accounts "
                    "exist, or needs an account ID for another query."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {},
                        "required": [],
                    }
                },
            }
        },
    ]
}


# ── Tool executor dispatch ─────────────────────────────────────────────────────

async def execute_tool(
    tool_name: str,
    tool_input: Dict[str, Any],
    tenant_id: str,
    account_ids: Optional[List[str]],
    role: str,
    inv_conn,
) -> Dict[str, Any]:
    """Route tool_name to the correct executor. Returns a plain dict."""
    try:
        if tool_name == "get_findings_summary":
            return _get_findings_summary(tool_input, tenant_id, account_ids, inv_conn)
        elif tool_name == "get_resource_posture":
            return _get_resource_posture(tool_input, tenant_id, account_ids, inv_conn)
        elif tool_name == "get_compliance_scores":
            return await _get_compliance_scores(tool_input, tenant_id, account_ids)
        elif tool_name == "list_accounts":
            return await _list_accounts(tenant_id, account_ids)
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    except Exception as exc:
        logger.warning("Tool %s failed: %s", tool_name, exc)
        try:
            inv_conn.rollback()
        except Exception:
            pass
        return {"error": str(exc)}


# ── Tool implementations ───────────────────────────────────────────────────────

def _get_findings_summary(
    params: Dict[str, Any],
    tenant_id: str,
    account_ids: Optional[List[str]],
    conn,
) -> Dict[str, Any]:
    severity    = params.get("severity")
    engine      = params.get("engine")
    account_id  = params.get("account_id")
    days        = params.get("days")
    limit       = min(int(params.get("limit", 10)), 50)

    conditions = ["tenant_id = %s"]
    args: list = [tenant_id]

    if account_ids is not None:
        conditions.append("account_id = ANY(%s)")
        args.append(account_ids)
    if account_id:
        conditions.append("account_id = %s")
        args.append(account_id)
    if severity:
        conditions.append("severity = %s")
        args.append(severity)
    if engine:
        conditions.append("source_engine = %s")
        args.append(engine)
    if days:
        conditions.append("first_seen_at >= NOW() - INTERVAL '%s days'")
        args.append(days)

    where = " AND ".join(conditions)

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # Summary counts by severity
        cur.execute(
            f"""
            SELECT
                severity,
                COUNT(*) AS count
            FROM security_findings
            WHERE {where}
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
            """,
            args,
        )
        by_severity = [dict(r) for r in cur.fetchall()]

        # Top findings
        cur.execute(
            f"""
            SELECT
                finding_id, title, severity, source_engine,
                resource_type, account_id, status, first_seen_at
            FROM security_findings
            WHERE {where}
            ORDER BY CASE severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                first_seen_at DESC
            LIMIT %s
            """,
            args + [limit],
        )
        top_findings = [dict(r) for r in cur.fetchall()]
        for f in top_findings:
            if f.get("first_seen_at"):
                f["first_seen_at"] = f["first_seen_at"].isoformat()

    total = sum(int(r["count"]) for r in by_severity)
    return {
        "total": total,
        "by_severity": [{"severity": r["severity"], "count": int(r["count"])} for r in by_severity],
        "top_findings": top_findings,
        "filters_applied": {
            k: v for k, v in params.items() if v is not None
        },
    }


def _get_resource_posture(
    params: Dict[str, Any],
    tenant_id: str,
    account_ids: Optional[List[str]],
    conn,
) -> Dict[str, Any]:
    resource_type = params.get("resource_type")
    account_id    = params.get("account_id")
    is_public     = params.get("is_public")
    min_score     = params.get("min_score")
    max_score     = params.get("max_score")
    order_by      = params.get("order_by", "score_asc")
    limit         = min(int(params.get("limit", 10)), 50)

    conditions = ["tenant_id = %s"]
    args: list = [tenant_id]

    if account_ids is not None:
        conditions.append("account_id = ANY(%s)")
        args.append(account_ids)
    if account_id:
        conditions.append("account_id = %s")
        args.append(account_id)
    if resource_type:
        conditions.append("resource_type ILIKE %s")
        args.append(f"%{resource_type}%")
    if is_public is True:
        conditions.append("is_publicly_accessible = TRUE")
    if min_score is not None:
        conditions.append("overall_posture_score >= %s")
        args.append(min_score)
    if max_score is not None:
        conditions.append("overall_posture_score <= %s")
        args.append(max_score)

    where = " AND ".join(conditions)
    order_sql = {
        "score_asc":    "overall_posture_score ASC NULLS LAST",
        "score_desc":   "overall_posture_score DESC NULLS LAST",
        "updated_desc": "updated_at DESC",
    }.get(order_by, "overall_posture_score ASC NULLS LAST")

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            f"""
            SELECT
                resource_uid, resource_type, account_id, region,
                overall_posture_score, compliance_score,
                is_publicly_accessible, is_encrypted_at_rest, is_in_private_subnet,
                network_detail, compliance_detail, updated_at
            FROM resource_security_posture
            WHERE {where}
            ORDER BY {order_sql}
            LIMIT %s
            """,
            args + [limit],
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r.get("updated_at"):
                r["updated_at"] = r["updated_at"].isoformat()

        # Count total matching
        cur.execute(
            f"SELECT COUNT(*) AS cnt FROM resource_security_posture WHERE {where}",
            args,
        )
        total = cur.fetchone()["cnt"]

    return {"total": int(total), "resources": rows}


async def _get_compliance_scores(
    params: Dict[str, Any],
    tenant_id: str,
    account_ids: Optional[List[str]],
) -> Dict[str, Any]:
    framework  = params.get("framework")
    account_id = params.get("account_id")

    qs: Dict[str, Any] = {"tenant_id": tenant_id}
    if account_id:
        qs["account_id"] = account_id

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{COMPLIANCE_URL}/api/v1/compliance/summary",
                params=qs,
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"error": f"Compliance engine unavailable: {exc}"}

    frameworks = data.get("frameworks", data if isinstance(data, list) else [])
    if framework:
        frameworks = [
            f for f in frameworks
            if framework.lower() in (f.get("name") or "").lower()
        ]

    return {"frameworks": frameworks, "total_frameworks": len(frameworks)}


async def _list_accounts(
    tenant_id: str,
    account_ids: Optional[List[str]],
) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                f"{ONBOARDING_URL}/api/v1/cloud-accounts",
                params={"tenant_id": tenant_id},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"error": f"Onboarding engine unavailable: {exc}"}

    accounts = data.get("accounts", [])

    # Filter by RBAC-allowed cloud account numbers if restricted
    if account_ids is not None:
        accounts = [a for a in accounts if a.get("account_number") in account_ids]

    return {
        "total": len(accounts),
        "accounts": [
            {
                "cloud_account_id": a.get("account_number"),
                "name": a.get("account_name"),
                "provider": a.get("provider"),
                "status": a.get("account_status"),
                "onboarding_status": a.get("account_onboarding_status"),
            }
            for a in accounts
        ],
    }
