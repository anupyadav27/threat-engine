"""
Base specialist agent — shared Bedrock loop + common DB tools.

Each specialist subclass sets:
  DOMAIN         — slug used in orchestrator routing
  SYSTEM_PROMPT  — domain-focused instructions
  EXTRA_TOOLS    — additional toolSpec dicts (beyond the 2 common ones)

Subclass overrides _execute_extra_tool() to implement domain tools.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras

logger = logging.getLogger("chat-engine.specialist")

BEDROCK_MODEL = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")

# ── Common tools available to ALL specialists ─────────────────────────────────

_COMMON_TOOLS: list = [
    {
        "toolSpec": {
            "name": "search_security_findings",
            "description": (
                "Search live security findings from the unified findings table. "
                "Filter by engine (source_engine), severity, days, resource type, account. "
                "Returns severity breakdown + top findings."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "source_engine": {
                            "type": "string",
                            "enum": [
                                "check", "iam", "network", "datasec", "vuln",
                                "cdr", "container", "dbsec", "encryption", "ai_security",
                            ],
                            "description": "Filter by source engine. Omit for all engines.",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                        },
                        "days": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 365,
                            "description": "Only findings from last N days.",
                        },
                        "resource_type": {
                            "type": "string",
                            "description": "Substring match on resource_type (e.g. 'ec2', 's3', 'rds').",
                        },
                        "account_id": {"type": "string"},
                        "in_kev": {
                            "type": "boolean",
                            "description": "True = only known-exploited (KEV) vulnerabilities.",
                        },
                        "mitre_tactic": {
                            "type": "string",
                            "description": "Filter by MITRE ATT&CK tactic (e.g. 'Lateral Movement').",
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50,
                            "description": "Max rows to return for top findings list. Default 10.",
                        },
                    },
                    "required": [],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "query_resource_posture",
            "description": (
                "Query resource security posture scores and risk signals. "
                "Use to find publicly exposed resources, resources on attack paths, "
                "crown jewel assets, unencrypted resources, active threat actors, etc."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "account_id": {"type": "string"},
                        "resource_type": {
                            "type": "string",
                            "description": "Substring match on resource_type.",
                        },
                        "is_internet_exposed": {"type": "boolean"},
                        "is_crown_jewel": {"type": "boolean"},
                        "is_on_attack_path": {"type": "boolean"},
                        "has_active_cdr_actor": {"type": "boolean"},
                        "is_encrypted_at_rest": {"type": "boolean"},
                        "is_encrypted_in_transit": {"type": "boolean"},
                        "role_has_wildcard_policy": {"type": "boolean"},
                        "mfa_enforced": {"type": "boolean"},
                        "has_privileged_container": {"type": "boolean"},
                        "image_has_critical_cve": {"type": "boolean"},
                        "has_shadow_ai_service": {"type": "boolean"},
                        "min_posture_score": {"type": "integer"},
                        "max_posture_score": {"type": "integer"},
                        "order_by": {
                            "type": "string",
                            "enum": ["posture_asc", "posture_desc", "risk_desc", "updated_desc"],
                            "description": "posture_asc = worst resources first.",
                        },
                        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                    },
                    "required": [],
                }
            },
        }
    },
]


class SpecialistAgent:
    DOMAIN: str = "unknown"
    SYSTEM_PROMPT: str = "You are a cloud security specialist."
    EXTRA_TOOLS: list = []

    def __init__(
        self,
        bedrock_client: Any,
        tenant_id: str,
        account_ids: Optional[List[str]],
        role: str,
        di_conn: Any,
    ) -> None:
        self.bedrock = bedrock_client
        self.tenant_id = tenant_id
        self.account_ids = account_ids
        self.role = role
        self.di_conn = di_conn
        self._collected_data: Dict[str, Any] = {}

    def _engine_headers(self) -> Dict[str, str]:
        """Build X-Auth-Context header for service-to-service engine API calls."""
        ctx = {
            "user_id": "chat-engine",
            "email": "chat-engine@internal",
            "role": self.role or "platform_admin",
            "level": 1,
            "scope_level": "platform",
            "engine_tenant_id": self.tenant_id,
            "tenant_ids": [self.tenant_id],
            "account_ids": self.account_ids,
            "permissions": [
                "compliance:read", "discoveries:read", "risks:read",
                "threats:read", "network:read", "iam:read",
                "attack_path:read", "vulnerabilities:read", "cdr:read",
                "inventory:read", "cloud_accounts:read",
            ],
        }
        return {"X-Auth-Context": json.dumps(ctx)}

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, question: str) -> Dict[str, Any]:
        """Run the specialist Bedrock loop. Returns {"domain", "answer", "data"}."""
        all_tools = _COMMON_TOOLS + self.EXTRA_TOOLS
        tool_config = {"tools": all_tools}
        messages: List[Dict] = [{"role": "user", "content": [{"text": question}]}]
        system = [{"text": self.SYSTEM_PROMPT}]

        for _ in range(3):  # max 3 tool rounds per specialist
            try:
                resp = self.bedrock.converse(
                    modelId=BEDROCK_MODEL,
                    system=system,
                    messages=messages,
                    toolConfig=tool_config,
                    inferenceConfig={"maxTokens": 1024, "temperature": 0.1},
                )
            except Exception as exc:
                logger.error("[%s] Bedrock error: %s", self.DOMAIN, exc)
                return {"domain": self.DOMAIN, "answer": f"Specialist unavailable: {exc}", "data": {}}

            stop_reason = resp.get("stopReason", "end_turn")
            out_msg = resp["output"]["message"]

            if stop_reason == "end_turn":
                text = "".join(
                    b["text"] for b in out_msg.get("content", []) if "text" in b
                )
                return {"domain": self.DOMAIN, "answer": text, "data": self._collected_data}

            if stop_reason != "tool_use":
                break

            messages.append(out_msg)
            tool_results = []

            for block in out_msg.get("content", []):
                if "toolUse" not in block:
                    continue
                tu = block["toolUse"]
                result = self._dispatch_tool(tu["name"], tu["input"])
                self._collected_data[tu["name"]] = result
                tool_results.append({
                    "toolResult": {
                        "toolUseId": tu["toolUseId"],
                        "content": [{"text": json.dumps(result, default=str)}],
                    }
                })

            messages.append({"role": "user", "content": tool_results})

        return {"domain": self.DOMAIN, "answer": "Analysis complete.", "data": self._collected_data}

    # ── Tool dispatcher ───────────────────────────────────────────────────────

    def _dispatch_tool(self, name: str, params: Dict) -> Dict:
        try:
            if name == "search_security_findings":
                return self._search_security_findings(params)
            elif name == "query_resource_posture":
                return self._query_resource_posture(params)
            else:
                return self._execute_extra_tool(name, params)
        except Exception as exc:
            logger.warning("[%s] Tool %s failed: %s", self.DOMAIN, name, exc)
            try:
                self.di_conn.rollback()
            except Exception:
                pass
            return {"error": str(exc)}

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        return {"error": f"Unknown tool: {name}"}

    # ── Common tool implementations ───────────────────────────────────────────

    def _search_security_findings(self, params: Dict) -> Dict:
        source_engine = params.get("source_engine")
        severity      = params.get("severity")
        days          = params.get("days")
        resource_type = params.get("resource_type")
        account_id    = params.get("account_id")
        in_kev        = params.get("in_kev")
        mitre_tactic  = params.get("mitre_tactic")
        limit         = min(int(params.get("limit", 10)), 50)

        conds = ["tenant_id = %s"]
        args: list = [self.tenant_id]

        if self.account_ids is not None:
            conds.append("account_id = ANY(%s)")
            args.append(self.account_ids)
        if account_id:
            conds.append("account_id = %s")
            args.append(account_id)
        if source_engine:
            conds.append("source_engine = %s")
            args.append(source_engine)
        if severity:
            conds.append("severity = %s")
            args.append(severity)
        if days:
            conds.append("first_seen_at >= NOW() - INTERVAL '%s days'")
            args.append(days)
        if resource_type:
            conds.append("resource_type ILIKE %s")
            args.append(f"%{resource_type}%")
        if in_kev is True:
            conds.append("in_kev = TRUE")
        if mitre_tactic:
            conds.append("mitre_tactic ILIKE %s")
            args.append(f"%{mitre_tactic}%")

        where = " AND ".join(conds)

        with self.di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT severity, source_engine, COUNT(*) AS cnt
                FROM security_findings
                WHERE {where}
                GROUP BY severity, source_engine
                ORDER BY CASE severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
                """,
                args,
            )
            breakdown = [dict(r) for r in cur.fetchall()]

            cur.execute(
                f"""
                SELECT finding_id, title, severity, source_engine,
                       resource_type, resource_uid, account_id,
                       mitre_tactic, mitre_technique_id, in_kev,
                       cvss_score, epss_score, status, first_seen_at
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
            findings = [dict(r) for r in cur.fetchall()]
            for f in findings:
                if f.get("first_seen_at"):
                    f["first_seen_at"] = f["first_seen_at"].isoformat()

        total = sum(int(r["cnt"]) for r in breakdown)
        return {
            "total": total,
            "breakdown": [{"severity": r["severity"], "engine": r["source_engine"], "count": int(r["cnt"])} for r in breakdown],
            "top_findings": findings,
        }

    def _query_resource_posture(self, params: Dict) -> Dict:
        account_id              = params.get("account_id")
        resource_type           = params.get("resource_type")
        is_internet_exposed     = params.get("is_internet_exposed")
        is_crown_jewel          = params.get("is_crown_jewel")
        is_on_attack_path       = params.get("is_on_attack_path")
        has_active_cdr_actor    = params.get("has_active_cdr_actor")
        is_encrypted_at_rest    = params.get("is_encrypted_at_rest")
        is_encrypted_in_transit = params.get("is_encrypted_in_transit")
        role_has_wildcard       = params.get("role_has_wildcard_policy")
        mfa_enforced            = params.get("mfa_enforced")
        has_privileged_container = params.get("has_privileged_container")
        image_has_critical_cve  = params.get("image_has_critical_cve")
        has_shadow_ai           = params.get("has_shadow_ai_service")
        min_score               = params.get("min_posture_score")
        max_score               = params.get("max_posture_score")
        order_by                = params.get("order_by", "posture_asc")
        limit                   = min(int(params.get("limit", 10)), 50)

        conds = ["tenant_id = %s"]
        args: list = [self.tenant_id]

        if self.account_ids is not None:
            conds.append("account_id = ANY(%s)")
            args.append(self.account_ids)
        if account_id:
            conds.append("account_id = %s")
            args.append(account_id)
        if resource_type:
            conds.append("resource_type ILIKE %s")
            args.append(f"%{resource_type}%")
        if is_internet_exposed is not None:
            conds.append(f"is_internet_exposed = {'TRUE' if is_internet_exposed else 'FALSE'}")
        if is_crown_jewel is not None:
            conds.append(f"is_crown_jewel = {'TRUE' if is_crown_jewel else 'FALSE'}")
        if is_on_attack_path is not None:
            conds.append(f"is_on_attack_path = {'TRUE' if is_on_attack_path else 'FALSE'}")
        if has_active_cdr_actor is not None:
            conds.append(f"has_active_cdr_actor = {'TRUE' if has_active_cdr_actor else 'FALSE'}")
        if is_encrypted_at_rest is not None:
            conds.append(f"is_encrypted_at_rest = {'TRUE' if is_encrypted_at_rest else 'FALSE'}")
        if is_encrypted_in_transit is not None:
            conds.append(f"is_encrypted_in_transit = {'TRUE' if is_encrypted_in_transit else 'FALSE'}")
        if role_has_wildcard is not None:
            conds.append(f"role_has_wildcard_policy = {'TRUE' if role_has_wildcard else 'FALSE'}")
        if mfa_enforced is not None:
            conds.append(f"mfa_enforced = {'TRUE' if mfa_enforced else 'FALSE'}")
        if has_privileged_container is not None:
            conds.append(f"has_privileged_container = {'TRUE' if has_privileged_container else 'FALSE'}")
        if image_has_critical_cve is not None:
            conds.append(f"image_has_critical_cve = {'TRUE' if image_has_critical_cve else 'FALSE'}")
        if has_shadow_ai is not None:
            conds.append(f"has_shadow_ai_service = {'TRUE' if has_shadow_ai else 'FALSE'}")
        if min_score is not None:
            conds.append("overall_posture_score >= %s")
            args.append(min_score)
        if max_score is not None:
            conds.append("overall_posture_score <= %s")
            args.append(max_score)

        where = " AND ".join(conds)
        order_sql = {
            "posture_asc":  "overall_posture_score ASC NULLS LAST",
            "posture_desc": "overall_posture_score DESC NULLS LAST",
            "risk_desc":    "highest_path_score DESC NULLS LAST",
            "updated_desc": "updated_at DESC",
        }.get(order_by, "overall_posture_score ASC NULLS LAST")

        with self.di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"SELECT COUNT(*) AS cnt FROM resource_security_posture WHERE {where}", args)
            total = int(cur.fetchone()["cnt"])

            cur.execute(
                f"""
                SELECT resource_uid, resource_type, resource_name, account_id, region, provider,
                       overall_posture_score, is_internet_exposed, is_crown_jewel, is_on_attack_path,
                       has_active_cdr_actor, is_encrypted_at_rest, is_encrypted_in_transit,
                       role_has_wildcard_policy, mfa_enforced, highest_path_score,
                       blast_radius_count, vuln_critical_count, vuln_high_count,
                       attack_path_count, check_critical, check_high
                FROM resource_security_posture
                WHERE {where}
                ORDER BY {order_sql}
                LIMIT %s
                """,
                args + [limit],
            )
            rows = [dict(r) for r in cur.fetchall()]

        return {"total": total, "resources": rows}
