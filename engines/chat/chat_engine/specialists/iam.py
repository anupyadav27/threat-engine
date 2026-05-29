"""IAM specialist — identity, access, MFA, privilege escalation."""

from __future__ import annotations

import os
from typing import Any, Dict

import httpx
import psycopg2.extras

from .base import SpecialistAgent

IAM_URL = os.getenv("IAM_ENGINE_URL", "http://engine-iam")


class IAMSpecialist(SpecialistAgent):
    DOMAIN = "iam"
    SYSTEM_PROMPT = """You are an IAM (Identity and Access Management) security specialist for a CSPM platform.
You analyze IAM posture including users without MFA, overprivileged roles, stale access keys, cross-account access, and privilege escalation paths.

When answering:
- Lead with count of high-risk identity issues (no MFA, wildcard policies, admin roles)
- Call out any privilege escalation paths
- Highlight cross-account access risks
- Mention stale credentials (access keys > 90 days)
- Be concise — focus on actionable IAM risks"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_iam_posture_summary",
                "description": "Get IAM posture statistics — MFA coverage, wildcard policy count, cross-account access, admin roles, privilege escalation paths.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "account_id": {"type": "string"},
                        },
                        "required": [],
                    }
                },
            }
        }
    ]

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        if name == "get_iam_posture_summary":
            return self._get_iam_posture_summary(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_iam_posture_summary(self, params: Dict) -> Dict:
        conds = ["tenant_id = %s"]
        args: list = [self.tenant_id]
        if self.account_ids is not None:
            conds.append("account_id = ANY(%s)")
            args.append(self.account_ids)
        if params.get("account_id"):
            conds.append("account_id = %s")
            args.append(params["account_id"])
        where = " AND ".join(conds)

        with self.di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) AS total_identity_resources,
                    COUNT(*) FILTER (WHERE mfa_enforced = FALSE) AS no_mfa_count,
                    COUNT(*) FILTER (WHERE role_has_wildcard_policy = TRUE) AS wildcard_policy_count,
                    COUNT(*) FILTER (WHERE role_allows_cross_account = TRUE) AS cross_account_count,
                    COUNT(*) FILTER (WHERE is_admin_role = TRUE) AS admin_role_count,
                    COUNT(*) FILTER (WHERE has_priv_escalation_path = TRUE) AS priv_escalation_count,
                    COUNT(*) FILTER (WHERE admin_role_without_mfa = TRUE) AS admin_without_mfa_count,
                    COUNT(*) FILTER (WHERE active_cdr_actor_on_admin_role = TRUE) AS active_threat_on_admin_count
                FROM resource_security_posture
                WHERE {where}
                  AND resource_type ILIKE ANY(ARRAY['%%iam%%','%%user%%','%%role%%','%%identity%%','%%principal%%'])
                """,
                args,
            )
            stats = dict(cur.fetchone() or {})

        return {"iam_posture": stats}
