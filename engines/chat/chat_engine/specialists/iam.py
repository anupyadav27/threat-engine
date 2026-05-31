"""IAM specialist — identity, access, MFA, privilege escalation."""

from __future__ import annotations

import json
import os
from typing import Dict

import psycopg2.extras

from .base import SpecialistAgent

IAM_URL = os.getenv("IAM_ENGINE_URL", "http://engine-iam")

_ACCESS_KEY_RULES = [
    "aws.iam.rotate.access_key_90_days_configured",
    "aws.iam.key.rotation_90_days_configured",
    "aws.iam.user.access_keys_rotated_90_days_or_less_when_present",
    "aws.iam.user.single_active_access_key_configured",
    "aws.iam.role.keys_not_used_or_rotated_90_days_or_less_configured",
    "oci.identity.user.rotate_access_key_90_days",
    "alicloud.ciem.correlation.stale_access_key",
    "ibm.iam.rotate.access_key_90_days_configured",
]


class IAMSpecialist(SpecialistAgent):
    DOMAIN = "iam"
    SYSTEM_PROMPT = """You are an IAM security specialist for a CSPM platform.

Format every response using this structure:

## IAM Risk Summary
One-line headline with the top risk count and severity (e.g. "25 users with stale access keys · 118 identities without MFA")

## Findings
Use a markdown table or tight bullet list — never prose paragraphs. Show counts and percentages.
| Risk | Count | Severity |
|------|-------|----------|

## Affected Resources
For stale key / MFA / admin findings, list the actual usernames/ARNs from the data. Max 10 rows.

## Recommended Actions
Numbered list, one line each. Start each with an action verb. No filler text.

Rules:
- Never write "The key findings from the IAM analyst are" or similar preamble
- Never write paragraphs — use tables and bullet points only
- Bold the numbers that matter
- If get_stale_access_keys returns empty, say "No stale key findings for this tenant" in one line
- For access key rotation questions, the pre-fetched data is already embedded in the question — use it directly"""

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
        },
        {
            "toolSpec": {
                "name": "get_stale_access_keys",
                "description": (
                    "Query IAM users whose access keys have not been rotated within the threshold. "
                    "Returns list of affected IAM user ARNs / names and a severity breakdown. "
                    "Use this for any question about stale/unrotated access keys, key rotation compliance, "
                    "or 'which users have not rotated keys in X days'."
                ),
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
        },
    ]

    def run(self, question: str) -> Dict:
        """Pre-fetch data, build structured markdown, ask LLM only for recommendations."""
        posture = self._get_iam_posture_summary({})
        stale_keys = self._get_stale_access_keys({})
        self._collected_data["get_iam_posture_summary"] = posture
        self._collected_data["get_stale_access_keys"] = stale_keys

        p = posture.get("iam_posture", {})
        sk = stale_keys.get("stale_access_key_findings", {})
        stale_total = sk.get("total_findings") or 0
        affected = sk.get("affected_users", [])
        sev_breakdown = sk.get("severity_breakdown", [])

        # Build severity table row
        sev_str = " · ".join(
            f"**{r['severity']}**: {r['cnt']}" for r in sev_breakdown
        ) if sev_breakdown else "none"

        # Distinct affected usernames (deduplicated)
        seen: set = set()
        unique_users = []
        for u in affected:
            name = u.get("username") or u.get("arn", "")
            if name and name not in seen:
                seen.add(name)
                unique_users.append(name)

        stale_user_count = len(unique_users)
        users_str = ", ".join(f"`{u}`" for u in unique_users[:10])
        if len(unique_users) > 10:
            users_str += f" … +{len(unique_users) - 10} more"

        total_ids    = p.get("total_identity_resources") or 0
        no_mfa       = p.get("no_mfa_count") or 0
        wildcard     = p.get("wildcard_policy_count") or 0
        cross_acct   = p.get("cross_account_count") or 0
        admin        = p.get("admin_role_count") or 0
        priv_esc     = p.get("priv_escalation_count") or 0
        admin_no_mfa = p.get("admin_without_mfa_count") or 0
        active_threat= p.get("active_threat_on_admin_count") or 0

        pct = lambda n: f"{round(n/total_ids*100)}%" if total_ids else "—"

        structured = f"""## IAM Risk Summary
**{stale_user_count} users with stale access keys** · **{no_mfa}/{total_ids} identities without MFA** · **{priv_esc} privilege escalation path(s)**

## Findings

| Risk | Count | % of Identities | Severity |
|------|-------|-----------------|----------|
| Users with unrotated access keys (>90d) | **{stale_user_count}** | {pct(stale_user_count)} | Medium |
| Identities without MFA | **{no_mfa}** | {pct(no_mfa)} | High |
| Wildcard policies attached | **{wildcard}** | {pct(wildcard)} | High |
| Admin roles | **{admin}** | {pct(admin)} | Medium |
| Admin roles without MFA | **{admin_no_mfa}** | {pct(admin_no_mfa)} | Critical |
| Cross-account access | **{cross_acct}** | {pct(cross_acct)} | Medium |
| Privilege escalation paths | **{priv_esc}** | {pct(priv_esc)} | Critical |
| Active threats on admin roles | **{active_threat}** | {pct(active_threat)} | Critical |

Stale key findings (total): {stale_total} · by severity: {sev_str}

## Affected Users (Stale Access Keys)
{users_str if users_str else "No stale key findings for this tenant."}
"""

        # Ask LLM only for recommendations based on the structured data
        reco_prompt = (
            f"Question: {question}\n\n"
            f"Pre-analyzed data:\n{structured}\n\n"
            "Write ONLY a '## Recommended Actions' section — numbered list, one line each, action verbs. "
            "No intro, no preamble, no summary. Max 5 items."
        )
        reco_result = super().run(reco_prompt)
        reco_text = reco_result.get("answer", "")

        # Strip any preamble the LLM adds before the ## header
        if "## Recommended" in reco_text:
            reco_text = reco_text[reco_text.index("## Recommended"):]

        full_answer = structured + "\n" + reco_text
        return {"domain": self.DOMAIN, "answer": full_answer, "data": self._collected_data}

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        if name == "get_iam_posture_summary":
            return self._get_iam_posture_summary(params)
        if name == "get_stale_access_keys":
            return self._get_stale_access_keys(params)
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

    def _get_stale_access_keys(self, params: Dict) -> Dict:
        conds = ["tenant_id = %s", "rule_id = ANY(%s)"]
        args: list = [self.tenant_id, _ACCESS_KEY_RULES]
        if self.account_ids is not None:
            conds.append("account_id = ANY(%s)")
            args.append(self.account_ids)
        if params.get("account_id"):
            conds.append("account_id = %s")
            args.append(params["account_id"])
        where = " AND ".join(conds)

        with self.di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Severity breakdown
            cur.execute(
                f"""
                SELECT severity, COUNT(*) AS cnt
                FROM security_findings
                WHERE {where}
                GROUP BY severity
                ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                         WHEN 'medium' THEN 3 ELSE 4 END
                """,
                args,
            )
            severity_counts = [dict(r) for r in cur.fetchall()]

            # Distinct affected users (extract username from ARN)
            cur.execute(
                f"""
                SELECT DISTINCT
                    resource_uid,
                    account_id,
                    rule_id,
                    severity,
                    last_seen_at
                FROM security_findings
                WHERE {where}
                ORDER BY severity, last_seen_at DESC
                LIMIT 30
                """,
                args,
            )
            affected_users = []
            for row in cur.fetchall():
                uid = row["resource_uid"] or ""
                username = uid.split("/")[-1] if "/" in uid else uid
                affected_users.append({
                    "username": username,
                    "arn": uid,
                    "account_id": row["account_id"],
                    "rule_id": row["rule_id"],
                    "severity": row["severity"],
                    "last_seen_at": str(row["last_seen_at"]) if row["last_seen_at"] else None,
                })

        total = sum(r["cnt"] for r in severity_counts)
        return {
            "stale_access_key_findings": {
                "total_findings": total,
                "severity_breakdown": severity_counts,
                "affected_users": affected_users,
                "note": (
                    "These are IAM users/roles with access keys that have not been rotated per policy. "
                    "Rotate or disable unused keys immediately."
                ) if total > 0 else "No stale access key findings detected for this tenant/account scope.",
            }
        }
