"""Data security specialist — PII, S3, classification, encryption."""

from __future__ import annotations

from typing import Dict

import psycopg2.extras

from .base import SpecialistAgent


class DataSecSpecialist(SpecialistAgent):
    DOMAIN = "datasec"
    SYSTEM_PROMPT = """You are a data security specialist for a CSPM platform.
You analyze data security posture including PII exposure, unencrypted data stores, S3 bucket misconfigurations, data classification, and exfiltration paths.

When answering:
- Lead with count of internet-exposed resources containing PII
- Highlight unencrypted PII stores (highest risk for compliance)
- Call out data exfiltration paths (reachable PII stores from compromised resources)
- Mention specific resource types (S3, RDS, DynamoDB, etc.)
- Be concise — lead with GDPR/HIPAA/PCI-DSS relevant data risks"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_data_security_summary",
                "description": "Get data security statistics — PII exposure, unencrypted data stores, data exfiltration paths.",
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
        if name == "get_data_security_summary":
            return self._get_data_security_summary(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_data_security_summary(self, params: Dict) -> Dict:
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
                    COUNT(*) FILTER (WHERE unencrypted_pii_store = TRUE) AS unencrypted_pii_stores,
                    COUNT(*) FILTER (WHERE internet_exposed_with_pii = TRUE) AS internet_exposed_pii,
                    COUNT(*) FILTER (WHERE has_exfil_path = TRUE) AS resources_with_exfil_path,
                    COUNT(*) FILTER (WHERE can_access_pii = TRUE) AS resources_can_access_pii,
                    SUM(reachable_pii_store_count) AS total_reachable_pii_stores,
                    COUNT(*) FILTER (WHERE data_classification IS NOT NULL) AS classified_resources
                FROM resource_security_posture
                WHERE {where}
                """,
                args,
            )
            stats = dict(cur.fetchone() or {})

        # data classification breakdown
        with self.di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT data_classification, COUNT(*) AS cnt
                FROM resource_security_posture
                WHERE {where} AND data_classification IS NOT NULL
                GROUP BY data_classification
                ORDER BY cnt DESC
                """,
                args,
            )
            classification = [dict(r) for r in cur.fetchall()]

        return {"data_security_stats": stats, "classification_breakdown": classification}
