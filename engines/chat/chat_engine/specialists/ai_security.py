"""AI Security specialist — SageMaker, Bedrock, ML model security."""

from __future__ import annotations

from typing import Dict

import psycopg2.extras

from .base import SpecialistAgent


class AISecuritySpecialist(SpecialistAgent):
    DOMAIN = "ai_security"
    SYSTEM_PROMPT = """You are an AI/ML security specialist for a CSPM platform.
You analyze AI security posture for SageMaker, Bedrock, and other ML workloads including model exposure, training data security, and shadow AI usage.

When answering:
- Lead with count of publicly accessible AI models and shadow AI services
- Highlight models trained on PII data without encryption
- Call out Bedrock endpoints exposed to the internet
- Mention shadow AI services (unsanctioned AI tools discovered in cloud)
- Be concise — focus on AI data poisoning and model exfiltration risks"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_ai_security_summary",
                "description": "Get AI/ML security statistics — public models, shadow AI, PII in training data.",
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
        if name == "get_ai_security_summary":
            return self._get_ai_security_summary(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_ai_security_summary(self, params: Dict) -> Dict:
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
                    COUNT(*) FILTER (WHERE has_shadow_ai_service = TRUE) AS shadow_ai_services,
                    COUNT(*) FILTER (WHERE ai_model_publicly_accessible = TRUE) AS public_ai_models,
                    COUNT(*) FILTER (WHERE ai_training_data_has_pii = TRUE) AS models_with_pii_training_data,
                    COUNT(*) FILTER (WHERE ai_model_publicly_accessible = TRUE AND ai_training_data_has_pii = TRUE) AS public_with_pii
                FROM resource_security_posture
                WHERE {where}
                """,
                args,
            )
            posture_stats = dict(cur.fetchone() or {})

            # AI security findings
            conds_sf = ["tenant_id = %s", "source_engine = 'ai_security'"]
            args_sf: list = [self.tenant_id]
            if self.account_ids is not None:
                conds_sf.append("account_id = ANY(%s)")
                args_sf.append(self.account_ids)
            where_sf = " AND ".join(conds_sf)

            cur.execute(
                f"""
                SELECT severity, COUNT(*) AS cnt
                FROM security_findings
                WHERE {where_sf}
                GROUP BY severity
                ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
                """,
                args_sf,
            )
            finding_counts = [dict(r) for r in cur.fetchall()]

        return {"ai_security_posture": posture_stats, "finding_severity_counts": finding_counts}
