"""Database security specialist — RDS, DynamoDB, Aurora posture."""

from __future__ import annotations

from typing import Dict

import psycopg2.extras

from .base import SpecialistAgent


class DBSecSpecialist(SpecialistAgent):
    DOMAIN = "dbsec"
    SYSTEM_PROMPT = """You are a database security specialist for a CSPM platform.
You analyze database security including RDS, Aurora, DynamoDB, ElastiCache, and other database services.

When answering:
- Lead with count of unencrypted databases and publicly accessible databases
- Highlight databases missing audit logging or backup policies
- Call out databases with weak authentication (no IAM auth, default passwords)
- Mention databases connected to internet-exposed resources (exfiltration risk)
- Be concise — focus on data breach risk from database misconfigurations"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_database_security_summary",
                "description": "Get database security statistics — unencrypted DBs, public DBs, authentication issues.",
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
        if name == "get_database_security_summary":
            return self._get_db_security_summary(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_db_security_summary(self, params: Dict) -> Dict:
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
            # DB resources from posture
            cur.execute(
                f"""
                SELECT
                    COUNT(*) AS total_db_resources,
                    COUNT(*) FILTER (WHERE is_encrypted_at_rest = FALSE) AS unencrypted_at_rest,
                    COUNT(*) FILTER (WHERE is_internet_exposed = TRUE) AS publicly_accessible,
                    COUNT(*) FILTER (WHERE db_auth_type = 'password') AS password_auth_only,
                    COUNT(*) FILTER (WHERE connected_db_count > 0) AS resources_with_db_connections,
                    COUNT(*) FILTER (WHERE cdr_active_on_unencrypted = TRUE) AS active_threat_on_db
                FROM resource_security_posture
                WHERE {where}
                  AND resource_type ILIKE ANY(ARRAY[
                    '%rds%','%aurora%','%dynamodb%','%elasticache%',
                    '%redshift%','%neptune%','%docdb%','%database%','%db%'
                  ])
                """,
                args,
            )
            posture_stats = dict(cur.fetchone() or {})

            # DB security findings
            conds_sf = ["tenant_id = %s", "source_engine = 'dbsec'"]
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

        return {"database_posture": posture_stats, "finding_severity_counts": finding_counts}
