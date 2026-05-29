"""CDR specialist — behavioral detections, threat actors, suspicious activity."""

from __future__ import annotations

from typing import Dict

import psycopg2.extras

from .base import SpecialistAgent


class CDRSpecialist(SpecialistAgent):
    DOMAIN = "cdr"
    SYSTEM_PROMPT = """You are a Cloud Detection & Response (CDR) specialist for a CSPM platform.
You analyze behavioral threat detections from cloud logs including CloudTrail, VPC Flow Logs, GuardDuty, and Azure Monitor.

When answering:
- Lead with count of active threat actors and highest severity detections
- Call out MITRE ATT&CK tactics detected (Credential Access, Lateral Movement, Exfiltration, etc.)
- Highlight resources with both active threat actors AND crown jewel status (immediate incident response needed)
- Mention detection timeline trends (spike in last 24h vs normal)
- Be concise — focus on active threats requiring immediate response"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_cdr_summary",
                "description": "Get CDR (detection) statistics — active threats, MITRE tactic distribution, threat actor count.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "account_id": {"type": "string"},
                            "days": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 90,
                                "description": "Detection window in days. Default 7.",
                            },
                        },
                        "required": [],
                    }
                },
            }
        }
    ]

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        if name == "get_cdr_summary":
            return self._get_cdr_summary(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_cdr_summary(self, params: Dict) -> Dict:
        days = int(params.get("days", 7))
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
            # Active threat posture
            cur.execute(
                f"""
                SELECT
                    COUNT(*) FILTER (WHERE has_active_cdr_actor = TRUE) AS resources_with_active_threat,
                    COUNT(*) FILTER (WHERE has_active_cdr_actor = TRUE AND is_crown_jewel = TRUE) AS active_threat_crown_jewels,
                    SUM(cdr_actor_count) AS total_active_actor_count,
                    COUNT(*) FILTER (WHERE priv_escalation_cdr_confirmed = TRUE) AS confirmed_priv_escalation
                FROM resource_security_posture
                WHERE {where}
                """,
                args,
            )
            posture_stats = dict(cur.fetchone() or {})

            # Recent CDR findings
            conds_sf = [
                "tenant_id = %s",
                "source_engine = 'cdr'",
                f"first_seen_at >= NOW() - INTERVAL '{days} days'",
            ]
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
            recent_by_severity = [dict(r) for r in cur.fetchall()]

            cur.execute(
                f"""
                SELECT mitre_tactic, COUNT(*) AS cnt
                FROM security_findings
                WHERE {where_sf} AND mitre_tactic IS NOT NULL
                GROUP BY mitre_tactic
                ORDER BY cnt DESC
                LIMIT 8
                """,
                args_sf,
            )
            tactic_distribution = [dict(r) for r in cur.fetchall()]

            # Top active threats
            cur.execute(
                f"""
                SELECT title, severity, resource_type, resource_uid, account_id,
                       mitre_tactic, mitre_technique_id, first_seen_at
                FROM security_findings
                WHERE {where_sf} AND severity IN ('critical', 'high')
                ORDER BY CASE severity WHEN 'critical' THEN 1 ELSE 2 END, first_seen_at DESC
                LIMIT 10
                """,
                args_sf,
            )
            top_threats = [dict(r) for r in cur.fetchall()]
            for t in top_threats:
                if t.get("first_seen_at"):
                    t["first_seen_at"] = t["first_seen_at"].isoformat()

        return {
            "active_threat_posture": posture_stats,
            "recent_detections_by_severity": recent_by_severity,
            "mitre_tactic_distribution": tactic_distribution,
            "top_threats": top_threats,
            "detection_window_days": days,
        }
