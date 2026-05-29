"""Risk specialist — FAIR model, blast radius, dollar exposure."""

from __future__ import annotations

import os
from typing import Dict

import httpx
import psycopg2.extras

from .base import SpecialistAgent

RISK_URL = os.getenv("RISK_ENGINE_URL", "http://engine-risk")


class RiskSpecialist(SpecialistAgent):
    DOMAIN = "risk"
    SYSTEM_PROMPT = """You are a risk quantification specialist for a CSPM platform.
You analyze risk scores using the FAIR model including blast radius, dollar exposure, attack path scores, and overall risk posture.

When answering:
- Lead with overall risk posture (average posture score, count of critical resources)
- Highlight resources with highest blast radius (most impact if compromised)
- Call out exploitable resources that are also internet-exposed
- Mention dollar exposure estimates if available
- Be concise — focus on risk prioritization"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_risk_summary",
                "description": "Get risk summary — worst posture score resources, blast radius leaders, exploitable exposed resources.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "account_id": {"type": "string"},
                            "top_n": {"type": "integer", "minimum": 1, "maximum": 20},
                        },
                        "required": [],
                    }
                },
            }
        }
    ]

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        if name == "get_risk_summary":
            return self._get_risk_summary(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_risk_summary(self, params: Dict) -> Dict:
        top_n = min(int(params.get("top_n", 10)), 20)
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
                    ROUND(AVG(overall_posture_score)::numeric, 1) AS avg_posture_score,
                    COUNT(*) FILTER (WHERE overall_posture_score < 40) AS critical_risk_resources,
                    COUNT(*) FILTER (WHERE overall_posture_score BETWEEN 40 AND 69) AS high_risk_resources,
                    COUNT(*) FILTER (WHERE exploitable_exposed_resource = TRUE) AS exploitable_exposed,
                    COUNT(*) FILTER (WHERE is_crown_jewel = TRUE AND overall_posture_score < 60) AS crown_jewels_at_risk,
                    MAX(blast_radius_count) AS max_blast_radius
                FROM resource_security_posture
                WHERE {where}
                """,
                args,
            )
            overview = dict(cur.fetchone() or {})

            cur.execute(
                f"""
                SELECT resource_uid, resource_type, resource_name, account_id,
                       overall_posture_score, blast_radius_count, attack_path_count,
                       is_crown_jewel, is_internet_exposed, highest_path_severity
                FROM resource_security_posture
                WHERE {where}
                ORDER BY blast_radius_count DESC NULLS LAST
                LIMIT %s
                """,
                args + [top_n],
            )
            top_blast_radius = [dict(r) for r in cur.fetchall()]

        # Try risk engine API for dollar figures
        dollar_risk = {}
        try:
            resp = httpx.get(
                f"{RISK_URL}/api/v1/risk/summary",
                params={"tenant_id": self.tenant_id},
                timeout=8.0,
            )
            if resp.status_code == 200:
                dollar_risk = resp.json()
        except Exception:
            pass

        return {
            "risk_overview": overview,
            "top_blast_radius_resources": top_blast_radius,
            "dollar_risk": dollar_risk,
        }
