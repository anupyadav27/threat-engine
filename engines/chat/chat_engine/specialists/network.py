"""Network specialist — exposure, topology, firewall, public resources."""

from __future__ import annotations

from typing import Dict

import psycopg2.extras

from .base import SpecialistAgent


class NetworkSpecialist(SpecialistAgent):
    DOMAIN = "network"
    SYSTEM_PROMPT = """You are a network security specialist for a CSPM platform.
You analyze network exposure including publicly accessible resources, security group misconfigurations, VPC isolation, WAF coverage, load balancer TLS, and VPC Flow Log monitoring.

When answering:
- Lead with count of internet-exposed resources
- Highlight resources on attack paths that are also internet-exposed (highest risk)
- Call out missing WAF protection on public-facing resources
- Mention security group issues (open ports to 0.0.0.0/0)
- Be concise — focus on the exposure risk"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_network_exposure_summary",
                "description": "Get network exposure statistics — internet-exposed count, WAF coverage, public resources with attack paths.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "account_id": {"type": "string"},
                            "resource_type": {"type": "string"},
                        },
                        "required": [],
                    }
                },
            }
        }
    ]

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        if name == "get_network_exposure_summary":
            return self._get_network_exposure_summary(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_network_exposure_summary(self, params: Dict) -> Dict:
        conds = ["tenant_id = %s"]
        args: list = [self.tenant_id]
        if self.account_ids is not None:
            conds.append("account_id = ANY(%s)")
            args.append(self.account_ids)
        if params.get("account_id"):
            conds.append("account_id = %s")
            args.append(params["account_id"])
        if params.get("resource_type"):
            conds.append("resource_type ILIKE %s")
            args.append(f"%{params['resource_type']}%")
        where = " AND ".join(conds)

        with self.di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) AS total_resources,
                    COUNT(*) FILTER (WHERE is_internet_exposed = TRUE) AS internet_exposed_count,
                    COUNT(*) FILTER (WHERE is_internet_exposed = TRUE AND is_on_attack_path = TRUE) AS exposed_on_attack_path,
                    COUNT(*) FILTER (WHERE is_internet_exposed = TRUE AND has_waf = FALSE) AS exposed_without_waf,
                    COUNT(*) FILTER (WHERE is_internet_exposed = TRUE AND is_crown_jewel = TRUE) AS exposed_crown_jewels,
                    COUNT(*) FILTER (WHERE is_internet_exposed = TRUE AND has_active_cdr_actor = TRUE) AS exposed_with_active_threat,
                    COUNT(*) FILTER (WHERE is_in_private_subnet = FALSE AND is_internet_exposed = FALSE) AS in_public_subnet_not_exposed,
                    ROUND(AVG(network_exposure_score)::numeric, 1) AS avg_network_exposure_score
                FROM resource_security_posture
                WHERE {where}
                """,
                args,
            )
            stats = dict(cur.fetchone() or {})

        return {"network_exposure": stats}
