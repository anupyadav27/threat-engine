"""Container security specialist — EKS, K8s RBAC, image CVEs, workload security."""

from __future__ import annotations

from typing import Dict

import psycopg2.extras

from .base import SpecialistAgent


class ContainerSpecialist(SpecialistAgent):
    DOMAIN = "container"
    SYSTEM_PROMPT = """You are a container and Kubernetes security specialist for a CSPM platform.
You analyze EKS/ECS container security including image vulnerabilities, privileged containers, K8s RBAC, network policies, and ECR scan coverage.

When answering:
- Lead with count of privileged containers and images with critical CVEs
- Highlight K8s RBAC over-permissive configurations
- Call out missing network policies (allow-all by default)
- Mention ECR scan-on-push disabled registries
- Be concise — focus on container breakout and lateral movement risks"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_container_security_summary",
                "description": "Get container security statistics — privileged containers, image CVEs, K8s RBAC issues, network policy gaps.",
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
        if name == "get_container_security_summary":
            return self._get_container_summary(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_container_summary(self, params: Dict) -> Dict:
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
                    COUNT(*) AS total_container_resources,
                    COUNT(*) FILTER (WHERE has_privileged_container = TRUE) AS privileged_containers,
                    COUNT(*) FILTER (WHERE image_has_critical_cve = TRUE) AS images_with_critical_cve,
                    COUNT(*) FILTER (WHERE k8s_rbac_overpermissive = TRUE) AS rbac_overpermissive,
                    COUNT(*) FILTER (WHERE container_network_policy_missing = TRUE) AS missing_network_policy,
                    COUNT(*) FILTER (WHERE ecr_scan_on_push_enabled = FALSE) AS ecr_scan_disabled,
                    COUNT(*) FILTER (WHERE eks_node_ami_outdated = TRUE) AS outdated_node_amis,
                    ROUND(AVG(container_security_score)::numeric, 1) AS avg_container_security_score
                FROM resource_security_posture
                WHERE {where}
                  AND resource_type ILIKE ANY(ARRAY[
                    '%eks%','%ecs%','%container%','%k8s%','%pod%',
                    '%ecr%','%fargate%','%task%','%service%mesh%'
                  ])
                """,
                args,
            )
            posture_stats = dict(cur.fetchone() or {})

            # Container findings
            conds_sf = ["tenant_id = %s", "source_engine = 'container'"]
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

        return {"container_posture": posture_stats, "finding_severity_counts": finding_counts}
