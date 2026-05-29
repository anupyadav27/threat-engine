"""Threat specialist — attack paths, MITRE ATT&CK, crown jewels."""

from __future__ import annotations

import os
from typing import Any, Dict

import httpx
import psycopg2.extras

from .base import SpecialistAgent

ATTACK_PATH_URL = os.getenv("ATTACK_PATH_ENGINE_URL", "http://engine-attack-path")


class ThreatSpecialist(SpecialistAgent):
    DOMAIN = "threat"
    SYSTEM_PROMPT = """You are a threat intelligence specialist for a CSPM platform.
You analyze attack paths, MITRE ATT&CK technique mappings, crown jewel assets, and blast radius.

When answering:
- Lead with number of active attack paths and highest severity
- Call out crown jewel assets at risk (databases, secrets, admin roles)
- Highlight choke points — fixing one resource could block multiple attack paths
- Map findings to MITRE ATT&CK tactics (Initial Access, Privilege Escalation, Lateral Movement, etc.)
- Be concise — focus on the most critical paths and what to fix first"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_attack_path_summary",
                "description": "Get attack path statistics — crown jewel count, choke points, blast radius, resources on attack paths.",
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
                "name": "get_attack_paths",
                "description": "Get top attack paths from the attack-path engine. Returns paths sorted by severity/score.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "account_id": {"type": "string"},
                            "limit": {"type": "integer", "minimum": 1, "maximum": 10},
                        },
                        "required": [],
                    }
                },
            }
        },
    ]

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        if name == "get_attack_path_summary":
            return self._get_attack_path_summary(params)
        if name == "get_attack_paths":
            return self._get_attack_paths(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_attack_path_summary(self, params: Dict) -> Dict:
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
                    COUNT(*) FILTER (WHERE is_on_attack_path = TRUE) AS resources_on_attack_path,
                    COUNT(*) FILTER (WHERE is_crown_jewel = TRUE) AS crown_jewel_count,
                    COUNT(*) FILTER (WHERE is_choke_point = TRUE) AS choke_point_count,
                    COUNT(*) FILTER (WHERE is_crown_jewel = TRUE AND is_on_attack_path = TRUE) AS crown_jewels_at_risk,
                    MAX(blast_radius_count) AS max_blast_radius,
                    MAX(attack_path_count) AS max_paths_to_resource,
                    COUNT(*) FILTER (WHERE paths_blocked_if_fixed > 0) AS fixable_choke_points,
                    MAX(paths_blocked_if_fixed) AS max_paths_blocked_by_single_fix
                FROM resource_security_posture
                WHERE {where}
                """,
                args,
            )
            stats = dict(cur.fetchone() or {})

        # MITRE tactic distribution
        conds_sf = ["tenant_id = %s", "mitre_technique_id IS NOT NULL"]
        args_sf: list = [self.tenant_id]
        if self.account_ids is not None:
            conds_sf.append("account_id = ANY(%s)")
            args_sf.append(self.account_ids)
        where_sf = " AND ".join(conds_sf)

        with self.di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT mitre_tactic, COUNT(*) AS cnt
                FROM security_findings
                WHERE {where_sf}
                GROUP BY mitre_tactic
                ORDER BY cnt DESC
                LIMIT 10
                """,
                args_sf,
            )
            mitre_tactics = [dict(r) for r in cur.fetchall()]

        return {"attack_path_stats": stats, "mitre_tactics": mitre_tactics}

    def _get_attack_paths(self, params: Dict) -> Dict:
        limit = min(int(params.get("limit", 5)), 10)
        try:
            resp = httpx.get(
                f"{ATTACK_PATH_URL}/api/v1/attack-paths",
                params={"tenant_id": self.tenant_id, "limit": limit},
                timeout=10.0,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            return {"error": f"Attack-path engine unavailable: {exc}"}
