"""Inventory specialist — asset counts, discovery, cloud accounts."""

from __future__ import annotations

import os
from typing import Dict

import httpx
import psycopg2.extras

from .base import SpecialistAgent

ONBOARDING_URL = os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding")


class InventorySpecialist(SpecialistAgent):
    DOMAIN = "inventory"
    SYSTEM_PROMPT = """You are an asset inventory specialist for a CSPM platform.
You analyze cloud asset counts, resource types, discovery coverage, and cloud account status.

When answering:
- Lead with total resource count and breakdown by provider/region
- Call out the top resource types by count
- Highlight any accounts with discovery failures or incomplete scans
- Mention drift detected resources if any
- Be concise — give clear inventory numbers"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_asset_summary",
                "description": "Get asset inventory statistics — resource counts by type, provider, region, account.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "provider": {
                                "type": "string",
                                "enum": ["aws", "azure", "gcp", "oci", "alicloud", "ibm", "k8s"],
                            },
                            "account_id": {"type": "string"},
                            "group_by": {
                                "type": "string",
                                "enum": ["resource_type", "provider", "region", "account_id"],
                                "description": "How to group the asset count. Default: resource_type.",
                            },
                            "limit": {"type": "integer", "minimum": 1, "maximum": 30},
                        },
                        "required": [],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "list_cloud_accounts",
                "description": "List all cloud accounts scanned in this tenant — name, provider, status.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {},
                        "required": [],
                    }
                },
            }
        },
    ]

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        if name == "get_asset_summary":
            return self._get_asset_summary(params)
        if name == "list_cloud_accounts":
            return self._list_accounts()
        return {"error": f"Unknown tool: {name}"}

    def _get_asset_summary(self, params: Dict) -> Dict:
        group_by = params.get("group_by", "resource_type")
        if group_by not in ("resource_type", "provider", "region", "account_id"):
            group_by = "resource_type"
        limit = min(int(params.get("limit", 20)), 30)

        conds = ["tenant_id = %s"]
        args: list = [self.tenant_id]
        if self.account_ids is not None:
            conds.append("account_id = ANY(%s)")
            args.append(self.account_ids)
        if params.get("account_id"):
            conds.append("account_id = %s")
            args.append(params["account_id"])
        if params.get("provider"):
            conds.append("provider = %s")
            args.append(params["provider"])
        where = " AND ".join(conds)

        with self.di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT COUNT(*) AS total FROM asset_inventory WHERE {where}
                """,
                args,
            )
            total = int(cur.fetchone()["total"])

            cur.execute(
                f"""
                SELECT {group_by}, COUNT(*) AS cnt
                FROM asset_inventory
                WHERE {where}
                GROUP BY {group_by}
                ORDER BY cnt DESC
                LIMIT %s
                """,
                args + [limit],
            )
            breakdown = [dict(r) for r in cur.fetchall()]

        return {"total_assets": total, "breakdown": breakdown}

    def _list_accounts(self) -> Dict:
        try:
            resp = httpx.get(
                f"{ONBOARDING_URL}/api/v1/cloud-accounts",
                params={"tenant_id": self.tenant_id},
                headers=self._engine_headers(),
                timeout=8.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            return {"error": f"Onboarding engine unavailable: {exc}"}

        accounts = data.get("accounts", [])
        if self.account_ids is not None:
            accounts = [a for a in accounts if a.get("account_number") in self.account_ids]

        return {
            "total": len(accounts),
            "accounts": [
                {
                    "cloud_account_id": a.get("account_number"),
                    "name": a.get("account_name"),
                    "provider": a.get("provider"),
                    "status": a.get("account_status"),
                }
                for a in accounts
            ],
        }
