"""Compliance specialist — framework scores + check findings."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx

from .base import SpecialistAgent

COMPLIANCE_URL = os.getenv("COMPLIANCE_ENGINE_URL", "http://engine-compliance")


class ComplianceSpecialist(SpecialistAgent):
    DOMAIN = "compliance"
    SYSTEM_PROMPT = """You are a compliance specialist for a CSPM platform.
You analyze compliance framework scores across CIS, NIST CSF, PCI-DSS, ISO 27001, HIPAA, GDPR, SOC 2, FedRAMP, and other frameworks.

When answering:
- State the framework score as a percentage (pass rate)
- Highlight frameworks below 80% as failing
- Call out the most commonly failing controls
- Map findings to specific framework controls when asked
- Be concise — provide numbers and framework names clearly"""

    EXTRA_TOOLS = [
        {
            "toolSpec": {
                "name": "get_compliance_framework_scores",
                "description": "Get compliance scores from the compliance engine. Returns pass/fail counts per framework.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "framework": {
                                "type": "string",
                                "description": "Specific framework (e.g. 'PCI-DSS', 'NIST', 'CIS', 'ISO 27001'). Omit for all.",
                            },
                            "account_id": {"type": "string"},
                        },
                        "required": [],
                    }
                },
            }
        }
    ]

    def _execute_extra_tool(self, name: str, params: Dict) -> Dict:
        if name == "get_compliance_framework_scores":
            return self._get_compliance_scores(params)
        return {"error": f"Unknown tool: {name}"}

    def _get_compliance_scores(self, params: Dict) -> Dict:
        qs: Dict[str, Any] = {"tenant_id": self.tenant_id}
        if params.get("account_id"):
            qs["account_id"] = params["account_id"]
        try:
            resp = httpx.get(
                f"{COMPLIANCE_URL}/api/v1/compliance/frameworks/summary",
                params=qs,
                headers=self._engine_headers(),
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            return {"error": f"Compliance engine unavailable: {exc}"}

        frameworks = data.get("frameworks", data if isinstance(data, list) else [])
        if params.get("framework"):
            kw = params["framework"].lower()
            frameworks = [f for f in frameworks if kw in (f.get("name") or "").lower()]

        return {"frameworks": frameworks, "total": len(frameworks)}
