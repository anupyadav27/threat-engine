"""
Pipeline stage handlers — each function triggers one engine via HTTP.

These mirror the ``_trigger_*`` methods in the onboarding orchestrator but
are standalone async functions, decoupled from the onboarding service.
All engines accept ``orchestration_id`` and derive the rest of their context
from the ``scan_orchestration`` DB table.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

# Default service URLs (overridden by env vars in K8s)
_DEFAULTS: Dict[str, str] = {
    "inventory": "http://engine-inventory.threat-engine-engines.svc.cluster.local",
    "check":     "http://engine-check.threat-engine-engines.svc.cluster.local",
    "threat":    "http://engine-threat.threat-engine-engines.svc.cluster.local",
    "compliance":"http://engine-compliance.threat-engine-engines.svc.cluster.local",
    "iam":       "http://engine-iam.threat-engine-engines.svc.cluster.local",
    "datasec":   "http://engine-datasec.threat-engine-engines.svc.cluster.local",
    "secops":    "http://engine-secops.threat-engine-engines.svc.cluster.local",
}


def _url(engine: str) -> str:
    env_key = f"{engine.upper()}_ENGINE_URL"
    return os.getenv(env_key, _DEFAULTS[engine])


async def trigger_inventory(
    orchestration_id: str,
    tenant_id: str,
    account_id: str,
    timeout: float = 300.0,
) -> Dict[str, Any]:
    """Trigger the inventory engine.  Returns the HTTP response JSON."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('inventory')}/api/v1/inventory/scan/discovery",
            json={"tenant_id": tenant_id, "orchestration_id": orchestration_id},
        )
        resp.raise_for_status()
        return resp.json()


async def trigger_check(
    orchestration_id: str,
    provider_type: str,
    timeout: float = 300.0,
) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('check')}/api/v1/scan",
            json={"orchestration_id": orchestration_id},
        )
        resp.raise_for_status()
        return resp.json()


async def trigger_threat(
    orchestration_id: str,
    provider_type: str,
    check_scan_id: Optional[str],
    timeout: float = 120.0,
) -> Dict[str, Any]:
    from datetime import datetime
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('threat')}/api/v1/scan",
            json={
                "orchestration_id": orchestration_id,
                "scan_run_id": orchestration_id,
                "cloud": provider_type.lower(),
                "trigger_type": "sqs",
                "accounts": [],
                "regions": [],
                "services": [],
                "started_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
            },
        )
        resp.raise_for_status()
        return resp.json()


async def trigger_compliance(
    orchestration_id: str,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('compliance')}/api/v1/scan",
            json={
                "orchestration_id": orchestration_id,
                "trigger_type": "sqs",
                "export_to_db": True,
            },
        )
        resp.raise_for_status()
        return resp.json()


async def trigger_iam(
    orchestration_id: str,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('iam')}/api/v1/scan",
            json={"orchestration_id": orchestration_id, "max_findings": 5000},
        )
        resp.raise_for_status()
        return resp.json()


async def trigger_datasec(
    orchestration_id: str,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('datasec')}/api/v1/scan",
            json={
                "orchestration_id": orchestration_id,
                "include_classification": True,
                "include_lineage": True,
                "include_residency": True,
                "include_activity": True,
                "allowed_regions": [],
                "max_findings": 5000,
            },
        )
        resp.raise_for_status()
        return resp.json()
