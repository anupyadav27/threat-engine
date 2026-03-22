"""
Orchestration — Direct Engine Calls from Gateway
=================================================

The gateway orchestrates the pipeline by calling each engine directly.

Pipeline stages:
  Discovery → Check + Inventory (parallel) → Threat → Compliance + IAM + DataSec (parallel)

All engines share a single scan_run_id (UUID). No per-engine scan IDs.
"""
import asyncio
import httpx
import os
import uuid
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

# ── Engine Registry ──────────────────────────────────────────────────────────

ENGINE_REGISTRY: Dict[str, Dict[str, Any]] = {
    "discovery": {
        "url": os.getenv("DISCOVERIES_ENGINE_URL", "http://engine-discoveries.threat-engine-engines.svc.cluster.local"),
        "scan_endpoint": "/api/v1/discovery",
        "timeout": 300,
    },
    "check": {
        "url": os.getenv("CHECK_ENGINE_URL", "http://engine-check.threat-engine-engines.svc.cluster.local"),
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
    "inventory": {
        "url": os.getenv("INVENTORY_ENGINE_URL", "http://engine-inventory.threat-engine-engines.svc.cluster.local"),
        "scan_endpoint": "/api/v1/inventory/scan/discovery",
        "timeout": 300,
    },
    "threat": {
        "url": os.getenv("THREAT_ENGINE_URL", "http://engine-threat.threat-engine-engines.svc.cluster.local"),
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
    "compliance": {
        "url": os.getenv("COMPLIANCE_ENGINE_URL", "http://engine-compliance.threat-engine-engines.svc.cluster.local"),
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
    "iam": {
        "url": os.getenv("IAM_ENGINE_URL", "http://engine-iam.threat-engine-engines.svc.cluster.local"),
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
    "datasec": {
        "url": os.getenv("DATASEC_ENGINE_URL", "http://engine-datasec.threat-engine-engines.svc.cluster.local"),
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
}


class OrchestrationRequest(BaseModel):
    customer_id: str = "default"
    tenant_id: str = "test-tenant-002"
    provider: str = "aws"
    account_id: Optional[str] = "588989875114"
    credential_type: str = "access_key"
    credential_ref: str = "threat-engine/account/588989875114"
    scan_run_id: Optional[str] = None
    include_services: Optional[List[str]] = None
    include_regions: Optional[List[str]] = None
    hierarchy_type: str = "account"
    credentials: Optional[Dict[str, Any]] = None
    use_database: bool = True


# ── Payload builders ─────────────────────────────────────────────────────────

def _build_payload(
    engine: str,
    scan_run_id: str,
    tenant_id: str = "",
    account_id: str = "",
    provider: str = "aws",
    credential_type: str = "access_key",
    credential_ref: str = "",
) -> Dict[str, Any]:
    base = {"scan_run_id": scan_run_id}

    if engine == "discovery":
        base.update({
            "provider": provider,
            "account_id": account_id,
            "tenant_id": tenant_id,
            "credential_type": credential_type,
            "credential_ref": credential_ref,
        })
    elif engine == "check":
        pass  # scan_run_id is sufficient
    elif engine == "inventory":
        base["tenant_id"] = tenant_id
    elif engine == "threat":
        base.update({
            "cloud": provider.lower(),
            "trigger_type": "api",
            "accounts": [],
            "regions": [],
            "services": [],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })
    elif engine == "compliance":
        base.update({"trigger_type": "orchestrated", "export_to_db": True})
    elif engine == "iam":
        base["max_findings"] = 5000
    elif engine == "datasec":
        base.update({
            "include_classification": True,
            "include_lineage": True,
            "include_residency": True,
            "include_activity": True,
            "allowed_regions": [],
            "max_findings": 5000,
        })

    return base


# ── Trigger helpers ──────────────────────────────────────────────────────────

async def _trigger_engine(engine: str, scan_run_id: str, payload: Dict) -> Dict:
    reg = ENGINE_REGISTRY[engine]
    url = f"{reg['url']}{reg['scan_endpoint']}"
    timeout = reg.get("timeout", 120)

    logger.info(f"Triggering {engine} at {url} scan_run_id={scan_run_id}")
    try:
        async with httpx.AsyncClient(timeout=float(timeout)) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return {"status": "triggered", "engine": engine, "response": resp.json()}
    except Exception as e:
        logger.error(f"Failed to trigger {engine}: {e}")
        return {"status": "failed", "engine": engine, "error": str(e)}


async def _trigger_parallel(engines: List[str], scan_run_id: str, **kwargs) -> Dict:
    tasks = [
        _trigger_engine(eng, scan_run_id, _build_payload(eng, scan_run_id, **kwargs))
        for eng in engines
    ]
    results_list = await asyncio.gather(*tasks, return_exceptions=True)
    results = {}
    for eng, result in zip(engines, results_list):
        if isinstance(result, Exception):
            results[eng] = {"status": "failed", "error": str(result)}
        else:
            results[eng] = result
    return results


# ── DB helpers via onboarding API ────────────────────────────────────────────

ONBOARDING_URL = os.getenv(
    "ONBOARDING_ENGINE_URL",
    "http://engine-onboarding.threat-engine-engines.svc.cluster.local",
)


async def _create_orchestration_record(request: OrchestrationRequest, scan_run_id: str):
    """Create orchestration record via onboarding engine's cloud-accounts API."""
    # The onboarding engine creates the scan_orchestration row when we POST to
    # its cloud-accounts endpoint. For now we just log — the discovery engine
    # itself handles the orchestration record via get_orchestration_metadata().
    logger.info(f"Orchestration record expected for scan_run_id={scan_run_id}")


# ── Main orchestration service ───────────────────────────────────────────────

class OrchestrationService:
    """Runs the full scan pipeline directly from the gateway."""

    async def run_orchestration(self, request: OrchestrationRequest) -> Dict[str, Any]:
        scan_run_id = request.scan_run_id or str(uuid.uuid4())

        # Create orchestration record in onboarding DB
        _create_orchestration_record(request, scan_run_id)

        kwargs = dict(
            tenant_id=request.tenant_id,
            account_id=request.account_id or "",
            provider=request.provider,
            credential_type=request.credential_type,
            credential_ref=request.credential_ref,
        )

        results: Dict[str, Any] = {
            "scan_run_id": scan_run_id,
            "overall_status": "running",
            "engines": {},
        }

        # ── Stage 0: Discovery ─────────────────────────────────────────
        logger.info(f"[{scan_run_id[:8]}] Stage 0: discovery")
        disc_payload = _build_payload("discovery", scan_run_id, **kwargs)
        disc_result = await _trigger_engine("discovery", scan_run_id, disc_payload)
        results["engines"]["discovery"] = disc_result
        _update_orchestration_status(scan_run_id, "discovery", disc_result.get("status", "failed"))

        if disc_result.get("status") == "failed":
            results["overall_status"] = "failed"
            return results

        # Discovery creates a K8s Job — it returns immediately.
        # Downstream engines will be triggered when discovery completes
        # (via the pipeline worker or callback).
        # For now, return with discovery triggered.
        results["overall_status"] = "discovery_triggered"
        results["message"] = (
            f"Discovery Job created for scan_run_id={scan_run_id}. "
            "Downstream engines (check, inventory, threat, compliance, iam, datasec) "
            "will run after discovery completes."
        )

        return results
