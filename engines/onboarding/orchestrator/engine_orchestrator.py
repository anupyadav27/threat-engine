"""
Engine Orchestrator — CSPM Scan Pipeline
=========================================

Orchestrates all downstream engines after account onboarding / discovery.

Pipeline stages (sequential + parallel):
  Discovery → Check + Inventory (parallel) → Threat → Compliance + IAM + DataSec (parallel)

All engines receive a single ``scan_run_id`` (UUID). No per-engine scan IDs.

Supports two modes:
  1. **Full pipeline** — ``run_pipeline(scan_run_id)`` runs all stages in order
  2. **Individual engine** — ``trigger_engine("check", scan_run_id)`` runs one engine
"""
import asyncio
import httpx
import sys
import os
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from engine_common.logger import setup_logger, LogContext

from engine_onboarding.config import settings
from engine_onboarding.database import (
    create_orchestration_status,
    update_orchestration_status
)
from engine_onboarding.database.postgres_operations import (
    create_orchestration_record,
    mark_orchestration_complete
)

logger = setup_logger(__name__, engine_name="orchestrator")

# ── Engine registry ──────────────────────────────────────────────────────────
# Single source of truth for engine URLs and scan endpoints.

ENGINE_REGISTRY: Dict[str, Dict[str, Any]] = {
    "discovery": {
        "url_setting": "discoveries_engine_url",
        "default_url": "http://engine-discoveries.threat-engine-engines.svc.cluster.local",
        "scan_endpoint": "/api/v1/discovery",
        "timeout": 300,
    },
    "check": {
        "url_setting": "check_engine_url",
        "default_url": "http://engine-check.threat-engine-engines.svc.cluster.local",
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
    "inventory": {
        "url_setting": "inventory_engine_url",
        "default_url": "http://engine-inventory.threat-engine-engines.svc.cluster.local",
        "scan_endpoint": "/api/v1/inventory/scan/discovery",
        "timeout": 300,
    },
    "threat": {
        "url_setting": "threat_engine_url",
        "default_url": "http://engine-threat.threat-engine-engines.svc.cluster.local",
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
    "compliance": {
        "url_setting": "compliance_engine_url",
        "default_url": "http://engine-compliance.threat-engine-engines.svc.cluster.local",
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
    "iam": {
        "url_setting": "iam_engine_url",
        "default_url": "http://engine-iam.threat-engine-engines.svc.cluster.local",
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
    "datasec": {
        "url_setting": "datasec_engine_url",
        "default_url": "http://engine-datasec.threat-engine-engines.svc.cluster.local",
        "scan_endpoint": "/api/v1/scan",
        "timeout": 120,
    },
}

VALID_ENGINES = list(ENGINE_REGISTRY.keys())


def _engine_url(engine: str) -> str:
    """Resolve engine URL from settings or default."""
    reg = ENGINE_REGISTRY[engine]
    return getattr(settings, reg["url_setting"], reg["default_url"])


# ── Core trigger helper ──────────────────────────────────────────────────────


async def _trigger_engine(
    engine: str,
    scan_run_id: str,
    payload: Dict[str, Any],
    account_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Trigger a single engine scan via HTTP POST.

    Args:
        engine: Engine name (must be in ENGINE_REGISTRY)
        scan_run_id: Pipeline-wide UUID
        payload: JSON body to POST
        account_id: For orchestration status tracking

    Returns:
        {"status": "triggered", "engine": engine, "response": {...}}
    """
    reg = ENGINE_REGISTRY[engine]
    url = _engine_url(engine)
    endpoint = f"{url}{reg['scan_endpoint']}"
    timeout = reg.get("timeout", 120)

    create_orchestration_status(scan_run_id, engine, "running", account_id=account_id)

    try:
        async with httpx.AsyncClient(timeout=float(timeout)) as client:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            result = {
                "status": "triggered",
                "engine": engine,
                "response": response.json()
            }
            update_orchestration_status(scan_run_id, engine, "completed", response_data=result)
            logger.info(f"{engine} triggered successfully scan_run_id={scan_run_id}")
            return result
    except Exception as e:
        logger.error(f"Failed to trigger {engine}: {e}", exc_info=True)
        update_orchestration_status(scan_run_id, engine, "failed", error=str(e))
        raise


# ── Payload builders ─────────────────────────────────────────────────────────


def _build_payload(
    engine: str,
    scan_run_id: str,
    tenant_id: str = "",
    account_id: str = "",
    provider_type: str = "aws",
) -> Dict[str, Any]:
    """Build the JSON payload for a given engine."""
    base = {"scan_run_id": scan_run_id}

    if engine == "discovery":
        base.update({"provider": provider_type, "account_id": account_id, "tenant_id": tenant_id})
    elif engine == "check":
        pass  # scan_run_id is sufficient
    elif engine == "inventory":
        base["tenant_id"] = tenant_id
    elif engine == "threat":
        base.update({
            "cloud": provider_type.lower(),
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


# ── Public API ───────────────────────────────────────────────────────────────


class EngineOrchestrator:
    """Orchestrates downstream engines after discovery completes.

    Usage:
        orch = EngineOrchestrator()

        # Full pipeline (discovery already done)
        result = await orch.run_pipeline(scan_run_id, tenant_id, account_id, "aws")

        # Single engine
        result = await orch.trigger_engine("threat", scan_run_id, tenant_id, account_id, "aws")
    """

    async def trigger_engine(
        self,
        engine: str,
        scan_run_id: str,
        tenant_id: str = "",
        account_id: str = "",
        provider_type: str = "aws",
    ) -> Dict[str, Any]:
        """Trigger a single engine directly.

        Args:
            engine: One of: discovery, check, inventory, threat, compliance, iam, datasec
            scan_run_id: Pipeline UUID (must exist in scan_orchestration)
            tenant_id: Tenant identifier
            account_id: Cloud account ID
            provider_type: Cloud provider

        Returns:
            Engine trigger result dict
        """
        if engine not in ENGINE_REGISTRY:
            raise ValueError(f"Unknown engine '{engine}'. Valid: {VALID_ENGINES}")

        payload = _build_payload(engine, scan_run_id, tenant_id, account_id, provider_type)
        return await _trigger_engine(engine, scan_run_id, payload, account_id=account_id)

    async def trigger_engines(
        self,
        engines: List[str],
        scan_run_id: str,
        tenant_id: str = "",
        account_id: str = "",
        provider_type: str = "aws",
    ) -> Dict[str, Any]:
        """Trigger multiple engines in parallel.

        Args:
            engines: List of engine names to run in parallel
            scan_run_id: Pipeline UUID
            tenant_id: Tenant identifier
            account_id: Cloud account ID
            provider_type: Cloud provider

        Returns:
            Dict mapping engine name → result or error
        """
        for eng in engines:
            if eng not in ENGINE_REGISTRY:
                raise ValueError(f"Unknown engine '{eng}'. Valid: {VALID_ENGINES}")

        tasks = [
            self.trigger_engine(eng, scan_run_id, tenant_id, account_id, provider_type)
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

    async def run_pipeline(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider_type: str,
    ) -> Dict[str, Any]:
        """Run the full pipeline: discovery(done) → check+inventory → threat → compliance+iam+datasec.

        Discovery is assumed to have already completed (triggered by account onboarding).

        Args:
            scan_run_id: Pipeline UUID (must exist in scan_orchestration)
            tenant_id: Tenant identifier
            account_id: Cloud account ID
            provider_type: Cloud provider (aws, azure, gcp, etc.)

        Returns:
            Dictionary with orchestration status for each engine
        """
        with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id, account_id=account_id):
            logger.info("Starting pipeline", extra={
                "extra_fields": {
                    "scan_run_id": scan_run_id,
                    "provider": provider_type,
                    "engines": ["check", "inventory", "threat", "compliance", "iam", "datasec"],
                }
            })

        # Create orchestration record
        try:
            create_orchestration_record(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider_type=provider_type,
            )
            logger.info(f"Created orchestration record: {scan_run_id}")
        except Exception as e:
            logger.error(f"Failed to create orchestration record: {e}", exc_info=True)

        results: Dict[str, Any] = {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "provider_type": provider_type,
            "orchestration_started_at": datetime.now(timezone.utc).isoformat(),
            "engines": {},
        }

        kwargs = dict(tenant_id=tenant_id, account_id=account_id, provider_type=provider_type)

        # ── Stage 1: Check + Inventory (parallel) ────────────────────────
        logger.info(f"[{scan_run_id[:8]}] Stage 1: check + inventory (parallel)")
        stage1 = await self.trigger_engines(
            ["check", "inventory"], scan_run_id, **kwargs
        )
        results["engines"].update(stage1)

        # If check failed, skip threat/compliance (they need check_findings)
        if stage1.get("check", {}).get("status") == "failed":
            logger.error(f"[{scan_run_id[:8]}] check FAILED — skipping threat + downstream")
            results["orchestration_status"] = "failed"
            results["orchestration_completed_at"] = datetime.now(timezone.utc).isoformat()
            try:
                mark_orchestration_complete(scan_run_id, status="failed")
            except Exception:
                pass
            return results

        # ── Stage 2: Threat ──────────────────────────────────────────────
        logger.info(f"[{scan_run_id[:8]}] Stage 2: threat")
        try:
            threat_result = await self.trigger_engine("threat", scan_run_id, **kwargs)
            results["engines"]["threat"] = threat_result
        except Exception as e:
            logger.error(f"[{scan_run_id[:8]}] threat FAILED: {e}")
            results["engines"]["threat"] = {"status": "failed", "error": str(e)}

        # ── Stage 3: Compliance + IAM + DataSec (parallel) ───────────────
        logger.info(f"[{scan_run_id[:8]}] Stage 3: compliance + iam + datasec (parallel)")
        stage3 = await self.trigger_engines(
            ["compliance", "iam", "datasec"], scan_run_id, **kwargs
        )
        results["engines"].update(stage3)

        # ── Final ────────────────────────────────────────────────────────
        failed_engines = [
            name for name, r in results["engines"].items()
            if isinstance(r, dict) and r.get("status") == "failed"
        ]
        overall_status = "failed" if failed_engines else "completed"

        try:
            mark_orchestration_complete(scan_run_id, status=overall_status)
        except Exception as e:
            logger.error(f"Failed to mark orchestration complete: {e}")

        results["orchestration_completed_at"] = datetime.now(timezone.utc).isoformat()
        results["orchestration_status"] = overall_status
        logger.info(f"[{scan_run_id[:8]}] Pipeline {overall_status}")
        return results
