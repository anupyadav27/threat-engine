"""
Orchestrates downstream engines after ConfigScan completes.

SQS mode
--------
When the environment variable ``SQS_PIPELINE_QUEUE_URL`` is set, the
orchestrator creates the ``scan_orchestration`` record and then publishes a
``scan_requested`` event to SQS **instead of** running the pipeline inline.
The ``pipeline_worker`` service picks up the message and runs the stages.

When ``SQS_PIPELINE_QUEUE_URL`` is NOT set, behaviour is identical to the
original synchronous HTTP pipeline (backward compatible).
"""
import asyncio
import httpx
import sys
import os
from typing import Dict, Any, Optional
from datetime import datetime

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from engine_common.logger import setup_logger, LogContext

from engine_onboarding.config import settings
from engine_onboarding.database import (
    create_orchestration_status,
    update_orchestration_status
)
from engine_onboarding.database.postgres_operations import (
    create_orchestration_record,
    update_orchestration_engine_scan_id,
    get_orchestration_scan_ids,
    mark_orchestration_complete
)

logger = setup_logger(__name__, engine_name="orchestrator")

# ── SQS helpers (imported lazily so missing boto3 doesn't break HTTP mode) ───

_SQS_QUEUE_URL: Optional[str] = os.getenv("SQS_PIPELINE_QUEUE_URL")


def _publish_scan_requested(
    orchestration_id: str,
    tenant_id: str,
    account_id: str,
    provider_type: str,
) -> None:
    """Publish a ``scan_requested`` event to SQS (best-effort).

    Import errors (boto3 not installed) are logged and silently swallowed so
    the caller can fall back to inline HTTP orchestration.
    """
    try:
        from engine_common.sqs import SQSClient  # type: ignore[import]
        from engine_common.pipeline_events import scan_requested  # type: ignore[import]
    except ImportError:
        # Fallback: try shared path directly
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
            from shared.common.sqs import SQSClient  # type: ignore[import]
            from shared.common.pipeline_events import scan_requested  # type: ignore[import]
        except ImportError as exc:
            logger.error("sqs module not available — cannot publish scan_requested: %s", exc)
            return

    event = scan_requested(
        orchestration_id=orchestration_id,
        tenant_id=tenant_id,
        account_id=account_id,
        provider=provider_type,
    )
    try:
        client = SQSClient()
        msg_id = client.publish(
            _SQS_QUEUE_URL,
            event.to_sqs_body(),
            deduplication_id=event.event_id,
            group_id=orchestration_id,
        )
        logger.info("scan_requested published to SQS msg_id=%s oid=%s", msg_id, orchestration_id)
    except Exception as exc:
        logger.error("failed to publish scan_requested to SQS: %s", exc)


class EngineOrchestrator:
    """Orchestrates downstream engines after ConfigScan completes"""
    
    def __init__(self):
        # Engine URLs from config
        self.check_engine_url = getattr(settings, 'check_engine_url', 'http://engine-check.threat-engine-engines.svc.cluster.local')
        self.threat_engine_url = getattr(settings, 'threat_engine_url', 'http://engine-threat.threat-engine-engines.svc.cluster.local')
        self.compliance_engine_url = getattr(settings, 'compliance_engine_url', 'http://engine-compliance.threat-engine-engines.svc.cluster.local')
        self.iam_engine_url = getattr(settings, 'iam_engine_url', 'http://engine-iam.threat-engine-engines.svc.cluster.local')
        self.datasec_engine_url = getattr(settings, 'datasec_engine_url', 'http://engine-datasec.threat-engine-engines.svc.cluster.local')
        self.inventory_engine_url = getattr(settings, 'inventory_engine_url', 'http://engine-inventory.threat-engine-engines.svc.cluster.local')
    
    async def trigger_downstream_engines(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider_type: str,
        scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Trigger all downstream engines after ConfigScan completes

        Args:
            scan_run_id: Unified scan identifier (used as orchestration_id)
            tenant_id: Tenant identifier
            account_id: Account identifier
            provider_type: Cloud provider (aws, azure, gcp, etc.)
            scan_id: ConfigScan engine's scan_id (may differ from scan_run_id)

        Returns:
            Dictionary with orchestration status for each engine
        """
        # Use scan_run_id as orchestration_id
        orchestration_id = scan_run_id

        with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id, account_id=account_id):
            logger.info("Triggering downstream engines", extra={
                "extra_fields": {
                    "orchestration_id": orchestration_id,
                    "provider": provider_type,
                    "scan_id": scan_id,
                    "engines": ["threat", "compliance", "iam", "datasec", "inventory"]
                }
            })

        # Create orchestration record in scan_orchestration table
        try:
            created_id = create_orchestration_record(
                orchestration_id=orchestration_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider_type=provider_type
            )
            logger.info(f"Created orchestration record: {created_id}")
        except Exception as e:
            logger.error(f"Failed to create orchestration record: {e}", exc_info=True)
            # Continue anyway - this is tracking only

        # ── SQS mode: publish event and return immediately ────────────────
        # When SQS_PIPELINE_QUEUE_URL is set, hand off to the pipeline_worker
        # service instead of running the stages inline.  This frees the
        # onboarding API to return to the caller without blocking for 10+ min.
        if _SQS_QUEUE_URL:
            _publish_scan_requested(orchestration_id, tenant_id, account_id, provider_type)
            return {
                "scan_run_id": scan_run_id,
                "orchestration_id": orchestration_id,
                "tenant_id": tenant_id,
                "account_id": account_id,
                "provider_type": provider_type,
                "orchestration_started_at": datetime.utcnow().isoformat(),
                "mode": "sqs",
                "status": "queued",
                "message": "Pipeline handed off to SQS worker — poll scan_orchestration for status.",
            }

        # Use scan_id if provided, otherwise use scan_run_id
        effective_scan_id = scan_id or scan_run_id

        results = {
            "scan_run_id": scan_run_id,
            "orchestration_id": orchestration_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "provider_type": provider_type,
            "orchestration_started_at": datetime.utcnow().isoformat(),
            "engines": {}
        }

        # Step 1: Record Discovery scan_id in scan_orchestration
        # (discovery already completed before this function is called)
        discovery_scan_id = effective_scan_id
        try:
            logger.info(f"Step 1: Recording Discovery scan_id: {discovery_scan_id}")
            update_orchestration_engine_scan_id(
                orchestration_id=orchestration_id,
                engine="discovery",
                engine_scan_id=discovery_scan_id
            )
            logger.info(f"Updated orchestration with discovery_scan_id: {discovery_scan_id}")
        except Exception as e:
            logger.error(f"Failed to update discovery scan ID: {e}")

        # Step 2: Run Inventory engine (reads discovery findings, builds enriched asset inventory)
        # Must run BEFORE check so check_engine can optionally read from inventory_findings.
        inventory_scan_id = None
        try:
            logger.info(f"Step 2: Running Inventory engine with discovery_scan_id={discovery_scan_id}")
            inventory_result = await self._trigger_inventory_engine(
                orchestration_id, tenant_id, account_id
            )
            results["engines"]["inventory"] = inventory_result

            # Extract inventory_scan_id — inventory returns "scan_run_id" in its response
            if isinstance(inventory_result, dict) and "response" in inventory_result:
                response_data = inventory_result["response"]
                inventory_scan_id = (
                    response_data.get("scan_run_id")
                    or response_data.get("scan_id")
                    or response_data.get("inventory_scan_id")
                )
                if inventory_scan_id:
                    try:
                        update_orchestration_engine_scan_id(
                            orchestration_id=orchestration_id,
                            engine="inventory",
                            engine_scan_id=inventory_scan_id
                        )
                        logger.info(f"Updated orchestration with inventory_scan_id: {inventory_scan_id}")
                    except Exception as e:
                        logger.error(f"Failed to update inventory scan ID: {e}")

            logger.info(f"Inventory engine completed, inventory_scan_id: {inventory_scan_id}")
        except Exception as e:
            logger.error(f"Inventory engine failed: {e}")
            results["engines"]["inventory"] = {"status": "failed", "error": str(e)}
            # Continue pipeline — check can still use discovery_scan_id directly

        # Step 3: Run Check engine (reads discovery findings, optionally enriched by inventory)
        # scan_orchestration now has inventory_scan_id so check can query it if needed.
        check_scan_id = None
        try:
            logger.info(f"Step 3: Running Check engine (discovery_scan_id={discovery_scan_id}, "
                        f"inventory_scan_id={inventory_scan_id})")
            check_result = await self._trigger_check_engine(
                orchestration_id, tenant_id, account_id, provider_type
            )
            results["engines"]["check"] = check_result

            # Extract check_scan_id from response
            if isinstance(check_result, dict) and "response" in check_result:
                response_data = check_result["response"]
                check_scan_id = response_data.get("check_scan_id") or response_data.get("scan_id")

                if check_scan_id:
                    try:
                        update_orchestration_engine_scan_id(
                            orchestration_id=orchestration_id,
                            engine="check",
                            engine_scan_id=check_scan_id
                        )
                        logger.info(f"Updated orchestration with check_scan_id: {check_scan_id}")
                    except Exception as e:
                        logger.error(f"Failed to update check scan ID: {e}")

            logger.info(f"Check engine completed, check_scan_id: {check_scan_id}")
        except Exception as e:
            logger.error(f"Check engine failed: {e}")
            results["engines"]["check"] = {"status": "failed", "error": str(e)}
            check_scan_id = discovery_scan_id  # fallback

        # Step 4: Run Threat engine (uses check_scan_id)
        threat_scan_run_id = scan_run_id  # Default fallback
        try:
            logger.info(f"Step 4: Running Threat engine with check_scan_id={check_scan_id}")
            threat_result = await self._trigger_threat_engine(
                orchestration_id, tenant_id, account_id, provider_type, check_scan_id
            )
            results["engines"]["threat"] = threat_result
            if isinstance(threat_result, dict):
                response = threat_result.get("response", {})
                threat_scan_run_id = response.get("scan_run_id") or scan_run_id

                try:
                    update_orchestration_engine_scan_id(
                        orchestration_id=orchestration_id,
                        engine="threat",
                        engine_scan_id=threat_scan_run_id
                    )
                    logger.info(f"Updated orchestration with threat_scan_id: {threat_scan_run_id}")
                except Exception as e:
                    logger.error(f"Failed to update threat scan ID: {e}")

            logger.info(f"Threat engine completed, scan_run_id: {threat_scan_run_id}")
        except Exception as e:
            logger.error(f"Threat engine failed: {e}")
            results["engines"]["threat"] = {"status": "failed", "error": str(e)}

        # Step 5: Run Compliance, IAM, Data Security in parallel (after Threat)
        logger.info("Step 5: Running Compliance/IAM/Data Security engines in parallel")
        parallel_tasks = [
            self._trigger_compliance_engine(orchestration_id, account_id),
            self._trigger_iam_engine(orchestration_id, account_id),
            self._trigger_datasec_engine(orchestration_id, account_id)
        ]

        parallel_results = await asyncio.gather(*parallel_tasks, return_exceptions=True)

        parallel_engine_names = ["compliance", "iam", "datasec"]
        for name, result in zip(parallel_engine_names, parallel_results):
            if isinstance(result, Exception):
                results["engines"][name] = {"status": "failed", "error": str(result)}
            else:
                results["engines"][name] = result

                try:
                    if isinstance(result, dict) and "response" in result:
                        response_data = result["response"]
                        engine_scan_id = response_data.get("scan_id") or response_data.get(f"{name}_scan_id")
                        if engine_scan_id:
                            update_orchestration_engine_scan_id(
                                orchestration_id=orchestration_id,
                                engine=name,
                                engine_scan_id=engine_scan_id
                            )
                            logger.info(f"Updated orchestration with {name}_scan_id: {engine_scan_id}")
                except Exception as e:
                    logger.error(f"Failed to update {name} scan ID: {e}")

        # Mark orchestration as complete
        try:
            # Determine overall status based on engine results
            failed_engines = [
                name for name, result in results["engines"].items()
                if isinstance(result, dict) and result.get("status") == "failed"
            ]
            overall_status = "failed" if failed_engines else "completed"

            mark_orchestration_complete(orchestration_id, status=overall_status)
            logger.info(f"Orchestration {orchestration_id} marked as {overall_status}")
        except Exception as e:
            logger.error(f"Failed to mark orchestration complete: {e}")

        results["orchestration_completed_at"] = datetime.utcnow().isoformat()
        results["orchestration_status"] = overall_status
        return results

    async def _trigger_check_engine(
        self,
        orchestration_id: str,
        tenant_id: str,
        account_id: str,
        provider_type: str
    ) -> Dict[str, Any]:
        """Trigger check engine to validate configurations"""
        # Create orchestration status
        create_orchestration_status(orchestration_id, "check", "running", account_id=account_id)

        try:
            check_engine_url = getattr(settings, 'check_engine_url', 'http://engine-check.threat-engine-engines.svc.cluster.local')
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{check_engine_url}/api/v1/scan",  # ✅ Uniform endpoint
                    json={
                        "orchestration_id": orchestration_id  # Check engine queries scan_orchestration for ALL metadata
                    }
                )
                response.raise_for_status()
                result = {
                    "status": "triggered",
                    "response": response.json()
                }
                update_orchestration_status(orchestration_id, "check", "completed", response_data=result)
                return result
        except Exception as e:
            with LogContext(tenant_id=tenant_id, scan_run_id=orchestration_id):
                logger.error("Failed to trigger check engine", exc_info=True, extra={
                    "extra_fields": {"error": str(e), "engine": "check", "orchestration_id": orchestration_id}
                })
            update_orchestration_status(orchestration_id, "check", "failed", error=str(e))
            raise

    async def _trigger_threat_engine(
        self,
        orchestration_id: str,
        tenant_id: str,
        account_id: str,
        provider_type: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """Trigger threat engine to generate threat report"""
        # Create orchestration status
        create_orchestration_status(orchestration_id, "threat", "running", account_id=account_id)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.threat_engine_url}/api/v1/scan",  # ✅ Uniform endpoint
                    json={
                        "orchestration_id": orchestration_id,  # Threat queries scan_orchestration for ALL metadata
                        "scan_run_id": orchestration_id,
                        "cloud": provider_type.lower(),
                        "trigger_type": "api",
                        "accounts": [],
                        "regions": [],
                        "services": [],
                        "started_at": datetime.utcnow().isoformat(),
                        "completed_at": datetime.utcnow().isoformat()
                    }
                )
                response.raise_for_status()
                result = {
                    "status": "triggered",
                    "response": response.json()
                }
                update_orchestration_status(orchestration_id, "threat", "completed", response_data=result)
                return result
        except Exception as e:
            with LogContext(tenant_id=tenant_id, scan_run_id=orchestration_id):
                logger.error("Failed to trigger threat engine", exc_info=True, extra={
                    "extra_fields": {"error": str(e), "engine": "threat"}
                })
            update_orchestration_status(orchestration_id, "threat", "failed", error=str(e))
            raise
    
    async def _trigger_compliance_engine(
        self,
        orchestration_id: str,
        account_id: str
    ) -> Dict[str, Any]:
        """Trigger compliance engine to generate compliance report"""
        # Create orchestration status
        create_orchestration_status(orchestration_id, "compliance", "running", account_id=account_id)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.compliance_engine_url}/api/v1/scan",  # ✅ Uniform endpoint
                    json={
                        "orchestration_id": orchestration_id,  # Compliance queries scan_orchestration for ALL metadata (csp, tenant_id, check_scan_id)
                        "trigger_type": "orchestrated",
                        "export_to_db": True
                    }
                )
                response.raise_for_status()
                result = {
                    "status": "triggered",
                    "response": response.json()
                }
                update_orchestration_status(orchestration_id, "compliance", "completed", response_data=result)
                return result
        except Exception as e:
            logger.error(f"Failed to trigger compliance engine: {e}")
            update_orchestration_status(orchestration_id, "compliance", "failed", error=str(e))
            raise
    
    async def _trigger_datasec_engine(
        self,
        scan_run_id: str,
        account_id: str
    ) -> Dict[str, Any]:
        """Trigger data security engine to run data security analysis"""
        # Create orchestration status
        create_orchestration_status(scan_run_id, "datasec", "running", account_id=account_id)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.datasec_engine_url}/api/v1/scan",  # ✅ Uniform endpoint
                    json={
                        "orchestration_id": scan_run_id,  # DataSec queries scan_orchestration for ALL metadata (csp, threat_scan_id, tenant_id)
                        "include_classification": True,
                        "include_lineage": True,
                        "include_residency": True,
                        "include_activity": True,
                        "allowed_regions": [],
                        "max_findings": 5000
                    }
                )
                response.raise_for_status()
                result = {
                    "status": "triggered",
                    "response": response.json()
                }
                update_orchestration_status(scan_run_id, "datasec", "completed", response_data=result)
                return result
        except Exception as e:
            logger.error(f"Failed to trigger datasec engine: {e}")
            update_orchestration_status(scan_run_id, "datasec", "failed", error=str(e))
            raise
    
    async def _trigger_iam_engine(
        self,
        scan_run_id: str,
        account_id: str
    ) -> Dict[str, Any]:
        """Trigger IAM security engine to generate IAM posture report"""
        # Create orchestration status
        create_orchestration_status(scan_run_id, "iam", "running", account_id=account_id)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.iam_engine_url}/api/v1/scan",  # ✅ Uniform endpoint
                    json={
                        "orchestration_id": scan_run_id,  # IAM queries scan_orchestration for threat_scan_id and metadata
                        "max_findings": 5000
                    }
                )
                response.raise_for_status()
                result = {
                    "status": "triggered",
                    "response": response.json()
                }
                update_orchestration_status(scan_run_id, "iam", "completed", response_data=result)
                return result
        except Exception as e:
            logger.error(f"Failed to trigger IAM engine: {e}")
            update_orchestration_status(scan_run_id, "iam", "failed", error=str(e))
            raise
    
    async def _trigger_inventory_engine(
        self,
        orchestration_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        """
        Trigger inventory engine to build enriched asset inventory.

        Uses /api/v1/inventory/scan/discovery (DiscoveryScanRequest) which only
        requires tenant_id + orchestration_id.  The inventory engine looks up
        discovery_scan_id and account_id from scan_orchestration itself.

        Runs in Step 2 — BEFORE check engine — so inventory_scan_id is recorded
        in scan_orchestration before downstream engines run.
        """
        create_orchestration_status(orchestration_id, "inventory", "running", account_id=account_id)

        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                response = await client.post(
                    f"{self.inventory_engine_url}/api/v1/inventory/scan/discovery",
                    json={
                        "tenant_id": tenant_id,
                        "orchestration_id": orchestration_id,
                        # Inventory engine reads discovery_scan_id, account_id, provider_type
                        # from scan_orchestration automatically via orchestration_id.
                    }
                )
                response.raise_for_status()
                result = {
                    "status": "triggered",
                    "response": response.json()
                }
                update_orchestration_status(orchestration_id, "inventory", "completed", response_data=result)
                return result
        except Exception as e:
            logger.error(f"Failed to trigger inventory engine: {e}")
            update_orchestration_status(orchestration_id, "inventory", "failed", error=str(e))
            raise
