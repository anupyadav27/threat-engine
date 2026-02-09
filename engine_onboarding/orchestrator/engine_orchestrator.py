"""
Orchestrates downstream engines after ConfigScan completes
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

logger = setup_logger(__name__, engine_name="orchestrator")


class EngineOrchestrator:
    """Orchestrates downstream engines after ConfigScan completes"""
    
    def __init__(self):
        # Engine URLs from config
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
            scan_run_id: Unified scan identifier
            tenant_id: Tenant identifier
            account_id: Account identifier
            provider_type: Cloud provider (aws, azure, gcp, etc.)
            scan_id: ConfigScan engine's scan_id (may differ from scan_run_id)
        
        Returns:
            Dictionary with orchestration status for each engine
        """
        with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id, account_id=account_id):
            logger.info("Triggering downstream engines", extra={
                "extra_fields": {
                    "provider": provider_type,
                    "scan_id": scan_id,
                    "engines": ["threat", "compliance", "iam", "datasec", "inventory"]
                }
            })
        
        # Use scan_id if provided, otherwise use scan_run_id
        effective_scan_id = scan_id or scan_run_id
        
        results = {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "provider_type": provider_type,
            "orchestration_started_at": datetime.utcnow().isoformat(),
            "engines": {}
        }
        
        # Step 1: Run Threat engine first (includes config drift + check drift detection)
        threat_scan_run_id = scan_run_id  # Default fallback
        try:
            logger.info("Step 1: Running Threat engine (with drift detection)")
            threat_result = await self._trigger_threat_engine(scan_run_id, tenant_id, provider_type, effective_scan_id)
            results["engines"]["threat"] = threat_result
            # Extract threat scan_run_id from result (Threat engine returns scan_run_id in response)
            if isinstance(threat_result, dict):
                response = threat_result.get("response", {})
                threat_scan_run_id = response.get("scan_run_id") or scan_run_id
            logger.info(f"Threat engine completed, scan_run_id: {threat_scan_run_id}")
        except Exception as e:
            logger.error(f"Threat engine failed: {e}")
            results["engines"]["threat"] = {"status": "failed", "error": str(e)}
            # Use scan_run_id as fallback
        
        # Step 2: Run Compliance, IAM, Data Security in parallel (after Threat)
        logger.info("Step 2: Running Compliance/IAM/Data Security engines in parallel")
        # Compliance uses check_scan_id (effective_scan_id), IAM/DataSec use threat_scan_run_id
        parallel_tasks = [
            self._trigger_compliance_engine(scan_run_id, tenant_id, provider_type, effective_scan_id),  # Check DB
            self._trigger_iam_engine(scan_run_id, tenant_id, provider_type, threat_scan_run_id),  # Threat DB
            self._trigger_datasec_engine(scan_run_id, tenant_id, provider_type, threat_scan_run_id)  # Threat DB
        ]
        
        parallel_results = await asyncio.gather(*parallel_tasks, return_exceptions=True)
        
        # Process parallel results
        parallel_engine_names = ["compliance", "iam", "datasec"]
        for name, result in zip(parallel_engine_names, parallel_results):
            if isinstance(result, Exception):
                results["engines"][name] = {"status": "failed", "error": str(result)}
            else:
                results["engines"][name] = result
        
        # Step 3: Run Inventory (after parallel engines)
        try:
            logger.info("Step 3: Running Inventory engine")
            inventory_result = await self._trigger_inventory_engine(scan_run_id, tenant_id, account_id, provider_type, effective_scan_id)
            results["engines"]["inventory"] = inventory_result
        except Exception as e:
            logger.error(f"Inventory engine failed: {e}")
            results["engines"]["inventory"] = {"status": "failed", "error": str(e)}
        
        results["orchestration_completed_at"] = datetime.utcnow().isoformat()
        return results
    
    async def _trigger_threat_engine(
        self,
        scan_run_id: str,
        tenant_id: str,
        provider_type: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """Trigger threat engine to generate threat report"""
        # Create orchestration status
        create_orchestration_status(scan_run_id, "threat", "running")
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.threat_engine_url}/api/v1/threat/generate",
                    json={
                        "tenant_id": tenant_id,
                        "scan_run_id": scan_run_id,
                        "cloud": provider_type,
                        "trigger_type": "orchestrated",
                        "accounts": [],  # Will be determined from scan results
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
                update_orchestration_status(scan_run_id, "threat", "completed", response_data=result)
                return result
        except Exception as e:
            with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id):
                logger.error("Failed to trigger threat engine", exc_info=True, extra={
                    "extra_fields": {"error": str(e), "engine": "threat"}
                })
            update_orchestration_status(scan_run_id, "threat", "failed", error=str(e))
            raise
    
    async def _trigger_compliance_engine(
        self,
        scan_run_id: str,
        tenant_id: str,
        provider_type: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """Trigger compliance engine to generate compliance report"""
        # Create orchestration status
        create_orchestration_status(scan_run_id, "compliance", "running")
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.compliance_engine_url}/api/v1/compliance/generate/enterprise",
                    json={
                        "scan_id": scan_id,  # Use scan_id for compatibility
                        "csp": provider_type,
                        "tenant_id": tenant_id,
                        "tenant_name": None,  # Can be fetched from database if needed
                        "trigger_type": "orchestrated"
                    }
                )
                response.raise_for_status()
                result = {
                    "status": "triggered",
                    "response": response.json()
                }
                update_orchestration_status(scan_run_id, "compliance", "completed", response_data=result)
                return result
        except Exception as e:
            logger.error(f"Failed to trigger compliance engine: {e}")
            update_orchestration_status(scan_run_id, "compliance", "failed", error=str(e))
            raise
    
    async def _trigger_datasec_engine(
        self,
        scan_run_id: str,
        tenant_id: str,
        provider_type: str,
        threat_scan_id: str  # Threat scan_run_id (reads from Threat DB)
    ) -> Dict[str, Any]:
        """Trigger data security engine to run data security analysis (reads from Threat DB)"""
        # Create orchestration status
        create_orchestration_status(scan_run_id, "datasec", "running")
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.datasec_engine_url}/api/v1/data-security/scan",
                    json={
                        "csp": provider_type,
                        "scan_id": threat_scan_id,  # Threat scan_run_id
                        "tenant_id": tenant_id,
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
        tenant_id: str,
        provider_type: str,
        threat_scan_id: str  # Threat scan_run_id (reads from Threat DB)
    ) -> Dict[str, Any]:
        """Trigger IAM security engine to generate IAM posture report (reads from Threat DB)"""
        # Create orchestration status
        create_orchestration_status(scan_run_id, "iam", "running")
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.iam_engine_url}/api/v1/iam-security/scan",
                    json={
                        "csp": provider_type,
                        "scan_id": threat_scan_id,  # Threat scan_run_id
                        "tenant_id": tenant_id,
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
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider_type: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """Trigger inventory engine to build inventory graph"""
        # Create orchestration status
        create_orchestration_status(scan_run_id, "inventory", "running")
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.inventory_engine_url}/api/v1/inventory/scan",
                    json={
                        "tenant_id": tenant_id,
                        "configscan_scan_id": scan_id,  # Use scan_id for compatibility
                        "providers": [provider_type],
                        "accounts": [],  # Will be determined from scan results
                        "previous_scan_id": None
                    }
                )
                response.raise_for_status()
                result = {
                    "status": "triggered",
                    "response": response.json()
                }
                update_orchestration_status(scan_run_id, "inventory", "completed", response_data=result)
                return result
        except Exception as e:
            logger.error(f"Failed to trigger inventory engine: {e}")
            update_orchestration_status(scan_run_id, "inventory", "failed", error=str(e))
            raise
