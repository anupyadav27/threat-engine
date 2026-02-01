"""
Orchestration Service - Discovery → Check → Threat → (Compliance + IAM + DataSec) → Inventory
Each step writes to its respective database; Threat/Compliance/IAM/DataSec use check/threat DBs.
"""
import asyncio
import httpx
import os
from typing import Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)


class OrchestrationRequest(BaseModel):
    """Request model for orchestration"""
    customer_id: str
    tenant_id: str
    provider: str = "aws"
    hierarchy_id: Optional[str] = None
    hierarchy_type: str = "account"
    include_services: Optional[list] = None
    include_regions: Optional[list] = None
    credentials: Optional[Dict[str, Any]] = None
    use_database: bool = True


class OrchestrationService:
    """Orchestrates Discovery → Check → Threat → (Compliance + IAM + Data) → Inventory pipeline"""
    
    def __init__(self):
        # Engine URLs from environment or defaults
        self.discoveries_engine_url = os.getenv(
            "DISCOVERIES_ENGINE_URL", 
            "http://localhost:8001"
        )
        self.check_engine_url = os.getenv(
            "CHECK_ENGINE_URL",
            "http://localhost:8002"
        )
        self.threat_engine_url = os.getenv(
            "THREAT_ENGINE_URL",
            "http://localhost:8020"
        )
        self.compliance_engine_url = os.getenv(
            "COMPLIANCE_ENGINE_URL",
            "http://localhost:8010"
        )
        self.iam_engine_url = os.getenv(
            "IAM_ENGINE_URL",
            "http://localhost:8003"  # Changed from 8001 to avoid conflict with Discovery
        )
        self.datasec_engine_url = os.getenv(
            "DATASEC_ENGINE_URL",
            "http://localhost:8004"  # Changed from 8000 to avoid conflict with API Gateway
        )
        self.inventory_engine_url = os.getenv(
            "INVENTORY_ENGINE_URL",
            "http://localhost:8022"
        )
    
    async def run_orchestration(
        self,
        request: OrchestrationRequest
    ) -> Dict[str, Any]:
        """
        Run complete orchestration: Discovery → Check → Threat → (Compliance + IAM + Data) → Inventory
        
        CSPM Best Practice Flow:
        1. Discovery: Scan cloud resources and store in discoveries database
        2. Check: Run compliance checks on discovered resources, store in check database
        3. Threat: Analyze check results for security threats (includes drift detection), generate threat report
        4. Compliance/IAM/Data Security: Run in parallel after Threat completes
        5. Inventory: Build asset inventory and relationships from discoveries
        
        Args:
            request: Orchestration request with customer, tenant, provider, etc.
        
        Returns:
            Dictionary with orchestration results for each step
        """
        orchestration_id = f"orch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        results = {
            "orchestration_id": orchestration_id,
            "customer_id": request.customer_id,
            "tenant_id": request.tenant_id,
            "provider": request.provider,
            "hierarchy_id": request.hierarchy_id,
            "started_at": datetime.utcnow().isoformat(),
            "steps": {}
        }
        
        try:
            # Step 1: Run Discovery
            logger.info(f"[{orchestration_id}] Step 1: Starting discovery scan")
            discovery_result = await self._run_discovery(request)
            results["steps"]["discovery"] = discovery_result
            
            if discovery_result.get("status") != "completed":
                results["status"] = "failed"
                results["error"] = "Discovery step failed"
                results["completed_at"] = datetime.utcnow().isoformat()
                return results
            
            discovery_scan_id = discovery_result.get("discovery_scan_id")
            logger.info(f"[{orchestration_id}] Step 1: Discovery completed - scan_id: {discovery_scan_id}")
            
            # Step 2: Run Check (depends on Discovery)
            logger.info(f"[{orchestration_id}] Step 2: Starting check scan")
            check_result = await self._run_check(
                request=request,
                discovery_scan_id=discovery_scan_id
            )
            results["steps"]["check"] = check_result
            
            if check_result.get("status") != "completed":
                logger.warning(f"[{orchestration_id}] Step 2: Check step failed, continuing to inventory")
            
            check_scan_id = check_result.get("check_scan_id")
            logger.info(f"[{orchestration_id}] Step 2: Check completed - scan_id: {check_scan_id}")
            
            # Step 3: Run Threat Analysis (depends on Check)
            logger.info(f"[{orchestration_id}] Step 3: Starting threat analysis")
            threat_result = await self._run_threat(
                request=request,
                check_scan_id=check_scan_id,
                discovery_scan_id=discovery_scan_id
            )
            results["steps"]["threat"] = threat_result
            
            if threat_result.get("status") != "completed":
                logger.warning(f"[{orchestration_id}] Step 3: Threat step failed, continuing to inventory")
            
            threat_report_id = threat_result.get("report_id") or threat_result.get("scan_run_id")
            logger.info(f"[{orchestration_id}] Step 3: Threat analysis completed - report_id: {threat_report_id}")
            
            # Step 4: Run Compliance, IAM, Data Security in parallel (after Threat)
            logger.info(f"[{orchestration_id}] Step 4: Starting compliance/IAM/data security (parallel)")
            # IAM and DataSec read from Threat DB, Compliance reads from Check DB
            parallel_tasks = [
                self._run_compliance(request, check_scan_id),  # Compliance uses check_scan_id
                self._run_iam_security(request, threat_report_id),  # IAM uses threat_scan_id
                self._run_data_security(request, threat_report_id)  # DataSec uses threat_scan_id
            ]
            
            parallel_results = await asyncio.gather(*parallel_tasks, return_exceptions=True)
            compliance_result, iam_result, datasec_result = parallel_results
            
            results["steps"]["compliance"] = compliance_result if not isinstance(compliance_result, Exception) else {"status": "failed", "error": str(compliance_result)}
            results["steps"]["iam_security"] = iam_result if not isinstance(iam_result, Exception) else {"status": "failed", "error": str(iam_result)}
            results["steps"]["data_security"] = datasec_result if not isinstance(datasec_result, Exception) else {"status": "failed", "error": str(datasec_result)}
            
            logger.info(f"[{orchestration_id}] Step 4: Parallel engines completed")
            
            # Step 5: Run Inventory (depends on Discovery)
            logger.info(f"[{orchestration_id}] Step 5: Starting inventory scan")
            inventory_result = await self._run_inventory(
                request=request,
                discovery_scan_id=discovery_scan_id
            )
            results["steps"]["inventory"] = inventory_result
            
            if inventory_result.get("status") != "completed":
                logger.warning(f"[{orchestration_id}] Step 5: Inventory step failed")
            
            inventory_scan_id = inventory_result.get("scan_run_id")
            logger.info(f"[{orchestration_id}] Step 5: Inventory completed - scan_id: {inventory_scan_id}")
            
            # All steps completed
            results["status"] = "completed"
            results["discovery_scan_id"] = discovery_scan_id
            results["check_scan_id"] = check_scan_id
            results["threat_report_id"] = threat_report_id
            results["inventory_scan_id"] = inventory_scan_id
            results["completed_at"] = datetime.utcnow().isoformat()
            
            logger.info(f"[{orchestration_id}] Orchestration completed successfully")
            
        except Exception as e:
            logger.error(f"[{orchestration_id}] Orchestration failed: {e}", exc_info=True)
            results["status"] = "failed"
            results["error"] = str(e)
            results["completed_at"] = datetime.utcnow().isoformat()
        
        return results
    
    async def _run_discovery(self, request: OrchestrationRequest) -> Dict[str, Any]:
        """Run discovery scan"""
        try:
            async with httpx.AsyncClient(timeout=3600.0) as client:
                # Call discovery API
                discovery_request = {
                    "customer_id": request.customer_id,
                    "tenant_id": request.tenant_id,
                    "provider": request.provider,
                    "hierarchy_id": request.hierarchy_id,
                    "hierarchy_type": request.hierarchy_type,
                    "include_services": request.include_services,
                    "include_regions": request.include_regions,
                    "credentials": request.credentials,
                    "use_database": request.use_database
                }
                
                response = await client.post(
                    f"{self.discoveries_engine_url}/api/v1/discovery",
                    json=discovery_request
                )
                response.raise_for_status()
                result = response.json()
                
                # Poll for completion
                discovery_scan_id = result.get("discovery_scan_id")
                if discovery_scan_id:
                    status = await self._poll_discovery_status(client, discovery_scan_id)
                    return {
                        "status": status.get("status", "unknown"),
                        "discovery_scan_id": discovery_scan_id,
                        "message": status.get("message", "Discovery scan completed")
                    }
                
                return {
                    "status": "failed",
                    "error": "No discovery_scan_id returned"
                }
                
        except Exception as e:
            logger.error(f"Discovery step failed: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e)
            }
    
    async def _poll_discovery_status(self, client: httpx.AsyncClient, scan_id: str, max_wait: int = 3600) -> Dict[str, Any]:
        """Poll discovery scan status until completion"""
        start_time = datetime.utcnow().timestamp()
        
        while True:
            elapsed = datetime.utcnow().timestamp() - start_time
            if elapsed > max_wait:
                return {"status": "timeout", "message": "Discovery scan timed out"}
            
            try:
                response = await client.get(
                    # ConfigScan engines expose a unified scan status endpoint.
                    # Discovery and Check scans are stored in the same in-memory `scans` map.
                    f"{self.discoveries_engine_url}/api/v1/scan/{scan_id}/status"
                )
                response.raise_for_status()
                status_data = response.json()
                
                status = status_data.get("status")
                if status in ["completed", "failed", "cancelled"]:
                    return status_data
                
                # Wait before next poll
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Error polling discovery status: {e}")
                return {"status": "error", "error": str(e)}
    
    async def _run_check(self, request: OrchestrationRequest, discovery_scan_id: str) -> Dict[str, Any]:
        """Run check scan"""
        try:
            async with httpx.AsyncClient(timeout=3600.0) as client:
                check_request = {
                    "discovery_scan_id": discovery_scan_id,
                    "customer_id": request.customer_id,
                    "tenant_id": request.tenant_id,
                    "provider": request.provider,
                    "hierarchy_id": request.hierarchy_id,
                    "hierarchy_type": request.hierarchy_type,
                    "include_services": request.include_services,
                    "check_source": "default",
                    "use_ndjson": False  # Use database mode
                }
                
                response = await client.post(
                    f"{self.check_engine_url}/api/v1/check",
                    json=check_request
                )
                response.raise_for_status()
                result = response.json()
                
                # Poll for completion
                check_scan_id = result.get("check_scan_id")
                if check_scan_id:
                    status = await self._poll_check_status(client, check_scan_id)
                    return {
                        "status": status.get("status", "unknown"),
                        "check_scan_id": check_scan_id,
                        "message": status.get("message", "Check scan completed")
                    }
                
                return {
                    "status": "failed",
                    "error": "No check_scan_id returned"
                }
                
        except Exception as e:
            logger.error(f"Check step failed: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e)
            }
    
    async def _poll_check_status(self, client: httpx.AsyncClient, scan_id: str, max_wait: int = 3600) -> Dict[str, Any]:
        """Poll check scan status until completion"""
        start_time = datetime.utcnow().timestamp()
        
        while True:
            elapsed = datetime.utcnow().timestamp() - start_time
            if elapsed > max_wait:
                return {"status": "timeout", "message": "Check scan timed out"}
            
            try:
                response = await client.get(
                    # ConfigScan engines expose a unified scan status endpoint.
                    f"{self.check_engine_url}/api/v1/scan/{scan_id}/status"
                )
                response.raise_for_status()
                status_data = response.json()
                
                status = status_data.get("status")
                if status in ["completed", "failed", "cancelled"]:
                    return status_data
                
                # Wait before next poll
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Error polling check status: {e}")
                return {"status": "error", "error": str(e)}
    
    async def _run_threat(self, request: OrchestrationRequest, check_scan_id: str, discovery_scan_id: str) -> Dict[str, Any]:
        """Run threat analysis on check results"""
        try:
            async with httpx.AsyncClient(timeout=3600.0) as client:
                # Use check_scan_id as scan_run_id for threat engine
                scan_run_id = check_scan_id or discovery_scan_id
                
                threat_request = {
                    "tenant_id": request.tenant_id,
                    "scan_run_id": scan_run_id,  # This is the check_scan_id
                    "cloud": request.provider,
                    "trigger_type": "orchestrated",
                    "accounts": [request.hierarchy_id] if request.hierarchy_id else [],
                    "regions": request.include_regions or [],
                    "services": request.include_services or [],
                    "started_at": datetime.utcnow().isoformat(),
                    "completed_at": None,
                    "discovery_scan_id": discovery_scan_id  # Pass discovery_scan_id for config drift detection
                }
                
                response = await client.post(
                    f"{self.threat_engine_url}/api/v1/threat/generate",
                    json=threat_request
                )
                response.raise_for_status()
                result = response.json()
                
                return {
                    "status": "completed",
                    "report_id": result.get("scan_run_id") or scan_run_id,
                    "message": "Threat analysis completed",
                    "total_threats": result.get("threat_summary", {}).get("total_threats", 0)
                }
        except Exception as e:
            logger.error(f"Threat step failed: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e)
            }
    
    async def _run_compliance(self, request: OrchestrationRequest, check_scan_id: str) -> Dict[str, Any]:
        """Run compliance engine"""
        try:
            async with httpx.AsyncClient(timeout=600.0) as client:
                compliance_request = {
                    "tenant_id": request.tenant_id,
                    "scan_id": check_scan_id,
                    "csp": request.provider
                }
                
                response = await client.post(
                    f"{self.compliance_engine_url}/api/v1/compliance/generate/from-check-db",
                    json=compliance_request
                )
                response.raise_for_status()
                result = response.json()
                
                return {
                    "status": "completed",
                    "report_id": result.get("report_id"),
                    "message": "Compliance report generated"
                }
                
        except Exception as e:
            logger.error(f"Compliance step failed: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e)
            }
    
    async def _run_iam_security(self, request: OrchestrationRequest, threat_scan_id: str) -> Dict[str, Any]:
        """Run IAM security engine (reads from Threat DB)"""
        try:
            async with httpx.AsyncClient(timeout=600.0) as client:
                iam_request = {
                    "csp": request.provider,
                    "scan_id": threat_scan_id,  # Threat scan_run_id
                    "tenant_id": request.tenant_id
                }
                
                response = await client.post(
                    f"{self.iam_engine_url}/api/v1/iam-security/scan",
                    json=iam_request
                )
                response.raise_for_status()
                result = response.json()
                
                return {
                    "status": "completed",
                    "message": "IAM security report generated",
                    "findings_count": result.get("summary", {}).get("total_findings", 0)
                }
                
        except Exception as e:
            logger.error(f"IAM security step failed: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e)
            }
    
    async def _run_data_security(self, request: OrchestrationRequest, check_scan_id: str) -> Dict[str, Any]:
        """Run data security engine"""
        try:
            async with httpx.AsyncClient(timeout=600.0) as client:
                datasec_request = {
                    "csp": request.provider,
                    "scan_id": check_scan_id,
                    "tenant_id": request.tenant_id,
                    "include_classification": True,
                    "include_lineage": True,
                    "include_residency": True,
                    "include_activity": True
                }
                
                response = await client.post(
                    f"{self.datasec_engine_url}/api/v1/data-security/scan",
                    json=datasec_request
                )
                response.raise_for_status()
                result = response.json()
                
                return {
                    "status": "completed",
                    "message": "Data security report generated",
                    "findings_count": result.get("summary", {}).get("total_findings", 0)
                }
                
        except Exception as e:
            logger.error(f"Data security step failed: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e)
            }
    
    async def _run_inventory(self, request: OrchestrationRequest, discovery_scan_id: str) -> Dict[str, Any]:
        """Run inventory scan"""
        try:
            async with httpx.AsyncClient(timeout=3600.0) as client:
                inventory_request = {
                    "tenant_id": request.tenant_id,
                    "configscan_scan_id": discovery_scan_id,  # Use discovery scan ID
                    "providers": [request.provider],
                    "accounts": [request.hierarchy_id] if request.hierarchy_id else None,
                    "previous_scan_id": None
                }
                
                response = await client.post(
                    f"{self.inventory_engine_url}/api/v1/inventory/scan/discovery",
                    json=inventory_request
                )
                response.raise_for_status()
                result = response.json()
                
                return {
                    "status": "completed",
                    "scan_run_id": result.get("scan_run_id"),
                    "message": "Inventory scan completed",
                    "total_assets": result.get("total_assets", 0),
                    "total_relationships": result.get("total_relationships", 0)
                }
                
        except Exception as e:
            logger.error(f"Inventory step failed: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e)
            }
