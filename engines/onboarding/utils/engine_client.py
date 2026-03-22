"""
Client for calling engine APIs
"""
import httpx
import asyncio
from typing import List, Optional, Dict, Any
from engine_onboarding.config import settings


class EngineClient:
    """HTTP client to call engine APIs via ClusterIP"""
    
    def __init__(self):
        self.aws_url = settings.aws_engine_url
        self.azure_url = settings.azure_engine_url
        self.gcp_url = settings.gcp_engine_url
        self.alicloud_url = settings.alicloud_engine_url
        self.oci_url = settings.oci_engine_url
        self.ibm_url = settings.ibm_engine_url
        self.k8s_url = settings.k8s_engine_url
    
    async def _run_discovery_scan(
        self,
        discoveries_url: str,
        request_payload: Dict[str, Any],
        provider_label: str,
        logger
    ) -> Dict[str, Any]:
        """Common discovery scan logic: start scan with retries, poll for completion.

        Used by scan_aws(), scan_azure(), scan_gcp() etc. All route through the
        unified discoveries engine at /api/v1/discovery.
        """
        async def _start_discovery_with_retries(client: httpx.AsyncClient) -> str:
            backoffs = [0.0, 1.0, 2.0]
            last_err: Exception | None = None
            for i, delay in enumerate(backoffs, start=1):
                if delay:
                    await asyncio.sleep(delay)
                try:
                    logger.info(f"POST {discoveries_url}/api/v1/discovery (attempt {i}/{len(backoffs)})")
                    resp = await client.post(
                        f"{discoveries_url}/api/v1/discovery",
                        json=request_payload,
                        timeout=httpx.Timeout(60.0, connect=30.0, read=60.0, write=60.0),
                    )
                    resp.raise_for_status()
                    discovery_scan_id = resp.json().get("discovery_scan_id")
                    if not discovery_scan_id:
                        raise RuntimeError(f"Discoveries engine response missing discovery_scan_id: {resp.text[:300]}")
                    return discovery_scan_id
                except (httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout) as e:
                    last_err = e
                    logger.warning(f"Start discovery attempt {i} failed: {type(e).__name__}: {e}")
                except httpx.HTTPStatusError as e:
                    raise Exception(f"Discoveries engine HTTP {e.response.status_code}: {e.response.text}") from e
            raise Exception(f"Failed to start discovery after retries: {last_err}") from last_err

        async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=30.0)) as client:
            discovery_scan_id = await _start_discovery_with_retries(client)
            logger.info(f"{provider_label} discovery started. discovery_scan_id={discovery_scan_id}")

            max_wait = int(getattr(settings, "engine_scan_max_wait_seconds", 3600))
            poll_interval = int(getattr(settings, "engine_scan_poll_interval_seconds", 10))
            elapsed = 0

            while elapsed < max_wait:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

                try:
                    status_response = await client.get(
                        f"{discoveries_url}/api/v1/discovery/{discovery_scan_id}/status",
                        timeout=30.0
                    )
                    status_response.raise_for_status()
                    status_data = status_response.json()
                except httpx.HTTPStatusError as e:
                    if e.response is not None and e.response.status_code == 404:
                        raise Exception(
                            f"Discovery {discovery_scan_id} not found on discoveries engine (engine restarted / lost state)"
                        ) from e
                    raise
                status = status_data.get("status")
                logger.info(f"Discovery {discovery_scan_id} status: {status} (elapsed: {elapsed}s)")

                if status == "completed":
                    return {
                        "scan_id": discovery_scan_id,
                        "status": "completed",
                        "total_checks": 0,
                        "passed_checks": 0,
                        "failed_checks": 0,
                        "duration_seconds": elapsed,
                    }

                if status == "failed":
                    raise Exception(f"Discovery failed: {status_data.get('error', 'Unknown error')}")

            raise Exception(f"Discovery {discovery_scan_id} timed out after {max_wait} seconds")

    async def scan_aws(
        self,
        credentials: Dict[str, Any],
        account_number: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        exclude_services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call AWS discoveries engine API and wait for completion"""
        import logging
        logger = logging.getLogger(__name__)

        discoveries_url = "http://engine-discoveries.threat-engine-engines.svc.cluster.local"

        request_payload = {
            "customer_id": tenant_id or "default",
            "tenant_id": tenant_id or "default-tenant",
            "provider": "aws",
            "account_id": account_number,
            "hierarchy_type": "account",
            "credentials": credentials,
            "use_database": True
        }
        if regions:
            request_payload["include_regions"] = regions
        if services:
            request_payload["include_services"] = services

        logger.info(f"Calling AWS Discoveries Engine API at {discoveries_url}/api/v1/discovery")
        logger.info(f"Request payload - Account: {account_number}")
        logger.info(f"  Include Regions: {request_payload.get('include_regions', 'None (scan all)')}")
        logger.info(f"  Include Services: {request_payload.get('include_services', 'None (scan all)')}")

        return await self._run_discovery_scan(discoveries_url, request_payload, "AWS", logger)
    
    async def scan_azure(
        self,
        credentials: Dict[str, Any],
        subscription_id: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call Azure discoveries engine API and wait for completion"""
        import logging
        logger = logging.getLogger(__name__)

        # NEW ARCHITECTURE: Route through unified discoveries engine (same as AWS)
        discoveries_url = "http://engine-discoveries.threat-engine-engines.svc.cluster.local"

        request_payload = {
            "customer_id": tenant_id or "default",
            "tenant_id": tenant_id or "default-tenant",
            "provider": "azure",
            "account_id": subscription_id,
            "hierarchy_type": "subscription",
            "credentials": credentials,
            "use_database": True
        }
        if regions:
            request_payload["include_regions"] = regions
        if services:
            request_payload["include_services"] = services

        logger.info(f"Calling Azure Discoveries Engine API at {discoveries_url}/api/v1/discovery")
        logger.info(f"Request payload - Subscription: {subscription_id}")

        return await self._run_discovery_scan(discoveries_url, request_payload, "Azure", logger)
    
    async def scan_gcp(
        self,
        credentials: Dict[str, Any],
        project_id: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call GCP discoveries engine API and wait for completion"""
        import logging
        logger = logging.getLogger(__name__)

        # NEW ARCHITECTURE: Route through unified discoveries engine (same as AWS)
        discoveries_url = "http://engine-discoveries.threat-engine-engines.svc.cluster.local"

        request_payload = {
            "customer_id": tenant_id or "default",
            "tenant_id": tenant_id or "default-tenant",
            "provider": "gcp",
            "account_id": project_id,
            "hierarchy_type": "project",
            "credentials": credentials,
            "use_database": True
        }
        if regions:
            request_payload["include_regions"] = regions
        if services:
            request_payload["include_services"] = services

        logger.info(f"Calling GCP Discoveries Engine API at {discoveries_url}/api/v1/discovery")
        logger.info(f"Request payload - Project: {project_id}")

        return await self._run_discovery_scan(discoveries_url, request_payload, "GCP", logger)
    
    async def scan_alicloud(
        self,
        credentials: Dict[str, Any],
        account_id: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call AliCloud engine API"""
        request_payload = {
            "account": account_id,
            "credentials": credentials,
            "regions": regions or [],
            "services": services or []
        }
        if tenant_id:
            request_payload["tenant_id"] = tenant_id
        if scan_run_id:
            request_payload["scan_run_id"] = scan_run_id
        
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{self.alicloud_url}/api/v1/scan",
                json=request_payload
            )
            response.raise_for_status()
            return response.json()
    
    async def scan_oci(
        self,
        credentials: Dict[str, Any],
        tenancy_ocid: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call OCI discoveries engine API and wait for completion"""
        import logging
        logger = logging.getLogger(__name__)

        discoveries_url = "http://engine-discoveries.threat-engine-engines.svc.cluster.local"

        request_payload = {
            "customer_id": tenant_id or "default",
            "tenant_id": tenant_id or "default-tenant",
            "provider": "oci",
            "account_id": tenancy_ocid,
            "hierarchy_type": "tenancy",
            "credentials": credentials,
            "use_database": True
        }
        if regions:
            request_payload["include_regions"] = regions
        if services:
            request_payload["include_services"] = services

        logger.info(f"Calling OCI Discoveries Engine API at {discoveries_url}/api/v1/discovery")
        logger.info(f"Request payload - Tenancy: {tenancy_ocid}")

        return await self._run_discovery_scan(discoveries_url, request_payload, "OCI", logger)

    async def scan_ibm(
        self,
        credentials: Dict[str, Any],
        account_id: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call IBM Cloud discoveries engine API and wait for completion"""
        import logging
        logger = logging.getLogger(__name__)

        discoveries_url = "http://engine-discoveries.threat-engine-engines.svc.cluster.local"

        request_payload = {
            "customer_id": tenant_id or "default",
            "tenant_id": tenant_id or "default-tenant",
            "provider": "ibm",
            "account_id": account_id,
            "hierarchy_type": "account",
            "credentials": credentials,
            "use_database": True
        }
        if regions:
            request_payload["include_regions"] = regions
        if services:
            request_payload["include_services"] = services

        logger.info(f"Calling IBM Discoveries Engine API at {discoveries_url}/api/v1/discovery")
        logger.info(f"Request payload - Account: {account_id}")

        return await self._run_discovery_scan(discoveries_url, request_payload, "IBM", logger)

    async def scan_k8s(
        self,
        credentials: Dict[str, Any],
        cluster_name: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call K8s discoveries engine API and wait for completion"""
        import logging
        logger = logging.getLogger(__name__)

        discoveries_url = "http://engine-discoveries.threat-engine-engines.svc.cluster.local"

        request_payload = {
            "customer_id": tenant_id or "default",
            "tenant_id": tenant_id or "default-tenant",
            "provider": "k8s",
            "account_id": cluster_name,
            "hierarchy_type": "cluster",
            "credentials": credentials,
            "use_database": True
        }
        if regions:
            request_payload["include_regions"] = regions
        if services:
            request_payload["include_services"] = services

        logger.info(f"Calling K8s Discoveries Engine API at {discoveries_url}/api/v1/discovery")
        logger.info(f"Request payload - Cluster: {cluster_name}")

        return await self._run_discovery_scan(discoveries_url, request_payload, "K8s", logger)

    # Common methods for all engines
    async def cancel_scan(self, provider: str, scan_id: str) -> Dict[str, Any]:
        """Cancel a running scan"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url,
            "k8s": self.k8s_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{url}/api/v1/scan/{scan_id}/cancel")
            response.raise_for_status()
            return response.json()
    
    async def get_scan_progress(self, provider: str, scan_id: str) -> Dict[str, Any]:
        """Get scan progress"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url,
            "k8s": self.k8s_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/scan/{scan_id}/progress")
            response.raise_for_status()
            return response.json()
    
    async def get_scan_status(self, provider: str, scan_id: str) -> Dict[str, Any]:
        """Get scan status with progress"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url,
            "k8s": self.k8s_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/scan/{scan_id}/status")
            response.raise_for_status()
            return response.json()
    
    async def get_scan_results(
        self,
        provider: str,
        scan_id: str,
        page: int = 1,
        page_size: int = 100
    ) -> Dict[str, Any]:
        """Get scan results with pagination"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url,
            "k8s": self.k8s_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(
                f"{url}/api/v1/scan/{scan_id}/results",
                params={"page": page, "page_size": page_size}
            )
            response.raise_for_status()
            return response.json()
    
    async def get_scan_summary(self, provider: str, scan_id: str) -> Dict[str, Any]:
        """Get scan summary with statistics"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url,
            "k8s": self.k8s_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/scan/{scan_id}/summary")
            response.raise_for_status()
            return response.json()
    
    async def list_scans(
        self,
        provider: str,
        status: Optional[str] = None,
        filter_key: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List scans with filters"""
        url_map = {
            "aws": (self.aws_url, "account"),
            "azure": (self.azure_url, "subscription"),
            "gcp": (self.gcp_url, "project"),
            "alicloud": (self.alicloud_url, "account"),
            "oci": (self.oci_url, "compartment"),
            "ibm": (self.ibm_url, "account"),
            "k8s": (self.k8s_url, "cluster")
        }
        
        url_info = url_map.get(provider.lower())
        if not url_info:
            raise ValueError(f"Unknown provider: {provider}")
        
        url, filter_param = url_info
        
        params = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if filter_key:
            params[filter_param] = filter_key
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/scans", params=params)
            response.raise_for_status()
            return response.json()
    
    async def get_engine_metrics(self, provider: str) -> Dict[str, Any]:
        """Get engine metrics"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url,
            "k8s": self.k8s_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/metrics")
            response.raise_for_status()
            return response.json()

